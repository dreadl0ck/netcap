/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017-2020 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package io

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/elastic/go-elasticsearch/v7"
	"github.com/elastic/go-elasticsearch/v7/esapi"
	"github.com/gogo/protobuf/proto"
	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/types"
)

const indexPrefix = "netcap-"

var (
	// errElasticFailed indicates sending data to elasticsearch has failed.
	errElasticFailed = errors.New("failed to send data to elastic")

	// errMissingAuditRecordInterface indicates the audit record is lacking methods to implement the types.AuditRecord interface.
	errMissingAuditRecordInterface = errors.New("type does not implement the types.AuditRecord interface")
)

// ElasticConfig allows to overwrite elastic defaults.
type ElasticConfig struct {
	// ElasticAddrs is a list of elastic database endpoints to send data to
	// the elastic default is localhost:9200
	ElasticAddrs []string

	// ElasticUser is the elastic user in case the database is protected via basic auth
	ElasticUser string

	// ElasticPass is the elastic password in case the database is protected via basic auth
	ElasticPass string

	// KibanaEndpoint is the address for Kibana
	KibanaEndpoint string

	// LimitTotalFields is the maximum number of fields allowed per batch
	LimitTotalFields int

	BulkSize int
}

// elasticWriter is a writer that writes into an elastic database.
type elasticWriter struct {
	client     *elasticsearch.Client
	queue      []proto.Message
	queueIndex int
	wc         *WriterConfig
	meta       []byte
	buf        bytes.Buffer
	processed  int

	indexName string
	sync.Mutex
}

/*
 * Public
 */

// newElasticWriter initializes and configures a new elasticWriter instance.
func newElasticWriter(wc *WriterConfig) *elasticWriter {
	// init new client
	c, err := elasticsearch.NewClient(elasticsearch.Config{
		Addresses: wc.ElasticAddrs,
		Username:  wc.ElasticUser,
		Password:  wc.ElasticPass,
	})
	if err != nil {
		log.Fatal(err)
	}

	return &elasticWriter{
		client:    c,
		wc:        wc,
		queue:     make([]proto.Message, wc.BulkSize),
		indexName: makeElasticIndexIdent(wc),
		meta:      []byte(fmt.Sprintf(`{ "index" : { } }%s`, "\n")),
	}
}

// CreateElasticIndex will create and configure a single elastic database index.
func CreateElasticIndex(wc *WriterConfig) {
	// catch uninitialized type error
	if wc.Type == types.Type_NC_Header {
		log.Fatal("uninitialized writer type, please set the Type field")
	}

	// init new client
	c, err := elasticsearch.NewClient(elasticsearch.Config{
		Addresses: wc.ElasticAddrs,
		Username:  wc.ElasticUser,
		Password:  wc.ElasticPass,
	})
	if err != nil {
		log.Fatal(err)
	}

	// create index identfier and the index
	index := makeElasticIndexIdent(wc)
	createElasticIndex(c, index)

	// create buffer for request and add meta data
	buf := initElasticBuffer(wc, index)

	// passing an explicit id to prevent kibana from duplicating patterns when executing the index creation multiple times
	r, err := http.NewRequest(
		"POST",
		wc.KibanaEndpoint+"/api/saved_objects/index-pattern/"+index,
		&buf,
	)
	if err != nil {
		fmt.Println("failed to create index pattern request:", err)
	} else {
		setElasticAuth(r, wc)

		// create the index
		resp, errAPI := http.DefaultClient.Do(r)
		if errAPI != nil || resp.StatusCode != http.StatusOK {
			fmt.Println("failed to create index pattern:", errAPI)

			if resp != nil {
				data, _ := ioutil.ReadAll(resp.Body)
				fmt.Println(string(data))
			}
		} else {
			fmt.Println("index pattern ", index+"* created:", resp.Status)
		}
	}

	// configure the mapping for the new index
	configureIndex(c, wc, index)
}

// Write writes a record to elastic.
func (w *elasticWriter) Write(msg proto.Message) error {
	w.Lock()
	defer w.Unlock()

	w.queue[w.queueIndex] = msg
	w.queueIndex++

	if w.queueIndex == w.wc.BulkSize {
		w.sendData()
	}

	return nil
}

// WriteHeader writes a CSV header.
func (w *elasticWriter) WriteHeader(_ types.Type) error {
	return nil
}

// Close flushes and closes the writer and the associated file handles.
func (w *elasticWriter) Close(numRecords int64) (name string, size int64) {
	err := w.sendBulk(0, 0)
	if err != nil {
		fmt.Println(err)
	}

	return "", 0
}

/*
 * Private
 */

type bulkResponse struct {
	Errors bool `json:"errors"`
	Items  []struct {
		Index struct {
			ID     string `json:"_id"`
			Result string `json:"result"`
			Status int    `json:"status"`
			Error  struct {
				Type   string `json:"type"`
				Reason string `json:"reason"`
				Cause  struct {
					Type   string `json:"type"`
					Reason string `json:"reason"`
				} `json:"caused_by"`
			} `json:"error"`
		} `json:"index"`
	} `json:"items"`
}

func (w *elasticWriter) sendData() {
	var (
		unit = w.wc.BulkSize
		err  error
		half bool
	)

	for {
		err = w.sendBulk(0, unit)
		if err != nil {
			fmt.Println("failed to send elastic bulk data:", err, w.wc.Name)

			if !half {
				// half the unit and try again
				half = true
				unit /= 2
				fmt.Println("half the unit from to", unit)
			}

			continue
		}

		// if the batch was cut in half due to a previous error, send the remainder
		if half {
			fmt.Println("sending remaining half", unit)

			err = w.sendBulk(0, unit)
			if err != nil {
				fmt.Println("failed to send elastic bulk data half", err, w.wc.Name)
			}

			fmt.Println("items in queue after sending second batch:", len(w.queue))

			// realloc queue
			w.queue = make([]proto.Message, w.wc.BulkSize)
		}

		// reset queue index
		w.queueIndex = 0

		break
	}
}

func makeElasticIndexIdent(wc *WriterConfig) string {
	return indexPrefix + strings.ReplaceAll(strings.ToLower(wc.Name), "/", "-")
}

func createElasticIndex(c *elasticsearch.Client, ident string) {
	res, err := c.Indices.Create(ident)
	if err != nil || res.StatusCode != http.StatusOK {
		fmt.Println("failed to create elastic index:", err)

		if res != nil {
			// ignore error in case the index exists already
			data, _ := ioutil.ReadAll(res.Body)
			fmt.Println(string(data))
		}
	} else {
		fmt.Println("created elastic index:", ident, res.Status())
	}
}

func initElasticBuffer(wc *WriterConfig, index string) bytes.Buffer {
	timeField := "Timestamp"

	switch wc.Name {
	case "Connection", "Flow", "IPProfile":
		timeField = "TimestampFirst"
	}

	var buf bytes.Buffer

	buf.WriteString(`{
    "attributes": {
     "title": "` + index + `*",
     "timeFieldName": "` + timeField + `"
     }
}`)

	return buf
}

func setElasticAuth(r *http.Request, wc *WriterConfig) {
	r.Header.Set("kbn-xsrf", "true")
	r.Header.Set("Content-Type", "application/json")
	r.SetBasicAuth(wc.ElasticUser, wc.ElasticPass)
}

func configureIndex(c *elasticsearch.Client, wc *WriterConfig, index string) {
	res, err := c.Indices.PutMapping(
		bytes.NewReader(generateMapping(wc.Type)),
		func(r *esapi.IndicesPutMappingRequest) {
			r.Index = []string{index}
		},
	)
	if err != nil || res.StatusCode != http.StatusOK {
		if res != nil {
			data, _ := ioutil.ReadAll(res.Body)
			fmt.Println(string(data))
		}

		log.Fatalf("error getting the response: %s", err)
	} else {
		fmt.Println("configured index mapping", res)
	}

	_ = res.Body.Close()

	// TODO: update Duration fieldFormatMap to milliseconds for flows and conns via saved objects API
	// e.g: /api/saved_objects/index-pattern/flow
	// {
	// 	"attributes":{
	// 	"title":"netcap-flow*",
	// 		"timeFieldName":"TimestampFirst",
	// 		"fields":"[{\"name\":\"DstIP\",\"type\":\"ip\",\"esTypes\":[\"ip\"],\"count\":1,\"scripted\":false,\"searchable\":true,\"aggregatable\":true,\"readFromDocValues\":true},{\"name\":\"Duration\",\"type\":\"number\",\"esTypes\":[\"integer\"],\"count\":0,\"scripted\":false,\"searchable\":true,\"aggregatable\":true,\"readFromDocValues\":true},{\"name\":\"ID\",\"type\":\"string\",\"esTypes\":[\"text\"],\"count\":0,\"scripted\":false,\"searchable\":true,\"aggregatable\":false,\"readFromDocValues\":false},{\"name\":\"Protocol\",\"type\":\"string\",\"esTypes\":[\"text\"],\"count\":0,\"scripted\":false,\"searchable\":true,\"aggregatable\":false,\"readFromDocValues\":false},{\"name\":\"SrcIP\",\"type\":\"ip\",\"esTypes\":[\"ip\"],\"count\":1,\"scripted\":false,\"searchable\":true,\"aggregatable\":true,\"readFromDocValues\":true},{\"name\":\"Timestamp\",\"type\":\"date\",\"esTypes\":[\"date\"],\"count\":0,\"scripted\":false,\"searchable\":true,\"aggregatable\":true,\"readFromDocValues\":true},{\"name\":\"TimestampFirst\",\"type\":\"date\",\"esTypes\":[\"date\"],\"count\":0,\"scripted\":false,\"searchable\":true,\"aggregatable\":true,\"readFromDocValues\":true},{\"name\":\"TimestampLast\",\"type\":\"date\",\"esTypes\":[\"date\"],\"count\":1,\"scripted\":false,\"searchable\":true,\"aggregatable\":true,\"readFromDocValues\":true},{\"name\":\"Version\",\"type\":\"string\",\"esTypes\":[\"text\"],\"count\":0,\"scripted\":false,\"searchable\":true,\"aggregatable\":false,\"readFromDocValues\":false},{\"name\":\"_id\",\"type\":\"string\",\"esTypes\":[\"_id\"],\"count\":0,\"scripted\":false,\"searchable\":true,\"aggregatable\":true,\"readFromDocValues\":false},{\"name\":\"_index\",\"type\":\"string\",\"esTypes\":[\"_index\"],\"count\":0,\"scripted\":false,\"searchable\":true,\"aggregatable\":true,\"readFromDocValues\":false},{\"name\":\"_score\",\"type\":\"number\",\"count\":0,\"scripted\":false,\"searchable\":false,\"aggregatable\":false,\"readFromDocValues\":false},{\"name\":\"_source\",\"type\":\"_source\",\"esTypes\":[\"_source\"],\"count\":0,\"scripted\":false,\"searchable\":false,\"aggregatable\":false,\"readFromDocValues\":false},{\"name\":\"_type\",\"type\":\"string\",\"esTypes\":[\"_type\"],\"count\":0,\"scripted\":false,\"searchable\":true,\"aggregatable\":true,\"readFromDocValues\":false}]",
	// 		"fieldFormatMap":"{\"Duration\":{\"id\":\"duration\",\"params\":{\"parsedUrl\":{\"origin\":\"KIBANA_ENDPOINT\",\"pathname\":\"/app/kibana\",\"basePath\":\"\"},\"inputFormat\":\"nanoseconds\",\"outputFormat\":\"asMilliseconds\",\"outputPrecision\":4}}}"
	// 	},
	// 	"version":"WzEwODgsM10="
	// }

	if wc.LimitTotalFields == 0 {
		wc.LimitTotalFields = defaults.ElasticLimitTotalFields
	}

	// create settings mapping
	data := make(map[string]string)
	data["index.mapping.total_fields.limit"] = strconv.Itoa(wc.LimitTotalFields)

	// serialize JSON
	d, err := json.Marshal(data)
	if err != nil {
		fmt.Println("failed to marshal json data:", err)

		return
	}

	// use put settings call to increase the maximum fields for each document
	// audit records like HTTP and IPProfile often generate a high number of fields
	res, err = c.Indices.PutSettings(bytes.NewReader(d),
		func(r *esapi.IndicesPutSettingsRequest) {
			r.Index = []string{index}
		},
	)
	if err != nil || res.StatusCode != http.StatusOK {
		if res != nil {
			d, _ = ioutil.ReadAll(res.Body)
			fmt.Println(string(d))
		}

		log.Fatal("failed to put index settings:", err)
	} else {
		fmt.Println("put index settings:", res)
	}

	_ = res.Body.Close()
}

// send a bulk of audit records and metadata to the elastic database daemon.
func (w *elasticWriter) sendBulk(start, limit int) error {
	w.processed = 0

	for _, qmsg := range w.queue[start:] {
		if qmsg == nil {
			continue
		}

		if rec, ok := qmsg.(types.AuditRecord); ok {
			// prepare the data payload: encode record to JSON
			js, err := rec.JSON()
			if err != nil {
				return err
			}

			// append newline to the data payload
			data := []byte(js)
			data = append(data, "\n"...)

			// append payloads to the buffer
			w.buf.Grow(len(w.meta) + len(data))
			_, _ = w.buf.Write(w.meta)
			_, _ = w.buf.Write(data)

			// pass limit = 0 to process the entire queue
			if limit > 0 && w.processed >= limit {
				w.processed++
				w.queue = w.queue[w.processed:]

				break
			}
		} else {
			return fmt.Errorf("%s: %w", qmsg, errMissingAuditRecordInterface)
		}
	}

	if w.buf.Len() == 0 {
		return nil
	}

	for {
		// send off the bulk data
		res, err := w.client.Bulk(bytes.NewReader(w.buf.Bytes()), w.client.Bulk.WithIndex(w.indexName))
		if err != nil {

			// network error - wait a little and retry
			dur := 500 * time.Millisecond

			fmt.Println("failure indexing batch:", err, "will sleep for", dur, "and retry")
			time.Sleep(dur)

			continue
		}

		// if the whole request failed, print error and mark all documents as failed
		if res.IsError() {
			var raw map[string]interface{}
			if err = json.NewDecoder(res.Body).Decode(&raw); err != nil {
				log.Printf("failure to to parse response body: %s", err)
			} else {
				ioLog.Error("elastic bulk request failed",
					zap.Int("status", res.StatusCode),
					zap.String("type", raw["error"].(map[string]interface{})["type"].(string)),
					zap.String("reason", raw["error"].(map[string]interface{})["reason"].(string)),
				)
			}

			// dump buffer in case of errors
			ioLog.Debug(w.buf.String())
			w.buf.Reset()

			return errElasticFailed
		}

		// a successful response can still contain errors for some documents
		var blk *bulkResponse
		if err = json.NewDecoder(res.Body).Decode(&blk); err != nil {
			log.Printf("failure to to parse response body: %s", err)

			// dump buffer in case of errors
			ioLog.Debug(w.buf.String())
			w.buf.Reset()

			return errElasticFailed
		}

		var hadErrors bool

		// log errors for HTTP status codes above 201
		for _, d := range blk.Items {
			if d.Index.Status > 201 {
				hadErrors = true

				ioLog.Error("error for item in elastic bulk request",
					zap.Int("status", d.Index.Status),
					zap.String("type", d.Index.Error.Type),
					zap.String("reason", d.Index.Error.Reason),
					zap.String("causeType", d.Index.Error.Cause.Type),
					zap.String("causeReason", d.Index.Error.Cause.Reason),
				)
			}
		}

		// dump buffer in case of errors
		if hadErrors {
			ioLog.Debug(w.buf.String())
		}

		// close the response body, to prevent reaching the limit for goroutines or file handles
		_ = res.Body.Close()

		ioLog.Info("sent audit records to elastic",
			zap.Int("total", w.processed),
			zap.String("type", w.wc.Name),
		)
		w.buf.Reset()

		// exit loop on success
		break
	}

	return nil
}

// JSON properties for elastic indices.
// e.g:
// {
// 	"properties": {
// 		"Timestamp": {
// 			"type": "date"
// 		},
// 	}
// }
// contains the type mapping for indexed documents.
type mappingJSON struct {
	Properties map[string]map[string]string `json:"properties"`
}

// overwrites for various field types
// default for string is text, this can be overwritten with keyword via this mapping.
var typeMapping = map[string]string{
	"Timestamp":          "date",
	"TimestampFirst":     "date",
	"TimestampLast":      "date",
	"ReferenceTimestamp": "date",

	"Duration":    "long",
	"Bytes":       "long",
	"SeqNum":      "long",
	"AckNum":      "long",
	"ReferenceID": "long",
	"Xid":         "long",

	"SrcIP":    "ip",
	"DstIP":    "ip",
	"IP":       "ip",
	"ServerIP": "ip",
	"ClientIP": "ip",

	"SrcPort": "integer",
	"DstPort": "integer",
	"Port":    "integer",

	"ID":                  "keyword",
	"User":                "keyword",
	"Pass":                "keyword",
	"Protocol":            "keyword",
	"Name":                "keyword",
	"Product":             "keyword",
	"Vendor":              "keyword",
	"SourceName":          "keyword",
	"Software.Product":    "keyword",
	"Software.Vendor":     "keyword",
	"Software.SourceName": "keyword",
	"Host":                "keyword",
	"UserAgent":           "keyword",
	"Method":              "keyword",
	"Hostname":            "keyword",
	"ServerName":          "keyword",

	"Answers":   "object",
	"Questions": "object",

	"Parameters.cmd":  "text",
	"Parameters.src":  "text",
	"Parameters.name": "text",

	// too big for long type ...
	"OriginTimestamp":   "text",
	"TransmitTimestamp": "text",
	"ReceiveTimestamp":  "text",

	"SrcPorts": "flattened",
	"DstPorts": "flattened",
}

// generates a valid elasticsearch type mapping for the given audit record
// and returns it as a JSON byte slice.
// see:
// https://www.elastic.co/guide/en/elasticsearch/reference/current/mapping-types.html
func generateMapping(t types.Type) []byte {
	mapping := mappingJSON{
		Properties: map[string]map[string]string{},
	}

	recordFields := 0
	if r, ok := InitRecord(t).(types.AuditRecord); ok {

		auditRecord := reflect.ValueOf(r).Elem()

		// iterate over audit record fields
		for i := 0; i < auditRecord.NumField(); i++ { // get StructField
			field := auditRecord.Type().Field(i)

			// first, check if a custom mapping is provided
			if m, exists := typeMapping[field.Name]; exists {
				// set the type for the field name
				mapping.Properties[field.Name] = map[string]string{"type": m}

				continue
			}

			// no custom type provided - make a decision based on the data type.
			switch field.Type.String() {
			case "string": // default for strings is text. for keyword, use the mapping table to overwrite
				mapping.Properties[field.Name] = map[string]string{"type": "text"}
			case "int32", "uint32", "int64", "uint64", "uint8", "float64":
				mapping.Properties[field.Name] = map[string]string{"type": "integer"}
			case "bool":
				mapping.Properties[field.Name] = map[string]string{"type": "boolean"}
			default:
				if field.Type.Elem().Kind() == reflect.Struct {
					mapping.Properties[field.Name] = map[string]string{"type": "object"}
				} else {
					if field.Type.Elem().Kind() == reflect.Ptr {
						mapping.Properties[field.Name] = map[string]string{"type": "object"}
					} else {
						// scalar array types
						// fmt.Println("  ", field.Name, field.Type, "1")
						recordFields++
					}
				}
			}
		}
	}

	j, err := json.MarshalIndent(mapping, " ", "  ")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("mapping for", t, string(j))

	return j
}
