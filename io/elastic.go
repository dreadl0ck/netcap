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
	"strings"
	"sync"

	"github.com/elastic/go-elasticsearch/v7"
	"github.com/elastic/go-elasticsearch/v7/esapi"
	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/types"
)

const indexPrefix = "netcap-v2-"

// ErrElasticFailed indicates sending data to elasticsearch has failed.
var ErrElasticFailed = errors.New("failed to send data to elastic")

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

	BulkSize int
}

// ElasticWriter is a writer that writes into an elastic database.
type ElasticWriter struct {
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

// NewElasticWriter initializes and configures a new ElasticWriter instance.
func NewElasticWriter(wc *WriterConfig) *ElasticWriter {
	// init new client
	c, err := elasticsearch.NewClient(elasticsearch.Config{
		Addresses: wc.ElasticAddrs,
		Username:  wc.ElasticUser,
		Password:  wc.ElasticPass,
	})
	if err != nil {
		log.Fatal(err)
	}

	return &ElasticWriter{
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
func (w *ElasticWriter) Write(msg proto.Message) error {
	w.Lock()
	defer w.Unlock()

	w.queue[w.queueIndex] = msg
	w.queueIndex++

	if w.queueIndex == w.wc.BulkSize {

		var (
			unit = w.wc.BulkSize
			err  error
			half bool
		)

		for {
			err = w.sendBulk(0, unit)
			if err != nil {
				fmt.Println("failed to send elastic bulk data", err, w.wc.Name)

				if !half {
					// half the unit and try again
					half = true
					unit /= 2
				}

				continue
			}

			// if the batch was cut in half due to a previous error, send the remainder
			if half {
				err = w.sendBulk(unit, unit)
				if err != nil {
					fmt.Println("failed to send elastic bulk data half", err, w.wc.Name)
				}
			}

			// reset queue index
			w.queueIndex = 0

			break
		}
	}

	return nil
}

// WriteHeader writes a CSV header.
func (w *ElasticWriter) WriteHeader(t types.Type) error {
	return nil
}

// Close flushes and closes the writer and the associated file handles.
func (w *ElasticWriter) Close() (name string, size int64) {
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
	case "Connection", "Flow":
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

	// TODO: update Duration fieldFormatMap for flows and conns via saved objects API
	// e.g: https://dreadl0ck.net:5443/api/saved_objects/index-pattern/flow
	// {
	// 	"attributes":{
	// 	"title":"netcap-flow*",
	// 		"timeFieldName":"TimestampFirst",
	// 		"fields":"[{\"name\":\"DstIP\",\"type\":\"ip\",\"esTypes\":[\"ip\"],\"count\":1,\"scripted\":false,\"searchable\":true,\"aggregatable\":true,\"readFromDocValues\":true},{\"name\":\"Duration\",\"type\":\"number\",\"esTypes\":[\"integer\"],\"count\":0,\"scripted\":false,\"searchable\":true,\"aggregatable\":true,\"readFromDocValues\":true},{\"name\":\"ID\",\"type\":\"string\",\"esTypes\":[\"text\"],\"count\":0,\"scripted\":false,\"searchable\":true,\"aggregatable\":false,\"readFromDocValues\":false},{\"name\":\"Protocol\",\"type\":\"string\",\"esTypes\":[\"text\"],\"count\":0,\"scripted\":false,\"searchable\":true,\"aggregatable\":false,\"readFromDocValues\":false},{\"name\":\"SrcIP\",\"type\":\"ip\",\"esTypes\":[\"ip\"],\"count\":1,\"scripted\":false,\"searchable\":true,\"aggregatable\":true,\"readFromDocValues\":true},{\"name\":\"Timestamp\",\"type\":\"date\",\"esTypes\":[\"date\"],\"count\":0,\"scripted\":false,\"searchable\":true,\"aggregatable\":true,\"readFromDocValues\":true},{\"name\":\"TimestampFirst\",\"type\":\"date\",\"esTypes\":[\"date\"],\"count\":0,\"scripted\":false,\"searchable\":true,\"aggregatable\":true,\"readFromDocValues\":true},{\"name\":\"TimestampLast\",\"type\":\"date\",\"esTypes\":[\"date\"],\"count\":1,\"scripted\":false,\"searchable\":true,\"aggregatable\":true,\"readFromDocValues\":true},{\"name\":\"Version\",\"type\":\"string\",\"esTypes\":[\"text\"],\"count\":0,\"scripted\":false,\"searchable\":true,\"aggregatable\":false,\"readFromDocValues\":false},{\"name\":\"_id\",\"type\":\"string\",\"esTypes\":[\"_id\"],\"count\":0,\"scripted\":false,\"searchable\":true,\"aggregatable\":true,\"readFromDocValues\":false},{\"name\":\"_index\",\"type\":\"string\",\"esTypes\":[\"_index\"],\"count\":0,\"scripted\":false,\"searchable\":true,\"aggregatable\":true,\"readFromDocValues\":false},{\"name\":\"_score\",\"type\":\"number\",\"count\":0,\"scripted\":false,\"searchable\":false,\"aggregatable\":false,\"readFromDocValues\":false},{\"name\":\"_source\",\"type\":\"_source\",\"esTypes\":[\"_source\"],\"count\":0,\"scripted\":false,\"searchable\":false,\"aggregatable\":false,\"readFromDocValues\":false},{\"name\":\"_type\",\"type\":\"string\",\"esTypes\":[\"_type\"],\"count\":0,\"scripted\":false,\"searchable\":true,\"aggregatable\":true,\"readFromDocValues\":false}]",
	// 		"fieldFormatMap":"{\"Duration\":{\"id\":\"duration\",\"params\":{\"parsedUrl\":{\"origin\":\"KIBANA_ENDPOINT\",\"pathname\":\"/app/kibana\",\"basePath\":\"\"},\"inputFormat\":\"nanoseconds\",\"outputFormat\":\"asMilliseconds\",\"outputPrecision\":4}}}"
	// 	},
	// 	"version":"WzEwODgsM10="
	// }

	// TODO: update num max fields for HTTP index via API
	//PUT netcap-v2-ipprofile/_settings
	//{
	//	"index.mapping.total_fields.limit": 100000000
	//}

	_ = res.Body.Close()
}

func (w *ElasticWriter) sendBulk(start, limit int) error {
	w.processed = 0

	for _, qmsg := range w.queue[start:] {
		if qmsg != nil {
			if rec, ok := qmsg.(types.AuditRecord); ok {

				// prepare the data payload: encode record to JSON
				js, err := rec.JSON()
				if err != nil {
					return err
				}

				// append newline to the data payload
				data := []byte(js)

				// hack to sneak the type info to the JSON
				// data := []byte(js[:len(js)-1] + `, "type" : "`+ w.wc.Name + `"}`)
				// fmt.Println(js[:len(js)-1] + `, "type" : "`+ w.wc.Name + `"}`)

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
				return fmt.Errorf("type does not implement the types.AuditRecord interface: %#v", qmsg)
			}
		}
	}

	if w.buf.Len() == 0 {
		return nil
	}

	// send off the bulk data
	res, err := w.client.Bulk(bytes.NewReader(w.buf.Bytes()), w.client.Bulk.WithIndex(w.indexName))
	if err != nil {
		log.Fatalf("failure indexing batch: %s", err)
	}

	// if the whole request failed, print error and mark all documents as failed
	if res.IsError() {
		var raw map[string]interface{}
		if err = json.NewDecoder(res.Body).Decode(&raw); err != nil {
			log.Printf("failure to to parse response body: %s", err)
		} else {
			log.Printf("Error: [%d] %s: %s",
				res.StatusCode,
				raw["error"].(map[string]interface{})["type"],
				raw["error"].(map[string]interface{})["reason"],
			)
		}

		// dump buffer in case of errors
		fmt.Println(w.buf.String())
		w.buf.Reset()

		return ErrElasticFailed
	}

	// a successful response can still contain errors for some documents
	var blk *bulkResponse
	if err = json.NewDecoder(res.Body).Decode(&blk); err != nil {
		log.Printf("failure to to parse response body: %s", err)

		// dump buffer in case of errors
		fmt.Println(w.buf.String())
		w.buf.Reset()

		return ErrElasticFailed
	}

	var hadErrors bool
	for _, d := range blk.Items {
		// for any HTTP status above 201
		if d.Index.Status > 201 {
			hadErrors = true

			log.Printf("Error: [%d]: %s: %s: %s: %s",
				d.Index.Status,
				d.Index.Error.Type,
				d.Index.Error.Reason,
				d.Index.Error.Cause.Type,
				d.Index.Error.Cause.Reason,
			)
		}
	}

	if hadErrors {
		// dump buffer in case of errors
		fmt.Println(w.buf.String())
	}

	// close the response body, to prevent reaching the limit for goroutines or file handles
	_ = res.Body.Close()

	// fmt.Println("sent", w.processed, w.wc.Name, "audit records to elastic")
	w.buf.Reset()

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

	"SrcIP":    "ip",
	"DstIP":    "ip",
	"IP":       "ip",
	"ServerIP": "ip",
	"ClientIP": "ip",

	"SrcPort":             "keyword",
	"DstPort":             "keyword",
	"Port":                "keyword",
	"User":                "keyword",
	"Pass":                "keyword",
	"ID":                  "keyword",
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
