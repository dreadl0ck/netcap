package io

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"sync"

	"github.com/elastic/go-elasticsearch/v7"
	"github.com/elastic/go-elasticsearch/v7/esapi"
	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/types"
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

var (
	docIndex   int64
	docIndexMu sync.Mutex
)

const indexPrefix = "netcap-"

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
		indexName: makeIndex(wc),
		meta:      []byte(fmt.Sprintf(`{ "index" : { } }%s`, "\n")),
	}
}

func makeIndex(wc *WriterConfig) string {
	return indexPrefix + strings.ReplaceAll(strings.ToLower(wc.Name), "/", "-")
}

// CreateElasticIndex will create and configure a single elastic database index.
func CreateElasticIndex(wc *WriterConfig) {
	// init new client
	c, err := elasticsearch.NewClient(elasticsearch.Config{
		Addresses: wc.ElasticAddrs,
		Username:  wc.ElasticUser,
		Password:  wc.ElasticPass,
	})
	if err != nil {
		log.Fatal(err)
	}

	index := makeIndex(wc)

	res, err := c.Indices.Create(index)
	if err != nil || res.StatusCode != http.StatusOK {
		// ignore error in case the index exists already
		data, _ := ioutil.ReadAll(res.Body)
		fmt.Println(string(data))
		fmt.Println("failed to create elastic index:", err)
	} else {
		fmt.Println("created elastic index:", index, res.Status())
	}

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

	// passing an explicit id to prevent kibana from duplicating patterns when executing the index creation multiple times
	r, err := http.NewRequest(
		"POST",
		// wc.KibanaEndpoint+"/api/saved_objects/index-pattern/"+index, // TODO:
		wc.KibanaEndpoint+"/api/saved_objects/index-pattern/"+strings.ReplaceAll(strings.ToLower(wc.Name), "/", "-"),
		&buf,
	)
	if err != nil {
		fmt.Println("failed to create index pattern request:", err)
	} else {
		r.Header.Set("kbn-xsrf", "true")
		r.Header.Set("Content-Type", "application/json")
		r.SetBasicAuth(wc.ElasticUser, wc.ElasticPass)

		resp, err := http.DefaultClient.Do(r)
		if err != nil || resp.StatusCode != http.StatusOK {
			fmt.Println("failed to create index pattern:", err)
			data, _ := ioutil.ReadAll(resp.Body)
			fmt.Println(string(data))
		} else {
			fmt.Println("index pattern ", index+"* created:", resp.Status)
		}
	}

	// TODO: create a proper per type mapping
	res, err = c.Indices.PutMapping(
		strings.NewReader(`{
			"properties": {
				"Timestamp": {
					"type": "date"
				},
				"TimestampFirst": {
					"type": "date"
				},
				"TimestampLast": {
					"type": "date"
				},
				"Duration": {
					"type": "long"
				},
				"Version": {
					"type": "text"
				},
				"SrcIP": {
					"type": "ip"
				},
				"Banner": {
					"type": "text"
				},
				"DstIP": {
					"type": "ip"
				},
				"Context.SrcIP": {
					"type": "ip"
				},
				"Context.DstIP": {
					"type": "ip"
				},
				"SrcPort": {
					"type": "keyword"
				},
				"DstPort": {
					"type": "keyword"
				},
				"Port": {
					"type": "keyword"
				},
				"IP": {
					"type": "ip"
				},
				"ServerIP": {
					"type": "ip"
				},
				"ClientIP": {
					"type": "ip"
				},
				"User": {
					"type": "keyword"
				},
				"Pass": {
					"type": "keyword"
				},
				"Context.SrcPort": {
					"type": "integer"
				},
				"Context.DstPort": {
					"type": "integer"
				},
				"ID": {
					"type": "keyword"
				},
				"Protocol": {
					"type": "keyword"
				},
				"Name": {
					"type": "keyword"
				},
				"Product": {
					"type": "keyword"
				},
				"Vendor": {
					"type": "keyword"
				},
				"SourceName": {
					"type": "keyword"
				},
				"Software.Product": {
					"type": "keyword"
				},
				"Software.Vendor": {
					"type": "keyword"
				},
				"Software.SourceName": {
					"type": "keyword"
				},
				"Answers": {
					"type": "object"	
				},
				"Questions": {
					"type": "object"	
				},
				"Length": {
					"type": "integer"
				},
				"PayloadSize": {
					"type": "integer"
				},
				"Host": {
					"type": "keyword"
				},
				"UserAgent": {
					"type": "keyword"
				},
				"Method": {
					"type": "keyword"
				},
				"Hostname": {
					"type": "keyword"
				},
				"SYN": {
					"type": "boolean"
				},
				"ACK": {
					"type": "boolean"
				},
				"RST": {
					"type": "boolean"
				},
				"FIN": {
					"type": "boolean"
				},
				"Window": {
					"type": "integer"
				},
				"DataOffset": {
					"type": "integer"
				},
				"Bytes": {
					"type": "long"
				},
				"NumPackets": {
					"type": "integer"
				},
				"Parameters.cmd": {
					"type": "text"
				},
				"Parameters.src": {
					"type": "text"
				},
				"Parameters.name": {
					"type": "text"
				},
				"ServerName": {
					"type": "keyword"
				}
			}
		}`),
		func(r *esapi.IndicesPutMappingRequest) {
			r.Index = []string{index}
		},
	)
	if err != nil || res.StatusCode != http.StatusOK {
		data, _ := ioutil.ReadAll(res.Body)
		fmt.Println(string(data))
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

	defer res.Body.Close()
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

var ErrElasticFailed = errors.New("failed to send data to elastic")

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

// JSON mapping for elastic indices
// e.g:
// {
// 	"properties": {
// 		"Timestamp": {
// 			"type": "date"
// 		},
// 	}
// }
type mappingJSON struct {
	Properties map[string]map[string]string `json:"properties"`
}

//func whatMapping(d CustomDecoderAPI) {
//	mapping := mappingJSON{
//		Properties: map[string]map[string]string{},
//	}
//
//	recordFields := 0
//	if r, ok := io.InitRecord(d.GetType()).(types.AuditRecord); ok {
//
//		auditRecord := reflect.ValueOf(r).Elem()
//
//		// iterate over audit record fields
//		for i := 0; i < auditRecord.NumField(); i++ { // get StructField
//			field := auditRecord.Type().Field(i)
//
//			switch field.Type.String() {
//			case "string":
//				mapping.Properties[field.Name] = map[string]string{"type": "text"}
//			case "int32", "uint32", "bool", "int64", "uint64", "uint8", "float64":
//				mapping.Properties[field.Name] = map[string]string{"type": "integer"}
//			default:
//				if field.Type.Elem().Kind() == reflect.Struct {
//					mapping.Properties[field.Name] = map[string]string{"type": "object"}
//				} else {
//					if field.Type.Elem().Kind() == reflect.Ptr {
//						mapping.Properties[field.Name] = map[string]string{"type": "object"}
//					} else {
//						// scalar array types
//						// fmt.Println("  ", field.Name, field.Type, "1")
//						recordFields++
//					}
//				}
//			}
//		}
//	}
//
//	j, err := json.MarshalIndent(mapping, " ", "  ")
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	fmt.Println(string(j))
//}

//
//func TestMappingGeneration(t *testing.T) {
//	ApplyActionToCustomDecoders(func(d CustomDecoderAPI) {
//		whatMapping(d)
//	})
//}