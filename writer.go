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

package netcap

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/elastic/go-elasticsearch/v7/esapi"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/elastic/go-elasticsearch/v7"

	"github.com/davecgh/go-spew/spew"
	"github.com/gogo/protobuf/proto"
	"github.com/klauspost/pgzip"

	"github.com/dreadl0ck/netcap/delimited"
	"github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/types"
)

// AuditRecordWriter is an interface for writing netcap audit records.
type AuditRecordWriter interface {
	Write(msg proto.Message) error
	WriteHeader(t types.Type) error
	Close() (name string, size int64)
}

// ChannelAuditRecordWriter extends the AuditRecordWriter
// by offering a function to get a channel to receive serialized audit records
type ChannelAuditRecordWriter interface {
	AuditRecordWriter
	GetChan() <-chan []byte
}

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

// WriterConfig contains config parameters for a audit record writer.
type WriterConfig struct {

	// Writer Types:
	// Comma Separated Values writer
	CSV bool
	// Protobuf writer
	Proto bool
	// JSON writer
	JSON bool
	// Channel writer
	Chan bool
	// ChanSize is the size of chunks sent through the channel
	ChanSize int

	// Elastic db writer
	Elastic bool

	// ElasticConfig allows to overwrite elastic defaults
	ElasticConfig

	// The Null writer will write nothing to disk and discard all data.
	Null bool

	// Netcap header information
	Name          string
	Buffer        bool
	Compress      bool
	Out           string
	MemBufferSize int

	// Netcap header information
	Source           string
	Version          string
	IncludesPayloads bool
	StartTime        time.Time
}

// NewAuditRecordWriter will return a new writer for netcap audit records.
func NewAuditRecordWriter(wc *WriterConfig) AuditRecordWriter {
	switch {
	case wc.CSV:
		return NewCSVWriter(wc)
	case wc.Chan:
		return NewChanWriter(wc)
	case wc.JSON:
		return NewJSONWriter(wc)
	case wc.Null:
		return NewNullWriter()
	case wc.Elastic:
		return NewElasticWriter(wc)

	// proto is the default, so this option should be checked last to allow overwriting it
	case wc.Proto:
		return NewProtoWriter(wc)
	default:
		spew.Dump(wc)
		panic("invalid WriterConfig")
	}

	return nil //nolint:govet
}

/*
 *	Type Definitions
 */

// ChanWriter writes length delimited, serialized protobuf records into a channel.
type ChanWriter struct {
	bWriter *bufio.Writer
	gWriter *pgzip.Writer
	dWriter *delimited.Writer
	cWriter *io.ChanProtoWriter

	file *os.File
	mu   sync.Mutex
	wc   *WriterConfig
}

// NewChanWriter initializes and configures a new ChanWriter instance.
func NewChanWriter(wc *WriterConfig) *ChanWriter {
	w := &ChanWriter{}
	w.wc = wc

	if wc.MemBufferSize <= 0 {
		wc.MemBufferSize = DefaultBufferSize
	}

	if wc.Buffer || wc.Compress {
		panic("buffering or compression cannot be activated when running using writeChan")
	}

	w.cWriter = io.NewChanProtoWriter(wc.ChanSize)

	// buffer data?
	if wc.Buffer {
		if wc.Compress {
			// experiment: pgzip -> file
			var errGzipWriter error
			w.gWriter, errGzipWriter = pgzip.NewWriterLevel(w.file, DefaultCompressionLevel)

			if errGzipWriter != nil {
				panic(errGzipWriter)
			}
			// experiment: buffer -> pgzip
			w.bWriter = bufio.NewWriterSize(w.gWriter, DefaultBufferSize)
			// experiment: delimited -> buffer
			w.dWriter = delimited.NewWriter(w.bWriter)
		} else {
			w.bWriter = bufio.NewWriterSize(w.file, DefaultBufferSize)
			w.dWriter = delimited.NewWriter(w.bWriter)
		}
	} else {
		if wc.Compress {
			var errGzipWriter error
			w.gWriter, errGzipWriter = pgzip.NewWriterLevel(w.file, DefaultCompressionLevel)
			if errGzipWriter != nil {
				panic(errGzipWriter)
			}
			w.dWriter = delimited.NewWriter(w.gWriter)
		} else {
			// write into channel writer without compression
			w.dWriter = delimited.NewWriter(w.cWriter)
		}
	}

	if w.gWriter != nil {
		// To get any performance gains, you should at least be compressing more than 1 megabyte of data at the time.
		// You should at least have a block size of 100k and at least a number of blocks that match the number of cores
		// your would like to utilize, but about twice the number of blocks would be the best.
		if err := w.gWriter.SetConcurrency(DefaultCompressionBlockSize, runtime.GOMAXPROCS(0)*2); err != nil {
			log.Fatal("failed to configure compression package: ", err)
		}
	}

	return w
}

// WriteProto writes a protobuf message.
func (w *ChanWriter) Write(msg proto.Message) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	data, err := proto.Marshal(msg)
	if err != nil {
		return err
	}

	_, err = w.cWriter.Write(data)

	return err
}

// WriteHeader writes a netcap file header for protobuf encoded audit record files.
func (w *ChanWriter) WriteHeader(t types.Type) error {
	data, err := proto.Marshal(NewHeader(t, w.wc.Source, w.wc.Version, w.wc.IncludesPayloads, w.wc.StartTime))
	if err != nil {
		return err
	}

	_, err = w.cWriter.Write(data)

	return err
}

// Close flushes and closes the writer and the associated file handles.
func (w *ChanWriter) Close() (name string, size int64) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.wc.Buffer {
		flushWriters(w.bWriter)
	}

	if w.wc.Compress {
		closeGzipWriters(w.gWriter)
	}

	return closeFile(w.wc.Out, w.file, w.wc.Name)
}

// GetChan returns a channel for receiving bytes.
func (w *ChanWriter) GetChan() <-chan []byte {
	return w.cWriter.Chan()
}

// ProtoWriter is a structure that supports writing protobuf audit records to disk.
type ProtoWriter struct {
	bWriter *bufio.Writer
	gWriter *pgzip.Writer
	dWriter *delimited.Writer
	pWriter *io.DelimitedProtoWriter

	file *os.File
	mu   sync.Mutex
	wc   *WriterConfig
}

// NewProtoWriter initializes and configures a new ProtoWriter instance.
func NewProtoWriter(wc *WriterConfig) *ProtoWriter {
	w := &ProtoWriter{}
	w.wc = wc

	if wc.MemBufferSize <= 0 {
		wc.MemBufferSize = DefaultBufferSize
	}

	if wc.Compress {
		w.file = createFile(filepath.Join(wc.Out, wc.Name), ".ncap.gz")
	} else {
		w.file = createFile(filepath.Join(wc.Out, wc.Name), ".ncap")
	}

	// buffer data?
	if wc.Buffer {
		if wc.Compress {
			// experiment: pgzip -> file
			var errGzipWriter error
			w.gWriter, errGzipWriter = pgzip.NewWriterLevel(w.file, DefaultCompressionLevel)

			if errGzipWriter != nil {
				panic(errGzipWriter)
			}
			// experiment: buffer -> pgzip
			w.bWriter = bufio.NewWriterSize(w.gWriter, DefaultBufferSize)
			// experiment: delimited -> buffer
			w.dWriter = delimited.NewWriter(w.bWriter)
		} else {
			w.bWriter = bufio.NewWriterSize(w.file, DefaultBufferSize)
			w.dWriter = delimited.NewWriter(w.bWriter)
		}
	} else {
		if w.wc.Compress {
			var errGzipWriter error
			w.gWriter, errGzipWriter = pgzip.NewWriterLevel(w.file, DefaultCompressionLevel)
			if errGzipWriter != nil {
				panic(errGzipWriter)
			}
			w.dWriter = delimited.NewWriter(w.gWriter)
		} else {
			w.dWriter = delimited.NewWriter(w.file)
		}
	}

	w.pWriter = io.NewDelimitedProtoWriter(w.dWriter)

	if w.gWriter != nil {
		// To get any performance gains, you should at least be compressing more than 1 megabyte of data at the time.
		// You should at least have a block size of 100k and at least a number of blocks that match the number of cores
		// your would like to utilize, but about twice the number of blocks would be the best.
		if err := w.gWriter.SetConcurrency(DefaultCompressionBlockSize, runtime.GOMAXPROCS(0)*2); err != nil {
			log.Fatal("failed to configure compression package: ", err)
		}
	}

	return w
}

// WriteProto writes a protobuf message.
func (w *ProtoWriter) Write(msg proto.Message) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	return w.pWriter.PutProto(msg)
}

// WriteHeader writes a netcap file header for protobuf encoded audit record files.
func (w *ProtoWriter) WriteHeader(t types.Type) error {
	return w.pWriter.PutProto(NewHeader(t, w.wc.Source, w.wc.Version, w.wc.IncludesPayloads, w.wc.StartTime))
}

// Close flushes and closes the writer and the associated file handles.
func (w *ProtoWriter) Close() (name string, size int64) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.wc.Buffer {
		flushWriters(w.bWriter)
	}

	if w.wc.Compress {
		closeGzipWriters(w.gWriter)
	}

	return closeFile(w.wc.Out, w.file, w.wc.Name)
}

// CSVWriter is a structure that supports writing CSV audit records to disk.
type CSVWriter struct {
	bWriter   *bufio.Writer
	gWriter   *pgzip.Writer
	csvWriter *io.CSVProtoWriter

	file *os.File
	mu   sync.Mutex
	wc   *WriterConfig
}

// NewCSVWriter initializes and configures a new ProtoWriter instance.
func NewCSVWriter(wc *WriterConfig) *CSVWriter {
	w := &CSVWriter{}
	w.wc = wc

	if wc.MemBufferSize <= 0 {
		wc.MemBufferSize = DefaultBufferSize
	}

	// create file
	if wc.Compress {
		w.file = createFile(filepath.Join(wc.Out, w.wc.Name), ".csv.gz")
	} else {
		w.file = createFile(filepath.Join(wc.Out, w.wc.Name), ".csv")
	}

	if wc.Buffer {
		w.bWriter = bufio.NewWriterSize(w.file, wc.MemBufferSize)

		if wc.Compress {
			var errGzipWriter error
			w.gWriter, errGzipWriter = pgzip.NewWriterLevel(w.bWriter, DefaultCompressionLevel)

			if errGzipWriter != nil {
				panic(errGzipWriter)
			}

			w.csvWriter = io.NewCSVWriter(w.gWriter)
		} else {
			w.csvWriter = io.NewCSVWriter(w.bWriter)
		}
	} else {
		if wc.Compress {
			var errGzipWriter error
			w.gWriter, errGzipWriter = pgzip.NewWriterLevel(w.file, DefaultCompressionLevel)
			if errGzipWriter != nil {
				panic(errGzipWriter)
			}
			w.csvWriter = io.NewCSVWriter(w.gWriter)
		} else {
			w.csvWriter = io.NewCSVWriter(w.file)
		}
	}

	if w.gWriter != nil {
		// To get any performance gains, you should at least be compressing more than 1 megabyte of data at the time.
		// You should at least have a block size of 100k and at least a number of blocks that match the number of cores
		// your would like to utilize, but about twice the number of blocks would be the best.
		if err := w.gWriter.SetConcurrency(DefaultCompressionBlockSize, runtime.GOMAXPROCS(0)*2); err != nil {
			log.Fatal("failed to configure compression package: ", err)
		}
	}

	return w
}

// WriteCSV writes a CSV record.
func (w *CSVWriter) Write(msg proto.Message) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	_, err := w.csvWriter.WriteRecord(msg)

	return err
}

// WriteHeader writes a CSV header.
func (w *CSVWriter) WriteHeader(t types.Type) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	_, err := w.csvWriter.WriteHeader(NewHeader(t, w.wc.Source, w.wc.Version, w.wc.IncludesPayloads, w.wc.StartTime), InitRecord(t))

	return err
}

// Close flushes and closes the writer and the associated file handles.
func (w *CSVWriter) Close() (name string, size int64) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.wc.Buffer {
		flushWriters(w.bWriter)
	}

	if w.wc.Compress {
		closeGzipWriters(w.gWriter)
	}

	return closeFile(w.wc.Out, w.file, w.wc.Name)
}

// JSONWriter is a structure that supports writing JSON audit records to disk.
type JSONWriter struct {
	bWriter *bufio.Writer
	gWriter *pgzip.Writer
	dWriter *delimited.Writer
	jWriter *io.JSONProtoWriter

	file *os.File
	mu   sync.Mutex
	wc   *WriterConfig
}

// NewJSONWriter initializes and configures a new JSONWriter instance.
func NewJSONWriter(wc *WriterConfig) *JSONWriter {
	w := &JSONWriter{}
	w.wc = wc

	if wc.MemBufferSize <= 0 {
		wc.MemBufferSize = DefaultBufferSize
	}

	// create file
	if wc.Compress {
		w.file = createFile(filepath.Join(wc.Out, w.wc.Name), ".json.gz")
	} else {
		w.file = createFile(filepath.Join(wc.Out, w.wc.Name), ".json")
	}

	if wc.Buffer {
		w.bWriter = bufio.NewWriterSize(w.file, wc.MemBufferSize)

		if wc.Compress {
			var errGzipWriter error
			w.gWriter, errGzipWriter = pgzip.NewWriterLevel(w.bWriter, DefaultCompressionLevel)

			if errGzipWriter != nil {
				panic(errGzipWriter)
			}

			w.jWriter = io.NewJSONProtoWriter(w.gWriter)
		} else {
			w.jWriter = io.NewJSONProtoWriter(w.bWriter)
		}
	} else {
		if wc.Compress {
			var errGzipWriter error
			w.gWriter, errGzipWriter = pgzip.NewWriterLevel(w.file, DefaultCompressionLevel)
			if errGzipWriter != nil {
				panic(errGzipWriter)
			}
			w.jWriter = io.NewJSONProtoWriter(w.gWriter)
		} else {
			w.jWriter = io.NewJSONProtoWriter(w.file)
		}
	}

	if w.gWriter != nil {
		// To get any performance gains, you should at least be compressing more than 1 megabyte of data at the time.
		// You should at least have a block size of 100k and at least a number of blocks that match the number of cores
		// your would like to utilize, but about twice the number of blocks would be the best.
		if err := w.gWriter.SetConcurrency(DefaultCompressionBlockSize, runtime.GOMAXPROCS(0)*2); err != nil {
			log.Fatal("failed to configure compression package: ", err)
		}
	}

	return w
}

// WriteCSV writes a CSV record.
func (w *JSONWriter) Write(msg proto.Message) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	_, err := w.jWriter.WriteRecord(msg)

	return err
}

// WriteHeader writes a CSV header.
func (w *JSONWriter) WriteHeader(t types.Type) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	_, err := w.jWriter.WriteHeader(NewHeader(t, w.wc.Source, w.wc.Version, w.wc.IncludesPayloads, w.wc.StartTime))

	return err
}

// Close flushes and closes the writer and the associated file handles.
func (w *JSONWriter) Close() (name string, size int64) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.wc.Buffer {
		flushWriters(w.bWriter)
	}

	if w.wc.Compress {
		closeGzipWriters(w.gWriter)
	}

	return closeFile(w.wc.Out, w.file, w.wc.Name)
}

// NullWriter is a writer that writes nothing to disk.
type NullWriter struct{}

// NewNullWriter initializes and configures a new NullWriter instance.
func NewNullWriter() *NullWriter {
	return &NullWriter{}
}

// WriteCSV writes a CSV record.
func (w *NullWriter) Write(msg proto.Message) error {
	return nil
}

// WriteHeader writes a CSV header.
func (w *NullWriter) WriteHeader(t types.Type) error {
	return nil
}

// Close flushes and closes the writer and the associated file handles.
func (w *NullWriter) Close() (name string, size int64) {
	return "", 0
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

const indexPrefix = "netcap-v2-"

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
	if err != nil {
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
		wc.KibanaEndpoint+"/api/saved_objects/index-pattern/"+index,
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
					"type": "integer"
				},
				"DstPort": {
					"type": "integer"
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
				//data := []byte(js[:len(js)-1] + `, "type" : "`+ w.wc.Name + `"}`)
				//fmt.Println(js[:len(js)-1] + `, "type" : "`+ w.wc.Name + `"}`)

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
			log.Printf("  Error: [%d] %s: %s",
				res.StatusCode,
				raw["error"].(map[string]interface{})["type"],
				raw["error"].(map[string]interface{})["reason"],
			)
		}

		// dump buffer in case of errors
		//fmt.Println(w.buf.String())
		w.buf.Reset()

		return ErrElasticFailed
	}

	// a successful response can still contain errors for some documents
	var blk *bulkResponse
	if err = json.NewDecoder(res.Body).Decode(&blk); err != nil {
		log.Printf("failure to to parse response body: %s", err)

		// dump buffer in case of errors
		//fmt.Println(w.buf.String())
		w.buf.Reset()

		return ErrElasticFailed
	}

	var hadErrors bool
	for _, d := range blk.Items {
		// for any HTTP status above 201
		if d.Index.Status > 201 {
			hadErrors = true
			log.Printf("  Error: [%d]: %s: %s: %s: %s",
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
		//fmt.Println(w.buf.String())
	}

	// close the response body, to prevent reaching the limit for goroutines or file handles
	_ = res.Body.Close()

	//fmt.Println("sent", w.processed, w.wc.Name, "audit records to elastic")
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

/*
 *	Utils
 */

type flushableWriter interface {
	Flush() error
}

func flushWriters(writers ...flushableWriter) {
	for _, w := range writers {
		err := w.Flush()
		if err != nil {
			panic(err)
		}
	}
}

func closeGzipWriters(writers ...*pgzip.Writer) {
	for _, w := range writers {
		err := w.Flush()
		if err != nil {
			panic(err)
		}

		err = w.Close()
		if err != nil {
			panic(err)
		}
	}
}
