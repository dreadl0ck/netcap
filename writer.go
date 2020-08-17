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
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
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
	// ChanSize is the size of chinks sent through the channel
	ChanSize int

	// Elastic db writer
	Elastic bool
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
	client *elasticsearch.Client
	queue  []proto.Message
	wc     *WriterConfig
	sync.Mutex
}

var (
	docIndex   int64
	docIndexMu sync.Mutex
)

const (
	indexName = "netcap-audit-records"
	bulkUnit = 1000
)

// NewElasticWriter initializes and configures a new ElasticWriter instance.
func NewElasticWriter(wc *WriterConfig) *ElasticWriter {
	// init new client
	c, err := elasticsearch.NewDefaultClient()
	if err != nil {
		log.Fatal(err)
	}

	// TODO: automate mapping creation: Elasticsearch 6.0 has deprecated support for multiple types in a single index
	// TODO: use simple types like text, keyword, date, long, double, boolean or ip where it makes sense in the mapping

	// DELETE netcap-audit-records
	// PUT netcap-audit-records
	// PUT /netcap-audit-records/_mapping
	// {
	// 	"properties": {
	// 	"Timestamp": {
	// 		"type": "date"
	// 	},
	// 	"Version": {
	// 		"type": "text"
	// 	},
	// 	"ID": {
	// 		"type": "text"
	// 	},
	// 	"Protocol": {
	// 		"type": "text"
	// 	}
	// }
	// }

	//res, err := c.Indices.PutMapping(
	//	strings.NewReader(`{
	//	  "properties": {
	//	    "name": {
	//	      "properties": {
	//	        "Timestamp": {
	//	          "type": "date"
	//	        }
	//	      }
	//	    }
	//	  }
	//	}`),
	//	func(r *esapi.IndicesPutMappingRequest) {
	//		r.Index = []string{indexName}
	//	},
	//)
	//fmt.Println(res, err)
	//if err != nil { // SKIP
	//	log.Fatalf("Error getting the response: %s", err) // SKIP
	//} // SKIP
	//
	//defer res.Body.Close() // SKIP

	return &ElasticWriter{
		client: c,
		wc:     wc,
	}
}

// WriteCSV writes a CSV record.
func (w *ElasticWriter) Write(msg proto.Message) error {

	w.Lock()
	defer w.Unlock()

	w.queue = append(w.queue, msg)

	if len(w.queue)%bulkUnit == 0 {
		err := w.sendBulk()
		if err != nil {
			return err
		}

		// reset queue
		w.queue = []proto.Message{}
	}

	return nil
}

func (w *ElasticWriter) sendBulk() error {

	if len(w.queue) == 0 {
		return nil
	}

	var buf bytes.Buffer

	for _, qmsg := range w.queue {
		if rec, ok := qmsg.(types.AuditRecord); ok {

			// prepare the metadata payload
			meta := []byte(fmt.Sprintf(`{ "index" : { } }%s`, "\n"))

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
			buf.Grow(len(meta) + len(data))
			_, _ = buf.Write(meta)
			_, _ = buf.Write(data)
		} else {
			return fmt.Errorf("type does not implement the types.AuditRecord interface: %#v", qmsg)
		}
	}

	// send off the bulk data
	res, err := w.client.Bulk(bytes.NewReader(buf.Bytes()), w.client.Bulk.WithIndex(indexName))
	if err != nil {
		log.Fatalf("Failure indexing batch: %s", err)
	}

	// if the whole request failed, print error and mark all documents as failed
	if res.IsError() {
		var raw map[string]interface{}
		if err = json.NewDecoder(res.Body).Decode(&raw); err != nil {
			log.Fatalf("Failure to to parse response body: %s", err)
		} else {
			log.Printf("  Error: [%d] %s: %s",
				res.StatusCode,
				raw["error"].(map[string]interface{})["type"],
				raw["error"].(map[string]interface{})["reason"],
			)
		}
	} else {
		// a successful response might still contain errors for particular documents...
		var blk *bulkResponse
		if err = json.NewDecoder(res.Body).Decode(&blk); err != nil {
			log.Fatalf("Failure to to parse response body: %s", err)
		} else {
			for _, d := range blk.Items {
				// for any HTTP status above 201
				if d.Index.Status > 201 {
					log.Printf("  Error: [%d]: %s: %s: %s: %s",
						d.Index.Status,
						d.Index.Error.Type,
						d.Index.Error.Reason,
						d.Index.Error.Cause.Type,
						d.Index.Error.Cause.Reason,
					)
				}
			}
		}
	}

	// close the response body, to prevent reaching the limit for goroutines or file handles
	_ = res.Body.Close()

	fmt.Println("sent", len(w.queue), w.wc.Name, "audit records to elastic")

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
	err := w.sendBulk()
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
