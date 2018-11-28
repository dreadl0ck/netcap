/*
 * NETCAP - Network Capture Toolkit
 * Copyright (c) 2017 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package encoder

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/types"
	"github.com/golang/protobuf/proto"
	"github.com/google/gopacket"
	"github.com/google/kythe/kythe/go/platform/delimited"
)

var (
	CustomEncoders     = []*CustomEncoder{}
	customEncoderSlice = []*CustomEncoder{
		TLSEncoder,
		LinkFlowEncoder,
		NetworkFlowEncoder,
		TransportFlowEncoder,
		HTTPEncoder,
		FlowEncoder,
		ConnectionEncoder,
	}
)

type (
	CustomEncoderHandler = func(p gopacket.Packet) proto.Message

	CustomEncoder struct {

		// Public
		Name string
		Type types.Type

		// Private
		file      *os.File
		bWriter   *bufio.Writer
		gWriter   *gzip.Writer
		dWriter   *delimited.Writer
		aWriter   *AtomicDelimitedWriter
		cWriter   *chanWriter
		csvWriter *csvWriter

		Handler  CustomEncoderHandler
		postinit func(*CustomEncoder) error
		deinit   func(*CustomEncoder) error

		// Config
		compress bool
		buffer   bool
		csv      bool
		out      string
	}
)

func init() {
	for _, e := range customEncoderSlice {
		allEncoderNames[e.Name] = struct{}{}
	}
	for _, e := range layerEncoderSlice {
		allEncoderNames[e.Layer.String()] = struct{}{}
	}
}

func InitCustomEncoders(c Config) {

	var (
		in        = strings.Split(c.IncludeEncoders, ",")
		ex        = strings.Split(c.ExcludeEncoders, ",")
		inMap     = make(map[string]bool)
		selection []*CustomEncoder
	)

	if len(in) > 0 && in[0] != "" {

		for _, name := range in {
			if name != "" {
				// check if proto exists
				if _, ok := allEncoderNames[name]; !ok {
					invalidProto(name)
				}
				inMap[name] = true
			}
		}

		for _, e := range customEncoderSlice {
			if _, ok := inMap[e.Name]; ok {
				selection = append(selection, e)
			}
		}
		customEncoderSlice = selection
	}

	for _, name := range ex {
		if name != "" {
			// check if proto exists
			if _, ok := allEncoderNames[name]; !ok {
				invalidProto(name)
			}
			for i, e := range customEncoderSlice {
				if name == e.Name {
					// remove encoder
					customEncoderSlice = append(customEncoderSlice[:i], customEncoderSlice[i+1:]...)
					break
				}
			}
		}
	}

	for _, e := range customEncoderSlice {
		// fmt.Println("init custom encoder", d.name)
		e.Init(c.Buffer, c.Compression, c.CSV, c.Out, c.WriteChan)
		if e.postinit != nil {
			err := e.postinit(e)
			if err != nil {
				panic(err)
			}
		}

		// write header
		if e.csv {
			_, err := e.csvWriter.WriteHeader(netcap.InitRecord(e.Type))
			if err != nil {
				panic(err)
			}
		} else {
			err := e.aWriter.PutProto(NewHeader(e.Type, c))
			if err != nil {
				fmt.Println("failed to write header")
				panic(err)
			}
		}

		CustomEncoders = append(CustomEncoders, e)
	}
	fmt.Println("initialized", len(CustomEncoders), "custom encoders | buffer size:", BlockSize)
}

func CreateCustomEncoder(t types.Type, name string, postinit func(*CustomEncoder) error, handler CustomEncoderHandler, deinit func(*CustomEncoder) error) *CustomEncoder {
	return &CustomEncoder{
		Name:     name,
		Handler:  handler,
		deinit:   deinit,
		postinit: postinit,
		Type:     t,
	}
}

// Encode is called for each layer
// this calls the handler function of the encoder
// and writes the serialized protobuf into the data pipe
func (d *CustomEncoder) Encode(p gopacket.Packet) error {
	decoded := d.Handler(p)
	if decoded != nil {
		err := d.aWriter.PutProto(decoded)
		if err != nil {
			return err
		}
	}
	return nil
}

func (d *CustomEncoder) Init(buffer, compress, csv bool, out string, writeChan bool) {

	d.compress = compress
	d.buffer = buffer
	d.csv = csv
	d.out = out

	if csv {

		// create file
		if compress {
			d.file = CreateFile(filepath.Join(out, d.Name), ".csv.gz")
		} else {
			d.file = CreateFile(filepath.Join(out, d.Name), ".csv")
		}

		if buffer {

			d.bWriter = bufio.NewWriterSize(d.file, BlockSize)

			if compress {
				d.gWriter = gzip.NewWriter(d.bWriter)
				d.csvWriter = NewCSVWriter(d.gWriter)
			} else {
				d.csvWriter = NewCSVWriter(d.bWriter)
			}
		} else {
			if compress {
				d.gWriter = gzip.NewWriter(d.file)
				d.csvWriter = NewCSVWriter(d.gWriter)
			} else {
				d.csvWriter = NewCSVWriter(d.file)
			}
		}
		return
	}

	if writeChan && buffer || writeChan && compress {
		panic("buffering or compression cannot be activated when running using writeChan")
	}

	// write into channel OR into file
	if writeChan {
		d.cWriter = newChanWriter()
	} else {
		if compress {
			d.file = CreateFile(filepath.Join(out, d.Name), ".ncap.gz")
		} else {
			d.file = CreateFile(filepath.Join(out, d.Name), ".ncap")
		}
	}

	// buffer data?
	if buffer {

		d.bWriter = bufio.NewWriterSize(d.file, BlockSize)
		if compress {
			d.gWriter = gzip.NewWriter(d.bWriter)
			d.dWriter = delimited.NewWriter(d.gWriter)
		} else {
			d.dWriter = delimited.NewWriter(d.bWriter)
		}
	} else {
		if compress {
			d.gWriter = gzip.NewWriter(d.file)
			d.dWriter = delimited.NewWriter(d.gWriter)
		} else {
			if writeChan {
				// write into channel writer without compression
				d.dWriter = delimited.NewWriter(d.cWriter)
			} else {
				d.dWriter = delimited.NewWriter(d.file)
			}
		}
	}
	d.aWriter = NewAtomicDelimitedWriter(d.dWriter)
}

func (d *CustomEncoder) Destroy() (name string, size int64) {
	if d.deinit != nil {
		err := d.deinit(d)
		if err != nil {
			panic(err)
		}
	}
	if d.compress {
		CloseGzipWriters(d.gWriter)
	}
	if d.buffer {
		FlushWriters(d.bWriter)
	}
	return CloseFile(d.out, d.file, d.Name)
}

func (d *CustomEncoder) GetChan() <-chan []byte {
	return d.cWriter.Chan()
}
