/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package webui

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	stdio "io"
	"os"
	"time"

	"github.com/gopacket/gopacket/pcap"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/dreadl0ck/netcap/collector"
)

// filterPCAPToFile reads inputFile (pcap or pcapng), keeps only the packets
// matching the BPF expression, and writes them to outputFile as a standard
// pcap, entirely in-process. It shells out to nothing — no tcpdump, no os/exec
// — which is what lets the App Store edition offer these downloads under the
// App Sandbox. The BPF semantics are libpcap's own (pcap.NewBPF), so they are
// the semantics the tcpdump path had.
//
// It returns the number of packets written. A zero count with a nil error
// means the filter matched nothing; callers treat that as "no packets found",
// exactly as they did with an empty tcpdump output file.
func filterPCAPToFile(inputFile, bpfExpr, outputFile string) (int, error) {
	return filterPCAPToFileContext(context.Background(), inputFile, bpfExpr, outputFile)
}

func filterPCAPToFileWithTimeout(parent context.Context, inputFile, bpfExpr, outputFile string, timeout time.Duration) (int, error) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	return filterPCAPToFileContext(ctx, inputFile, bpfExpr, outputFile)
}

func filterPCAPToFileContext(ctx context.Context, inputFile, bpfExpr, outputFile string) (int, error) {
	reader, err := collector.OpenCapture(inputFile)
	if err != nil {
		return 0, err
	}
	defer reader.Close()

	linkType := reader.LinkType()

	// Compile the BPF against the capture's own link type so offsets match,
	// exactly as tcpdump does when reading the file.
	bpf, err := pcap.NewBPF(linkType, 262144, bpfExpr)
	if err != nil {
		return 0, fmt.Errorf("compile bpf %q: %w", bpfExpr, err)
	}

	out, err := os.Create(outputFile)
	if err != nil {
		return 0, fmt.Errorf("create output: %w", err)
	}
	buffered := bufio.NewWriter(out)

	writer := pcapgo.NewWriter(buffered)
	if err = writer.WriteFileHeader(262144, linkType); err != nil {
		out.Close()
		os.Remove(outputFile)
		return 0, fmt.Errorf("write pcap header: %w", err)
	}

	written := 0
	for {
		if err := ctx.Err(); err != nil {
			out.Close()
			os.Remove(outputFile)
			return 0, err
		}

		data, ci, rerr := reader.ReadPacketData()
		if rerr == stdio.EOF {
			break
		}
		if rerr != nil {
			out.Close()
			os.Remove(outputFile)
			return 0, fmt.Errorf("read packet: %w", rerr)
		}
		if !bpf.Matches(ci, data) {
			continue
		}
		if werr := writer.WritePacket(ci, data); werr != nil {
			out.Close()
			os.Remove(outputFile)
			return 0, fmt.Errorf("write packet: %w", werr)
		}
		written++
	}

	if err = buffered.Flush(); err != nil {
		out.Close()
		os.Remove(outputFile)
		return 0, fmt.Errorf("flush output: %w", err)
	}
	if err = out.Close(); err != nil {
		os.Remove(outputFile)
		return 0, fmt.Errorf("close output: %w", err)
	}

	// Nothing matched: drop the header-only file so callers see no artifact,
	// matching tcpdump's empty-output behaviour the handlers relied on.
	if written == 0 {
		os.Remove(outputFile)
	}

	return written, nil
}

func isPCAPFilterTimeout(err error) bool {
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
}
