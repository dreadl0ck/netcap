package tcp

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sync/atomic"

	"github.com/dreadl0ck/netcap/internal/aggregate"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/packetmeta"
	"github.com/dreadl0ck/netcap/internal/packetview"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/gopacket/gopacket"
)

type storedTCPReader struct {
	state                 *aggregate.Store
	prefix                string
	count                 uint64
	loaded                bool
	budget                *core.StateBudget
	payloadBudget         *retainedPayloadBudget
	credit, payloadCredit int64
}

type storedTCPFragment struct {
	Capture, Context           []byte
	Link, Network, Transport   reassembly.FlowState
	HasContext, NilPayload     bool
	Direction                  reassembly.TCPFlowDirection
	Skipped                    int
	Discarded                  int64
	DiscardReason, Observation string
}

var tcpReaderSequence atomic.Uint64

func encodeTCPFragment(data *core.StreamData) ([]byte, error) {
	s := storedTCPFragment{Direction: data.Dir, Skipped: data.SkippedBytes, Discarded: data.DiscardedBytes,
		DiscardReason: data.DiscardReason, Observation: data.TCPObservation, NilPayload: data.RawData == nil,
		Network: reassembly.SaveFlow(data.Net), Transport: reassembly.SaveFlow(data.Trans)}
	var err error
	s.Capture, err = packetmeta.Marshal(data.CaptureInformation)
	if err != nil {
		return nil, err
	}
	if data.Context() != nil {
		s.HasContext = true
		s.Context, err = packetmeta.Marshal(data.Context().GetCaptureInfo())
		if err != nil {
			return nil, err
		}
		if linked, ok := data.Context().(interface{ GetLinkFlow() gopacket.Flow }); ok {
			s.Link = reassembly.SaveFlow(linked.GetLinkFlow())
		}
	}
	meta, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	wire := binary.AppendUvarint(nil, uint64(len(meta)))
	wire = append(wire, meta...)
	return append(wire, data.RawData...), nil
}

func decodeTCPFragment(wire []byte) (*core.StreamData, error) {
	size, n := binary.Uvarint(wire)
	if n <= 0 || size > uint64(len(wire)-max(n, 0)) {
		return nil, fmt.Errorf("invalid retained TCP fragment framing")
	}
	var s storedTCPFragment
	if err := json.Unmarshal(wire[n:n+int(size)], &s); err != nil {
		return nil, err
	}
	ci, err := packetmeta.Unmarshal(s.Capture)
	if err != nil {
		return nil, err
	}
	network, err := s.Network.Restore()
	if err != nil {
		return nil, err
	}
	transport, err := s.Transport.Restore()
	if err != nil {
		return nil, err
	}
	payload := wire[n+int(size):]
	if s.NilPayload {
		if len(payload) != 0 {
			return nil, fmt.Errorf("nil retained TCP payload carries bytes")
		}
		payload = nil
	}
	data := &core.StreamData{RawData: payload, CaptureInformation: ci, Net: network, Trans: transport, Dir: s.Direction,
		SkippedBytes: s.Skipped, DiscardedBytes: s.Discarded, DiscardReason: s.DiscardReason, TCPObservation: s.Observation}
	if s.HasContext {
		capture, err := packetmeta.Unmarshal(s.Context)
		if err != nil {
			return nil, err
		}
		link, err := s.Link.Restore()
		if err != nil {
			return nil, err
		}
		scope := ""
		if view := packetview.FromCapture(capture); view != nil {
			scope = view.Scope
		}
		data.AssemblerContext = &context{CaptureInfo: capture, link: link, scope: scope}
	}
	return data, nil
}

func (s *storedTCPReader) append(data *core.StreamData) error {
	return s.state.Do(func(tx *aggregate.Tx) error {
		if s.count == ^uint64(0) {
			return fmt.Errorf("retained TCP fragment counter exhausted")
		}
		wire, err := encodeTCPFragment(data)
		if err != nil {
			return err
		}
		var credit, payloadCredit int64
		if s.loaded {
			credit = int64(len(wire)) + 256
			if err := s.budget.Reserve(credit); err != nil {
				return err
			}
			if s.payloadBudget != nil {
				payloadCredit = int64(len(data.RawData))
				if !s.payloadBudget.reserve(payloadCredit) {
					s.budget.Release(credit)
					return fmt.Errorf("TCP backing-reader payload materialization budget exceeded")
				}
			}
		}
		if err := tx.Put(fmt.Sprintf("%s%016x", s.prefix, s.count), wire); err != nil {
			s.budget.Release(credit)
			if s.payloadBudget != nil {
				s.payloadBudget.release(payloadCredit)
			}
			return err
		}
		s.credit += credit
		s.payloadCredit += payloadCredit
		s.count++
		return nil
	})
}

func (s *storedTCPReader) read() (core.DataFragments, error) {
	var data core.DataFragments
	credit, payloadCredit := int64(0), int64(0)
	err := s.state.Do(func(tx *aggregate.Tx) error {
		err := tx.Each(s.prefix, func(key string, wire []byte) error {
			if key != fmt.Sprintf("%s%016x", s.prefix, len(data)) {
				return fmt.Errorf("retained TCP fragment sequence is incomplete")
			}
			amount := int64(len(wire)) + 256
			if err := s.budget.Reserve(amount); err != nil {
				return err
			}
			credit += amount
			fragment, err := decodeTCPFragment(wire)
			if err != nil {
				return err
			}
			if s.payloadBudget != nil {
				n := int64(len(fragment.RawData))
				if !s.payloadBudget.reserve(n) {
					return fmt.Errorf("TCP backing-reader payload materialization budget exceeded")
				}
				payloadCredit += n
			}
			data = append(data, fragment)
			return nil
		})
		if err == nil && uint64(len(data)) != s.count {
			return fmt.Errorf("retained TCP fragment count mismatch: got %d, want %d", len(data), s.count)
		}
		return err
	})
	if err != nil {
		s.budget.Release(credit)
		if s.payloadBudget != nil {
			s.payloadBudget.release(payloadCredit)
		}
		return nil, err
	}
	s.credit, s.payloadCredit = credit, payloadCredit
	return data, err
}

func (s *storedTCPReader) clear() error {
	s.budget.Release(s.credit)
	if s.payloadBudget != nil {
		s.payloadBudget.release(s.payloadCredit)
	}
	s.credit, s.payloadCredit = 0, 0
	err := s.state.Do(func(tx *aggregate.Tx) error { return tx.Delete(s.prefix) })
	if err == nil {
		s.count, s.loaded = 0, false
	}
	return err
}
