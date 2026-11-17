package tcp

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
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
	completionBudget      *core.StateBudget
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
	if s.count >= math.MaxInt64 {
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
				return fmt.Errorf("backing-reader payload materialization: %w", ErrRetainedPayloadLimit)
			}
		}
	}
	err = s.state.Do(func(tx *aggregate.Tx) error { return tx.Put(fmt.Sprintf("%s%016x", s.prefix, s.count), wire) })
	if err != nil {
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
}

func (s *storedTCPReader) Count() int64 { return int64(s.count) }

func (s *storedTCPReader) readBudget() *core.StateBudget {
	if s.completionBudget != nil {
		return s.completionBudget
	}
	return s.budget
}

// A pass borrows one decoded fragment; consumers retaining it must copy its bytes.
func (s *storedTCPReader) Walk(yield func(core.DataFragment) bool) error {
	return s.WalkRange(0, s.Count(), yield)
}

func (s *storedTCPReader) WalkRange(start, length int64, yield func(core.DataFragment) bool) error {
	if err := core.CheckFragmentRange(s.Count(), start, length); err != nil {
		return err
	}
	count := s.count
	budget := s.readBudget()
	for index := uint64(start); index < uint64(start+length); index++ {
		if s.count != count {
			return fmt.Errorf("retained TCP source changed during iteration")
		}
		key := fmt.Sprintf("%s%016x", s.prefix, index)
		var wire []byte
		err := s.state.Do(func(tx *aggregate.Tx) error {
			var exists bool
			var err error
			wire, exists, err = tx.Get(key)
			if err == nil && !exists {
				return fmt.Errorf("retained TCP fragment sequence is incomplete")
			}
			return err
		})
		if err != nil {
			return err
		}
		credit := int64(len(wire)) + 256
		if err := budget.Reserve(credit); err != nil {
			return err
		}
		more, err := func() (bool, error) {
			defer budget.Release(credit)
			fragment, err := decodeTCPFragment(wire)
			if err != nil {
				return false, s.state.Do(func(*aggregate.Tx) error { return err })
			}
			if s.payloadBudget != nil {
				amount := int64(len(fragment.RawData))
				if !s.payloadBudget.reserve(amount) {
					return false, fmt.Errorf("backing-reader payload iteration: %w", ErrRetainedPayloadLimit)
				}
				defer s.payloadBudget.release(amount)
			}
			return yield(fragment), nil
		}()
		if err != nil || !more {
			return err
		}
	}
	if s.count != count {
		return fmt.Errorf("retained TCP source changed during iteration")
	}
	if start != 0 || uint64(length) != count {
		return nil
	}
	return s.state.Do(func(tx *aggregate.Tx) error {
		last := ""
		if count > 0 {
			last = fmt.Sprintf("%s%016x", s.prefix, count-1)
		}
		_, _, exists, err := tx.Next(s.prefix, last)
		if err == nil && exists {
			return fmt.Errorf("retained TCP fragment count mismatch")
		}
		return err
	})
}

func (s *storedTCPReader) read() (core.DataFragments, error) {
	var data core.DataFragments
	budget := s.readBudget()
	credit, payloadCredit := int64(0), int64(0)
	read := func() error {
		last := ""
		for {
			var rows []aggregate.Row
			err := s.state.Do(func(tx *aggregate.Tx) error {
				var err error
				rows, err = tx.NextBatch(s.prefix, last)
				return err
			})
			if err != nil {
				return err
			}
			if len(rows) == 0 {
				break
			}
			for _, row := range rows {
				key, wire := row.Key, row.Value
				if key != fmt.Sprintf("%s%016x", s.prefix, len(data)) {
					return s.state.Do(func(*aggregate.Tx) error { return fmt.Errorf("retained TCP fragment sequence is incomplete") })
				}
				amount := int64(len(wire)) + 256
				if err := budget.Reserve(amount); err != nil {
					return err
				}
				credit += amount
				fragment, err := decodeTCPFragment(wire)
				if err != nil {
					return s.state.Do(func(*aggregate.Tx) error { return err })
				}
				if s.payloadBudget != nil {
					n := int64(len(fragment.RawData))
					if !s.payloadBudget.reserve(n) {
						return fmt.Errorf("backing-reader payload materialization: %w", ErrRetainedPayloadLimit)
					}
					payloadCredit += n
				}
				data = append(data, fragment)
				last = key
			}
		}
		if uint64(len(data)) != s.count {
			return s.state.Do(func(*aggregate.Tx) error {
				return fmt.Errorf("retained TCP fragment count mismatch: got %d, want %d", len(data), s.count)
			})
		}
		return nil
	}
	err := read()
	if err != nil {
		budget.Release(credit)
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
