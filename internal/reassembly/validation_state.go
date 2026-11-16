package reassembly

import (
	"fmt"
	"time"

	"github.com/gopacket/gopacket"
)

type TimeState struct {
	Seconds int64
	Nanos   int
	Present bool
}

func SaveTime(t time.Time) TimeState {
	return TimeState{Seconds: t.Unix(), Nanos: t.Nanosecond(), Present: !t.IsZero()}
}

func (s TimeState) Restore() (time.Time, error) {
	if !s.Present {
		return time.Time{}, nil
	}
	if s.Nanos < 0 || s.Nanos >= 1_000_000_000 {
		return time.Time{}, fmt.Errorf("invalid stored timestamp")
	}
	return time.Unix(s.Seconds, int64(s.Nanos)), nil
}

type FlowState struct {
	Type     int64
	Src, Dst []byte
}

func SaveFlow(flow gopacket.Flow) FlowState {
	return FlowState{Type: int64(flow.EndpointType()), Src: append([]byte(nil), flow.Src().Raw()...), Dst: append([]byte(nil), flow.Dst().Raw()...)}
}

func (f FlowState) Restore() (gopacket.Flow, error) {
	if len(f.Src) > 16 || len(f.Dst) > 16 || f.Type < 0 {
		return gopacket.Flow{}, fmt.Errorf("invalid stored flow")
	}
	return gopacket.NewFlow(gopacket.EndpointType(f.Type), f.Src, f.Dst), nil
}

type TCPValidationOptions struct {
	MSS, Scale int
	Window     uint
}

type TCPValidationState struct {
	State                int
	Direction            TCPFlowDirection
	MissingEstablishment bool
	Options              [2]TCPValidationOptions
}

func SaveTCPValidation(fsm *TCPSimpleFSM, check TCPOptionCheck) TCPValidationState {
	s := TCPValidationState{State: fsm.state, Direction: fsm.dir, MissingEstablishment: fsm.options.SupportMissingEstablishment}
	for i, option := range check.options {
		s.Options[i] = TCPValidationOptions{MSS: option.mss, Scale: option.scale, Window: option.receiveWindow}
	}
	return s
}

func (s TCPValidationState) Restore() (*TCPSimpleFSM, TCPOptionCheck, error) {
	check := NewTCPOptionCheck()
	if s.State < TCPStateClosed || s.State > TCPStateReset {
		return nil, check, fmt.Errorf("invalid stored TCP FSM state")
	}
	for i, option := range s.Options {
		if option.MSS < -1 || option.MSS > 65535 || option.Scale < -1 || option.Scale > 14 || option.Window > 65535<<14 {
			return nil, check, fmt.Errorf("invalid stored TCP options")
		}
		check.options[i] = tcpStreamOptions{mss: option.MSS, scale: option.Scale, receiveWindow: option.Window}
	}
	return &TCPSimpleFSM{state: s.State, dir: s.Direction, options: TCPSimpleFSMOptions{SupportMissingEstablishment: s.MissingEstablishment}}, check, nil
}
