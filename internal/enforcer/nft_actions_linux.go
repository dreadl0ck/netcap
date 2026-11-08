//go:build linux

package enforcer

import (
	"errors"
	"strconv"
	"strings"
)

func actionComment(l Lease) string {
	s := "netcap-lease:" + l.ID
	a := l.Action
	if a == (Action{}) {
		return s
	}
	code := map[ActionKind]string{BlockSource: "b", Quarantine: "q", RateSource: "r", RedirectSource: "n", DropFlow: "d", RejectFlow: "j"}[a.Kind]
	if a.Kind == DropFlow || a.Kind == RejectFlow {
		return s + "|" + code + "|" + a.Flow.Destination + "|" + strconv.Itoa(int(a.Flow.SourcePort))
	}
	return s + "|" + code + "|" + a.Profile
}

func (b *NFTBackend) parseAction(parts []string) (Action, error) {
	if len(parts) == 0 {
		return Action{}, nil
	}
	if len(parts) != 2 && len(parts) != 3 {
		return Action{}, errors.New("invalid action metadata")
	}
	k := map[string]ActionKind{"b": BlockSource, "q": Quarantine, "r": RateSource, "n": RedirectSource, "d": DropFlow, "j": RejectFlow}[parts[0]]
	if k == "" {
		return Action{}, errors.New("unknown action metadata")
	}
	a := Action{Kind: k}
	if k == DropFlow || k == RejectFlow {
		if len(parts) != 3 {
			return a, errors.New("incomplete flow metadata")
		}
		port, err := strconv.ParseUint(parts[2], 10, 16)
		if err != nil || strconv.FormatUint(port, 10) != parts[2] {
			return a, errors.New("invalid flow port")
		}
		a.Flow = Flow{Destination: parts[1], Protocol: b.config.Scope.Protocol, SourcePort: uint16(port), DestinationPort: b.config.Scope.Port}
	} else {
		if len(parts) != 2 || strings.Contains(parts[1], "|") {
			return a, errors.New("invalid profile metadata")
		}
		a.Profile = parts[1]
	}
	return a, nil
}
