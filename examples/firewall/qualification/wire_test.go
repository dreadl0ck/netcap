//go:build coraza && http3

package main

import (
	"context"
	"testing"
)

func TestRealWireProfilesRejectBeforeOriginAndContinue(t *testing.T) {
	for _, protocol := range []string{"dns", "redis", "postgres", "mysql", "smtp", "modbus", "dnp3", "websocket", "grpc"} {
		t.Run(protocol, func(t *testing.T) {
			var p *profile
			var err error
			if protocol == "dns" {
				p, err = newDNSProfile(context.Background())
			} else if protocol == "websocket" || protocol == "grpc" {
				p, err = newMessageProfile(context.Background(), protocol)
			} else {
				p, err = newTCPProfile(context.Background(), protocol)
			}
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			for _, attack := range []bool{true, false, true, false} {
				w := training[0]
				want := 200
				if attack {
					w.Body = forbidden
					want = 403
				}
				status, _, err := p.request(w)
				if err != nil || status != want {
					t.Fatalf("attack=%v status=%d err=%v", attack, status, err)
				}
				if err = checkLedger(p.Ledger); err != nil {
					t.Fatal(err)
				}
			}
			if p.Ledger.Requests.Load() == 0 || p.Ledger.Bytes.Load() == 0 {
				t.Fatal("allowed flow never reached origin")
			}
		})
	}
}
