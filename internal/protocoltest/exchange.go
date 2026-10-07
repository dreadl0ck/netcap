package protocoltest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

type Step struct {
	Name            string `json:"name"`
	Send            []byte `json:"send,omitempty"`
	SendPresent     bool   `json:"sendPresent,omitempty"`
	Receive         bool   `json:"receive"`
	Expect          []byte `json:"expect,omitempty"`
	ExpectPresent   bool   `json:"expectPresent,omitempty"`
	Contains        []byte `json:"contains,omitempty"`
	CaptureVariable string `json:"captureVariable,omitempty"`
	CaptureOffset   int    `json:"captureOffset,omitempty"`
	CaptureLength   int    `json:"captureLength,omitempty"`
	SendVariable    string `json:"sendVariable,omitempty"`
}

type Exchange struct {
	ServerTLS             *ServerTLS `json:"serverTLS,omitempty"`
	PeerCertificateSHA256 string     `json:"peerCertificateSHA256,omitempty"`
	Version               int        `json:"version"`
	Network               string     `json:"network"`
	Address               string     `json:"address"`
	TLS                   bool       `json:"tls"`
	ServerName            string     `json:"serverName,omitempty"`
	RootCAFile            string     `json:"rootCAFile,omitempty"`
	ClientCertificateFile string     `json:"clientCertificateFile,omitempty"`
	ClientKeyFile         string     `json:"clientKeyFile,omitempty"`
	Framing               Framing    `json:"framing"`
	TimeoutMilliseconds   int        `json:"timeoutMilliseconds"`
	MaxTotalBytes         int        `json:"maxTotalBytes"`
	Steps                 []Step     `json:"steps"`
}

type Observation struct {
	Step        int    `json:"step"`
	Name        string `json:"name"`
	Direction   string `json:"direction"`
	TimestampNs string `json:"timestampNs"`
	Bytes       []byte `json:"bytes"`
	SHA256      string `json:"sha256"`
}

type Result struct {
	Version             int           `json:"version"`
	ConfigurationSHA256 string        `json:"configurationSHA256"`
	Address             string        `json:"address"`
	LocalAddress        string        `json:"localAddress,omitempty"`
	RemoteAddress       string        `json:"remoteAddress,omitempty"`
	TLSVersion          uint16        `json:"tlsVersion,omitempty"`
	TLSCipher           uint16        `json:"tlsCipher,omitempty"`
	Status              string        `json:"status"`
	Error               string        `json:"error,omitempty"`
	Observations        []Observation `json:"observations"`
	Limitations         []string      `json:"limitations"`
}

func (e Exchange) Validate() error {
	if e.Version != 1 || (e.Network != "tcp" && e.Network != "udp") {
		return fmt.Errorf("version 1 and TCP/UDP required")
	}
	if _, _, err := net.SplitHostPort(e.Address); err != nil {
		return err
	}
	if e.TimeoutMilliseconds < 1 || e.TimeoutMilliseconds > 300000 || e.MaxTotalBytes < 1 || e.MaxTotalBytes > 16<<20 || len(e.Steps) < 1 || len(e.Steps) > 256 {
		return fmt.Errorf("invalid exchange limits")
	}
	if e.TLS && e.Network != "tcp" {
		return fmt.Errorf("TLS requires TCP")
	}
	if !e.TLS && (e.ServerTLS != nil || e.PeerCertificateSHA256 != "") {
		return fmt.Errorf("certificate configuration requires TLS")
	}
	if !e.TLS && (e.RootCAFile != "" || e.ClientCertificateFile != "" || e.ClientKeyFile != "" || e.ServerName != "") {
		return fmt.Errorf("TLS settings require tls=true")
	}
	if (e.ClientCertificateFile == "") != (e.ClientKeyFile == "") {
		return fmt.Errorf("both client certificate and key are required")
	}
	if e.Network == "tcp" {
		if err := e.Framing.Validate(); err != nil {
			return err
		}
	} else if e.Framing.MaxBytes < 1 || e.Framing.MaxBytes > 65507 {
		return fmt.Errorf("UDP maxBytes must be 1..65507")
	}
	for _, step := range e.Steps {
		if !step.SendPresent && len(step.Send) == 0 && step.SendVariable == "" && !step.Receive {
			return fmt.Errorf("empty experiment step")
		}
		if len(step.Send) > e.Framing.MaxBytes || len(step.Expect) > e.Framing.MaxBytes || len(step.Contains) > e.Framing.MaxBytes {
			return fmt.Errorf("step exceeds frame budget")
		}
		if step.CaptureOffset < 0 || step.CaptureLength < 0 || step.CaptureLength > e.Framing.MaxBytes {
			return fmt.Errorf("invalid capture range")
		}
		if !step.Receive && (step.ExpectPresent || len(step.Expect) > 0 || len(step.Contains) > 0 || step.CaptureVariable != "") {
			return fmt.Errorf("receive assertions require receive=true")
		}
	}
	return nil
}

func Run(ctx context.Context, exchange Exchange) (result Result, runErr error) {
	result = Result{Version: 1, Address: exchange.Address, Status: "error", Observations: []Observation{}, Limitations: []string{"matching responses demonstrate protocol observations, not endpoint execution or authorization effects", "captured variables replay fresh response bytes; application lengths/checksums remain specified by the experiment"}}
	defer func() {
		if runErr != nil {
			result.Error = runErr.Error()
		}
	}()
	if err := exchange.Validate(); err != nil {
		return result, err
	}
	if exchange.ServerTLS != nil {
		return result, fmt.Errorf("serverTLS is only supported by server emulation")
	}
	configuration, err := json.Marshal(exchange)
	if err != nil {
		return result, err
	}
	digest := sha256.Sum256(configuration)
	result.ConfigurationSHA256 = hex.EncodeToString(digest[:])
	ctx, cancel := context.WithTimeout(ctx, time.Duration(exchange.TimeoutMilliseconds)*time.Millisecond)
	defer cancel()
	dialer := net.Dialer{}
	var conn net.Conn
	if exchange.TLS {
		config := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: exchange.ServerName}
		if err := setPeerPin(config, exchange.PeerCertificateSHA256); err != nil {
			return result, err
		}
		if exchange.RootCAFile != "" {
			config.RootCAs, err = loadTrust(exchange.RootCAFile)
			if err != nil {
				return result, err
			}
		}
		if exchange.ClientCertificateFile != "" {
			certificate, err := loadIdentity(exchange.ClientCertificateFile, exchange.ClientKeyFile)
			if err != nil {
				return result, err
			}
			config.Certificates = []tls.Certificate{certificate}
		}
		d := tls.Dialer{NetDialer: &dialer, Config: config}
		conn, err = d.DialContext(ctx, "tcp", exchange.Address)
	} else {
		conn, err = dialer.DialContext(ctx, exchange.Network, exchange.Address)
	}
	if err != nil {
		return result, err
	}
	defer conn.Close()
	return runConnection(ctx, conn, exchange, result)
}

func runConnection(ctx context.Context, conn net.Conn, exchange Exchange, result Result) (Result, error) {
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return result, err
	}
	result.LocalAddress, result.RemoteAddress = conn.LocalAddr().String(), conn.RemoteAddr().String()
	if tlsConn, ok := conn.(*tls.Conn); ok {
		state := tlsConn.ConnectionState()
		result.TLSVersion, result.TLSCipher = state.Version, state.CipherSuite
	}
	var err error
	total := 0
	variables := map[string][]byte{}
	record := func(index int, name, direction string, data []byte) {
		digest := sha256.Sum256(data)
		result.Observations = append(result.Observations, Observation{Step: index, Name: name, Direction: direction, TimestampNs: fmt.Sprint(time.Now().UnixNano()), Bytes: append([]byte(nil), data...), SHA256: hex.EncodeToString(digest[:])})
	}
	for index, step := range exchange.Steps {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		if step.SendPresent || len(step.Send) > 0 || step.SendVariable != "" {
			data := append([]byte(nil), step.Send...)
			if step.SendVariable != "" {
				value, ok := variables[step.SendVariable]
				if !ok {
					return result, fmt.Errorf("undefined response variable %q", step.SendVariable)
				}
				data = append(data, value...)
			}
			if len(data) > exchange.Framing.MaxBytes || len(data) > exchange.MaxTotalBytes-total {
				return result, fmt.Errorf("send byte budget exceeded")
			}
			n := 0
			if exchange.Network == "udp" {
				n, err = conn.Write(data)
			} else {
				for n < len(data) {
					written, werr := conn.Write(data[n:])
					n += written
					if werr != nil {
						err = werr
						break
					}
					if written == 0 {
						err = io.ErrShortWrite
						break
					}
				}
			}
			record(index, step.Name, "sent", data[:n])
			total += n
			if err != nil {
				return result, err
			}
			if n != len(data) {
				return result, io.ErrShortWrite
			}
		}
		if step.Receive {
			var data []byte
			if exchange.Framing.MaxBytes > exchange.MaxTotalBytes-total {
				return result, fmt.Errorf("receive byte budget exhausted")
			}
			if exchange.Network == "udp" {
				buffer := make([]byte, exchange.Framing.MaxBytes+1)
				var n int
				n, err = conn.Read(buffer)
				data = buffer[:n]
				if n > exchange.Framing.MaxBytes {
					err = fmt.Errorf("UDP datagram exceeds maxBytes")
				}
			} else {
				data, err = exchange.Framing.Read(conn)
			}
			record(index, step.Name, "received", data)
			total += len(data)
			if err != nil {
				return result, err
			}
			if (step.ExpectPresent || len(step.Expect) > 0) && !bytes.Equal(data, step.Expect) {
				return result, fmt.Errorf("step %d response mismatch", index)
			}
			if len(step.Contains) > 0 && !bytes.Contains(data, step.Contains) {
				return result, fmt.Errorf("step %d expected marker absent", index)
			}
			if step.CaptureVariable != "" {
				if step.CaptureOffset > len(data) || step.CaptureLength > len(data)-step.CaptureOffset {
					return result, fmt.Errorf("response capture exceeds frame")
				}
				variables[step.CaptureVariable] = append([]byte(nil), data[step.CaptureOffset:step.CaptureOffset+step.CaptureLength]...)
			}
		}
	}
	result.Status = "matched"
	return result, nil
}

func boundedFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("input file exceeds size limit")
	}
	return data, nil
}
