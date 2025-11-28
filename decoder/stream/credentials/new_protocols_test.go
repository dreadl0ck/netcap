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

package credentials

import (
	"encoding/binary"
	"testing"
	"time"
)

// TestRADIUSHarvester tests the RADIUS credential harvester
func TestRADIUSHarvester(t *testing.T) {
	tests := []struct {
		name           string
		data           []byte
		expectCreds    bool
		expectUser     string
		expectService  string
		expectAuthSet  bool
		expectSuccess  bool
	}{
		{
			name:        "Empty packet",
			data:        []byte{},
			expectCreds: false,
		},
		{
			name:        "Too short packet",
			data:        []byte{0x01, 0x00, 0x00, 0x14},
			expectCreds: false,
		},
		{
			name:          "Valid Access-Request with username",
			data:          buildRADIUSAccessRequest("testuser"),
			expectCreds:   true,
			expectUser:    "testuser",
			expectService: serviceRADIUS,
		},
		{
			name:          "Access-Accept response",
			data:          buildRADIUSAccessAccept(),
			expectCreds:   true,
			expectService: serviceRADIUS,
			expectAuthSet: true,
			expectSuccess: true,
		},
		{
			name:          "Access-Reject response",
			data:          buildRADIUSAccessReject(),
			expectCreds:   true,
			expectService: serviceRADIUS,
			expectAuthSet: true,
			expectSuccess: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			creds := radiusHarvesterFunc(tt.data, "test-flow", time.Now())

			if tt.expectCreds {
				if creds == nil {
					t.Error("Expected credentials but got nil")
					return
				}
				if tt.expectUser != "" && creds.User != tt.expectUser {
					t.Errorf("Expected user %q, got %q", tt.expectUser, creds.User)
				}
				if creds.Service != tt.expectService {
					t.Errorf("Expected service %q, got %q", tt.expectService, creds.Service)
				}
				if tt.expectAuthSet {
					if !creds.AuthSuccessSet {
						t.Error("Expected AuthSuccessSet to be true")
					}
					if creds.AuthSuccess != tt.expectSuccess {
						t.Errorf("Expected AuthSuccess %v, got %v", tt.expectSuccess, creds.AuthSuccess)
					}
				}
			} else {
				if creds != nil {
					t.Errorf("Expected no credentials but got: %+v", creds)
				}
			}
		})
	}
}

// buildRADIUSAccessRequest builds a RADIUS Access-Request packet with username
func buildRADIUSAccessRequest(username string) []byte {
	// Code: Access-Request (1)
	// Identifier: 0x01
	// Length: 20 + attributes
	// Authenticator: 16 random bytes
	// Attributes: User-Name (type=1, len=2+strlen, value=username)

	attrLen := 2 + len(username) // type(1) + len(1) + value(n)
	packetLen := 20 + attrLen

	packet := make([]byte, packetLen)
	packet[0] = radiusAccessRequest // Code
	packet[1] = 0x01                // Identifier
	binary.BigEndian.PutUint16(packet[2:4], uint16(packetLen))
	// Authenticator (bytes 4-19) - leave as zeros for test
	
	// User-Name attribute
	packet[20] = radiusAttrUserName // Type
	packet[21] = byte(attrLen)       // Length
	copy(packet[22:], []byte(username))

	return packet
}

// buildRADIUSAccessAccept builds a RADIUS Access-Accept packet
func buildRADIUSAccessAccept() []byte {
	packet := make([]byte, 20)
	packet[0] = radiusAccessAccept // Code
	packet[1] = 0x01               // Identifier
	binary.BigEndian.PutUint16(packet[2:4], 20)
	return packet
}

// buildRADIUSAccessReject builds a RADIUS Access-Reject packet
func buildRADIUSAccessReject() []byte {
	packet := make([]byte, 20)
	packet[0] = radiusAccessReject // Code
	packet[1] = 0x01               // Identifier
	binary.BigEndian.PutUint16(packet[2:4], 20)
	return packet
}

// TestSOCKSHarvester tests the SOCKS credential harvester
func TestSOCKSHarvester(t *testing.T) {
	tests := []struct {
		name           string
		data           []byte
		expectCreds    bool
		expectUser     string
		expectPass     string
		expectService  string
		expectVersion  int32
	}{
		{
			name:        "Empty packet",
			data:        []byte{},
			expectCreds: false,
		},
		{
			name:        "Too short packet",
			data:        []byte{0x01, 0x04},
			expectCreds: false,
		},
		{
			name:          "SOCKS5 Username/Password auth",
			data:          buildSOCKS5UserPassAuth("admin", "secret123"),
			expectCreds:   true,
			expectUser:    "admin",
			expectPass:    "secret123",
			expectService: serviceSOCKS,
			expectVersion: socks5Version,
		},
		{
			name:          "SOCKS4 request with username",
			data:          buildSOCKS4Request("proxyuser"),
			expectCreds:   true,
			expectUser:    "proxyuser",
			expectService: serviceSOCKS,
			expectVersion: socks4Version,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			creds := socksHarvesterFunc(tt.data, "test-flow", time.Now())

			if tt.expectCreds {
				if creds == nil {
					t.Error("Expected credentials but got nil")
					return
				}
				if tt.expectUser != "" && creds.User != tt.expectUser {
					t.Errorf("Expected user %q, got %q", tt.expectUser, creds.User)
				}
				if tt.expectPass != "" && creds.Password != tt.expectPass {
					t.Errorf("Expected password %q, got %q", tt.expectPass, creds.Password)
				}
				if creds.Service != tt.expectService {
					t.Errorf("Expected service %q, got %q", tt.expectService, creds.Service)
				}
				if creds.SocksVersion != tt.expectVersion {
					t.Errorf("Expected SOCKS version %d, got %d", tt.expectVersion, creds.SocksVersion)
				}
			} else {
				if creds != nil {
					t.Errorf("Expected no credentials but got: %+v", creds)
				}
			}
		})
	}
}

// buildSOCKS5UserPassAuth builds a SOCKS5 username/password auth request
func buildSOCKS5UserPassAuth(username, password string) []byte {
	// VER(1) + ULEN(1) + UNAME(ULEN) + PLEN(1) + PASSWD(PLEN)
	packet := make([]byte, 1+1+len(username)+1+len(password))
	packet[0] = socksUserPassVersion // Version
	packet[1] = byte(len(username))
	copy(packet[2:], []byte(username))
	packet[2+len(username)] = byte(len(password))
	copy(packet[3+len(username):], []byte(password))
	return packet
}

// buildSOCKS4Request builds a SOCKS4 CONNECT request with userid
func buildSOCKS4Request(userid string) []byte {
	// VER(1) + CMD(1) + DSTPORT(2) + DSTIP(4) + USERID(variable) + NULL(1)
	packet := make([]byte, 9+len(userid))
	packet[0] = socks4Version // VER
	packet[1] = 0x01          // CMD: CONNECT
	binary.BigEndian.PutUint16(packet[2:4], 80) // DSTPORT
	packet[4] = 192
	packet[5] = 168
	packet[6] = 1
	packet[7] = 1
	copy(packet[8:], []byte(userid))
	packet[8+len(userid)] = 0x00 // NULL terminator
	return packet
}

// TestSIPHarvester tests the SIP credential harvester
func TestSIPHarvester(t *testing.T) {
	tests := []struct {
		name           string
		data           []byte
		expectCreds    bool
		expectUser     string
		expectService  string
		expectMethod   string
	}{
		{
			name:        "Empty packet",
			data:        []byte{},
			expectCreds: false,
		},
		{
			name:          "SIP REGISTER with Digest auth",
			data:          []byte(buildSIPRegisterWithDigest("alice", "example.com")),
			expectCreds:   true,
			expectUser:    "alice",
			expectService: serviceSIP,
			expectMethod:  "REGISTER",
		},
		{
			name:          "SIP 401 Unauthorized",
			data:          []byte(buildSIP401Response()),
			expectCreds:   true,
			expectService: serviceSIP,
		},
		{
			name:          "SIP 200 OK (auth success)",
			data:          []byte(buildSIP200OKResponse()),
			expectCreds:   true,
			expectService: serviceSIP,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			creds := sipHarvesterFunc(tt.data, "test-flow", time.Now())

			if tt.expectCreds {
				if creds == nil {
					t.Error("Expected credentials but got nil")
					return
				}
				if tt.expectUser != "" && creds.User != tt.expectUser {
					t.Errorf("Expected user %q, got %q", tt.expectUser, creds.User)
				}
				if creds.Service != tt.expectService {
					t.Errorf("Expected service %q, got %q", tt.expectService, creds.Service)
				}
				if tt.expectMethod != "" && creds.SipMethod != tt.expectMethod {
					t.Errorf("Expected SIP method %q, got %q", tt.expectMethod, creds.SipMethod)
				}
			} else {
				if creds != nil {
					t.Errorf("Expected no credentials but got: %+v", creds)
				}
			}
		})
	}
}

func buildSIPRegisterWithDigest(username, realm string) string {
	return "REGISTER sip:" + realm + " SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bK776asdhds\r\n" +
		"From: <sip:" + username + "@" + realm + ">;tag=1928301774\r\n" +
		"To: <sip:" + username + "@" + realm + ">\r\n" +
		"Call-ID: a84b4c76e66710@192.168.1.100\r\n" +
		"CSeq: 314159 REGISTER\r\n" +
		"Authorization: Digest username=\"" + username + "\", realm=\"" + realm + "\", " +
		"nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", uri=\"sip:" + realm + "\", " +
		"response=\"6629fae49393a05397450978507c4ef1\", algorithm=MD5\r\n" +
		"Content-Length: 0\r\n\r\n"
}

func buildSIP401Response() string {
	return "SIP/2.0 401 Unauthorized\r\n" +
		"Via: SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bK776asdhds\r\n" +
		"From: <sip:alice@example.com>;tag=1928301774\r\n" +
		"To: <sip:alice@example.com>;tag=4321\r\n" +
		"Call-ID: a84b4c76e66710@192.168.1.100\r\n" +
		"CSeq: 314159 REGISTER\r\n" +
		"WWW-Authenticate: Digest realm=\"example.com\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\"\r\n" +
		"Content-Length: 0\r\n\r\n"
}

func buildSIP200OKResponse() string {
	return "SIP/2.0 200 OK\r\n" +
		"Via: SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bK776asdhds\r\n" +
		"From: <sip:alice@example.com>;tag=1928301774\r\n" +
		"To: <sip:alice@example.com>;tag=4321\r\n" +
		"Call-ID: a84b4c76e66710@192.168.1.100\r\n" +
		"CSeq: 314159 REGISTER\r\n" +
		"Content-Length: 0\r\n\r\n"
}

// TestMQTTHarvester tests the MQTT credential harvester
func TestMQTTHarvester(t *testing.T) {
	tests := []struct {
		name           string
		data           []byte
		expectCreds    bool
		expectUser     string
		expectPass     string
		expectService  string
		expectAuthSet  bool
		expectSuccess  bool
	}{
		{
			name:        "Empty packet",
			data:        []byte{},
			expectCreds: false,
		},
		{
			name:        "Too short packet",
			data:        []byte{0x10, 0x05},
			expectCreds: false,
		},
		{
			name:          "MQTT CONNECT with username and password",
			data:          buildMQTTConnect("iot_device", "mqtt_user", "mqtt_pass"),
			expectCreds:   true,
			expectUser:    "mqtt_user",
			expectPass:    "mqtt_pass",
			expectService: serviceMQTT,
		},
		{
			name:          "MQTT CONNECT with username only",
			data:          buildMQTTConnectUserOnly("device1", "admin"),
			expectCreds:   true,
			expectUser:    "admin",
			expectService: serviceMQTT,
		},
		{
			name:          "MQTT CONNACK accepted",
			data:          buildMQTTConnackAccepted(),
			expectCreds:   true,
			expectService: serviceMQTT,
			expectAuthSet: true,
			expectSuccess: true,
		},
		{
			name:          "MQTT CONNACK bad credentials",
			data:          buildMQTTConnackBadCredentials(),
			expectCreds:   true,
			expectService: serviceMQTT,
			expectAuthSet: true,
			expectSuccess: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			creds := mqttHarvesterFunc(tt.data, "test-flow", time.Now())

			if tt.expectCreds {
				if creds == nil {
					t.Error("Expected credentials but got nil")
					return
				}
				if tt.expectUser != "" && creds.User != tt.expectUser {
					t.Errorf("Expected user %q, got %q", tt.expectUser, creds.User)
				}
				if tt.expectPass != "" && creds.Password != tt.expectPass {
					t.Errorf("Expected password %q, got %q", tt.expectPass, creds.Password)
				}
				if creds.Service != tt.expectService {
					t.Errorf("Expected service %q, got %q", tt.expectService, creds.Service)
				}
				if tt.expectAuthSet {
					if !creds.AuthSuccessSet {
						t.Error("Expected AuthSuccessSet to be true")
					}
					if creds.AuthSuccess != tt.expectSuccess {
						t.Errorf("Expected AuthSuccess %v, got %v", tt.expectSuccess, creds.AuthSuccess)
					}
				}
			} else {
				if creds != nil {
					t.Errorf("Expected no credentials but got: %+v", creds)
				}
			}
		})
	}
}

// buildMQTTConnect builds an MQTT 3.1.1 CONNECT packet with credentials
func buildMQTTConnect(clientID, username, password string) []byte {
	// Variable header
	protoName := "MQTT"
	protoLevel := byte(4) // MQTT 3.1.1
	
	// Connect flags: username + password
	connectFlags := byte(mqttFlagUsername | mqttFlagPassword | mqttFlagCleanSess)
	keepAlive := uint16(60)

	// Calculate payload length
	clientIDLen := 2 + len(clientID)
	usernameLen := 2 + len(username)
	passwordLen := 2 + len(password)
	
	// Variable header: proto name (2+4) + proto level (1) + flags (1) + keepalive (2)
	varHeaderLen := 2 + len(protoName) + 1 + 1 + 2
	payloadLen := clientIDLen + usernameLen + passwordLen
	remainingLen := varHeaderLen + payloadLen

	packet := make([]byte, 0, 2+remainingLen)
	
	// Fixed header
	packet = append(packet, mqttConnect) // Packet type
	packet = append(packet, byte(remainingLen)) // Remaining length (simplified for small packets)
	
	// Variable header
	packet = append(packet, 0, byte(len(protoName))) // Proto name length
	packet = append(packet, []byte(protoName)...)
	packet = append(packet, protoLevel)
	packet = append(packet, connectFlags)
	packet = append(packet, byte(keepAlive>>8), byte(keepAlive)) // Keep alive
	
	// Payload
	// Client ID
	packet = append(packet, 0, byte(len(clientID)))
	packet = append(packet, []byte(clientID)...)
	// Username
	packet = append(packet, 0, byte(len(username)))
	packet = append(packet, []byte(username)...)
	// Password
	packet = append(packet, 0, byte(len(password)))
	packet = append(packet, []byte(password)...)

	return packet
}

// buildMQTTConnectUserOnly builds an MQTT CONNECT packet with username only
func buildMQTTConnectUserOnly(clientID, username string) []byte {
	protoName := "MQTT"
	protoLevel := byte(4)
	connectFlags := byte(mqttFlagUsername | mqttFlagCleanSess)
	keepAlive := uint16(60)

	clientIDLen := 2 + len(clientID)
	usernameLen := 2 + len(username)
	varHeaderLen := 2 + len(protoName) + 1 + 1 + 2
	payloadLen := clientIDLen + usernameLen
	remainingLen := varHeaderLen + payloadLen

	packet := make([]byte, 0, 2+remainingLen)
	
	packet = append(packet, mqttConnect)
	packet = append(packet, byte(remainingLen))
	packet = append(packet, 0, byte(len(protoName)))
	packet = append(packet, []byte(protoName)...)
	packet = append(packet, protoLevel)
	packet = append(packet, connectFlags)
	packet = append(packet, byte(keepAlive>>8), byte(keepAlive))
	packet = append(packet, 0, byte(len(clientID)))
	packet = append(packet, []byte(clientID)...)
	packet = append(packet, 0, byte(len(username)))
	packet = append(packet, []byte(username)...)

	return packet
}

// buildMQTTConnackAccepted builds an MQTT CONNACK packet (accepted)
func buildMQTTConnackAccepted() []byte {
	// CONNACK: packet type (0x20) + remaining length (2) + session present (0) + return code
	return []byte{
		0x20,                  // Packet type (CONNACK = 2 << 4)
		2,                     // Remaining length
		0,                     // Session Present
		mqttConnackAccepted,   // Return code (0 = accepted)
	}
}

// buildMQTTConnackBadCredentials builds an MQTT CONNACK packet (bad credentials)
func buildMQTTConnackBadCredentials() []byte {
	return []byte{
		0x20,                      // Packet type (CONNACK = 2 << 4)
		2,                         // Remaining length
		0,                         // Session Present
		mqttConnackRefusedBadUser, // Return code (4 = bad username or password)
	}
}

// TestBruteforceDetector tests the bruteforce detection module
func TestBruteforceDetector(t *testing.T) {
	t.Run("Threshold not reached", func(t *testing.T) {
		config := &BruteforceConfig{
			FailureThreshold:    5,
			MeasurementInterval: time.Minute,
			PerSourceTracking:   true,
			PerServiceTracking:  false,
			Enabled:             true,
		}
		detector := NewBruteforceDetector(config)
		defer detector.Stop()

		// Record fewer failures than threshold
		for i := 0; i < 4; i++ {
			detector.RecordFailure("192.168.1.100", "10.0.0.1", "SSH", "user", time.Now())
		}

		alerts := detector.GetAlerts()
		if len(alerts) != 0 {
			t.Errorf("Expected 0 alerts, got %d", len(alerts))
		}
	})

	t.Run("Threshold reached", func(t *testing.T) {
		config := &BruteforceConfig{
			FailureThreshold:    3,
			MeasurementInterval: time.Minute,
			PerSourceTracking:   true,
			PerServiceTracking:  false,
			Enabled:             true,
		}
		detector := NewBruteforceDetector(config)
		defer detector.Stop()

		// Record enough failures to trigger alert
		for i := 0; i < 5; i++ {
			detector.RecordFailure("192.168.1.100", "10.0.0.1", "SSH", "user", time.Now())
		}

		alerts := detector.GetAlerts()
		if len(alerts) != 1 {
			t.Errorf("Expected 1 alert, got %d", len(alerts))
		}

		if len(alerts) > 0 {
			if alerts[0].SourceIP != "192.168.1.100" {
				t.Errorf("Expected source IP 192.168.1.100, got %s", alerts[0].SourceIP)
			}
			if alerts[0].FailedAttempts < 3 {
				t.Errorf("Expected at least 3 failed attempts, got %d", alerts[0].FailedAttempts)
			}
		}
	})

	t.Run("Per service tracking", func(t *testing.T) {
		config := &BruteforceConfig{
			FailureThreshold:    3,
			MeasurementInterval: time.Minute,
			PerSourceTracking:   false,
			PerServiceTracking:  true,
			Enabled:             true,
		}
		detector := NewBruteforceDetector(config)
		defer detector.Stop()

		// Record failures for different services
		for i := 0; i < 5; i++ {
			detector.RecordFailure("192.168.1.100", "10.0.0.1", "FTP", "user", time.Now())
		}

		alerts := detector.GetAlerts()
		if len(alerts) != 1 {
			t.Errorf("Expected 1 alert, got %d", len(alerts))
		}

		if len(alerts) > 0 && alerts[0].Service != "FTP" {
			t.Errorf("Expected service FTP, got %s", alerts[0].Service)
		}
	})

	t.Run("Disabled detector", func(t *testing.T) {
		config := &BruteforceConfig{
			FailureThreshold:    3,
			MeasurementInterval: time.Minute,
			PerSourceTracking:   true,
			Enabled:             false,
		}
		detector := NewBruteforceDetector(config)
		defer detector.Stop()

		// Record many failures
		for i := 0; i < 100; i++ {
			detector.RecordFailure("192.168.1.100", "10.0.0.1", "SSH", "user", time.Now())
		}

		alerts := detector.GetAlerts()
		if len(alerts) != 0 {
			t.Errorf("Expected 0 alerts when disabled, got %d", len(alerts))
		}
	})

	t.Run("Stats reporting", func(t *testing.T) {
		config := DefaultBruteforceConfig()
		detector := NewBruteforceDetector(config)
		defer detector.Stop()

		stats := detector.GetStats()
		if stats["failure_threshold"] != config.FailureThreshold {
			t.Errorf("Expected threshold %d, got %v", config.FailureThreshold, stats["failure_threshold"])
		}
	})
}

// TestHarvesterRegistration tests that all new harvesters are properly registered
func TestHarvesterRegistration(t *testing.T) {
	expectedHarvesters := []string{
		"RADIUS",
		"SOCKS",
		"SIP",
		"MQTT",
	}

	for _, name := range expectedHarvesters {
		t.Run(name, func(t *testing.T) {
			if _, ok := allHarvesters[name]; !ok {
				t.Errorf("Harvester %q not found in allHarvesters map", name)
			}
		})
	}
}

