package tlsdecrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"hash"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

type Record struct {
	Type    byte
	Version uint16
	Body    []byte
	At      int64
}
type Plaintext struct {
	Data   []byte
	At     int64
	Client bool
}
type Session struct {
	ClientRandom, ServerRandom []byte
	Suite                      uint16
	TLS13                      bool
	clientSide                 int
}

func (s *Session) ClientSide() int { return s.clientSide }

func Handshake(records [2][]Record) *Session {
	s := &Session{clientSide: -1}
	for side, stream := range records {
		var pending []byte
		for _, r := range stream {
			if r.Type != 22 {
				break
			}
			if len(pending)+len(r.Body) > 1<<20 {
				return nil
			}
			pending = append(pending, r.Body...)
			for len(pending) >= 4 {
				n := int(pending[1])<<16 | int(pending[2])<<8 | int(pending[3])
				if n > 1<<20 {
					return nil
				}
				if len(pending) < n+4 {
					break
				}
				body := pending[4 : n+4]
				if pending[0] == 1 && len(body) >= 34 {
					s.ClientRandom = append([]byte(nil), body[2:34]...)
					s.clientSide = side
				}
				if pending[0] == 2 && len(body) >= 38 {
					pos := 35 + int(body[34])
					if pos+3 > len(body) {
						return nil
					}
					s.ServerRandom = append([]byte(nil), body[2:34]...)
					s.Suite = binary.BigEndian.Uint16(body[pos:])
					s.TLS13 = s.Suite >= 0x1301 && s.Suite <= 0x1303
				}
				pending = pending[n+4:]
			}
		}
	}
	if len(s.ClientRandom) != 32 || len(s.ServerRandom) != 32 || s.clientSide < 0 {
		return nil
	}
	return s
}

func suite(id uint16) (keylen int, sha func() hash.Hash, chacha bool) {
	switch id {
	case 0x1301, 0xc02f, 0xc02b, 0x009c, 0x009e:
		return 16, sha256.New, false
	case 0x1302, 0xc030, 0xc02c, 0x009d, 0x009f:
		return 32, sha512.New384, false
	case 0x1303, 0xcca8, 0xcca9:
		return 32, sha256.New, true
	}
	return 0, nil, false
}
func aead(key []byte, chacha bool) cipher.AEAD {
	if chacha {
		a, _ := chacha20poly1305.New(key)
		return a
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	a, _ := cipher.NewGCM(b)
	return a
}
func prf(secret, seed []byte, n int, sha func() hash.Hash) []byte {
	mac := hmac.New(sha, secret)
	digest := func(data []byte) []byte { mac.Reset(); _, _ = mac.Write(data); return mac.Sum(nil) }
	a := seed
	var out []byte
	for len(out) < n {
		a = digest(a)
		out = append(out, digest(append(append([]byte(nil), a...), seed...))...)
	}
	return out[:n]
}
func expand(secret []byte, label string, n int, sha func() hash.Hash) []byte {
	label = "tls13 " + label
	info := []byte{byte(n >> 8), byte(n), byte(len(label))}
	info = append(info, []byte(label)...)
	info = append(info, 0)
	out := make([]byte, n)
	_, _ = io.ReadFull(hkdf.Expand(sha, secret, info), out)
	return out
}
func nonce(iv []byte, seq uint64) []byte {
	n := append([]byte(nil), iv...)
	for i := 0; i < 8; i++ {
		n[len(n)-1-i] ^= byte(seq)
		seq >>= 8
	}
	return n
}

// Decrypt returns only authenticated application data. A failed authenticated
// record terminates its direction; gaps cannot be joined into invented HTTP.
func (s *Session) Decrypt(keys *Secrets, records [2][]Record) []Plaintext {
	keylen, sha, chacha := suite(s.Suite)
	if keylen == 0 || keys.Empty() {
		return nil
	}
	var material []byte
	if !s.TLS13 {
		master := keys.lookup("CLIENT_RANDOM", s.ClientRandom)
		if len(master) != 48 {
			return nil
		}
		ivlen := 4
		if chacha {
			ivlen = 12
		}
		seed := append([]byte("key expansion"), s.ServerRandom...)
		seed = append(seed, s.ClientRandom...)
		material = prf(master, seed, 2*keylen+2*ivlen, sha)
	}
	var out []Plaintext
	for side, stream := range records {
		client := side == s.clientSide
		var a cipher.AEAD
		var iv, hsSecret, appSecret []byte
		var seq uint64
		active, application := false, false
		if s.TLS13 {
			label := "SERVER"
			if client {
				label = "CLIENT"
			}
			hsSecret = keys.lookup(label+"_HANDSHAKE_TRAFFIC_SECRET", s.ClientRandom)
			appSecret = keys.lookup(label+"_TRAFFIC_SECRET_0", s.ClientRandom)
			if len(hsSecret) > 0 {
				a = aead(expand(hsSecret, "key", keylen, sha), chacha)
				iv = expand(hsSecret, "iv", 12, sha)
			}
		} else {
			which := 1
			if client {
				which = 0
			}
			ivlen := 4
			if chacha {
				ivlen = 12
			}
			a = aead(material[which*keylen:(which+1)*keylen], chacha)
			iv = material[2*keylen+which*ivlen : 2*keylen+(which+1)*ivlen]
		}
		var handshake []byte
		for _, r := range stream {
			if s.TLS13 {
				if r.Type != 23 {
					continue
				}
				header := []byte{r.Type, byte(r.Version >> 8), byte(r.Version), byte(len(r.Body) >> 8), byte(len(r.Body))}
				var plain []byte
				var err error
				if a != nil {
					plain, err = a.Open(nil, nonce(iv, seq), r.Body, header)
				}
				if a == nil || err != nil {
					if application || len(appSecret) == 0 {
						break
					}
					next := aead(expand(appSecret, "key", keylen, sha), chacha)
					nextIV := expand(appSecret, "iv", 12, sha)
					plain, err = next.Open(nil, nonce(nextIV, 0), r.Body, header)
					if err != nil {
						if a == nil {
							continue
						}
						break
					}
					a, iv, seq, application = next, nextIV, 0, true
				}
				seq++
				end := len(plain) - 1
				for end >= 0 && plain[end] == 0 {
					end--
				}
				if end < 0 {
					break
				}
				typ := plain[end]
				plain = plain[:end]
				if typ == 23 {
					out = append(out, Plaintext{plain, r.At, client})
				}
				if typ == 22 {
					handshake = append(handshake, plain...)
					if len(handshake) > 1<<20 {
						break
					}
					for len(handshake) >= 4 {
						n := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
						if n+4 > len(handshake) {
							break
						}
						if handshake[0] == 20 && !application && len(appSecret) > 0 {
							a = aead(expand(appSecret, "key", keylen, sha), chacha)
							iv = expand(appSecret, "iv", 12, sha)
							seq, application = 0, true
						}
						if handshake[0] == 24 && application {
							appSecret = expand(appSecret, "traffic upd", sha().Size(), sha)
							a = aead(expand(appSecret, "key", keylen, sha), chacha)
							iv = expand(appSecret, "iv", 12, sha)
							seq = 0
						}
						handshake = handshake[n+4:]
					}
				}
			} else {
				if r.Type == 20 {
					active = true
					seq = 0
					continue
				}
				if !active {
					continue
				}
				body := r.Body
				var n []byte
				if chacha {
					n = nonce(iv, seq)
				} else {
					if len(body) < 8 {
						break
					}
					n = append(append([]byte(nil), iv...), body[:8]...)
					body = body[8:]
				}
				if len(body) < a.Overhead() {
					break
				}
				aad := make([]byte, 13)
				binary.BigEndian.PutUint64(aad, seq)
				aad[8] = r.Type
				binary.BigEndian.PutUint16(aad[9:], r.Version)
				binary.BigEndian.PutUint16(aad[11:], uint16(len(body)-a.Overhead()))
				plain, err := a.Open(nil, n, body, aad)
				seq++
				if err != nil {
					break
				}
				if r.Type == 23 {
					out = append(out, Plaintext{plain, r.At, client})
				}
			}
		}
	}
	return out
}
