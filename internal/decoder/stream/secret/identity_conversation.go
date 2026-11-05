package secret

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/dreadl0ck/netcap/types"
	"net"
	"strconv"
	"strings"
)

const IdentityService = "NTLMSSP Identity"

func identityToken(b []byte) *types.Secret {
	if len(b) < 64 || !bytes.Equal(b[:8], ntlmsspSignature) || binary.LittleEndian.Uint32(b[8:]) != 3 || binary.LittleEndian.Uint32(b[60:])&1 == 0 {
		return nil
	}
	for _, at := range []int{12, 20, 28, 36, 44, 52} {
		length, maximum, offset := uint64(binary.LittleEndian.Uint16(b[at:])), uint64(binary.LittleEndian.Uint16(b[at+2:])), uint64(binary.LittleEndian.Uint32(b[at+4:]))
		if length > maximum || length > 0 && (offset < 64 || offset > 65536 || length > 65536-offset || offset > uint64(len(b)) || length > uint64(len(b))-offset) || at >= 28 && at <= 44 && length%2 != 0 {
			return nil
		}
	}
	_, _, domain, user, workstation := extractNTLMAuthFields(b)
	if user == "" || len(user) > 512 || len(domain) > 512 || len(workstation) > 512 {
		return nil
	}
	return &types.Secret{Service: IdentityService, User: user, Domain: domain, Realm: domain, Workstation: workstation, Notes: "Observed NTLM authentication identity; authentication success and challenge are not established"}
}

func identityFlow(a string, p int32, b string, q int32) string {
	return net.JoinHostPort(a, strconv.Itoa(int(p))) + "->" + net.JoinHostPort(b, strconv.Itoa(int(q)))
}

func harvestNTLMIdentity(c *core.ConversationInfo, emit func(*types.Secret)) {
	var buffers [2][]byte
	var scan [2]int
	seen := map[string]bool{}
	for _, f := range c.Data {
		i := 0
		if f.Direction() == reassembly.TCPDirServerToClient {
			i = 1
		}
		if d, ok := f.(*core.StreamData); ok && d.SkippedBytes != 0 {
			buffers[i] = nil
			scan[i] = 0
		}
		if len(buffers[i])+len(f.Raw()) > 4<<20 {
			continue
		}
		buffers[i] = append(buffers[i], f.Raw()...)
		b := buffers[i]
		pending := -1
		for pos := scan[i]; pos < len(b); {
			offset := bytes.Index(b[pos:], ntlmsspSignature)
			if offset < 0 {
				break
			}
			pos += offset
			r := identityToken(b[pos:])
			if r == nil && len(b)-pos < 65536 && pending < 0 {
				pending = pos
			}
			pos++
			if r == nil {
				continue
			}
			a, z, p, q := c.Endpoints(f)
			r.Service = "NTLMSSP Token"
			r.Notes = "Observed NTLM identity token; transport context and authentication are unverified"
			r.Flow = identityFlow(a, p, z, q)
			key := r.Flow + "|" + r.Domain + "|" + r.User + "|" + r.Workstation
			if seen[key] || len(seen) >= 256 {
				continue
			}
			seen[key] = true
			r.Timestamp = core.FragmentTime(f)
			r.CommunityID = c.CommunityID
			emit(r)
		}
		scan[i] = max(0, len(b)-7)
		if pending >= 0 {
			scan[i] = pending
		}
		buffers[i] = append([]byte(nil), b[scan[i]:]...)
		scan[i] = 0
	}
}

func HarvestHTTPNTLMIdentity(header, src, dst string, srcPort, dstPort int32, at int64, community string) {
	if Decoder.Writer == nil || !useHarvesters {
		return
	}
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "NTLM") && !strings.EqualFold(parts[0], "Negotiate") {
		return
	}
	data, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil || len(data) > 65536 {
		return
	}
	HarvestNTLMIdentityToken(data, src, dst, srcPort, dstPort, at, community)
}

// Call only for credentials carried in an explicitly parsed authentication field.
func HarvestNTLMIdentityToken(data []byte, src, dst string, srcPort, dstPort int32, at int64, community string) {
	if Decoder.Writer == nil || !useHarvesters {
		return
	}
	enabled := false
	for _, h := range tcpConnectionHarvesters {
		if h.Name == "NTLMSSP" {
			enabled = true
		}
	}
	if !enabled || decoderconfig.Instance.HarvesterPortFilter && !harvesterMatchesPort("NTLMSSP", int(srcPort), int(dstPort)) {
		return
	}
	index := bytes.Index(data, ntlmsspSignature)
	if index < 0 {
		return
	}
	r := identityToken(data[index:])
	if r == nil {
		return
	}
	r.Flow = identityFlow(src, srcPort, dst, dstPort)
	r.Timestamp = at
	r.CommunityID = community
	writeConversationSecret(r)
}

func SecretEndpoints(flow string) (string, int32, string, int32, bool) {
	a, b, ok := strings.Cut(flow, "->")
	if !ok {
		return "", 0, "", 0, false
	}
	x, p, err := net.SplitHostPort(a)
	if err != nil {
		return "", 0, "", 0, false
	}
	y, q, err := net.SplitHostPort(b)
	if err != nil {
		return "", 0, "", 0, false
	}
	pp, e1 := strconv.ParseUint(p, 10, 16)
	qq, e2 := strconv.ParseUint(q, 10, 16)
	return x, int32(pp), y, int32(qq), e1 == nil && e2 == nil
}
