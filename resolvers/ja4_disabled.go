//go:build !ja4plus

package resolvers

// JA4Entry preserves the public resolver API for records created by JA4+
// opt-in builds. Official builds do not load or index JA4+ databases.
type JA4Entry struct {
	Application          string `json:"application"`
	Library              string `json:"library"`
	Device               string `json:"device"`
	OS                   string `json:"os"`
	UserAgentString      string `json:"user_agent_string"`
	CertificateAuthority string `json:"certificate_authority"`
	ObservationCount     int    `json:"observation_count"`
	Verified             bool   `json:"verified"`
	Notes                string `json:"notes"`
	JA4Fingerprint       string `json:"ja4_fingerprint"`
	JA4FingerprintString string `json:"ja4_fingerprint_string"`
	JA4SFingerprint      string `json:"ja4s_fingerprint"`
	JA4HFingerprint      string `json:"ja4h_fingerprint"`
	JA4XFingerprint      string `json:"ja4x_fingerprint"`
	JA4TFingerprint      string `json:"ja4t_fingerprint"`
	JA4TSFingerprint     string `json:"ja4ts_fingerprint"`
	JA4TScanFingerprint  string `json:"ja4tscan_fingerprint"`
}

func (*JA4Entry) GetDescription() string   { return "" }
func LookupJA4(string) string              { return "" }
func LookupJA4Entry(string) *JA4Entry      { return nil }
func LookupJA4S(string) string             { return "" }
func LookupJA4SEntry(string) *JA4Entry     { return nil }
func LookupJA4H(string) string             { return "" }
func LookupJA4HEntry(string) *JA4Entry     { return nil }
func LookupJA4X(string) string             { return "" }
func LookupJA4XEntry(string) *JA4Entry     { return nil }
func LookupJA4T(string) string             { return "" }
func LookupJA4TEntry(string) *JA4Entry     { return nil }
func LookupJA4TS(string) string            { return "" }
func LookupJA4TSEntry(string) *JA4Entry    { return nil }
func LookupJA4TScan(string) string         { return "" }
func LookupJA4TScanEntry(string) *JA4Entry { return nil }
func GetJA4DBSize() int                    { return 0 }
func GetJA4SDBSize() int                   { return 0 }
func GetJA4HDBSize() int                   { return 0 }
func GetJA4XDBSize() int                   { return 0 }
func GetJA4TDBSize() int                   { return 0 }
func GetJA4TSDBSize() int                  { return 0 }
func GetJA4TScanDBSize() int               { return 0 }
func initJA4Resolver()                     {}
