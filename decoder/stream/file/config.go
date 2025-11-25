/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017-2020 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package file

import (
	"os"
	"sync"

	"gopkg.in/yaml.v2"
)

// Config represents the file extraction configuration
type Config struct {
	FileExtraction FileExtractionConfig `yaml:"file_extraction"`
}

// FileExtractionConfig contains all settings for file extraction
type FileExtractionConfig struct {
	Enabled   bool              `yaml:"enabled"`
	Protocols ProtocolsConfig   `yaml:"protocols"`
	SizeLimits SizeLimitsConfig `yaml:"size_limits"`
	HashAlgorithms HashAlgorithmsConfig `yaml:"hash_algorithms"`
	MimeTypes MimeTypesConfig   `yaml:"mime_types"`
	Storage   StorageConfig     `yaml:"storage"`
	IncompleteFiles IncompleteFilesConfig `yaml:"incomplete_files"`
	Reassembly ReassemblyConfig  `yaml:"reassembly"`
	Advanced  AdvancedConfig    `yaml:"advanced"`
}

// ProtocolsConfig defines which protocols have file extraction enabled
type ProtocolsConfig struct {
	HTTP bool `yaml:"http"`
	FTP  bool `yaml:"ftp"`
	SMTP bool `yaml:"smtp"`
	POP3 bool `yaml:"pop3"`
	IMAP bool `yaml:"imap"`
	SMB  bool `yaml:"smb"`
	IRC  bool `yaml:"irc"`
}

// SizeLimitsConfig defines size limits for file extraction
type SizeLimitsConfig struct {
	MaxFileSize           int64 `yaml:"max_file_size"`
	IncludeMissingBytes   bool  `yaml:"include_missing_bytes"`
	MaxFilesPerSession    int   `yaml:"max_files_per_session"`
}

// HashAlgorithmsConfig defines which hash algorithms to compute
type HashAlgorithmsConfig struct {
	MD5    bool `yaml:"md5"`
	SHA1   bool `yaml:"sha1"`
	SHA256 bool `yaml:"sha256"`
}

// MimeTypesConfig defines MIME type filtering
type MimeTypesConfig struct {
	Whitelist []string `yaml:"whitelist"`
	Blacklist []string `yaml:"blacklist"`
}

// StorageConfig defines how extracted files are organized
type StorageConfig struct {
	OrganizeByMime       bool `yaml:"organize_by_mime"`
	OrganizeByProtocol   bool `yaml:"organize_by_protocol"`
	OrganizeByDate       bool `yaml:"organize_by_date"`
	CompressStoredFiles  bool `yaml:"compress_stored_files"`
	IncludeConnectionID  bool `yaml:"include_connection_id"`
}

// IncompleteFilesConfig defines handling of incomplete files
type IncompleteFilesConfig struct {
	WriteIncomplete   bool   `yaml:"write_incomplete"`
	IncompletePrefix  string `yaml:"incomplete_prefix"`
}

// ReassemblyConfig defines file reassembly settings
type ReassemblyConfig struct {
	Enabled         bool  `yaml:"enabled"`
	AllowSparseFiles bool `yaml:"allow_sparse_files"`
	MaxBufferSize   int64 `yaml:"max_buffer_size"`
}

// AdvancedConfig defines advanced file extraction options
type AdvancedConfig struct {
	UseMagicDetection bool `yaml:"use_magic_detection"`
	DecodeCompressed  bool `yaml:"decode_compressed"`
	DecodeBase64      bool `yaml:"decode_base64"`
	MaxFilenameLength int  `yaml:"max_filename_length"`
}

var (
	globalConfig *Config
	configMutex  sync.RWMutex
)

// LoadConfig loads file extraction configuration from a YAML file
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// SetGlobalConfig sets the global configuration
func SetGlobalConfig(cfg *Config) {
	configMutex.Lock()
	defer configMutex.Unlock()
	globalConfig = cfg
}

// GetGlobalConfig returns the global configuration
func GetGlobalConfig() *Config {
	configMutex.RLock()
	defer configMutex.RUnlock()
	
	if globalConfig == nil {
		// Return default configuration
		return GetDefaultConfig()
	}
	
	return globalConfig
}

// GetDefaultConfig returns the default configuration
func GetDefaultConfig() *Config {
	return &Config{
		FileExtraction: FileExtractionConfig{
			Enabled: true,
			Protocols: ProtocolsConfig{
				HTTP: true,
				FTP:  true,
				SMTP: true,
				POP3: false,
				IMAP: false,
				SMB:  false,
				IRC:  false,
			},
			SizeLimits: SizeLimitsConfig{
				MaxFileSize:         104857600, // 100MB
				IncludeMissingBytes: true,
				MaxFilesPerSession:  0, // Unlimited
			},
			HashAlgorithms: HashAlgorithmsConfig{
				MD5:    true,
				SHA1:   true,
				SHA256: true,
			},
			MimeTypes: MimeTypesConfig{
				Whitelist: []string{},
				Blacklist: []string{},
			},
			Storage: StorageConfig{
				OrganizeByMime:      true,
				OrganizeByProtocol:  false,
				OrganizeByDate:      false,
				CompressStoredFiles: false,
				IncludeConnectionID: true,
			},
			IncompleteFiles: IncompleteFilesConfig{
				WriteIncomplete:  false,
				IncompletePrefix: "incomplete-",
			},
			Reassembly: ReassemblyConfig{
				Enabled:          true,
				AllowSparseFiles: true,
				MaxBufferSize:    10485760, // 10MB
			},
			Advanced: AdvancedConfig{
				UseMagicDetection: true,
				DecodeCompressed:  true,
				DecodeBase64:      true,
				MaxFilenameLength: 255,
			},
		},
	}
}

// IsProtocolEnabled checks if file extraction is enabled for a protocol
func IsProtocolEnabled(protocol string) bool {
	cfg := GetGlobalConfig()
	if !cfg.FileExtraction.Enabled {
		return false
	}

	switch protocol {
	case "HTTP":
		return cfg.FileExtraction.Protocols.HTTP
	case "FTP":
		return cfg.FileExtraction.Protocols.FTP
	case "SMTP", "MAIL":
		return cfg.FileExtraction.Protocols.SMTP
	case "POP3":
		return cfg.FileExtraction.Protocols.POP3
	case "IMAP":
		return cfg.FileExtraction.Protocols.IMAP
	case "SMB":
		return cfg.FileExtraction.Protocols.SMB
	case "IRC":
		return cfg.FileExtraction.Protocols.IRC
	default:
		return false
	}
}

// ShouldExtractMimeType checks if a MIME type should be extracted based on whitelist/blacklist
func ShouldExtractMimeType(mimeType string) bool {
	cfg := GetGlobalConfig()
	
	// Check whitelist first (if set, only extract whitelisted types)
	if len(cfg.FileExtraction.MimeTypes.Whitelist) > 0 {
		for _, allowed := range cfg.FileExtraction.MimeTypes.Whitelist {
			if mimeType == allowed {
				return true
			}
		}
		return false
	}

	// Check blacklist
	for _, blocked := range cfg.FileExtraction.MimeTypes.Blacklist {
		if mimeType == blocked {
			return false
		}
	}

	return true
}

// GetMaxFileSize returns the configured maximum file size
func GetMaxFileSize() int64 {
	cfg := GetGlobalConfig()
	return cfg.FileExtraction.SizeLimits.MaxFileSize
}

// ShouldComputeHash checks if a specific hash algorithm should be computed
func ShouldComputeHash(algorithm string) bool {
	cfg := GetGlobalConfig()
	
	switch algorithm {
	case "MD5":
		return cfg.FileExtraction.HashAlgorithms.MD5
	case "SHA1":
		return cfg.FileExtraction.HashAlgorithms.SHA1
	case "SHA256":
		return cfg.FileExtraction.HashAlgorithms.SHA256
	default:
		return false
	}
}

// IsReassemblyEnabled checks if file reassembly is enabled
func IsReassemblyEnabled() bool {
	cfg := GetGlobalConfig()
	return cfg.FileExtraction.Reassembly.Enabled
}

// ShouldUseMagicDetection checks if magic number detection should be used
func ShouldUseMagicDetection() bool {
	cfg := GetGlobalConfig()
	return cfg.FileExtraction.Advanced.UseMagicDetection
}

