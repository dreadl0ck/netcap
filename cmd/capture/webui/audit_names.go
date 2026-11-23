package webui

import (
	"path/filepath"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/internal/auditname"
)

// canonicalAuditType maps a requested audit type or file base (VRRP, GTPv1U)
// to the record type name. Unknown names are returned unchanged.
func canonicalAuditType(name string) string {
	if typ := auditname.TypeForFile(name); typ != "" {
		return typ
	}
	return name
}

// auditFilePath returns the existing audit file holding auditType in dir, or
// the canonical compressed path when none exists so callers report not-found.
func auditFilePath(dir, auditType string) string {
	auditType = canonicalAuditType(auditType)
	if path, err := auditname.Resolve(dir, auditType); err == nil {
		return path
	}
	return filepath.Join(dir, auditType+defaults.FileExtension+".gz")
}
