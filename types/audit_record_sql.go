package types

type SQLCapableAuditRecord interface {
	AuditRecord
	SQLTable() string
	SQLInsert() (query string, values []any)
}
