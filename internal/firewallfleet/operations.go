package firewallfleet

type AuditPage struct {
	Version   int     `json:"version"`
	Records   []Audit `json:"records"`
	Next      int64   `json:"next"`
	Oldest    int64   `json:"oldest"`
	More      bool    `json:"more"`
	Truncated bool    `json:"truncated"`
}

func (s *Service) operationsCapabilities() map[string]any {
	return map[string]any{"operations_version": OperationsVersion, "allow_effects": s.cfg.AllowEffects, "rollback_on_failure": s.cfg.RollbackOnFailure, "effects_execution": "external scope-authorized broker", "coordination": s.disk.Coordination(), "max_targets": MaxTargets, "max_revisions": MaxRevisions, "max_jobs": MaxJobs, "max_artifact_bytes": MaxArtifactBytes, "max_archived_jobs": MaxArchivedJobs, "job_receipt_retention_seconds": s.cfg.JobReceiptRetention.Seconds(), "audit_max_records": s.cfg.AuditMaxRecords, "audit_retention_seconds": s.cfg.AuditRetention.Seconds(), "audit_required": s.cfg.AuditRequired, "audit_sink": "transactional database outbox; pull export and explicit CAS acknowledgment", "audit_overflow": "optional: drop oldest; required: reject mutation atomically with HTTP 507", "audit_integrity": "transactional database; no external tamper evidence", "retention": "explicit candidate lists; preview plan CAS; protected references retained; receipt expiry requires explicit prune before ID reuse", "export_page_max": 256}
}
