package stream

import (
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/internal/rules"
	"github.com/dreadl0ck/netcap/types"
)

func abstractAuditWriter(config *netio.WriterConfig) netio.AuditRecordWriter {
	if config.Type == types.Type_NC_Alert && config.Compress && !config.CSV && !config.JSON && !config.Chan && !config.Null && !config.Elastic && !config.UnixSocket {
		header := netio.NewHeader(config.Type, config.Source, config.Version, config.IncludesPayloads, config.StartTime)
		if writer, shared := rules.SharedAlertAuditWriter(config.Out, header); shared {
			return writer
		}
	}
	return netio.NewAuditRecordWriter(config)
}
