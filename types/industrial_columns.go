package types

// Keep the legacy metric labels: omit the capture timestamp and the new
// assembly columns, but keep the trailing CommunityID.
func legacyOTLabels(row []string, added int) []string {
	end := len(row) - 1 - added
	return append(row[1:end:end], row[len(row)-1])
}
