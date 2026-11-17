package webui

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

func groupedAlertPageRows(groups []GroupedAlert) ([]map[string]any, error) {
	rows := make([]map[string]any, 0, len(groups))
	for _, group := range groups {
		scalar := group
		scalar.UniqueSrcIPs, scalar.UniqueDstIPs, scalar.UniqueSrcPorts, scalar.UniqueDstPorts = nil, nil, nil, nil
		scalar.SampleAlerts = nil
		hash := sha256.New()
		encoder := json.NewEncoder(hash)
		if err := encoder.Encode(scalar); err != nil {
			return nil, err
		}
		for _, values := range [][]string{group.UniqueSrcIPs, group.UniqueDstIPs, group.UniqueSrcPorts, group.UniqueDstPorts} {
			if err := encoder.Encode(len(values)); err != nil {
				return nil, err
			}
			for _, value := range values {
				if err := encoder.Encode(value); err != nil {
					return nil, err
				}
			}
		}
		for _, sample := range group.SampleAlerts {
			if err := encoder.Encode(sample); err != nil {
				return nil, err
			}
		}
		preview := group
		preview.UniqueSrcIPs = group.UniqueSrcIPs[:min(10, len(group.UniqueSrcIPs))]
		preview.UniqueDstIPs = group.UniqueDstIPs[:min(10, len(group.UniqueDstIPs))]
		preview.UniqueSrcPorts = group.UniqueSrcPorts[:min(10, len(group.UniqueSrcPorts))]
		preview.UniqueDstPorts = group.UniqueDstPorts[:min(10, len(group.UniqueDstPorts))]
		preview.SampleAlerts = []AlertResponse{}
		raw, err := json.Marshal(preview)
		if err != nil {
			return nil, err
		}
		var row map[string]any
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		if err := decoder.Decode(&row); err != nil {
			return nil, err
		}
		row["uniqueSrcIPsTotal"], row["uniqueDstIPsTotal"] = len(group.UniqueSrcIPs), len(group.UniqueDstIPs)
		row["uniqueSrcPortsTotal"], row["uniqueDstPortsTotal"] = len(group.UniqueSrcPorts), len(group.UniqueDstPorts)
		row["sampleAlertsTotal"] = len(group.SampleAlerts)
		row["membersPaged"] = true
		row["groupDataSHA256"] = hex.EncodeToString(hash.Sum(nil))
		row["members"] = map[string]any{"tool": "list_alerts", "arguments": map[string]string{"group_id": group.GroupID}}
		rows = append(rows, row)
	}
	return rows, nil
}

func appendGroupUnique(values *[]string, seen map[string]bool, value string) {
	if value != "" && !seen[value] {
		seen[value] = true
		*values = append(*values, value)
	}
}
