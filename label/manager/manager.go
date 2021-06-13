package manager

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/types"
	"github.com/evilsocket/islazy/tui"
)

var Location = time.Local

// LabelManager keeps track of attack information that shall be mapped onto the audit records.
type LabelManager struct {
	labels   []*attackInfo
	progress bool

	// classificationMap map of classifications.
	classificationMap map[string]int
	excluded          map[string]bool

	// debug mode
	Debug bool

	removeFilesWithoutMatches bool
}

// NewLabelManager returns a new label manager instance.
func NewLabelManager(progress bool, debug bool, removeFilesWithoutMatches bool) *LabelManager {
	return &LabelManager{
		progress:          progress,
		classificationMap: make(map[string]int),
		excluded:          make(map[string]bool),
		Debug:             debug,
	}
}

// Init will load the attack information from disk.
func (m *LabelManager) Init(pathMappingInfo string) {

	_, m.labels = m.parseAttackInfosYAML(pathMappingInfo)
	if len(m.labels) == 0 {
		fmt.Println("no labels found.")
		os.Exit(1)
	}

	fmt.Println("got", len(m.labels), "labels")

	var rows [][]string
	for i, c := range m.labels {
		y, m, d := c.Date.Date()
		rows = append(rows, []string{strconv.Itoa(i + 1), c.Name, fmt.Sprintf("%d-%d-%d", y, m, d), strconv.Itoa(len(c.Victims)), strconv.Itoa(len(c.Attackers)), c.MITRE, c.Category})
	}

	// print alert summary
	tui.Table(os.Stdout, []string{"Num", "AttackName", "Date", "Victims", "NumAttackers", "MITRE", "category"}, rows)
	fmt.Println()
}

// Label returns the label for the current audit record according to the loaded label mapping.
func (m *LabelManager) Label(record types.AuditRecord) string {

	var label string

	// verify time interval of audit record is within the attack period
	// TODO: add simple option to increment or decrement UTC instead of using named timezone
	//auditRecordTime := time.Unix(0, record.Time()).UTC().Add(-4 * time.Hour)

	auditRecordTime := time.Unix(0, record.Time()).In(Location)

	//fmt.Println("LABEL", auditRecordTime, "------------------", time.Unix(0, record.Time()).In(location))

	// check if flow has a source or destination address matching an alert
	// if not label it as normal
	for _, l := range m.labels {

		//fmt.Println(l.Start, "-", l.End)

		// if the audit record has a timestamp in the attack period
		if (l.Start.Before(auditRecordTime) && l.End.After(auditRecordTime)) ||

			// or matches exactly the one on the audit record
			l.Start.Equal(auditRecordTime) || l.End.Equal(auditRecordTime) {

			if m.Debug {
				fmt.Println("-----------------------", record.NetcapType(), l.Name, l.Category)
				fmt.Println("flow:", record.Src(), "->", record.Dst(), "addr:", "IPs:", l.IPs)
				fmt.Println("victims", l.Victims, "attackers", l.Attackers)
				fmt.Println("start", l.Start)
				fmt.Println("end", l.End)
				fmt.Println("auditRecordTime", auditRecordTime)
				fmt.Println("(l.Start.Before(auditRecordTime) && l.End.After(auditRecordTime))", l.Start.Before(auditRecordTime) && l.End.After(auditRecordTime))
				fmt.Println("l.Start.Equal(auditRecordTime)", l.Start.Equal(auditRecordTime))
				fmt.Println("l.End.Equal(auditRecordTime))", l.End.Equal(auditRecordTime))
			}
			var numMatches int

			// check if any of the addresses from the labeling info
			// is either source or destination of the current audit record
			if len(l.IPs) > 0 {
				for _, addr := range l.IPs {
					if record.Src() == addr || record.Dst() == addr {
						numMatches++
					}
				}
			} else {
				// for each attacker IP
				for _, addr := range l.Attackers {

					// check if src or dst of packet is from an attacker
					if record.Src() == addr || record.Dst() == addr {

						numMatches++

						// for each victim
						for _, victimAddr := range l.Victims {

							// if either the src or dst addr of the packet is a victim
							if record.Src() == victimAddr || record.Dst() == victimAddr {
								numMatches++

								// break from this loop and process the next attack
								// TODO: make configurable to stop after first match
								break
							}
						}
					}
				}
			}

			if numMatches != 2 {
				continue
			}

			// only if it is not already part of the label
			if !strings.Contains(label, l.Category) {
				if label == "" {
					label = l.Category
				} else {
					label += " | " + l.Category
				}
			}
		}
	}

	if label == "" {
		return labelNormal
	}

	return label
}

const labelNormal = "normal"
