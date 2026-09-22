/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package manager

import (
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

// TODO: make configurable
const labelNormal = "normal"

// Label returns the label for the current audit record according to the loaded label mapping.
func (m *LabelManager) Label(record types.AuditRecord) string {

	var label = labelNormal

	// verify time interval of audit record is within the attack period
	// TODO: add simple option to increment or decrement UTC instead of using named timezone
	//auditRecordTime := time.Unix(0, record.Time()).UTC().Add(-4 * time.Hour)

	auditRecordTime := time.Unix(0, record.Time()).In(Location)

	// check if flow has a source or destination address matching an alert
	// if not label it as normal
	for _, l := range m.labels {

		// if the audit record has a timestamp in the attack period
		if (l.Start.Before(auditRecordTime) && l.End.After(auditRecordTime)) ||

			// or matches exactly the one on the audit record
			l.Start.Equal(auditRecordTime) || l.End.Equal(auditRecordTime) {

			//if m.Debug {
			//	fmt.Println("-----------------------", record.NetcapType(), l.Name, l.Category)
			//	fmt.Println("flow:", record.Src(), "->", record.Dst(), "addr:", "IPs:", l.IPs)
			//	fmt.Println("victims", l.Victims, "attackers", l.Attackers)
			//	fmt.Println("start", l.Start)
			//	fmt.Println("end", l.End)
			//	fmt.Println("auditRecordTime", auditRecordTime)
			//	fmt.Println("(l.Start.Before(auditRecordTime) && l.End.After(auditRecordTime))", l.Start.Before(auditRecordTime) && l.End.After(auditRecordTime))
			//	fmt.Println("l.Start.Equal(auditRecordTime)", l.Start.Equal(auditRecordTime))
			//	fmt.Println("l.End.Equal(auditRecordTime))", l.End.Equal(auditRecordTime))
			//}
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

				if numMatches == 0 {
					if l.FlagVictimTraffic {
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

			if l.FlagVictimTraffic || len(l.IPs) > 0 {
				// if flagging victim traffic, a single match is also fine.
				if numMatches != 1 && numMatches != 2 {
					continue
				}
			} else {
				// if flagging only traffic between attackers and victim,
				// we need both a match for an attacker and a victim IP.
				if numMatches != 2 {
					continue
				}
			}

			// only if it is not already part of the label
			if !strings.Contains(label, l.Category) {
				if label == labelNormal {
					label = l.Category
				} else {
					label += " | " + l.Category
				}
			}
		}
	}

	if m.scatterPlot {
		t := auditRecordTime.Truncate(m.scatterDuration)
		if label != labelNormal {
			m.scatterMapMu.Lock()
			if _, ok := m.scatterAttackMap[t]; !ok {
				m.scatterAttackMap[t] = 1
			} else {
				m.scatterAttackMap[t]++
			}
			if _, ok := m.scatterNormalMap[t]; !ok {
				m.scatterNormalMap[t] = 0
			}
			m.scatterMapMu.Unlock()
		} else {
			m.scatterMapMu.Lock()
			if _, ok := m.scatterNormalMap[t]; !ok {
				m.scatterNormalMap[t] = 1
			} else {
				m.scatterNormalMap[t]++
			}
			if _, ok := m.scatterAttackMap[t]; !ok {
				m.scatterAttackMap[t] = 0
			}
			m.scatterMapMu.Unlock()
		}
	}

	m.Lock()
	m.labelHits[label]++
	m.Unlock()

	return label
}
