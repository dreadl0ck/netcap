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
	"fmt"
	"io/ioutil"
	"log"
	"strconv"
	"time"

	"gopkg.in/yaml.v2"
)

type attacks struct {
	Location   string        `yaml:"location"`
	TimeFormat string        `yaml:"timeFormat"`
	DateFormat string        `yaml:"dateFormat"`
	Attacks    []*AttackInfo `yaml:"attacks"`
}

// AttackInfo models an attack and contains meta information.
// Timestamps are provided as strings to support custom time formats.
type AttackInfo struct {

	// Attack instance number
	Num int `csv:"num" yaml:"num"`

	// Attack Name
	Name string `csv:"name" yaml:"name"`

	// Attack timeframe
	Start string `csv:"start" yaml:"start"`
	End   string `csv:"end" yaml:"end"`

	// any traffic going from and towards the specified IPs in the given timeframe
	// the field value from parsed CSV is going to be split by ";"
	IPs []string `csv:"ips" yaml:"ips"`

	// Underlying Protocol(s)
	Proto string `csv:"proto" yaml:"proto"`

	// Additional notes
	Notes string `csv:"notes" yaml:"notes"`

	// Associated category
	Category string `csv:"category" yaml:"category"`

	// MITRE Tactic or Technique Name
	MITRE string `csv:"mitre" yaml:"mitre"`

	// Day of Attack
	Date string `yaml:"date" yaml:"date"`

	// Separate victims and attacks, flag any traffic BETWEEN the specified IPs.
	Victims   []string `csv:"victims" yaml:"victims"`
	Attackers []string `csv:"attackers" yaml:"attackers"`

	// FlagVictimTraffic will also label traffic from and towards the victim for the current attack timeframe,
	// and can be used when specifying victim and attacker IPs separately.
	// This is useful for example during infiltration scenarios,
	// where malicious activity is conducted by an infected host.
	FlagVictimTraffic bool `yaml:"flagVictimTraffic"`
}

// private

// internal attackInfo with parsed timestamps
type attackInfo struct {

	// Attack instance number
	Num int `yaml:"num"`

	// Attack Name
	Name string `yaml:"name"`

	// Attack timeframe
	Start time.Time `yaml:"start"`
	End   time.Time `yaml:"end"`

	// any traffic going from and towards the specified IPs in the given timeframe
	// the field value from parsed CSV is going to be split by ";"
	// this approach is less granular compared to specifying victim and attacker ips separately.
	IPs []string `yaml:"ips"`

	// Underlying Protocol(s)
	Proto string `yaml:"proto"`

	// Additional notes
	Notes string `yaml:"notes"`

	// Associated category
	Category string `yaml:"category"`

	// MITRE Tactic or Technique Name
	MITRE string `yaml:"mitre"`

	// Day of Attack
	Date time.Time `yaml:"date"`

	// Separate victims and attacks, flag any traffic BETWEEN the specified IPs.
	Victims   []string `yaml:"victims"`
	Attackers []string `yaml:"attackers"`

	// FlagVictimTraffic will also label traffic from and towards the victim for the current attack timeframe,
	// and can be used when specifying victim and attacker IPs separately.
	// This is useful for example during infiltration scenarios,
	// where malicious activity is conducted by an infected host.
	FlagVictimTraffic bool `yaml:"flagVictimTraffic"`
}

func (m *LabelManager) parseAttackInfosYAML(path string) (labelMap map[string]*attackInfo, labels []*attackInfo) {

	data, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatal("failed to read attack yml path: ", err)
	}

	var atks = &attacks{}
	err = yaml.UnmarshalStrict(data, &atks)
	if err != nil {
		log.Fatal("failed to unmarshal attack config: ", err)
	}

	if atks.Location != "" {
		Location, err = time.LoadLocation(atks.Location)
		if err != nil {
			log.Fatal("failed to load timezone: ", err)
		}
	}

	// alerts that have a duplicate timestamp
	var duplicates []*attackInfo

	// ts:alert
	labelMap = make(map[string]*attackInfo)

	for i, a := range atks.Attacks {

		start, errParseStart := time.ParseInLocation(atks.TimeFormat, a.Start, Location)
		if errParseStart != nil {
			log.Fatal("failed to parse start time: ", errParseStart)
		}

		end, errParseEnd := time.ParseInLocation(atks.TimeFormat, a.End, Location)
		if errParseEnd != nil {
			log.Fatal("failed to parse end time: ", errParseEnd)
		}

		// golang example: "2006/1/2 15:04:05"
		date, errParseDate := time.ParseInLocation(atks.DateFormat, a.Date, Location)
		if errParseDate != nil {
			log.Fatal("failed to parse date time: ", errParseDate)
		}

		start = start.AddDate(date.Year(), int(date.Month())-1, date.Day()-1)
		end = end.AddDate(date.Year(), int(date.Month())-1, date.Day()-1)

		custom := &attackInfo{
			Num:               i,     // int
			Start:             start, // time.Time
			End:               end,   // time.Time
			Victims:           a.Victims,
			Attackers:         a.Attackers,
			Date:              date,
			Name:              a.Name,     // string
			Proto:             a.Proto,    // string
			Notes:             a.Notes,    // string
			Category:          a.Category, // string
			MITRE:             a.MITRE,
			FlagVictimTraffic: a.FlagVictimTraffic,
			IPs:               a.IPs,
		}

		// ensure no alerts with empty name are collected
		if custom.Name == "" || custom.Name == " " {
			fmt.Println("skipping entry with empty name", custom)

			continue
		}

		// count total occurrences of classification
		m.classificationMap[custom.Name]++

		// check if excluded
		if !m.excluded[custom.Name] { // append to collected alerts
			labels = append(labels, custom)

			startTSString := strconv.FormatInt(custom.Start.Unix(), 10)

			// add to label map
			if _, ok := labelMap[startTSString]; ok {
				// an alert for this timestamp already exists
				// if configured the execution will stop
				// for now the first seen alert for a timestamp will be kept
				duplicates = append(duplicates, custom)
			} else {
				labelMap[startTSString] = custom
			}
		}
	}

	return
}
