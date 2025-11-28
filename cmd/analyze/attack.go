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

package main

import (
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

/*
 * Attack
 */

type attack struct {
	AttackNumber   int
	StartTime      time.Time
	EndTime        time.Time
	AttackDuration time.Duration
	AttackPoints   []string
	Adresses       []string
	AttackName     string
	AttackType     string
	Intent         string
	ActualChange   string
	Notes          string
}

func (a attack) affectsHosts(src, dst string) bool {
	for _, addr := range a.Adresses {
		if addr == src || addr == dst {
			return true
		}
	}
	return false
}

func (a attack) during(t time.Time) bool {
	if a.StartTime.Equal(t) || a.EndTime.Equal(t) {
		return true
	}

	if a.StartTime.Before(t) && a.EndTime.After(t) {
		return true
	}

	return false
}

// Attack information parsing
// parses a CSV file that contains the attack timestamps and descriptions
func parseAttackList(path string) (labels []*attack) {

	fmt.Println("parsing attacks in", path)

	// open input file
	f, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	// create CSV file reader
	r := csv.NewReader(f)
	records, err := r.ReadAll()
	if err != nil {
		log.Fatal(err)
	}

	// TODO: make configurable
	// fields Attack Info:
	// 0  AttackNumber
	// 1  AttackNumberOriginal
	// 2  StartTime
	// 3  EndTime
	// 4  AttackDuration
	// 5  AttackPoints
	// 6  Adresses
	// 7  AttackName
	// 8  AttackType
	// 9  Intent
	// 10 ActualChange
	// 11 Notes
	for _, record := range records[1:] {

		// fmt.Println("processing attack record:", i+1)

		num, err := strconv.Atoi(record[0])
		if err != nil {
			log.Fatal("failed to parse attack number:", err)
		}

		start, err := strconv.ParseInt(record[2], 10, 64)
		if err != nil {
			log.Fatal("failed to parse start time as UNIX timestamp:", err)
		}

		end, err := strconv.ParseInt(record[3], 10, 64)
		if err != nil {
			log.Fatal("failed to parse end time as UNIX timestamp:", err)
		}

		duration, err := time.ParseDuration(record[4])
		if err != nil {
			log.Fatal("failed to parse duration:", err)
		}

		toArr := func(input string) []string {
			return strings.Split(strings.Trim(input, "\""), ",")
		}

		atk := &attack{
			AttackNumber:   num,                 // int
			StartTime:      time.Unix(start, 0), // time.Time
			EndTime:        time.Unix(end, 0),   // time.Time
			AttackDuration: duration,            // time.Duration
			AttackPoints:   toArr(record[5]),    // []string
			Adresses:       toArr(record[6]),    // []string
			AttackName:     record[7],           // string
			AttackType:     record[8],           // string
			Intent:         record[9],           // string
			ActualChange:   record[10],          // string
			Notes:          record[11],          // string
		}

		// ensure no alerts with empty name are collected
		if atk.AttackName == "" || atk.AttackName == " " {
			fmt.Println("skipping entry with empty name", atk)
			continue
		}

		// append to collected alerts
		labels = append(labels, atk)
	}

	return
}
