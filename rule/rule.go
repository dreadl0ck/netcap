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

package rule

import (
	"net"
	"regexp"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

// Suspicious activity / normal usage violation
//
//   - activity during non-office hours
//   - activity from and towards countries without business contacts or offices
//   - activity from and towards cities without business contacts or offices
//   - In house subnets VS outside world
//   - unusual data volume, e.g: more than X% of usual flow size
//
// events that are valid in the protocol used, but still uncommon:
//
//   - High port number as destination for HTTP requests
//   - advertised content type for file does not match detected content type
//   - HTTP host is IP address and not domain
//   - shell commands in URL params

// Config holds all rules.
type Config struct {
	Rules []*Rule
}

// Action to execute when the rule applies.
type Action func() error

// Operation to compare values
type Operation func() bool

// Rule models a generic detection rule, that will be executed based on the provided information.
// Simple rules could be created as a YAML configuration,
// while more complex ones should be written in Go in order to implement a custom Action.
type Rule struct {

	// Audit record type for which the rule shall be applied
	Typ types.Type

	// or apply to all audit records
	ApplyToAllTypes bool

	// todo: make timezone configurable!
	// fire if record has a timestamp in a given interval
	StartAt time.Time
	EndAt   time.Time

	// Description text for the event
	Description string

	// Logic to execute
	Action Action

	// Comparison Operations
	// ==, <, >, >=, <= etc
	Operation Operation

	// num bytes
	ingressBytes int
	egressBytes  int

	// ip network information
	homeSubnet net.IPNet
	homeMask   net.IPMask

	// Port number
	Port int

	// IP address
	IP net.IP

	// MAC address
	MAC string

	// Regular expression to match against packet contents or stream banners
	Regex regexp.Regexp
}
