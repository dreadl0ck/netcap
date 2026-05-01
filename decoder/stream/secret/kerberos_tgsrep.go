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

package secret

import (
	"fmt"
	"strings"
	"time"

	netcaptypes "github.com/dreadl0ck/netcap/types"
	"github.com/jcmturner/gokrb5/v8/messages"
)

// kerberosTGSRepHarvesterFunc extracts TGS-REP service tickets from Kerberos traffic
// TGS-REP (Ticket Granting Service Reply) contains service tickets for Kerberoasting
// This harvester extracts tickets in Hashcat format for modes 13100, 19600, 19700
func kerberosTGSRepHarvesterFunc(data []byte, ident string, ts time.Time) *netcaptypes.Secret {
	// Handle TCP record mark (4-byte length prefix) if present
	payload := handleKerberosRecordMark(data)
	if payload == nil || len(payload) < 20 {
		return nil
	}

	// Try to unmarshal as TGS-REP
	var tgsrep messages.TGSRep
	err := tgsrep.Unmarshal(payload)
	if err != nil {
		// Not a valid TGS-REP message, might be other traffic on port 88
		return nil
	}

	// Extract required fields
	username := extractPrincipalName(tgsrep.CName)
	if username == "" {
		// No username, can't create valid hash
		return nil
	}

	realm := tgsrep.CRealm
	serviceName := extractPrincipalName(tgsrep.Ticket.SName)

	// For TGS-REP, we need to format the service name properly
	// Join all parts with "/" for service principal names like HTTP/webserver.domain.com
	var fullServiceName string
	if len(tgsrep.Ticket.SName.NameString) > 0 {
		fullServiceName = strings.Join(tgsrep.Ticket.SName.NameString, "/")
	}
	if fullServiceName == "" {
		fullServiceName = serviceName
	}

	etype := tgsrep.Ticket.EncPart.EType
	cipher := tgsrep.Ticket.EncPart.Cipher

	// Only process supported etypes (17, 18, 23)
	if !isSupportedEtype(etype) {
		return nil
	}

	// Verify we have cipher data
	if len(cipher) == 0 {
		return nil
	}

	// Format for Hashcat (Kerberoasting)
	hashcatFormat := formatTGSRepForHashcat(username, realm, fullServiceName, cipher, etype)
	if hashcatFormat == "" {
		return nil
	}

	hashcatMode := getHashcatMode("TGS-REP", etype)

	return &netcaptypes.Secret{
		Timestamp: ts.UnixNano(),
		Service:   "Kerberos",
		Flow:      ident,
		User:      username,
		Password:  hashcatFormat,
		Notes:     fmt.Sprintf("HashType: Kerberos V5 TGS-REP etype %d, Realm: %s, Service: %s (Kerberoasting), Hashcat mode: %d", etype, realm, fullServiceName, hashcatMode),
	}
}

// kerberosTGSRepHarvester is the harvester definition for Kerberos TGS-REP
var kerberosTGSRepHarvester = Harvester{
	Name:          "Kerberos TGS-REP",
	Description:   "Kerberos TGS-REP Kerberoasting - extracts service tickets for offline cracking (Hashcat mode 13100)",
	HarvesterFunc: kerberosTGSRepHarvesterFunc,
}
