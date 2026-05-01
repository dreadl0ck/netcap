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
	"time"

	netcaptypes "github.com/dreadl0ck/netcap/types"
	"github.com/jcmturner/gokrb5/v8/messages"
)

// kerberosASRepHarvesterFunc extracts AS-REP tickets from Kerberos traffic
// AS-REP (Authentication Service Reply) contains encrypted data that can be cracked offline
// This harvester extracts tickets in Hashcat format for modes 18200, 19600, 19700
func kerberosASRepHarvesterFunc(data []byte, ident string, ts time.Time) *netcaptypes.Secret {
	// Handle TCP record mark (4-byte length prefix) if present
	payload := handleKerberosRecordMark(data)
	if payload == nil || len(payload) < 20 {
		return nil
	}

	// Try to unmarshal as AS-REP
	var asrep messages.ASRep
	err := asrep.Unmarshal(payload)
	if err != nil {
		// Not a valid AS-REP message, might be other traffic on port 88
		return nil
	}

	// Extract required fields
	username := extractPrincipalName(asrep.CName)
	if username == "" {
		// No username, can't create valid hash
		return nil
	}

	realm := asrep.CRealm
	serviceName := extractPrincipalName(asrep.Ticket.SName)
	etype := asrep.EncPart.EType
	cipher := asrep.EncPart.Cipher

	// Only process supported etypes (17, 18, 23)
	if !isSupportedEtype(etype) {
		return nil
	}

	// Verify we have cipher data
	if len(cipher) == 0 {
		return nil
	}

	// Format for Hashcat
	hashcatFormat := formatASRepForHashcat(username, realm, cipher, etype)
	if hashcatFormat == "" {
		return nil
	}

	hashcatMode := getHashcatMode("AS-REP", etype)

	return &netcaptypes.Secret{
		Timestamp: ts.UnixNano(),
		Service:   "Kerberos",
		Flow:      ident,
		User:      username,
		Password:  hashcatFormat,
		Notes:     fmt.Sprintf("HashType: Kerberos V5 AS-REP etype %d, Realm: %s, Service: %s, Hashcat mode: %d", etype, realm, serviceName, hashcatMode),
	}
}

// kerberosASRepHarvester is the harvester definition for Kerberos AS-REP
var kerberosASRepHarvester = Harvester{
	Name:          "Kerberos AS-REP",
	Description:   "Kerberos AS-REP Roasting - extracts encrypted TGT tickets for offline cracking (Hashcat mode 18200)",
	HarvesterFunc: kerberosASRepHarvesterFunc,
}
