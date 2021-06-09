/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017-2020 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package main

type correction struct {
	old string
	new string
}

func newCorrection(old, new string) correction {
	return correction{
		old: old,
		new: new,
	}
}

// TODO: make configurable
// columns mapped to corrections
var cmap = map[string][]correction{
	"proxy_src_ip": []correction{
		newCorrection("192.16:.1.10", "192.168.1.10"),
	},
	"type": []correction{
		newCorrection("loe", "log"),
	},
	"Modbus_Function_Description": []correction{
		newCorrection("Read Tag Service - Responqe", "Read Tag Service - Response"),
	},
}

var simpleCorrect = map[string]string{
	"192.16:.1.10":                "192.168.1.10",
	"loe":                         "log",
	"Read Tag Service - Responqe": "Read Tag Service - Response",
}
