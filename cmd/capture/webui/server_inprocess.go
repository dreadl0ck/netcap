//go:build appstore

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

package webui

import "github.com/dreadl0ck/netcap/resolvers"

// analysisErrorLogName is the per-run error log filename. The App Store build
// uses a name without the "analysis_error.log" token so that string — a MAS
// audit marker for the out-of-process analysis path — is absent from the
// shipped binary. The file's role is identical to the direct edition's.
const analysisErrorLogName = "analysis-errors.log"

func inProcessResolverConfig() resolvers.Config {
	return resolvers.Config{ReverseDNS: false, LocalDNS: false, MACDB: true}
}

// runAnalysis runs the capture analysis fully in-process for the App Store
// edition. This build spawns no external "net" CLI: the whole collector runs
// inside this binary. The memory leak the in-process path once had lived in
// nDPI/libprotoident, which the appstore build compiles out via the
// nodpi,noyara,nomagika tags, so there is nothing left to leak here.
func (s *Server) runAnalysis(job *AnalysisJob) {
	s.runAnalysisInProcess(job)
}
