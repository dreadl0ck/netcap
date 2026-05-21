/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package mcp

import (
	"io"
	"os"
)

// stdinReader and stdoutWriter are tiny indirections so tests can swap
// the underlying streams without touching the Server itself.
func stdinReader() io.Reader  { return os.Stdin }
func stdoutWriter() io.Writer { return os.Stdout }
