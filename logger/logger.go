// SPDX-License-Identifier: BSD-2-Clause
// Provenance-includes-location: https://github.com/nspcc-dev/saml/blob/a32b643a25a46182499b1278293e265150056d89/logger/logger.go
// Provenance-includes-license: BSD-2-Clause
// Provenance-includes-copyright: 2015-2023 Ross Kinder

// Package logger provides a logging interface.
package logger

import (
	"log"
	"os"
)

// Interface provides the minimal logging interface.
type Interface interface {
	// Printf prints to the logger using the format.
	Printf(format string, v ...any)
	// Print prints to the logger.
	Print(v ...any)
	// Println prints new line.
	Println(v ...any)
	// Fatal is equivalent to Print() followed by a call to os.Exit(1).
	Fatal(v ...any)
	// Fatalf is equivalent to Printf() followed by a call to os.Exit(1).
	Fatalf(format string, v ...any)
	// Fatalln is equivalent to Println() followed by a call to os.Exit(1).
	Fatalln(v ...any)
	// Panic is equivalent to Print() followed by a call to panic().
	Panic(v ...any)
	// Panicf is equivalent to Printf() followed by a call to panic().
	Panicf(format string, v ...any)
	// Panicln is equivalent to Println() followed by a call to panic().
	Panicln(v ...any)
}

// DefaultLogger logs messages to os.Stdout.
var DefaultLogger = log.New(os.Stdout, "", log.LstdFlags)
