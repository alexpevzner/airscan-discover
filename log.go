// Discovery tool for sane-airscan compatible devices
//
// Copyright (C) 2020 and up by Alexander Pevzner (pzz@apevzner.com)
// See LICENSE for license terms and conditions
//
// Logging facilities

package main

import (
	"bytes"
	"fmt"
	"os"
)

// Debug enables or disables debugging
var Debug = false

// LogMessage represents a multiline log message
type LogMessage struct {
	prefix string   // Per-line prefix
	lines  []string // LogMessage lines
}

// LogCheck terminates a program, if err != nil
func LogCheck(err error) {
	if err != nil {
		LogFatal("%s", err)
	}
}

// LogFatal writes an error message and terminates a program
func LogFatal(format string, args ...interface{}) {
	LogError(format, args...)
	os.Exit(1)
}

// LogError writes an error message
func LogError(format string, args ...interface{}) {
	os.Stdout.Write([]byte(fmt.Sprintf(format, args...) + "\n"))
}

// LogDebug writes a message
func LogDebug(format string, args ...interface{}) {
	if Debug {
		os.Stdout.Write([]byte(fmt.Sprintf(format, args...) + "\n"))
	}
}

// LogBegin starts a new multiline debug message
func LogBegin(prefix string) *LogMessage {
	return &LogMessage{
		prefix: prefix,
	}
}

// Debug appends line to the LogMessage
func (m *LogMessage) Debug(format string, args ...interface{}) *LogMessage {
	if Debug {
		m.lines = append(m.lines, fmt.Sprintf(format, args...))
	}
	return m
}

// Commit the message to the log
func (m *LogMessage) Commit() {
	var buf bytes.Buffer
	for _, l := range m.lines {
		if m.prefix != "" {
			buf.Write([]byte(m.prefix))
			buf.Write([]byte(": "))
		}
		buf.Write([]byte(l))
		buf.WriteByte('\n')
	}
	os.Stdout.Write(buf.Bytes())
}
