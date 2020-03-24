// Discovery tool for sane-airscan compatible devices
//
// Copyright (C) 2020 and up by Alexander Pevzner (pzz@apevzner.com)
// See LICENSE for license terms and conditions
//
// Logging facilities

package main

import (
	"archive/tar"
	"bytes"
	"fmt"
	"os"
	"sync"
)

// Debug enables or disables debugging
var Debug = false

// Trace enables or disables protocol trace
var Trace = true

// Trace file name
const traceName = "trace.tar"

// Trace file handle, opened on demand
var (
	traceFile  *tar.Writer
	traceLock  sync.Mutex
	traceIndex int
)

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

// Add record to the protocol trace
func LogTrace(name string, data []byte) {
	// Trace enabled?
	if !Trace {
		return
	}

	// Acquire trace lock
	traceLock.Lock()
	defer traceLock.Unlock()

	// Open trace file on demand
	if traceFile == nil {
		file, err := os.OpenFile(traceName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			LogError("%s: %s", traceName, err)
			return
		}

		traceFile = tar.NewWriter(file)
	}

	// Build full name
	name = fmt.Sprintf("%.3d-%s.xml", traceIndex, name)
	traceIndex++

	// Write file header and data
	hdr := &tar.Header{
		Name: name,
		Mode: 0644,
		Size: int64(len(data)),
	}

	traceFile.WriteHeader(hdr)
	traceFile.Write(data)
	traceFile.Flush()
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
