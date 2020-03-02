// Discovery tool for sane-airscan compatible devices
//
// Copyright (C) 2020 and up by Alexander Pevzner (pzz@apevzner.com)
// See LICENSE for license terms and conditions
//
// Logging facilities

package main

import (
	"fmt"
	"os"
)

// Debug enables or disables debugging
var Debug = false

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
