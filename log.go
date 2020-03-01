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

// LogCheck terminates a program, if err != nil
func LogCheck(err error) {
	if err != nil {
		LogFatal("%s", err)
	}
}

// LogFatal writes a message and terminates a program
func LogFatal(format string, args ...interface{}) {
	println(fmt.Sprintf(format, args...))
	os.Exit(1)
}

// LogDebug writes a message
func LogDebug(format string, args ...interface{}) {
	println(fmt.Sprintf(format, args...))
}
