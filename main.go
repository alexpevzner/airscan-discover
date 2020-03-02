// Discovery tool for sane-airscan compatible devices
//
// Copyright (C) 2020 and up by Alexander Pevzner (pzz@apevzner.com)
// See LICENSE for license terms and conditions
//
// The main function

package main

import (
	"fmt"
	"os"
	"time"
)

// Usage/usage error templates
const usage = `Usage:
    %s [options]

Options are:
    -d   enable debug mode
    -h   print help page
`

const usageError = `Invalid argument -%s
Try %s -h for more information
`

// The main function
func main() {
	// Parse options
	for _, arg := range os.Args[1:] {
		switch arg {
		case "-d":
			Debug = true
		case "-h":
			fmt.Printf(usage, os.Args[0])
			os.Exit(0)
		default:
			fmt.Printf(usageError, arg, os.Args[0])
			os.Exit(1)
		}
	}

	// Perform a discovery
	c := make(chan *Endpoint)
	t := time.NewTimer(2500 * time.Millisecond)

	go DNSSdDiscover(c)
	go WSSDDiscover(c)

	fmt.Printf("[devices]\n")
loop:
	for {
		select {
		case endpoint := <-c:
			line := fmt.Sprintf("%q = %s", endpoint.Name, endpoint.URL)
			if endpoint.Proto != "" {
				line += ", " + endpoint.Proto
			}
			fmt.Printf("  %s\n", line)
		case <-t.C:
			break loop
		}
	}
}
