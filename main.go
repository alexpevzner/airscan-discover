// Discovery tool for sane-airscan compatible devices
//
// Copyright (C) 2020 and up by Alexander Pevzner (pzz@apevzner.com)
// See LICENSE for license terms and conditions
//
// The main function

package main

import (
	"fmt"
	"time"
)

func main() {
	c := make(chan *Endpoint)
	t := time.NewTimer(2500 * time.Millisecond)

	go DNSSdDiscover(c)

	fmt.Printf("[devices]\n")
loop:
	for {
		select {
		case endpoint := <-c:
			fmt.Printf("  %q = %s\n", endpoint.Name, endpoint.URL)
		case <-t.C:
			break loop
		}
	}
}
