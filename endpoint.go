// Discovery tool for sane-airscan compatible devices
//
// Copyright (C) 2020 and up by Alexander Pevzner (pzz@apevzner.com)
// See LICENSE for license terms and conditions
//
// Device endpoint

package main

// Endpoint represents scanner endpoint
type Endpoint struct {
	Proto string // Protocol name
	Name  string // Device name
	URL   string // Endpoint URL
}
