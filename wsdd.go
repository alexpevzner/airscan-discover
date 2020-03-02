// Discovery tool for sane-airscan compatible devices
//
// Copyright (C) 2020 and up by Alexander Pevzner (pzz@apevzner.com)
// See LICENSE for license terms and conditions
//
// WS-Discovery

package main

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

var (
	// WSDiscoveryAddrIp4 is IPv4 WS-Discovery multicast address
	WSDiscoveryAddrIp4 = net.ParseIP("239.255.255.250")

	// WSDiscoveryAddrIp6 is IPv6 WS-Discovery multicast address
	WSDiscoveryAddrIp6 = net.ParseIP("ff02::c")
)

// wsddNsMap maps WS-Discovery XML namespaces into short prefixes,
// convenient to compare
var wsddNsMap = map[string]string{
	"http://www.w3.org/2003/05/soap-envelope":           "s",
	"https://www.w3.org/2003/05/soap-envelope":          "s",
	"http://schemas.xmlsoap.org/ws/2005/04/discovery":   "d",
	"https://schemas.xmlsoap.org/ws/2005/04/discovery":  "d",
	"http://schemas.xmlsoap.org/ws/2004/08/addressing":  "a",
	"https://schemas.xmlsoap.org/ws/2004/08/addressing": "a",
	"http://schemas.xmlsoap.org/ws/2006/02/devprof":     "devprof",
	"https://schemas.xmlsoap.org/ws/2006/02/devprof":    "devprof",
}

// wsddFound contains a set of already discovered devices
var (
	wsddFound      = map[string]struct{}{}
	wsddFoundMutex sync.Mutex
)

// probe represents a Probe message template
const probeTemplate = `<?xml version="1.0" ?>
<s:Envelope xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:s="http://www.w3.org/2003/05/soap-envelope">
	<s:Header>
		<a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</a:Action>
		<a:MessageID>urn:uuid:%s</a:MessageID>
		<a:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To>
	</s:Header>
	<s:Body>
		<d:Probe/>
	</s:Body>
</s:Envelope>
`

// getMetadataTemplate represents a Get Metadata message template
const getMetadataTemplate = `<?xml version="1.0" ?>
<s:Envelope xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:s="http://www.w3.org/2003/05/soap-envelope">
	<s:Header>
		<a:Action>http://schemas.xmlsoap.org/ws/2004/09/transfer/Get</a:Action>
		<a:MessageID>urn:uuid:%s</a:MessageID>
		<a:To>%s</a:To>
	</s:Header>
	<s:Body>
	</s:Body>
</s:Envelope>
`

// ifAddrs returns slice of addresses of all network interfaces
func IfAddrs() []*net.UDPAddr {
	var addrs []*net.UDPAddr

	interfaces, _ := net.Interfaces()
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		ifaddrs, _ := iface.Addrs()
		zone := fmt.Sprintf("%d", iface.Index)
		for _, ifaddr := range ifaddrs {
			addr := &net.UDPAddr{
				IP: ifaddr.(*net.IPNet).IP,
			}
			if addr.IP.To4() == nil && addr.IP.IsLinkLocalUnicast() {
				addr.Zone = zone
			}
			addrs = append(addrs, addr)
		}
	}

	return addrs
}

// getMetadata requests a device metadata, usung WD-Discovery
// Get/GetResponse messages
//
// On success, it builds and returns a device endpoint
func getMetadata(address, xaddr string) *Endpoint {
	u, err := uuid.NewRandom()
	LogCheck(err)

	msg := fmt.Sprintf(getMetadataTemplate, u, address)

	// Send Get request
	resp, err := http.Post(xaddr, "application/soap+xml; charset=utf-8",
		bytes.NewBuffer(([]byte)(msg)))

	if err != nil {
		return nil
	}

	defer resp.Body.Close()

	// Parse response
	var name, text string
	var action, manufacturer, model string

	decoder := xml.NewDecoder(resp.Body)
	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}

		switch t := token.(type) {
		case xml.StartElement:
			name = wsddNsMap[t.Name.Space] + ":" + t.Name.Local
		case xml.CharData:
			text = string(bytes.TrimSpace(t))

			if text != "" {
				switch name {
				case "a:Action":
					action = text
				case "devprof:Manufacturer":
					manufacturer = text
				case "devprof:ModelName":
					model = text
				}
			}
		}

	}

	// Check results
	switch action {
	case "http://schemas.xmlsoap.org/ws/2004/09/transfer/GetResponse",
		"https://schemas.xmlsoap.org/ws/2004/09/transfer/GetResponse":
	default:
		return nil
	}

	if model == "" && manufacturer == "" {
		return nil
	}

	// Return device endpoint
	endpoint := &Endpoint{Proto: "wsd", URL: xaddr}
	if manufacturer == "" {
		endpoint.Name = model
	} else {
		endpoint.Name = manufacturer + " " + model
	}

	return endpoint
}

// handleUDPMessage handles received UDP message
func handleUDPMessage(msg []byte, outchan chan *Endpoint) {
	var name, text string
	var action, address, types string
	var xaddrs []string

	// Parse XML
	decoder := xml.NewDecoder(bytes.NewBuffer(msg))
	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}

		switch t := token.(type) {
		case xml.StartElement:
			name = wsddNsMap[t.Name.Space] + ":" + t.Name.Local
		case xml.CharData:
			text = string(bytes.TrimSpace(t))

			if text != "" {
				switch name {
				case "a:Action":
					action = text
				case "a:Address":
					address = text
				case "d:XAddrs":
					xaddrs = append(xaddrs, text)
				case "d:Types":
					types = text
				}
			}
		}

	}

	// Check results
	switch action {
	case "http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches",
		"https://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches":
	default:
		return
	}

	if len(xaddrs) == 0 {
		return
	}

	if strings.Index(types, "ScanDeviceType") < 0 {
		return
	}

	if address == "" {
		return
	}

	// Check for duplicates
	wsddFoundMutex.Lock()
	_, found := wsddFound[address]
	if !found {
		wsddFound[address] = struct{}{}
	}
	wsddFoundMutex.Unlock()

	if found {
		return
	}

	for _, xaddr := range xaddrs {
		endpoint := getMetadata(address, xaddr)
		if endpoint != nil {
			outchan <- endpoint
		}
	}
}

// recvUDPMessages receives and handles UDP messages
func recvUDPMessages(conn *net.UDPConn, outchan chan *Endpoint) {
	for {
		buf := make([]byte, 32768)
		n, _, _ := conn.ReadFromUDP(buf)
		if n > 0 {
			handleUDPMessage(buf[:n], outchan)
		}
	}
}

// WSSDDiscover performs WS-Discovery for scanner devices
func WSSDDiscover(outchan chan *Endpoint) {
	var conns []*net.UDPConn

	// Create sockets, one per interface
	for _, addr := range IfAddrs() {
		ip4 := addr.IP.To4() != nil
		if !ip4 {
			continue
		}
		if ip4 || addr.IP.IsLinkLocalUnicast() {
			proto := "udp4"
			if !ip4 {
				proto = "udp6"
			}
			conn, err := net.ListenUDP(proto, addr)
			LogCheck(err)

			if conn != nil {
				conns = append(conns, conn)
			}
		}
	}

	// Start receivers
	for _, conn := range conns {
		go recvUDPMessages(conn, outchan)
	}

	// Send Probe requests
	dest4 := &net.UDPAddr{IP: WSDiscoveryAddrIp4, Port: 3702}
	dest6 := &net.UDPAddr{IP: WSDiscoveryAddrIp6, Port: 3702}

	for {
		u, err := uuid.NewRandom()
		LogCheck(err)

		for _, conn := range conns {
			laddr := conn.LocalAddr().(*net.UDPAddr)
			dest := dest4
			if laddr.IP.To4() == nil {
				dest = dest6
				dest.Zone = laddr.Zone
			}

			msg := fmt.Sprintf(probeTemplate, u)
			conn.WriteTo([]byte(msg), dest)
		}

		time.Sleep(250 * time.Millisecond)
	}
}
