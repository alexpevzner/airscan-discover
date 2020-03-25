// Discovery tool for sane-airscan compatible devices
//
// Copyright (C) 2020 and up by Alexander Pevzner (pzz@apevzner.com)
// See LICENSE for license terms and conditions
//
// WS-Discovery

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
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
	"http://www.w3.org/2003/05/soap-envelope":            "s",
	"https://www.w3.org/2003/05/soap-envelope":           "s",
	"http://schemas.xmlsoap.org/ws/2005/04/discovery":    "d",
	"https://schemas.xmlsoap.org/ws/2005/04/discovery":   "d",
	"http://schemas.xmlsoap.org/ws/2004/08/addressing":   "a",
	"https://schemas.xmlsoap.org/ws/2004/08/addressing":  "a",
	"http://schemas.xmlsoap.org/ws/2006/02/devprof":      "devprof",
	"https://schemas.xmlsoap.org/ws/2006/02/devprof":     "devprof",
	"http://schemas.xmlsoap.org/ws/2004/09/mex":          "mex",
	"https://schemas.xmlsoap.org/ws/2004/09/mex":         "mex",
	"http://schemas.microsoft.com/windows/pnpx/2005/10":  "pnpx",
	"https://schemas.microsoft.com/windows/pnpx/2005/10": "pnpx",
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
<s:Envelope xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:mex="http://schemas.xmlsoap.org/ws/2004/09/mex">
	<s:Header>
		<a:Action>http://schemas.xmlsoap.org/ws/2004/09/transfer/Get</a:Action>
		<a:MessageID>urn:uuid:%s</a:MessageID>
		<a:To>%s</a:To>
		<a:ReplyTo>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:ReplyTo>
	</s:Header>
	<s:Body>
		<mex:Get/>
	</s:Body>
</s:Envelope>
`

// Check if address is already known. If save is true, it will
// be added to the table of already known addresses
func alreadyKnown(address string, save bool) bool {
	wsddFoundMutex.Lock()
	defer wsddFoundMutex.Unlock()

	_, found := wsddFound[address]
	if !found && save {
		wsddFound[address] = struct{}{}
	}

	return found
}

// ifAddrs returns slice of addresses of all network interfaces
func ifAddrs() []*net.UDPAddr {
	var addrs []*net.UDPAddr

	interfaces, _ := net.Interfaces()
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		ifaddrs, _ := iface.Addrs()
		for _, ifaddr := range ifaddrs {
			addr := &net.UDPAddr{
				IP:   ifaddr.(*net.IPNet).IP,
				Zone: iface.Name,
			}
			addrs = append(addrs, addr)
		}
	}

	return addrs
}

// fixURLZone appends zone to address literal, if address
// is IPv6 link-local unicast
func fixIpv6URLZone(rawurl, zone string) (string, error) {
	// Parse URL
	parsed, err := url.Parse(rawurl)
	if err != nil {
		return "", err
	}
	if !parsed.IsAbs() {
		return "", errors.New("Invalid URL: not absolute")
	}

	// Split address to host and port
	var host, port string
	if i := strings.LastIndexByte(parsed.Host, ':'); i < 0 {
		host = parsed.Host
	} else {
		host = parsed.Host[:i]
		port = parsed.Host[i+1:]
	}

	// For IPv4 address we don't need to do something
	if !strings.HasPrefix(host, "[") {
		return rawurl, nil
	}

	// Parse IPv6 addr
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return "", errors.New("Invalid URL: bad IPv6 address")
	}

	if ip.IsLinkLocalUnicast() {
		parsed.Host = fmt.Sprintf("[%s%%%s]:%s", ip, zone, port)
		return parsed.String(), nil
	} else {
		return rawurl, nil
	}
}

// parseHosted parses devprof:Hosted section of the device metadata:
//   <devprof:Hosted>
//     <a:EndpointReference>
//       <a:Address>http://192.168.1.102:5358/WSDScanner</a:Address>
//     </addressing:EndpointReference>
//     <devprof:Types>scan:ScannerServiceType</devprof:Types>
//     <devprof:ServiceId>uri:4509a320-00a0-008f-00b6-002507510eca/WSDScanner</devprof:ServiceId>
//     <pnpx:CompatibleId>http://schemas.microsoft.com/windows/2006/08/wdp/scan/ScannerServiceType</pnpx:CompatibleId>
//     <pnpx:HardwareId>VEN_0103&amp;DEV_069D</pnpx:HardwareId>
//   </devprof:Hosted>
//
// It ignores all endpoints except ScannerServiceType, extracts endpoint
// URLs and returns them as slice of strings
func parseHosted(elements []*XMLElement) []string {
	var types string
	var urls []string

	for _, elem := range elements {
		switch elem.Path {
		case "/s:Envelope/s:Body/mex:Metadata/mex:MetadataSection/devprof:Relationship/devprof:Hosted/devprof:Types":
			types = elem.Text
		case "/s:Envelope/s:Body/mex:Metadata/mex:MetadataSection/devprof:Relationship/devprof:Hosted/a:EndpointReference/a:Address":
			urls = append(urls, elem.Text)
		}
	}

	if strings.Index(types, "ScannerServiceType") < 0 {
		return nil
	}

	return urls
}

// getMetadata requests a device metadata, usung WD-Discovery
// Get/GetResponse messages
//
// On success, it builds and returns a device endpoint
func getMetadata(log *LogMessage, address, xaddr string) []Endpoint {
	u, err := uuid.NewRandom()
	LogCheck(err)

	msg := fmt.Sprintf(getMetadataTemplate, u, address)

	// Send Get request
	log.Debug("requesting a metadata")

	resp, err := http.Post(xaddr, "application/soap+xml; charset=utf-8",
		bytes.NewBuffer(([]byte)(msg)))

	LogTrace("http-request", []byte(msg))

	if err != nil {
		log.Debug("HTTP: %s", err)
		return nil
	}

	// Load response body
	response, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		log.Debug("HTTP: %s", err)
		return nil
	}

	LogTrace("http-response", response)

	// Parse response XML
	elements, err := XMLDecode(wsddNsMap, bytes.NewBuffer(response))
	if err != nil {
		log.Debug("XML: %s", err)
		return nil
	}

	// Decode response
	var action, manufacturer, model string
	var urls []string

	for _, elem := range elements {
		switch elem.Path {
		case "/s:Envelope/s:Header/a:Action":
			action = elem.Text
		case "/s:Envelope/s:Body/mex:Metadata/mex:MetadataSection/devprof:ThisModel/devprof:Manufacturer":
			manufacturer = elem.Text
		case "/s:Envelope/s:Body/mex:Metadata/mex:MetadataSection/devprof:ThisModel/devprof:ModelName":
			model = elem.Text
		case "/s:Envelope/s:Body/mex:Metadata/mex:MetadataSection/devprof:Relationship/devprof:Hosted":
			urls = append(urls, parseHosted(elem.Children)...)
		}
	}

	// Write debug messages
	log.Debug("metadata response parameters:")
	log.Debug("  action:       %q", action)
	log.Debug("  manufacturer: %q", manufacturer)
	log.Debug("  model:        %q", model)
	log.Debug("  urls:         %q", urls)

	// Check results
	switch action {
	case "http://schemas.xmlsoap.org/ws/2004/09/transfer/GetResponse",
		"https://schemas.xmlsoap.org/ws/2004/09/transfer/GetResponse":
	default:
		log.Debug("metadata ignored: unknown action")
		return nil
	}

	if model == "" && manufacturer == "" {
		log.Debug("metadata ignored: no model or manufacturer")
		return nil
	}

	if len(urls) == 0 {
		log.Debug("metadata ignored: no scanner URLs")
		return nil
	}

	// Return discovered endpoints
	var endpoints []Endpoint

	if manufacturer != "" {
		model = manufacturer + " " + model
	}

	for _, url := range urls {
		endpoint := Endpoint{Proto: "wsd", Name: model, URL: url}
		endpoints = append(endpoints, endpoint)
	}

	return endpoints
}

// handleUDPMessage handles received UDP message
func handleUDPMessage(log *LogMessage, msg []byte, zone string, outchan chan Endpoint) {
	var action, address, types string
	var xaddrs []string

	// Parse XML
	elements, err := XMLDecode(wsddNsMap, bytes.NewBuffer(msg))
	if err != nil {
		log.Debug("XML: %s", err)
		return
	}

	// Decode the message
	for _, elem := range elements {
		switch elem.Path {
		case "/s:Envelope/s:Header/a:Action":
			action = elem.Text
		case "/s:Envelope/s:Body/d:ProbeMatches/d:ProbeMatch/d:Types":
			types = elem.Text
		case "/s:Envelope/s:Body/d:ProbeMatches/d:ProbeMatch/d:XAddrs":
			for _, url := range strings.Fields(elem.Text) {
				url, err := fixIpv6URLZone(url, zone)
				if err != nil {
					log.Debug("%s: %s", elem.Text, err)
				} else {
					xaddrs = append(xaddrs, url)
				}
			}
		case "/s:Envelope/s:Body/d:ProbeMatches/d:ProbeMatch/a:EndpointReference/a:Address":
			address = elem.Text
		}
	}

	// Check for duplicates
	if alreadyKnown(address, false) {
		log.Debug("message ignored: %s already known", address)
		return
	}

	// Write debug messages
	log.Debug("message parameters:")
	log.Debug("  action:  %q", action)
	log.Debug("  address: %q", address)
	log.Debug("  types:   %q", types)
	log.Debug("  xaddrs:  %q", xaddrs)

	// Check results
	switch action {
	case "http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches",
		"https://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches":
	default:
		log.Debug("message ignored: unknown action")
		return
	}

	if len(xaddrs) == 0 {
		log.Debug("message ignored: no xaddrs")
		return
	}

	if strings.Index(types, "ScanDeviceType") < 0 {
		log.Debug("message ignored: not a scanner")
		return
	}

	if address == "" {
		log.Debug("message ignored: no endpoint address")
		return
	}

	endpoints := make(map[Endpoint]struct{})
	for _, xaddr := range xaddrs {
		epp := getMetadata(log, address, xaddr)
		for _, endpoint := range epp {
			endpoints[endpoint] = struct{}{}
		}
	}

	// Update table of already known addresses
	alreadyKnown(address, true)

	for endpoint := range endpoints {
		url, err := fixIpv6URLZone(endpoint.URL, zone)
		if err != nil {
			log.Debug("%s: %s", endpoint.URL, err)
		} else {
			endpoint.URL = url
			outchan <- endpoint
		}
	}
}

// recvUDPMessages receives and handles UDP messages
func recvUDPMessages(conn *net.UDPConn, zone string, outchan chan Endpoint) {
	buf := make([]byte, 32768)

	for {
		n, from, _ := conn.ReadFromUDP(buf)
		if n > 0 {
			msg := buf[:n]

			LogDebug("%s: UDP message received", from)
			LogTrace(fmt.Sprintf("udp-from-%s", from), msg)

			log := LogBegin(fmt.Sprintf("%s", from))
			handleUDPMessage(log, msg, zone, outchan)
			log.Commit()
		}
	}
}

// WSSDDiscover performs WS-Discovery for scanner devices
func WSSDDiscover(outchan chan Endpoint) {
	var conns []*net.UDPConn
	var zones []string

	// Create sockets, one per interface
	addrs := ifAddrs()

	LogDebug("Interface addresses:")
	for _, addr := range addrs {
		LogDebug("  %s", addr.IP)
	}

	for _, addr := range addrs {
		// Note, on IPv6 WSSD works with link local
		// addresses only
		ip4 := addr.IP.To4() != nil
		if ip4 || addr.IP.IsLinkLocalUnicast() {
			proto := "udp4"
			if !ip4 {
				proto = "udp6"
			}
			conn, err := net.ListenUDP(proto, addr)
			LogCheck(err)

			if conn != nil {
				conns = append(conns, conn)
				zones = append(zones, addr.Zone)
			}
		}
	}

	// Start receivers
	for i, conn := range conns {
		go recvUDPMessages(conn, zones[i], outchan)
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
			LogDebug("%s: UDP message sent", dest)
			LogTrace(fmt.Sprintf("udp-to-%s", dest), []byte(msg))
		}

		time.Sleep(250 * time.Millisecond)
	}
}
