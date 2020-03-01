// Discovery tool for sane-airscan compatible devices
//
// Copyright (C) 2020 and up by Alexander Pevzner (pzz@apevzner.com)
// See LICENSE for license terms and conditions
//
// DNS-SD discovery

package main

import (
	"bytes"
	"fmt"
	"log"
	"net"

	"github.com/godbus/dbus/v5"
	"github.com/holoplot/go-avahi"
)

func DNSSdDiscover(out chan *Endpoint) {
	conn, err := dbus.SystemBus()
	if err != nil {
		log.Fatal("Cannot get system bus")
	}

	server, err := avahi.ServerNew(conn)
	if err != nil {
		log.Fatal("Avahi new failed")
	}

	sb, err := server.ServiceBrowserNew(avahi.InterfaceUnspec,
		avahi.ProtoUnspec, "_uscan._tcp", "local", 0)
	if err != nil {
		log.Fatal("ServiceBrowserNew() failed", err.Error())
	}

	for {
		select {
		case service := <-sb.AddChannel:
			service, err = server.ResolveService(service.Interface,
				service.Protocol, service.Name, service.Type,
				service.Domain, avahi.ProtoUnspec, 0)
			if err != nil {
				continue
			}

			addr := net.ParseIP(service.Address)
			if addr == nil {
				continue
			}

			endpoint := &Endpoint{
				Name: service.Name,
			}

			rs := ""

			for _, txt := range service.Txt {
				name := ""
				if i := bytes.IndexByte(txt, '='); i >= 0 {
					name = string(bytes.ToLower(txt[:i]))
					txt = txt[i+1:]
				} else {
					name = string(bytes.ToLower(txt))
					txt = txt[len(txt):]
				}

				switch name {
				case "rs":
					rs = string(bytes.Trim(txt, "/"))
				}
			}

			if addr.To4() != nil {
				endpoint.URL = fmt.Sprintf("http://%s:%d/%s", addr, service.Port, rs)
			} else if addr.IsLinkLocalUnicast() {
				endpoint.URL = fmt.Sprintf("http://[%s%%25%d]:%d/%s", addr,
					service.Interface, service.Port, rs)
			} else {
				endpoint.URL = fmt.Sprintf("http://[%s]:%d/%s", addr, service.Port, rs)
			}

			out <- endpoint
		}
	}
}
