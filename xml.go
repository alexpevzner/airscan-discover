// Discovery tool for sane-airscan compatible devices
//
// Copyright (C) 2020 and up by Alexander Pevzner (pzz@apevzner.com)
// See LICENSE for license terms and conditions
//
// XML decoder

package main

import (
	"bytes"
	"encoding/xml"
	"io"
)

type XMLElement struct {
	Path, Text string
}

// XMLDecode parses XML document, and represents it as a sequence of
// Path/Text pairs, where Path is a full path to the element, starting
// from root, and Text is the XML element body, stripped from leading
// and trailing space. Elements with empty body text are not included
// into this sequence. Namespace prefixes are rewritten according to
// the 'ns' map. Full namespace URL used as map index, and value that
// corresponds to the index replaced with map value. If URL is not
// found in the map, prefix replaced with "-" string
func XMLDecode(ns map[string]string, in io.Reader) ([]XMLElement, error) {
	var elements []XMLElement
	var path bytes.Buffer
	var lenStack []int

	decoder := xml.NewDecoder(in)
	for {
		token, err := decoder.Token()
		if err != nil {
			if err != io.EOF {
				return nil, err
			}
			break
		}

		switch t := token.(type) {
		case xml.StartElement:
			lenStack = append(lenStack, path.Len())

			prefix, ok := ns[t.Name.Space]
			if !ok {
				prefix = "-"
			}
			path.WriteByte('/')
			path.WriteString(prefix)
			path.WriteByte(':')
			path.WriteString(t.Name.Local)

		case xml.EndElement:
			last := len(lenStack) - 1
			path.Truncate(lenStack[last])
			lenStack = lenStack[:last]

		case xml.CharData:
			text := string(bytes.TrimSpace(t))
			if text != "" {
				elements = append(elements, XMLElement{path.String(), text})
			}
		}
	}

	return elements, nil
}
