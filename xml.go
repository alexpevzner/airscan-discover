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
	Parent     *XMLElement
	Children   []*XMLElement
}

// XMLDecode parses XML document, and represents it as a linear
// sequence of XML elements
//
// Each element has a Path, which is a full path to the element,
// starting from root, Text, which is XML element body, stripped
// from leading and trailing space, and Children, which includes
// its direct children, children of children and so on.
//
// Namespace prefixes are rewritten according to the 'ns' map.
// Full namespace URL used as map index, and value that corresponds
// to the index replaced with map value. If URL is not found in the
// map, prefix replaced with "-" string
func XMLDecode(ns map[string]string, in io.Reader) ([]*XMLElement, error) {
	var elements []*XMLElement
	var elem *XMLElement
	var path bytes.Buffer

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
			prefix, ok := ns[t.Name.Space]
			if !ok {
				prefix = "-"
			}
			path.WriteByte('/')
			path.WriteString(prefix)
			path.WriteByte(':')
			path.WriteString(t.Name.Local)

			elem = &XMLElement{
				Path:   path.String(),
				Parent: elem,
			}
			elements = append(elements, elem)

			for p := elem.Parent; p != nil; p = p.Parent {
				p.Children = append(p.Children, elem)
			}

		case xml.EndElement:
			elem = elem.Parent
			if elem != nil {
				path.Truncate(len(elem.Path))
			} else {
				path.Truncate(0)
			}

		case xml.CharData:
			if elem != nil {
				elem.Text = string(bytes.TrimSpace(t))
			}
		}
	}

	return elements, nil
}
