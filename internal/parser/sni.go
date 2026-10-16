package parser

import (
	"encoding/binary"
)

// tlsVersionName maps a TLS legacy version number to a human label.
func tlsVersionName(v uint16) string {
	switch v {
	case 0x0300:
		return "SSL 3.0"
	case 0x0301:
		return "TLS 1.0"
	case 0x0302:
		return "TLS 1.1"
	case 0x0303:
		return "TLS 1.2"
	case 0x0304:
		return "TLS 1.3"
	default:
		return ""
	}
}

// parseSNI extracts the server_name extension from a TLS ClientHello in data.
// It returns the SNI hostname and the best-effort TLS version label. Data may
// point at the start of a TLS record or at the TCP payload. All parsing is
// bounds-checked; malformed input returns ("", "") with no panic.
func parseSNI(data []byte) (sni string, version string) {
	if len(data) < 6 {
		return "", ""
	}
	// Optional TLS record header (content type 0x16 handshake).
	off := 0
	if data[0] == 0x16 {
		if len(data) < 5+4 {
			return "", ""
		}
		recVer := binary.BigEndian.Uint16(data[1:3])
		recLen := int(binary.BigEndian.Uint16(data[3:5]))
		if 5+recLen > len(data) {
			recLen = len(data) - 5
		}
		version = tlsVersionName(recVer)
		off = 5
		_ = recLen
		// Handshake header: type(1)=0x01 ClientHello, length(3).
		if off+4 > len(data) || data[off] != 0x01 {
			return "", version
		}
		off += 4
	} else {
		// Not a TLS record we recognize.
		return "", ""
	}

	// ClientHello body: version(2), random(32), sessionID<var>.
	if off+34 > len(data) {
		return "", version
	}
	// Prefer the supported_versions extension for TLS 1.3, but record legacy too.
	legacyVer := binary.BigEndian.Uint16(data[off : off+2])
	if version == "" {
		version = tlsVersionName(legacyVer)
	}
	off += 34 // version + random

	// sessionID
	if off+1 > len(data) {
		return "", version
	}
	sessLen := int(data[off])
	off++
	if off+sessLen > len(data) {
		return "", version
	}
	off += sessLen

	// cipherSuites
	if off+2 > len(data) {
		return "", version
	}
	csLen := int(binary.BigEndian.Uint16(data[off : off+2]))
	off += 2
	if off+csLen > len(data) {
		return "", version
	}
	off += csLen

	// compressionMethods
	if off+1 > len(data) {
		return "", version
	}
	cmLen := int(data[off])
	off++
	if off+cmLen > len(data) {
		return "", version
	}
	off += cmLen

	// extensions
	if off+2 > len(data) {
		return "", version
	}
	extTotal := int(binary.BigEndian.Uint16(data[off : off+2]))
	off += 2
	extEnd := off + extTotal
	if extEnd > len(data) {
		extEnd = len(data)
	}

	for off+4 <= extEnd {
		extType := binary.BigEndian.Uint16(data[off : off+2])
		extLen := int(binary.BigEndian.Uint16(data[off+2 : off+4]))
		off += 4
		if off+extLen > extEnd {
			break
		}
		if extType == 0x00 { // server_name
			sni = parseServerNameExt(data[off : off+extLen])
		}
		if extType == 0x002b { // supported_versions
			if v := parseSupportedVersions(data[off : off+extLen]); v != "" {
				version = v
			}
		}
		off += extLen
	}
	return sni, version
}

func parseServerNameExt(d []byte) string {
	if len(d) < 2 {
		return ""
	}
	listLen := int(binary.BigEndian.Uint16(d[0:2]))
	end := 2 + listLen
	if end > len(d) {
		end = len(d)
	}
	p := 2
	for p+3 <= end {
		nameType := d[p]
		nameLen := int(binary.BigEndian.Uint16(d[p+1 : p+3]))
		p += 3
		if p+nameLen > end {
			break
		}
		if nameType == 0 { // host_name
			return string(d[p : p+nameLen])
		}
		p += nameLen
	}
	return ""
}

func parseSupportedVersions(d []byte) string {
	if len(d) < 1 {
		return ""
	}
	// Client: length(1) then versions(2 each); Server: single version(2).
	if len(d) == 2 {
		return tlsVersionName(binary.BigEndian.Uint16(d[0:2]))
	}
	p := 0
	listLen := int(d[p])
	p++
	if p+listLen > len(d) {
		return ""
	}
	// Prefer the highest supported version offered.
	best := ""
	for p+2 <= p+listLen && p+2 <= len(d) {
		v := binary.BigEndian.Uint16(d[p : p+2])
		if name := tlsVersionName(v); name != "" {
			best = name
		}
		p += 2
	}
	return best
}
