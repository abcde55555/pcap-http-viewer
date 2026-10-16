package parser

import (
	"bufio"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"io"
	"net"
	"os"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// multiReader holds an open file and a buffered reader used by pcapgo readers.
type multiReader struct {
	file   *os.File
	reader *bufio.Reader
}

func openReader(path string) (*multiReader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	return &multiReader{file: f, reader: bufio.NewReaderSize(f, 1<<20)}, nil
}

func (m *multiReader) close() error { return m.file.Close() }

// packetSource is the common subset of pcapgo.NgReader and pcapgo.Reader.
type packetSource interface {
	ReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error)
	LinkType() layers.LinkType
}

func buildFlow(src, dst []byte, ethType uint16) gopacket.Flow {
	var endpointType gopacket.EndpointType
	switch ethType {
	case 0x0800:
		endpointType = layers.EndpointIPv4
	case 0x86dd:
		endpointType = layers.EndpointIPv6
	default:
		endpointType = layers.EndpointIPv4
	}
	return gopacket.NewFlow(endpointType, net.IP(src), net.IP(dst))
}

func buildPorts(srcPort, dstPort int) gopacket.Flow {
	src := []byte{byte(srcPort >> 8), byte(srcPort)}
	dst := []byte{byte(dstPort >> 8), byte(dstPort)}
	return gopacket.NewFlow(layers.EndpointTCPPort, src, dst)
}

// flowSrc returns the source IP bytes and source TCP port from two flows.
func flowSrc(netFlow, transFlow gopacket.Flow) (net.IP, int) {
	ip := append(net.IP(nil), netFlow.Src().Raw()...)
	raw := transFlow.Src().Raw()
	var port int
	if len(raw) >= 2 {
		port = int(raw[0])<<8 | int(raw[1])
	}
	return ip, port
}

func newGzipReader(r io.Reader) (*gzip.Reader, error) { return gzip.NewReader(r) }

func newFlateReader(r io.Reader) io.Reader {
	// HTTP "deflate" may be zlib-wrapped (RFC 1950) or raw deflate (RFC 1951).
	// Try zlib first; on failure fall back to raw.
	zr, err := zlib.NewReader(r)
	if err == nil {
		return zr
	}
	return flate.NewReader(r)
}
