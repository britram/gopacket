// Copyright 2012 Google, Inc. All rights reserved.
// Copyright 2009-2011 Andreas Krennmair. All rights reserved.
// Copyright 2017 Brian Trammell. All Rights Reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"fmt"

	"github.com/google/gopacket"
)

const (
	typeShortP0P1            = 0x01
	typeShortP0P2            = 0x02
	typeShortP0P4            = 0x03
	typeShortP1P1            = 0x21
	typeShortP1P2            = 0x22
	typeShortP1P4            = 0x23
	typeShortCidP0P1         = 0x41
	typeShortCidP0P2         = 0x42
	typeShortCidP0P4         = 0x43
	typeShortCidP1P1         = 0x61
	typeShortCidP1P2         = 0x62
	typeShortCidP1P4         = 0x63
	typeVersionNego          = 0x81
	typeClientInitial        = 0x82
	typeServerStatelessRetry = 0x83
	typeServerCleartext      = 0x84
	typeClientCleartext      = 0x85
	typeLongZeroRtt          = 0x86
	typeLongPhaseZero        = 0x87
	typeLongPhaseOne         = 0x88
	typePublicReset          = 0x89
)

var quicPayloadOffset = map[byte]int{
	typeShortP0P1:            10,
	typeShortP0P2:            11,
	typeShortP0P4:            13,
	typeShortP1P1:            10,
	typeShortP1P2:            11,
	typeShortP1P4:            13,
	typeShortCidP0P1:         18,
	typeShortCidP0P2:         19,
	typeShortCidP0P4:         21,
	typeShortCidP1P1:         18,
	typeShortCidP1P2:         19,
	typeShortCidP1P4:         21,
	typeVersionNego:          25,
	typeClientInitial:        25,
	typeServerStatelessRetry: 25,
	typeServerCleartext:      25,
	typeClientCleartext:      25,
	typeLongZeroRtt:          25,
	typeLongPhaseZero:        25,
	typeLongPhaseOne:         25,
	typePublicReset:          25,
}

var quicCIDOffset = map[byte]int{
	typeShortP0P1:            0,
	typeShortP0P2:            0,
	typeShortP0P4:            0,
	typeShortP1P1:            0,
	typeShortP1P2:            0,
	typeShortP1P4:            0,
	typeShortCidP0P1:         9,
	typeShortCidP0P2:         9,
	typeShortCidP0P4:         9,
	typeShortCidP1P1:         9,
	typeShortCidP1P2:         9,
	typeShortCidP1P4:         9,
	typeVersionNego:          9,
	typeClientInitial:        9,
	typeServerStatelessRetry: 9,
	typeServerCleartext:      9,
	typeClientCleartext:      9,
	typeLongZeroRtt:          9,
	typeLongPhaseZero:        9,
	typeLongPhaseOne:         9,
	typePublicReset:          9,
}

var quicPNOffset = map[byte]int{
	typeShortP0P1:            9,
	typeShortP0P2:            9,
	typeShortP0P4:            9,
	typeShortP1P1:            9,
	typeShortP1P2:            9,
	typeShortP1P4:            9,
	typeShortCidP0P1:         17,
	typeShortCidP0P2:         17,
	typeShortCidP0P4:         17,
	typeShortCidP1P1:         17,
	typeShortCidP1P2:         17,
	typeShortCidP1P4:         17,
	typeVersionNego:          17,
	typeClientInitial:        17,
	typeServerStatelessRetry: 17,
	typeServerCleartext:      17,
	typeClientCleartext:      17,
	typeLongZeroRtt:          17,
	typeLongPhaseZero:        17,
	typeLongPhaseOne:         17,
	typePublicReset:          17,
}

var quicPNLength = map[byte]int{
	typeShortP0P1:            1,
	typeShortP0P2:            2,
	typeShortP0P4:            4,
	typeShortP1P1:            1,
	typeShortP1P2:            2,
	typeShortP1P4:            4,
	typeShortCidP0P1:         1,
	typeShortCidP0P2:         2,
	typeShortCidP0P4:         4,
	typeShortCidP1P1:         1,
	typeShortCidP1P2:         2,
	typeShortCidP1P4:         4,
	typeVersionNego:          4,
	typeClientInitial:        4,
	typeServerStatelessRetry: 4,
	typeServerCleartext:      4,
	typeClientCleartext:      4,
	typeLongZeroRtt:          4,
	typeLongPhaseZero:        4,
	typeLongPhaseOne:         4,
	typePublicReset:          4,
}

var quicKeyPhase = map[byte]int{
	typeShortP0P1:            0,
	typeShortP0P2:            0,
	typeShortP0P4:            0,
	typeShortP1P1:            1,
	typeShortP1P2:            1,
	typeShortP1P4:            1,
	typeShortCidP0P1:         0,
	typeShortCidP0P2:         0,
	typeShortCidP0P4:         0,
	typeShortCidP1P1:         1,
	typeShortCidP1P2:         1,
	typeShortCidP1P4:         1,
	typeVersionNego:          -1,
	typeClientInitial:        -1,
	typeServerStatelessRetry: -1,
	typeServerCleartext:      -1,
	typeClientCleartext:      -1,
	typeLongZeroRtt:          -1,
	typeLongPhaseZero:        0,
	typeLongPhaseOne:         1,
	typePublicReset:          -1,
}

type QUIC struct {
	UDP // a QUIC packet is a UDP packet; delegate for udp.go for UDP stuff

	ConnID       uint64
	PktNum       uint32
	PktNumLen    uint8
	Version      uint32
	KeyPhase     int
	HasConnID    bool
	IsLongHeader bool

	qType byte
}

// LayerType returns gopacket.LayerTypeUDP
func (q *QUIC) LayerType() gopacket.LayerType { return LayerTypeQUIC }

func (q *QUIC) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {

	// get UDP header first
	q.SrcPort = UDPPort(binary.BigEndian.Uint16(data[0:2]))
	q.sPort = data[0:2]
	q.DstPort = UDPPort(binary.BigEndian.Uint16(data[2:4]))
	q.dPort = data[2:4]
	q.Length = binary.BigEndian.Uint16(data[4:6])
	q.Checksum = binary.BigEndian.Uint16(data[6:8])

	// check for stunted packet or jumbogram
	if q.Length == 0 {
		return fmt.Errorf("QUIC jumbograms not supported")
	}

	if q.Length < 10 {
		return fmt.Errorf("QUIC packet too small: %d bytes", q.Length)
	}

	// find payload offset
	offset, ok := quicPayloadOffset[q.qType]
	if !ok {
		return fmt.Errorf("Unknown QUIC packet type %d", q.qType)
	}

	// check for truncation
	hlen := int(q.Length)
	if hlen < offset {
		return fmt.Errorf("Incomplete QUIC header: %d of %d bytes for type %d", q.Length, offset, q.qType)
	}

	if hlen > len(data) {
		df.SetTruncated()
		hlen = len(data)
	}

	// unpack quic header
	cidoffset := quicCIDOffset[q.qType]
	if cidoffset > 0 {
		q.ConnID = binary.BigEndian.Uint64(data[cidoffset : cidoffset+8])
		q.HasConnID = true
	} else {
		q.HasConnID = false
	}

	pnoffset := quicPNOffset[q.qType]
	switch quicPNLength[q.qType] {
	case 1:
		q.PktNum = uint32(data[pnoffset])
		q.PktNumLen = 1
	case 2:
		q.PktNum = uint32(binary.BigEndian.Uint16(data[pnoffset : pnoffset+2]))
		q.PktNumLen = 2
	case 4:
		q.PktNum = binary.BigEndian.Uint32(data[pnoffset : pnoffset+2])
		q.PktNumLen = 4
	}

	q.KeyPhase = quicKeyPhase[q.qType]
	q.IsLongHeader = q.qType >= 0x80

	return nil
}

//
func decodeQUIC(data []byte, p gopacket.PacketBuilder) error {
	quic := &QUIC{}
	err := quic.DecodeFromBytes(data, p)
	p.AddLayer(quic)
	p.SetTransportLayer(quic)
	if err != nil {
		return err
	}
	return p.NextDecoder(quic.NextLayerType())
}
