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

//******************************************************************************
//
// QUIC Decoding Layer
// ------------------------------------------
// This file provides a GoPacket decoding layer for QUIC.
// It follows the First Implementation Draft version of the protocol
// as documented in draft-ietf-quic-protocol-04.
//
//******************************************************************************
//

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
	typeShortP0P1:            2,
	typeShortP0P2:            3,
	typeShortP0P4:            5,
	typeShortP1P1:            2,
	typeShortP1P2:            3,
	typeShortP1P4:            5,
	typeShortCidP0P1:         10,
	typeShortCidP0P2:         11,
	typeShortCidP0P4:         13,
	typeShortCidP1P1:         10,
	typeShortCidP1P2:         11,
	typeShortCidP1P4:         13,
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

var quicCIDOffset = map[byte]int{
	typeShortP0P1:            0,
	typeShortP0P2:            0,
	typeShortP0P4:            0,
	typeShortP1P1:            0,
	typeShortP1P2:            0,
	typeShortP1P4:            0,
	typeShortCidP0P1:         1,
	typeShortCidP0P2:         1,
	typeShortCidP0P4:         1,
	typeShortCidP1P1:         1,
	typeShortCidP1P2:         1,
	typeShortCidP1P4:         1,
	typeVersionNego:          1,
	typeClientInitial:        1,
	typeServerStatelessRetry: 1,
	typeServerCleartext:      1,
	typeClientCleartext:      1,
	typeLongZeroRtt:          1,
	typeLongPhaseZero:        1,
	typeLongPhaseOne:         1,
	typePublicReset:          1,
}

var quicVNOffset = map[byte]int{
	typeShortP0P1:            0,
	typeShortP0P2:            0,
	typeShortP0P4:            0,
	typeShortP1P1:            0,
	typeShortP1P2:            0,
	typeShortP1P4:            0,
	typeShortCidP0P1:         0,
	typeShortCidP0P2:         0,
	typeShortCidP0P4:         0,
	typeShortCidP1P1:         0,
	typeShortCidP1P2:         0,
	typeShortCidP1P4:         0,
	typeVersionNego:          13,
	typeClientInitial:        13,
	typeServerStatelessRetry: 13,
	typeServerCleartext:      13,
	typeClientCleartext:      13,
	typeLongZeroRtt:          13,
	typeLongPhaseZero:        13,
	typeLongPhaseOne:         13,
	typePublicReset:          13,
}

var quicPNOffset = map[byte]int{
	typeShortP0P1:            1,
	typeShortP0P2:            1,
	typeShortP0P4:            1,
	typeShortP1P1:            1,
	typeShortP1P2:            1,
	typeShortP1P4:            1,
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
	BaseLayer

	PktType    byte   // packet type, not decoded
	ConnID     uint64 // Connection ID
	HasConnID  bool   // Connection ID is present
	PktNum     uint32 // Packet Number
	PktNumLen  int    // Length of packet number on wire
	Version    uint32 // Version number for VN packets
	HasVersion bool   // Version number is present
	KeyPhase   int    // Key phase for short packets

	payload []byte
}

// LayerType returns the layer type of the QUIC object, which is LayerTypeQUIC.
func (q *QUIC) LayerType() gopacket.LayerType {
	return LayerTypeQUIC
}

// decodeQUIC analyses a byte slice and attempts to decode it as an QUIC
// packet (under a UDP packet)
//
// If it succeeds, it loads p with information about the packet and returns nil.
// If it fails, it returns an error (non nil).
//
// This function is employed in layertypes.go to register the QUIC layer.
func decodeQUIC(data []byte, p gopacket.PacketBuilder) error {
	quic := &QUIC{}
	err := quic.DecodeFromBytes(data, p)

	if err != nil {
		return err
	}

	p.AddLayer(quic)
	p.SetApplicationLayer(quic)
	return p.NextDecoder(quic.NextLayerType())
}

// DecodeFromBytes analyses a byte slice and attempts to decode it as an QUIC
// packet.
//
// If it succeeds, it loads the NTP object with information about the packet
// and returns nil.
// If not, it returns an error (non nil).
func (q *QUIC) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {

	// min quic header size is 2
	if len(data) < 2 {
		return fmt.Errorf("QUIC packet too small: %d bytes", len(data))
	}

	// switch on header type
	q.PktType = data[0]

	// find payload offset and snarf payload
	payoff, ok := quicPayloadOffset[q.PktType]
	if !ok {
		return fmt.Errorf("Unknown QUIC packet type %d", q.PktType)
	}
	q.payload = data[payoff:]

	// unpack quic header
	cidoffset := quicCIDOffset[q.PktType]
	if cidoffset > 0 {
		if len(data) < cidoffset+8 {
			return fmt.Errorf("Truncated QUIC header decoding CID", q.PktType)
		}
		q.ConnID = binary.BigEndian.Uint64(data[cidoffset : cidoffset+8])
		q.HasConnID = true
	} else {
		q.HasConnID = false
	}

	vnoffset := quicVNOffset[q.PktType]
	if vnoffset > 0 {
		if len(data) < vnoffset+4 {
			return fmt.Errorf("Truncated QUIC header decoding version number", q.PktType)
		}
		q.Version = binary.BigEndian.Uint32(data[vnoffset : vnoffset+4])
		q.HasVersion = true
	} else {
		q.HasVersion = false
	}

	pnoffset := quicPNOffset[q.PktType]
	q.PktNumLen = quicPNLength[q.PktType]
	if len(data) < pnoffset+q.PktNumLen {
		return fmt.Errorf("Truncated QUIC header decoding PN", q.PktType)
	}
	switch q.PktNumLen {
	case 1:
		q.PktNum = uint32(data[pnoffset])
	case 2:
		q.PktNum = uint32(binary.BigEndian.Uint16(data[pnoffset : pnoffset+2]))
	case 4:
		q.PktNum = binary.BigEndian.Uint32(data[pnoffset : pnoffset+4])
	}

	q.KeyPhase = quicKeyPhase[q.PktType]

	// FIXME fully decode special long packets?

	return nil
}

// CanDecode returns a set of layers that QUIC objects can decode.
// This is always just LayerTypeQUIC.
func (q *QUIC) CanDecode() gopacket.LayerClass {
	return LayerTypeQUIC
}

// NextLayerType specifies the next layer type; for QUIC, this is always just
// payload (LayerTypePayload), since the header contains no information for
// differentiation.
func (q *QUIC) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// NTP packets do not carry any data payload, so the empty byte slice is retured.
// In Go, a nil slice is functionally identical to an empty slice, so we
// return nil to avoid a heap allocation.
func (q *QUIC) Payload() []byte {
	return q.payload
}
