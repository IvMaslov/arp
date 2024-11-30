package arp

import (
	"net"
	"net/netip"
	"testing"
)

func Test_Packet_Marshal(t *testing.T) {
	p := &Packet{
		HarwAddrLength:     6,
		ProtocolAddrLength: 4,
		Opcode:             1,
		HarwAddrSpace:      1,
		ProtocolAddrSpace:  2048,
		SrcProtocolAddr:    netip.AddrFrom4([4]byte{10, 10, 10, 10}),
		DstProtocolAddr:    netip.AddrFrom4([4]byte{10, 10, 10, 11}),
		SrcHarwAddr:        net.HardwareAddr{0xee, 0xee, 0xee, 0xee, 0xee, 0xee},
	}

	expected := []byte{0, 1, 8, 0, 6, 4, 0, 1, 238, 238, 238, 238, 238, 238, 10, 10, 10, 10, 0, 0, 0, 0, 0, 0, 10, 10, 10, 11}

	if len(expected) != len(p.Marshal()) {
		t.Error("Len is not equal")
	}

	for i, v := range p.Marshal() {
		if v != expected[i] {
			t.Errorf("Byte [%v|%v] not equal %v", i, v, expected[i])
		}
	}
}

func Test_Packet_Unmarshal(t *testing.T) {
	input := []byte{0, 1, 8, 0, 6, 4, 0, 1, 238, 238, 238, 238, 238, 238, 10, 10, 10, 10, 0, 0, 0, 0, 0, 0, 10, 10, 10, 11}

	p := &Packet{}
	p.Unmarshal(input)

	if p.HarwAddrLength != 6 {
		t.Error("Unmarshal Error")
	}

	if p.ProtocolAddrLength != 4 {
		t.Error("Unmarshal Error")
	}

	if p.Opcode != 1 {
		t.Error("Unmarshal Error")
	}

	if p.HarwAddrSpace != 1 {
		t.Error("Unmarshal Error")
	}

	if p.ProtocolAddrSpace != 0x0800 {
		t.Error("Unmarshal Error")
	}

	for _, v := range p.SrcHarwAddr {
		if v != 0xee {
			t.Error("Unmarshal Error")
		}
	}

	if p.SrcProtocolAddr != netip.AddrFrom4([4]byte{10, 10, 10, 10}) {
		t.Error("Unmarshal Error")
	}

	for _, v := range p.DstHarwAddr {
		if v != 0 {
			t.Error("Unmarshal Error")
		}
	}

	if p.DstProtocolAddr != netip.AddrFrom4([4]byte{10, 10, 10, 11}) {
		t.Error("Unmarshal Error")
	}
}
