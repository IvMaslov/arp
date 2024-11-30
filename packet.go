package arp

import (
	"encoding/binary"
	"net"
	"net/netip"
)

const (
	OpcodeRequest = 1
	OpcodeReply   = 2
)

// ARP packet from RFC 826  https://www.rfc-editor.org/rfc/rfc826
type Packet struct {
	// byte length of each hardware address
	HarwAddrLength uint8
	// byte length of each protocol address
	ProtocolAddrLength uint8
	// opcode (REQUEST | REPLY)
	Opcode uint16
	// Hardware address space (e.g., Ethernet, Packet Radio Net.)
	HarwAddrSpace uint16
	// Protocol address space.  For Ethernet hardware, this is from the set of type fields <ether_type>
	ProtocolAddrSpace uint16
	// Hardware address of sender of this packet, with length <HarwAddrLength>
	SrcHarwAddr net.HardwareAddr
	// Hardware address of destination of this packet (if known)
	DstHarwAddr net.HardwareAddr
	//	Protocol address of sender of this packet, with length <ProtocolAddrLength>
	SrcProtocolAddr netip.Addr
	// Protocol address of destination
	DstProtocolAddr netip.Addr
}

func NewRequest() *Packet {
	return &Packet{
		HarwAddrLength:     6,
		ProtocolAddrLength: 4,
		Opcode:             OpcodeRequest,
		HarwAddrSpace:      1,
		ProtocolAddrSpace:  2048,
	}
}

func NewReply() *Packet {
	return &Packet{
		HarwAddrLength:     6,
		ProtocolAddrLength: 4,
		Opcode:             OpcodeReply,
		HarwAddrSpace:      1,
		ProtocolAddrSpace:  2048,
	}
}

func (p *Packet) WithSrcHarwAddr(addr net.HardwareAddr) *Packet {
	p.SrcHarwAddr = addr

	return p
}

func (p *Packet) WithSrcProtocolAddr(addr netip.Addr) *Packet {
	p.SrcProtocolAddr = addr
	if addr.Is6() {
		p.ProtocolAddrLength = 16
	}

	return p
}

func (p *Packet) WithDstHarwAddr(addr net.HardwareAddr) *Packet {
	p.DstHarwAddr = addr

	return p
}

func (p *Packet) WithDstProtocolAddr(addr netip.Addr) *Packet {
	p.DstProtocolAddr = addr
	if addr.Is6() {
		p.ProtocolAddrLength = 16
	}

	return p
}

func (p *Packet) Marshal() []byte {
	buf := make([]byte, 2*4+2*p.HarwAddrLength+2*p.ProtocolAddrLength)

	binary.BigEndian.PutUint16(buf[:2], p.HarwAddrSpace)
	binary.BigEndian.PutUint16(buf[2:4], p.ProtocolAddrSpace)

	buf[4] = p.HarwAddrLength
	buf[5] = p.ProtocolAddrLength

	binary.BigEndian.PutUint16(buf[6:8], p.Opcode)

	offset := 8 + p.HarwAddrLength

	copy(buf[8:offset], p.SrcHarwAddr)
	copy(buf[offset:offset+p.ProtocolAddrLength], p.SrcProtocolAddr.AsSlice())
	offset += p.ProtocolAddrLength

	copy(buf[offset:offset+p.HarwAddrLength], p.DstHarwAddr)
	offset += p.HarwAddrLength

	copy(buf[offset:], p.DstProtocolAddr.AsSlice())

	return buf
}

func (p *Packet) Unmarshal(input []byte) {
	if len(input) < 28 {
		return
	}

	p.HarwAddrSpace = binary.BigEndian.Uint16(input[:2])
	p.ProtocolAddrSpace = binary.BigEndian.Uint16(input[2:4])
	p.HarwAddrLength = input[4]
	p.ProtocolAddrLength = input[5]
	p.Opcode = binary.BigEndian.Uint16(input[6:8])

	if len(input) < int(2*4+2*p.HarwAddrLength+2*p.ProtocolAddrLength) {
		return
	}

	offset := 8 + p.HarwAddrLength

	p.SrcHarwAddr = input[8:offset]
	p.SrcProtocolAddr, _ = netip.AddrFromSlice(input[offset : offset+p.ProtocolAddrLength])
	offset += p.ProtocolAddrLength

	p.DstHarwAddr = input[offset : offset+p.HarwAddrLength]
	offset += p.HarwAddrLength

	p.DstProtocolAddr, _ = netip.AddrFromSlice(input[offset : offset+p.ProtocolAddrLength])
}
