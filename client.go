package arp

import (
	"net"
	"net/netip"
	"os/exec"
	"strings"

	"github.com/IvMaslov/ethernet"
	"github.com/IvMaslov/socket"
)

var broadcastMac = []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

type Client struct {
	s  *socket.Interface
	ip netip.Addr
}

// Creates new ARP client, pass empty string to use default gateway
func New(device string) (*Client, error) {
	if device == "" {
		device = getDefaultGateway()
	}

	sock, err := socket.New(socket.WithDevice(device))

	if err != nil {
		return nil, err
	}

	ifce, err := net.InterfaceByName(device)
	if err != nil {
		return nil, err
	}

	addrs, err := ifce.Addrs()
	if err != nil {
		return nil, err
	}

	return &Client{
		s:  sock,
		ip: findIP(addrs),
	}, nil
}

// Read first ARP packet
func (c *Client) Read() (*Packet, error) {
	buf := make([]byte, 1500)

	for {
		_, err := c.s.Read(buf)
		if err != nil {
			return nil, err
		}

		ethFr := &ethernet.Frame{}
		err = ethFr.Unmarshal(buf)
		if err != nil {
			return nil, err
		}

		if ethFr.EtherType != ethernet.EtherTypeARP {
			continue
		}

		arpPacket := &Packet{}
		arpPacket.Unmarshal(ethFr.Payload)

		return arpPacket, nil
	}
}

// Write ARP packet to certain MAC address
func (c *Client) Write(p *Packet, to net.HardwareAddr) error {
	data := p.Marshal()

	ethFr := ethernet.Frame{
		SrcHarwAddr:  c.s.GetHardwareAddr(),
		DestHarwAddr: to,
		EtherType:    ethernet.EtherTypeARP,
		Payload:      data,
	}

	frame, err := ethFr.Marshal()
	if err != nil {
		return err
	}

	_, err = c.s.Write(frame)
	if err != nil {
		return err
	}

	return nil
}

// Close arp client
func (c *Client) Close() error {
	return c.s.Close()
}

// Make ARP request looking for ip
func (c *Client) Request(ip netip.Addr) error {
	p := NewRequest().
		WithDstProtocolAddr(ip).
		WithSrcProtocolAddr(c.ip).
		WithSrcHarwAddr(c.s.GetHardwareAddr()).
		WithDstHarwAddr(broadcastMac)

	err := c.Write(p, broadcastMac)

	return err
}

// Make ARP request and wait for response
func (c *Client) Resolve(ip netip.Addr) (net.HardwareAddr, error) {
	if err := c.Request(ip); err != nil {
		return nil, err
	}

	for {
		p, err := c.Read()
		if err != nil {
			return nil, err
		}

		if p.Opcode == OpcodeReply && p.SrcProtocolAddr == ip {
			return p.SrcHarwAddr, nil
		}
	}
}

func findIP(addrs []net.Addr) netip.Addr {
	for _, addr := range addrs {
		ip, _, err := net.ParseCIDR(addr.String())
		if err != nil {
			continue
		}

		if ipAddr := netip.MustParseAddr(ip.String()); ipAddr.Is4() {
			return ipAddr
		}
	}

	return netip.IPv4Unspecified()
}

func getDefaultGateway() string {
	data, err := exec.Command("/sbin/ip", "route").Output()
	if err != nil {
		return ""
	}

	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "default") {
			splitted := strings.Split(line, " ")

			for i, v := range splitted {
				if v == "dev" {
					return splitted[i+1]
				}
			}
		}
	}

	return ""
}
