import socket
import sys
import struct
import select

"""
Steps:
  1. receive a packet at the internal net interface
  2. map the packet to be sent in the external net interface
  3. change the properties of the packet to be sent
  4. send the packet
  4.1. if some 'response' to the packet is received in the mapped external net interface
  4.2. forward the packet to the internal net interface

Helpers:
  1. Get MAC address from socket: https://www.bitforestinfo.com/2018/01/how-to-get-mac-address-using-python.html
"""

ETH_P_ALL = 0x0003


def bytes_to_mac(bytesmac):
    return ":".join("{:02x}".format(x) for x in bytesmac)


if __name__ == "__main__":
    print('wasuuuuppp')

    # Create 2 sockets, one for each interface eth0 and eth1
    try:
        s0 = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                           socket.ntohs(ETH_P_ALL))
        s0.bind(('eth0', 0))
        s1 = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                           socket.ntohs(ETH_P_ALL))
        s1.bind(('eth1', 0))
    except OSError as msg:
        print('Error'+str(msg))
        sys.exit(1)

    print('Sockets created!')

    # Sockets from which we expect to read
    inputs = [s0, s1]

    while inputs:

        readable, _, exceptional = select.select(
            inputs, [], inputs)

        for s in readable:
            (packet, addr) = s.recvfrom(65536)

            eth_length = 14
            eth_header = packet[:14]

            eth = struct.unpack("!6s6sH", eth_header)

            interface = "eth0" if s is s0 else "eth1"
            print("Received from "+interface)
            print("MAC Dst: "+bytes_to_mac(eth[0]))
            print("MAC Src: "+bytes_to_mac(eth[1]))
            print("Type: "+hex(eth[2]))
