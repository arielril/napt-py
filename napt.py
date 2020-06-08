from util.format import bytes_to_mac

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



if __name__ == '__main__':
    print('wasuuuuppp')

    # Create 2 sockets, one for each interface eth0 and eth1
    try:
        sniff_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                     socket.ntohs(ETH_P_ALL))
        sniff_socket.bind(('eth0', 0))

        deliv_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                     socket.ntohs(ETH_P_ALL))
        deliv_socket.bind(('eth1', 0))
    except OSError as msg:
        print('Error'+str(msg))
        sys.exit(1)

    print('Sockets created!')

    inputs = [sniff_socket, deliv_socket]
    outputs = []
    message_queues = {}

    while inputs:
        readable, writable, exceptional = select.select(
            inputs, outputs, inputs)
        for s in readable:
            (packet, addr) = s.recvfrom(65536)

            eth_length = 14
            eth_header = packet[:14]

            eth = struct.unpack('!6s6sH', eth_header)

            interface = 'eth0' if s is sniff_socket else 'eth1'
            print('Received from '+interface)
            print('MAC Dst: '+bytes_to_mac(eth[0]))
            print('MAC Src: '+bytes_to_mac(eth[1]))
            print('Type: '+hex(eth[2]))
            print('{0}'.format(eth[2]))

            nexthdr = packet[14:]

            if s is sniff_socket:  # eth0 - 00:00:00:aa:00:01
                if eth[2] == 2048:  # IP
                    # Header Ethernet
                    # MAC Destino - 6 bytes
                    dest_mac = b'\x00\x00\x00\xaa\x00\x03'
                    # MAC Origem - 6 bytes
                    source_mac = b'\x00\x00\x00\xaa\x00\x02'
                    protocol = eth[2]

                    eth_hdr = struct.pack(
                        '!6s6sH', dest_mac, source_mac, protocol)

                    packet = eth_hdr+nexthdr
                    deliv_socket.send(packet)
            else:
                if eth[2] == 2048:  # IP
                    # Header Ethernet
                    # MAC Destino - 6 bytes
                    dest_mac = b'\x00\x00\x00\xaa\x00\x00'
                    # MAC Origem - 6 bytes
                    source_mac = b'\x00\x00\x00\xaa\x00\x01'
                    protocol = eth[2]

                    eth_hdr = struct.pack(
                        '!6s6sH', dest_mac, source_mac, protocol)

                    packet = eth_hdr+nexthdr
                    sniff_socket.send(packet)
