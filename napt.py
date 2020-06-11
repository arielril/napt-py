from util.format import bytes_to_mac
import queue
from queue import Queue
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
  2. How to create a template Vagrantfile: https://github.com/test-kitchen/kitchen-vagrant/blob/master/templates/Vagrantfile.erb
"""

ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800
ETH_LEN = 14


napt_table = list(dict({
    "protocol": "",
    "ip_src": "",
    "ip_dst": "",
    "port_src": "",
    "port_dst": "",
}))


def getSocketByProto(proto: int = socket.getprotobyname('icmp')) -> socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, proto)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    return s


def isIP(eth) -> bool:
    return eth[2] == 2048


# def getWritableSocketFromPacket(packet):
#     wrt_sock = getSocketByProto(socket.getprotobyname('icmp'))
#     return wrt_sock


def showPacket(packet):
    eth_header = packet[:ETH_LEN]
    eth = struct.unpack('!6s6sH', eth_header)

    print('MAC Src: '+bytes_to_mac(eth[1]))
    print('MAC Dst: '+bytes_to_mac(eth[0]))
    print('Type: '+hex(eth[2]))
    print('{0}'.format(eth[2]))


if __name__ == '__main__':
    # Create 2 sockets, one for each interface eth0 and eth1
    try:
        sniff_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                     socket.ntohs(ETH_P_IP))
        sniff_socket.bind(('eth0', 0))
        ext_sniff = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                  socket.ntohs(ETH_P_IP))
        ext_sniff.bind(('eth1', 0))
    except OSError as msg:
        print('Error'+str(msg))
        sys.exit(1)

    print('Sockets created!')

    inputs = [sniff_socket, ext_sniff]
    outputs = []
    message_queues = {}

    while inputs:
        readable, writable, exceptional = select.select(
            inputs, outputs, inputs)

        for s in readable:
            packet = s.recv(2048)
            print('received', packet)
            eth_header = packet[:ETH_LEN]

            eth = struct.unpack('!6s6sH', eth_header)

            nexthdr = packet[ETH_LEN:]

            if isIP(eth):
                if s is sniff_socket:
                    deliv_socket = socket.socket(
                        socket.AF_INET, socket.SOCK_RAW, socket.htons(ETH_P_IP))
                    deliv_socket.setsockopt(
                        socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                    deliv_socket.bind(('10.0.1.1', 0))

                    ip_unpack = struct.unpack(
                        '!BBHHHBBH4s4s', packet[ETH_LEN:20+ETH_LEN])
                    ip_dest = socket.inet_ntoa(ip_unpack[9])  # PUB NET

                    if deliv_socket not in message_queues.keys():
                        message_queues[deliv_socket] = Queue()

                    message_queues[deliv_socket].put({
                        'pkt': nexthdr,
                        'dest': (ip_dest, 0),
                    })
                    outputs.append(deliv_socket)

                elif s is ext_sniff:
                    deliv_socket = socket.socket(
                        socket.AF_INET, socket.SOCK_RAW, socket.htons(ETH_P_IP))
                    deliv_socket.setsockopt(
                        socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                    deliv_socket.bind(('10.0.0.1', 0))

                    ip_unpack = struct.unpack(
                        '!BBHHHBBH4s4s', packet[ETH_LEN:20+ETH_LEN])
                    ip_dest = socket.inet_ntoa(ip_unpack[9])  # PRIV NET

                    if deliv_socket not in message_queues.keys():
                        message_queues[deliv_socket] = Queue()

                    message_queues[deliv_socket].put({
                        'pkt': nexthdr,
                        'dest': (ip_dest, 0),
                    })

                    outputs.append(deliv_socket)

                else:
                    print('not sniff')
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

        for w in writable:
            try:
                msg = message_queues[w].get_nowait()
            except queue.Empty:
                # no more messages from w
                outputs.remove(w)
            else:
                w.sendto(msg['pkt'], msg['dest'])

        for e in exceptional:
            inputs.remove(e)
            if e in outputs:
                outputs.remove(e)
            e.close()
            del message_queues[e]
