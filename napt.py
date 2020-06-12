import typing

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

TCP_INIT_PORT = 40000
UDP_INIT_PORT = 5000

"""
    ip_src: str
    ip_dst: str
    port_src: int | None
    port_dst: int | None
    port_tlt: int | None
"""
napt_table = list()


def isIP(eth) -> bool:
    return eth[2] == 2048


def isIcmp(ip_packet: bytes) -> bool:
    ip_unpack = struct.unpack(
        '!BBHHHBBH4s4s', ip_packet[:20])

    return ip_unpack[6] == 1


def isTCP(ip_packet: bytes) -> bool:
    ip_unpack = struct.unpack(
        '!BBHHHBBH4s4s', ip_packet[:20])

    return ip_unpack[6] == 6


def isUDP(ip_packet: bytes) -> bool:
    ip_unpack = struct.unpack(
        '!BBHHHBBH4s4s', ip_packet[:20])

    return ip_unpack[6] == 50


def getChecksum(msg: bytes) -> int:
    s = 0
    msg = (msg + b'\x00') if len(msg) % 2 else msg
    for i in range(0, len(msg), 2):
        w = msg[i] + (msg[i+1] << 8)
        s = s + w
        s = (s & 0xffff) + (s >> 16)
    s = ~s & 0xffff
    return socket.ntohs(s)


def getPacketWithRedirect(old_pkt: bytes, to_ip_src: str, to_ip_dst: str, to_port_src: int = None) -> bytes:
    ip_unpack = struct.unpack('!BBHHHBBH4s4s', old_pkt[:20])

    if not to_ip_src:
        to_ip_src = socket.inet_ntoa(ip_unpack[8])

    ip_saddr = socket.inet_aton(to_ip_src)
    ip_daddr = socket.inet_aton(to_ip_dst)

    rest_pkt = old_pkt[20:]

    if to_port_src:
        rest_pkt_unpacked = struct.unpack('!HHLLBBHHH', old_pkt[20:40])

        packet = struct.pack(
            '!HHLLBBHHH',
            to_port_src,
            rest_pkt_unpacked[1],  # dest port
            0,  # seq num
            0,  # ack num
            rest_pkt_unpacked[4],  # header len + res
            0,  # flags
            rest_pkt_unpacked[6],  # window size
            0,  # checksum
            0,  # urgent point
        )

        pseudo_tcp_hdr = struct.pack(
            '!4s4sHH',
            ip_saddr,
            ip_daddr,
            socket.IPPROTO_TCP,
            len(packet)+len(old_pkt[40:]),
        )
        checksum = getChecksum(pseudo_tcp_hdr+packet)

        packet = struct.pack(
            '!HHLLBBH',
            to_port_src,
            rest_pkt_unpacked[1],  # dest port
            rest_pkt_unpacked[2],  # seq num
            rest_pkt_unpacked[3],  # ack num
            rest_pkt_unpacked[4],  # data offset
            rest_pkt_unpacked[5],  # flags
            rest_pkt_unpacked[6],  # window
        )+struct.pack('H', checksum)+struct.pack('!H', rest_pkt_unpacked[8])

        rest_pkt = packet+old_pkt[40:]

    newPkt = struct.pack(
        '!BBHHHBBH4s4s',
        ip_unpack[0],
        ip_unpack[1],
        ip_unpack[2],
        ip_unpack[3],
        ip_unpack[4],
        ip_unpack[5],
        ip_unpack[6],
        ip_unpack[7],
        ip_saddr,
        ip_daddr,
    )

    return newPkt+rest_pkt


def addRedirected(ip_src: str, ip_dst: str, port_src: int = None, port_dst: int = None, port_tlt: int = None):
    napt_row = dict({
        'ip_src': ip_src,
        'ip_dst': ip_dst,
        'port_src': port_src,
        'port_dst': port_dst,
        'port_tlt': port_tlt,
    })
    napt_table.append(napt_row)


def addRedirectedICMP(ip_src: str, ip_dst: str, ip_packet: bytes):
    addRedirected(ip_src, ip_dst)


def addRedirectedTCP(ip_src: str, ip_dst: str, port_src: int, port_dst: int, port_translated: int) -> None:
    addRedirected(ip_src, ip_dst, port_src, port_dst)


def getInternalRequestFromExtPacket(ext_ip_packet: bytes) -> dict:
    ip_unpack = struct.unpack('!BBHHHBBH4s4s', ext_ip_packet[:20])
    priv_ip_src_pkt = None
    # ! IP_SRC FROM PUB NET PKT
    priv_ip_dest_pkt = socket.inet_ntoa(ip_unpack[8])
    # ! PORT_SRC FROM PUB NET PKT
    priv_port_dst_pkt = None
    # ! PORT_DST FROM PUB NET PKT
    pub_port_tlt_pkt = None

    if isTCP(ext_ip_packet) or isUDP(ext_ip_packet):
        tp_unpack = struct.unpack('!HH', ext_ip_packet[20:24])
        # source port
        priv_port_dst_pkt = tp_unpack[0]
        # dest port
        pub_port_tlt_pkt = tp_unpack[1]

    result = None
    for val in napt_table:
        if val['ip_dst'] == priv_ip_dest_pkt \
                and val['port_src'] == priv_port_dst_pkt \
                and val['port_tlt'] == pub_port_tlt_pkt:
            result = val
            break

    if result:
        # consume the response
        napt_table.remove(val)

    return result


def getOpenPort(protocol: str = 'tcp') -> int:
    tcp_ports = []

    for val in napt_table:
        if val and val['port_tlt']:
            tcp_ports.append(val['port_tlt'])

    tcp_ports.sort()

    last_port = TCP_INIT_PORT

    for p in tcp_ports:
        if p > last_port:
            last_port = p

    return last_port+1


if __name__ == '__main__':
    print('running....')
    # Create 2 sockets, one for each interface eth0 and eth1
    try:
        sniff_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                     socket.ntohs(ETH_P_IP))
        sniff_socket.bind(('eth0', 0))
        ext_sniff = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                  socket.ntohs(ETH_P_IP))
        ext_sniff.bind(('eth1', 0))
    except OSError as msg:
        print('failed to create the sniffer socket'+str(msg))
        sys.exit(1)

    inputs = [sniff_socket]
    outputs = []
    message_queues = {}

    while inputs:
        readable, writable, exceptional = select.select(
            inputs, outputs, inputs)

        for s in readable:
            (packet, addr) = s.recvfrom(65536)

            if not packet and not s is sniff_socket:
                if s in outputs:
                    outputs.remove(s)
                inputs.remove(s)
                s.close()

                del message_queues[s]

            eth_header = packet[:ETH_LEN]
            eth = struct.unpack('!6s6sH', eth_header)
            ip_packet = packet[ETH_LEN:]

            if s is sniff_socket:

                # * Handle ICMP "connections"
                if isIP(eth):

                    if isIcmp(ip_packet):
                        nsock = socket.socket(
                            socket.AF_INET, socket.SOCK_RAW, socket.htons(ETH_P_IP))
                        nsock.setsockopt(
                            socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

                        ip_unpack = struct.unpack(
                            '!BBHHHBBH4s4s', ip_packet[:20])

                        ip_source = socket.inet_ntoa(ip_unpack[8])  # PRIV NET
                        ip_dest = socket.inet_ntoa(ip_unpack[9])  # PUB NET

                        if nsock not in message_queues.keys():
                            message_queues[nsock] = Queue()

                        addRedirectedICMP(ip_source, ip_dest, ip_packet)
                        print('translating s: ({}, {}) => ({}, {}) to ({},{}) => ({},{})'.format(
                            ip_source, 0,
                            ip_dest, 0,
                            '10.0.1.1', 0,
                            ip_dest, 0,
                        ))
                        msg = {
                            'pkt': ip_packet,
                            'dest': (ip_dest, 0),
                            'priv_to_pub': True,
                            'redirect_port': None,
                        }

                        message_queues[nsock].put(msg)
                        inputs.append(ext_sniff)
                        outputs.append(nsock)

                    else:
                        # * handle TCP and UDP
                        nsock = socket.socket(
                            socket.AF_INET, socket.SOCK_RAW, socket.htons(ETH_P_IP))
                        nsock.setsockopt(socket.IPPROTO_IP,
                                         socket.IP_HDRINCL, 1)

                        ip_unpack = struct.unpack(
                            '!BBHHHBBH4s4s', ip_packet[:20])
                        ip_source = socket.inet_ntoa(ip_unpack[8])  # PRIV NET
                        ip_dest = socket.inet_ntoa(ip_unpack[9])  # PUB NET

                        port_unpack = struct.unpack('!HH', ip_packet[20:24])
                        port_source = port_unpack[0]
                        port_dest = port_unpack[1]

                        if nsock not in message_queues.keys():
                            message_queues[nsock] = Queue()

                        port_translated = getOpenPort('tcp')
                        addRedirectedTCP(
                            ip_source, ip_dest, port_source, port_dest, port_translated)

                        print('translating s: ({}, {}) => ({}, {}) to ({},{}) => ({},{})'.format(
                            ip_source, port_source,
                            ip_dest, port_dest,
                            '10.0.1.1', port_translated,
                            ip_dest, port_dest,
                        ))

                        msg = {
                            'pkt': ip_packet,
                            'dest': (ip_dest, port_dest),
                            'priv_to_pub': True,
                            'redirect_port': port_translated,
                        }
                        message_queues[nsock].put(msg)
                        # inputs.append(nsock)
                        outputs.append(nsock)

            else:
                # * not the initial connection

                if isIP(eth):
                    # disable external sniffer
                    inputs.remove(ext_sniff)

                    nsock = socket.socket(
                        socket.AF_INET, socket.SOCK_RAW, socket.htons(ETH_P_IP))
                    nsock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

                    ip_unpack = struct.unpack(
                        '!BBHHHBBH4s4s', ip_packet[:20])
                    pkt_ip_source = socket.inet_ntoa(ip_unpack[8])  # PRIV NET
                    pkt_ip_dest = socket.inet_ntoa(ip_unpack[9])  # PUB NET

                    port_unpack = struct.unpack('!HH', ip_packet[20:24])
                    pkt_port_source = port_unpack[0]
                    pkt_port_dest = port_unpack[1]

                    fromNaptTable = getInternalRequestFromExtPacket(ip_packet)

                    if not fromNaptTable:
                        print('\nrequest to response not found in db')
                        continue

                    if nsock not in message_queues.keys():
                        message_queues[nsock] = Queue()

                    ip_dest = fromNaptTable['ip_src']
                    port_dest = 0

                    if fromNaptTable['port_src']:
                        port_dest = fromNaptTable['port_src']

                    print('translating ns: ({}, {}) => ({}, {}) to ({},{}) => ({},{})'.format(
                        pkt_ip_source, pkt_port_source,
                        pkt_ip_dest, pkt_port_dest,
                        pkt_ip_source, pkt_port_source,
                        ip_dest, port_dest,
                    ))

                    msg = {
                        'pkt': ip_packet,
                        'dest': (ip_dest, port_dest),
                        'priv_to_pub': False,
                        'redirect_port': port_dest,
                    }
                    message_queues[nsock].put(msg)

                    outputs.append(nsock)

        for w in writable:
            try:
                msg = message_queues[w].get_nowait()

                if msg['priv_to_pub']:
                    new_ip_src = '10.0.1.1'
                    new_port_src = msg['redirect_port']
                else:
                    new_ip_src = None
                    new_port_src = msg['redirect_port']

                msg['pkt'] = getPacketWithRedirect(
                    msg['pkt'], new_ip_src, msg['dest'][0], new_port_src)

            except queue.Empty as e:
                # no more messages from w
                outputs.remove(w)
            else:
                print('Sending msg to ({}, {})'.format(
                    msg['dest'][0], msg['dest'][1]))
                w.sendto(msg['pkt'], msg['dest'])

        for e in exceptional:
            inputs.remove(e)
            if e in outputs:
                outputs.remove(e)
            e.close()
            del message_queues[e]
