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


# napt_table = list(dict({
#     "protocol": "",
#     "ip_src": "",
#     "ip_dst": "",
#     "port_src": "",
#     "port_dst": "",
# }))

"""
    protocol: str
    ip_src: str
    ip_dst: str
    icmp_pid: int | None
    imcp_seqid: int | None
"""
db = list()


def isIP(eth) -> bool:
    return eth[2] == 2048


def isIcmp(ip_packet: bytes) -> bool:
    ip_unpack = struct.unpack(
        '!BBHHHBBH4s4s', ip_packet[:20])

    return ip_unpack[6] == 1


def getPacketWithRedirect(old_pkt: bytes, to_ip_src: str, to_ip_dst: str) -> bytes:
    rest_pkt = old_pkt[20:]
    ip_unpack = struct.unpack(
        '!BBHHHBBH4s4s', old_pkt[:20])

    if to_ip_src == None:
        to_ip_src = socket.inet_ntoa(ip_unpack[8])

    ip_saddr = socket.inet_aton(to_ip_src)
    ip_daddr = socket.inet_aton(to_ip_dst)

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


def addRedirected(protocol: str, ip_src: str, ip_dst: str, icmp_pid: int = None, icmp_seqid: int = None):
    dbval = dict({
        'protocol': protocol,
        'ip_src': ip_src,
        'ip_dst': ip_dst,
        'icmp_pid': icmp_pid,
        'icmp_seqid': icmp_seqid,
    })
    db.append(dbval)


def addRedirectedICMP(ip_src: str, ip_dst: str, ip_packet: bytes):
    unpack = struct.unpack('!BBHHH', ip_packet[20:28])
    icmp_pid = unpack[3]
    icmp_seqid = unpack[4]

    addRedirected('icmp', ip_src, ip_dst, icmp_pid, icmp_seqid)


def getInternalRequestFromExtPacket(ip_packet: bytes) -> dict:
    ip_unpack = struct.unpack('!BBHHHBBH4s4s', ip_packet[:20])
    priv_ip_src_pkt = None
    # ! IP_SRC PARAM FROM PUB NET
    priv_ip_dest_pkt = socket.inet_ntoa(ip_unpack[8])
    icmp_pid = None
    icmp_seqid = None
    protocol = None

    if isIcmp(ip_packet):
        icmp_unpack = struct.unpack('!BBHHH', ip_packet[20:28])
        icmp_pid = icmp_unpack[3]
        icmp_seqid = icmp_unpack[4]
        protocol = 'icmp'

    result = None

    for val in db:
        if val['protocol'] == protocol \
                and val['ip_dst'] == priv_ip_dest_pkt \
                and val['icmp_pid'] == icmp_pid \
                and val['icmp_seqid'] == icmp_seqid:
            result = val
            break

    if result:
        # consume the response
        db.remove(val)

    return result


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
                        msg = {
                            'pkt': ip_packet,
                            'dest': (ip_dest, 0),
                            'redirect': True,
                            'set_dest': False,
                        }

                        message_queues[nsock].put(msg)
                        inputs.append(ext_sniff)
                        outputs.append(nsock)

                    else:
                        # * handle TCP and UDP
                        print('TCP bitcheee')

            else:
                # * not the initial connection

                if isIP(eth):
                    # disable external sniffer
                    inputs.remove(ext_sniff)

                    nsock = socket.socket(
                        socket.AF_INET, socket.SOCK_RAW, socket.htons(ETH_P_IP))
                    nsock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

                    fromDB = getInternalRequestFromExtPacket(ip_packet)

                    if not fromDB:
                        continue

                    if nsock not in message_queues.keys():
                        message_queues[nsock] = Queue()

                    ip_dest = fromDB['ip_src']
                    msg = {
                        'pkt': ip_packet,
                        'dest': (ip_dest, 0),
                        'redirect': False,
                        'set_dest': True,
                    }
                    message_queues[nsock].put(msg)

                    outputs.append(nsock)

        for w in writable:
            try:
                msg = message_queues[w].get_nowait()

                if msg['redirect']:
                    msg['pkt'] = getPacketWithRedirect(
                        msg['pkt'], '10.0.1.1', msg['dest'][0])
                if msg['set_dest']:
                    msg['pkt'] = getPacketWithRedirect(
                        msg['pkt'], None, msg['dest'][0])

            except queue.Empty as e:
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
