import dpkt
import socket
from dpkt.utils import mac_to_str
parse_data = {}


def analyze_packet(packet):
    global parse_data
    parse_data = {}
    # 以太网帧
    eth = dpkt.ethernet.Ethernet(packet)
    parse_data["raw_data"] = packet
    eth_data = {}
    eth_data["eth_frame_len"] = len(eth)
    eth_data["eth_data_len"] = len(eth.data)
    eth_data["eth_src_mac"] = mac_to_str(eth.src)
    eth_data["eth_dst_mac"] = mac_to_str(eth.dst)
    eth_data["eth_type"] = eth.type
    eth_data["eth_dst_mac"] = mac_to_str(eth.dst)
    parse_data["eth"] = eth_data
    # 判断类型
    if eth.type == dpkt.ethernet.ETH_TYPE_IP:
        # IP数据报
        ip = eth.data
        if ip.v == 4:
            analyze_ipv4_packet(ip)
        elif ip.v == 6:
            analyze_ipv6_packet(ip)
        else:
            # 其他IP版本
            print(f"Other IP version: {ip.v}")
    elif eth.type == dpkt.ethernet.ETH_TYPE_ARP:
        # ARP数据包
        arp = eth.data
        analyze_arp_packet(arp)
    else:
        # 其他以太网帧
        print(f"Other Ethernet type: {hex(eth.type)}")
    return parse_data


def analyze_ipv4_packet(ip):
    # ip.len：IP包头和数据的总长度，单位字节。
    # ip.ttl：IP包在网络中的最大跳数，每经过一个路由器就会减一，减到零就会被丢弃。
    # ip.df：1表示IP包不允许分片，0允许分片。
    # ip.mf：IP包是否是一个分片，为0表示不是一个分片或者是最后一个分片。
    # ip.offset：IP包在原始数据中的偏移量，单位8字节。
    ip_data = {}
    ip_data["ip_version"] = ip.v
    ip_data["ip_length"] = ip.len
    ip_data["ip_id"] = ip.id
    ip_data["ip_source_address"] = socket.inet_ntoa(ip.src)
    ip_data["ip_destination_address"] = socket.inet_ntoa(ip.dst)
    ip_data["ip_header_length"] = ip.hl * 4
    ip_data["ip_TOS"] = ip.tos
    ip_data["ip_flags"] = ip.offset >> 13
    ip_data["ip_offset"] = ip.offset & 0x1fff
    # 判断协议类型
    if ip.p == dpkt.ip.IP_PROTO_TCP:
        tcp = ip.data
        analyze_tcp_segment(tcp, ip_data)
    elif ip.p == dpkt.ip.IP_PROTO_UDP:
        udp = ip.data
        analyze_udp_datagram(udp, ip_data)
    elif ip.p == dpkt.ip.IP_PROTO_ICMP:
        icmp = ip.data
        analyze_icmp_packet(icmp, ip_data)
    else:
        # 其他协议类型
        print(f"Other protocol: {ip.p}")


def analyze_ipv6_packet(ip):
    ip6_data = {}
    ip6_data["ip6_version"] = ip.v
    ip6_data["ip6_length"] = ip.plen
    ip6_data["ip_source_address"] = socket.inet_ntop(socket.AF_INET6, ip.src)
    ip6_data["ip_destination_address"] = socket.inet_ntop(socket.AF_INET6, ip.dst)
    if ip.nxt == dpkt.ip.IP_PROTO_TCP:
        tcp = ip.data
        analyze_tcp_segment(tcp, ip6_data)
    elif ip.nxt == dpkt.ip.IP_PROTO_UDP:
        udp = ip.data
        analyze_udp_datagram(udp, ip6_data)
    elif ip.nxt == dpkt.ip.IP_PROTO_ICMP6:
        icmp6 = ip.data
        analyze_icmpv6_packet(icmp6, ip6_data)
    else:
        print(f"Other protocol: {ip.nxt}")


def analyze_arp_packet(arp):
    global parse_data
    arp_data = {}
    arp_data["arp_hardware_type"] = arp.hrd
    arp_data["arp_protocol_type"] = arp.pro
    arp_data["arp_hardware_address_length"] = arp.hln
    arp_data["arp_protocol_address_length"] = arp.pln
    arp_data["arp_operation_code"] = arp.op
    arp_data["arp_sender_hardware_address"] = arp.sha.hex()
    arp_data["arp_sender_protocol_address"] = socket.inet_ntoa(arp.spa)
    arp_data["arp_target_hardware_address"] = arp.tha.hex()
    arp_data["arp_target_protocol_address"] = socket.inet_ntoa(arp.tpa)
    parse_data["arp"] = arp_data


def analyze_tcp_segment(tcp, ip_data):
    global parse_data
    ip_data["ip_protocol"] = "tcp"
    parse_data["ip"] = ip_data
    tcp_data = {}
    tcp_data["tcp_source_port"] = str(tcp.sport)
    tcp_data["tcp_destination_port"] = str(tcp.dport)
    tcp_data["tcp_sequence_number"] = tcp.seq
    tcp_data["tcp_acknowledgment_number"] = tcp.ack
    tcp_data["tcp_window_size"] = tcp.win
    tcp_data["tcp_flags"] = tcp.flags
    tcp_data["tcp_header_len"] = tcp.off * 4
    # 是否有应用层数据
    if tcp.data and len(tcp.data) > 0:
        tcp_data["application_layer_data_length"] = len(tcp.data)
        parse_data["tcp"] = tcp_data
        if tcp.dport == 80 or tcp.sport == 80:
            # HTTP
            analyze_http_data(tcp.data)
        elif tcp.dport == 443 or tcp.sport == 443:
            # HTTPS
            analyze_https_data(tcp.data)
        else:
            print(f"Other Application")
    else:
        parse_data["tcp"] = tcp_data


def analyze_udp_datagram(udp, ip_data):
    global parse_data
    ip_data["ip_protocol"] = "udp"
    parse_data["ip"] = ip_data
    udp_data = {}
    udp_data["source_port"] = str(udp.sport)
    udp_data["destination_port"] = str(udp.dport)
    udp_data["length"] = udp.ulen
    if udp.data:
        udp_data["application_layer_data_length"] = len(udp.data)
        parse_data["udp"] = udp_data
        if udp.dport == 53 or udp.sport == 53:
            # DNS
            analyze_dns_data(udp.data)
        else:
            print(f"Other Application")
    else:
        parse_data["udp"] = udp_data


def analyze_icmp_packet(icmp, ip_data):
    global parse_data
    ip_data["ip_protocol"] = "icmp"
    parse_data["ip"] = ip_data
    icmp_data = {}
    icmp_data["icmp_type"] = icmp.type
    icmp_data["icmp_code"] = icmp.code
    icmp_data["icmp_checksum"] = icmp.sum
    icmp_data["icmp_data"] = icmp.data
    parse_data["icmp"] = icmp_data


def analyze_icmpv6_packet(icmp6, ip_data):
    global parse_data
    ip_data["ip_protocol"] = "icmp6"
    parse_data["ip"] = ip_data
    icmp6_data = {}
    icmp6_data["icmp6_type"] = icmp6.type
    icmp6_data["icmp6_code"] = icmp6.code
    icmp6_data["icmp6_checksum"] = icmp6.sum
    parse_data["icmp6"] = icmp6_data


def analyze_http_data(data):
    global parse_data
    http_data = {}
    http_data["http_raw_data"] = data
    error = 0
    try:
        # 解析http请求或响应
        http = dpkt.http.Request(data)
        http_data["http_type"] = "request"
        http_data["http_uri"] =http.uri
        http_data["http_method"] = http.method
    except Exception as e:
        print(e)
        try:
            http = dpkt.http.Response(data)
            http_data["http_type"] = "response"
            http_data["http_status"] = http.status
            http_data["http_reason"] = http.reason
        except Exception as e:
            error = 1
            print(e)
    if error == 1:
        parse_data["http"] = http_data
        return
    http_data["http_version"] = http.version
    headers = {}
    for k, v in http.headers.items():
        headers[k] = v
    http_data["http_headers"] = headers
    http_data["http_body"] = http.body
    parse_data["http"] = http_data


def analyze_https_data(data):
    global parse_data
    https_data = {}
    https_data["https_raw_data"] = data.hex()
    try:
        https = dpkt.ssl.TLS(data)
        records = {}
        tls = https.records[0]
        records["tls_type"] = tls.type
        records["tls_version"] = tls.version
        records["tls_length"] = tls.length
        records["tls_compressed"] = "True" if tls.compressed else "False"
        records["tls_encrypted"] = "True" if tls.encrypted else "False"
        https_data["records"] = records
    except Exception as e:
        print("HTTPS error ", e)
    parse_data["https"] = https_data


def analyze_dns_data(data):
    global parse_data
    try:
        # 解析 DNS 数据包
        dns = dpkt.dns.DNS(data)
        dns_data = {}
        dns_data["dns_ID"] = dns.id
        dns_data["dns_QR"] = dns.qr
        dns_data["dns_OPCODE"] = dns.opcode
        dns_data["dns_AA"] = dns.aa
        dns_data["dns_TC"] = dns.tc
        dns_data["dns_RD"] = dns.rd
        dns_data["dns_RA"] = dns.ra
        dns_data["dns_RCODE"] = dns.rcode
        parse_data["dns"] = dns_data
    except Exception as e:
        print(e)


# libpcap读取方式
# errbuf = ct.create_string_buffer(pcap.PCAP_ERRBUF_SIZE + 1)
# fname = b"realtime.cap"
# fin = pcap.open_offline(fname, errbuf)
# if errbuf.value:
#     print(errbuf.value)
# pheader = pcap.pkthdr()
# i = 0
# while True:
#     print("i = ", i)
#     i = i + 1
#     if i > 10:
#         break
#     packet = pcap.next(fin, pheader)
#     if not packet:
#         break
#     print(i, pheader.ts.tv_sec, pheader.len, pheader.caplen)
#     packet_data = bytes(packet)
# pcap.close(fin)

# dpkt读取方式
# f = open('realtime.cap', "rb")
# pcaps = dpkt.pcap.Reader(f)
# for ts, packet in pcaps:
#     print('Timestamp: ', str(datetime.datetime.utcfromtimestamp(ts)), '   raw data: ', packet)
#     analyze_packet(packet)
#     print()