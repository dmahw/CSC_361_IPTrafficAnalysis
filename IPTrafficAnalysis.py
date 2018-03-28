import sys, dpkt, socket
from dpkt.compat import compat_ord

TYPE = -1
TYPE_LINUX = 0
TYPE_WINDOW = 1
FIRST_PACKET = 0

class Trace:
    src_ip = 0
    dst_ip = 0
    rtrs = []
    protos = []
    num_frags = 0
    off_frags = 0
    src_pkts = []
    src_ff = []
    src_mf = []

def mac_addr(address):      #Refer to Reference                     #Used to convert binary to mac addresses
    return ":".join("%02x" % compat_ord(b) for b in address)

def ip_address(inet):      #Refer to Reference                     #Used to convert binary to Ip Addresses
    return socket.inet_ntop(socket.AF_INET, inet)

def list_src_dst():
    global trace
    print("The IP address of the source node: " + trace.src_ip)
    print("The IP address of ultimate destination node: " + trace.dst_ip)

def add_proto(eth):
    global trace
    for proto in trace.protos:
        if eth.data.p == proto:
            return 0
    trace.protos.append(eth.data.p)
    return 1

def list_protos():
    global trace
    protos = trace.protos
    protos.sort()
    print("The values in the protocol field of IP headers:")
    for proto in protos:
        if proto == 1:
            print("\t1: ICMP")
        elif proto == 17:
            print("\t17: UDP")
    return 1

def add_router(eth):
    global trace
    for packet in trace.rtrs:
        if ip_address(eth.data.src) == ip_address(packet.data.src):
            return 0
    trace.rtrs.append(eth)
    print(len(trace.rtrs))
    return 1

def list_routers():
    global trace
    count = 0
    print("The IP addresses of the intermediate destination nodes:")
    for packet in trace.rtrs:
        count = count + 1
        if count != 1:
            print(",")
        print("\trouter " + str(count) + ": " + ip_address(packet.data.src), end = "")

    print(".")
    return 0

def linux_workflow(eth):
    global trace
    ip = eth.data
    for packet in trace.src_pkts:
        print(repr(packet))
        if ip.id == packet.data.id:
            
            print(packet.data.off & dpkt.ip.IP_MF)

    if ip.p == dpkt.ip.IP_PROTO_UDP:
        udp = ip.data
        if udp.dport >= 33434 and udp.dport <= 33534:
            for packet in trace.src_pkts:
                if udp.dport == packet.data.data.dport:
                    return 0
                if packet.data.off & dpkt.ip.IP_MF == 0x2000:
                    trace.src_ff.append(eth)
                else:
                    trace.src_pkts.append(eth)
                    add_proto(eth)
            print("LINUX ECHO")
            return 1

    elif ip.p == dpkt.ip.IP_PROTO_ICMP:
        icmp = ip.data
        icmp_stat = icmp.data
        ip_old = icmp_stat.data
        udp_old = ip_old.data
        if icmp.type == 11:
            if udp_old.dport >= 33434 and udp_old.dport <= 33534:
                for packet in trace.src_pkts:
                    if udp_old.dport == packet.data.data.dport:
                        add_router(eth)
                        add_proto(eth)
                        print("LINUX TTL EXCEEDED")
                        print(ip_address(ip.src))
                        return 1
    return 0

def window_workflow(eth):
    global trace
    ip = eth.data
    if ip.p == dpkt.ip.IP_PROTO_ICMP:
        icmp = ip.data
        if icmp.type == 8:
            for packet in trace.src_pkts:
                if icmp.data.seq == packet.data.data.data.seq:
                    return 0
            trace.src_pkts.append(eth)
            add_proto(eth)
            print("WINDOW NEW ECHO")
            return 1

        elif icmp.type == 11:
            for packet in trace.src_pkts:
                if icmp.data.data.data.data.seq == packet.data.data.data.seq:
                    print("WINDOW TTL EXCEED")
                    add_router(eth)
                    add_proto(eth)
                    return 1
    return 0

def get_first_packet(eth):
    global FIRST_PACKET
    global trace
    global TYPE

    ip = eth.data
    if ip.p == dpkt.ip.IP_PROTO_UDP:
        udp = ip.data
        if FIRST_PACKET == 0:
            if ip.ttl == 1: 
                if udp.dport >= 33434 and udp.dport <= 33534:
                    FIRST_PACKET = 1
                    TYPE = TYPE_LINUX
                    print("Traceroute is Linux Type")
                    trace.src_pkts.append(eth)
                    
                    trace.src_ip = ip_address(ip.src)
                    trace.dst_ip = ip_address(ip.dst)
                    print("Source IP: " + trace.src_ip)
                    print("Destination IP: " + trace.dst_ip)
                    print("Time to live: " + str(ip.ttl))
                    return 1
            else:
                return 0

    elif ip.p == dpkt.ip.IP_PROTO_ICMP:
        icmp = ip.data
        if FIRST_PACKET == 0:
            if ip.ttl == 1:
                if icmp.type == 8:
                    FIRST_PACKET = 1
                    TYPE = TYPE_WINDOW
                    
                    trace.src_ip = ip_address(ip.src)
                    trace.dst_ip = ip_address(ip.dst)

                    print("Traceroute is Windows Type")
                    print("Source IP: " + trace.src_ip)
                    print("Destination IP: " + trace.dst_ip)
                    print("Time to live: " + str(ip.ttl))
                    trace.src_pkts.append(eth)
            else:
                return 0
    return 0


def main():
    traceFileName = sys.argv[1]

    traceFile = open(traceFileName, 'rb')
    tracePcap = dpkt.pcapng.Reader(traceFile)

    count = 0

    for timeStamp, buf in tracePcap:
        count = count + 1
        # if count >= 10:
        #     break
        print("\n********** Packet " + str(count) + " **********")

        eth = dpkt.ethernet.Ethernet(buf)
        
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue

        if FIRST_PACKET == 0:
            get_first_packet(eth)     
        elif TYPE == TYPE_LINUX:
            linux_workflow(eth)
        elif TYPE == TYPE_WINDOW:
            window_workflow(eth)   

    list_src_dst()
    list_routers()
    list_protos()
    return 0

trace = Trace()
main()