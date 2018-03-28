import sys, dpkt, socket
from dpkt.compat import compat_ord

TYPE = -1
TYPE_LINUX = 0
TYPE_WINDOW = 1
FIRST_PACKET = 0

class Trace:
    src_ip = 0
    dst_ip = 0
    rtr = []
    proto = []
    num_frags = 0
    off_frags = 0
    src_pkts = []

def mac_addr(address):      #Refer to Reference                     #Used to convert binary to mac addresses
    return ":".join("%02x" % compat_ord(b) for b in address)

def ip_address(inet):      #Refer to Reference                     #Used to convert binary to Ip Addresses
    return socket.inet_ntop(socket.AF_INET, inet)

def linux_workflow(eth):
    global trace
    ip = eth.data
    if ip.p == dpkt.ip.IP_PROTO_UDP:
        udp = ip.data
        if udp.dport >= 33434 and udp.dport <= 33534:
            for packet in trace.src_pkts:
                if udp.dport == packet.data.data.dport:
                    return 0
            trace.src_pkts.append(eth)
    elif ip.p == dpkt.ip.IP_PROTO_ICMP:
        icmp = ip.data
        icmp_stat = icmp.data
        ip_old = icmp_stat.data
        udp_old = ip_old.data
        if udp_old.dport >= 33434 and udp_old.dport <= 33534:
            for packet in trace.src_pkts:
                if udp_old.dport == packet.data.data.dport:
                    trace.rtr.append(eth)
                    print("TTL EXCEEDED FOUND")
                    print(ip_address(ip.src))
    else:
        return 0

def window_workflow(eth):
    
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
        if count >= 10:
            break
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

        # src_ip = ip_address(ip.src)
        # dst_ip = ip_address(ip.dst)
        # print("\nPacket:" + str(count))
        # print(src_ip)
        # print(dst_ip)
        # print(ip.ttl)


trace = Trace()
main()