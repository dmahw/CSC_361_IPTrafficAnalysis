import sys, dpkt, socket
from dpkt.compat import compat_ord

TYPE = -1
TYPE_LINUX = 0
TYPE_WINDOW = 1
FIRST_PACKET = 0

class Trace:
    src_ip = 0
    dst_ip = 0
    rtr_ip = []
    proto = []
    num_frags = 0
    off_frags = 0
    src_pkts = []

def mac_addr(address):      #Refer to Reference                     #Used to convert binary to mac addresses
    return ":".join("%02x" % compat_ord(b) for b in address)

def ipAddress(inet):      #Refer to Reference                     #Used to convert binary to Ip Addresses
    return socket.inet_ntop(socket.AF_INET, inet)

def linux_workflow(eth):
    global trace
    ip = eth.data
    if ip.p == dpkt.ip.IP_PROTO_UDP:
        udp = ip.data
        print("UDP Packet")
        trace.src_pkts.append(eth)
        
        print("Time to live: " + str(ip.ttl))
        
        # print(trace.src_pkts[0].data.ttl)
        # print(trace.src_pkts[0].data.data.sport)
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
                FIRST_PACKET = 1
                TYPE = TYPE_LINUX
                print("Traceroute is Linux Type")
                trace.src_pkts.append(eth)
                
                trace.src_ip = ipAddress(ip.src)
                trace.dst_ip = ipAddress(ip.dst)
                print("Source IP: " + trace.src_ip)
                print("Destination IP: " + trace.dst_ip)
                print("Time to live: " + str(ip.ttl))
                print("UDP Checksum: " + str(udp.sum))
                
                # print(trace.src_pkts[0].data.ttl)
                # print(trace.src_pkts[0].data.data.sport)
                return 1
            else:
                return 0

    elif ip.p == dpkt.ip.IP_PROTO_ICMP:
        icmp = ip.data
        if FIRST_PACKET == 0:
            if ip.ttl == 1:
                FIRST_PACKET = 1
                TYPE = TYPE_WINDOW
                print("Traceroute is Windows Type")
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
        if count >= 19:
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

        # src_ip = ipAddress(ip.src)
        # dst_ip = ipAddress(ip.dst)
        # print("\nPacket:" + str(count))
        # print(src_ip)
        # print(dst_ip)
        # print(ip.ttl)


trace = Trace()
main()