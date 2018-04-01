import sys, dpkt, socket, statistics
from dpkt.compat import compat_ord

TYPE = -1               #Global Variables
TYPE_LINUX = 0
TYPE_WINDOW = 1
FIRST_PACKET = 0

class Packet:
    time = 0
    eth = 0

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
    src_dst = []

def mac_addr(address):      #Refer to Reference                     #Used to convert binary to mac addresses
    return ":".join("%02x" % compat_ord(b) for b in address)

def ip_address(inet):      #Refer to Reference                     #Used to convert binary to Ip Addresses
    return socket.inet_ntop(socket.AF_INET, inet)

def list_src_dst():             #Responsible for listing the ultimate source and destination
    global trace
    print("The IP address of the source node: " + trace.src_ip)
    print("The IP address of ultimate destination node: " + trace.dst_ip)

def add_proto(packet):                  #Add protocol to list
    global trace
    for proto in trace.protos:
        if packet.eth.data.p == proto:
            return 0
    trace.protos.append(packet.eth.data.p)
    return 0

def list_protos():                      #Listing protocols 
    global trace
    protos = trace.protos
    protos.sort()
    print("The values in the protocol field of IP headers:")
    for proto in protos:
        if proto == 1:
            print("\t1: ICMP")
        elif proto == 17:
            print("\t17: UDP")
    return 0

def add_router(packet):                 #Add router as an intermediate router
    global trace
    trace.rtrs.append(packet)
    return 0

def list_routers():                     #List all intermediate routers
    global trace
    global TYPE
    global TYPE_LINUX
    global TYPE_WINDOW
    count = 0
    print("The IP addresses of the intermediate destination nodes:")
    routers = trace.rtrs
    
    print_routers = []                  #Print unique routers
    for rtr in routers:
        unique = 1
        for prtr in print_routers:
            if ip_address(rtr.eth.data.src) == ip_address(prtr.eth.data.src):
                unique = 0
        if unique == 1:
            print_routers.append(rtr)
    if TYPE == TYPE_LINUX:              #Sort routers by their corresponding TTL value
        print_routers = sorted(print_routers, key=lambda x: x.eth.data.data.data.data.data.dport)
    else:
        print_routers = sorted(print_routers, key=lambda x: x.eth.data.data.data.data.data.data.seq)
    for packet in print_routers:        #Print all the routers
        count = count + 1
        if ip_address(packet.eth.data.src) == trace.dst_ip:
            continue
        if count != 1:
            print(",")
        print("\trouter " + str(count) + ": " + ip_address(packet.eth.data.src), end = "")

    print(".")
    return 0

def list_frags():               #Responsible for storing all the fragments 
    global trace
    
    for pri in trace.src_pkts:      #Count number of fragments with the corresponding id from original datagram
        count = 0
        temp = 0
        for frag in trace.src_mf:
            if frag.eth.data.id == pri.eth.data.id:
                count = count + 1
                temp = frag
        if count == 0:              
            print("The number of fragments created from the original datagram " + str(pri.eth.data.id) + " is: " + str(count))
            print("The offset of the last fragment is: 0")
            print("")
        else:
            print("The number of fragments created from the original datagram " + str(pri.eth.data.id) + " is: " + str(count + 1))
            print("The offset of the last fragment is: " + str(temp.eth.data.off * 8))
            print("")
    return 0

def calc_rtt():                     #Calculate all the RTT values for each router
    global trace
    global TYPE
    global TYPE_LINUX
    global TYPE_WINDOW
    rtts = []
    routers = trace.rtrs
    
    if TYPE == TYPE_LINUX:          #If the type is LINUX or Windows, use destination port or seq
        routers = sorted(routers, key=lambda x: x.eth.data.data.data.data.data.dport)
    else:
        routers = sorted(routers, key=lambda x: x.eth.data.data.data.data.data.data.seq)

    group_routers = []
    for rtr in routers:                     #Unique routers, used for calculating with same TTL different port
        unique = 1
        for prtr in group_routers:
            if ip_address(rtr.eth.data.src) == ip_address(prtr.eth.data.src):
                unique = 0
        if unique == 1:
            group_routers.append(rtr)

    if TYPE == TYPE_LINUX:
        for group in group_routers:         #For each router
            rtts = []
            for rtr in routers:             #For each router with the same source as the above router but diff TTL
                if ip_address(rtr.eth.data.src) == ip_address(group.eth.data.src):
                    for src in trace.src_pkts:      #For each router if the originating source port is the same, calc rtt
                        if src.eth.data.data.dport == rtr.eth.data.data.data.data.data.dport:
                            rtts.append(rtr.time - src.time)
                            if src.eth.data.off & dpkt.ip.IP_MF == 0x2000:                          #If the source echo is in fragments
                                for frags in trace.src_mf:                                          #Find all same id fragments with first fragment
                                    if frags.eth.data.id == src.eth.data.id:                        
                                        rtts.append(rtr.time - frags.time)
            print("The avg RTT between " + ip_address(group.eth.data.dst) + " and " + ip_address(group.eth.data.src) + " is: " + str(sum(rtts) / len(rtts)), end = "")
            if len(rtts) > 1:               #Standard deviation, if only 1 rtt for a router, print 0
                print(" ms, the s.d. is: " + str(statistics.stdev(rtts)) + " ms")
            else:
                print(" ms, the s.d. is: 0 ms")

    elif TYPE == TYPE_WINDOW:               #Same workflow as above, but using the ICMP seq, not UDP port
        for group in group_routers:
            rtts = []
            for rtr in routers:
                if ip_address(rtr.eth.data.src) == ip_address(group.eth.data.src):
                    for src in trace.src_pkts:
                        if src.eth.data.data.data.seq == rtr.eth.data.data.data.data.data.data.seq:
                            rtts.append(rtr.time - src.time)
                            if src.eth.data.off & dpkt.ip.IP_MF == 0x2000:                          #If the source echo is in fragments
                                for frags in trace.src_mf:                                          #Find all same id fragments with first fragment
                                    if frags.eth.data.id == src.eth.data.id:                        
                                        rtts.append(rtr.time - frags.time)
            print("The avg RTT between " + ip_address(group.eth.data.dst) + " and " + ip_address(group.eth.data.src) + " is: " + str(sum(rtts) / len(rtts)), end = "")
            if len(rtts) > 1:
                print(" ms, the s.d. is: " + str(statistics.stdev(rtts)) + " ms")
            else:
                print(" ms, the s.d. is: 0 ms")
    return 0

def window_calc_src_dst_rtt():              #Calculate RTT special case window for ultimate source and destination
    global TYPE
    rtts = []
    for dst in trace.src_dst:
        for src in trace.src_pkts:          #For all ultimate src and dst packets, calculate the RTT
            if ip_address(dst.eth.data.src) == ip_address(src.eth.data.dst):
                if dst.eth.data.data.data.seq == src.eth.data.data.data.seq:
                    rtts.append(dst.time - src.time)
    print("The avg RTT between " + trace.src_ip + " and " + trace.dst_ip + " is: " + str(sum(rtts) / len(rtts)), end = "")
    if len(rtts) > 1:
        print(" ms, the s.d. is: " + str(statistics.stdev(rtts)) + " ms")
    else:
        print(" ms, the s.d. is: 0 ms")
    return 0

def linux_workflow(packet):             
    global trace
    ip = packet.eth.data
    for gram in trace.src_ff:               #Check for packet if fragmented
        if ip.id == gram.eth.data.id:
            if packet.eth.data.off & dpkt.ip.IP_MF == 0x2000:
                    trace.src_mf.append(packet)
                    return 0
            trace.src_pkts.append(gram)
            trace.src_mf.append(packet)
            return 0

    if ip.p == dpkt.ip.IP_PROTO_UDP:        #For all UDP packets
        udp = ip.data
        if udp.dport >= 33434 and udp.dport <= 33534:       #Traceroute uses the following ports
            if packet.eth.data.off & dpkt.ip.IP_MF == 0x2000:       #Check for more fragments
                trace.src_ff.append(packet)
                add_proto(packet)
                return 0
            else:
                trace.src_pkts.append(packet)
                add_proto(packet)
                return 0
            return 1

    elif ip.p == dpkt.ip.IP_PROTO_ICMP:         #For all ICMP Pakcets
        icmp = ip.data
        icmp_stat = icmp.data
        ip_old = icmp_stat.data
        udp_old = ip_old.data
        if udp_old.dport >= 33434 and udp_old.dport <= 33534:
            for gram in trace.src_pkts:         #Verify if valid response
                if udp_old.dport == gram.eth.data.data.dport:
                    add_router(packet)
                    add_proto(packet)
                    return 0
    return 0

def window_workflow(packet):                #Window Workflow
    global trace
    ip = packet.eth.data

    for gram in trace.src_ff:               #Check if this is a fragmented packet
        if ip.id == gram.eth.data.id:       #Match fragment with the first fragmented packet
            if packet.eth.data.off & dpkt.ip.IP_MF == 0x2000:
                    trace.src_mf.append(packet)
                    return 0
            trace.src_pkts.append(gram)
            trace.src_mf.append(packet)
            return 0

    if ip.p == dpkt.ip.IP_PROTO_ICMP:               #Check if echo for ALL icmp 
        icmp = ip.data
        if icmp.type == 8:
            for gram in trace.src_pkts:
                if packet.eth.data.off & dpkt.ip.IP_MF == 0x2000:   #Check if their will be more fragments
                    trace.src_ff.append(packet)
                    add_proto(packet)
                    return 0
                else:
                    trace.src_pkts.append(packet)
                    add_proto(packet)
                    return 0
            return 0

        elif icmp.type == 11:                       #Echo reply / response
            for gram in trace.src_pkts:             #Check if response corresponds to a packet
                if icmp.data.data.data.data.seq == gram.eth.data.data.data.seq:
                    add_router(packet)
                    add_proto(packet)
                    return 0
        elif icmp.type == 0:
            if ip_address(packet.eth.data.src) == trace.dst_ip:
                trace.src_dst.append(packet)
    return 0

def get_first_packet(packet):                       #First echo to determine what traceroute is it
    global FIRST_PACKET
    global trace
    global TYPE

    ip = packet.eth.data
    if ip.p == dpkt.ip.IP_PROTO_UDP:                #UDP 
        udp = ip.data
        if FIRST_PACKET == 0:
            if ip.ttl == 1:                         #First echo
                if udp.dport >= 33434 and udp.dport <= 33534:       #Similar workflow as above
                    FIRST_PACKET = 1
                    TYPE = TYPE_LINUX
                    trace.src_ip = ip_address(ip.src)
                    trace.dst_ip = ip_address(ip.dst)

                    if packet.eth.data.off & dpkt.ip.IP_MF == 0x2000:       #Similar workflow as above
                        trace.src_ff.append(packet)
                    else:
                        trace.src_pkts.append(packet)
                        add_proto(packet)
                    return 0
            else:
                return 0

    elif ip.p == dpkt.ip.IP_PROTO_ICMP:
        icmp = ip.data
        if FIRST_PACKET == 0:
            if ip.ttl == 1:
                if icmp.type == 8:                                      #Similar workflow as above
                    FIRST_PACKET = 1
                    TYPE = TYPE_WINDOW
                    trace.src_ip = ip_address(ip.src)
                    trace.dst_ip = ip_address(ip.dst)

                    if packet.eth.data.off & dpkt.ip.IP_MF == 0x2000:   #Similar workflow as above
                        trace.src_ff.append(packet)
                    else:
                        trace.src_pkts.append(packet)
                        add_proto(packet)
                    return 0
            else:
                return 0
    return 0


def main():
    global TYPE
    global TYPE_LINUX
    global TYPE_WINDOW
    traceFileName = sys.argv[1]                 #Get trace file

    traceFile = open(traceFileName, 'rb')
    tracePcap = dpkt.pcapng.Reader(traceFile)   #Read file as PCAPNG

    count = 0

    for timeStamp, buf in tracePcap:
        count = count + 1

        eth = dpkt.ethernet.Ethernet(buf)
        
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue

        packet = Packet()
        packet.time = timeStamp * 1000
        packet.eth = eth
        if FIRST_PACKET == 0:
            get_first_packet(packet)     
        elif TYPE == TYPE_LINUX:
            linux_workflow(packet)
        elif TYPE == TYPE_WINDOW:
            window_workflow(packet)   

    list_src_dst()              #Print statements
    list_routers()
    print("")
    list_protos()
    print("")
    list_frags()
    calc_rtt()
    if TYPE == TYPE_WINDOW:             #GET RTT for source destination
        window_calc_src_dst_rtt()
    return 0

trace = Trace()
main()