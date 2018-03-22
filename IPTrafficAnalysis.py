def main():
    traceFileName = sys.argv[1]                         #name of file to read from

    traceFile = open(traceFileName, "rb")               #open the file to read in binary
    tracePcap = dpkt.pcap.Reader(traceFile)             #use a reader to parse

    stats = Statistics()                                
    connections = Connections()
    count = 0

    for timeStamp, buf in tracePcap:                    #Refer to reference. Parts of the referenced code has been deleted or modified.
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data                                   #IP Header
        tcp = ip.data                                   #TCP Header

        packet = Packet()                               #Storing various values into a packet class
        packet.srcMac = mac_addr(eth.src)
        packet.dstMac = mac_addr(eth.dst)
        
        packet.srcIP = inet_to_str(ip.src)
        packet.dstIP = inet_to_str(ip.dst)
        packet.IPLen = ip.len
        packet.id = ip.id
        
        packet.seq = tcp.seq
        packet.ack = tcp.ack
        packet.windowSize = tcp.win
        packet.flagsBin = tcp.flags
        packet.srcPort = tcp.sport
        packet.dstPort = tcp.dport
        packet.time = timeStamp
        packet = binToFlags(packet)

        analyzePacket(stats, connections, packet)       #For each packet, analyze
        del packet
    
    finalStatCheck(stats, connections)
    printFinal(stats, connections)

main()