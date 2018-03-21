### Author - Gunj Manseta/Shalin Shah University of Colorado Boulder ###
###References: Example codes from the dpkt doc website mentioned in the question
import dpkt
import socket
import sys
import os
#if windows OS, inet_ntop function needs the below package to run properly
if os.name == 'nt':
    import win_inet_pton

#this function definition is taken from the dpkt package source code
def inet_to_str(inet):
    """Convert inet object to a string

        Args:
            inet (inet struct): inet network address
        Returns:
            str: Printable/readable IP address
    """
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

#self written
def displayCountProgress(count):
    print '\r# of packets processed [%s]' % (count),
    sys.stdout.flush()

#Code for extracting the pcap and reading it - inspired from the example code from the dpkt documentation
def parse_pcap(filepath):
    S_SRC_DICT = {}
    SA_DST_DICT = {}
    with open(filepath, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        for num,(ts, buff) in enumerate(pcap):
            displayCountProgress(num)
            try:
                eth = dpkt.ethernet.Ethernet(buff)
            #to solve the problem of the prog throwing needdata exception, we just move on and dead ignore it.
            except dpkt.NeedData:
                continue
            if not isinstance(eth.data, dpkt.ip.IP):
                # Filter out non IP packets
                continue
            ip = eth.data
            if not isinstance(ip.data, dpkt.tcp.TCP):
                # Filter out non TCP
                continue
            tcp = ip.data
            if ((tcp.flags & dpkt.tcp.TH_SYN) and not(tcp.flags & dpkt.tcp.TH_ACK)):
                # TCP SYN and no ACK        
                if inet_to_str(ip.src) in S_SRC_DICT:
                    S_SRC_DICT[inet_to_str(ip.src)] += 1
                else:
                    S_SRC_DICT[inet_to_str(ip.src)] = 1
            elif ((tcp.flags & dpkt.tcp.TH_SYN) and (tcp.flags & dpkt.tcp.TH_ACK)):
                # TCP SYN and ACK
                if inet_to_str(ip.dst) in SA_DST_DICT:
                    SA_DST_DICT[inet_to_str(ip.dst)] += 1
                else:
                    SA_DST_DICT[inet_to_str(ip.dst)] = 1
                    
        #We have got the list of respective src and dst ipaddrs. Now we compare the counts
        print "\n"
        #for all IP in the src dict - all ip which sends a SYN
        for ip in S_SRC_DICT:
            #if the ip in the dst dict - the ip who sent a syn signal, recving a SYN+ACK 
            if ip in SA_DST_DICT:
                #if the sending of SYN is 3 times greater that recving back SYN+ACK
                if S_SRC_DICT[ip] > 3*SA_DST_DICT[ip]:
                    print (ip)
            #a tricky condition which I did not get the first time, if the IP list wouldnt have been given, I would not have figured it out
            #the ip who sent a SYN but did not recv any SYN+ACK back should also be considered as a port scanner
            else:
                print (ip)

def  portScan_detect(filepath):
    parse_pcap(filepath)
    #parse_pcap("lbl-internal.20041004-1305.port002.dump.anon")

if __name__ == "__main__":
        if len(sys.argv) > 1:
            filepath = sys.argv[1]
        else:
            print "ERROR. Filename not given"
            sys.exit();
        #we got the filename as parameter    
        portScan_detect(filepath)
