## Author - Gunj Manseta University of Colorado Boulder  
### This python scripts takes a pcap file and detects the suspicious IP involved in port scanning  

The script uses dpkt package to parse the packets.   
The IP which sends SYN packets but does not receive comparable response i.e. SYN+ACK from the destination IP is suspected to be involved in port scanning.  
So the threshold taken here is 3 times - The number of SYN packets sent if greater than 3 times the number of SYN+ACK packets received.   
Only the ETHR, IP and TCP packets for all ports are taken into consideration here.   

Pre req: 
"pip install dpkt"   
If on windows: "pip install win_inet_pton"    

Want to know what is a Port scan?   
[Palo Alto Networks](https://www.paloaltonetworks.com/cyberpedia/what-is-a-port-scan)  
[searchmidmarketsecurity](http://searchmidmarketsecurity.techtarget.com/definition/port-scan)  
[Wiki page](https://en.wikipedia.org/wiki/Port_scanner)  
