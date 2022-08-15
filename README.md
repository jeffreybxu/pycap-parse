# pycap-parse
A multi-featured pcap parser written in Python

This is a work in progress and will be updated as I learn more about .pcap parsing using Scapy. 

As of right now, you can perform the following:
- count the packets in a .pcap file and count packets with http connections
- list the most frequently seen source or destination IP addresses
- list DNS queries and responses
- convert a number of packets into JSON format with IPs and DNS queries listed

pycap parse currently outputs most data in the form of pickled files so that further analysis tools in the script can be written to use those pickled files instead of having to spend time parsing the .pcap again.