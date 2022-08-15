from scapy.all import *
import sys
from argparse import *
import pickle
import json

pcapparse = ArgumentParser()
subparsers = pcapparse.add_subparsers(dest="subcommand")

def subcommand(args=[], parent=subparsers):
    def decorator(func):
        parser = parent.add_parser(func.__name__, description=func.__doc__)
        for arg in args:
            parser.add_argument(*arg[0], **arg[1])
        parser.set_defaults(func=func)
    return decorator

def argument(*name_or_flags, **kwargs):
    return ([*name_or_flags], kwargs)

# Take the first X packets in a pcap file and put them into a JSON format with source IP, destination IP, and DNS (if applicable)

@subcommand([argument("-i", "--input", help="An input pcap file"),argument("-o", "--output", help="An output JSON file"),argument("-c", "--count", help="how many packets to convert")])
def jsonconvert(args):
    print("Opening {} and creating a JSON file with the first {} packets.".format(args.input, args.count))
    packetdict = {}
    pcap_object = rdpcap(args.input)
    count = 1
    for pkt in pcap_object:
        if count <= int(args.count):
            packetdict[count] = {}
            if pkt.haslayer("IP"):
                packetdict[count]["IP"] = {}
                packetdict[count]["IP"]["ipsrc"] = pkt.getlayer("IP").src
                packetdict[count]["IP"]["ipdst"] = pkt.getlayer("IP").dst
            if pkt.haslayer("DNS"):
                packetdict[count]["DNS"] = {}
                packetdict[count]["DNS"]["dnsquery"] = str(pkt.getlayer("DNS").qd.qname)
            count +=1 
    with open(args.output, "w") as outfile:
        json.dump(packetdict, outfile)

# Put a list of all source IPs into a pickled file

@subcommand([argument("-i", "--input", help="An input pcap file"),argument("-o", "--output", help="An output pickle file")])
def getsourceips(args):
    print("Extracting source IPs from {}".format(args.input))
    count = 0
    for (pkt_data,pkt_metadata) in RawPcapReader(args.input):
        count += 1
    print("{} contains {} packets".format(args.input, count))
    pcap_object = rdpcap(args.input)
    ip_src_list = []
    for pkt in pcap_object:
        if pkt.haslayer("IP"):
            ip_src = pkt.getlayer("IP").src
            if ip_src not in ip_src_list:
                ip_src_list.append(ip_src)
    print("Writing to {}".format(args.output))
    with open(args.output, "wb") as pickled:
        pickle.dump(ip_src_list, pickled)

# Put a list of all destination IPs into a pickled file

@subcommand([argument("-i", "--input", help="An input pcap file"),argument("-o", "--output", help="An output pickle file")])
def getdstips(args):
    print("Extracting destination IPs from {}".format(args.input))
    count = 0
    for (pkt_data,pkt_metadata) in RawPcapReader(args.input):
        count += 1
    print("{} contains {} packets".format(args.input, count))
    pcap_object = rdpcap(args.input)
    ip_dst_list = []
    for pkt in pcap_object:
        if pkt.haslayer("IP"):
            ip_dst = pkt.getlayer("IP").dst
            if ip_dst not in ip_dst_list:
                ip_dst_list.append(ip_dst)
    print("Writing to {}".format(args.output))
    with open(args.output, "wb") as pickled:
        pickle.dump(ip_dst_list, pickled)

# Create a list of the top X source IPs and output into a pickled file

@subcommand([argument("-i", "--input", help="An input pcap file"),argument("-o", "--output", help="An output pickle file"),argument("-c", "--count", help="How many IPs to list")])
def topsrcips(args):
    print("Extracting source IPs from {} and listing the top {} most frequently used.".format(args.input, args.count))
    pcap_object = rdpcap(args.input)
    ip_src_list_full = []
    ip_src_list_uniq = []
    for pkt in pcap_object:
        if pkt.haslayer("IP"):
            ip_src = pkt.getlayer("IP").src
            ip_src_list_full.append(ip_src)
            if ip_src not in ip_src_list_uniq:
                ip_src_list_uniq.append(ip_src)
    for i in range(len(ip_src_list_uniq)):
        ip_src_list_uniq[i] = [ip_src_list_uniq[i], ip_src_list_full.count(ip_src_list_uniq[i])]
    ip_src_list_uniq.sort(key=lambda x:x[1], reverse=True)
    del ip_src_list_uniq[int(args.count):]
    print("Writing to {}".format(args.output))
    with open(args.output, "wb") as pickled:
        pickle.dump(ip_src_list_uniq, pickled)

# Create a list of the top X destination IPs and output into a pickled file

@subcommand([argument("-i", "--input", help="An input pcap file"),argument("-o", "--output", help="An output pickle file"),argument("-c", "--count", help="How many IPs to list")])
def topdstips(args):
    print("Extracting destination IPs from {} and listing the top {} most frequently used.".format(args.input, args.count))
    pcap_object = rdpcap(args.input)
    ip_dst_list_full = []
    ip_dst_list_uniq = []
    for pkt in pcap_object:
        if pkt.haslayer("IP"):
            ip_dst = pkt.getlayer("IP").dst
            ip_dst_list_full.append(ip_dst)
            if ip_dst not in ip_dst_list_uniq:
                ip_dst_list_uniq.append(ip_dst)
    for i in range(len(ip_dst_list_uniq)):
        ip_dst_list_uniq[i] = [ip_dst_list_uniq[i], ip_dst_list_full.count(ip_dst_list_uniq[i])]
    ip_dst_list_uniq.sort(key=lambda x:x[1], reverse=True)
    del ip_dst_list_uniq[int(args.count):]
    print("Writing to {}".format(args.output))
    with open(args.output, "wb") as pickled:
        pickle.dump(ip_dst_list_uniq, pickled)

# Make a list of all DNS queries and output into a pickled file

@subcommand([argument("-i", "--input", help="An input pcap file"),argument("-o", "--output", help="An output pickle file")])
def getdns(args):
    print("Extracting DNS queries from {}".format(args.input))
    dns_list=[]
    pcap_object = rdpcap(args.input)
    for pkt in pcap_object:
        if pkt.haslayer("DNS"):
            dns_query = pkt.getlayer("DNS").qd.qname
            if dns_query not in dns_list:
                dns_list.append(dns_query)
    print("Writing to {}".format(args.output))
    with open(args.output, "wb") as pickled:
        pickle.dump(dns_list, pickled)

# Make a list of all DNS responses and output into a pickled file

@subcommand([argument("-i", "--input", help="An input pcap file"),argument("-o", "--output", help="An output pickle file")])
def getdnsans(args):
    print("Extracting DNS queries from {}".format(args.input))
    dns_ans_list=[]
    pcap_object = rdpcap(args.input)
    for pkt in pcap_object:
        if pkt.haslayer("DNSRR"):
            dns_ans = pkt.an.rrname
            if dns_ans not in dns_ans_list:
                dns_ans_list.append(dns_ans)
    print("Writing to {}".format(args.output))
    with open(args.output, "wb") as pickled:
        pickle.dump(dns_ans_list, pickled)

# Count the number of packets with http connections

@subcommand([argument("-i", "--input", help="An input pcap file")])
def gethttp(args):
    print("Finding HTTP connections in {} ...".format(args.input))
    pcap_object = rdpcap(args.input)
    count = 0
    for pkt in pcap_object:
        if pkt.haslayer("TCP") and pkt.getlayer("TCP").dport == 80 and pkt.haslayer("Raw"):
            count += 1
    print(count)

# Print the contents of a pickled file

@subcommand([argument("-p", "--pickle", help="A pickled file")])
def printpickle(args):
    infile = open(args.pickle, "rb")
    unpickle = pickle.load(infile)
    infile.close()
    print(unpickle)

# Count the number of packets in the .pcap file

@subcommand([argument("-f", "--filename", help="A pcap file")])
def countpackets(args):
    count = 0
    for (pkt_data,pkt_metadata) in RawPcapReader(args.filename):
        count += 1
    print("{} contains {} packets".format(args.filename, count))

if __name__ == "__main__":
    args = pcapparse.parse_args()
    if args.subcommand is None:
        pcapparse.print_help()
    else:
        args.func(args)

