#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING

# TODO: Feel free to import any Python standard moduless as necessary.
from string import ascii_lowercase
import struct, socket
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries, though.

class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext
        self.TCP = 6
        self.UDP = 17
        self.ICMP = 1

        # TODO: Load the firewall rules (from rule_filename) here.
        # print 'I am supposed to load rules from %s, but I am feeling lazy.' % \
        #         config['rule']
        self.all_rules = load_rules(config['rule'])

        # TODO: Load the GeoIP DB ('geoipdb.txt') as well.
        self.geoipdb = load_geoipdb("geoipdb.txt")

        # TODO: Also do some initialization if needed.
        self.parse_rules()

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        # TODO: Your main firewall code will be here.
        src_ip = pkt[12:16]	# hex string array, size 4
        dst_ip = pkt[16:20]	# hex string array, size 4
        header_len = 0b00001111 & struct.unpack('!B',pkt[0])[0]	#before mutliplied by 4
        ip_header_length = 4 * header_len
        no_header_pkt = pkt[ip_header_length:]



        protocol = struct.unpack('!B', pkt[9])[0]
        ext_ip = self.get_ext_ip(dst_ip, pkt_dir, src_ip)
        sorted_pkt = self.sort_packet(pkt, pkt_dir, protocol, ip_header_length, no_header_pkt)

        self.verify_packet(pkt, pkt_dir, protocol, sorted_pkt)

        pass

    # TODO: You can add more methods as you want.
    def parse_rules(self):
        all_letters = list(ascii_lowercase)
        for r in self.all_rules:
            if r[1] not in ['tcp', 'udp', 'icmp']:
                ip = r[2]
                port = r[3]

                #handle 'any'
                if ip == 'any':
                    r[2] = {'any': ip}

                #handle county code
                elif len(ip) == 2 and ip[0] in all_letters and ip[1] in all_letters:
                    r[2] = {'county': ip}

                #handle single ip address
                elif ip.count('.') == 3 and not '/' in ip:
                    r[2] = {'s_addr': intify_ip(ip.split('.'))}

                #handle prefix
                else:
                    prefix_addr = ip.split('/')[1]
                    prefix_number = int(ip.split('/')[1])
                    available = 32 - prefix_number

                    mask = 2**(available)-1
                    range_end = prefix_addr | mask

                    r[2] = {'ip_range': [prefix_addr, range_end]}

                #handle 'any' port
                if port == 'any':
                    r[3] = {'any': port}
                #handle single port
                elif not '-' in port:
                    r[3] = {'s_port': int(port)}
                #handle range of ports
                else:
                    split_p = port.split('-')
                    r[3] = {'range': [int(split_p[0]), int(split_p[1])]}

            elif r[1] == 'dns': #handle dns rules
                r[2] = r[2].split('.')

    def verify_packet(self, pkt, pkt_dir, protocol, ext_ip, sorted_pkt):
        if not sorted_pkt: return False
        for rule in self.all_rules:
            result = self.verify_packet_by_rule(sorted_pkt, protocol, ext_ip, rule)
            if result != 0:
                passing = result
        return passing >= 0

    def verify_packet_by_rule(self, sorted_pkt, protocol, ext_ip, rule):

        return



    def sort_packet(self, pkt, pkt_dir, protocol, ip_header_length, no_header_pkt):
        if protocol == self.ICMP:
            return int(struct.unpack('!B', pkt[ip_header_length])[0])  #packet type
        elif protocol == self.TCP:
            return self.get_ext_port(no_header_pkt, pkt_dir)  # returns ext port
        elif protocol == self.UDP:
            ext_port = self.get_ext_port(no_header_pkt, pkt_dir)

            if pkt_dir == PKT_DIR_OUTGOING and ext_port == 53:
                # decode dns info, get a domain string
                domain = self.get_domain_from_dns(no_header_pkt)
                if domain:
                    # a DNS packet
                    return ['dns', ext_port, domain]  # returns port, domain
                else:
                    return False # corrupted
            return ext_port # returns ext port

    def get_domain_from_dns(self, pkt_no_header):  # return ['www', 'google', 'com']
        dns_pkt = pkt_no_header[8:]
        qdcount = struct.unpack('!H', dns_pkt[4:6])[0]
        dns_no_header = dns_pkt[12:]

        qname = []
        if qdcount == 0x1:
            for i in range(len(dns_no_header)):
                temp = struct.unpack('!B',dns_no_header[i])[0]
                qname.append(chr(temp))
                end_index = i+1
                if temp == 0x0:
                    break
        else:
            return False

        if qname[len(qname)-1] != chr(0x0):
            return False

        #need to refactor!
        section_len = ord(qname[0])
        qname = qname[1:]
        webaddr = []
        out_addr = []
        while section_len is not 0x0:
            for i in range(section_len):
                webaddr.append(qname[i])
            out_addr.append("".join(webaddr))
            webaddr = []
            temp = ord(qname[section_len])
            if temp > 0:
                qname=qname[section_len+1:]
            section_len = temp
        return out_addr

    # take in 2 lists of domain
    def match_dns_domain(self, domain_from_rule, domain): #if matched, return True
        if '*' in domain_from_rule:
            need_match = domain_from_rule[1:]
            for i in range(len(need_match)):
                if domain[len(domain)-1-i] != need_match[len(need_match)-1-i]:
                    return False
            return True
        else:
            if len(domain) != len(domain_from_rule):
                return False
            for i in range(len(domain)):
                if domain[i] != domain_from_rule[i]:
                    return False
            return True

    # returns an int of ip
    def get_ext_ip(self, dst_ip, pkt_dir, src_ip):
        return intify_ip(socket.inet_ntoa(src_ip.split('.'))) \
            if pkt_dir == PKT_DIR_INCOMING else intify_ip(socket.inet_ntoa(dst_ip.split('.')))

    # returns the external port
    def get_ext_port(self, no_header_pkt, pkt_dir):
        src_port = no_header_pkt[:2]
        dst_port = no_header_pkt[2:4]
        if pkt_dir == PKT_DIR_INCOMING:
            return struct.unpack('!H', src_port)[0]
        else:
            return struct.unpack('!H', dst_port)[0]

# TODO: You may want to add more classes/functions as well.

def load_rules(path): # a list of rules within a list of ALL rules
    rules = []
    f = open(path, 'r')
    l = f.readline().strip()
    temp = []
    while l != '':
        split_line = l.split()
        if split_line[0] == '%':
            continue
        for i in split_line: # convert to lower case and make a new list
            temp.append(i.lower())
        rules.append(temp) # put into the main rules list
    return rules

def load_geoipdb(path):
    ipdb = []
    f = open(path, 'r')
    l = f.readline().strip()

    while l != '':
        split_line = l.split()
        #store as a list within a list
        ipdb.append([intify_ip(split_line[0].split('.')), intify_ip(split_line[1].split('.')), split_line[2]])
        l = f.readline().strip()
    return ipdb

def intify_ip(ip): #take in a list
    ret = 0
    for i in range(len(ip)):
        ret += int(ip[i])*(256**(3-i))
    return ret
