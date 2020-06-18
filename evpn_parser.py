import socket
import struct
import sys
import json
import requests


class MessageBuilder:

    def __init__(self):
        self.message = {}

    def set_bmp_common(self, version, message_length, message_type):
        self.message.update({"BMP Header": {}})
        self.message["BMP Header"].update({
            "BMP Version": version,
            "Message Length": message_length,
            "Message Type": message_type
        })

    def set_bmp_per_peer(self, peer_type, flags, peer_distinguisher, address, asn, bgp_id, timestamp_sec, timestamp_msec):
        self.message["BMP Header"].update({
            "Peer Type": peer_type,
            "Flags": flags,
            "Peer Distinguisher": peer_distinguisher,
            "Address": address,
            "AS Number": asn,
            "BGP ID": bgp_id,
            "Timestamp (s)": timestamp_sec,
            "Timestamp (ms)": timestamp_msec
        })

    def set_bgp_basics(self, length, message_type):
        self.message.update({"BGP Message": {}})
        self.message["BGP Message"].update({
            "Message Type": message_type,
            "Length": length
        })

    def set_bgp_notification(self, error_code, error_subcode):
        self.message["BGP Message"].update({"Notification": {}})
        self.message["BGP Message"]["Notification"].update({
            "Error Code": error_code,
            "Error Subcode": error_subcode
        })

    def set_bgp_open(self, bgp_version, my_as, hold_time, bgp_identifier):
        peer = None
        if not "Open" in self.message["BGP Message"]:
            peer = "Peer One"
            self.message["BGP Message"].update({"Open": {"Peer One": {}}})
        else:
            peer = "Peer Two"
            self.message["BGP Message"]["Open"].update({"Peer Two": {}})
        self.message["BGP Message"]["Open"][peer].update({
            "BGP Version": bgp_version,
            "AS Number": my_as,
            "BGP Identifier": bgp_identifier,
        })

    def set_bgp_update(self):
        self.message["BGP Message"].update({"Update": {}})

    def set_bgp_nlri_mac(self, route_distinguisher, esi, ethernet_tag_id, mac_address, ip_address, mpls_label, nlri):
        self.message["BGP Message"]["Update"].update({
            "EVPN Route Type": "MAC Advertisement",
            "Type": "New Route" if nlri else "Withdrawn",
            "Route Distinguisher": route_distinguisher,
            "ESI": esi,
            "Ethernet Tag ID": ethernet_tag_id,
            "MAC Address": mac_address,
            "IP Address": ip_address,
            "MPLS Label": mpls_label
        })

    def set_bgp_nlri_ip(self, route_distinguisher, esi, ethernet_tag_id, ip_address, ip_gateway, mpls_label, nlri):
        self.message["BGP Message"]["Update"].update({
            "EVPN Route Type": "IP Prefix Route",
            "Type": "New Route" if nlri else "Withdrawn",
            "Route Distinguisher": route_distinguisher,
            "ESI": esi,
            "Ethernet Tag ID": ethernet_tag_id,
            "IP Address": ip_address,
            "IP gateway": ip_gateway,
            "MPLS Label": mpls_label
        })

    def set_bgp_extended_community(self):
        self.message["BGP Message"]["Update"].update(
            {"Extended Communities": []})

    def set_bgp_extended_community_entry(self, ec_type, ec_subtype, global_adm, local_adm):
        self.message["BGP Message"]["Update"]["Extended Communities"].append({
            "Type": ec_type,
            "Subtype": ec_subtype,
            "Global Administration": global_adm,
            "Local Administration": local_adm
        })

    def get_json(self):
        return json.dumps(self.message, indent=2)


marker = b'\xff' * 16

bgp_message_type = {
    1:  "OPEN",
    2:  "UPDATE",
    3:  "NOTIFICATION",
    4:  "KEEPALIVE",
    5:  "ROUTE-REFRESH"
}

bgp_path_attributes = {
    1: 	    "ORIGIN",
    2: 	    "AS_PATH",
    3: 	    "NEXT_HOP",
    4: 	    "MULTI_EXIT_DISC",
    5: 	    "LOCAL_PREF",
    6: 	    "ATOMIC_AGGREGATE",
    7: 	    "AGGREGATOR",
    8: 	    "COMMUNITY",
    9: 	    "ORIGINATOR_ID",
    10: 	"CLUSTER_LIST",
    14: 	"MP_REACH_NLRI",    # only care about...
    15: 	"MP_UNREACH_NLRI",  # ... these two
    16: 	"EXTENDED COMMUNITIES",
    17: 	"AS4_PATH",
    18: 	"AS4_AGGREGATOR",
    22: 	"PMSI_TUNNEL",
    23: 	"Tunnel Encapsulation Attribute",
    24: 	"Traffic Engineering",
    25: 	"IPv6 Address Specific Extended Community",
    26: 	"AIGP",
    27: 	"PE Distinguisher Labels",
    29: 	"BGP-LS Attribute",
    32: 	"LARGE_COMMUNITY",
    33: 	"BGPsec_Path",
    36: 	"BGP Domain Pat",
}

bmp_message_types = {
    0: "Route Monitoring",
    1: "Statistics Report",
    2: "Peer Down Notification",
    3: "Peer Up Notification",
    4: "Initiation Message",
    5: "Termination Message",
    6: "Route Mirroring Message",
}

single_length_path_attributes = {
    "ORIGIN", "EXTENDED COMMUNITIES", "MULTI_EXIT_DISC", "COMMUNITY"}
double_length_path_attributes = {
    "MP_REACH_NLRI", "AS_PATH", "MP_UNREACH_NLRI"}

evpn_route_types = {
    1: "Ethernet Autodiscovery",
    2: "MAC Advertisement Route",
    3: "Inclusive Multicast Ethernet tag route",
    4: "Ethernet segment Route",
    5: "IP prefix Route",
    6: "Selective Multicast Ethernet tag routes",
    7: "NLRI to sync IGMP joins",
    8: "NLRI to sync IGMP leaves"
}

bgp_notification_types = {
    6: "Cease"
}

bgp_extended_communities_evpn_subtypes = {
    0: "MAC Mobility",
    1: "ESI Label",
    2: "ES-Import Route Target",
    3: "EVPN Router’s MAC Extended Community",
    4: "EVPN Layer 2 Attributes",
    5: "E-Tree Extended Community",
    6: "DF Election Extended Community",
    7: "I-SID Extended Community",
    8: "ND Extended Community",
    9: "Multicast Flags Extended Community",
    10: "EVI-RT Type 0 Extended Community",
    11: "EVI-RT Type 1 Extended Community",
    12: "EVI-RT Type 2 Extended Community",
    13: "EVI-RT Type 3 Extended Community",
    14: "EVPN Attachment Circuit Extended Community",
    15: "Service Carving Timestamp"
}

bgp_extended_communities_two_octect_subtypes = {
    2: "Route Target",
    3: "Route Origin",
    5: "OSPF Domain Identifier",
    8: "BGP Data Collection",
    9: "Source AS",
    10: "L2VPN Identifier",
    16: "Cisco VPN-Distinguisher",
    19: "Route-Target Record"
}

bgp_extended_communities_four_octect_subtypes = {
    2: "Route Target",
    3: "Route Origin",
    5: "OSPF Domain Identifier",
    8: "BGP Data Collection",
    9: "Source AS",
    16: "Cisco VPN Identifier",
    19: "Route-Target Record"
}

bgp_extended_communities_opaque = {
    1: "Cost Community",
    3: "CP-ORF",
    4: "Extranet Source Extended Community",
    5: "Extranet Separation Extended Community",
    6: "OSPF Route Type",
    7: "Additional PMSI Tunnel Attribute Flags",
    8: "Context Label Space ID Extended Community",
    11: "Color Extended Community",
    12: "Encapsulation Extended Community",
    13: "Default Gateway",
    14: "Point-to-Point-to-Multipoint (PPMP) Label"
}

bpd_extended_communities_types = {
    0: ("Transitive Two-Octet AS-Specific Extended Community", bgp_extended_communities_two_octect_subtypes),
    1: ("Transitive IPv4-Address-Specific Extended Community", None),
    2: ("Transitive Four-Octet AS-Specific Extended Community", bgp_extended_communities_four_octect_subtypes),
    3: ("Transitive Opaque Extended Community", bgp_extended_communities_opaque),
    4: ("QoS Marking", None),
    5: ("CoS Capability", None),
    6: ("EVPN", bgp_extended_communities_evpn_subtypes),
    7: ("FlowSpec Transitive Extended Communities", None),
    8: ("Flow spec redirect/mirror to IP next-hop", None),
    9: ("FlowSpec Redirect to indirection-id Extended Community", None)
}


def bytes_to_IP(num):
    num = num.split(" ")
    if len(num) == 4:
        tmp = [str(int(x.replace("0x", ""), 16)) for x in num]
        return ".".join(tmp)
    if len(num) == 6:
        tmp = [x.replace("0x", "") if len(x.replace("0x", ""))
               == 2 else "0" + x.replace("0x", "") for x in num]
        return ":".join(tmp)
    if len(num) == 8:
        tmp = [str(int(x.replace("0x", ""), 16)) for x in num]
        return ".".join(tmp[2:-2]) + ":{}".format(str(tmp[-2]) + " " + str(tmp[-1]))
    elif len(num) == 16:
        tmp = []
        for x in range(0, len(num), 2):
            f = "0" + num[x].replace("0x", "") if len(num[x].replace("0x", "")
                                                      ) == 1 else num[x].replace("0x", "")
            s = "0" + num[x+1].replace("0x", "") if len(
                num[x+1].replace("0x", "")) == 1 else num[x+1].replace("0x", "")
            tmp.append("{}{}".format(f, s))
        return ":".join(tmp)
    else:
        print("Unknown IP length")


def route_byte_repr(num):
    ret = []
    for x in num:
        ret.append(hex(x))
    return " ".join(ret)


def pull_bytes(blob, pos, amount):
    if amount > 0:
        ret = route_byte_repr(blob[pos:pos+amount])
        pos += amount
        return ret, pos
    else:
        return None, pos


def pull_int(blob, pos, amount):
    if amount > 0:
        if amount == 1:
            ret = int(blob[pos])
            pos += 1
        else:
            ret = int.from_bytes(blob[pos:pos+amount], byteorder='big')
            pos += amount
        return ret, pos
    else:
        return 0, pos


def parse_bmp_common_header(blob, pos, message):
    version, pos = pull_int(blob, pos, 1)
    message_length, pos = pull_int(blob, pos, 4)
    message_type, pos = pull_int(blob, pos, 1)
    if bmp_message_types[message_type] == "Initiation Message":
        _, pos = pull_bytes(blob, pos, message_length - 6)
        parse_bmp_header(blob[pos:], message)
    else:
        message.set_bmp_common(version, message_length, message_type)
        return pos


def parse_bmp_per_peer_header(blob, pos, message):
    peer_type, pos = pull_int(blob, pos, 1)
    flags, pos = pull_int(blob, pos, 1)
    peer_distinguisher, pos = pull_bytes(blob, pos, 8)
    if flags >= 128:  # First bit set means IPv6
        address, pos = pull_bytes(blob, pos, 16)
    else:
        address, pos = pull_bytes(blob, pos, 4)
    if address:
        address = bytes_to_IP(address)
    asn, pos = pull_int(blob, pos, 4)
    bgp_id, pos = pull_bytes(blob, pos, 4)
    if bgp_id:
        bgp_id = bytes_to_IP(bgp_id)
    timestamp_sec, pos = pull_int(blob, pos, 4)
    timestamp_msec, pos = pull_int(blob, pos, 4)
    message.set_bmp_per_peer(peer_type, flags, peer_distinguisher,
                             address, asn, bgp_id, timestamp_sec, timestamp_msec)


def parse_bmp_header(blob, message):
    pos = 0
    pos = parse_bmp_common_header(blob[:6], pos, message)
    if len(blob) > 6:  # Meaning there is a per-peer-header too
        parse_bmp_per_peer_header(blob, pos, message)


def extended_communities(blob, pos, length, message):
    print("Received Extended Community")
    number_of_communities = int(length / 8)
    message.set_bgp_extended_community()
    for community in range(number_of_communities):
        ec_type, pos = pull_int(blob, pos, 1)
        ec_subtype, pos = pull_int(blob, pos, 1)
        ec_type, subtype_class = bpd_extended_communities_types[ec_type]
        if subtype_class:
            ec_subtype = subtype_class[ec_subtype]
        else:
            print("Subtype not recognized for EC type {}".format(ec_type))
        global_adm, pos = pull_int(blob, pos, 2)
        local_adm, pos = pull_int(blob, pos, 4)
        message.set_bgp_extended_community_entry(
            ec_type, ec_subtype, global_adm, local_adm)
    return pos


def mp_nlri(blob, pos, length, nlri, message):
    print("Received NLRI, {}".format("New" if nlri else "Withdrawn"))
    afi, pos = pull_int(blob, pos, 2)
    safi, pos = pull_int(blob, pos, 1)
    if afi != 25 or safi != 70:
        # Return pointer to next path attribute (minus bytes we already consumed)
        return pos + length - 3
    else:
        if nlri:
            # Network Address of Next Hop, is it really always 5-bytes in our case?
            _, pos = pull_int(blob, pos, 5)
            # SNPA, is it really always 1-bytes in our case?
            _, pos = pull_int(blob, pos, 1)
        evpn_type, pos = pull_int(blob, pos, 1)
        evpn_length, pos = pull_int(blob, pos, 1)
        route_distinguisher, pos = pull_bytes(blob, pos, 8)
        route_distinguisher = bytes_to_IP(route_distinguisher)
        esi, pos = pull_int(blob, pos, 10)
        ethernet_tag_id, pos = pull_int(blob, pos, 4)
        if evpn_route_types[evpn_type] == "MAC Advertisement Route":
            # MAC length, assuming it is always 48-bits
            _, pos = pull_int(blob, pos, 1)
            mac_address, pos = pull_bytes(blob, pos, 6)
            if mac_address:
                mac_address = bytes_to_IP(mac_address)
            # IP length, and MPLS label
            ip_length, pos = pull_int(blob, pos, 1)
            ip_address, pos = pull_bytes(blob, pos, int(ip_length / 8))
            if ip_address:
                ip_address = bytes_to_IP(ip_address)
            mpls_label, pos = pull_bytes(blob, pos, 3)
            message.set_bgp_nlri_mac(
                route_distinguisher, esi, ethernet_tag_id, mac_address, ip_address, mpls_label, nlri)
        elif evpn_route_types[evpn_type] == "IP prefix Route":
            # print("We have prefix route, left ",  evpn_length - 24)
            if evpn_length - 22 < 12:
                ip_prefix_length, pos = pull_int(blob, pos, 1)
                ip_address, pos = pull_bytes(blob, pos, 4)
                ip_address = bytes_to_IP(ip_address)
                ip_gateway, pos = pull_bytes(blob, pos, 4)
                ip_gateway = bytes_to_IP(ip_gateway)
                print(ip_address)
                print(ip_gateway)
            else:
                ip_prefix_length, pos = pull_int(blob, pos, 1)
                ip_address, pos = pull_bytes(blob, pos, 16)
                ip_address = bytes_to_IP(ip_address)
                ip_gateway, pos = pull_bytes(blob, pos, 16)
                ip_gateway = bytes_to_IP(ip_gateway)
            mpls_label, pos = pull_bytes(blob, pos, 3)
            message.set_bgp_nlri_ip(
                route_distinguisher, esi, ethernet_tag_id, ip_address, ip_gateway, mpls_label, nlri)
        else:
            print("Unsupported advertisement type: {}".format(
                evpn_route_types[evpn_type]))
            # Return pointer to next path attribute (minus bytes we already consumed)
            return pos + length - 4
        return pos


def parse_path_attribute(blob, pos, message):
    _, pos = pull_int(blob, pos, 1)
    path_attribute_type, pos = pull_int(blob, pos, 1)
    if bgp_path_attributes[path_attribute_type] in single_length_path_attributes:
        length, pos = pull_int(blob, pos, 1)
    elif bgp_path_attributes[path_attribute_type] in double_length_path_attributes:
        length, pos = pull_int(blob, pos, 2)
    else:
        print("Unkown length attribute",
              bgp_path_attributes[path_attribute_type])
        exit()
    if bgp_path_attributes[path_attribute_type] == "MP_REACH_NLRI":
        pos = mp_nlri(blob, pos, length, True, message)
    elif bgp_path_attributes[path_attribute_type] == "MP_UNREACH_NLRI":
        pos = mp_nlri(blob, pos, length, False, message)
    elif bgp_path_attributes[path_attribute_type] == "EXTENDED COMMUNITIES":
        pos = extended_communities(blob, pos, length, message)
    else:
        pos += length  # Return pointer to next path attribute
    return pos


def update(blob, pos, message):
    print("Received Update")
    message.set_bgp_update()
    _, pos = pull_int(blob, pos, 2)
    path_attributes_length, pos = pull_int(blob, pos, 2)
    drawn = 0
    while(drawn < path_attributes_length):
        new_pos = parse_path_attribute(blob, pos, message)
        drawn += new_pos - pos
        pos = new_pos
    return pos


def notification(blob, pos, message):
    print("Received Notification")
    error_code, pos = pull_int(blob, pos, 1)
    error_subcode, pos = pull_int(blob, pos, 1)
    if bgp_notification_types[error_code] == "Cease":
        message.set_bgp_notification(error_code, error_subcode)
    else:
        print("NOTIFICATION RECEIVED, unsupported type {}".format(error_code))
    return pos


def open_m(blob, pos, message):
    print("Received Open")
    bgp_version, pos = pull_int(blob, pos, 1)
    my_as, pos = pull_int(blob, pos, 2)
    hold_time, pos = pull_int(blob, pos, 2)
    bgp_identifier, pos = pull_bytes(blob, pos, 4)
    bgp_identifier = bytes_to_IP(bgp_identifier)
    optional_parameters_length, pos = pull_int(blob, pos, 1)
    pos += optional_parameters_length  # Skipping parameters for now
    message.set_bgp_open(bgp_version, my_as, hold_time, bgp_identifier)
    return pos


def run(blob, index):
    pos = 0
    new_start = 0
    while(blob.find(marker, 0) != -1):
        roll_back = pos
        pos = blob.find(marker, 0)
        tmp = pos
        _, pos = pull_int(blob, pos, 16)
        try:
            message_length, pos = pull_int(blob, pos, 2)
            if len(blob) < roll_back + message_length:
                raise Exception()
        except:
            return new_start
        message = MessageBuilder()
        message_type, pos = pull_int(blob, pos, 1)
        message.set_bgp_basics(message_length, bgp_message_type[message_type])
        parse_bmp_header(blob[:tmp], message)
        if bgp_message_type[message_type] == "UPDATE":
            pos = update(blob, pos, message)
        elif bgp_message_type[message_type] == "NOTIFICATION":
            pos = notification(blob, pos, message)
        elif bgp_message_type[message_type] == "OPEN":
            try:
                if len(blob) < roll_back + (2 * message_length + 10):
                    raise Exception()
            except:
                return new_start
            pos = open_m(blob, pos, message)
            _, pos = pull_int(blob, pos, 19)
            pos = open_m(blob, pos, message)
        else:
            print("Unsupported message, ", bgp_message_type[message_type])
        new_start += pos
        blob = blob[pos:]
        if __name__ == "__main__":
            print(message.get_json())
        else:
            print("Pushing JSON")
            requests.post("http://localhost:9200/{}/_doc".format(index),
                          json=message.message)
    return new_start


if __name__ == "__main__":
    f = open(sys.argv[1], "rb")
    blob = f.read()
    f.close()
    # index = sys.argv[2]
    # requests.put("http://localhost:9200/{}?pretty".format(index))
    run(blob, "")
