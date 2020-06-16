import socket
import struct
import sys
import json
import requests


class ELK:
    logstash_host = ""
    logstash_port = ""


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

    def set_bgp_update(self, route_distinguisher, esi, ethernet_tag_id, mac_address, ip_address, mpls_label):
        self.message["BGP Message"].update({"Update": {}})
        self.message["BGP Message"]["Update"].update({
            "Route Distinguisher": route_distinguisher,
            "ESI": esi,
            "Ethernet Tag ID": ethernet_tag_id,
            "MAC Address": mac_address,
            "IP Address": ip_address,
            "MPLS Label": mpls_label
        })
        pass

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

single_length_path_attributes = {"ORIGIN", "EXTENDED COMMUNITIES"}
double_length_path_attributes = {"MP_REACH_NLRI", "AS_PATH", "MP_UNREACH_NLRI"}

evpn_route_types = {
    2: "MAC Advertisement Route"
}

bgp_notification_types = {
    6: "Cease"
}

# def int_to_IP(num):
#     return socket.inet_ntoa(struct.pack("!I", num))


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
    # #print("\n#########################################\n")
    # try:
    #     print("BMP Version: {}\nMessage Type: {}".format(version, bmp_message_types[message_type]))
    # except KeyError: # For some reason the first capture has a malformed BMP header
    #     print("Failed!!!!")
    message.set_bmp_common(version, message_length, message_type)
    return pos, message_type


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
    # if bgp_id:
    #     bgp_id = bytes_to_IP(bgp_id)
    timestamp_sec, pos = pull_int(blob, pos, 4)
    timestamp_msec, pos = pull_int(blob, pos, 4)
    message.set_bmp_per_peer(peer_type, flags, peer_distinguisher,
                             address, asn, bgp_id, timestamp_sec, timestamp_msec)
    # print("Peer ID: {},\nASN: {},\nAddress:{}".format(bgp_id, asn, address))


def parse_bmp_header(blob, message):
    pos = 0
    pos, message_type = parse_bmp_common_header(blob[:6], pos, message)
    if len(blob) > 6:  # Meaning there is a per-peer-header too
        parse_bmp_per_peer_header(blob[6:], pos, message)


def mp_nlri(blob, pos, length, nlri, message):
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
        if evpn_route_types[evpn_type] == "MAC Advertisement Route":
            evpn_length, pos = pull_int(blob, pos, 1)
            route_distinguisher, pos = pull_bytes(blob, pos, 8)
            route_distinguisher = bytes_to_IP(route_distinguisher)
            esi, pos = pull_int(blob, pos, 10)
            ethernet_tag_id, pos = pull_int(blob, pos, 4)
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
            # print("\n#########################################\n")
            # print("New MAC advertisement route ({}).\nRoute distinguisher: {},\nMAC Address: {},\nIP Address: {},\nMPLS Label: {}".format(
            #     "New Route" if nlri else "Withdrawn", route_distinguisher, mac_address, ip_address, mpls_label))
            # print("\n#########################################\n")
            message.set_bgp_update(
                route_distinguisher, esi, ethernet_tag_id, mac_address, ip_address, mpls_label)
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
    else:
        pos += length  # Return pointer to next path attribute
    return pos


def update(blob, pos, message):
    _, pos = pull_int(blob, pos, 2)
    path_attributes_length, pos = pull_int(blob, pos, 2)
    drawn = 0
    while(drawn < path_attributes_length):
        new_pos = parse_path_attribute(blob, pos, message)
        drawn += new_pos - pos
        pos = new_pos
    return pos


def notification(blob, pos, message):
    error_code, pos = pull_int(blob, pos, 1)
    error_subcode, pos = pull_int(blob, pos, 1)
    if bgp_notification_types[error_code] == "Cease":
        message.set_bgp_notification(error_code, error_subcode)
    else:
        print("NOTIFICATION RECEIVED, unsupported type {}".format(error_code))
    return pos


def open_m(blob, pos, message):
    bgp_version, pos = pull_int(blob, pos, 1)
    my_as, pos = pull_int(blob, pos, 2)
    hold_time, pos = pull_int(blob, pos, 2)
    bgp_identifier, pos = pull_bytes(blob, pos, 4)
    bgp_identifier = bytes_to_IP(bgp_identifier)
    optional_parameters_length, pos = pull_int(blob, pos, 1)
    pos += optional_parameters_length  # Skipping parameters for now
    # print("BGP Version: {},\nAS Number:{},\nBGP Identifier: {}".format(
    #     bgp_version, my_as, bytes_to_IP(bgp_identifier)))  # bytes_to_IP(bgp_identifier)
    message.set_bgp_open(bgp_version, my_as, hold_time, bgp_identifier)
    return pos


def run(blob, index):
    cnt = 0
    new_start = 0
    while(blob.find(marker, cnt) != -1):
        message = MessageBuilder()
        pos = blob.find(marker, cnt)
        _, pos = pull_int(blob, pos, 16)
        message_length, pos = pull_int(blob, pos, 2)
        if len(blob) < pos + message_length:
            return len(blob) - pos
        message_type, pos = pull_int(blob, pos, 1)
        message.set_bgp_basics(message_length, bgp_message_type[message_type])
        # Slows execution down considerably
        parse_bmp_header(blob[new_start:pos], message)
        if bgp_message_type[message_type] == "UPDATE":
            pos = update(blob, pos, message)
        elif bgp_message_type[message_type] == "NOTIFICATION":
            pos = notification(blob, pos, message)
        elif bgp_message_type[message_type] == "OPEN":
            pos = open_m(blob, pos, message)
            _, pos = pull_int(blob, pos, 19)
            pos = open_m(blob, pos, message)
        else:
            print("Unsupported message, ", bgp_message_type[message_type])
        new_start = pos
        cnt = pos + 1
        res = requests.post("http://localhost:9200/{}/_doc".format(index),
                            json=message.message)
    return 0


if __name__ == "__main__":
    f = open(sys.argv[1], "rb")
    blob = f.read()
    f.close()
    index = sys.argv[2]
    requests.put("http://localhost:9200/{}?pretty".format(index))
    run(blob, index)
