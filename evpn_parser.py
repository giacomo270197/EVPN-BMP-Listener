import socket
import struct
import sys

class ELK:
    pass

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
        tmp = [x.replace("0x", "") if len(x.replace("0x", "")) == 2 else "0" + x.replace("0x", "")  for x in num]
        return ":".join(tmp)
    if len(num) == 8:
        tmp = [str(int(x.replace("0x", ""), 16)) for x in num]
        return ".".join(tmp[2:-2]) + ":{}".format(str(tmp[-2]) + " " + str(tmp[-1]))
    elif len(num) == 16:
        tmp = []
        for x in range(0, len(num), 2):
            f = "0" + num[x].replace("0x", "") if len(num[x].replace("0x", "")) == 1 else num[x].replace("0x", "")
            s = "0" + num[x+1].replace("0x", "") if len(num[x+1].replace("0x", "")) == 1 else num[x+1].replace("0x", "")
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

def parse_bmp_common_header(blob, pos):
    version, pos = pull_int(blob, pos, 1)
    message_length, pos = pull_int(blob, pos, 4)
    message_type, pos = pull_int(blob, pos, 1)
    print("\n#########################################\n")
    try:
        print("BMP Version: {}\nMessage Type: {}".format(version, bmp_message_types[message_type]))
    except KeyError: # For some reason the first capture has a malformed BMP header
        print("Failed!!!!")
    return pos, message_type

def parse_bmp_per_peer_header(blob, pos):
    peer_type, pos = pull_int(blob, pos, 1)
    flags , pos = pull_int(blob, pos, 1)
    peer_distinguisher, pos = pull_bytes(blob, pos, 8)
    if flags >= 128: # First bit set means IPv6
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
    print("Peer ID: {},\nASN: {},\nAddress:{}".format(bgp_id, asn, address))

def parse_bmp_header(blob):
    pos = 0
    pos, message_type = parse_bmp_common_header(blob[:6], pos)
    if len(blob) > 6: # Meaning there is a per-peer-header too
        parse_bmp_per_peer_header(blob[6:], pos)
    return message_type

def mp_nlri(blob, pos, length, nlri):
    afi, pos = pull_int(blob, pos, 2)
    safi, pos = pull_int(blob, pos, 1)
    if afi != 25 or safi != 70:
        return pos + length - 3 # Return pointer to next path attribute (minus bytes we already consumed)
    else:
        if nlri:
            _, pos = pull_int(blob, pos, 5) # Network Address of Next Hop, is it really always 5-bytes in our case?
            _, pos = pull_int(blob, pos, 1) # SNPA, is it really always 1-bytes in our case?
        evpn_type, pos = pull_int(blob, pos, 1)
        if evpn_route_types[evpn_type] == "MAC Advertisement Route":
            evpn_length, pos = pull_int(blob, pos, 1)
            route_distinguisher, pos = pull_bytes(blob, pos, 8)
            esi, pos = pull_int(blob, pos, 10)
            ethernet_tag_id, pos = pull_int(blob, pos, 4)
            _, pos = pull_int(blob, pos, 1) # MAC length, assuming it is always 48-bits
            mac_address, pos = pull_bytes(blob, pos, 6)
            if mac_address:
                mac_address = bytes_to_IP(mac_address)
            ip_length, pos = pull_int(blob, pos, 1) # IP length, and MPLS label
            ip_address, pos = pull_bytes(blob, pos, int(ip_length / 8))
            if ip_address:
                ip_address = bytes_to_IP(ip_address)
            mpls_label, pos = pull_bytes(blob, pos, 3)
            # print("\n#########################################\n")
            print("New MAC advertisement route ({}).\nRoute distinguisher: {},\nMAC Address: {},\nIP Address: {},\nMPLS Label: {}".format(\
                "New Route" if nlri else "Withdrawn", bytes_to_IP(route_distinguisher), mac_address, ip_address, mpls_label))
            print("\n#########################################\n")
        return pos

def parse_path_attribute(blob, pos):
    _, pos = pull_int(blob, pos, 1)
    path_attribute_type, pos = pull_int(blob, pos, 1)
    if bgp_path_attributes[path_attribute_type] in single_length_path_attributes:
        length, pos =  pull_int(blob, pos, 1)
    elif bgp_path_attributes[path_attribute_type] in double_length_path_attributes:
        length, pos =  pull_int(blob, pos, 2)
    else:
        print("Unkown length attribute", bgp_path_attributes[path_attribute_type])
        exit()
    if bgp_path_attributes[path_attribute_type] == "MP_REACH_NLRI":
        pos = mp_nlri(blob, pos, length, True)
    elif bgp_path_attributes[path_attribute_type] == "MP_UNREACH_NLRI":
        pos = mp_nlri(blob, pos, length, False)
    else:
        pos += length # Return pointer to next path attribute
    return pos

def update(blob, pos):
        _, pos = pull_int(blob, pos, 2)
        path_attributes_length, pos = pull_int(blob, pos, 2)
        drawn = 0
        while(drawn < path_attributes_length):
            new_pos = parse_path_attribute(blob, pos)
            drawn += new_pos - pos
            pos = new_pos
        return pos

def notification(blob, pos):
    error_code, pos = pull_int(blob, pos, 1)
    error_subcode, pos = pull_int(blob, pos, 1)
    if bgp_notification_types[error_code] == "Cease":
        print("NOTIFICATION RECEIVED, Peer Down")
    else:
        print("NOTIFICATION RECEIVED, unsupported type {}".format(error_code))
    print("\n#########################################\n")
    return pos

def open_m(blob, pos):
    bgp_version, pos = pull_int(blob, pos, 1)
    my_as, pos = pull_int(blob, pos, 2)
    hold_time, pos = pull_int(blob, pos, 2)
    bgp_identifier, pos = pull_bytes(blob, pos, 4)
    optional_parameters_length, pos = pull_int(blob, pos, 1)
    pos += optional_parameters_length # Skipping parameters for now
    print("BGP Version: {},\nAS Number:{},\nBGP Identifier: {}".format(bgp_version, my_as, bytes_to_IP(bgp_identifier))) # bytes_to_IP(bgp_identifier)
    return pos

def run(blob):
    cnt = 0
    messages = [] # Use somehow 
    new_start = 0
    while(blob.find(marker, cnt) != -1):
        pos = blob.find(marker, cnt)
        tmp = pos
        _, pos = pull_int(blob, pos, 16)
        message_length, pos = pull_int(blob, pos, 2)
        if len(blob) < pos + message_length:
            return len(blob) - pos
        message_type, pos = pull_int(blob, pos, 1)
        bmp_message_type = parse_bmp_header(blob[new_start:pos])  # Slows execution down considerably
        if bgp_message_type[message_type] == "UPDATE":
            pos = update(blob, pos)
        elif bgp_message_type[message_type] == "NOTIFICATION":
            parse_bmp_header(blob[new_start:pos])  # Slows execution down considerably
            pos = notification(blob, pos)
        elif bgp_message_type[message_type] == "OPEN":
            pos = open_m(blob, pos)
            _, pos = pull_int(blob, pos, 19)
            pos = open_m(blob, pos)
            print("\n#########################################\n")
        else:
            print("Unsupported message, ", bgp_message_type[message_type])
        new_start = pos
        cnt = pos + 1
    return 0

if __name__ == "__main__":
    blob = b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x7c\x02\x00\x00\x00\x65\x40\x01\x01\x00\x50\x02\x00\x0a\x02\x02\xfa\x56\xed\xfd\xfa\x56\xed\xf3\xc0\x10\x20\x00\x02\xed\xf3\x00\x01\x8a\x8c\x00\x02\xed\xf3\x00\x06\x2a\x23\x03\x0c\x00\x00\x00\x00\x00\x08\x06\x03\x44\x38\x39\x00\x01\x02\x90\x0e\x00\x2c\x00\x19\x46\x04\x0a\x0a\x64\x01\x00\x02\x21\x00\x01\x0a\x0a\x0a\x01\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x30\x44\x38\x39\xff\x00\x21\x00\x00\x00\x00'
    if len(sys.argv) > 1:
        f = open(sys.argv[1], "rb")
        blob = f.read()
        f.close()
    run(blob)
    

