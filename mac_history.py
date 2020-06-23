import sys
import requests
import json
import dateutil.parser
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from matplotlib.colors import ListedColormap
import matplotlib
import math
import statistics
import networkx as nx
import hashlib

es_host = None
es_port = None
es_index = None
target = None

tolerance = 1

nlri_possibilities = ["MP_NLRI_REACH", "MP_NLRI_UNREACH"]


class EventTree:
    def __init__(self):
        self.tree = nx.DiGraph()
        self.source_nodes = []
        self.nodes_to_add = []

    def add_to_source(self, node):
        self.source_nodes.append(node)

    def rm_from_source(self, node):
        rm = []
        for x in self.source_nodes:
            if node in x:
                rm.append(x)
        try:
            self.source_nodes.pop(self.source_nodes.index(node))
        except:
            pass

    def add_to_to_add(self, node):
        self.nodes_to_add.append(node)

    def rm_from_to_add(self, node):
        rm = []
        for x in self.nodes_to_add:
            if node in x:
                rm.append(x)
        for x in rm:
            try:
                self.nodes_to_add.pop(self.nodes_to_add.index(x))
            except:
                pass

    def add_new_layer(self):
        if not self.source_nodes:
            self.tree.add_node(self.nodes_to_add[0])
        for s_node in self.source_nodes:
            for d_node in self.nodes_to_add:
                self.tree.add_node(d_node)
                self.tree.add_edge(s_node, d_node)


def find_best_placement(total):
    sqrt = math.sqrt(total)
    n_cols = math.ceil(sqrt)
    n_row = math.floor(sqrt)
    if n_cols * n_row < total:
        n_row += 1
    return n_row, n_cols


def divide(event, event_times):
    event_div = [[], []]
    event_times_div = [[], []]
    for i in range(len(event)):
        if event[i] == "MP_NLRI_REACH":
            event_div[0].append(event[i])
            event_times_div[0].append(event_times[i])
        else:
            event_div[1].append(event[i])
            event_times_div[1].append(event_times[i])
    return event_div, event_times_div


def plot(events, events_times):
    matplotlib.rcParams['axes.prop_cycle'] = matplotlib.cycler(color=[
                                                               "b", "r"])
    for event, i in zip(events, range(len(events))):
        plt.gca().xaxis.set_major_formatter(
            mdates.DateFormatter("%M:%S"))  # ("%Y-%m-%d %H:%M:%S"))
        locator = mdates.SecondLocator()
        plt.gca().xaxis.set_major_locator(locator)
        event_div, event_times_div = divide(event, events_times[i])
        plt.gca().yaxis.set_visible(False)
        plt.scatter(event_times_div[0], event_div[0], label="MP_NLRI_REACH")
        plt.scatter(event_times_div[1], event_div[1], label="MP_NLRI_UNREACH")
        plt.legend(loc='best')
        plt.xlabel('Time')
        plt.gcf().autofmt_xdate()
        plt.show()


def compute_convergence(event_times):
    tmp = []
    for times in event_times:
        tmp.append((times[-1] - times[0]).total_seconds())
    print("Convergence Mean: {}".format(statistics.mean(tmp)))
    print("Convergence Stdev: {}".format(statistics.stdev(tmp)))


def set_es_parameters():
    global es_host
    global es_port
    global es_index
    with open("config.txt", "r") as file:
        es_host = file.readline().replace("\n", "")
        es_port = file.readline().replace("\n", "")
        es_index = file.readline().replace("\n", "")


def launch_request(query):
    header = {
        "Content-Type": "application/json"
    }
    response = requests.get(
        "http://{}:{}/{}/_search/?size=10000".format(es_host, es_port, target), data=json.dumps(query), headers=header)
    return response.json()


def retrieve_mac_info(mac):
    query = {
        "query": {
            "term": {
                "bgp_message.update.mac_address.keyword": {
                    "value": mac
                }
            }
        }
    }
    return launch_request(query)


def retrieve_updates():
    query = {
        "query": {
            "term": {
                "bgp_message.message_type.keyword": {
                    "value": "UPDATE"
                }
            }
        }
    }
    return launch_request(query)


def find_mean_timedelta(adv_timestamps, adv):
    mean_delta = 0
    count = 0
    intervals = []
    for x in range(len(adv_timestamps) - 1):
        intervals.append((adv_timestamps[x+1] -
                          adv_timestamps[x]).total_seconds())
        # print(intervals[-1])
        count += 1
    mean_delta = statistics.mean(intervals)
    stdev_delta = statistics.stdev(intervals)
    return mean_delta, stdev_delta


def find_events(adv, adv_timestamps):
    events = []
    events_times = []
    delimiters = []
    bgn = 0
    mean_delta, stdev_delta = find_mean_timedelta(adv_timestamps, adv)
    print((mean_delta) * (len(adv) / (stdev_delta)))
    for x in range(len(adv_timestamps) - 1):
        if (adv_timestamps[x+1] - adv_timestamps[x]).total_seconds() > (mean_delta) * (tolerance * len(adv) / (stdev_delta)):
            delimiters.append(x)
    for x in delimiters:
        events.append(adv[bgn:x+1])
        events_times.append(adv_timestamps[bgn:x+1])
        bgn = x + 1
    events.append(adv[bgn:])
    events_times.append(adv_timestamps[bgn:])
    if not events:
        events = adv
        events_times = adv_timestamps
    return events, events_times


def analyze_mac(mac):
    mac_info = retrieve_mac_info(mac)["hits"]["hits"]
    tmp = []
    for entry in mac_info:
        bmp = entry["_source"]
        adv_type = None
        for up in bmp["bgp_message"]["update"]:
            try:
                if up["type"] == "New Route":
                    adv_type = nlri_possibilities[0]
                elif up["type"] == "Withdrawn":
                    adv_type = nlri_possibilities[1]
                tmp.append((adv_type, dateutil.parser.isoparse(
                    bmp["timestamp_received"])))
            except KeyError:
                print("This isn't an update: ",
                      bmp["bgp_message"]["message_type"])
    tmp = sorted(tmp, key=lambda d: d[1].timestamp())
    adv = [x for x, _ in tmp]
    adv_timestamps = [x for _, x in tmp]
    events, events_times = find_events(adv, adv_timestamps)
    plot(events, events_times)
    compute_convergence(events_times)


def find_all_macs(data):
    macs = []
    lis = [x["_source"]["bgp_message"]["update"] for x in data]
    for x in lis:
        for y in x:
            macs.append(y["mac_address"])
    macs = set(macs)
    return macs


def find_macs_events(data):
    macs = find_all_macs(data)
    ret = {}
    for mac in macs:
        events = [x for x in data if x["_source"]
                  ["bgp_message"]["update"][0]["mac_address"] == mac]
        events, _ = find_events(events, [dateutil.parser.isoparse(
            x["_source"]["timestamp_received"]) for x in events])
        ret[mac] = events
    return ret


def find_rds(data):
    rds_new = []
    rds_withdrawn = []
    for x in data:
        for u in x["_source"]["bgp_message"]["update"]:
            rd = u["route_distinguisher"]
            print(rd)
            if u["type"] == "New Route":
                rds_new.append(rd)
            else:
                rds_withdrawn.append(rd)
    return rds_new, rds_withdrawn


def detect_flapping():
    rd_to_anycast = {
        "10.10.10.1:0 6": "10.10.100.1",
        "10.10.10.2:0 6": "10.10.100.1",
        "10.10.10.3:0 6": "10.10.100.2",
        "10.10.10.4:0 6": "10.10.100.2",
    }
    updates = retrieve_updates()["hits"]["hits"]
    updates = sorted(updates, key=lambda d: dateutil.parser.isoparse(
        d["_source"]["timestamp_received"]).timestamp())
    mac_events = find_macs_events(updates)
    for mac in mac_events.keys():
        tree = EventTree()
        for event in mac_events[mac]:
            rds_new, rds_withdrawn = find_rds(event)
            rds_new = list(set([rd_to_anycast[x] for x in rds_new]))
            rds_withdrawn = list(set([rd_to_anycast[x]
                                      for x in rds_withdrawn]))

            print("1, ", tree.nodes_to_add)
            for rd in rds_new:
                tree.add_to_to_add(rd[-1] + " ,  " + event[0]
                                   ["_source"]["timestamp_received"][-15:-7])
                tree.rm_from_source(rd)
            for rd in rds_withdrawn:
                tree.rm_from_to_add(rd)

            tree.add_new_layer()

        plt.plot()
        plt.title = mac
        pos = nx.spring_layout(tree.tree)
        nx.draw(tree.tree, pos, with_labels=True)
        plt.show()


if __name__ == "__main__":
    set_es_parameters()
    option = sys.argv[1]
    target = sys.argv[-1]
    if option == "--mac-analysis":
        mac = sys.argv[2]
        if len(sys.argv) > 3:
            tolerance = float(sys.argv[3])
        analyze_mac(mac)
    elif option == "--mac-flapping":
        detect_flapping()
