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

es_host = None
es_port = None
es_index = None

tolerance = 1


nlri_possibilities = ["MP_NLRI_REACH", "MP_NLRI_UNREACH"]


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
        "http://{}:{}/_search/?size=10000".format(es_host, es_port), data=json.dumps(query), headers=header)
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


# def detect_flapping():
#     updates = retrieve_updates()["hits"]["hits"]
#     final_state = {}
#     for entry in updates:
#         bmp = entry["_source"]
#         route_target = None
#         for ec in bmp["bgp_message"]["extended_communities"]:
#             if ec["type"] == "Transitive Two-Octet AS-Specific Extended Community" and ec["subtype"] == "Route Target":
#                 route_target = "{} {}".format(
#                     ec["2_bytes_value"], ec["4_bytes_value"])
#         if not route_target:
#             exit("No route target found")
#         for update in entry["update"]:


if __name__ == "__main__":
    set_es_parameters()
    option = sys.argv[1]
    if option == "--mac-analysis":
        mac = sys.argv[2]
        if len(sys.argv) > 3:
            tolerance = float(sys.argv[3])
        analyze_mac(mac)
    elif option == "--mac-flapping":
        pass
