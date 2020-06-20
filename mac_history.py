import sys
import requests
import json
import dateutil.parser
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from matplotlib.colors import ListedColormap
import matplotlib
import math

es_host = None
es_port = None
es_index = None


nlri_possibilities = ["MP_NLRI_REACH", "MP_NLRI_UNREACH"]


def find_best_placement(total):
    sqrt = math.sqrt(total)
    n_cols = math.ceil(sqrt)
    n_row = math.floor(sqrt)
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
    plt.gca().xaxis.set_major_formatter(mdates.DateFormatter("#%Y-%m-%d %H:%M:%S"))
    locator = mdates.MicrosecondLocator(interval=100000)
    plt.gca().xaxis.set_major_locator(locator)
    rows, cols = find_best_placement(len(events))
    for event, i in zip(events, range(len(events))):
        event_div, event_times_div = divide(event, events_times[i])
        plt.subplot(rows, cols, i+1)
        plt.gca().yaxis.set_visible(False)
        plt.scatter(event_times_div[0], event_div[0], label="MP_NLRI_REACH")
        plt.scatter(event_times_div[1], event_div[1], label="MP_NLRI_UNREACH")
        plt.legend(loc='upper left')
        plt.xlabel('Time')
    plt.gcf().autofmt_xdate()
    plt.show()


def set_es_parameters():
    global es_host
    global es_port
    global es_index
    with open("config.txt", "r") as file:
        es_host = file.readline().replace("\n", "")
        es_port = file.readline().replace("\n", "")
        es_index = file.readline().replace("\n", "")


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
    header = {
        "Content-Type": "application/json"
    }
    response = requests.get(
        "http://{}:{}/_search/?size=10000".format(es_host, es_port), data=json.dumps(query), headers=header)
    return response.json()


def find_mean_timedelta(adv_timestamps):
    mean_delta = 0
    count = 0
    for x in range(len(adv_timestamps) - 1):
        mean_delta += (adv_timestamps[x+1] -
                       adv_timestamps[x]).total_seconds()
        count += 1
    mean_delta /= count
    return mean_delta


def find_events(adv, adv_timestamps):
    events = []
    events_times = []
    delimiters = []
    bgn = 0
    mean_delta = find_mean_timedelta(adv_timestamps)
    for x in range(len(adv_timestamps) - 1):
        if (adv_timestamps[x+1] - adv_timestamps[x]).total_seconds() > mean_delta:
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


def analyze(mac):
    set_es_parameters()
    mac_info = retrieve_mac_info(mac)
    adv = []
    adv_timestamps = []
    for entry in mac_info["hits"]["hits"]:
        bmp = entry["_source"]
        try:
            if bmp["bgp_message"]["update"]["type"] == "New Route":
                adv.append(nlri_possibilities[0])
            elif bmp["bgp_message"]["update"]["type"] == "Withdrawn":
                adv.append(nlri_possibilities[1])
            adv_timestamps.append(dateutil.parser.isoparse(
                bmp["timestamp_received"]))
        except KeyError:
            print("This isn't an update: ",
                  bmp["bgp_message"]["message_type"])
    events, events_times = find_events(adv, adv_timestamps)
    plot(events, events_times)


if __name__ == "__main__":
    mac = sys.argv[1]
    analyze(mac)
