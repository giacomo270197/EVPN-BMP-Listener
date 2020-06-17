import evpn_parser
import os
import requests
import selectors
import signal
import socket
import sys
import threading
import types
from queue import Queue

lock = threading.Lock()
sock = None
blob = b''


def cleanup(sig, frame):
    global sock
    try:
        sock.shutdown()
        sock.close()
    except:
        pass
    finally:
        os._exit(0)


def accept_wrapper(sock, sel):
    conn, addr = sock.accept()  # Should be ready to read
    print('accepted connection from', addr)
    conn.setblocking(False)
    data = types.SimpleNamespace(addr=addr, inb=b'', outb=b'')
    events = selectors.EVENT_READ
    sel.register(conn, events, data=data)


def service_connection(key, mask, sel):
    global blob
    sock = key.fileobj
    data = key.data
    if mask & selectors.EVENT_READ:
        recv_data = sock.recv(1024)  # Should be ready to read
        if recv_data:
            with lock:
                blob = blob + recv_data
        else:
            print('closing connection to', data.addr)
            sel.unregister(sock)
            sock.close()


def listen(host, port):
    global sock
    sel = selectors.DefaultSelector()
    sel.register(sock, selectors.EVENT_READ, data=None)
    while True:
        events = sel.select(timeout=None)
        for key, mask in events:
            if key.data is None:
                accept_wrapper(key.fileobj, sel)
            else:
                service_connection(key, mask, sel)


def parse(index):
    global blob
    global lock
    to_parse = b''
    while True:
        if len(blob) != 0:
            print(len(blob))
        with lock:
            if blob:
                to_parse = to_parse + blob
                blob = b''
        if len(to_parse) > 1024:
            print("Starting parse run")
            leftovers = evpn_parser.run(to_parse, index)
            to_parse = to_parse[-leftovers:]
            print("Parsed: {} left".format(leftovers))


if __name__ == "__main__":
    # Standard loopback interface address (localhost)
    host = sys.argv[1]
    # Port to listen on (non-privileged ports are > 1023)
    port = int(sys.argv[2])

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen()
    sock.setblocking(False)
    print('listening on', (host, port))

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    index = "port{}".format(port)
    requests.put(
        "http://localhost:9200/{}?pretty".format(index))

    l = threading.Thread(target=listen, args=(host, port))
    l.daemon = True
    l.start()
    p = threading.Thread(target=parse, args=(index,))
    p.daemon = True
    p.start()
    for t in [l, p]:
        t.join()
