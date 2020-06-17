import selectors
import socket
import types
import sys
import evpn_parser
import threading
from queue import Queue
import requests

lock = threading.Lock()
lsock = None
blob = b''


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
    global lsock
    sel = selectors.DefaultSelector()
    sel.register(lsock, selectors.EVENT_READ, data=None)
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

    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.bind((host, port))
    lsock.listen()
    lsock.setblocking(False)
    print('listening on', (host, port))

    index = "port{}".format(port)
    requests.put(
        "http://localhost:9200/{}?pretty".format(index))

    threading.Thread(target=listen, args=(host, port)).start()
    threading.Thread(target=parse, args=(index,)).start()
