#!/usr/bin/python

import socket
import os, os.path
import sys
import logging
import threading
import signal

print(sys.argv)

buf_size = 1024
connections = list()
stop_threads = False
stop_count = 0

def signal_handler(sig, frame):

    global stop_count
    stop_count = stop_count+1
    print('stopping', stop_count)

    if stop_count > 1:
        quit()

    global stop_threads
    stop_threads = True

    for index, thread in enumerate(threads):
        thread.join()
        logging.info("Main    : thread %d done", index)

    for index, conn in enumerate(connections):
        logging.info("Main    : closing connection %d", index)
        try:
            conn.close()
        except:
            print("closing failed")

    quit()

def create_unix_socket(name):
    socket_name = "/tmp/" + name + ".sock"
    logging.info("Thread %s: starting to read from %s", name, socket_name)

    if os.path.exists(socket_name):
        os.remove(socket_name)

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    sock.bind(socket_name)
    connections.append(sock)

    while True:
        global stop_threads
        if stop_threads:
            break
        datagram = sock.recv(buf_size)
        if datagram:
            print(datagram)
            send_alert()

    logging.info("Thread %s: finishing", name)

#alert_socket_name = "/tmp/Alert.sock"

# if os.path.exists(alert_socket_name):
#     os.remove(alert_socket_name)

#alert_socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
#alert_socket.connect(alert_socket_name)

def send_alert():
    print("send_alert")
    #global alert_socket
    #alert_socket.send(b'Hello alert')

if __name__ == "__main__":

    if len(sys.argv) == 1:
        print("args please")
        quit()

    format = "%(asctime)s: %(message)s"
    logging.basicConfig(format=format, level=logging.INFO, datefmt="%H:%M:%S")

    signal.signal(signal.SIGINT, signal_handler)
    print('press Ctrl+C to stop')

    threads = list()
    for name in sys.argv[1].split(","):
        x = threading.Thread(target=create_unix_socket, args=(name,))
        x.start()
        threads.append(x)

    for index, thread in enumerate(threads):
        thread.join()
        logging.info("Main    : thread %d done", index)
