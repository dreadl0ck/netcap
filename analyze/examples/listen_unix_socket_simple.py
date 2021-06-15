#!/usr/bin/python

import socket
import os, os.path
import sys
import logging
import signal

print(sys.argv)

buf_size = 256
stop_count = 0
num_datagrams = 0

def signal_handler(sig, frame):

    global stop_count
    stop_count = stop_count+1
    print('stopping, stop_count:', stop_count, "sig:", sig, "frame:", frame)

    global num_datagrams
    logging.info("received %d datagrams", num_datagrams)

    try:
        print("CLOSING alert socket")
        alert_socket.close()
    except:
        print("closing alert socket failed")

    if stop_count > 1:
        quit()

def create_unix_socket(name):
    socket_name = "/tmp/" + name + ".sock"
    logging.info("starting to read from %s", socket_name)

    if os.path.exists(socket_name):
        os.remove(socket_name)

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    sock.bind(socket_name)

    while True:
        global num_datagrams
        datagram = sock.recv(buf_size)
        if datagram:
            num_datagrams += 1
            print(datagram, num_datagrams)
            #send_alert()


alert_socket_name = "/tmp/Alert.sock"

alert_socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
alert_socket.connect(alert_socket_name)

def send_alert():
    print("send_alert")
    global alert_socket
    alert_socket.send(b'This is a test alert')

if __name__ == "__main__":

    if len(sys.argv) == 1:
        print("args please")
        quit()

    format = "%(asctime)s: %(message)s"
    logging.basicConfig(format=format, level=logging.INFO, datefmt="%H:%M:%S")

    signal.signal(signal.SIGINT, signal_handler)
    print('press Ctrl+C to stop')

    create_unix_socket("Connection")
