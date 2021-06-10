#!/usr/bin/python
#
# stream version
# todo: benchmark

server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind("/tmp/Connection.sock")
while True:
   server.listen(1)
   conn, addr = server.accept()
   while True:
       datagram = conn.recv(1024)
       if datagram:
           print(datagram)
conn.close()