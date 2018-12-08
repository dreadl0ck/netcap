#
# NETCAP - Traffic Analysis Framework
# Copyright (c) 2017 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

# this file contains experiments on reading netcap data in python
# unfinished, needs some love

from google.protobuf.internal.decoder import _DecodeVarint32
import gzip
import struct
import numpy as np
import netcap_pb2 as netcap
from read_protobuf import read_protobuf

# see
# https://www.datadoghq.com/blog/engineering/protobuf-parsing-in-python/

def read_all(f):
    buf = f.read()
    n = 0
    while n < len(buf):
        msg_len, new_pos = _DecodeVarint32(buf, n)
        n = new_pos
        msg_buf = buf[n:n+msg_len]
        n += msg_len
        tcp = netcap.TCP()
        tcp.ParseFromString(msg_buf)
        print("got TCP packet", tcp)

def read_in_chunks(file_object, chunk_size=1024):
    """Lazy function (generator) to read a file piece by piece.
    Default chunk size: 1k."""
    while True:
        data = file_object.read(chunk_size)
        if not data:
            break
        yield data

def read_chunks3(f, chunk_size=4096):
    """Lazy function (generator) to read a file piece by piece.
    Default chunk size: 4096."""
    data = f.read(chunk_size)
    if not data:
        return
    n = 0
    while n < len(data):
        msg_len, new_pos = _DecodeVarint32(data, n)
        if (new_pos + msg_len) > len(data):
            n = new_pos
            # read first part
            msg_buf = data[n:n+msg_len]
            # refill buffer
            data = f.read(chunk_size)
            if not data:
                return
            n = 0
            # read remaining bytes
            new_pos = msg_len-len(msg_buf)
            msg_buf += data[n:n+msg_len-len(msg_buf)]
            n += new_pos
        else:
            n = new_pos
            msg_buf = data[n:n+msg_len]
            n += msg_len
        # refill buffer if necessary
        if not n < len(data):
            data = f.read(chunk_size)
            if not data:
                return
            n = 0
        yield read_protobuf(msg_buf, netcap.TCP())

def read_chunks2(f, chunk_size=4096):
    """Lazy function (generator) to read a file piece by piece.
    Default chunk size: 4096."""
    data = f.read(chunk_size)
    if not data:
        return
    n = 0
    while n < len(data):
        msg_len, new_pos = _DecodeVarint32(data, n)
        if (new_pos + msg_len) > len(data):
            n = new_pos
            # read first part
            msg_buf = data[n:n+msg_len]
            # refill buffer
            data = f.read(chunk_size)
            if not data:
                return
            n = 0
            # read remaining bytes
            new_pos = msg_len-len(msg_buf)
            msg_buf += data[n:n+msg_len-len(msg_buf)]
            n += new_pos
        else:
            n = new_pos
            msg_buf = data[n:n+msg_len]
            n += msg_len
        tcp = netcap.TCP()
        tcp.ParseFromString(msg_buf)
        # refill buffer if necessary
        if not n < len(data):
            data = f.read(chunk_size)
            if not data:
                return
            n = 0
        yield tcp

count = 1

def processDataframe(df):
    print(df)

def processPacket(packet):
    global count
    count += 1
    #print("got packet")

f = gzip.open('tcp.ncap', "rb")
for df in read_chunks3(f):
    #processPacket(packet)
    processDataframe(df)

print("total", count)
