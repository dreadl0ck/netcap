#!/usr/bin/python
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

import os
import gzip
import struct
import numpy as np
import nctypes as t
import netcap_pb2 as netcap
import pandas as pd

from google.protobuf.internal.decoder import _DecodeVarint32
from read_protobuf import read_protobuf

# see
# https://www.datadoghq.com/blog/engineering/protobuf-parsing-in-python/

class NCReader:

    filepath = ""
    gotHeader = False
    count = 0
    df = pd.DataFrame()
    records = []
    
    def __init__(self, filepath):
        self.filepath = filepath

    # primitive for reading buffered from a netcap file
    def read_chunks(self, f, NCType, dataframe, chunk_size=4096):
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

            # print(msg_buf, msg_len)
            if not self.gotHeader:
                self.gotHeader = True
            else:
                yield read_protobuf(bytes(msg_buf), NCType, dataframe, index=self.count)

    def handle(self, r, dataframe):
        self.count += 1
        if dataframe:
            self.df = self.df.append(r)
        else:
            self.records.append(r)

    def read(self, dataframe):

        path, ext = os.path.splitext(self.filepath)
        if ext == ".gz":
            f = gzip.open(self.filepath, "rb")
        else:
            f = open(self.filepath, "rb")

        segments = os.path.split(path)
        ident = segments[-1].strip(".ncap")
        NCType = t.types[ident]

        for r in self.read_chunks(f, NCType, dataframe):
            self.handle(r, dataframe)
        
        f.close()
        print("total", self.count)


