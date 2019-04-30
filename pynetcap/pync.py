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

import pynetcap as nc
import argparse

def str2bool(v):
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')

parser = argparse.ArgumentParser()
parser.add_argument("path", action="store", type=str)
parser.add_argument("--dataframe", type=str2bool, nargs='?',
                        const=True, default=True,
                        help="Activate dataframe mode.")
args = parser.parse_args()

#reader = nc.NCReader('../pcaps/LOKI/HTTP.ncap.gz')
reader = nc.NCReader(args.path)

if args.dataframe:
    reader.read(dataframe=True)
    print("[INFO] completed reading the audit record file:", reader.filepath)
    print("DATAFRAME:")
    print(reader.df)
else:
    reader.read(dataframe=False)
    print("RECORDS:")
    print(reader.records)