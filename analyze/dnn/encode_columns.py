#!/usr/bin/python3

# Run LSTM, locally:
# $ ./train.py -read data/TCP_labeled.csv -dimensionality 22 -class_amount 2 -sample 0.5 -lstm true
# on server, 2019 SWaT dataset:
# $ ./train.py -read */TCP_labeled.csv -dimensionality 22 -class_amount 2 -sample 0.5 -lstm true
# on server, 2015 SWaT dataset:
# $ ./train.py -read */*_labeled.csv -dimensionality XX -class_amount 2 -sample 0.5 -lstm true

import argparse
import pandas as pd
import traceback

from utils import * 
from glob import glob
from termcolor import colored

# because the data is split over multiple files
# we need to implement early stopping ourselves
# monitor = EarlyStopping(
#     monitor='val_loss', 
#     min_delta=1e-3, 
#     patience=5, 
#     verbose=1, 
#     mode='auto'
# )

def readCSV(f):
    print("[INFO] reading file", f)
    return pd.read_csv(f, delimiter=',', engine='c', encoding="utf-8-sig")

def run():
    print(colored("[INFO] loading file ", 'yellow'))
    df = readCSV(files[0])

    # TODO move back into process_dataset?
    print("[INFO] process dataset, shape:", df.shape)

    print("[INFO] columns:", df.columns)
    columns_before = set(df.columns)
    print("[INFO] analyze dataset:", df.shape)
    analyze(df)


    print("[INFO] Shape when encoding dataset:", df.shape)
    encode_columns(df, arguments.resultColumn, arguments.lstm, arguments.debug)
    print("[INFO] Shape AFTER encoding dataset:", df.shape)

    print("[INFO] dropped columns:", columns_before - set(df.columns))
   
    if arguments.debug:
        print("--------------AFTER DROPPING COLUMNS ----------------")
        print("df.columns", df.columns, len(df.columns))
        with pd.option_context('display.max_rows', 10, 'display.max_columns', None):  # more options can be specified also
            print(df)
    exit()
    df.to_csv('out.csv', index=False)

# instantiate the parser
parser = argparse.ArgumentParser(description='NETCAP compatible implementation of Network Anomaly Detection with a Deep Neural Network and TensorFlow')

# add commandline flags
parser.add_argument('-read', required=True, type=str, help='Regex to find all labeled input CSV file to read from (required)')
parser.add_argument('-drop', type=str, help='optionally drop specified columns, supply multiple with comma')
parser.add_argument('-sample', type=float, default=1.0, help='optionally sample only a fraction of records')
parser.add_argument('-dropna', default=False, action='store_true', help='drop rows with missing values')
parser.add_argument('-testSize', type=float, default=0.2, help='specify size of the test data in percent (default: 0.25)')
parser.add_argument('-loss', type=str, default='categorical_crossentropy', help='set function (default: categorical_crossentropy)')
parser.add_argument('-optimizer', type=str, default='adam', help='set optimizer (default: adam)')
parser.add_argument('-resultColumn', type=str, default='classification', help='set name of the column with the prediction')
#parser.add_argument('-class_amount', type=int, default=2, help='The amount of classes e.g. normal, attack1, attack3 is 3')
parser.add_argument('-fileBatchSize', type=int, default=1, help='The amount of files to be read in. (default: 1)')
parser.add_argument('-epochs', type=int, default=1, help='The amount of epochs. (default: 1)')
parser.add_argument('-numCoreLayers', type=int, default=1, help='set number of core layers to use')
parser.add_argument('-shuffle', default=False, help='shuffle data before feeding it to the DNN')
parser.add_argument('-dropoutLayer', default=False, help='insert a dropout layer at the end')
parser.add_argument('-coreLayerSize', type=int, default=4, help='size of an DNN core layer')
parser.add_argument('-wrapLayerSize', type=int, default=2, help='size of the first and last DNN layer')
parser.add_argument('-lstm', default=False, help='use a LSTM network')
parser.add_argument('-batchSize', type=int, default=100000, help='chunks of records read from CSV and being passed to DNN')
parser.add_argument('-debug', default=False, help='debug mode on off')
parser.add_argument('-zscoreUnixtime', default=False, help='apply zscore to unixtime column')
parser.add_argument('-encodeColumns', default=False, help='switch between auto encoding or using a fully encoded dataset')
parser.add_argument('-classes', type=str, help='supply one or multiple comma separated class identifiers')
parser.add_argument('-saveModel', default=False, help='save model (if false, only the weights will be saved)')

# parse commandline arguments
arguments = parser.parse_args()
if arguments.read is None:
    print("[INFO] need an input file / multi file regex. use the -read flag")
    exit(1)


# get all files
files = glob(arguments.read)
files.sort()

if len(files) == 0:
    print("[INFO] no files matched")
    exit(1)

# MAIN
try:
    run()
except: # catch *all* exceptions
    e = sys.exc_info()
    print("[EXCEPTION]", e)
    traceback.print_tb(e[2], None, None)

