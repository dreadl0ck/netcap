#!/usr/bin/python3

# Run LSTM, locally:
# $ ./score.py -read data/TCP_labeled.csv -features 22 -class_amount 2 -sample 0.5 -lstm true
# on server, 2019 SWaT dataset:
# $ ./score.py -read */TCP_labeled.csv -features 22 -class_amount 2 -sample 0.5 -lstm true
# on server, 2015 SWaT dataset:
# $ ./score.py -read */*_labeled.csv -features XX -class_amount 2 -sample 0.5 -lstm true

import argparse
import pandas as pd
import traceback
import time
import datetime
import sys
import socket
import numpy as np
from utils import * 
from glob import glob

from sklearn.metrics import confusion_matrix
from sklearn import metrics

from termcolor import colored
from keras.models import load_model

# cf_total is for summing up all of the confusion matrices from all of the separate files
cf_total = None

# configurable via argument
# hardcoded these are the labeltypes that can be found in the dataset
#classes = ["normal", "Single Stage Single Point", "Single Stage Multi Point", "Multi Stage Single Point", "Multi Stage Multi Point"]
classes = [b'normal', b'infiltration']

def readCSV(f):
    print("[INFO] reading file", f)
    return pd.read_csv(f, delimiter=',', engine='c', encoding="utf-8-sig")

def run():
    global model
    leftover = None

    # Create a new model instance
    if arguments.model is not None:
        print("loading model")
        model = load_model(
            arguments.model,
            custom_objects={
                #"tp": keras.metrics.TruePositives,
                # "TruePositives": keras.metrics.TruePositives(name='tp'),
                # "fp": keras.metrics.FalsePositives(name='fp'),
                # "tn": keras.metrics.TrueNegatives(name='tn'),
                # "fn": keras.metrics.FalseNegatives(name='fn'),
                # "accuracy": keras.metrics.BinaryAccuracy(name='accuracy'),
                # "precision": keras.metrics.Precision(name='precision'),
                # "recall": keras.metrics.Recall(name='recall'),
                # "auc": keras.metrics.AUC(name='auc'),
            }
        )
    else:
        print("loading weights:", arguments.weights)
        weight_files = glob(arguments.weights)
        weight_files.sort()

        #print("FILES:", weight_files)
        print("loading file", weight_files[-1])
        model.load_weights(weight_files[-1])

    print(colored("[INFO] model summary:", 'yellow'))
    model.summary()

    leftover = None
    for i in range(0, len(files), arguments.fileBatchSize):

        df_from_each_file = [readCSV(f) for f in files[i:(i+arguments.fileBatchSize)]]

        # ValueError: The truth value of a DataFrame is ambiguous. Use a.empty, a.bool(), a.item(), a.any() or a.all().
        if leftover is not None:
            df_from_each_file.insert(0, leftover)

        print("[INFO] concatenate the files")
        df = pd.concat(df_from_each_file, ignore_index=True)

        print("[INFO] process dataset, shape:", df.shape)
        if arguments.drop is not None:
            for col in arguments.drop.split(","):
                drop_col(col, df)

        if not arguments.lstm:
            print("dropping all time related columns...")
            drop_col('unixtime',df)

        print("[INFO] columns:", df.columns)
        if arguments.debug:
            print("[INFO] analyze dataset:", df.shape)
            analyze(df)

        if arguments.zscoreUnixtime:
            encode_numeric_zscore(df, "unixtime")

        if arguments.encodeColumns:
            print("[INFO] Shape when encoding dataset:", df.shape)
            encode_columns(df, arguments.resultColumn, arguments.lstm, arguments.debug)
            print("[INFO] Shape AFTER encoding dataset:", df.shape)
        
        if arguments.encodeCategoricals:
            print("[INFO] Shape when encoding dataset:", df.shape)
            encode_categorical_columns(df, arguments.features)    
            print("[INFO] Shape AFTER encoding dataset:", df.shape)

        batchSize = arguments.batchSize
        for batch_index in range(0, df.shape[0], batchSize):
            
            dfCopy = df[batch_index:batch_index+batchSize]

            # skip leftover that does not reach batch size
            if len(dfCopy.index) != batchSize:
                leftover = dfCopy
                continue

            print("[INFO] processing batch {}-{}/{}".format(batch_index, batch_index+batchSize, df.shape[0]))
            eval_dnn(dfCopy)
            leftover = None

buf_size = 512
stop_count = 0
num_datagrams = 0

datagrams = list()

def create_unix_socket(name):

    global datagrams
    global epoch
    socket_name = "/tmp/" + name + ".sock"

    global model
    leftover = None

    # Create a new model instance
    if arguments.model is not None:
        print("loading model")
        model = load_model(
            arguments.model,
            custom_objects={
                #"tp": keras.metrics.TruePositives,
                # "TruePositives": keras.metrics.TruePositives(name='tp'),
                # "fp": keras.metrics.FalsePositives(name='fp'),
                # "tn": keras.metrics.TrueNegatives(name='tn'),
                # "fn": keras.metrics.FalseNegatives(name='fn'),
                # "accuracy": keras.metrics.BinaryAccuracy(name='accuracy'),
                # "precision": keras.metrics.Precision(name='precision'),
                # "recall": keras.metrics.Recall(name='recall'),
                # "auc": keras.metrics.AUC(name='auc'),
            }
        )
    else:
        print("loading weights:", arguments.weights)
        weight_files = glob(arguments.weights)
        weight_files.sort()

        #print("FILES:", weight_files)
        print("loading file", weight_files[-1])
        model.load_weights(weight_files[-1])

    print(colored("[INFO] model summary:", 'yellow'))
    model.summary()

    # TODO: this seems to redirect stdout and stderr? also affects following print statements
    #logging.info("starting to read from %s", socket_name)

    if os.path.exists(socket_name):
        os.remove(socket_name)

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    sock.bind(socket_name)

    while True:
        global num_datagrams
        datagram = sock.recv(buf_size)
        if datagram:
            if num_datagrams != 0 and num_datagrams % arguments.batchSize == 0:

                # create the pandas DataFrame
                df = pd.DataFrame(datagrams, columns=['TimestampFirst',
                                                       'LinkProto',
                                                       'NetworkProto',
                                                       'TransportProto',
                                                       'ApplicationProto',
                                                       'SrcMAC',
                                                       'DstMAC',
                                                       'SrcIP',
                                                       'SrcPort',
                                                       'DstIP',
                                                       'DstPort',
                                                       'TotalSize',
                                                       'AppPayloadSize',
                                                       'NumPackets',
                                                       'Duration',
                                                       'TimestampLast',
                                                       'BytesClientToServer',
                                                       'BytesServerToClient',
                                                       'Category'])

                #analyze(df)
                eval_dnn(df)

                # reset datagrams
                datagrams = list()

            for data in datagram.split(b'\n'):
                if data != b'':
                    arr = data.split(b',')
                    if len(arr) != 19:
                        # TODO: make configurable
                        #print(arr, len(arr))
                        if arr[0].startswith(b'Timestamp'): 
                            epoch += 1
                            print("epoch", epoch)
                    else:
                        num_datagrams += 1
                        datagrams.append(arr)

            # TODO: dispatch alert as soon we have anything to report
            #send_alert()

def run_socket():
    create_unix_socket("Connection")

epoch = 0

def process(df):

    global epoch
    global patience
    global min_delta

    history, leftover = process_dataframe(df, 0, epoch)

    if history is not None:
        # get current loss
        lossValues = history.history['val_loss']
        currentLoss = lossValues[-1]
        print(colored("[LOSS] " + str(currentLoss),'yellow'))

        # implement early stopping to avoid overfitting
        # start checking the val_loss against the threshold after patience epochs
        if epoch >= patience:
            print("[CHECKING EARLY STOP]: currentLoss < min_delta ? =>", currentLoss, " < ", min_delta)
            if currentLoss < min_delta:
                print("[STOPPING EARLY]: currentLoss < min_delta =>", currentLoss, " < ", min_delta)
                print("EPOCH", epoch)
                exit(0)

def process_dataframe(df, i, epoch):

    print("[INFO] process dataset, shape:", df.shape)
    if arguments.sample != None:
        if arguments.sample > 1.0:
            print("invalid sample rate")
            exit(1)

        if arguments.sample <= 0:
            print("invalid sample rate")
            exit(1)

    print("[INFO] sampling", arguments.sample)
    if arguments.sample < 1.0:
        df = df.sample(frac=arguments.sample, replace=False)

    if arguments.drop is not None:
        for col in arguments.drop.split(","):
            drop_col(col, df)

    if not arguments.lstm:
        print("[INFO] dropping all time related columns...")
        drop_col('Timestamp', df)
        drop_col('TimestampFirst', df)
        drop_col('TimestampLast', df)

    if arguments.debug:
        print("[INFO] columns:", df.columns)
        print("[INFO] analyze dataset:", df.shape)
        analyze(df)

    if arguments.zscoreUnixtime:
        encode_numeric_zscore(df, "Timestamp")

    if arguments.encodeColumns:
        print("[INFO] Shape when encoding dataset:", df.shape)
        encode_columns(df, arguments.resultColumn, arguments.lstm, arguments.debug)
        print("[INFO] Shape AFTER encoding dataset:", df.shape)

    if arguments.debug:
        print("--------------AFTER DROPPING COLUMNS ----------------")
        print("df.columns", df.columns, len(df.columns))
        with pd.option_context('display.max_rows', 10, 'display.max_columns', None):  # more options can be specified also
            print(df)

    if arguments.encodeCategoricals:
        print("[INFO] Shape when encoding dataset:", df.shape)
        encode_categorical_columns(df, arguments.features)
        print("[INFO] Shape AFTER encoding dataset:", df.shape)

    # for batch_size in range(0, df.shape[0], arguments.batchSize):
    #
    #     dfCopy = df[batch_size:batch_size+arguments.batchSize]
    #
    #     # skip leftover that does not reach batch size
    #     if len(dfCopy.index) != arguments.batchSize:
    #         leftover = dfCopy
    #         continue

    print("[INFO] processing batch {}/{}".format(arguments.batchSize, df.shape[0]))
    history = train_dnn(df, i, epoch, batch=arguments.batchSize)
    leftover = None

    return history, leftover

def eval_dnn(df):
    global cf_total
    global model

    if arguments.drop is not None:
        for col in arguments.drop.split(","):
            drop_col(col, df)
    
    if not arguments.lstm:
        print("[INFO] dropping all time related columns...")
        drop_col('Timestamp', df)
        drop_col('TimestampFirst', df)
        drop_col('TimestampLast', df)

    x_test, y_test = to_xy(df, arguments.resultColumn, classes, arguments.debug, arguments.binaryClasses)
    #print("x_test", x_test, "shape", x_test.shape)
    
    #np.set_printoptions(threshold=sys.maxsize)
    #print("y_test", y_test, "shape", y_test.shape)
    #np.set_printoptions(threshold=10)

    print(colored("[INFO] measuring accuracy...", 'yellow'))
    print("x_test.shape:", x_test.shape)

    if arguments.debug:
        print("--------SHAPES--------")
        print("x_test.shape", x_test.shape)
        print("y_test.shape", y_test.shape)

    if arguments.lstm:

        print("[INFO] reshape for using LSTM layers")
        x_test = x_test.reshape(int(arguments.batchSize / arguments.dnnBatchSize), arguments.dnnBatchSize, x_test.shape[1])
        y_test = y_test.reshape(int(arguments.batchSize / arguments.dnnBatchSize), arguments.dnnBatchSize, y_test.shape[1])

        if arguments.debug:
            print("--------RESHAPED--------")
            print("x_test.shape", x_test.shape)
            print("y_test.shape", y_test.shape)
    
    pred = model.predict(x_test)
    #print("=====>", pred)
    
    if arguments.lstm:
        #print("y_test shape", y_test.shape)
        pred = pred.reshape(int((arguments.batchSize / arguments.dnnBatchSize) * y_test.shape[1]), y_test.shape[2])
    
    pred = np.argmax(pred,axis=1)
    print("pred (argmax)", pred, pred.shape)

    y_eval = np.argmax(y_test,axis=1)
    print("y_eval (argmax)", y_eval, y_eval.shape)
    
    if not arguments.lstm:    
        score = metrics.accuracy_score(y_eval, pred)
        print("[INFO] Validation score: {}".format(colored(score, 'yellow')))
    
    print("============== [INFO] metrics =====================")
    baseline_results = model.evaluate(
        x_test,
        y_test,
        verbose=1
    )  
    print("===================================================")

    try:
        for name, value in zip(model.metrics_names, baseline_results):
            print(name, ': ', value)
        print()
    except TypeError:
        pass        

    unique, counts = np.unique(y_eval, return_counts=True)
    print("y_eval",dict(zip(unique, counts)))
# 
    unique, counts = np.unique(pred, return_counts=True)
    print("pred",dict(zip(unique, counts)))
# 
#             print("y_test", np.sum(y_test,axis=0), np.sum(y_test,axis=1))

    cf = confusion_matrix(y_eval,pred,labels=np.arange(len(classes)))
    print("[INFO] confusion matrix for file ")
    print(cf)
    print("[INFO] confusion matrix after adding it to total:")
    cf_total += cf
    print(cf_total)

#             cf = np.zeros((5,5))
#             for i,j in zip(y_eval, pred):
#                 cf[i,j] += 1
#             print(cf)
                
# instantiate the parser
parser = argparse.ArgumentParser(description='NETCAP compatible implementation of Network Anomaly Detection with a Deep Neural Network and TensorFlow')

# add commandline flags
parser.add_argument('-read', type=str, help='Regex to find all labeled input CSV file to read from (required)')
parser.add_argument('-model', type=str, help='the path to the model to be loaded')
parser.add_argument('-weights', type=str, default='models/*', help='the path to the checkpoint to be loaded')
parser.add_argument('-drop', type=str, help='optionally drop specified columns, supply multiple with comma')
parser.add_argument('-loss', type=str, default='categorical_crossentropy', help='set function (default: categorical_crossentropy)')
parser.add_argument('-optimizer', type=str, default='adam', help='set optimizer (default: adam)')
parser.add_argument('-resultColumn', type=str, default='Category', help='set name of the column with the prediction')
parser.add_argument('-features', type=int, required=True, help='The amount of columns in the csv')
parser.add_argument('-numCoreLayers', type=int, default=1, help='set number of core layers to use')
parser.add_argument('-dropoutLayer', default=False, help='insert a dropout layer at the end')
parser.add_argument('-coreLayerSize', type=int, default=4, help='size of an DNN core layer')
parser.add_argument('-wrapLayerSize', type=int, default=2, help='size of the first and last DNN layer')
parser.add_argument('-fileBatchSize', type=int, default=16, help='The amount of files to be read in')
parser.add_argument('-lstm', default=False, help='use LSTM layers')
parser.add_argument('-batchSize', type=int, default=256000, help='chunks of records read from CSV')
parser.add_argument('-debug', default=False, help='debug mode on off')
parser.add_argument('-classes', type=str, help='supply one or multiple comma separated class identifiers')
parser.add_argument('-zscoreUnixtime', default=False, help='apply zscore to unixtime column')
parser.add_argument('-encodeColumns', default=False, help='switch between auto encoding or using a fully encoded dataset')
parser.add_argument('-binaryClasses', default=True, help='use binary classses')
parser.add_argument('-relu', default=False, help='use ReLU activation function (default: LeakyReLU)')
parser.add_argument('-encodeCategoricals', default=False, help='encode categorical with one hot strategy')
parser.add_argument('-dnnBatchSize', type=int, default=16, help='set dnn batch size')
parser.add_argument('-socket', type=bool, default=False, help='read data from unix socket')

# parse commandline arguments
arguments = parser.parse_args()

# wtf why is encodeCategoricals always True, I've set default=False x)
print("") # newline to break from netcap status log msg when debugging
print("encodeCategoricals", arguments.encodeCategoricals)
arguments.encodeCategoricals = False
print("encodeCategoricals", arguments.encodeCategoricals)

if not arguments.socket:
    if arguments.read is None:
        print("[INFO] need an input file / multi file regex. use the -read flag")
        exit(1)

if arguments.binaryClasses:
    # TODO: make configurable
    classes = [b'normal', b'infiltration']

if arguments.classes is not None:
    classes = arguments.classes.split(',')
    print("set classes to:", classes)

# ensure correct data type in classes list
# - sockets will receive byte strings
# - csv data will come as strings 
# on the CLI we will always receive strings
newClasses = list()

if arguments.socket:
    # convert all to byte strings
    for c in classes:
        if type(c) == bytes:
            newClasses.append(c)
        else:
            data = c.encode('utf-8')
            newClasses.append(data)
else:
    # convert all to string
    for c in classes:
        if type(c) == str:
            newClasses.append(c)
        else:
            data = c.decode('utf-8')
            newClasses.append(data)

classes = newClasses
print("classes after type update", classes)

classes_length = len(classes)
cf_total = np.zeros((classes_length, classes_length),dtype=np.int)

# get all files
if not arguments.socket:
    files = glob(arguments.read)
    files.sort()

    if len(files) == 0:
        print("[INFO] no files matched")
        exit(1)

print("=================================================")
print("        SCORING v0.4.5")
print("=================================================")
print("Date:", datetime.datetime.now())
start_time = time.time()

if not arguments.binaryClasses:
    print("MULTI-CLASS", "num classes:", len(classes))

# we need to include the dropped time columns for non LSTM DNNs in the specified input shape when creating the model.
num_time_columns = 0
if not arguments.lstm:
    # Connection audit records have two time columns
    num_time_columns = 2

num_dropped = 0
if arguments.drop:
    num_dropped = len(arguments.drop.split(","))

# create models
model = create_dnn(
    # input shape: (num_features - dropped_features) [ - time_columns ]
    arguments.features-num_dropped-num_time_columns, 
    len(classes),
    arguments.loss,
    arguments.optimizer,
    arguments.lstm,
    arguments.numCoreLayers,
    arguments.coreLayerSize,
    arguments.dropoutLayer,
    arguments.batchSize,
    arguments.wrapLayerSize,
    arguments.relu,
    arguments.binaryClasses,
    arguments.dnnBatchSize
)
print("[INFO] created DNN")

# MAIN
try:
    if arguments.socket:
        run_socket()
    else:
        run()
except: # catch *all* exceptions
    e = sys.exc_info()
    # for debugging argument errors
    #print("=====================================")
    #for d in datagrams:
    #    print(d)
    print("=====================================")
    print("[EXCEPTION]", e)
    print("=====================================")
    traceback.print_tb(e[2], None, None)

print("--- %s seconds ---" % (time.time() - start_time))

