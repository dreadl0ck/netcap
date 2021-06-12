#!/usr/bin/python3

# Run LSTM, locally:
# $ ./score.py -read data/TCP_labeled.csv -dimensionality 22 -class_amount 2 -sample 0.5 -lstm true
# on server, 2019 SWaT dataset:
# $ ./score.py -read */TCP_labeled.csv -dimensionality 22 -class_amount 2 -sample 0.5 -lstm true
# on server, 2015 SWaT dataset:
# $ ./score.py -read */*_labeled.csv -dimensionality XX -class_amount 2 -sample 0.5 -lstm true

import argparse
import pandas as pd
import traceback
import time
import datetime

import numpy as np
from tfUtils import * 
from glob import glob

from sklearn.metrics import confusion_matrix
from sklearn import metrics

from termcolor import colored
from keras.models import load_model

# cf_total is for summing up all of the confusion matrices from all of the separate files
cf_total = None

# configurable via argument
# hardcoded these are the labeltypes that can be found in the dataset
classes = ["normal", "Single Stage Single Point", "Single Stage Multi Point", "Multi Stage Single Point", "Multi Stage Multi Point"]
#classes = ["Normal", "Attack"]

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

def eval_dnn(df):
    global cf_total
    global model

    x_test, y_test = to_xy(df, arguments.resultColumn, classes, arguments.debug, arguments.binaryClasses)
    #print("x_test", x_test, "shape", x_test.shape)
    
    #np.set_printoptions(threshold=sys.maxsize)
    #print("y_test", y_test, "shape", y_test.shape)
    #np.set_printoptions(threshold=10)

    print(colored("[INFO] measuring accuracy...", 'yellow'))
    print("x_test.shape:", x_test.shape)

    y_eval = np.argmax(y_test,axis=1)
    print("y_eval", y_eval, y_eval.shape)

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
    #print("pred 1", pred, pred.shape)

    if arguments.lstm:
        #print("y_test shape", y_test.shape)
        pred = pred.reshape(int((arguments.batchSize / arguments.dnnBatchSize) * y_test.shape[1]), y_test.shape[2])
        #print("pred 2", pred, pred.shape)

    pred = np.argmax(pred,axis=1)
    #print("pred 3 (argmax)", pred, pred.shape)

    if not arguments.lstm:
        score = metrics.accuracy_score(y_eval, pred)
        print("[INFO] Validation score: {}".format(colored(score, 'yellow')))
    
    print(colored("[INFO] metrics:", 'yellow'))
    baseline_results = model.evaluate(
        x_test,
        y_test,
        verbose=0
    )

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
parser.add_argument('-read', required=True, type=str, help='Regex to find all labeled input CSV file to read from (required)')
parser.add_argument('-model', type=str, help='the path to the model to be loaded')
parser.add_argument('-weights', type=str, default='checkpoints/*', help='the path to the checkpoint to be loaded')
parser.add_argument('-drop', type=str, help='optionally drop specified columns, supply multiple with comma')
parser.add_argument('-loss', type=str, default='categorical_crossentropy', help='set function (default: categorical_crossentropy)')
parser.add_argument('-optimizer', type=str, default='adam', help='set optimizer (default: adam)')
parser.add_argument('-resultColumn', type=str, default='classification', help='set name of the column with the prediction')
parser.add_argument('-features', type=int, required=True, help='The amount of columns in the csv')
parser.add_argument('-numCoreLayers', type=int, default=1, help='set number of core layers to use')
parser.add_argument('-dropoutLayer', default=False, help='insert a dropout layer at the end')
parser.add_argument('-coreLayerSize', type=int, default=4, help='size of an DNN core layer')
parser.add_argument('-wrapLayerSize', type=int, default=2, help='size of the first and last DNN layer')
parser.add_argument('-fileBatchSize', type=int, default=16, help='The amount of files to be read in')
parser.add_argument('-lstm', default=False, help='use a LSTM network')
parser.add_argument('-batchSize', type=int, default=256000, help='chunks of records read from CSV')
parser.add_argument('-debug', default=False, help='debug mode on off')
parser.add_argument('-classes', type=str, help='supply one or multiple comma separated class identifiers')
parser.add_argument('-zscoreUnixtime', default=False, help='apply zscore to unixtime column')
parser.add_argument('-encodeColumns', default=False, help='switch between auto encoding or using a fully encoded dataset')
parser.add_argument('-binaryClasses', default=True, help='use binary classses')
parser.add_argument('-relu', default=False, help='use ReLU activation function (default: LeakyReLU)')
parser.add_argument('-encodeCategoricals', default=True, help='encode categorical with one hot strategy')
parser.add_argument('-dnnBatchSize', type=int, default=16, help='set dnn batch size')

# parse commandline arguments
arguments = parser.parse_args()
if arguments.read is None:
    print("[INFO] need an input file / multi file regex. use the -read flag")
    exit(1)

if arguments.binaryClasses:
    classes = ["normal", "attack"]

if arguments.classes is not None:
    classes = arguments.classes.split(',')
    print("set classes to:", classes)

classes_length = len(classes)
cf_total = np.zeros((classes_length, classes_length),dtype=np.int)

# get all files
files = glob(arguments.read)
files.sort()

if len(files) == 0:
    print("[INFO] no files matched")
    exit(1)

print("=================================================")
print("        SCORING v0.4.5 (binary)")
print("=================================================")
print("Date:", datetime.datetime.now())
start_time = time.time()

if not arguments.binaryClasses:
    print("MULTI-CLASS", "num classes:", len(classes))

# create models
model = create_dnn(
    arguments.features,
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
    run()
except: # catch *all* exceptions
    e = sys.exc_info()
    print("[EXCEPTION]", e)
    traceback.print_tb(e[2], None, None)

print("--- %s seconds ---" % (time.time() - start_time))

