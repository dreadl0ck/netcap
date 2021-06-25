#!/usr/bin/python3

# Run LSTM, locally:
# $ ./train.py -read data/TCP_labeled.csv -dimensionality 22 -class_amount 2 -sample 0.5 -lstm true
# on server, 2019 SWaT dataset:
# $ ./train.py -read */TCP_labeled.csv -dimensionality 22 -class_amount 2 -sample 0.5 -lstm true
# on server, 2015 SWaT dataset:
# $ ./train.py -read */*_labeled.csv -dimensionality XX -class_amount 2 -sample 0.5 -lstm true

import argparse
import pandas as pd
import time
import traceback
import datetime

from utils import * 
from glob import glob
import os
from os import path
from sklearn.model_selection import train_test_split

from termcolor import colored
import sys
import socket
import logging

from sklearn.metrics import confusion_matrix
from sklearn import metrics
from keras.callbacks import EarlyStopping

# cf_total is for summing up all of the confusion matrices from all of the separate files
cf_total = None

# Note: when the data is split over multiple files,
# and the data is fed in batches,
# we need to implement early stopping ourselves.
early_stopping = EarlyStopping(
     monitor='val_loss', 
     min_delta=1e-3, 
     patience=20, 
     verbose=1, 
     mode='auto'
)
min_delta = 1e-3
patience = 3

# caution: when streaming data over unix socket 
# can be overwritten via cmdline flags
# Default uses two classes: binary classification
classes = [b'normal', b'infiltration']

def train_dnn(df, i, epoch, batch=0):

    if arguments.debug:
        print("[INFO] breaking into predictors and prediction...")
    
    # Break into X (predictors) & y (prediction)
    x, y = to_xy(df, arguments.resultColumn, classes, arguments.debug, arguments.binaryClasses)

    if arguments.debug:
        print("[INFO] creating train/test split:", arguments.testSize)

    # Create a test/train split.
    # by default, 25% of data is used for testing
    # it can be configured using the test_size commandline flag
    x_train, x_test, y_train, y_test = train_test_split(
        x,
        y,
        test_size=arguments.testSize,
        #random_state=42, # TODO make
        shuffle=arguments.shuffle
    )

    if arguments.debug:
        print("--------SHAPES--------")
        print("x_train.shape", x_train.shape)
        print("x_test.shape", x_test.shape)
        print("y_train.shape", y_train.shape)
        print("y_test.shape", y_test.shape)

    if arguments.lstm:

        if arguments.debug:
            print("[INFO] using LSTM layers")
        
        x_train = x_train.reshape(int((arguments.batchSize / arguments.dnnBatchSize) * (1.0 - arguments.testSize)), arguments.dnnBatchSize, x.shape[1])
        y_train = y_train.reshape(int((arguments.batchSize / arguments.dnnBatchSize) * (1.0 - arguments.testSize)), arguments.dnnBatchSize, y.shape[1])

        x_test = x_test.reshape(int((arguments.batchSize / arguments.dnnBatchSize) * arguments.testSize), arguments.dnnBatchSize, x.shape[1])
        y_test = y_test.reshape(int((arguments.batchSize / arguments.dnnBatchSize) * arguments.testSize), arguments.dnnBatchSize, y.shape[1])
        
        if arguments.debug:
            print("--------RESHAPED--------")
            print("x_train.shape", x_train.shape)
            print("x_test.shape", x_test.shape)
            print("y_train.shape", y_train.shape)
            print("y_test.shape", y_test.shape)

    # TODO: using a timestep size of 1 and feeding numRows batches should also work
    #x_train = np.reshape(x_train, (x_train.shape[0], 1, x_train.shape[1]))
    #x_test = np.reshape(x_test, (x_test.shape[0], 1, x_test.shape[1]))

    if arguments.debug:
        model.summary()
    
    # sparse shape fix
    # if arguments.loss == "sparse_categorical_crossentropy":
        
    #     x_train = x_train.reshape((-1, 1, y.shape[1]))
    #     x_test = x_test.reshape((-1, 1, y.shape[1]))

    #     y_train = y_train.reshape((-1, 1, y.shape[1]))
    #     y_test = y_test.reshape((-1, 1, y.shape[1]))

    #     if arguments.debug:
    #         print("-------- SPARSE RESHAPED --------")
    #         print("x_train.shape", x_train.shape)
    #         print("x_test.shape", x_test.shape)
    #         print("y_train.shape", y_train.shape)
    #         print("y_test.shape", y_test.shape)

    if arguments.debug:
        print("[INFO] fitting model. xtrain.shape:", x_train.shape, "y_train.shape:", y_train.shape)
    
    history = model.fit(
        x_train,
        y_train,
        validation_data=(x_test, y_test),
        callbacks=[early_stopping],
        verbose=1,
        epochs=arguments.epochs,
        # The batch size defines the number of samples that will be propagated through the network.
        # The smaller the batch the less accurate the estimate of the gradient will be.
        # let tensorflow set this value for us
        batch_size=2048
    )

    # history = model.train_on_batch(
    #     x=x_train,
    #     y=y_train,
    #     return_dict=True,
    #     #reset_metrics=False,
    # )
    # #print("history after training on batch", history)
    # history = model.test_on_batch(
    #     x=x_test,
    #     y=y_test,
    #     return_dict=True,
    #     #reset_metrics=False,
    # )
    # #print(history)

#    print('---------intermediate testing--------------')
#    
#    pred = model.predict(x_test)
#    pred = np.argmax(pred,axis=1)
#    y_eval = np.argmax(y_test,axis=1)
#    unique, counts = np.unique(y_eval, return_counts=True)
#    print("y_eval",dict(zip(unique, counts)))
# 
#    unique, counts = np.unique(pred, return_counts=True)
#    print("pred",dict(zip(unique, counts)))
#
#    cf = confusion_matrix(y_eval,pred,labels=np.arange(len(labeltypes)))
#    print("[info] confusion matrix for file ")
#    print(cf)
#    print('-----------------------------')

    # TODO: make saving model or checkpoint after every batch configurable
    # if arguments.saveModel:
    #     save_model(i, str(epoch), batch=batch)
    # else:
    #     save_weights(i, str(epoch), batch=batch)

    return history

# epoch.zfill(3) is used to pad the epoch num with zeros
# so the alphanumeric sorting preserves the correct file order: 01, 02, ..., 09, 10
def save_model(i, epoch, batch=0):
    if not path.exists("models"):
        os.mkdir("models")

    if arguments.lstm:
        if arguments.debug:
            print("[INFO] saving model to models/lstm-epoch-{}-files-{}-{}-batch-{}-{}.h5".format(epoch.zfill(3), i, i+arguments.fileBatchSize, batch, batch+arguments.batchSize))
        model.save('./models/lstm-epoch-{}-files-{}-{}-batch-{}-{}.h5'.format(epoch.zfill(3), i, i+arguments.fileBatchSize, batch, batch+arguments.batchSize))        
    else:
        if arguments.debug:
            print("[INFO] saving model to models/dnn-epoch-{}-files-{}-{}.h5".format(epoch.zfill(3), i, i+arguments.fileBatchSize))
        model.save('./models/dnn-epoch-{}-files-{}-{}.h5'.format(epoch.zfill(3), i, i+arguments.fileBatchSize))        

# epoch.zfill(3) is used to pad the epoch num with zeros
# so the alphanumeric sorting preserves the correct file order: 01, 02, ..., 09, 10
def save_weights(i, epoch, batch=0):
    if not path.exists("checkpoints"):
        os.mkdir("checkpoints")

    if arguments.lstm:
        print("[INFO] saving weights to checkpoints/lstm-epoch-{}-files-{}-{}-batch-{}-{}".format(epoch.zfill(3), i, i+arguments.fileBatchSize, batch, batch+arguments.batchSize))
        model.save_weights('./checkpoints/lstm-epoch-{}-files-{}-{}-batch-{}-{}'.format(epoch.zfill(3), i, i+arguments.fileBatchSize, batch, batch+arguments.batchSize))
    else:
        print("[INFO] saving weights to checkpoints/dnn-epoch-{}-files-{}-{}".format(epoch.zfill(3), i, i+arguments.fileBatchSize))
        model.save_weights('./checkpoints/dnn-epoch-{}-files-{}-{}'.format(epoch.zfill(3), i, i+arguments.fileBatchSize))

def readCSV(f):
    print("[INFO] reading file", f)
    return pd.read_csv(f, delimiter=',', engine='c', encoding="utf-8-sig")

def run():
    leftover = None
    global patience
    global min_delta

    for epoch in range(arguments.epochs):
        history = None
        leftover = None

        print(colored("[INFO] epoch {}/{}".format(epoch, arguments.epochs), 'yellow'))
        for i in range(0, len(files), arguments.fileBatchSize):

            print(colored("[INFO] loading file {}-{}/{} on epoch {}/{}".format(i+1, i+arguments.fileBatchSize, len(files), epoch, arguments.epochs), 'yellow'))
            df_from_each_file = [readCSV(f) for f in files[i:(i+arguments.fileBatchSize)]]

            # ValueError: The truth value of a DataFrame is ambiguous. Use a.empty, a.bool(), a.item(), a.any() or a.all().
            if leftover is not None:
                df_from_each_file.insert(0, leftover)

            print("[INFO] concatenate the files")
            df = pd.concat(df_from_each_file, ignore_index=True)

            # TODO move back into process_dataset?
            print("[INFO] process dataset, shape:", df.shape)
            if arguments.sample != None:
                if arguments.sample > 1.0:
                    print("invalid sample rate")
                    exit(1)

                if arguments.sample <= 0:
                    print("invalid sample rate")
                    exit(1)

            if arguments.sample < 1.0:
                print("[INFO] sampling", arguments.sample)
                df = df.sample(frac=arguments.sample, replace=False)

            if arguments.drop is not None:
                for col in arguments.drop.split(","):
                    drop_col(col, df)

            if not arguments.lstm:
                print("[INFO] dropping all time related columns...")
                # TODO: make field name configurable
                drop_col('Timestamp', df)
                drop_col('TimestampFirst', df)
                drop_col('TimestampLast', df)

            print("[INFO] columns:", df.columns)
            if arguments.debug:
                print("[INFO] analyze dataset:", df.shape)
                analyze(df)

            if arguments.zscoreUnixtime:
               # TODO: make field name configurable
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

            for batch_size in range(0, df.shape[0], arguments.batchSize):

                dfCopy = df[batch_size:batch_size+arguments.batchSize]

                # skip leftover that does not reach batch size
                if len(dfCopy.index) != arguments.batchSize:
                    leftover = dfCopy
                    continue

                print("[INFO] processing batch {}-{}/{}".format(batch_size, batch_size+arguments.batchSize, df.shape[0]))                    
                history = train_dnn(dfCopy, i, epoch, batch=batch_size)
                leftover = None
        
        # save model or checkpoint after every epoch
        if arguments.saveModel:
            save_model(0, str(epoch), batch=0)
        else:
            save_weights(0, str(epoch), batch=0)

        if history is not None:
            currentLoss = history['loss']
            #currentLoss = lossValues[-1]
            #print("============== lossValues:", lossValues)

            print(colored("[LOSS] " + str(currentLoss),'yellow') + " ==> EPOCH", epoch , "/", arguments.epochs)

            # implement early stopping to avoid overfitting
            # start checking the val_loss against the threshold after patience epochs
            if epoch >= patience:
                #print("[CHECKING EARLY STOP]: currentLoss < min_delta ? =>", currentLoss, " < ", min_delta)
                if currentLoss < min_delta:
                    print("[STOPPING EARLY]: currentLoss < min_delta =>", currentLoss, " < ", min_delta)
                    print("EPOCH", epoch)
                    exit(0)

def eval_dnn(df, sizeTrain):
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

    csv = ""
    try:
        for name, value in zip(model.metrics_names, baseline_results):
            print(name, ': ', value)
            csv += str(value) + ","
        print()
    except TypeError:
        pass        

    unique, counts = np.unique(y_eval, return_counts=True)
    print("y_eval",dict(zip(unique, counts)))

    csv += str(dict(zip(unique, counts))) + ","
# 
    unique, counts = np.unique(pred, return_counts=True)
    print("pred",dict(zip(unique, counts)))

    csv += str(dict(zip(unique, counts))) + ","

    # metrics values in order:
    # loss :  0.010494242422282696
    # tp :  114633.0
    # fp :  0.0
    # tn :  114633.0
    # fn :  0.0
    # accuracy :  1.0
    # precision :  1.0
    # recall :  1.0
    # auc :  1.0

    precision = baseline_results[6]
    recall = baseline_results[7]

    # The traditional F-measure or balanced F-score (F1 score) is the harmonic mean of precision and recall: 
    f1_score = 2 * ((precision*recall)/(precision+recall))

    print("[INFO] F1 score:", f1_score)

    # TODO: append to logfile
    # Epochs,File,Loss,True Positives,False Positives,True Negatives,False Negatives,Accuracy,Precision,Recall,AUC,Y_EVAL,Y_PRED,Time,SizeTrain,SizeEval,TestSize,F1
    print("=== CSV " + str(arguments.epochs) + "," + arguments.read + "," + csv + str(time.time() - start_time) + "," + str(sizeTrain) + "," + str(df.shape[0]) + "," + str(arguments.testSize) + "," + str(f1_score))
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

def run_in_memory(df, df_score):
    leftover = None
    global patience
    global min_delta
        
    history = None
    leftover = None

    for epoch in range(arguments.epochs):
        numEpoch = epoch+1   

        for batch_size in range(0, df.shape[0], arguments.batchSize):

            dfCopy = df[batch_size:batch_size+arguments.batchSize]

            # skip leftover that does not reach batch size
            if len(dfCopy.index) != arguments.batchSize:
                leftover = dfCopy
                continue

            if arguments.debug:
                print("[INFO] processing batch {}-{}/{}".format(batch_size, batch_size+arguments.batchSize, df.shape[0]))                    
            
            history = train_dnn(dfCopy, 0, numEpoch, batch=batch_size)
            #history["epoch"] = numEpoch
            leftover = None
    
            if history is not None:
                #currentLoss = history['loss']
                lossValues = history.history['val_loss']
                currentLoss = lossValues[-1]
                #print("============== lossValues:", lossValues)

                #print(colored("[EPOCH] " + str(numEpoch) + " / " + str(arguments.epochs),'red') + " " + colored("[LOSS] " + str(currentLoss),'yellow'))

                # implement early stopping to avoid overfitting
                # start checking the val_loss against the threshold after patience epochs
                if epoch >= patience:
                    #print("[CHECKING EARLY STOP]: currentLoss < min_delta ? =>", currentLoss, " < ", min_delta)
                    if currentLoss < min_delta:

                        if arguments.saveModel:
                            save_model(0, str(numEpoch), batch=batch_size)
                        else:
                            save_weights(0, str(numEpoch), batch=batch_size)
                        print("[STOPPING EARLY]: currentLoss < min_delta =>", currentLoss, " < ", min_delta)
                        print("EPOCH", numEpoch)

                        plot_metrics(history, "train-metrics")

                        # TODO 
                        if arguments.score:
                            eval_dnn(df_score, df.shape[0])
                        
                        exit(0)
        
        print(colored("[EPOCH] " + str(numEpoch) + " / " + str(arguments.epochs),'red') + " " + colored("[LOSS] " + str(currentLoss),'yellow'))

        # save model or checkpoint after every epoch
        if arguments.saveModel:
            save_model(0, str(numEpoch), batch=0)
        else:
            save_weights(0, str(numEpoch), batch=0)
    
    print("all epochs done")
    plot_metrics(history, "train-metrics")
    
    # TODO 
    if arguments.score:
        eval_dnn(df_score, df.shape[0])

def run_in_memory_v2(df, df_score):
    global patience
    global min_delta
    
    history = train_dnn(df, 0, 0, batch=arguments.batchSize)
    if history is not None:
        #currentLoss = history['loss']
        lossValues = history.history['val_loss']
        currentLoss = lossValues[-1]
        #print("============== lossValues:", lossValues)

        #print(colored("[EPOCH] " + str(numEpoch) + " / " + str(arguments.epochs),'red') + " " + colored("[LOSS] " + str(currentLoss),'yellow'))

        # TODO: implement via callback again
        # implement early stopping to avoid overfitting
        # start checking the val_loss against the threshold after patience epochs
        # if epoch >= patience:
        #     #print("[CHECKING EARLY STOP]: currentLoss < min_delta ? =>", currentLoss, " < ", min_delta)
        #     if currentLoss < min_delta:

        #         if arguments.saveModel:
        #             save_model(0, str(arguments.epochs), batch=batch_size)
        #         else:
        #             save_weights(0, str(arguments.epochs), batch=batch_size)
        #         print("[STOPPING EARLY]: currentLoss < min_delta =>", currentLoss, " < ", min_delta)
        #         print("EPOCH", arguments.epochs)

        #         plot_metrics(history, "train-metrics")

        #         # TODO 
        #         if arguments.score:
        #             eval_dnn(df_score, df.shape[0])
                
        #         exit(0)
    
    # save model or checkpoint
    if arguments.saveModel:
        save_model(0, str(arguments.epochs), batch=0)
    else:
        save_weights(0, str(arguments.epochs), batch=0)
    
    print("all epochs done")
    plot_metrics(history, "train-metrics")
    
    # TODO 
    if arguments.score:
        eval_dnn(df_score, df.shape[0])

buf_size = 512
stop_count = 0
num_datagrams = 0

datagrams = list()

def create_unix_socket(name):

    global datagrams
    global epoch
    socket_name = "/tmp/" + name + ".sock"

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

                process(df)
                
                #print(df)

                # reset datagrams
                datagrams = list()

            for data in datagram.split(b'\n'):
                if data != b'':
                    arr = data.split(b',')
                    if len(arr) != 19:
                        # TODO: make configurable for troubleshooting
                        #print(arr, len(arr))

                        # TODO: make configurable
                        # increment epoch when receiving the CSV header again 
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

        #print("history:", history)

        # get current loss
        currentLoss = history['loss']
        #currentLoss = lossValues[-1]
        #print("============== lossValues:", lossValues)

        print(colored("[EPOCH] " + epoch + " / " +  arguments.epochs ,'red') + " " + colored("[LOSS] " + str(currentLoss),'yellow'))

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

# instantiate the parser
parser = argparse.ArgumentParser(description='NETCAP compatible implementation of Network Anomaly Detection with a Deep Neural Network and TensorFlow')

# add commandline flags
parser.add_argument('-read', type=str, help='Regex to find all labeled input CSV file to read from (required)')
parser.add_argument('-drop', type=str, help='optionally drop specified columns, supply multiple with comma')
parser.add_argument('-sample', type=float, default=1.0, help='optionally sample only a fraction of records')
parser.add_argument('-dropna', default=False, action='store_true', help='drop rows with missing values')
parser.add_argument('-testSize', type=float, default=0.25, help='specify size of the test data in percent (default: 0.25)')
parser.add_argument('-loss', type=str, default='categorical_crossentropy', help='set function (default: categorical_crossentropy)')
parser.add_argument('-optimizer', type=str, default='adam', help='set optimizer (default: adam)')
parser.add_argument('-resultColumn', type=str, default='Category', help='set name of the column with the prediction')
parser.add_argument('-features', type=int, required=True, help='The amount of columns in the csv (dimensionality)')
#parser.add_argument('-class_amount', type=int, default=2, help='The amount of classes e.g. normal, attack1, attack3 is 3')
parser.add_argument('-fileBatchSize', type=int, default=50, help='The amount of files to be read in')
parser.add_argument('-epochs', type=int, default=2500, help='The amount of epochs. (default: 1)')
parser.add_argument('-numCoreLayers', type=int, default=1, help='set number of core layers to use')
parser.add_argument('-shuffle', default=False, help='shuffle data before feeding it to the DNN')
parser.add_argument('-dropoutLayer', default=False, help='insert a dropout layer at the end')
parser.add_argument('-coreLayerSize', type=int, default=4, help='size of an DNN core layer')
parser.add_argument('-wrapLayerSize', type=int, default=2, help='size of the first and last DNN layer')
parser.add_argument('-lstm', default=False, help='use a LSTM network')
parser.add_argument('-batchSize', type=int, default=256000, help='chunks of records read from CSV')
parser.add_argument('-debug', default=False, help='debug mode on off')
parser.add_argument('-zscoreUnixtime', default=False, help='apply zscore to unixtime column')
parser.add_argument('-encodeColumns', default=False, help='switch between auto encoding or using a fully encoded dataset')
parser.add_argument('-classes', type=str, help='supply one or multiple comma separated class identifiers')
parser.add_argument('-saveModel', default=True, help='save model (if false, only the weights will be saved)')
parser.add_argument('-binaryClasses', default=True, help='use binary classses')
parser.add_argument('-relu', default=False, help='use ReLU activation function (default: LeakyReLU)')
parser.add_argument('-encodeCategoricals', type=bool, default=False, help='encode categorical with one hot strategy')
parser.add_argument('-dnnBatchSize', type=int, default=16, help='set dnn batch size')
parser.add_argument('-socket', type=bool, default=False, help='read data from unix socket')
parser.add_argument('-mem', type=bool, default=False, help='hold entire data in memory to avoid re-reading it')
parser.add_argument('-score', type=bool, default=False, help='run scoring on the configured share of the input data')

# parse commandline arguments
arguments = parser.parse_args()

# wtf why is encodeCategoricals always True, I've set default=False x)
#print("") # newline to break from netcap status log msg when debugging
#print("encodeCategoricals", arguments.encodeCategoricals)
#arguments.encodeCategoricals = False
#print("encodeCategoricals", arguments.encodeCategoricals)

if not arguments.socket:
    if arguments.read is None:
        print("[INFO] need an input file / multi file regex. use the -read flag")
        exit(1)

if arguments.binaryClasses:
    # TODO: make configurable
    classes = [b'normal', b'infiltration']
    print("classes", classes)

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

print("=================================================")
print("        TRAINING v0.4.5")
print("=================================================")
print("Date:", datetime.datetime.now())
start_time = time.time()

# get all files
if not arguments.socket:
    files = glob(arguments.read)
    files.sort()
    if len(files) == 0:
        print("[INFO] no files matched")
        exit(1)

if not arguments.binaryClasses:
    print("MULTI-CLASS", "num classes:", len(classes), classes)

# we need to include the dropped time columns for non LSTM DNNs in the specified input shape when creating the model.
num_time_columns = 0
if not arguments.lstm:
    # Connection audit records have two time columns
    num_time_columns = 2

num_dropped = 0
if arguments.drop:
    num_dropped = len(arguments.drop.split(","))

classes_length = len(classes)
cf_total = np.zeros((classes_length, classes_length),dtype=np.int)

print("[INFO] input shape", arguments.features-num_dropped-num_time_columns)

initial_bias = None
df_score = {}
df = {}

# in memory assumes that the entire dataset fits into memory.
if arguments.mem:

    # read everything into a single dataframe
    df_from_each_file = [readCSV(f) for f in files]

    print("[INFO] concatenate the files")
    df = pd.concat(df_from_each_file, ignore_index=True)

    print("[INFO] process df, shape:", df.shape)
    if arguments.sample != None:
        if arguments.sample > 1.0:
            print("invalid sample rate")
            exit(1)

        if arguments.sample <= 0:
            print("invalid sample rate")
            exit(1)

    if arguments.sample < 1.0:
        print("[INFO] sampling", arguments.sample)
        df = df.sample(frac=arguments.sample, replace=False)

    if arguments.drop is not None:
        for col in arguments.drop.split(","):
            drop_col(col, df)

    if not arguments.lstm:
        print("[INFO] dropping all time related columns...")
        # TODO: make field name configurable
        drop_col('Timestamp', df)
        drop_col('TimestampFirst', df)
        drop_col('TimestampLast', df)

    print("[INFO] columns:", df.columns)
    if arguments.debug:
        print("[INFO] analyze dataset:", df.shape)
        analyze(df)

    if arguments.zscoreUnixtime:
        # TODO: make field name configurable
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

    if arguments.score:
        
        # Create a test/train split.
        # by default, 25% of data is used for testing
        # it can be configured using the test_size commandline flag
        df, df_score = train_test_split(
            df,
            test_size=arguments.testSize,
            #random_state=42, # TODO make configurable
            shuffle=arguments.shuffle
        )
        print("df_train:", df.shape)
        print("df_score:", df_score.shape, "test_size", arguments.testSize)

    ############# expand Y values for training split ########################

    # convert to two dimensional arrays with Y values
    y_values = expand_y_values(df, arguments.resultColumn, classes, arguments.debug, arguments.binaryClasses)
            
    # create array with 0 for normal and 1 for attack labels   
    y = []
    for arr in y_values:
        if arr[0] == 1:
            y.append(0)
        else:
            y.append(1)

    # calculate negative and positive ratio
    neg, pos = np.bincount(y)
    total = neg + pos
    print('Examples:\n    Total: {}\n    Positive: {} ({:.2f}% of total)\n'.format(
        total, pos, 100 * pos / total))

    # calculate initial bias to reduce number of epochs needed
    # This way the model doesn't need to spend the first few epochs just learning that positive examples are unlikely. 
    initial_bias = np.log([pos/neg])
    print("initial_bias", initial_bias)

    ###########################################

# create network model
model = create_dnn(
    # input shape: (num_features - dropped_features) [ - time_columns ]
    (arguments.features-num_dropped)-num_time_columns, 
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
    arguments.dnnBatchSize,
    initial_bias
)
print("[INFO] created DNN")

# MAIN
try:
    if arguments.socket:
        run_socket()
    elif arguments.mem:
        run_in_memory_v2(df, df_score)
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

source = ""
if arguments.socket:
    source = "UNIX socket"
else:
    source = arguments.read

print("--- %s seconds --- source: %s" % (time.time() - start_time, source))
