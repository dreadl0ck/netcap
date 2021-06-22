# ANALYZE

Run manually:

Train model:

    python3 ../analyze/dnn/train.py -mem=True -features 18 -batchSize=24000 -read infiltration_train/Connection.csv -drop=SrcIP,DstIP,SrcMAC,DstMAC,SrcPort  

Eval:

    python3 ../analyze/dnn/score.py -mem=True -features 18 -batchSize=24000 -read infiltration_eval/Connection.csv -drop=SrcIP,DstIP,SrcMAC,DstMAC,SrcPort  

Process entire data in memory and run scoring:

    python3 $HOME/go/src/github.com/dreadl0ck/netcap/analyze/dnn/train.py -features 18 -batchSize=24000 -read Thursday-01-03-2018.pcapng.net/Connection.csv -score=True -mem=True -epochs 2000