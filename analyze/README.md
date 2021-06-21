# ANALYZE

Run manually:

Train model:

    python3 ../analyze/dnn/train.py -mem=True -features 18 -batchSize=24000 -read infiltration_train/Connection.csv -drop=SrcIP,DstIP,SrcMAC,DstMAC,SrcPort  

Eval:

    python3 ../analyze/dnn/score.py -mem=True -features 18 -batchSize=24000 -read infiltration_eval/Connection.csv -drop=SrcIP,DstIP,SrcMAC,DstMAC,SrcPort  