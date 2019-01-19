# Notes on decoding protobuf data

Protobuf:

    message ProtocolBuffer {
        repeated string  Types   = 1;
        repeated bytes   Fields  = 2;
    }

Go:
 
    type ProtocolBuffer struct {
        []string Types
        [][]byte Fields
    }

Example:

    message Test {
        string Name        = 1;
        string Stuff       = 2;
        int32  Number      = 3;
        bytes  Data        = 4;
        string Version     = 5;
    }

Debug with Go:

    0: t=  1 bytes [6] 41 20 6e 61 6d 65
    8: t=  2 bytes [10] 73 6f 6d .. 75 66 66
    20: t=  3 varint 42
    22: t=  4 bytes [3] 01 02 03
    27: t=  5 bytes [5] 30 2e 31 2e 31


Protoc:

    $ protoc --decode_raw < test.bin
    1: "A name"
    2: "some stuff"
    3: 42
    4: "\001\002\003"
    5: "0.1.1"