---
description: ICS / SCADA threat hunting
---

# Industrial Control Systems

## Protocol Support

Netcap offers audit records for the following protocols seen in industrial control systems:

* Ethernet/IP
* CIP - Common Industrial Protocol
* Modbus / ModbusTCP

The decoders are enabled by default.

## Modbus

```erlang
message Modbus {
    string Timestamp     = 1;
    int32  TransactionID = 2; // Identification of a MODBUS Request/Response transaction
    int32  ProtocolID    = 3; // It is used for intra-system multiplexing
    int32  Length        = 4; // Number of following bytes (includes 1 byte for UnitIdentifier + Modbus data length
    int32  UnitID        = 5; // Identification of a remote slave connected on a serial line or on other buses
    bytes  Payload       = 6;
    bool   Exception     = 7;
    int32  FunctionCode  = 8;

    PacketContext Context = 9;
}
```

## CIP

```erlang
message CIP {
    string          Timestamp        = 1;
    bool            Response         = 2; // false if request, true if response
    int32           ServiceID        = 3; // The service specified for the request
    uint32          ClassID          = 4; // request only
    uint32          InstanceID       = 5; // request only
    int32           Status           = 6; // Response only
    repeated uint32 AdditionalStatus = 7; // Response only
    bytes           Data             = 8; // Command data for request, reply data for response
    PacketContext   Context          = 9;
}
```

## ENIP

```erlang
message ENIP {
    string                  Timestamp        = 1;
    uint32                  Command          = 2; 
    uint32                  Length           = 3;
    uint32                  SessionHandle    = 4;
    uint32                  Status           = 5;
    bytes                   SenderContext    = 6;
    uint32                  Options          = 7;
    ENIPCommandSpecificData CommandSpecific  = 8;
    PacketContext           Context          = 9;
}
```

