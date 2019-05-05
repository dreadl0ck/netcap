---
description: Implementing new audit records and features
---

# Extension

To add support for a new protocol or custom abstraction the following steps need to be performed. 

First, a type definition of the new audit record type must be added to the AuditRecord protocol buffers definitions, as well as a **Type enumeration** following the naming convention with the **NC prefix**. 

After recompiling the protocol buffers, a file for the new encoder named after the protocol must be created in the encoder package. The new file must contain a variable created with **CreateLayerEncoder** or **CreateCustomEncoder** depending on the desired encoder type. 

Depending on the choice of the encoder type, the new variable must be added to the customEncoderSlice in **encoder/customEncoder.go** or layerEncoderSlice in **encoder/layerEncoder.go**. 

Next, the interface for conversion to CSV and JSON and exporting metrics must be implemented in the types package, by creating a new file with the protocol name and implementing the **CSVHeader\(\) \[\]string, CSVRecord\(\) \[\]string** and **NetcapTimestamp\(\) string** functions of the types.AuditRecord interface. 

If the new protocol contains sub-structures, functions to convert them to strings need to be implemented as well. 

Finally, the **InitRecord\(typ types.Type\) \(record proto.Message\)** function in netcap.go needs to be updated, to initialize the structure for the new type.

