"""
read-protobuf

Source: https://github.com/mlshapiro/read-protobuf

modified for NETCAP project by github.com/dreadl0ck

Attributes:
    DEFAULTS (dict): Default inputs
"""

import pandas as pd

DEFAULTS = {
    'flatten': True,
    'prefix_nested': True
}


class ProtobufReader(object):
    """ ProtobufReader class to handle interpretation"""

    def __init__(self, flatten=DEFAULTS['flatten'],
                       prefix_nested=DEFAULTS['prefix_nested']):

        self.flatten = flatten
        self.prefix_nested = prefix_nested

    def to_array(self, Message, field=None):
        """Convert an arbitrary message to an array

        Args:
            Message (TYPE): Description
            field (string, optional): field within message to convert to array

        Returns:
            TYPE: Description
        """
        if field:
            array = [self.interpret_message(m) for m in getattr(Message, field)]
        else:
            array = [self.interpret_message(Message)]

        return array

    def interpret_message(self, Message):
        """Interpret a message into a dict or array

        Args:
            Message (TYPE): Description

        Returns:
            dict | list: protobuf message interpreted into a list or dict
        """

        data = {}  # default to dict
        for field in Message.ListFields():

            # repeated nested message
            if field[0].type == field[0].TYPE_MESSAGE and field[0].label == field[0].LABEL_REPEATED:

                # is this the only field in the pb? if so, look at flatten
                if len(Message.ListFields()) == 1 and self.flatten:
                    data = self.to_array(Message, field[0].name)

                # if there are multiple repeated messages in object, set as keys
                else:
                    data[field[0].name] = self.to_array(Message, field[0].name)

            # nested message
            elif field[0].type == field[0].TYPE_MESSAGE:
                if self.flatten:
                    nested_dict = self.interpret_message(field[1])
                    for key in nested_dict:
                        if key in data or self.prefix_nested:
                            data['{}.{}'.format(field[0].name, key)] = nested_dict[key]
                        else:
                            data[key] = nested_dict[key]
                else:
                    data[field[0].name] = self.interpret_message(field[1])

            # repeated scalar
            elif field[0].label == field[0].LABEL_REPEATED:
                data[field[0].name] = list(field[1])

            # scalar
            else:
                data[field[0].name] = field[1]

        return data


def read_protobuf(pb, MessageType, flatten=DEFAULTS['flatten'],
                               prefix_nested=DEFAULTS['prefix_nested'],
                               index=0,
                               dataframe=True):

    """Summary

    Args:
        pb (string | bytes |list): file path to pb file(s) or bytes from pb file(s). Multiple entries allowed in list.
        MessageType (google.protobuf.message.Message): Message class of pb message
        flatten (bool, optional): flatten all nested objects into a 2-d dataframe. This will also collapse  repeated message containers
        prefix_nested (bool, optional): prefix all flattened objects with parent keys


    Returns:
        DataFrame: pandas dataframe with interpreted pb data
    """
    pass

    # message parsing
    if not isinstance(pb, list):
        pb = [pb]

    raw = bytes()
    for entry in pb:

        if isinstance(entry, bytes):

            # print("GOT BYTES")

            raw = entry
            break

            # python 2 interprets "bytes" as "str"
            # if the entry can be decoded as ascii, treat as a path
            try:
                entry.decode('ascii')
                with open(entry, 'rb') as f:
                    raw += f.read()
            except (UnicodeDecodeError, AttributeError):
                raw += entry

        elif isinstance(entry, str):

            # print("GOT STR")

            with open(entry, 'rb') as f:
                raw += f.read()

        else:
            raise TypeError('unknown input source for protobuf')

    # parse concatenated message
    Message = MessageType.FromString(raw)

    # check message
    if not Message.ListFields():
        raise ValueError('Parsed message is empty')

    # instantiate reader
    reader = ProtobufReader(flatten, prefix_nested)

    # intepret message
    data = reader.interpret_message(Message)

    #print(data)

    if not dataframe:
        return data

    # put data into frame
    df = pd.DataFrame.from_records([data], index=[index])

    return df
