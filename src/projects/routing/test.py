import struct
msg = b'\x01\x7f\x00\x00\x04\x7f\x00\x00\x02Groovy Gorilla'
routing_table = {'127.0.0.2': [1, '127.0.0.2'], '127.0.0.3': [3, '127.0.0.3'], '127.0.0.4': [7, '127.0.0.4']}
def parse_hello(msg: bytes, routing_table: dict) -> str:
    """
    Parse the HELLO message
    :param msg: message
    :param routing_table: this router's routing table
    :returns the action taken as a string
    """
    # print(msg[1:5])
    # print(msg[5:9])
    # print(msg[9:])
    print(len(msg))
    forwarding = msg[1:5]
    forwardingStruct = struct.unpack('!bbbb', forwarding)

    sending = msg[5:9]
    sendingStruct = struct.unpack('!bbbb', sending)

    message = msg[9:]
    lengthMessage = len(message)
    numberofB = int(lengthMessage) * "c"
    # numberofB = "!" + numberofB
    textStruct = struct.unpack('{}'.format(numberofB), message)
    print(textStruct)
    
print(parse_hello(msg, routing_table))

    # my_msg_forward = struct.unpack('!bbbbbbbbb', msg[1:6])
    # print(my_msg_forward)
    # # Get the IP value in String
    # myIps = ""
    # for val in my_msg_forward:
    #     myIps += (str(val) + ".")
    # myIps = (myIps[:-2])
    # print(myIps)