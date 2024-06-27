__author__ = 'Yossi'

# from  tcp_by_size import send_with_size ,recv_by_size


SIZE_HEADER_FORMAT = "00000000~" # n digits for data size + one delimiter
size_header_size = len(SIZE_HEADER_FORMAT) #the length of the size section
TCP_DEBUG = False
LEN_TO_PRINT = 100


def recv_by_size(sock):
    size_header = b''
    data_len = 0
    err = b''
    # size_header will be after this loop the first section of the socket, the size section as a string. (ex: "00000004")
    while len(size_header) < size_header_size: #loop until we receive the right number of bytes
        _s = sock.recv(size_header_size - len(size_header))
        if _s == b'':
            size_header = b''
            err = b'ERRR~003~Bad Format message too short'
            break
        size_header += _s
    data  = b''
    if size_header != b'':
        data_len = int(size_header[:size_header_size - 1]) # size_header as a int, not indluding the ~
        # data will be after this loop the data section of the socket
        while len(data) < data_len: #loop until we receive the right number of bytes
            _d = sock.recv(data_len - len(data))
            if _d == b'':
                data  = b''
                err = b'ERRR~003~Bad Format incorrect message length'
                break
            data += _d

    if  TCP_DEBUG and size_header != b'':
        print ("\nRecv(%s)>>>" % (size_header,), end='')
        print ("%s"%(data[:min(len(data),LEN_TO_PRINT)],))
    if data_len != len(data):
        data=b'' # Partial data is like no data !
        err = b'ERRR~003~Bad Format incorrect message length'
    return data, err





def send_with_size(sock, bdata):
    if type(bdata) == str:
        bdata = bdata.encode()
    len_data = len(bdata)
    header_data = str(len(bdata)).zfill(size_header_size - 1) + "~" # create the header, the size section. ex: "00000004~"
    bytea = bytearray(header_data,encoding='utf8') + bdata # byte array, the header and the data

    sock.send(bytea[:size_header_size])
    sent = 0
    while sent < len(bdata):
        _s = sock.send(bdata)
        sent += _s
    if TCP_DEBUG and  len_data > 0:
        print ("\nSent(%s)>>>" % (len_data,), end='')
        print ("%s"%(bytea[:min(len(bytea),LEN_TO_PRINT)],))
