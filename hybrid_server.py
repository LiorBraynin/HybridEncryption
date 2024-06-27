import os.path
import threading
import socket
from tcp_by_size import send_with_size, recv_by_size
import time
import os.path
import pickle
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from cryptography.hazmat.primitives import padding
from Crypto.Random import get_random_bytes
import random


all_to_die = False  # global
MAX_CLIENTS = 20  # max amount of clients at the same time
users = {}  # username : password
users_sock = {}  # username : sock | change in sign up
connected_users = {}  # active sock : passive sock | change in connect
lock = threading.Lock()
users_keys = {}  # active sock : common AES key


def connect(username, password, sock):
    global connected_users
    global users_sock
    global users
    lock.acquire()
    if not os.path.exists('users.pkl'):
        lock.release()
        return b"ERRR~wrong username and password", sock
        # if the pickle doesn't exist -> no usernames and passwords at all
    with open('users.pkl', 'rb') as f:
        pickle_data = pickle.load(f)  # read the pickle
    lock.release()
    try:
        for k, v in pickle_data.items():
            if k == username and v == password and username in users_sock:
                if users_sock[username] != sock:
                    connected_users[sock] = users_sock[username]
                    return b'CONR~connected successfully', sock
    except Exception as err:
        print(f"CONNECT ERROR -> {err}")
    return b"ERRR~wrong username and password", sock


def sign_up(sock, username, password):
    global users
    global users_sock
    global connected_users
    if os.path.exists('users.pkl'):  # if the pickle exists -> check if username already exists
        lock.acquire()
        with open('users.pkl', 'rb') as f:
            loaded_data = pickle.load(f)
        lock.release()
        for k in loaded_data:
            if k == username:
                return b'ERRR~username already exists', sock
        lock.acquire()
        users[username] = password
        users_sock[username] = sock
        full_data = {**loaded_data, **users}
        with open('users.pkl', 'wb') as f:
            pickle.dump(full_data, f)
        lock.release()
    else:
        lock.acquire()
        users[username] = password
        users_sock[username] = sock
        with open('users.pkl', 'wb') as f:
            pickle.dump(users, f)
        lock.release()
    return b'SIGR~signed up successfully~' + username, sock


def disc(sock):
    del connected_users[sock]
    return b'DISR~disconnected successfully', sock


def async_data_send(sock, byte_data):
    dest_sock = connected_users[sock]
    for name in users_sock.keys():
        if users_sock[name] == sock:
            return b'DATR~' + byte_data + b"~from [" + name + b']', dest_sock
    return b'DATR~' + byte_data + b"~UNKNOWN USER", dest_sock


def close_client(sock):
    global users_sock
    global users_keys
    global connected_users
    try:
        if sock in users_keys:
            del users_keys[sock]
        if sock in connected_users:
            del connected_users[sock]
        for k,v in users_sock.items():
            if v == sock:
                del users_sock[k]
    except Exception as err:
        print(f"CLOSE ERROR -> {err}")

def protocol_build_reply(byte_data, sock):
    """
    :param sock:
    :param byte_data:
    :return: determine by the code, what is the code to send back
    """
    parts = byte_data.split(b'~')
    code = parts[0]
    if code == b'EXIT':
        return b'EXTR', sock
    elif code == b'CONN':
        username = parts[1]
        password = parts[2]
        return connect(username, password, sock)
    elif code == b'SIGN':
        username = parts[1]
        password = parts[2]
        return sign_up(sock, username, password)
    elif code == b'DISC':
        return disc(sock)
    elif code == b'DATA':
        data = parts[1]
        return async_data_send(sock, data)
    elif code == b'FNSH':
        return b'finish', sock
    else:
        return b'ERRR~002~code not supported', sock


def send_key_rsa(serialized_key):
    key = get_random_bytes(16)
    public_key = RSA.importKey(serialized_key)
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_key = cipher.encrypt(key)
    return encrypted_key, key


def gen_p_g():
    return 3529, 3


def gen_a():
    a = random.randint(1, 100)
    return a


def gen_public_key_dh(p, g, a):
    public_key = pow(g, a) % p
    return public_key


def get_key(b, a, p):
    key_ = str(pow(b, a) % p).encode()
    return key_


def pad(data, block_size=16):
    padder = padding.PKCS7(block_size * 8).padder()
    padded_data = padder.update(data) + padder.finalize()
    return padded_data


def unpad(padded_data, block_size=16):
    unpadder = padding.PKCS7(block_size * 8).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data


def encrypt_aes(key, data):
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    return ciphertext, iv


def AES_decrypt_CBC(key, cipher_text, iv):
    decrypt_cipher = AES.new(key, AES.MODE_CBC, iv)
    plain_text = unpad(decrypt_cipher.decrypt(cipher_text))
    return plain_text


def dh_key_to_aes(key):
    while len(key) < 16:
        key += b'0'
    return key


def handle_client(sock):
    """
    :param sock:
    thread loop
    """
    global users
    global users_sock
    global all_to_die
    print("GOT CLIENT\n\n")
    lock.acquire()
    users = {}
    lock.release()
    encryption_method = sock.recv(1024)  # the first message in the conversation | the client send to the server the
    # encryption method (RSA or DH)
    print(f"METHOD -> {encryption_method}\n\n")
    key = 0
    if encryption_method == b'RSA':
        serialized_key = sock.recv(4096)  # get the public key from the client
        to_send, key = send_key_rsa(serialized_key)  # send the common AES key to the client using the RSA public cipher
        print(f"RSA SERIALIZED KEY ->\t{to_send}\n")
        print(f"RSA KEY ->\t{key}\n\n")
        sock.send(to_send)
    elif encryption_method == b'DH':
        # DH:
        # first, the server generate p and g (two public numbers)
        # then, both the server and the client choose a private key (a = server, b = client)
        # then, each side generate their public key using their private keys. the server send their public key and then
        # the client send theirs
        # then, each side calculates the common key using each other's public keys.
        # *each size fill the key to a 16 bytes length using zeros.
        p, g = gen_p_g()  # gen the p and g
        print(f"DH P ->\t{p}\n")
        print(f"DH G ->\t{g}\n")
        sock.send(str(p).encode() + b'~' + str(g).encode())
        a = gen_a()
        print(f"DH A ->\t{a}\n")
        public_key = gen_public_key_dh(p, g, a)
        print(f"DH SERVER'S PUBLIC KEY ->\t{public_key}\n")
        sock.send(str(public_key).encode())
        b = int(sock.recv(1024).decode())
        print(f"DH CLIENT'S PUBLIC KEY ->\t{b}\n\n")
        key = get_key(b, a, p)
        key = dh_key_to_aes(key)
        print(f"KEY -> {key}\n\n")
    users_keys[sock] = key  # add the common AES key with the current client to the keys dic.
    finish = False
    while not finish:
        try:
            iv, err = recv_by_size(sock)  # get the iv
            encrypted_data, err = recv_by_size(sock)  # get the encrypted data
            byte_data = AES_decrypt_CBC(users_keys[sock], encrypted_data, iv)  # decrypt the encrypted data.
            print(f"GOT ENCRYPTED DATA ->\t{encrypted_data}")
            print(f"GOT DATA ->\t{byte_data}\n\n")
            if err != b'':
                to_send = err
                dest_sock = sock
            else:
                to_send, dest_sock = protocol_build_reply(byte_data, sock)
                print(f"DATA TO SEND ->\t{to_send}")
                to_send, iv = encrypt_aes(users_keys[dest_sock], to_send)
                print(f"ENCRYPTED DATA TO SEND ->\t{to_send}\n\n")
                if byte_data == b'FNSH~finish':
                    close_client(dest_sock)
                    send_with_size(dest_sock, iv)
                    send_with_size(dest_sock, to_send)
                    finish = True
            if finish:
                time.sleep(1)
                break
            send_with_size(dest_sock, iv)
            send_with_size(dest_sock, to_send)
        except socket.error as err:
            print(f"Socket error: {err}")
            break
        except Exception as err:
            print(f"Thread error: {err}")
            break
    print("finished client")


def main():
    global all_to_die
    threads = []
    srv_sock = socket.socket()
    srv_sock.bind(('0.0.0.0', 1233))
    srv_sock.listen(50)

    i = 1
    while True:
        print("\nMain Thread: before accepting ...")
        cli_sock, addr = srv_sock.accept()
        t = threading.Thread(target=handle_client, args=(cli_sock,))
        t.start()
        threads.append(t)
        i += 1
        threads.append(t)
        if i > MAX_CLIENTS:
            print("Main Thread: going down -> too much clients")
            break

    all_to_die = True
    print("Main Thread: waiting to all clients to die...")
    for t in threads:
        t.join()
    srv_sock.close()
    print('Bye...')


if __name__ == '__main__':
    main()
