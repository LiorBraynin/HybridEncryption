import socket
import sys
import wx
import threading
from tcp_by_size import send_with_size, recv_by_size
import time
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from cryptography.hazmat.primitives import padding
import random
import select


HEIGHT = 300
WIDTH = 500


die = False
dis = False
input_dic = {}
sign_dic = {}
send = b""
lock = threading.Lock()
key = 0
encryption_method = b''
threads = []


class LoginFrame(wx.Frame):
    def __init__(self):
        wx.Frame.__init__(self, parent=None, title='Login', size=(WIDTH, HEIGHT), style=wx.DEFAULT_FRAME_STYLE
                          | wx.MINIMIZE_BOX)
        self.Bind(wx.EVT_CLOSE, self.OnCLose)
        self.panel = wx.Panel(self)
        self.rsa = wx.Button(self.panel, label='RSA')
        self.rsa.Bind(wx.EVT_BUTTON, self.on_rsa)
        self.dh = wx.Button(self.panel, label='Diffie-Hellman')
        self.dh.Bind(wx.EVT_BUTTON, self.on_dh)
        self.username_label = wx.StaticText(self.panel, label='Username:')
        self.username_text = wx.TextCtrl(self.panel)
        self.password_label = wx.StaticText(self.panel, label='Password:')
        self.password_text = wx.TextCtrl(self.panel)  # can add: style=wx.TE_PASSWORD
        self.connect_button = wx.Button(self.panel, label='Connect')
        self.signup_button = wx.Button(self.panel, label="Sign up")
        self.connect_button.Bind(wx.EVT_BUTTON, self.on_connect)
        self.signup_button.Bind(wx.EVT_BUTTON, self.on_signup)
        self.send_data_label = wx.StaticText(self.panel, label='↓ To send data ↓')
        self.send_data = wx.TextCtrl(self.panel, size=(20, 70), style=wx.TE_MULTILINE)
        self.send_data_button = wx.Button(self.panel, label="Send data")
        self.send_data_button.Bind(wx.EVT_BUTTON, self.on_send)
        self.got_data_label = wx.StaticText(self.panel, label='↓ RECEIVED data ↓')
        self.got_data = wx.TextCtrl(self.panel, size=(20, 70), style=wx.TE_MULTILINE)
        self.from_server = wx.TextCtrl(self.panel, size=(20, 40))
        self.cur_username = wx.StaticText(self.panel, label='Current Username:')
        self.cur_username_text = wx.TextCtrl(self.panel, size=(500, 30))
        self.__do_layout()

    def OnCLose(self, event):
        global die
        print("WINDOW CLOSED\nFINISHING CLIENT...")
        die = True
        self.Destroy()

    def __do_layout(self):
        sizer = wx.BoxSizer(wx.VERTICAL)
        hbox2 = wx.BoxSizer(wx.HORIZONTAL)
        hbox2.Add(self.rsa, 0, wx.ALL)
        hbox2.Add(self.dh, 0, wx.ALL)
        sizer.Add(hbox2, 0, wx.EXPAND)
        sizer.Add(self.username_label, 0, wx.ALL, 5)
        sizer.Add(self.username_text, 0, wx.EXPAND | wx.ALL, 5)
        sizer.Add(self.password_label, 0, wx.ALL, 5)
        sizer.Add(self.password_text, 0, wx.EXPAND | wx.ALL, 5)
        sizer.Add(self.connect_button, 0, wx.ALIGN_CENTER | wx.ALL, 5)
        sizer.Add(self.signup_button, 0, wx.ALIGN_CENTER | wx.ALL, 5)
        sizer.Add(self.send_data_label, 0, wx.ALL, 5)
        sizer.Add(self.send_data, 0, wx.ALL | wx.EXPAND, 5)
        sizer.Add(self.send_data_button, 0, wx.ALIGN_CENTER | wx.ALL, 5)
        sizer.Add(self.got_data_label, 0, wx.ALL, 5)
        sizer.Add(self.got_data, 0, wx.ALL | wx.EXPAND, 5)
        sizer.Add(self.from_server, 0, wx.ALL | wx.EXPAND, 5)
        self.send_data.SetEditable(False)
        self.panel.SetSizer(sizer)
        self.got_data.SetEditable(False)
        self.from_server.SetEditable(False)
        self.connect_button.Enable(False)
        self.signup_button.Enable(False)
        self.username_text.SetEditable(False)
        self.password_text.SetEditable(False)
        self.send_data_button.Enable(False)
        hbox2 = wx.BoxSizer(wx.HORIZONTAL)
        hbox2.Add(self.cur_username, 0, wx.ALL, 5)
        hbox2.Add(self.cur_username_text, 0, wx.ALL | wx.EXPAND, 5)
        self.cur_username_text.SetEditable(False)
        sizer.Add(hbox2, 0, wx.EXPAND)
        sizer.Fit(self)

    def on_rsa(self, event):
        global encryption_method
        self.rsa.Enable(False)
        self.dh.Enable(False)
        self.username_text.SetEditable(True)
        self.password_text.SetEditable(True)
        self.connect_button.Enable(True)
        self.signup_button.Enable(True)
        encryption_method = b'RSA'

    def on_dh(self, event):
        global encryption_method
        self.rsa.Enable(False)
        self.dh.Enable(False)
        self.username_text.SetEditable(True)
        self.password_text.SetEditable(True)
        self.connect_button.Enable(True)
        self.signup_button.Enable(True)
        encryption_method = b'DH'

    def write_from_server(self, mes):
        self.from_server.SetValue(mes.decode())

    def on_connect(self, event):
        global dis
        global input_dic
        username = self.username_text.GetValue()
        password = self.password_text.GetValue()
        if not username and not password:
            print("BLANK USERNAME AND PASSWORD!\nPls login again")
        elif not username:
            print("BLANK USERNAME!\nPls login again")
        elif not password:
            print("BLANK PASSWORD!\nPls login again")
        elif self.connect_button.GetLabel() == "Connect":
            input_dic[username] = password
        elif self.connect_button.GetLabel() == "Disconnect":
            dis = True
            self.send_data_button.Enable(False)
            self.connect_button.SetLabel("Connect")
            self.username_text.SetEditable(True)
            self.password_text.SetEditable(True)
            self.username_text.Clear()
            self.password_text.Clear()
            self.send_data.SetEditable(False)
            self.send_data.Clear()
        else:
            pass

    def on_signup(self, event):
        global sign_dic
        username = self.username_text.GetValue()
        password = self.password_text.GetValue()
        if self.signup_button.GetLabel() != 'Sign up':
            return
        if not username and not password:
            print("BLANK USERNAME AND PASSWORD!\nPls sign up again")
        elif not username:
            print("BLANK USERNAME!\nPls sign up again")
        elif not password:
            print("BLANK PASSWORD!\nPls sign up again")
        elif self.signup_button.GetLabel() == "Sign up":
            sign_dic[username] = password

    def on_send(self, event):
        global send
        if self.connect_button.GetLabel() == 'Disconnect':
            send = self.send_data.GetValue().encode()

    def signed_suc(self, username):
        self.signup_button.SetLabel("Signed up")
        self.cur_username_text.write(username.decode())

    def connect_suc(self):
        self.connect_button.SetLabel("Disconnect")
        self.send_data.SetEditable(True)
        self.send_data_button.Enable(True)
        self.send_data.SetEditable(True)

    def wrong_connect(self):
        lock.acquire()
        lock.release()
        prev_size = self.connect_button.GetSize()
        prev_pos = self.connect_button.GetPosition()
        self.connect_button.SetLabel("WRONG USERNAME AND PASSWORD ")
        self.connect_button.SetSize(250, 30)
        self.connect_button.SetPosition((prev_pos[0] - 80, prev_pos[1]))
        start_time = time.time()
        sec = 5.0
        prev_time = time.time()
        while True:
            self.connect_button.SetLabel("WRONG USERNAME AND PASSWORD " + str(round(sec, 2)))
            now = time.time()
            if time.time() - start_time >= 5:
                break
            sec -= (now - prev_time)
            prev_time = time.time()
        self.connect_button.SetSize(prev_size)
        self.connect_button.SetPosition(prev_pos)
        self.connect_button.SetLabel("Connect")
        self.username_text.SetEditable(True)
        self.password_text.SetEditable(True)
        self.username_text.Clear()
        self.password_text.Clear()
        self.send_data.SetEditable(False)
        self.send_data.Clear()

    def write_data(self, data, username):
        prev_data = self.got_data.GetValue()
        new_data = f"{prev_data}\n{username.decode()} -> {data.decode()}"
        if prev_data == '':
            new_data = f'{username.decode()} -> {data.decode()}'
        self.got_data.Clear()
        self.got_data.WriteText(new_data)


app = ''
frame = ''


def wait_input():
    global input_dic
    if input_dic:
        for i in input_dic:
            username = i
            password = input_dic[i]
            input_dic = {}
            return username.encode(), password.encode()
    return b'', b''


def wait_sign():
    global sign_dic
    if sign_dic:
        for i in sign_dic:
            username = i
            password = sign_dic[i]
            sign_dic = {}
            return username.encode(), password.encode()
    return b'', b''


def run_wx():
    global frame
    global app
    app = wx.App()
    frame = LoginFrame()
    frame.SetMinSize((WIDTH, HEIGHT))
    frame.Show()
    app.MainLoop()


def protocol_parse_reply(byte_data):
    global frame
    print(f"GOT DATA ->\t{byte_data}\n\n")
    try:
        parts = byte_data.split(b'~')
        code = parts[0]
        frame.write_from_server(byte_data)
        if byte_data == b"ERRR~wrong username and password":
            frame.wrong_connect()
        elif byte_data == b'ERRR~username already exists':
            print("username exists")
        elif code == b"CONR":
            frame.connect_suc()
        elif code == b"SIGR":
            frame.signed_suc(parts[2])
        elif code == b"DISR":
            print("disconnected successfully")
        elif code == b"DATR":
            got_data = parts[1]
            username = parts[2]
            frame.write_data(got_data, username)
            print("GOT DATA")
        elif code == b'ERRR':
            print(f"ERRR")
    except Exception as err:
        print(f'Server replay bad format -> {err}')


def recv_loop(sock, key):
    global die
    while not die:
        ready_to_read, _, _ = select.select([sock], [], [], 0)
        if sock in ready_to_read:
            time.sleep(1)
            iv, _ = recv_by_size(sock)
            enc_data, _ = recv_by_size(sock)
            print(f"GOT ENCRYPTED DATA ->\t{enc_data}")
            data = AES_decrypt_CBC(key, enc_data, iv)
            if data != b"":
                protocol_parse_reply(data)


#  generating rsa key and
def send_key_rsa():
    rsa_key = RSA.generate(2048)
    public_rsa_key = rsa_key.publickey().export_key()
    cipher = PKCS1_OAEP.new(rsa_key)
    return public_rsa_key, cipher


def recv_key(encrypted_key, cipher):
    decrypted_key = cipher.decrypt(encrypted_key)
    return decrypted_key


def gen_b():
    b = random.randint(1, 100)
    return b


def gen_public_key_dh(p, g, b):
    public_key = pow(g, b) % p
    print(public_key)
    return public_key


def get_key(a, b, p):
    key_ = str(pow(a, b) % p).encode()
    return key_


def pad(data, block_size=16):
    padder = padding.PKCS7(block_size * 8).padder()
    padded_data = padder.update(data) + padder.finalize()
    return padded_data


def unpad(padded_data, block_size=16):
    unpadder = padding.PKCS7(block_size * 8).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data


def AES_encrypt_CBC(key, plain_text):
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text, iv


def AES_decrypt_CBC(key, cipher_text, iv):
    decrypt_cipher = AES.new(key, AES.MODE_CBC, iv)
    plain_text = unpad(decrypt_cipher.decrypt(cipher_text))
    return plain_text


def dh_key_to_aes(key):
    while len(key) < 16:
        key += b'0'
    return key


def main(ip):
    """
    main client - handle socket and main loop
    """
    global die
    global dis
    global send
    global key
    global encryption_method
    global threads

    sock = socket.socket()

    port = 1233
    try:
        sock.connect((ip, port))
        print(f'Connect succeeded {ip}: {port}\n\n')
    except:
        print(f'Error while trying to connect.  Check ip or port -- {ip}: {port}')

    t_wx = threading.Thread(target=run_wx)
    threads.append(t_wx)
    t_wx.start()
    while True:
        if encryption_method != b'':
            break
    sock.send(encryption_method)
    print(f"METHOD ->\t{encryption_method}\n\n")
    if encryption_method == b'RSA':
        public_rsa_key, cipher = send_key_rsa()
        sock.send(public_rsa_key)
        encrypted_key = sock.recv(4096)
        print(f"SERIALIZED KEY ->\t{encrypted_key}\n")
        key = recv_key(encrypted_key, cipher)
        print(f"KEY ->\t{key}\n\n")
    elif encryption_method == b'DH':
        p_g = sock.recv(1024).split(b'~')
        p = int(p_g[0].decode())
        g = int(p_g[1].decode())
        print(f"P ->\t{p}\n")
        print(f"G ->\t{g}\n")
        b = gen_b()
        print(f"B ->\t{b}\n")
        public_key = gen_public_key_dh(p, g, b)
        print(f"CLIENT'S PUBLIC KEY ->\t{public_key}\n")
        a = int(sock.recv(1024).decode())
        print(f"SERVER'S PUBLIC KEY ->\t{a}\n\n")
        sock.send(str(public_key).encode())
        key = get_key(a, b, p)
        key = dh_key_to_aes(key)
        print(f"KEY ->\t{key}\n\n")
    t_recv = threading.Thread(target=recv_loop, args=(sock, key))
    threads.append(t_recv)
    t_recv.start()
    while not die:
        to_send = b''
        if input_dic:  # if client pressed connect
            username, password = wait_input()
            if username != b'' or password != b'':
                to_send = b"CONN~" + username + b"~" + password
        if sign_dic:  # if client pressed sign up
            username, password = wait_sign()
            if username != b'' or password != b'':
                to_send = b"SIGN~" + username + b"~" + password
        if dis:
            dis = False
            to_send = b"DISC"
        if send != b"":
            to_send = b"DATA~" + send
            send = b""
        try:
            if to_send != b'':
                print(f"DATA TO SEND ->\t{to_send}")
                to_send, iv = AES_encrypt_CBC(key, to_send)
                print(f"ENCRYPTED DATA TO SEND ->\t{to_send}\n\n")
                send_with_size(sock, iv)
                send_with_size(sock, to_send)
        except socket.error as err:
            print(f'Got socket error: {err}')
            break
        except Exception as err:
            print(f'General error: {err}')
            break
    print("FINISHED")
    to_send = b"FNSH~finish"
    to_send, iv = AES_encrypt_CBC(key, to_send)
    send_with_size(sock, iv)
    send_with_size(sock, to_send)
    print(recv_by_size(sock))
    print(recv_by_size(sock))
    for t in threads:
        print(f"finishing -> {t}")
        t.join()
        print("FINISHED THIS THREAD")
    sock.close()
    print("CLOSED ALL")
    sys.exit()



if __name__ == "__main__":
    main('127.0.0.1')
