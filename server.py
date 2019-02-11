import csv
from hashlib import sha1
import os
import pickle
import random
import socket
from threading import (
    Lock,
    Thread,
)

from ciphers import (
    Caesar_Cipher,
)
from constants import (
    PORT,
)
from message import (
    Header,
    Message,
)
from utils import (
    gen_keys,
    modularquickpow,
)


# Mutex for the passord.csv file
file_write_lock = Lock()

# IP Addresses
hostname = socket.gethostname()
server_IPAddr = socket.gethostbyname(hostname)
client_IPAddr = None


def send_msg_to_client(socket, msg):
    socket.send(str(msg).encode("ASCII"))
    ack_msg = socket.recv(1024).decode("ASCII")
    # Make sure that the msg has been acknowledged by the server
    assert ack_msg == "ACK"


def recv_msg_from_client(socket):
    msg_from_client = socket.recv(1024).decode("ASCII")
    # Send Acknowledgement to client
    socket.send("ACK".encode("ASCII"))

    return msg_from_client


def handle_login_creation_request(socket, msg, cipher):
    file_write_lock.acquire()
    if not os.path.isfile("password.csv"):
        f = open("password.csv", "a+")
        f.close()
    f = open("password.csv", "r")
    csv_reader = csv.reader(f)

    # Search for id in this file
    id_already_present = False
    for row in csv_reader:
        if row[0] == msg.id:
            id_already_present = True
    f.close()

    if id_already_present:
        print("Account already exists")
        status = 1
    else:
        print("Account created")
        salt = str(random.randint(100, 1000))
        hashed_pswd = sha1((msg.pswd + salt + msg.q).encode("ASCII")).hexdigest()
        status = 0

        # Write to file
        f = open("password.csv", "a+")
        csv_writer = csv.writer(f)
        csv_writer.writerow([msg.id, salt, hashed_pswd, msg.q])

    file_write_lock.release()

    reply_msg = Message(
        header=Header(20, server_IPAddr, client_IPAddr),
        status=status,
    )
    encrypted_reply_msg = reply_msg.encrypt(cipher)
    socket.send(pickle.dumps(encrypted_reply_msg))


def handle_auth_request(socket, msg, cipher):
    file_write_lock.acquire()

    if not os.path.isfile("password.csv"):
        f = open("password.csv", "a+")
        f.close()
    f = open("password.csv", "r")
    csv_reader = csv.reader(f)

    # Search for id in this file
    id_already_present = False
    for row in csv_reader:
        if row[0] == msg.id:
            id_already_present = True
            break
    f.close()

    if not id_already_present:
        # Not authenticated
        status = 1
    else:
        salt, hashed_pswd, user_prime = row[1], row[2], row[3]
        new_hash = sha1((msg.pswd + salt + user_prime).encode("ASCII")).hexdigest()
        if new_hash == hashed_pswd:
            # Authenticated
            status = 0
        else:
            # Not authenticated
            status = 1
    file_write_lock.release()

    auth_reply = Message(
        header=Header(40, server_IPAddr, client_IPAddr),
        status=status,
    )
    encrypted_auth_reply = auth_reply.encrypt(cipher)
    socket.send(pickle.dumps(encrypted_auth_reply))


def handle_service_request(socket, msg, cipher):
    if not os.path.isfile(msg.file):
        service_reply = Message(
            header=Header(60, server_IPAddr, client_IPAddr),
            status=1,
        )
        encrypted_service_reply = service_reply.encrypt(cipher)
        socket.send(pickle.dumps(encrypted_service_reply))
        return
    else:
        f = open(msg.file, "r")
        file_contents = f.read()
        print("Length of file to be transferred is {} bytes".format(len(file_contents)))
        length_file_covered = 0
        while length_file_covered <= len(file_contents):
            service_reply = Message(
                header=Header(60, server_IPAddr, client_IPAddr),
                buffer=file_contents[length_file_covered:(length_file_covered + 1024)],
                status=2,
            )
            encrypted_service_reply = service_reply.encrypt(cipher)
            socket.send(pickle.dumps(encrypted_service_reply))
            length_file_covered += 1024

            # Wait for the ACK message from client
            ack_msg = socket.recv(1024).decode("ASCII")
            assert ack_msg == "ACK"

        # Send the final over message
        service_reply = Message(
            header=Header(60, server_IPAddr, client_IPAddr),
            status=0,
        )
        encrypted_service_reply = service_reply.encrypt(cipher)
        socket.send(pickle.dumps(encrypted_service_reply))


def handle_client(socket, addr):
    global client_IPAddr
    client_IPAddr = addr[0]

    # Receive the prime value and its primitive root from client
    prime = int(recv_msg_from_client(socket))
    g = int(recv_msg_from_client(socket))

    # Generate the DH Secret Key
    pub_key, priv_key = gen_keys(g, prime)
    # Read the client's public key
    client_pub_key = int(recv_msg_from_client(socket))
    # Send the server's public key
    send_msg_to_client(socket, pub_key)
    # Compute the Diffe-Hellman secret key b/w client and server
    dh_secret_key = modularquickpow(client_pub_key, priv_key, prime)
    # Create the Caesar Cipher
    cipher = Caesar_Cipher(dh_secret_key)

    # Serve the client until it exists
    while True:
        # Read msg from client
        encrypted_msg = pickle.loads(socket.recv(1024))
        msg = encrypted_msg.decrypt(cipher)
        if msg.header.opcode == "10":
            handle_login_creation_request(socket, msg, cipher)
        elif msg.header.opcode == "30":
            handle_auth_request(socket, msg, cipher)
        elif msg.header.opcode == "50":
            handle_service_request(socket, msg, cipher)
        elif msg.header.opcode == "0":
            socket.close()
            print('Connection from {} got closed'.format(addr))
            return
        else:
            raise Exception("INVALID OPCODE: {}".format(msg.header.opcode))


def accept_connections():
    # Initializing the socket
    s = socket.socket()
    # Binding to the port
    s.bind(('', PORT))
    # put the socket into listening mode
    s.listen(5)

    # Continuously
    while True:
        # Establish connection with client.
        c, addr = s.accept()
        print('Got connection from {}'.format(addr))
        # Does handle_client(c) on a thread
        t = Thread(target=handle_client, args=(c, addr))
        t.start()

    s.close()


if __name__ == "__main__":
    accept_connections()
