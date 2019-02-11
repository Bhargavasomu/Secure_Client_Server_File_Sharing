import getpass
import pickle
import socket
import sys

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
from utils import (  # noqa: F401
    gen_large_prime,
    get_least_primitive_root,
    gen_keys,
    modularquickpow,
)


# IP Addresses
hostname = socket.gethostname()
client_IPAddr = socket.gethostbyname(hostname)
server_IPAddr = None


def send_msg_to_server(socket, msg):
    socket.send(str(msg).encode("ASCII"))
    ack_msg = socket.recv(1024).decode("ASCII")
    # Make sure that the msg has been acknowledged by the server
    assert ack_msg == "ACK"


def recv_msg_from_server(socket):
    msg_from_server = socket.recv(1024).decode("ASCII")
    # Send Acknowledgement to server
    socket.send("ACK".encode("ASCII"))

    return msg_from_server


def connect_to_server(server_ip):
    # Initializing socket object
    s = socket.socket()
    # Connecting to the server
    s.connect((server_ip, PORT))

    return s


def handle_account_creation(socket, key):
    id = input("\tEnter ID: ")
    pswd = getpass.getpass("\tEnter Password: ")
    user_prime = gen_large_prime()
    cipher = Caesar_Cipher(key)

    # Creating the message contents
    msg = Message(
        header=Header(10, client_IPAddr, server_IPAddr),
        id=id,
        q=user_prime,
        pswd=pswd,
    )
    encrypted_msg = msg.encrypt(cipher)
    socket.send(pickle.dumps(encrypted_msg))
    encrypted_login_reply_msg = pickle.loads(socket.recv(1024))
    login_reply_msg = encrypted_login_reply_msg.decrypt(cipher)

    # Make sure that LOGINREPLY only is received
    assert login_reply_msg.header.opcode == "20"
    if login_reply_msg.status == "0":
        print("Account Creation Status: SUCCESSFULL")
    elif login_reply_msg.status == "1":
        print("Account Creation Status: UNSUCCESSFULL (ID ALREADY EXISTS)")
    else:
        raise Exception("Invariant, should not occur")


def authenticate(socket, key):
    """
    Authenticates the client
    """
    id = input("\tEnter ID: ")
    pswd = getpass.getpass("\tEnter Password: ")
    cipher = Caesar_Cipher(key)

    auth_msg = Message(
        header=Header(30, client_IPAddr, server_IPAddr),
        id=id,
        pswd=pswd,
    )
    encrypted_auth_msg = auth_msg.encrypt(cipher)
    socket.send(pickle.dumps(encrypted_auth_msg))

    encrypted_auth_reply = pickle.loads(socket.recv(1024))
    auth_reply = encrypted_auth_reply.decrypt(cipher)
    assert auth_reply.header.opcode == "40"
    if auth_reply.status == "0":
        print("Authenticated !!!")
        return True
    else:
        print("Invalid Credentials")
        return False


def handle_file_download(socket, key):
    authenticate(socket, key)
    file_name = input("\tFile Name: ")
    service_req_msg = Message(
        header=Header(50, client_IPAddr, server_IPAddr),
        file=file_name,
    )

    cipher = Caesar_Cipher(key)
    encrypted_service_req_msg = service_req_msg.encrypt(cipher)
    socket.send(pickle.dumps(encrypted_service_req_msg))

    # file_name = "test.txt"
    f = open(file_name, 'w')
    # Stitch all the packets to form the whole file
    while True:
        encrypted_service_reply = pickle.loads(socket.recv(2500))
        service_reply = encrypted_service_reply.decrypt(cipher)
        if service_reply.status == "0":
            break
        elif service_reply.status == "1":
            print("File Not found in server")
            return
        elif service_reply.status == "2":
            # This means that there are still other packets which form the file
            f.write(service_reply.buffer)
            # Sending ACK
            socket.send("ACK".encode("ASCII"))

    f.close()
    print("File Transfer Complete !!!")


def handle_exit(socket, key):
    cipher = Caesar_Cipher(key)

    # Creating the exit message contents
    msg = Message(
        header=Header(0, client_IPAddr, server_IPAddr),
    )
    encrypted_msg = msg.encrypt(cipher)
    socket.send(pickle.dumps(encrypted_msg))


def main():
    global server_IPAddr

    server_IPAddr = sys.argv[1]
    socket = connect_to_server(server_IPAddr)
    # # Generate a large prime and it's primitive root
    # prime = gen_large_prime()
    # # Taking a lot of time
    # g = get_least_primitive_root(prime)
    # Show the below only for demonstration purpose but not while deploying this
    prime = 4016118052302531731
    g = 2

    # Send the chosen public prime number
    send_msg_to_server(socket, prime)
    # Send the public primitive root of the chosen prime number
    send_msg_to_server(socket, g)

    # Generate the DH Secret Key
    pub_key, priv_key = gen_keys(g, prime)
    # Send the client's public key
    send_msg_to_server(socket, pub_key)
    # Read the server's public key
    server_pub_key = int(recv_msg_from_server(socket))
    # Compute the Diffe-Hellman secret key b/w client and server
    dh_secret_key = modularquickpow(server_pub_key, priv_key, prime)

    while True:
        cmd = input(">>> ")
        if cmd == "CREATE":
            handle_account_creation(socket, dh_secret_key)
        elif cmd == "DOWNLOAD":
            handle_file_download(socket, dh_secret_key)
        elif cmd == "EXIT":
            handle_exit(socket, dh_secret_key)
            break

    socket.close()


if __name__ == "__main__":
    main()
