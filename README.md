## About
This is an implementation of the Secure File Sharing using 
`Diffe-Hellman key exchange` and `Caesar Cipher`. The users would first have to create an account with the server by using the `CREATE` command. Then they can download a file from the server by using the command 
`DOWNLOAD`.

### Requirements
Needs `python` versions of **3.6** or above to run the code.

### Client
```
python client.py
```

The supported Commands are
* CREATE - Create an account
* DOWNLOAD - Download a file from server

### Server
```
python server.py
```
The server can support multiple clients at the same time (Implemented using threads)
The Server stores the user ids and their corresponding hashed passwords in password.csv file.
