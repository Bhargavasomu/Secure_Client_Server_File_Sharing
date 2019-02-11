class Header:
    def __init__(self, opcode, src_addr="127.0.0.1", dest_addr="127.0.0.1"):
        self.opcode = str(opcode)
        self.src_addr = src_addr
        self.dest_addr = dest_addr

    def encrypt(self, cipher):
        return type(self)(
            opcode=cipher.encrypt(self.opcode),
            src_addr=cipher.encrypt(self.src_addr),
            dest_addr=cipher.encrypt(self.dest_addr),
        )

    def decrypt(self, cipher):
        return type(self)(
            opcode=int(cipher.decrypt(self.opcode)),
            src_addr=cipher.decrypt(self.src_addr),
            dest_addr=cipher.decrypt(self.dest_addr),
        )


class Message:
    def __init__(
            self,
            header,
            buffer=None,
            id=None,
            q=None,
            pswd=None,
            status=None,
            file=None,
            dummy=None):
        self.header = header
        self.buffer = str(buffer)
        self.id = str(id)
        self.q = str(q)
        self.pswd = str(pswd)
        self.status = str(status)
        self.file = str(file)
        self.dummy = str(dummy)

    def encrypt(self, cipher):
        return type(self)(
            header=self.header.encrypt(cipher),
            buffer=cipher.encrypt(self.buffer),
            id=cipher.encrypt(self.id),
            q=cipher.encrypt(self.q),
            pswd=cipher.encrypt(self.pswd),
            status=cipher.encrypt(self.status),
            file=cipher.encrypt(self.file),
            dummy=cipher.encrypt(self.dummy),
        )

    def decrypt(self, cipher):
        return type(self)(
            header=self.header.decrypt(cipher),
            buffer=cipher.decrypt(self.buffer),
            id=cipher.decrypt(self.id),
            q=cipher.decrypt(self.q),
            pswd=cipher.decrypt(self.pswd),
            status=cipher.decrypt(self.status),
            file=cipher.decrypt(self.file),
            dummy=cipher.decrypt(self.dummy),
        )
