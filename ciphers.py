from textwrap import (
    wrap,
)

from encoding import (
    decode_number_to_character,
    encode_character_to_number,
    normalize_single_digits,
)


class Caesar_Cipher:

    def __init__(self, key):
        self.key = key

    def encrypt(self, msg):
        encrypted_msg = ""
        for char in msg:
            encrypted_char = (int(encode_character_to_number(char)) + self.key) % 67
            normalized_encrypted_char = normalize_single_digits(encrypted_char)
            encrypted_msg += normalized_encrypted_char

        return encrypted_msg

    def decrypt(self, encrypted_msg):
        decrypted_msg = ""
        for encoded_char in wrap(encrypted_msg, 2):
            decrypted_char = (int(encoded_char) - self.key) % 67
            normalized_decrypted_char = normalize_single_digits(decrypted_char)
            decrypted_msg += decode_number_to_character(normalized_decrypted_char)

        return decrypted_msg
