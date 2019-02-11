def normalize_single_digits(num):
    s = str(num)
    if len(s) == 1:
        return "0" + s
    return s


def encode_character_to_number(char):
    assert len(char) == 1
    if char.isalpha():
        if char.isupper():
            encoding = ord(char) - 64
        else:
            encoding = ord(char) - 57
    elif char.isdigit():
        encoding = int(char) + 30
    elif char == ",":
        encoding = 27
    elif char == ".":
        encoding = 28
    elif char == "?":
        encoding = 29
    elif char == "!":
        encoding = 66
    elif char == " ":
        encoding = 0
    else:
        raise Exception("Invalid Literal To Encode, got {}".format(char))

    return normalize_single_digits(encoding)


def decode_number_to_character(num):
    assert len(num) == 2
    int_version = int(num)
    if int_version == 0:
        return " "
    if int_version == 27:
        return ","
    elif int_version == 28:
        return "."
    elif int_version == 29:
        return "?"
    elif int_version == 66:
        return "!"
    elif int_version >= 30 and int_version <= 39:
        return str(int_version - 30)
    elif int_version >= 40 and int_version <= 65:
        return chr(int_version + 57)
    elif int_version >= 1 and int_version <= 26:
        return chr(int_version + 64)
    else:
        raise Exception("Invalid Numeber To Decode, got {}".format(num))
