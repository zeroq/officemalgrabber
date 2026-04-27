
import struct

def readInt(binary, index):
    try:
        return struct.unpack('<I', binary[index : index + 4])[0]
    except (struct.error, IndexError):
        return 0

def readShort(binary, index):
    try:
        # '<H' means: Little-Endian (<), Unsigned Short (H) - 2 bytes
        return struct.unpack('<H', binary[index : index + 2])[0]
    except (struct.error, IndexError):
        return 0

def readSignedShort(binary, index):
    try:
        # '<h' means: Little-Endian (<), Signed Short (h)
        # This automatically handles the "if value >= 32768" logic for you.
        return struct.unpack('<h', binary[index : index + 2])[0]
    except (struct.error, IndexError):
        return 0

def readInt_old(binary, index):
    value = 0
    try:
        value += binary[index+3]
        value = value << 8
        value += binary[index+2]
        value = value << 8
        value += binary[index+1]
        value = value << 8
        value += binary[index+0]
    except:
        pass
    return value

def readShort_old(binary, index):
    value = 0
    try:
        value += binary[index+1]
        value = value << 8
        value += binary[index+0]
    except:
        pass
    return value


def readSignedShort_old(binary, index):
    value = readShort(binary, index)
    if value >= 32768:
        value -= 65536
    return value
