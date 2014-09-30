def readInt(binary, index):
	value = 0
	value += ord(binary[index+3])
	value = value << 8
	value += ord(binary[index+2])
	value = value << 8
	value += ord(binary[index+1])
	value = value << 8
	value += ord(binary[index+0])
	return value
	
def readShort(binary, index):
	value = 0
	value += ord(binary[index+1])
	value = value << 8
	value += ord(binary[index+0])
	return value
	
	
def readSignedShort(binary, index):
	value = readShort(binary, index)
	if value >= 32768:
		value -= 65536
	return value