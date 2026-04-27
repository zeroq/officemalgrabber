# -*- coding: utf-8 -*-
# vim: tabstop=4 shiftwidth=4 expandtab

import math

def decodeSequence(decompressedChunk, sequence):
    decodedSequence = ''
    flagMap = sequence[0]
    iterator = 1;
    currentLength = decompressedChunk.__len__()

    for bytePosition in range(0,8):
        if iterator >= len(sequence):
            break
        #if bitmask is 0 at the current byteposition, simply copy byte to decompressed chunk
        if flagMap % 2 == 0:
            #decompressedChunk += sequence[iterator]
            decompressedChunk.append(sequence[iterator])
            iterator += 1
            currentLength += 1
        #bitmask is 1 at current position -> process the next two bytes as copyToken
        else:
            if iterator + 1 >= len(sequence):
                break
            #offsetBits = int(max(4, math.ceil(math.log(currentLength, 2))))
            log_input = currentLength if currentLength > 0 else 1
            offsetBits = int(max(4, math.ceil(math.log(log_input, 2))))
            lengthBits = 16 - offsetBits
            copyToken = sequence[iterator+1]
            copyToken = copyToken << 8
            copyToken += sequence[iterator]
            walkBack = (copyToken >> lengthBits) + 1
            copyLength = (copyToken - ((copyToken >> lengthBits) << lengthBits)) + 3
            startCopying = currentLength - walkBack
            for x in range(0, copyLength):
                #decompressedChunk += decompressedChunk[startCopying + x]
                if startCopying + x < 0 or startCopying + x >= len(decompressedChunk):
                    decompressedChunk.append(0)
                else:
                    byte_to_copy = decompressedChunk[startCopying + x]
                    decompressedChunk.append(byte_to_copy)
            iterator += 2
            currentLength += copyLength
        flagMap = flagMap >> 1
    return decompressedChunk

def getSequences_old(compressedChunk):
    #extract chunkHeader from the first and second byte
    chunkHeader = compressedChunk[1] << 8
    chunkHeader += compressedChunk[0]

    #compute length of current chunk
    try:
        compressionIndicator = chunkHeader >> 12
        chunkLenght = chunkHeader - (compressionIndicator << 12) + 3
    except Exception as error:
        print(f"getSequences: {error}")
        raise

    sequences = []
    iterator = 2        #first byte of first sequence is second of chunk
    while iterator < chunkLenght:
        bufferSequence = ''

        #sequence has at least 9 bytes: 1 byte for the bitmap and 8 character bytes,
        #if there were only uncompressed characters in the sequence
        sequenceLength = 9
        sequenceBitmap = compressedChunk[iterator]
        #for every copyToken, the sequence will grow by on byte to a maximum of 17 bytes
        while sequenceBitmap > 0:
            if sequenceBitmap % 2 != 0:
                sequenceLength += 1
            sequenceBitmap = sequenceBitmap >> 1

        if iterator + sequenceLength > chunkLenght:
            return sequences
        #move the sequence bytes into an own bytestring and append it to the sequence list
        for copyPointer in range(iterator, iterator+sequenceLength):
            bufferSequence += chr(compressedChunk[copyPointer])
        sequences.append(bufferSequence)
        iterator += sequenceLength
    return sequences


def getSequences(compressedChunk):
    if len(compressedChunk) < 2:
        return []
    # chunkHeader extrahieren
    # Da compressedChunk ein bytes-Objekt ist, liefert [1] und [0] bereits Integer
    chunkHeader = (compressedChunk[1] << 8) + compressedChunk[0]

    # Länge des Chunks berechnen
    compressionIndicator = chunkHeader >> 12
    # chunkHeader & 0x0FFF ist eine sauberere Art, die unteren 12 Bits zu bekommen
    chunkLength = (chunkHeader & 0x0FFF) + 3
    if chunkLength > len(compressedChunk):
        chunkLength = len(compressedChunk)

    sequences = []
    iterator = 2  # Erstes Byte der ersten Sequenz
    
    while iterator < chunkLength:
        # Initialisierung als leeres bytes-Objekt statt String
        bufferSequence = b''

        # Berechnung der sequenceLength
        # Wir müssen ein Backup vom Bitmap machen, um es nicht zu zerstören
        sequenceBitmap = compressedChunk[iterator]
        tempBitmap = sequenceBitmap
        
        # Ein Flag-Byte + 8 literale Bytes (Standardfall)
        sequenceLength = 1 
        # Wir prüfen 8 Bits (eine Sequenz hat immer 8 Einheiten)
        for _ in range(8):
            if tempBitmap % 2 != 0:
                sequenceLength += 2 # Ein CopyToken ist 2 Bytes lang
            else:
                sequenceLength += 1 # Ein Literal ist 1 Byte lang
            tempBitmap >>= 1

        # Falls wir über das Ende des Chunks hinausschießen würden
        if iterator + sequenceLength > chunkLength:
            # Manchmal ist die letzte Sequenz kürzer
            sequenceLength = chunkLength - iterator

        # Slicing ist der "Python 3 Weg" - viel schneller und liefert bytes!
        bufferSequence = compressedChunk[iterator : iterator + sequenceLength]
        
        sequences.append(bufferSequence)
        iterator += sequenceLength
    return sequences
