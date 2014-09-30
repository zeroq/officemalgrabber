# -*- coding: utf-8 -*-
# vim: tabstop=4 shiftwidth=4 expandtab

import math

def decodeSequence(decompressedChunk, sequence):
    decodedSequence = ''
    flagMap = ord(sequence[0])
    iterator = 1;
    currentLength = decompressedChunk.__len__()


    for bytePosition in range(0,8):
        #if bitmask is 0 at the current byteposition, simply copy byte to decompressed chunk
        if flagMap % 2 == 0:
            decompressedChunk += sequence[iterator]
            iterator += 1
            currentLength += 1
        #bitmask is 1 at current position -> process the next two bytes as copyToken
        else:
            offsetBits = int(max(4, math.ceil(math.log(currentLength, 2))))
            lengthBits = 16 - offsetBits
            copyToken = ord(sequence[iterator+1])
            copyToken = copyToken << 8
            copyToken += ord(sequence[iterator])
            walkBack = (copyToken >> lengthBits) + 1
            copyLength = (copyToken - ((copyToken >> lengthBits) << lengthBits)) + 3
            startCopying = currentLength - walkBack
            for x in range(0, copyLength):
                decompressedChunk += decompressedChunk[startCopying + x]
            iterator += 2
            currentLength += copyLength
        flagMap = flagMap >> 1

    return decompressedChunk

def getSequences(compressedChunk):
    #extract chunkHeader from the first and second byte
    chunkHeader = ord(compressedChunk[1]) << 8
    chunkHeader += ord(compressedChunk[0])

    #compute length of current chunk
    compressionIndicator = chunkHeader >> 12
    chunkLenght = chunkHeader - (compressionIndicator << 12) + 3

    sequences = []
    iterator = 2        #first byte of first sequence is second of chunk
    while iterator < chunkLenght:
        bufferSequence = ''

        #sequence has at least 9 bytes: 1 byte for the bitmap and 8 character bytes,
        #if there were only uncompressed characters in the sequence
        sequenceLength = 9
        sequenceBitmap = ord(compressedChunk[iterator])

        #for every copyToken, the sequence will grow by on byte to a maximum of 17 bytes
        while sequenceBitmap > 0:
            if sequenceBitmap % 2 != 0:
                sequenceLength += 1
            sequenceBitmap = sequenceBitmap >> 1

        if iterator + sequenceLength > chunkLenght:
            return sequences
        #move the sequence bytes into an own bytestring and append it to the sequence list
        for copyPointer in range(iterator, iterator+sequenceLength):
            bufferSequence += compressedChunk[copyPointer]
        sequences.append(bufferSequence)
        iterator += sequenceLength
    return sequences
























