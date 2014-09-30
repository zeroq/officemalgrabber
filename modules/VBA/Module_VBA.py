# -*- coding: utf-8 -*-
# vim: tabstop=4 shiftwidth=4 expandtab

import array
import imp
import os

import core.littleEndian as littleEndian
import core.OleFileIO_PL as OleFileIO_PL

macroDecoder = imp.load_source('macroDecoder', 'modules/VBA/auxiliary/macroDecoder.py')


class VBA_Mod:
    fileName = ''
    mode = 0
    docType = ''
    def __init__(self, fileName, mode, docType):
        self.fileName = fileName
        self.mode = mode
        self.docType = docType

    def getCompressedChunkLength(self, blob):
        chunkLength = littleEndian.readShort(blob, 0)
        chunkLength = chunkLength & 0x0fff
        return chunkLength + 3


    def extractMacroCode(self):
        foundMacroCode = False
        fileName = self.fileName
        #prefix will vary by OLE or XML mode
        prefix = ''
        if self.mode == 0:
            if not os.path.exists(fileName + self.docType + '/vbaProject.bin'):
                print 'found no macro-code'
                return
            assert OleFileIO_PL.isOleFile(fileName + self.docType + '/vbaProject.bin')

            ole = OleFileIO_PL.OleFileIO(fileName + self.docType + '/vbaProject.bin')
            prefix = 'VBA/'
            oleFileList = [ole]

        else:
            assert OleFileIO_PL.isOleFile(fileName)

            ole = OleFileIO_PL.OleFileIO(fileName)
            oleFileList = [ole]
            if self.docType == '/xl':
                prefix = '_VBA_PROJECT_CUR/VBA/'
            elif self.docType == '/word':
                prefix = 'Macros/VBA/'
            elif self.docType == '/ppt':
                prefix = 'VBA/'
                print 'extracting VBA-Storage...'
                current_user_stream = ole.openstream('Current User').read()
                document_stream = ole.openstream('PowerPoint Document').read()
                ppt_structures = imp.load_source('ppt_structures', 'modules/OLE_parsing/ppt_structures.py')

                folderName = os.path.abspath(self.fileName.split('.')[0])
                if not os.path.exists(folderName):
                    os.makedirs(folderName)
                externalOleObjectStorages = ppt_structures.findExternalOleObjectStorageLocation(current_user_stream, document_stream)
                if externalOleObjectStorages != None:
                    decompressedStorageFiles = ppt_structures.decompressExternalOleObjectStorage(folderName, document_stream, externalOleObjectStorages)
                    ole.close()
                    oleFileList = []
                    for externalOleObjectStorage in decompressedStorageFiles:
                        openOleFile = OleFileIO_PL.OleFileIO(externalOleObjectStorage)
                        oleFileList += [openOleFile]


        for ole in oleFileList:

            if ole.exists(prefix+'dir'):
                    dir = ole.openstream(prefix+'dir')
                    content = dir.read()
                    dir.close()

            else:
                ole.close()
                continue

            moduleOffsetRecordIdentifier = '\x31\x00\x04\x00\x00\x00'
            moduleNameRecordIdentifier = '\x19\x00'

            decompressedDir = ''
            dirSequences = []

            dirSequences = macroDecoder.getSequences(content[1:])

            #decode dir-stream in order to find metadata about the macro streams
            for sequence in dirSequences:
                decompressedDir = macroDecoder.decodeSequence(decompressedDir, sequence)

            #find all Module Offset Records
            current = 0
            listModuleOffsetRecords = []
            while decompressedDir.find(moduleOffsetRecordIdentifier, current) != -1:
                foundAt = decompressedDir.find(moduleOffsetRecordIdentifier, current)
                listModuleOffsetRecords.append(foundAt)
                current = foundAt+1


            #find the name of the modules/streams corresponding to the found Module Offsets
            listModuleNames = []
            start = 0
            for count in range(0,len(listModuleOffsetRecords)):
                moduleName = ''
                index = decompressedDir.rfind(moduleNameRecordIdentifier, start, listModuleOffsetRecords[count])
                nameLength = ord(decompressedDir[index+5]) << 24
                nameLength += ord(decompressedDir[index+4]) << 16
                nameLength += ord(decompressedDir[index+3]) << 8
                nameLength += ord(decompressedDir[index+2])
                for nameCharacter in range(0,nameLength):
                    moduleName += decompressedDir[index + 6 + nameCharacter]
                listModuleNames.append(moduleName)
                start = listModuleOffsetRecords[count]


            #find the Offsets in the Module Streams, where the textual reprensentation of the macrocode starts
            listCodeOffsets = []
            for offsets in listModuleOffsetRecords:
                codeOffset = ord(decompressedDir[offsets+9]) << 24
                codeOffset += ord(decompressedDir[offsets+8]) << 16
                codeOffset += ord(decompressedDir[offsets+7]) << 8
                codeOffset += ord(decompressedDir[offsets+6])

                listCodeOffsets.append(codeOffset)


            listEncodedMacroCode = []
            current = 0
            for moduleName in listModuleNames:
                codeBuffer = ''
                path = prefix + moduleName

                if ole.exists(path):
                    print 'decoding module:', moduleName
                    oleStream = ole.openstream(path)
                    codeBuffer = oleStream.read()
                else:
                    print path, 'does\'t exist'

                codeBuffer = codeBuffer[listCodeOffsets[current]+1:]
                chunkList = []
                #find all chunks, which follow after each other
                #0x00 will be at the end of the last chunk
                while len(codeBuffer) > 0 and codeBuffer[0] != 0x00:
                    chunkLength = littleEndian.readShort(codeBuffer, 0)
                    chunkLength = (chunkLength & 0x0fff) + 3
                    currentChunk = codeBuffer[:chunkLength]
                    codeBuffer = codeBuffer[chunkLength:]
                    listEncodedMacroCode.append(currentChunk)

                    current += 1
                oleStream.close()

            folderName = self.fileName

            if self.mode == 1:
                #OLE case
                folderName = os.path.abspath(self.fileName.split('.')[0])
                if not os.path.exists(folderName):
                    os.makedirs(folderName)


            decodedMacroCode = open(os.path.abspath(folderName + '/macroCode.txt'), 'a')
            codeSequences = []
            for encodedSequences in listEncodedMacroCode:
                codeSequences = macroDecoder.getSequences(encodedSequences)


                decompressedMacroCode = ''
                for sequence in codeSequences:

                    decompressedMacroCode = macroDecoder.decodeSequence(decompressedMacroCode, sequence)
                decodedMacroCode.write(decompressedMacroCode)
                decodedMacroCode.write('\r\n\r\n\r\n\r\n')

            decodedMacroCode.close()
            print 'saved macrocode to file:', os.path.abspath(folderName + '/macroCode.txt')
            foundMacroCode = True

            '''blackList = ["kernel32" , "CreateThread", "VirtualAlloc", "RtlMoveMemory"]
            binaryFile = open("vbaProject.bin", "rb")   #open .bin-file in binary mode
            text = binaryFile.read()                    #and read into variable
            allBadWords = True

            for badword in blackList:                   #check if every 'badword' occurs in the vba-file
                #print(badword)
                if (badword.encode("cp1252")).lower() not in text.lower():      #we use cp1252 encoding, as it is the
                    #print("didn't find " + badword + " in the file")           #default encoding for windows systems
                    allBadWords = False
            if allBadWords == True:
                #print("found the whole badWord-List!")
                pass'''

            ole.close()

        if not foundMacroCode:
            print 'found no macro-code'
