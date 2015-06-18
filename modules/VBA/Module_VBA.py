# -*- coding: utf-8 -*-
# vim: tabstop=4 shiftwidth=4 expandtab

import array
import imp
import os
import re
from itertools import groupby

import core.littleEndian as littleEndian
import core.OleFileIO_PL as OleFileIO_PL

macroDecoder = imp.load_source('macroDecoder', 'modules/VBA/auxiliary/macroDecoder.py')


class VBA_Mod:
    fileName = ''
    mode = 0
    docType = ''
    def __init__(self, fileName, mode, docType, args, json_result):
        self.fileName = fileName
        self.mode = mode
        self.docType = docType
        self.extractionFolder = args.extractionFolder
        self.args = args
        self.json_result = json_result

    def getCompressedChunkLength(self, blob):
        chunkLength = littleEndian.readShort(blob, 0)
        chunkLength = chunkLength & 0x0fff
        return chunkLength + 3

    def checkMacroCode(self, path):
        try:
            fp = open(path, 'r')
            content = fp.read()
            fp.close()
        except Exception as e:
            if self.args.json:
                pass
            else:
                print e
        # Check for auto_open string in macro
        re_may_obfuscate = re.compile('Chr\(.+?\)', re.I|re.S)
        re_auto_open = re.compile('Sub AutoOpen\(\)', re.I|re.S)
        re_workbook_open = re.compile('Sub Workbook_Open\(\)', re.I|re.S)
        re_may_write_to_file = re.compile('Open .+? For Output As ', re.I|re.S)
        re_may_write_to_file_2 = re.compile('Print #', re.I|re.S)
        re_may_get_files_internet = re.compile('Open "GET"', re.I|re.S)
        re_may_execute_file = re.compile('Shell\(.+?\)', re.I|re.S)
        re_may_read_environment = re.compile('Environ\(.+?\)', re.I|re.S)
        re_may_create_object = re.compile('CreateObject\(.+?\)', re.I|re.S)
        re_may_domain = re.compile('([a-z0-9]{1,30}(?:\.[a-z0-9]{1,30})*?\.(?:[a-z]{2,3}/))|([a-z0-9]{1,30}(?:\.[a-z0-9]{1,30})*?\.(?:com|org|net|mil|edu|de|ir))', re.I|re.S)
        # Eval regexes
        match = re_may_obfuscate.search(content)
        if match:
            if self.args.json:
                self.json_result['signatures'].append({'match': 'Found suspicious keyword "Chr" which indicates: "May attempt to obfuscate specific strings"'})
            else:
                print '>>>> Found suspicious keyword "Chr" which indicates: "May attempt to obfuscate specific strings"'
        match = re_auto_open.search(content)
        if match:
            if self.args.json:
                self.json_result['signatures'].append({'match': 'Found keyword "AutoOpen" which indicates: "Runs when the Word document is opened"'})
            else:
                print '>>>> Found keyword "AutoOpen" which indicates: "Runs when the Word document is opened"'
        match = re_workbook_open.search(content)
        if match:
            if self.args.json:
                self.json_result['signatures'].append({'match': 'Found keyword "Workbook_Open" which indicates: "Runs when the Excel Workbook is opened"'})
            else:
                print '>>>> Found keyword "Workbook_Open" which indicates: "Runs when the Excel Workbook is opened"'
        match = re_may_write_to_file.search(content)
        if match:
            if self.args.json:
                self.json_result['signatures'].append({'match': 'Found suspicious keywords "Open ... For Output" which indicates: "May write to a file"'})
            else:
                print '>>>> Found suspicious keywords "Open ... For Output" which indicates: "May write to a file"'
        match = re_may_write_to_file_2.search(content)
        if match:
            if self.args.json:
                self.json_result['signatures'].append({'match': 'Found suspicious keyword "Print #" which indicates: "May write to a file (if combined with Open)"'})
            else:
                print '>>>> Found suspicious keyword "Print #" which indicates: "May write to a file (if combined with Open)"'
        match = re_may_get_files_internet.search(content)
        if match:
            if self.args.json:
                self.json_result['signatures'].append({'match': 'Found suspicious keyword "GET" which indicates: "May retrieve files from the internet""'})
            else:
                print '>>>> Found suspicious keyword "GET" which indicates: "May retrieve files from the internet"'
        match = re_may_execute_file.search(content)
        if match:
            if self.args.json:
                self.json_result['signatures'].append({'match': 'Found suspicious keyword "Shell" which indicates: "May run an executable file or a system command"'})
            else:
                print '>>>> Found suspicious keyword "Shell" which indicates: "May run an executable file or a system command"'
        match = re_may_read_environment.search(content)
        if match:
            if self.args.json:
                self.json_result['signatures'].append({'match': 'Found suspicious keyword "Environ" which indicates: "May read system environment variables"'})
            else:
                print '>>>> Found suspicious keyword "Environ" which indicates: "May read system environment variables"'
        match = re_may_create_object.search(content)
        if match:
            if self.args.json:
                self.json_result['signatures'].append({'match': 'Found suspicious keyword "CreateObject" which indicates: "May create an OLE object"'})
            else:
                print '>>>> Found suspicious keyword "CreateObject" which indicates: "May create an OLE object"'
        match = re_may_domain.findall(content)
        if match:
            urlpatterns = []
            for item in match:
                if item[0] != '' and item[0] not in urlpatterns:
                    urlpatterns.append(item[0])
                if item[1] != '' and item[1] not in urlpatterns:
                    urlpatterns.append(item[1])
            if self.args.json:
                self.json_result['signatures'].append({'match': 'Found URL like patterns in decoded VBA strings: %s' % (urlpatterns)})
            else:
                print '>>>> Found URL like patterns in decoded VBA strings: %s' % (urlpatterns)

    def extractMacroCode(self):
        foundMacroCode = False
        fileName = self.fileName
        #prefix will vary by OLE or XML mode
        prefix = ''
        if self.mode == 0:
            if not os.path.exists(fileName + self.docType + '/vbaProject.bin'):
                if not self.args.quiet and not self.args.json:
                    print 'no macro-code'
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
                if not self.args.quiet and not self.args.json:
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
                try:
                    codeOffset = ord(decompressedDir[offsets+9]) << 24
                    codeOffset += ord(decompressedDir[offsets+8]) << 16
                    codeOffset += ord(decompressedDir[offsets+7]) << 8
                    codeOffset += ord(decompressedDir[offsets+6])
                except:
                    continue

                listCodeOffsets.append(codeOffset)

            listEncodedMacroCode = []
            current = 0
            for moduleName in listModuleNames:
                codeBuffer = ''
                path = prefix + moduleName

                if ole.exists(path):
                    if not self.args.quiet and not self.args.json:
                        print 'decoding module:', moduleName
                    oleStream = ole.openstream(path)
                    codeBuffer = oleStream.read()
                else:
                    if not self.args.quiet and not self.args.json:
                        print path, 'does\'t exist'

                try:
                    codeBuffer = codeBuffer[listCodeOffsets[current]+1:]
                except IndexError:
                    continue
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

            if not self.extractionFolder:
                folderName1 = self.fileName.rsplit('.', 1)[0]
            elif self.extractionFolder == '.':
                folderName1 = self.fileName.rsplit('/', 1)[1].split('.')[0]
            else:
                folderName1 = os.path.join(self.extractionFolder, self.fileName.rsplit('/', 1)[1].split('.')[0])

            if self.mode == 1:
                #OLE case
                folderName = os.path.abspath(folderName1)
                if not os.path.exists(folderName):
                    os.makedirs(folderName)
            else:
                folderName = folderName1

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
            macro_save_location = os.path.abspath(folderName + '/macroCode.txt')
            if not self.args.quiet:
                if self.args.json:
                    self.json_result['debug'].append('saved macrocode to file: %s' % (macro_save_location))
                else:
                    print 'saved macrocode to file: %s' % (macro_save_location)
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

        if not foundMacroCode and not self.args.quiet and not self.args.json:
            print 'no macro-code'
        elif foundMacroCode:
            if self.args.json:
                self.json_result['detections'].append({'type': 'macro code', 'location': macro_save_location})
            else:
                print '>> macro code detected!'
            self.checkMacroCode(macro_save_location)
