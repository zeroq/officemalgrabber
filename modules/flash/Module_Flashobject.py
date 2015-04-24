# -*- coding: utf-8 -*-
# vim: tabstop=4 shiftwidth=4 expandtab

import os
import re
import fnmatch
import array
import imp

import core.littleEndian as littleEndian
import core.OleFileIO_PL as OleFileIO_PL


class Flash_Mod:
    pathToActiveX = ''
    fileName = ''
    docType = ''
    mode = 0
    ShockwaveFlashClassID = 'D27CDB6E-AE6D-11CF-96B8-444553540000'

    def __init__(self, fileName, mode, docType, args):
        self.pathToActiveX = './' + fileName.split('.')[0] + docType + '/activeX'
        if mode == 0:
            #XML format case
            self.pathToActiveX = fileName + docType + '/activeX'
        self.fileName = fileName
        self.mode = mode
        self.docType = docType
        self.args = args

    def locateFlashObjects(self):
        pathToActiveX = self.pathToActiveX
        fileName = self.fileName
        docType = self.docType
        foundFlashObject = False

        if self.mode == 0:
            #this is an XML-based document
            activeXContainers = []

            fileNames = []

            for dirname, dirnames, filenames in os.walk(pathToActiveX):
                for filename in filenames:
                    fileNames.append(os.path.join(dirname, filename))

            filtered = fnmatch.filter(fileNames, '*activeX*.xml')

            for activeXcontrol in filtered:
                currentControl = open(activeXcontrol, 'r')
                controlText = currentControl.read()

                #the Class-ID: D27CDB6E-AE6D-11CF-96B8-444553540000 identifies an activeX-control as flash-object
                if self.ShockwaveFlashClassID in controlText:
                    if not self.args.quiet:
                        print activeXcontrol + " is a FlashObject!"
                    foundFlashObject = True
                    activeXBinFileName = activeXcontrol[:-3]
                    activeXBinFileName += 'bin'
                    activeXContainers.append(activeXBinFileName)

                currentControl.close()

            #starting to determine the origin of the .swf file
            if self.docType == '/xl':
                for activeXBinFileName in activeXContainers:
                    acitveXStream = open(activeXBinFileName, 'rb').read()
                    currentOffset = acitveXStream.find('.swf')
                    if currentOffset == -1:
                        currentOffset = acitveXStream.find('.\x00s\x00w\x00f')
                    if currentOffset != -1:
                        pathLength = 5
                        path = '.swf'
                        #reading the path from back to front, since we don't know the length of the path yet
                        while acitveXStream[currentOffset-3:currentOffset] != '\x00\x00\x00':
                            path = acitveXStream[currentOffset-2] + path
                            currentOffset = currentOffset -2
                            pathLength = pathLength+1
                        bytesForPath = littleEndian.readInt(acitveXStream, currentOffset-4)
                        #check if the length of our extracted path matches the 4 bytes in front
                        #of it, (interpreting the 4 bytes as a unsigned integer in littleendian)
                        if bytesForPath == pathLength*2 and not self.args.quiet:
                            print 'path to .swf: ' + path
                if not foundFlashObject and not self.args.quiet:
                    print 'found no Flash-Objects'
                return
            for activeXBinFileName in activeXContainers:
                #make sure that our .bin files are actually OLE-files
                assert OleFileIO_PL.isOleFile(activeXBinFileName)

                ole = OleFileIO_PL.OleFileIO(activeXBinFileName)

                if ole.exists('Contents'):
                    #Flash-files are embedded via activeX-controls, which are located in the "Contens" folder of the OLE-file
                    Contents = ole.openstream('Contents')
                    content = Contents.read()
                    Contents.close()
                else:
                    if not self.args.quiet:
                        print('Contents doesn\'t exsit')
                    ole.close()

                if littleEndian.readShort(content, 24) == 8:
                    #this means the next 4 bytes (little-endian) will tell the length of an unicode string,
                    #which will follow right after the length field
                    pathLength = littleEndian.readInt(content, 26)

                    pathToSWFfile = ''
                    for iterator in range(30, 30+pathLength):
                        if iterator % 2 == 0:
                            #every second byte will be 0x00. Office doesn't allow characters, which would have to use this second byte
                            pathToSWFfile += content[iterator]
                    #print as a hex string, if you need to search manually in the .bin file
                    #print (':'.join(x.encode('hex') for x in pathToSWFfile))
                    if not self.args.quiet:
                        print 'path to swf-file: ' + pathToSWFfile
                else:
                    if not self.args.quiet:
                        print 'this doesn\'t seem to be an unicode string'

                ole.close()
            if not foundFlashObject and not self.args.quiet:
                print 'found no Flash-Objects'
        else:
            #this is a OLE-formated document
            assert OleFileIO_PL.isOleFile(fileName)

            ole = OleFileIO_PL.OleFileIO(fileName)
            if docType == '/word':
                wordDocStream = ole.openstream('WordDocument')
                wordDocBuffer = wordDocStream.read()
                if 'CONTROL ShockwaveFlash.ShockwaveFlash' in wordDocBuffer:
                    if not self.args.quiet:
                        print 'use of Shockwafe Flash detected'
                    foundFlashObject = True
                else:
                    if not foundFlashObject and not self.args.quiet:
                        print 'found no Flash-Objects'
                    return
                listOCXContents = []
                listOLEPaths = ole.listdir()
                #print ole.listdir()
                #find all OCXNAME streams in the word file
                for path in listOLEPaths:
                    if path[len(path)-1] == 'Contents':
                        #print ('/'.join(x for x in path))
                        listOCXContents.append('/'.join(x for x in path))
                for content in listOCXContents:
                    OCXStream = ole.openstream(content)
                    contentBuffer = OCXStream.read()
                    #print contentBuffer
                    currentOffset = contentBuffer.find('.swf')
                    if currentOffset == -1:
                        currentOffset = contentBuffer.find('.\x00s\x00w\x00f')
                    if currentOffset != -1:
                        pathLength = 5
                        path = '.swf'
                        #reading the path from back to front, since we don't know the length of the path yet
                        while contentBuffer[currentOffset-3:currentOffset] != '\x00\x00\x00':
                            path = contentBuffer[currentOffset-2] + path
                            currentOffset = currentOffset -2
                            pathLength = pathLength+1
                        bytesForPath = littleEndian.readInt(contentBuffer, currentOffset-4)
                        #check if the length of our extracted path matches the 4 bytes in front
                        #of it, (interpreting the 4 bytes as a unsigned integer in littleendian)
                        if bytesForPath == pathLength*2:
                            #print 'length does match!'
                            pass
                        if not self.args.quiet:
                            print 'path to .swf: ' + path
                    else:
                        if not self.args.quiet:
                            print 'no .swf found in contents'
                    OCXStream.close()

            elif docType == '/xl':
                excel_structures = imp.load_source('excel_structures', 'modules/OLE_parsing/excel_structures.py')
                #import excel_structures
                ws = excel_structures.workbook(ole)
                foundFlashObject = ws.findFlashObjects()
                pass
            elif docType == '/ppt':
                ppt_structures = imp.load_source('ppt_structures', 'modules/OLE_parsing/ppt_structures.py')
                #import ppt_structures
                ppt_document_stream = ole.openstream('PowerPoint Document').read()
                current_user_stream = ole.openstream('Current User').read()
                ppt_flash = ppt_structures.ppt_container(ppt_document_stream)
                #find externalOleObjectStorage-Ids, which point to a source of Flash
                foundFlashObject = ppt_structures.findShockwaveFlash(ppt_flash)
                folderName = os.path.abspath(self.fileName.split('.')[0])
                if not os.path.exists(folderName):
                    os.makedirs(folderName)

                externalOleObjectStorages = ppt_structures.findExternalOleObjectStorageLocation(current_user_stream, ppt_document_stream)
                if not externalOleObjectStorages:
                    return
                decompressedStorageFiles = ppt_structures.decompressExternalOleObjectStorage(folderName, ppt_document_stream, externalOleObjectStorages)
                #extract paths to Flash-Objects
                currentPersistId = 0
                for oleStorageFile in decompressedStorageFiles:
                    currentStorage = OleFileIO_PL.OleFileIO(oleStorageFile)
                    if not currentStorage.exists('Contents'):
                        currentPersistId += 1
                        continue
                    contentBuffer = currentStorage.openstream('Contents').read()

                    currentOffset = contentBuffer.find('.swf')
                    if currentOffset == -1:
                        currentOffset = contentBuffer.find('.\x00s\x00w\x00f')
                    if currentOffset != -1:
                        pathLength = 5
                        path = '.swf'
                        #reading the path from back to front, since we don't know the length of the path yet
                        while contentBuffer[currentOffset-3:currentOffset] != '\x00\x00\x00':
                            path = contentBuffer[currentOffset-2] + path
                            currentOffset = currentOffset -2
                            pathLength = pathLength+1
                        if not self.args.quiet:
                            print 'path to .swf: ' + path
                    else:
                        if not self.args.quiet:
                            print 'no .swf found in contents'
                    currentStorage.close()
                    currentPersistId += 1
            else:
                if not self.args.quiet:
                    print 'No document type was given'

            if not foundFlashObject and not self.args.quiet:
                    print 'found no Flash-Objects'
            ole.close()
