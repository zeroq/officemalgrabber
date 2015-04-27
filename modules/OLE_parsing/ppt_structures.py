# -*- coding: utf-8 -*-
# vim: tabstop=4 shiftwidth=4 expandtab

import zlib
import os

import core.littleEndian as littleEndian

class rcHeader:
    recVer = 0
    recInstance = 0
    recType = 0
    recLen = 0

    def __init__(self, binaryString):
        temp = littleEndian.readShort(binaryString, 0)
        self.recVer = temp & 0x000f
        self.recInstance = temp >> 4
        self.recType = (ord(binaryString[3]) << 8) + ord(binaryString[2])
        self.recLen = littleEndian.readInt(binaryString, 4)

    def printHeader(self):
        print 'recVersion: 0x%X\r\nrecInstance: 0x%03X\r\nrecType: 0x%04X\r\nrecLength: %d\r\n' \
        %(self.recVer  ,self.recInstance ,self.recType  ,self.recLen)



class record:
    head = None
    binaryHead = None
    binaryData = None
    def __init__(self, binary):
        self.head = rcHeader(binary)
        self.binaryHead = binary[0:8]
        self.binaryData = binary[8:self.head.recLen+8]

        if isinstance(self, ppt_container) or isinstance(self, ppt_atom):
            return
        if self.head.recVer == 0x0f:
            self = ppt_container(binary)
        else:
            self = ppt_atom(binary)

        if isinstance(self, ppt_container):
            print 'I am a container!'
        elif isinstance(self, ppt_atom):
            print 'I am an atom!'
        elif isinstance(self, record):
            print 'Damn! I am just a not further specified record'

    def unfold(self):
        pass
    def printContent(self):
        print 'Oops! You should never see this!'


class ppt_container():
    children = []
    numberOfChilds = 0
    head = None
    binaryHead = None
    binaryData = None
    def __init__(self, binary):
        #fill record header
        self.head = rcHeader(binary)
        self.binaryHead = binary[0:8]
        self.binaryData = binary[8:self.head.recLen+8]
        currentBytePosition = 0


        #add child records, which then fill themselves recursively
        while currentBytePosition < self.head.recLen:
            childHeader = rcHeader(self.binaryData[currentBytePosition:])

            if childHeader.recVer == 0x0f:
                #this child is a subcontainer
                subContainer = ppt_container(self.binaryData[currentBytePosition:currentBytePosition+8+childHeader.recLen])
                self.children = self.children + [subContainer]
                pass
            else:
                #this child is an atom
                atom = ppt_atom(self.binaryData[currentBytePosition:currentBytePosition+8+childHeader.recLen])
                self.children = self.children + [atom]
                pass
            currentBytePosition = currentBytePosition + childHeader.recLen + 8
            self.numberOfChilds = self.numberOfChilds+1


    def printContent(self):
        if self.numberOfChilds == 0: return
        for child in self.children:
            child.printContent()
            pass

    def printStructure(self, level):
        indent = '     '*level
        if self.numberOfChilds == 0: return
        print indent + 'children[%d]'  %self.numberOfChilds
        print indent + '--------->'
        ChildNumber = 0
        for child in self.children:
            print indent + 'ChildNumber: ', ChildNumber
            ChildNumber = ChildNumber+1
            child.printStructure(level+1)
        print indent + '<---------'


class ppt_atom():
    head = None
    binaryHead = None
    binaryData = None
    def __init__(self, binary):
        self.head = rcHeader(binary)
        self.binaryHead = binary[0:8]
        self.binaryData = binary[8:]

    def unfold(self):
        return

    def printStructure(self, level):
        indent = '     '*level
        print indent + 'end of structure'


    def getContent(self):
        if self.head.recType == 0x0FBA:
            cstring = ''
            for index in range(0, self.head.recLen, 2):
                cstring = cstring + self.binaryData[index]
            return cstring
        return self.binaryData

    def printContent(self):
        cstring = self.getContent()
        if self.head.recType == 0x0FBA:
            print cstring
        else:
            print 'data is not printable!'


def findExternalOleObjectStorageLocation(current_user_stream, ppt_document_stream):
    try:
        currentUserAtom = ppt_atom(current_user_stream)
        currentUserAtom.size = littleEndian.readInt(currentUserAtom.binaryData, 0)
        currentUserAtom.headerToken = currentUserAtom.binaryData[4:8]
        currentUserAtom.offsetToCurrentEdit = littleEndian.readInt(currentUserAtom.binaryData, 8)
    except:
        #print 'failed to parse currentUserAtom, file might be corrupted!'
        return None

    if len(ppt_document_stream[currentUserAtom.offsetToCurrentEdit:])<=0:
        #print 'end of stream?'
        return None

    print [ppt_document_stream[currentUserAtom.offsetToCurrentEdit:]]

    userEditAtom = ppt_atom(ppt_document_stream[currentUserAtom.offsetToCurrentEdit:])
    userEditAtom.lastSlieIdRef = userEditAtom.binaryData[0:4]
    userEditAtom.version = littleEndian.readShort(userEditAtom.binaryData, 4)
    userEditAtom.minorVersion = userEditAtom.binaryData[6]
    userEditAtom.majorVersion = userEditAtom.binaryData[7]
    userEditAtom.offsetLastEdit = littleEndian.readInt(userEditAtom.binaryData, 8)
    userEditAtom.offestPersistDirectory = littleEndian.readInt(userEditAtom.binaryData, 12)

    if len(ppt_document_stream[userEditAtom.offestPersistDirectory:])<=0:
        #print 'end of stream'
        return None

    persistDirectoryAtom = ppt_atom(ppt_document_stream[userEditAtom.offestPersistDirectory:])
    persistId16bits = littleEndian.readShort(persistDirectoryAtom.binaryData, 0)
    persistId4bits = (ord(persistDirectoryAtom.binaryData[2]) & 0b00001111) << (8*2)
    persistDirectoryAtom.persistId = persistId4bits + persistId16bits
    persistDirectoryAtom.cPersist = ((ord(persistDirectoryAtom.binaryData[2]) & 0b11110000) >> 4) +\
    (ord(persistDirectoryAtom.binaryData[3]) << 8)
    rgPersistOffset = [None]*persistDirectoryAtom.cPersist
    for PersistOffsetEntry in range(0, persistDirectoryAtom.cPersist):
        rgPersistOffset[PersistOffsetEntry] = littleEndian.readInt(persistDirectoryAtom.binaryData, 4+PersistOffsetEntry*4)

    persistDirectoryAtom.rgPersistOffset = rgPersistOffset

    externalOleObjectStorages = []
    for entry in rgPersistOffset:
        potentialExtOleObjectStg = ppt_atom(ppt_document_stream[entry:])
        if potentialExtOleObjectStg.head.recType == 0x1011:
            externalOleObjectStorages += [entry]
    return externalOleObjectStorages



def decompressExternalOleObjectStorage(folderName, ppt_document_stream, offsets):
    decompressedStorages = []
    for offset in range(0, len(offsets)):
        decompressedOleFilename = os.path.abspath(folderName) + '/compressedStg' + str(offset) + '.ole'

        compressedStorageAtom = ppt_atom(ppt_document_stream[offsets[offset]:])
        decompressed_storage_data = inflate(compressedStorageAtom.binaryData[4:compressedStorageAtom.head.recLen])
        with open(decompressedOleFilename,'wb') as file:
            file.write(decompressed_storage_data)
        decompressedStorages += [decompressedOleFilename]
    return decompressedStorages

def inflate(data):
    decompress = zlib.decompressobj()
    inflated = decompress.decompress(data)
    inflated += decompress.flush()
    return inflated


def findShockwaveFlash(pptDocumentContainer):
    foundFlashObject = False
    listOfPersistIdRefs = []
    #check if a record exists, which fullfills all constraints to be a flash-object
    if pptDocumentContainer.head.recVer == 0xF and pptDocumentContainer.head.recType == 0x03E8:
        for exObjList in pptDocumentContainer.children:
            if exObjList.head.recVer == 0xF and exObjList.head.recType == 0x0409:
                for exControl in exObjList.children:
                    if exControl.head.recVer == 0xF and exControl.head.recType == 0x0FEE:
                        for atom in exControl.children:
                            if atom.head.recVer == 0x0 and atom.head.recType == 0x0FBA:
                                if 'Shockwave' in atom.getContent():
                                    if not foundFlashObject:
                                        #print 'detected use of Shockwave-Flash'
                                        foundFlashObject = True
                                    for externalOleObjectAtom in exControl.children:
                                        if externalOleObjectAtom.head.recType == 0x0FC3:
                                            positionInPersistDirectory = littleEndian.readInt\
                                            (externalOleObjectAtom.getContent(), len(externalOleObjectAtom.getContent())-8)
                                            if not positionInPersistDirectory in listOfPersistIdRefs:
                                                listOfPersistIdRefs += [positionInPersistDirectory]

    else:
        #print 'this doesn\'t seem to be a pptDocumentContainer'
        pass
    return foundFlashObject

def findScriptlets(pptDocumentContainer):
    foundScriptlet = False
    listOfPersistIdRefs = []
    #check if a record exists, which fullfills all constraints to be a scriptlet
    if pptDocumentContainer.head.recVer == 0xF and pptDocumentContainer.head.recType == 0x03E8:
        for exObjList in pptDocumentContainer.children:
            if exObjList.head.recVer == 0xF and exObjList.head.recType == 0x0409:
                for exControl in exObjList.children:
                    if exControl.head.recVer == 0xF and exControl.head.recType == 0x0FEE:
                        for atom in exControl.children:
                            if atom.head.recVer == 0x0 and atom.head.recType == 0x0FBA:
                                if 'Scriptlet' in atom.getContent() or 'ScriptBridge' in atom.getContent():
                                    if not foundScriptlet:
                                        #print 'detected use of MS Scriptlet-Component'
                                        foundScriptlet = True
                                    #return foundScriptlet
                                    for externalOleObjectAtom in exControl.children:
                                        if externalOleObjectAtom.head.recType == 0x0FC3:
                                            positionInPersistDirectory = littleEndian.readInt\
                                            (externalOleObjectAtom.getContent(), len(externalOleObjectAtom.getContent())-8)
                                            if not positionInPersistDirectory in listOfPersistIdRefs:
                                                listOfPersistIdRefs += [positionInPersistDirectory]

    else:
        #print 'this doesn\'t seem to be a pptDocumentContainer'
        pass
    return foundScriptlet

