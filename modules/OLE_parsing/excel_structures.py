# -*- coding: utf-8 -*-
# vim: tabstop=4 shiftwidth=4 expandtab

import core.littleEndian as littleEndian
import core.OleFileIO_PL as OleFileIO_PL

class BiffRecordHeader:
    type = 0x0000
    length = 0x0000

    def __init__(self, binary):
        self.type = littleEndian.readShort(binary, 0)
        self.length = littleEndian.readShort(binary, 2)

class FtCmo:
    ft = 0x0000
    cb = 0x0000
    ot = 0x0000
    id = 0x0000
    bitmap = 0x0000


    def __init__(self, binary):
        if len(binary) != 22:
            print 'length doesn\'t match the length of a regular FtCmo structure'
            return
        self.ft = littleEndian.readShort(binary, 0)
        self.cb = littleEndian.readShort(binary, 2)
        self.ot = littleEndian.readShort(binary, 4)
        self.id = littleEndian.readShort(binary, 6)
        self.bitmap = littleEndian.readShort(binary, 8)
        self.unused8 = littleEndian.readInt(binary, 10)
        self.unused9 = littleEndian.readInt(binary, 14)
        self.unused10 = littleEndian.readInt(binary, 18)
        if self.ft != 0x15 or self.cb != 0x12:
            print 'Error parsing a FtCmo-structure'
            return None

class FtGmo:
    def __init__(self, binary):
        self.ft = littleEndian.readShort(binary, 0)
        self.cb = littleEndian.readShort(binary, 2)
        self.unused = littleEndian.readShort(binary, 4)

    def validate(self):
        if self.ft != 0x0006:
            return -1
        if self.cb != 0x0002:
            return -1
        return 0


class FtCf:
    def __init__(self, binary):
        self.ft = littleEndian.readShort(binary, 0)
        self.cb = littleEndian.readShort(binary, 2)
        self.cf = littleEndian.readShort(binary, 4)

    def validate(self):
        if self.ft != 0x0007:
            return -1
        if self.cb != 0x0002:
            return -1
        if not self.cf in [0x0002, 0x0009, 0xFFFF]:
            return -1
        return 0


class FtCbls:
    def __init__(self, binary):
        self.ft = littleEndian.readShort(binary, 0)
        self.cb = littleEndian.readShort(binary, 2)
        self.unused1 = littleEndian.readInt(binary, 4)
        self.unused2 = littleEndian.readInt(binary, 8)
        self.unused3 = littleEndian.readInt(binary, 12)

    def validate(self):
        if self.ft != 0x000A:
            return -1
        if self.cb != 0x000C:
            return -1
        return 0

class FtRbo:
    def __init__(self, binary):
        self.ft = littleEndian.readShort(binary, 0)
        self.cb = littleEndian.readShort(binary, 2)
        self.unused1 = littleEndian.readInt(binary, 4)
        self.unused2 = littleEndian.readShort(binary, 8)

    def validate(self):
        if self.ft != 0x000B:
            return -1
        if self.cb != 0x0006:
            return -1
        return 0

class FtSbs:
    def __init__(self, binary):
        self.ft = littleEndian.readShort(binary, 0)
        self.cb = littleEndian.readShort(binary, 2)
        self.unused1 = littleEndian.readInt(binary, 4)
        self.iVal = littleEndian.readSignedShort(binary, 8)
        self.iMin = littleEndian.readSignedShort(binary, 10)
        self.iMax = littleEndian.readSignedShort(binary, 12)
        self.dInc = littleEndian.readSignedShort(binary, 14)
        self.dPage = littleEndian.readSignedShort(binary, 16)
        self.fHoriz = littleEndian.readShort(binary, 18)
        self.dxScroll = littleEndian.readSignedShort(binary, 20)
        self.flags = (ord(binary[22]) & 0xf0) >> 4
        self.unused2 = (ord(binary[22]) & 0x0f) << 8
        self.unused2 += ord(binary[23])


    def validate(self):
        if self.ft != 0x000C:
            return -1
        if self.cb != 0x0014:
            return -1
        if self.iVal < self.iMin or self.iVal > self.iMax:
            return -1
        if self.iMax < self.iMin:
            return -1
        if self.dInc < 0 or self.dPage < 0:
            return -1
        if self.fHoriz > 0x01:
            return -1
        if self.dxScroll < 0:
            return -1
        return 0

class FtNts:
    def __init__(self, binary):
        self.ft = littleEndian.readShort(binary, 0)
        self.cb = littleEndian.readShort(binary, 2)
        self.guid = binary[4:20]
        self.fSharedNote = littleEndian.readShort(binary, 20)
        self.unused = littleEndian.readInt(binary, 22)


    def validate(self):
        if self.ft != 0x000D:
            return -1
        if self.cb != 0x0016:
            return -1
        if self.fSharedNote > 0x01:
            return -1
        return 0

class ObjLinkFmla:
    def __init__(self, binary, cmo_ot):
        self.cmo_ot = cmo_ot
        self.ft = littleEndian.readShort(binary, 0)
        self.fmla = ObjFmla(binary[2:])
        self.sizeInBytes = self.fmla.cbFmla+4

    def validate(self):
        if (self.cmo_ot == 0x0B or self.cmo_ot == 0x0C) and self.ft != 0x0014:
            return -1
        if not (self.cmo_ot in [0x10, 0x11, 0x12, 0x14]) and self.ft != 0x000E:
            return -1
        return 0

class FtCblsData:
    def __init__(self, binary):
        self.ft = littleEndian.readShort(binary, 0)
        self.cb = littleEndian.readShort(binary, 2)
        self.fChecked = littleEndian.readShort(binary, 4)
        self.accel = littleEndian.readShort(binary, 6)
        self.reserved = littleEndian.readShort(binary, 8)

    def validate(self):
        if self.ft != 0x000D:
            return -1
        if self.cb != 0x0016:
            return -1
        if self.fChecked < 0x02:
            return -1
        if self.reserved != 0x0000:
            return -1
        return 0

class FtRboData:
    def __init__(self, binary):
        self.ft = littleEndian.readShort(binary, 0)
        self.cb = littleEndian.readShort(binary, 2)
        self.idRadNext = littleEndian.readShort(binary, 4)
        self.fFirstBtn = littleEndian.readShort(binary, 6)

    def validate(self):
        if self.ft != 0x000D:
            return -1
        if self.cb != 0x0016:
            return -1
        if self.fFirstBtn > 0x0001:
            return -1
        return 0

class FtEdoData:
    def __init__(self, binary):
        self.ft = littleEndian.readShort(binary, 0)
        self.cb = littleEndian.readShort(binary, 2)
        self.ivtEdit = littleEndian.readShort(binary, 4)
        self.fMultiLine = littleEndian.readShort(binary, 6)
        self.fScroll = littleEndian.readShort(binary, 8)
        self.id = littleEndian.readShort(binary, 10)

    def validate(self):
        if self.ft != 0x0010:
            return -1
        if self.cb != 0x0006:
            return -1
        if self.ivtEdit > 0x004:
            return -1
        if self.fMultiLine > 0x0001:
            return -1
        if self.fScroll > 0x0001:
            return -1
        return 0

class FtLbsData:
    def __init__(self, binary, cmo_ot):
        self.dropData = None
        self.ft = littleEndian.readShort(binary, 0)
        self.cbFContinued = littleEndian.readShort(binary, 2)
        self.sizeInBytes = 4
        if self.cbFContinued != 0x0000:
            self.fmla = ObjFmla(binary[4:])
            firstByteOfCLines = self.fmla.cbFmla + 2 + 4
            self.cLines = littleEndian.readShort(binary, firstByteOfCLines)
            self.iSel = littleEndian.readShort(binary, firstByteOfCLines + 2)
            ########################
            self.flags = ord(binary[firstByteOfCLines + 4])
            self.lct = littleEndian.readShort(binary, firstByteOfCLines + 5)
            ########################
            #excel documentation is wrong about the combination of flags+lct (MS-XLS p. 717)
            #documentation says, that those two are combined into 2 bytes of data
            #in reality its 1 byte for flags and 2 bytes for lct
            self.idEdit = littleEndian.readShort(binary, firstByteOfCLines + 7)
            firstByteOfDropData = firstByteOfCLines + 9
            firstByteOfRgLines = firstByteOfCLines + 9

            if cmo_ot == 0x0014:
                self.dropData = LbsDropData(binary[firstByteOfDropData:])
                firstByteOfRgLines += self.dropData.sizeInBytes
                self.sizeInBytes = firstByteOfRgLines
            if self.flags & 0b01000000 == 0b01000000:
                self.rgLines = []
                offset = 0
                for element in range(0, self.cLines):
                    self.rgLines += [XLUnicodeString(binary[firstByteOfRgLines+offset:])]
                    if self.rgLines[-1].fHighByte != 0x00:
                        offset += (self.rgLines[-1].cch * 2) + 3
                    else:
                        offset += self.rgLines[-1].cch + 3
                firstByteOfBsels = firstByteOfRgLines + offset
                self.sizeInBytes = firstByteOfBsels
            if self.flags & 0b00001100 != 0x00:
                self.bsels = binary[firstByteOfBsels:firstByteOfBsels + self.cLines]





    def validate(self):
        if self.ft != 0x0013:
            return -1
        if self.cLines > 0x7FFF:
            return -1
        if self.iSel > self.cLines:
            return -1
        if self.dropData != None:
            if self.dropData.validate() != 0:
                return -1
        return 0


class FtGboData:
    def __init__(self, binary):
        self.ft = littleEndian.readShort(binary, 0)
        self.cb = littleEndian.readShort(binary, 2)
        self.accel = littleEndian.readShort(binary, 4)
        self.reserved = littleEndian.readShort(binary, 6)

    def validate(self):
        if self.ft != 0x000F:
            return -1
        if self.cb != 0x0006:
            return -1
        if self.reserved != 0x0000:
            return -1
        return 0

class LbsDropData:
    def __init__(self, binary):
        self.cLine = littleEndian.readShort(binary, 2)
        self.dxMin = littleEndian.readShort(binary, 4)
        self.str = XLUnicodeString(binary[6:])
        self.sizeInBytes = 6 + self.str.sizeInBytes
        if self.str.sizeInBytes % 2 != 0:
            self.sizeInBytes += 1


    def validate(self):
        if self.cLine > 0x7FFF:
            return -1
        if self.dxMin > 0x7FFF:
            return -1
        return 0


class FtPictFmla:
    ft = 0x0000
    cb = 0x0000
    fmla = None
    IposInCtlStm = 0x00000000
    cbBufInCtlStm = 0x00000000

    def __init__(self, binary):
        self.ft = littleEndian.readShort(binary, 0)
        self.cb = littleEndian.readShort(binary, 2)
        if self.ft != 0x0009:
            #print 'Error parsing a FtPictFmla-structure'
            return None
        self.fmla = ObjFmla(binary[4:])
        self.IposInCtlStm = littleEndian.readInt(binary, 6+self.fmla.cbFmla)
        self.cbBufInCtlStm = littleEndian.readInt(binary, 10+self.fmla.cbFmla)


class ObjFmla:
    cbFmla = 0x0000
    fmla = None
    embededInfo = None

    def __init__(self, binary):
        self.cbFmla = littleEndian.readShort(binary, 0)
        if self.cbFmla > 0 and self.cbFmla % 2 == 0:
            self.fmla = ObjectParsedFormula(binary[2:])
            if self.fmla.rgce.ptg == 0x02:
                #create embeded info-structure
                self.embededInfo = PictFmlaEmbededInfo(binary[8+self.fmla.cce:])
                pass



class PictFmlaEmbededInfo:
    ttb = 0x00
    cbClass = 0x00
    stClass = None

    def __init__(self, binary):
        self.ttb = binary[0]
        self.cbClass = binary[1]
        self.stClass = XLUnicodeStringNoCch(binary[3:], ord(self.cbClass))

class XLUnicodeStringNoCch:
    doubleByte = 0x00
    characters = ''

    def __init__(self, binary, length):
        self.doubleByte = ord(binary[0]) >> 7
        if self.doubleByte == 0:
            self.characters = binary[1:1+length]
        else:
            for char in range(1,1+(length*2), 2):
                self.characters = self.characters + binary[char]

class XLUnicodeString:
    def __init__(self, binary):
        self.sizeInBytes = 0
        self.cch = littleEndian.readShort(binary, 0)
        self.fHighByte = ord(binary[2])
        if self.fHighByte > 0x00:
            self.rgb = binary[3:3+(self.cch*2)]
            self.sizeInBytes = 3 + (self.cch * 2)
        else:
            self.rgb = binary[3:(3+self.cch)]
            self.sizeInBytes = 3 + self.cch

class ObjectParsedFormula:
        cce = 0x0000
        rgce = None

        def __init__(self, binary):
            self.cce = (littleEndian.readShort(binary, 0))
            self.rgce = PtgTbl(binary[6:6+self.cce])

class PtgTbl:
    ptg = 0x00
    row = 0x0000
    col = 0x0000

    def __init__(self, binary):
        self.ptg = ord(binary[0])
        if self.ptg != 0x02:
            print 'Error parsing a PtgTbl-structure'
            return None
        col = littleEndian.readShort(binary,1)
        row = littleEndian.readShort(binary,3)

class FtMacro:
    ft = 0x0000
    fmla = None
    sizeInBytes = 0

    def __init__(self, binary):
        self.ft = littleEndian.readShort(binary, 0)
        cbFmla = littleEndian.readShort(binary, 2)
        if self.ft != 0x0004 or cbFmla % 2 != 0:
            self.ft = 0xFFFF
        self.fmla = binary[2:4+cbFmla]
        self.sizeInBytes = 4+cbFmla

class WsBool:
    bitmap = 0x0000
    def __init__(self, binary):
        binary = binary[4:]
        self.bitmap = littleEndian.readShort(binary, 0)

class BOF:
    vers = 0x0000
    dt = 0x0000
    rupBuild = 0x0000
    rupYear = 0x0000
    bitmap = 0x00000
    reserved1 = 0x000
    verLowestBiff = 0x0
    bitmap2 = 0x0
    reserved2 = 0x000

    def __init__(self, binary):
        binary = binary[4:]
        self.vers =  littleEndian.readShort(binary, 0)
        self.dt =  littleEndian.readShort(binary, 2)
        self.rupBuild =  littleEndian.readShort(binary, 4)
        self.rupYear =  littleEndian.readShort(binary, 6)
        self.bitmap = (littleEndian.readInt(binary, 8)) & int('11111111111111111110000000000000',2)
        self.verLowestBiff = binary[12]
        self.bitmap2 = ord(binary[13]) & int('11110000',2)

class Obj:


    def __init__(self, binary):
        self.cmo = None
        self.gmo = None
        self.pictFormat = 0x000000
        self.pictFlags = 0x000000
        self.cbls = None
        self.rbo = None
        self.sbs = None
        self.nts = None
        self.marcro = None
        self.pictFmla = None
        self.linkFmla = None
        self.checkBox = None
        self.radioButton = None
        self.edit = None
        self.list = None
        self.gbo = None
        self.reserved = None


        self.cmo = FtCmo(binary[0:22])
        offset = 22

        #fixed length structures
        if self.cmo.ot == 0x00:
            self.gmo = FtGmo(binary[offset:offset+6])
            offset += 6
        elif self.cmo.ot == 0x08:
            #skipping the pictFormat and pictFlags structures
            offset += 12
        elif self.cmo.ot == 0x0B:
            self.cbls = FtCbls(binary[offset:offset+16])
            offset += 16
        elif self.cmo.ot == 0x0C:
            self.cbls = FtCbls(binary[offset:offset+16])
            self.rbo = FtRbo(binary[offset+16:offset+26])
            offset += 26
        elif self.cmo.ot in [0x10, 0x11, 0x12, 0x14]:
            self.sbs = FtSbs(binary[offset:offset+24])
            offset += 24
        elif self.cmo.ot == 0x19:
            self.nts = FtNts(binary[offset:offset+26])
            offset += 26

        #the macro structure may be present regardless of the value of cmo.ot
        self.macro = FtMacro(binary[offset:])
        if self.macro.ft == 0x0004:
            offset = offset + self.macro.sizeInBytes
        else:
            self.macro = None

        #variable length structures
        if self.cmo.ot == 0x08:
            self.pictFmla = FtPictFmla(binary[offset:])
            if self.pictFmla.ft == 0x0009:
                offset += (4 + self.pictFmla.cb)
            else:
                self.pictFmla = None
        elif self.cmo.ot in [0x0B, 0x0C, 0x10, 0x11, 0x12, 0x14]:
            try:
                self.linkFmla = ObjLinkFmla(binary[offset:], self.cmo.ot)
                if self.linkFmla.ft in [0x14, 0x0E]:
                    offset += self.linkFmla.sizeInBytes
                else:
                    self.linkFmla = None
            except IndexError:
                #there is no linkFmla present in this Obj-Record
                #do nothing
                pass


        if self.cmo.ot == 0x0B:
            self.checkBox = FtCblsData(binary[offset:offset+12])
            self.offset += 12
        elif self.cmo.ot == 0x0C:
            self.checkBox = FtCblsData(binary[offset:offset+12])
            self.radioButton = FtRboData(binary[offset+12:offset+20])
            self.offset += 20
        elif self.cmo.ot == 0x0D:
            self.edit = FtEdoData(binary[offset:offset+12])
            offset += 12

        elif self.cmo.ot in [0x12, 0x14]:
            self.list = FtLbsData(binary[offset:], self.cmo.ot)
            offset += self.list.sizeInBytes


    def validate(self):
        if self.sbs != None:
            if self.sbs.validate() != 0:
                return -1
        if self.list != None:
            if self.list.validate() != 0:
                return -1
        return 0


class workbook:
    worksheetStreams = []
    workbookStream = ''
    oleObject = None
    offset = 0
    def __init__(self, oleObject):
        self.oleObject = oleObject
        self.workbookStream = (oleObject.openstream('Workbook')).read()
        #find all worksheets in the excel-file
        self.worksheetStreams.append(worksheet(self.workbookStream, self.offset))

        while self.worksheetStreams[-1].currentIndex < len(self.workbookStream):
            self.worksheetStreams.append(worksheet(self.workbookStream, self.worksheetStreams[-1].currentIndex))


    def findFlashObjects(self):
        foundFlashObject = False
        for worksheet in self.worksheetStreams:
            #get all flash-objects for the previously extracted worksheets
            found = worksheet.findFlashObjects(self.oleObject)
            if not foundFlashObject:
                foundFlashObject = found
        return foundFlashObject

    def findScriptlets(self):
        foundScriptlet = False
        for worksheet in self.worksheetStreams:
            #get all flash-objects for the previously extracted worksheets
            found = worksheet.findScriptlets(self.oleObject)
            if found:
                foundScriptlet = True
        if foundScriptlet:
            print 'detected use of MS Scriptlet-Component'
        return foundScriptlet

class worksheet:
    records = []
    currentIndex = 0
    def __init__(self, workbookStream, currentIndex):
        self.currentIndex = currentIndex
        self.records = []
        self.currentIndex = self.getRecords(workbookStream, self.currentIndex)

        #make sure that a new substream starts at the given offset(=currentIndex)
        substreamIdentifier = BOF(self.records[0])
        if substreamIdentifier.dt == 0x0010:
            for record in self.records:
                wsBoolRecord = BiffRecordHeader(record)
                if wsBoolRecord.type == 129 and wsBoolRecord.length == 2:
                    wsBool = WsBool(record)
                    if (wsBool.bitmap & int('0010000000000000',2)) == int('0010000000000000',2):
                        #print 'found a dialog stream'
                        #self.currentIndex = len(workbookStream)
                        #print 'currentIndex befor return: ',  self.currentIndex
                        pass
                    else:
                        #print 'found a worksheet stream'
                        #print 'currentIndex before return: ',  self.currentIndex
                        pass
                        return


    def getRecords(self, workbookStream, currentIndex):
        #read every record in the given workbookstream and add them to the record list
        #until a EOF record is read(EOF record is 4 bytes long and exactly 0x0000000A)
        while littleEndian.readInt(workbookStream, currentIndex) != 0x0000000A:
            recHeader = BiffRecordHeader(workbookStream[currentIndex:currentIndex+4])
            #add current record to records-list
            #keep in mind: records are still unformated (binary data)
            self.records.append(workbookStream[currentIndex:currentIndex + recHeader.length + 4])
            currentIndex = currentIndex + recHeader.length + 4
        currentIndex = currentIndex + 4
        if currentIndex >= len(workbookStream) -1:
            return currentIndex
        #check if another substream starts at the end of this stream. just a safety measure
        recHeader = BiffRecordHeader(workbookStream[currentIndex:currentIndex+4])
        if recHeader.type == 2057 and recHeader.length == 16:
            #print 'found start of second substream at offset: %d  (0x%08X)' %(currentIndex, currentIndex)
            pass
        else:
            #print 'found data:\r\nType: %d Length: %d' %(recHeader.type, recHeader.length)
            pass
        return currentIndex

    def findFlashObjects(self, oleObject):
        foundFlashObject = False
        for binaryRecord in self.records:
            record = BiffRecordHeader(binaryRecord)
            if record.type == 93:
                try:
                    objectRecord = Obj(binaryRecord[4:])
                    #check if a found obj-record has a pictFmla, which is mandatory for flash-objects
                    if objectRecord.cmo.ot == 0x08:
                        if objectRecord.pictFmla.fmla.fmla.rgce.ptg == 0x02 and \
                        'Shockwave' in objectRecord.pictFmla.fmla.embededInfo.stClass.characters:
                            #get offset of the associated acitveX control in the "ctls"-stream
                            ctlsStream = oleObject.openstream('Ctls').read()[objectRecord.pictFmla.IposInCtlStm:\
                            objectRecord.pictFmla.IposInCtlStm+objectRecord.pictFmla.cbBufInCtlStm]
                            #look for ".swf" suffix and extract path (relative or absolute) to the embedded flash-file
                            currentOffset = ctlsStream.find('.swf')
                            if currentOffset == -1:
                                currentOffset = ctlsStream.find('.\x00s\x00w\x00f')
                            if currentOffset != -1:
                                pathLength = 5
                                path = '.swf'
                                #reading the path from back to front, since we don't know the length of the path yet
                                while ctlsStream[currentOffset-3:currentOffset] != '\x00\x00\x00':
                                    path = ctlsStream[currentOffset-2] + path
                                    currentOffset = currentOffset -2
                                    pathLength = pathLength+1
                                bytesForPath = littleEndian.readInt(ctlsStream, currentOffset-4)
                                #check if the length of our extracted path matches the 4 bytes in front
                                #of it, (interpreting the 4 bytes as a unsigned integer in littleendian)
                                if bytesForPath == pathLength*2:
                                    print 'path to .swf: ' + path
                            foundFlashObject = True
                except AttributeError:
                    pass
        return foundFlashObject


    def findScriptlets(self, oleObject):
        foundScriptlet = False
        binaryClassID = '\xAE\xFD\x24\xAE\xC6\x03\xD1\x11\x8B\x76\x00\x80\xC7\x44\xF3\x89'
        for binaryRecord in self.records:
            record = BiffRecordHeader(binaryRecord)
            if record.type == 93:
                try:
                    objectRecord = Obj(binaryRecord[4:])
                    #check if a found obj-record has a pictFmla, which is mandatory for scriptlet-controls
                    if objectRecord.cmo.ot == 0x08:
                        if objectRecord.pictFmla.fmla.fmla.rgce.ptg == 0x02 and \
                        'ScriptBridge' in objectRecord.pictFmla.fmla.embededInfo.stClass.characters:
                            #get offset of the associated acitveX control in the "ctls"-stream
                            ctlsStream = oleObject.openstream('Ctls').read()[objectRecord.pictFmla.IposInCtlStm:\
                            objectRecord.pictFmla.IposInCtlStm+objectRecord.pictFmla.cbBufInCtlStm]

                            pathToSourceFile = ''
                            if ctlsStream[0:16] == binaryClassID:
                                #a scriptlet-control will start with a 128-bit signature (ClsID)
                                pathLength = littleEndian.readInt(ctlsStream, 18)
                                for character in range(22, 22+(pathLength*2), 2):
                                    pathToSourceFile = pathToSourceFile + ctlsStream[character]
                                foundScriptlet = True
                                print 'path to source file: ', pathToSourceFile
                except AttributeError:
                    pass
        return foundScriptlet

