# -*- coding: utf-8 -*-
# vim: tabstop=4 shiftwidth=4 expandtab

import imp

import core.littleEndian as littleEndian
import core.OleFileIO_PL as OleFileIO_PL

def getNewInstance(fileName, docType, extractionFolder, args, json_result):
    return CVE_2010_1246_detector(fileName, extractionFolder, args, json_result)

class CVE_2010_1246_detector:

    def __init__(self, fileName, extractionFolder, args, json_result):
        self.ole = None
        self.json_result = json_result
        self.args = args
        #import excel_structures
        self.excel_structures = imp.load_source('excel_structures', 'modules/OLE_parsing/excel_structures.py')
        if OleFileIO_PL.isOleFile(fileName):
            self.ole = OleFileIO_PL.OleFileIO(fileName)
        self.workbook = self.excel_structures.workbook(self.ole)
        if self.ole != None:
            self.ole.close()

    def check(self):
        for worksheet in self.workbook.worksheetStreams:
            for binaryRecord in worksheet.records:
                recordHeader = self.excel_structures.BiffRecordHeader(binaryRecord)
                if recordHeader.type == 0x0813:
                    #this is a RTD-Record
                    rtdRecord = RTD_Record(binaryRecord[4:], self.args, self.json_result)
                    rtdRecord.checkIfMalformed()


class RTD_Record:
    def __init__(self, binary, args, json_result):
        self.args = args
        self.json_result = json_result
        self.frtHeader = frtHeader(binary) #12 bytes
        self.ichSamePrefix = littleEndian.readInt(binary, 12) #4 bytes
        self.XLUnicodeStringSegmentedRTD = XLUnicodeStringSegmentedRTD(binary[16:])
        self.rtdOper = rtdOper(binary[self.XLUnicodeStringSegmentedRTD.lengthInBytes:])

    def checkIfMalformed(self):
        if self.frtHeader.valitdate() != 0:
            if not self.args.json:
                print 'detected malformed RTD-Record'
                print 'file might be an exploit for CVE-2010-1246'
            else:
                self.json_result['signatures'].append({'match': 'cve-2010-1246'})
            return
        if self.XLUnicodeStringSegmentedRTD.valitdate() != 0:
            if not self.args.json:
                print 'detected malformed RTD-Record'
                print 'file might be an exploit for CVE-2010-1246'
            else:
                self.json_result['signatures'].append({'match': 'cve-2010-1246'})
            return
        if self.rtdOper.valitdate() != 0:
            if not self.args.json:
                print 'detected malformed RTD-Record'
                print 'file might be an exploit for CVE-2010-1246'
            else:
                self.json_result['signatures'].append({'match': 'cve-2010-1246'})
            return

class frtHeader:
    def __init__(self, binary):
        self.rt = littleEndian.readShort(binary, 0) #MUST be 0x0813
        self.grbitFrt = littleEndian.readShort(binary, 2) #MUST be 0x0000
        self.reserved1 = littleEndian.readInt(binary, 4) #MUST be 0x00000000
        self.reserved2 = littleEndian.readInt(binary, 8) #MUST be 0x00000000

    def valitdate(self):
        if self.rt != 0x0813:
            return -1
        if self.grbitFrt != 0x0000:
            return -1
        if self.reserved1 != 0x00000000 or self.reserved2 != 0x00000000:
            return -1
        return 0

class XLUnicodeStringSegmentedRTD:
    def __init__(self, binary):
        self.cch = littleEndian.readInt(binary, 0)
        self.fHighByte = ord(binary[4])
        if self.fHighByte == 0x00:
            self.rgb = binary[5:5+self.cch]
        elif self.fHighByte == 0x01:
            self.rgb = binary[5:5+(self.cch*2)]
        else:
            #malformed RTD-Record validate will fail
            pass
        self.lengthInBytes = 5 + (self.cch << self.fHighByte)

    def valitdate(self):
        if self.fHighByte > 0x1:
            return -1

        return 0


class rtdOper:
    def __init__(self, binary):
        self.grbit = littleEndian.readInt(binary, 0)

        if self.grbit == 0x0010 or self.grbit == 0x0800:
            #self.rtdVt is a 4 byte integer
            self.rtdVt = littleEndian.readInt(binary,4)
            self.lengthInBytes = 8
        elif self.grbit == 0x0004:
            #self.rdtVt is a 4 byte boolean
            self.rtdVt = binary[4:8]
            self.lengthInBytes = 8
        elif self.grbit == 0x0001:
            #self.rdtVt is a 64 bit floating point number
            self.rtdVt = binary[4:12]
            self.lengthInBytes = 12
        elif self.grbit == 0x0002:
            #self.rdtVt is a RDTOpenStr, which MUST be less then 256 characters long
            strLength = littleEndian.readInt(binary, 4)
            self.rdtVT = excel_structures.XLUnicodeStringNoCch(binary[8:], strLength)
            self.lengthInBytes = (strLength << self.rtdVt.doubleByte) + 1
        elif self.grbit == 0x1000:
            #self.rdtVt is a RDTOpenStr, which MUST be at least 256 characters long
            strLength = littleEndian.readInt(binary, 4)
            self.rdtVT = excel_structures.XLUnicodeStringNoCch(binary[8:], strLength)
            self.lengthInBytes = (strLength << self.rtdVt.doubleByte) + 1

    def valitdate(self):
        if not self.grbit in [0x01, 0x02, 0x04, 0x10, 0x800, 0x1000]:
            return -1
        if self.grbit == 0x0002 and self.strLength > 255:
            return -1
        if self.grbit == 0x1000 and self.strLength < 256:
            return -1

        return 0

