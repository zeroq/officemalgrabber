# -*- coding: utf-8 -*-
# vim: tabstop=4 shiftwidth=4 expandtab

import imp

import core.littleEndian as littleEndian
import core.OleFileIO_PL as OleFileIO_PL

def getNewInstance(fileName, docType):
    return CVE_2010_822_detector(fileName)


class CVE_2010_822_detector:

    def __init__(self, fileName):
        self.ole = None
        #import excel_structures
        self.excel_structures = imp.load_source('excel_structures', 'modules/OLE_parsing/excel_structures.py')
        if OleFileIO_PL.isOleFile(fileName):
            self.ole = OleFileIO_PL.OleFileIO(fileName)
        self.workbook = self.excel_structures.workbook(self.ole)
        if self.ole != None:
            self.ole.close()

    def check(self):
        #if this is an exploit for cve-2010-0822 there will be a pointer
        #in a normally empty data-field
        #this two pointers are most commonly for this exploit: [0x307D91AC, 0x307D908E]
        objRecords = []
        for worksheet in self.workbook.worksheetStreams:
            for binaryRecord in worksheet.records:
                recordHeader = self.excel_structures.BiffRecordHeader(binaryRecord)
                if recordHeader.type == 0x005D:
                    #this is a Obj-Record
                    ObjRecord = self.excel_structures.Obj(binaryRecord[4:])
                    objRecords += [ObjRecord]
        for ObjRecord in objRecords:
            self.checkIfMalformed(ObjRecord)
        for ObjRecord in objRecords:
            unused = []
            unused += [ObjRecord.cmo.unused8]
            unused += [ObjRecord.cmo.unused9]
            unused += [ObjRecord.cmo.unused10]
            for unusedSpace in unused:
                if unusedSpace != 0:
                    #this space should not be used and should be 0x00000000
                    if unusedSpace & 0xFFF00000 == 0x30700000:
                        print 'found exploit for CVE-2010-0822'
                        break

    def checkIfMalformed(self, ObjRecord):
        if ObjRecord.validate() != 0:
            print 'detected malformed Obj-Record'
            print 'file might be an exploit for CVE-2010-0822'
            return



