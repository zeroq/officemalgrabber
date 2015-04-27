# -*- coding: utf-8 -*-
# vim: tabstop=4 shiftwidth=4 expandtab

import os
import fnmatch
import imp

import core.littleEndian as littleEndian
import core.OleFileIO_PL as OleFileIO_PL

class JS_Mod:
    pathToActiveX = ''
    fileName = ''
    docType = ''
    mode = 0
    MSscriptletClassID = 'AE24FDAE-03C6-11D1-8B76-0080C744F389'

    def __init__(self, fileName, mode, docType, args, json_result):
        self.pathToActiveX = './' + fileName.split('.')[0] + docType + '/activeX'
        if mode == 0:
            #XML format case
            self.pathToActiveX = fileName + docType + '/activeX'
        self.fileName = fileName
        self.mode = mode
        self.docType = docType
        self.args = args
        self.json_result = json_result
        self.locations = []

    def locateJavascriptSource(self):
        foundScripttlet = False
        if self.mode == 0:
            controlTag = '<ax:ocxPr ax:name="URL" ax:value="'
            activeXContainers = []

            fileNames = []

            for dirname, dirnames, filenames in os.walk(self.pathToActiveX):
                for filename in filenames:
                    fileNames.append(os.path.join(dirname, filename))

            filtered = fnmatch.filter(fileNames, '*activeX*.xml')

            for activeXcontrol in filtered:
                currentControl = open(activeXcontrol, 'r')
                controlText = currentControl.read()

                #the Class-ID: AE24FDAE-03C6-11D1-8B76-0080C744F389 identifies an activeX-control as flash-object
                if self.MSscriptletClassID in controlText:
                    foundScripttlet = True
                    if not self.args.quiet:
                        print activeXcontrol + ' is a MS-Scriptlet!'
                    activeXBinFileName = activeXcontrol[:-3]
                    activeXBinFileName += 'bin'
                    activeXContainers.append(activeXBinFileName)
                    if controlTag in controlText:
                        codeOrigin = ''
                        tagStart = controlText.index(controlTag)
                        iterator = tagStart + len(controlTag)
                        while controlText[iterator] != '"':
                            codeOrigin = codeOrigin + controlText[iterator]
                            iterator = iterator + 1
                        print codeOrigin


                currentControl.close()
        else:
            binaryClassID = '\xAE\xFD\x24\xAE\xC6\x03\xD1\x11\x8B\x76\x00\x80\xC7\x44\xF3\x89'
            assert OleFileIO_PL.isOleFile(self.fileName)
            ole = OleFileIO_PL.OleFileIO(self.fileName)
            if self.docType == '/word':
                wordDocStream = ole.openstream('WordDocument')
                wordDocBuffer = wordDocStream.read()
                if 'CONTROL ScriptBridge.ScriptBridge' in wordDocBuffer:
                    if not self.args.quiet:
                        print 'use of MS Scriptlet detected'

                    listOCXContents = []
                    listOLEPaths = ole.listdir()
                    #find all OCXNAME streams in the word file
                    for path in listOLEPaths:
                        if path[len(path)-1] == '\x03OCXDATA':
                            listOCXContents.append('/'.join(x for x in path))
                    for content in listOCXContents:
                        OCXStream = ole.openstream(content)
                        contentBuffer = OCXStream.read()
                        if contentBuffer[0:16] == binaryClassID:
                            foundScripttlet = True
                            pathToSourceFile = ''
                            pathLength = littleEndian.readInt(contentBuffer, 18)
                            for character in range(22, 22+(pathLength*2), 2):
                                pathToSourceFile = pathToSourceFile + contentBuffer[character]
                            if not self.args.quiet:
                                print 'path to source file: ', pathToSourceFile
                            if self.args.json:
                                self.locations.append(pathToSourceFile)
                        OCXStream.close()

            elif self.docType == '/xl':
                excel_structures = imp.load_source('excel_structures', 'modules/OLE_parsing/excel_structures.py')
                ws = excel_structures.workbook(ole)
                foundScripttlet = ws.findScriptlets()
            elif self.docType == '/ppt':
                ppt_structures = imp.load_source('ppt_structures', 'modules/OLE_parsing/ppt_structures.py')
                ppt_document_stream = ole.openstream('PowerPoint Document').read()
                current_user_stream = ole.openstream('Current User').read()
                ppt_scriptlet = ppt_structures.ppt_container(ppt_document_stream)
                foundScripttlet = ppt_structures.findScriptlets(ppt_scriptlet)
                if foundScripttlet:
                    folderName = os.path.abspath(self.fileName.split('.')[0])
                    if not os.path.exists(folderName):
                        os.makedirs(folderName)

                    externalOleObjectStorages = ppt_structures.findExternalOleObjectStorageLocation(current_user_stream, ppt_document_stream)
                    if not externalOleObjectStorages:
                        return
                    decompressedStorageFiles = ppt_structures.decompressExternalOleObjectStorage(folderName, ppt_document_stream, externalOleObjectStorages)
                    for oleStorageFile in decompressedStorageFiles:
                        currentStorage = OleFileIO_PL.OleFileIO(oleStorageFile)
                        if not currentStorage.exists('\x03OCXDATA'):
                            continue
                        OCXStream = currentStorage.openstream('\x03OCXDATA')
                        contentBuffer = OCXStream.read()
                        if contentBuffer[0:16] == binaryClassID:
                            foundScripttlet = True
                            pathToSourceFile = ''
                            pathLength = littleEndian.readInt(contentBuffer, 18)
                            for character in range(22, 22+(pathLength*2), 2):
                                pathToSourceFile = pathToSourceFile + contentBuffer[character]
                            if not self.args.quiet:
                                print 'path to source file: ', pathToSourceFile
                            if self.args.json:
                                self.locations.append(pathToSourceFile)
                        OCXStream.close()
                        currentStorage.close()

        if not foundScripttlet and not self.args.quiet and not self.args.json:
            print 'no Javascript/Scriptlett detected'
        if foundScripttlet:
            if self.args.json:
                self.json_result['detections'].append({'type': 'javascript/scriptlett', 'location': self.locations})
