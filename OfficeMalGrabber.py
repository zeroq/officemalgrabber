#!/usr/bin/python2.7
# -*- coding: utf-8 -*-
# vim: tabstop=4 shiftwidth=4 expandtab

import zipfile
import os.path
import sys
import imp
import argparse
import textwrap

import core.littleEndian as littleEndian
import core.OleFileIO_PL as OleFileIO_PL




def unzip(path, extractionFolder):
    extractionFolder = os.path.abspath(extractionFolder)
    tempString = extractionFolder
    if not os.path.exists(extractionFolder):
        os.makedirs(extractionFolder)

    zfile = zipfile.ZipFile(path)

    for name in zfile.namelist():
        (dirname, filename) = os.path.split(name)
        if filename == '':
            continue
        parts = dirname.rsplit('/')
        for subFolder in parts:
            if not os.path.exists(tempString + "/" + subFolder):
                os.makedirs(tempString + "/" + subFolder)
            tempString += ("/" + subFolder)
        tempString = extractionFolder
        fd = open(tempString + "/" + name, 'wb')
        fd.write(zfile.read(name))
        fd.close()
    zfile.close()

def getFat(binaryContent, sectorsize):
    #buf = None
    #with open(fileName, 'rb') as file:
    #   buf = file.read()
    header = binaryContent[76:sectorsize]
    fatSectors = []
    current = 0
    fatSect = littleEndian.readInt(header, current)
    while not fatSect in (0xFFFFFFFEL, 0xFFFFFFFFL) and current < 512:
        fatSectors += [fatSect+1]
        current += 4
        fatSect = littleEndian.readInt(header, current)


    myFat = []
    for fatSect in fatSectors:
        current = 0
        sect = binaryContent[fatSect*sectorsize:(fatSect+1)*sectorsize]
        while current < sectorsize:
            if littleEndian.readInt(sect, current) != 0xffffffff:
                myFat += [littleEndian.readInt(sect, current)]
            current += 4
    return myFat



if __name__ == '__main__':
    helpText = '''
    --fileName {name of file to scan for malware}
    -f         {name of file to scan for malware}

    --recursive {folder to scan for office malware}
    -r          {folder to scan for office malware}

    --extractionFolder {folder to use, if files are created/unzipped during scan}
    -e                 {folder to use, if files are created/unzipped during scan}
    '''
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
    description=textwrap.dedent(helpText))
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--fileName','-f', type=str)
    group.add_argument('--recursive', '-r', type=str)
    parser.add_argument('--extractionFolder', '-e', type=str, default='.')
    args = parser.parse_args()
    filesToScan = []
    if not args.recursive and not args.fileName:
        parser.print_help()
        sys.exit()
    if args.recursive:
        for dirname, dirnames, filenames in os.walk(args.recursive):
            for file in filenames:
                filesToScan.append(os.path.abspath(os.path.join(dirname, file)))
    else:
        filesToScan = [args.fileName]



    for fileName in filesToScan:
        #[PL]: added constants for Sector IDs (from AAF specifications)
        MAXREGSECT = 0xFFFFFFFAL; # maximum SECT
        DIFSECT    = 0xFFFFFFFCL; # (-4) denotes a DIFAT sector in a FAT
        FATSECT    = 0xFFFFFFFDL; # (-3) denotes a FAT sector in a FAT
        ENDOFCHAIN = 0xFFFFFFFEL; # (-2) end of a virtual stream chain
        FREESECT   = 0xFFFFFFFFL; # (-1) unallocated sector
        MAGIC_VALUES = [MAXREGSECT, DIFSECT, FATSECT, ENDOFCHAIN, FREESECT]
        line = '_'*60
        doubleLine = '='*60
        fileFormat = ''
        docType = ''
        print doubleLine
        print 'document-file:', fileName
        print line
        try:
            Module_VBA = imp.load_source('Module_VBA', 'modules/VBA/Module_VBA.py')
            if OleFileIO_PL.isOleFile(fileName):

                fileFormat = '/OLE'
                ole = OleFileIO_PL.OleFileIO(fileName)
                '''attempt to scan for malware placed behind FAT-addressed storage
                #the document being scanned is in the old OLE-format
                #sectors are either 512 or 4096 bytes long.
                #in any case they are a multiple of 512 bytes
                with open(fileName, 'rb') as OLEfile:
                    buf = OLEfile.read()
                if len(buf) % 512 != 0:
                    print 'filesize is not a multiple of 512 bytes. File might contain data behind FAT-addressed storage'
                #check if there is more data behind the data addressed by FAT
                fat = getFat(buf, ole.SectorSize)
                if (len(fat)+1)*ole.SectorSize < len(buf):
                    print 'found not addressed data behind FAT-storage'
                    dumpFileName = fileName.split('.')[0] + 'Overhang.bin'
                    with open(dumpFileName,'wb') as dump:
                        dump.write(buf[(len(fat)+1)*ole.SectorSize:])
                    print 'saved overhang to:', dumpFileName
                '''


                if ole.exists('WordDocument'):
                    docType = '/word'
                elif ole.exists('Workbook'):
                    docType = '/xl'
                elif ole.exists('PowerPoint Document'):
                    docType = '/ppt'
                else:
                    print 'flie seems to be neither .docx, .xlsx nor .pptx'
                    #skip this file as it is probably an activeX.bin
                    continue

                extractor = Module_VBA.VBA_Mod(fileName, 1, docType)
                extractor.extractMacroCode()
                Module_Flashobject = imp.load_source('Module_Flashobject', 'modules/flash/Module_Flashobject.py')
                #import modules/flash/Module_Flashobject
                flashMod = Module_Flashobject.Flash_Mod(fileName, 1, docType )
                flashMod.locateFlashObjects()
                Module_Javascript = imp.load_source('Module_Javascript', 'modules/javascript/Module_Javascript.py')
                #import modules/javascript/Module_Javascript
                JSMod = Module_Javascript.JS_Mod(fileName, 1, docType )
                JSMod.locateJavascriptSource()

            else:
                #the document being scanned is in the new xml-based format
                fileFormat = '/XML'
                folderName = fileName.split('.')[0].split('/')[-1]
                folderName = args.extractionFolder + '/' + folderName
                if args.extractionFolder == '.':
                    folderName = fileName.split('.')[0]

                try:
                    unzip(fileName, folderName)
                except zipfile.BadZipfile:
                    print 'failed to extract XML-based document:', fileName
                    continue



                if os.path.exists(folderName + "\\word"):
                    docType = '/word'
                elif os.path.exists(folderName + "\\xl"):
                    docType = '/xl'
                elif os.path.exists(folderName + "\\ppt"):
                    docType = '/ppt'
                else:
                    print 'could not determine filetype, skipping this file'
                    continue

                #search for VBA-Macros
                extractor = Module_VBA.VBA_Mod(folderName, 0, docType)
                extractor.extractMacroCode()

                #search for flash-objects
                Module_Flashobject = imp.load_source('Module_Flashobject', 'modules/flash/Module_Flashobject.py')
                #import modules/flash/Module_Flashobject
                flashMod = Module_Flashobject.Flash_Mod(folderName, 0, docType )
                flashMod.locateFlashObjects()

                #search for javascript aka MS scriptlett-component
                Module_Javascript = imp.load_source('Module_Javascript', 'modules/javascript/Module_Javascript.py')
                #import modules/javascript/Module_Javascript
                JSMod = Module_Javascript.JS_Mod(folderName, 0, docType )
                JSMod.locateJavascriptSource()


            #load and run cve-detection-plugins, which are suitable for the current document file

            #put your plugins in the corresponding folder in modules/CVE_detection/fileFormat/docType
            #a plugin is must have a wrapper-function, which calls the constructor of the actual module
            #this wrapper is called: getNewInstance(fileName, docType) and takes:
                #fileName: path to the document being scanned
                #doctype: defines wether the document is a word-, excel- or powerpoint-document
            #be sure too add this wrapper to your newly created plugins
            pluginLoader = imp.load_source('pluginLoader', 'modules/CVE_detection/pluginLoader.py')
            detectors = pluginLoader.pluginLoader(fileFormat, docType, fileName)
            detectors.runDetectors()
            print line
        except IOError as e:
            for arg in e.args:
                if 'malformed OLE' in arg:
                    print 'WARNING: document: ' + os.path.abspath(fileName) + ' seems to be damaged!'
                    print 'this might be an indicator for embedded malware'

                    break
                else:
                    print 'document: ' +  os.path.abspath(fileName) + ' caused ' + str(type(e))
                    print e.args
                    break
            print line
            continue



