#!/usr/bin/python2.7
# -*- coding: utf-8 -*-
# vim: tabstop=4 shiftwidth=4 expandtab

import zipfile
import os.path
import sys
import imp
import argparse
import textwrap
import shutil
import json

import core.littleEndian as littleEndian
import core.OleFileIO_PL as OleFileIO_PL

__author__ = "holger huettl, jan goebel <goebel@pi-one.net>"
__version__ = "0.0.2"


def omg_unzip(path, extractionFolder):
    extractionFolder = os.path.abspath(extractionFolder)
    tempString = extractionFolder
    if not os.path.exists(extractionFolder):
        os.makedirs(extractionFolder)
    zfile = zipfile.ZipFile(path)
    zfile.extractall(extractionFolder)
    zfile.close()
    return extractionFolder

def getFat(binaryContent, sectorsize):
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
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--fileName','-f', type=str, help='scan particular file')
    group.add_argument('--recursive', '-r', type=str, help='recursively traverse given directory for files')
    parser.add_argument('--extractionFolder', '-e', type=str, default='.', help='extract files such as macro code to this folder (default: current)')
    parser.add_argument('--quiet','-q', action="store_true", help='disable noisy output')
    parser.add_argument('--json','-j', action="store_true", help='output results in json format')
    args = parser.parse_args()
    json_response = []
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
        json_result = {'filename': fileName, 'debug': [], 'detections': [], 'signatures': [], 'threat index': 0}
        if not os.path.exists(fileName):
            if args.json:
                json_result['debug'].append("no such file: %s" % (fileName))
                json_response.append(json_result)
            else:
                print "no such file: %s" % (fileName)
            continue
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
        if not args.quiet and not args.json:
            print doubleLine
        if args.json:
            json_result['filename'] = fileName
        else:
            print 'scanning document-file:', fileName
        if not args.quiet and not args.json:
            print line
        sys.stdout.flush()
        try:
            Module_VBA = imp.load_source('Module_VBA', 'modules/VBA/Module_VBA.py')
            if not args.quiet and not args.json:
                print "checking file format ...",
            sys.stdout.flush()
            if OleFileIO_PL.isOleFile(fileName):
                fileFormat = '/OLE'
                if not args.quiet and not args.json:
                    print fileFormat
                    sys.stdout.flush()
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
                    if args.json:
                        json_result['debug'].append('file seems to be neither .docx, .xlsx nor .pptx')
                        json_response.append(json_result)
                    else:
                        print 'file seems to be neither .docx, .xlsx nor .pptx'
                    #skip this file as it is probably an activeX.bin
                    continue

                extractor = Module_VBA.VBA_Mod(fileName, 1, docType, args, json_result)
                extractor.extractMacroCode()
                Module_Flashobject = imp.load_source('Module_Flashobject', 'modules/flash/Module_Flashobject.py')
                #import modules/flash/Module_Flashobject
                flashMod = Module_Flashobject.Flash_Mod(fileName, 1, docType, args, json_result)
                flashMod.locateFlashObjects()
                Module_Javascript = imp.load_source('Module_Javascript', 'modules/javascript/Module_Javascript.py')
                #import modules/javascript/Module_Javascript
                JSMod = Module_Javascript.JS_Mod(fileName, 1, docType, args, json_result)
                JSMod.locateJavascriptSource()
                extractionFolder = None
            else:
                #the document being scanned is in the new xml-based format
                fileFormat = '/XML'
                if not args.quiet and not args.json:
                    print fileFormat
                    sys.stdout.flush()

                """ determine folder where to extract XML parts """
                folderName = fileName.rsplit('.', 1)[0].rsplit('/', 1)[-1]
                folderName = args.extractionFolder + '/' + folderName
                if args.extractionFolder == '.':
                    folderName = fileName.rsplit('.', 1)[0]

                if zipfile.is_zipfile(fileName):
                    if not args.quiet and not args.json:
                        print "extracting file ...",
                        sys.stdout.flush()
                    try:
                        extractionFolder = omg_unzip(fileName, folderName)
                    except zipfile.BadZipfile:
                        if args.json:
                            json_result['debug'].append('failed to extract XML-based document:', fileName)
                            json_response.append(json_result)
                        else:
                            print
                            print 'failed to extract XML-based document:', fileName
                        continue
                    if not args.quiet and not args.json:
                        print "done"
                    sys.stdout.flush()
                else:
                    if args.json:
                        json_result['debug'].append("this is not a zip file")
                        json_response.append(json_result)
                    else:
                        print "this is not a zip file"
                    continue

                if os.path.exists(os.path.join(folderName, "word")):
                    docType = '/word'
                elif os.path.exists(os.path.join(folderName, "xl")):
                    docType = '/xl'
                elif os.path.exists(os.path.join(folderName, "ppt")):
                    docType = '/ppt'
                else:
                    if args.json:
                        json_result['debug'].append('could not determine filetype, skipping this file (%s)' % (folderName))
                        json_response.append(json_result)
                    else:
                        print 'could not determine filetype, skipping this file (%s)' % (folderName)
                    continue

                #search for VBA-Macros
                if not args.quiet and not args.json:
                    print "searching for VBA ...",
                    sys.stdout.flush()
                extractor = Module_VBA.VBA_Mod(folderName, 0, docType, args, json_result)
                extractor.extractMacroCode()

                #search for flash-objects
                if not args.quiet and not args.json:
                    print "searching for FLASH ...",
                    sys.stdout.flush()
                Module_Flashobject = imp.load_source('Module_Flashobject', 'modules/flash/Module_Flashobject.py')
                #import modules/flash/Module_Flashobject
                flashMod = Module_Flashobject.Flash_Mod(folderName, 0, docType, args, json_result)
                flashMod.locateFlashObjects()

                #search for javascript aka MS scriptlett-component
                if not args.quiet and not args.json:
                    print "searching for JavaScript ...",
                    sys.stdout.flush()
                Module_Javascript = imp.load_source('Module_Javascript', 'modules/javascript/Module_Javascript.py')
                #import modules/javascript/Module_Javascript
                JSMod = Module_Javascript.JS_Mod(folderName, 0, docType, args, json_result)
                JSMod.locateJavascriptSource()

            #load and run cve-detection-plugins, which are suitable for the current document file

            #put your plugins in the corresponding folder in modules/CVE_detection/fileFormat/docType
            #a plugin is must have a wrapper-function, which calls the constructor of the actual module
            #this wrapper is called: getNewInstance(fileName, docType) and takes:
                #fileName: path to the document being scanned
                #doctype: defines wether the document is a word-, excel- or powerpoint-document
            #be sure too add this wrapper to your newly created plugins
            if not args.quiet and not args.json:
                print "loading plugins ...",
                sys.stdout.flush()
            pluginLoader = imp.load_source('pluginLoader', 'modules/CVE_detection/pluginLoader.py')
            detectors = pluginLoader.pluginLoader(fileFormat, docType, fileName, extractionFolder, args, json_result)
            if not args.quiet and not args.json:
                print "done"
                sys.stdout.flush()
            detectors.runDetectors()
            if not args.quiet and not args.json:
                print line
            if extractionFolder:
                try:
                    pass
                    #shutil.rmtree(extractionFolder)
                except StandardError as e:
                    print e
            if args.json:
                if len(json_result['signatures'])>0:
                    json_result['threat index'] += 5
                if len(json_result['detections'])>0:
                    json_result['threat index'] += 2
                json_response.append(json_result)
        except IOError as e:
            for arg in e.args:
                if 'malformed OLE' in arg:
                    if args.json:
                        json_result['debug'].append('WARNING: document: ' + os.path.abspath(fileName) + ' seems to be damaged!')
                        json_result['debug'].append('this might be an indicator for embedded malware')
                    else:
                        print 'WARNING: document: ' + os.path.abspath(fileName) + ' seems to be damaged!'
                        print 'this might be an indicator for embedded malware'
                    break
                else:
                    if args.json:
                        json_result['debug'].append('document: ' +  os.path.abspath(fileName) + ' caused ' + str(type(e)))
                        json_result['debug'].append(e.args)
                    else:
                        print 'document: ' +  os.path.abspath(fileName) + ' caused ' + str(type(e))
                        print e.args
                    break
            if not args.quiet and not args.json:
                print line
            if args.json:
                json_response.append(json_result)
            continue
    if args.json:
        print json.dumps(json_response, sort_keys=False, indent=4, separators=(',', ': '))
