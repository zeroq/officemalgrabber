# -*- coding: utf-8 -*-
# vim: tabstop=4 shiftwidth=4 expandtab

import imp
import re

import core.littleEndian as littleEndian
import core.OleFileIO_PL as OleFileIO_PL

def getNewInstance(fileName, docType, extractionFolder, args, json_result):
    return CVE_2006_2492_detector(fileName, extractionFolder, args, json_result)

class CVE_2006_2492_detector:

    def __init__(self, fileName, extractionFolder, args, json_result):
        self.ole = None
        self.json_result = json_result
        self.args = args
        self.fileName = fileName

    def report(self):
        print "....: CVE-2006-2492"

    def check(self):
        try:
            fp = open(self.fileName, 'r')
            content = fp.read()
            fp.close()
        except Exception as e:
            if not self.args.json:
                print e
            content = None
        possible = False
        if content:
            re_kernel = re.compile('kernel32\.dll', re.I|re.S)
            re_shell = re.compile('ShellExecuteExA', re.I|re.S)
            re_startup = re.compile('GetStartupInfoA', re.I|re.S)
            re_remote_thread = re.compile('CreateRemoteThread', re.I|re.S)
            match = re_kernel.search(content)
            if match:
                possible = True
                if self.args.json:
                    self.json_result['signatures'].append({'match': 'Found keyword "kernel32.dll" which indicates: "May have shellcode embedded"'})
                else:
                    print '>>>> Found keyword "kernel32.dll" which indicates: "May have shellcode embedded"'
            match = re_shell.search(content)
            if match:
                possible = True
                if self.args.json:
                    self.json_result['signatures'].append({'match': 'Found keyword "ShellExecuteExA" which indicates: "May run an executable file or a system command"'})
                else:
                    print '>>>> Found keyword "ShellExecuteExA" which indicates: "May run an executable file or a system command"'
            match = re_startup.search(content)
            if match:
                possible = True
                if self.args.json:
                    self.json_result['signatures'].append({'match': 'Found keyword "GetStartupInfoA" which indicates: "May gather system information"'})
                else:
                    print '>>>> Found keyword "GetStartupInfoA" which indicates: "May gather system information"'
            match = re_remote_thread.search(content)
            if match:
                possible = True
                if self.args.json:
                    self.json_result['signatures'].append({'match': 'Found keyword "CreateRemoteThread" which indicates: "May inject code in other process"'})
                else:
                    print '>>>> Found keyword "CreateRemoteThread" which indicates: "May inject code in other process"'
        if possible:
            try:
                ole = OleFileIO_PL.OleFileIO(self.fileName)
                wordDocStream = ole.openstream('WordDocument')
                wordDocBuffer = wordDocStream.read()
            except Exception as e:
                if str(e) == 'incomplete OLE stream':
                    if self.args.json:
                        self.json_result['signatures'].append({'match': 'cve-2006-2492'})
                    else:
                        print '>>>> file might be an exploit for CVE-2006-2492'
