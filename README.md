OfficeMalGrabber (OMG)
==================

Static Analysis Tool for Microsoft Office Documents.

Run as follows:

`./OfficeMalGrabber.py -f testfiles/CVEs/cve-2013-3906.docx
============================================================
document-file: testfiles/CVEs/cve-2013-3906.docx
____________________________________________________________
checking file format ... /XML
extracting file ... done
searching for VBA ... found no macro-code
searching for FLASH ... found no Flash-Objects
searching for JavaScript ... no Javascript/Scriptlett detected
loading plugins ... done
found an exploit for CVE-2013-3906!
____________________________________________________________`
