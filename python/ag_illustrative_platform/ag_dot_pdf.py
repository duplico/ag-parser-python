"""
Python script for combining the AG generated PDFs into a single one.
Pretty hackish. Sorry.
"""

from pyPdf import PdfFileWriter, PdfFileReader
import os, re

dots = os.listdir('.')
dotre = re.compile(r'^nm_state\d*\.dot$')
for dotfile in dots:
    if dotre.match(dotfile):
        os.system('dot -O -Tpdf %s' % dotfile)

pdfre = re.compile(r'^nm_state(?P<statenum>\d*)\.dot\.pdf$')
pdfs = os.listdir('.')
pdfpaths = []
for pdffile in pdfs:
    if pdfre.match(pdffile):
        pdfpaths.append(pdffile)

def sortfun(filename):
    return int(pdfre.match(filename).groupdict()['statenum'])

pdfpaths.sort(key=sortfun)
print pdfpaths

output = PdfFileWriter()

for pdf in pdfpaths:
    infile = file(pdf, 'rb')
    input = PdfFileReader(infile)
    output.addPage(input.getPage(0))
    outfile = file("stitched.pdf", 'wb')
    output.write(outfile)
    outfile.close()
    infile.close()