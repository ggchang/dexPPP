#*-*coding:utf-8*-*

import struct
import os,sys
import binascii

def parseNotype(filepath):
    filesize=os.path.getsize(filepath)
    os.mkdir(filepath+'.parsed')
    savepath=filepath+'.parsed\\'
    binfile=open(filepath,'rb')
    dumpbin(savepath+'header.hdr',"None")

    #文件头dump
    if filesize>0x4:
        binfile.seek(0)
        hbytes=struct.unpack_from("c"*0x4,binfile.read(0x4))
        for i in hbytes:
            dumpbin(savepath+'FileHead1.bin',i)
    if filesize>0x10:
        binfile.seek(0)
        hbytes=struct.unpack_from("c"*0x10,binfile.read(0x10))
        for i in hbytes:
            dumpbin(savepath+'FileHead2.bin',i)
    if filesize>0x100:
        binfile.seek(0)
        hbytes=struct.unpack_from("c"*0x100,binfile.read(0x100))
        for i in hbytes:
            dumpbin(savepath+'FileHead3.bin',i)
    if filesize>0x200:
        binfile.seek(0)
        hbytes=struct.unpack_from("c"*0x200,binfile.read(0x200))
        for i in hbytes:
            dumpbin(savepath+'FileHead4.bin',i)

    #文件尾dump
    if filesize>0x4:
        binfile.seek(-4,2)
        hbytes=struct.unpack_from("c"*0x4,binfile.read(0x4))
        for i in hbytes:
            dumpbin(savepath+'FileEnd1.bin',i)
    if filesize>0x10:
        binfile.seek(-16,2)
        hbytes=struct.unpack_from("c"*0x10,binfile.read(0x10))
        for i in hbytes:
            dumpbin(savepath+'FileEnd2.bin',i)
    if filesize>0x100:
        binfile.seek(-256,2)
        hbytes=struct.unpack_from("c"*0x100,binfile.read(0x100))
        for i in hbytes:
            dumpbin(savepath+'FileEnd3.bin',i)
    if filesize>0x200:
        binfile.seek(-512,2)
        hbytes=struct.unpack_from("c"*0x200,binfile.read(0x200))
        for i in hbytes:
            dumpbin(savepath+'FileEnd4.bin',i)

def dumpbin(binfile,buffer):
    file=open(binfile,'ab+')
    file.write(buffer)
    file.close()

if __name__ == '__main__':
    parseNotype(sys.argv[1])