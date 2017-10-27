#*_*coding:utf-8*_*
import pefile
import struct
import os

def dumpBIN(src_file,dst_file,str_offset,size):
    #dumpBIN用于将src_file的size个字节从文件起始位置起str_offset偏移处保存到dst_file
    src_file=open(src_file,'rb')
    dst_file=open(dst_file,'ab+')
    src_file.seek(str_offset)
    hbytes=struct.unpack_from("c"*size,src_file.read(size))
    for i in hbytes:
        dst_file.write(i)
    src_file.close()
    dst_file.close()

def clean_section_str(string):
    string=string.replace(" ","").split(":")[1]
    return string

def dump_sections(pefile_path,savepath):
    pe=pefile.PE(pefile_path)
    for section in pe.sections:
        #Name:                          .text
        #Misc:                          0x13AD0
        #Misc_PhysicalAddress:          0x13AD0
        #Misc_VirtualSize:              0x13AD0
        #VirtualAddress:                0x1000
        #SizeOfRawData:                 0x13C00
        #PointerToRawData:              0x400
        #PointerToRelocations:          0x0
        #PointerToLinenumbers:          0x0
        #NumberOfRelocations:           0x0
        #NumberOfLinenumbers:           0x0
        #Characteristics:               0x60000020
        section_name = clean_section_str(section.dump()[1])
        RVA = int(clean_section_str(section.dump()[5]),16)
        VirtSize=int(clean_section_str(section.dump()[4]),16)
        SizeOfRawData=int(clean_section_str(section.dump()[6]),16)
        offset=int(clean_section_str(section.dump()[7]),16)
        dumpBIN(pefile_path,savepath+section_name+".bin",offset,SizeOfRawData)

def dump_DosHeader(pefile_path,savepath):
    pe=pefile.PE(pefile_path)
    dumpBIN(pefile_path,savepath+"DosHeader.bin",0,64)

def dump_DosStub(pefile_path,savepath):
    pe=pefile.PE(pefile_path)
    option_off=int(clean_section_str(pe.DOS_HEADER.dump()[-1]),16)
    size=option_off-64
    dumpBIN(pefile_path,savepath+"DosStub.bin",64,size)

def dump_NtHeader(pefile_path):
    pe=pefile.PE(pefile_path)
    binfile=open(pefile_path,'rb')
    binfile.seek(0x3C)
    hbytes=struct.unpack_from("I"*1,binfile.read(4))
    #NtHeader的偏移存放在文件偏移0x3c处
    NtHeader_offset = hbytes[0]

def dump_Overlay(pefile_path,savepath):
    filesize=os.path.getsize(filepath)
    pe=pefile.PE(pefile_path)
    coo=len(pe.sections)-1
    offset = int(clean_section_str(pe.sections[coo].dump()[7]),16)
    SizeOfRawData = int(clean_section_str(pe.sections[coo].dump()[6]),16)
    Overlay_off=offset+SizeOfRawData
    SizeOfOverlay=filesize-Overlay_off
    dumpBIN(pefile_path,savepath+"overlay.bin",Overlay_off,SizeOfOverlay)

def parse_IAT(pefile_path,savepath):
    pe=pefile.PE(pefile_path)
    wf=open(savepath+"import.txt",'a')
    for importeddll in pe.DIRECTORY_ENTRY_IMPORT:
        #importeddll.dll
        for importedapi in importeddll.imports:
            if importedapi.name!=None:
                wf.write(importedapi.name+'\r')
            else:
                break
    wf.close()

def EntryPoint_dump(pefile_path,savepath):
    pe=pefile.PE(pefile_path)
    print int(clean_section_str(pe.OPTIONAL_HEADER.dump()[7]),16)

if __name__ == '__main__':
    filepath="D:\\code\\PYprescan\\ParseFile\\PeParse\\notepad.exe"
    #os.mkdir(filepath+'.parsed')
    savepath=filepath+'.parsed\\'
    #dump_sections(filepath,savepath)
    #dump_DosStub(filepath,savepath)
    #dump_DosHeader(filepath,savepath)
    #dump_Overlay(filepath,savepath)
    dump_NtHeader(filepath)
    #parse_IAT(filepath,savepath)
    EntryPoint_dump(filepath,savepath)