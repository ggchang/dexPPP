#*_*coding:utf-8*_*
import pefile
import struct

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

def dump_sections(pefile_path):
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
        dumpBIN(pefile_path,section_name+".bin",offset,SizeOfRawData)

#if __name__ == '__main__':
    #dumpBIN("D:\\code\\notepad.exe",'a.bin',0,0x40)