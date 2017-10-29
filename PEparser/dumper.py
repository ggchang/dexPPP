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

def check_in_which_section(offset,pe):
    #return section of this offset
    RVA_list=[]
    for section in pe.sections:
        RVA=int(clean_section_str(section.dump()[5]),16)
        RVA_list.append(RVA)
    for i in range(len(RVA_list)):
        if offset>RVA_list[i] and offset<RVA_list[i+1]:
            return i+1

def get_file_offset(memory_offset,RVA,offset):
    #memory_offset  该点在内存中的偏移
    #RVA            该点所在区段在内存中的偏移
    #offset         该点所在区段的文件偏移
    file_offset=offset+(memory_offset-RVA)
    return file_offset

def dump_sections(pefile_path,savepath):
    pe=pefile.PE(pefile_path)
    wf=open(savepath+"sections.txt",'a')
    wf.write("Name     VirtSize RVA      PhysSize offset\r")
    for section in pe.sections:
        section_name = clean_section_str(section.dump()[1])
        RVA = int(clean_section_str(section.dump()[5]),16)
        VirtSize=int(clean_section_str(section.dump()[4]),16)
        SizeOfRawData=int(clean_section_str(section.dump()[6]),16)
        offset=int(clean_section_str(section.dump()[7]),16)
        dumpBIN(pefile_path,savepath+section_name+".bin",offset,SizeOfRawData)
        wf.write(("%-8s %-8s %-8s %-8s %-8s\r")%(section_name,hex(VirtSize),hex(RVA),hex(SizeOfRawData),hex(offset)))

def dump_DosHeader(pefile_path,savepath):
    pe=pefile.PE(pefile_path)
    dumpBIN(pefile_path,savepath+"DosHeader.bin",0,64)

def dump_DosStub(pefile_path,savepath):
    pe=pefile.PE(pefile_path)
    pe=pefile.PE(pefile_path)
    wf=open(savepath+"data_directorys.txt",'a')
    wf.write(("%-50s %-8s %-8s\r")%('name','VirtualAddress','Size'))
    dumpBIN(pefile_path,savepath+"DosStub.bin",64,176)
    for data_dir in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
        wf.write(("%-50s %-8s %-8s\r")%(data_dir.name,data_dir.VirtualAddress,data_dir.Size))

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

def EntryPoint_dump(pefile_path,savepath,size):
    pe=pefile.PE(pefile_path)
    AddressOfEntryPoint=int(clean_section_str(pe.OPTIONAL_HEADER.dump()[7]),16)
    seq_of_EntryPoint=check_in_which_section(AddressOfEntryPoint,pe)
    RVA=int(clean_section_str(pe.sections[seq_of_EntryPoint-1].dump()[5]),16)
    offset=int(clean_section_str(pe.sections[seq_of_EntryPoint-1].dump()[7]),16)
    file_offset=get_file_offset(AddressOfEntryPoint,RVA,offset)
    dumpBIN(pefile_path,savepath+"entrypoint_up.bin",file_offset-size,size)
    dumpBIN(pefile_path,savepath+"entrypoint_down.bin",file_offset,size)

def get_imp_field(pefile_path,savepath):
    Machine_list={'0x14c':'IMAGE_FILE_MACHINE_I386','0x8664':'IMAGE_FILE_MACHINE_AMD64',
                '0x0':'IMAGE_FILE_MACHINE_UNKNOWN','0x1d3':'IMAGE_FILE_MACHINE_AM33'}
    pe=pefile.PE(pefile_path)
    wf=open(savepath+"header.hdr",'a')
    filesize=os.path.getsize(filepath)
    #0xFC       0x0   Machine:                       0x14C
    #0xFE       0x2   NumberOfSections:              0x7
    #0x100      0x4   TimeDateStamp:                 0x59AE29FC [Tue Sep 05 04:37:16 2017 UTC]
    #0x104      0x8   PointerToSymbolTable:          0x0
    #0x108      0xC   NumberOfSymbols:               0x0
    #0x10C      0x10  SizeOfOptionalHeader:          0xE0
    #0x10E      0x12  Characteristics:               0x102
    Machine= hex(int(clean_section_str(pe.FILE_HEADER.dump()[1]),16))
    for Mac in Machine_list:
        if Mac==Machine:
            machine_type=Machine_list[Mac]
            break
    Machine = machine_type
    NumberOfSections=pe.FILE_HEADER.NumberOfSections
    TimeDateStamp = pe.FILE_HEADER.dump()[3].split("[")[1].split("]")[0]
    Characteristics = hex(int(clean_section_str(pe.FILE_HEADER.dump()[7]),16))
    checksum=pe.OPTIONAL_HEADER.CheckSum
    filetype = pe.FILE_HEADER.Characteristics
    wf.write("filesize:"+str(filesize)+'\r')
    wf.write("filetype:"+str(filetype)+'\r')
    wf.write("TimeDateStamp:"+TimeDateStamp+'\r')
    wf.write("CheckSum:"+hex(checksum)+'\r')
    wf.write("Machine:"+str(Machine)+'\r')
    wf.write("NumberOfSections:"+str(NumberOfSections)+'\r')

if __name__ == '__main__':
    filepath="D:\\code\\iexplore.exe"
    #os.mkdir(filepath+'.parsed')
    savepath=filepath+'.parsed\\'
    #dump_sections(filepath,savepath)
    dump_DosStub(filepath,savepath)
    #dump_DosHeader(filepath,savepath)
    #dump_Overlay(filepath,savepath)
    #dump_NtHeader(filepath)
    #parse_IAT(filepath,savepath)
    #EntryPoint_dump(filepath,savepath,200)
    get_imp_field(filepath,savepath)