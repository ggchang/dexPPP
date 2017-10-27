import pefile

pefile_path="D:\\code\\notepad.exe"

pe=pefile.PE(pefile_path)
#    print section
#for impentdll in pe.DIRECTORY_ENTRY_IMPORT:
#    print impentdll.dll
#    for fuc in impentdll.imports:
#        print fuc.name
#print pe.FILE_HEADER.dump()
#for i in pe.FILE_HEADER.dump():
#    print i
#print pe.DOS_HEADER.dump()
#print pe.DOS_HEADER.dump_dict()
#for i in pe.DOS_HEADER.dump():
#    print i

#pe_header
for i in pe.