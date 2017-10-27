import pefile

def PeParse():
    pefile_path="D:\\code\\PYprescan\\ParseFile\\PeParse\\notepad.exe"
    Pefile=pefile.PE(pefile_path)
    print pefile.OPTIONAL_HEADER_MAGIC_PE
    #for section in Pefile.sections:
    #    #print section.set_file_offset
    #    print section.__unpack__
    #get_import(Pefile)

def get_import(pefile):
    for importeddll in pefile.DIRECTORY_ENTRY_IMPORT:
        #print importeddll.dll
        for importedapi in importeddll.imports:
            print importedapi.name

if __name__ == '__main__':
    PeParse()