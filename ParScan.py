#*-*coding:utf-8*-*

import os,sys,struct,binascii
from ParseFile.DexParse import dexParser
from ParseFile.Notype import NotypeParser
from GenerateLog import generate
from Hashkuz import ChaHash

def ParScan(dirpath):
    filelist=os.listdir(dirpath)
    for file in filelist:
        FilePath=dirpath+"\\"+file
        FileType=GetFileType(FilePath)
        if FileType==None:
            print FilePath+'  ->  NoType\r'
            try:
                NotypeParser.parseNotype(FilePath)
            except:
                pass
        elif FileType=='dex':
            try:
                dexParser.writeDex(FilePath)
            except:
                pass
        else:
            print FilePath+' have a error!'

        #生成html格式的log之后删除parsed文件夹
        fileSHA1=ChaHash.getSHA1(FilePath)
        generate.GenerateLog(fileSHA1)
        for delfile in os.listdir(dirpath+"\\"+file+'.parsed'):
            os.remove(dirpath+"\\"+file+'.parsed\\'+delfile)
        os.rmdir(dirpath+"\\"+file+'.parsed')

def ParScan2(dirpath):
    filelist=os.listdir(dirpath)
    for file in filelist:
        FilePath=dirpath+"\\"+file
        NotypeParser.parseNotype(FilePath)
        FileType=GetFileType(FilePath)
        if FileType==None:
            print FilePath+'  ->  None\r'
        elif FileType=='dex':
            dexParser.writeDex(FilePath)
        else:
            print FilePath+' have a error!'

        #生成html格式的log之后删除parsed文件夹
        fileSHA1=ChaHash.getSHA1(FilePath)
        generate.GenerateLog(fileSHA1)
        for delfile in os.listdir(dirpath+"\\"+file+'.parsed'):
            os.remove(dirpath+"\\"+file+'.parsed\\'+delfile)
        os.rmdir(dirpath+"\\"+file+'.parsed')

def GetFileType(filepath):
    #文件头magic字段字典
    magic_list={'pe':'MZ','dex':'dex'}
    for filetype in magic_list:
        TmpMagic=''
        num_of_magic=len(magic_list[filetype])
        binfile=open(filepath,'rb')
        binfile.seek(0)
        hbytes=struct.unpack_from("s"*num_of_magic,binfile.read(num_of_magic))
        for i  in hbytes:
            TmpMagic=TmpMagic+i
        if TmpMagic==magic_list[filetype]:
            print filepath+'  ->  '+filetype+'\r'
            return filetype

if __name__ == '__main__':
    ParScan2(sys.argv[1])