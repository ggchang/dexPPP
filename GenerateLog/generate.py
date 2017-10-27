#*_*coding:utf-8*_*
import os,sys
from Hashkuz import ChaHash
import hashlib

Banner="HR Perscan log\r\r"
zzline='-'*80+'*#**#*'+'-'*80+'\r'
zline='-'*150+'\r'

def GenerateLog(SHA1):
    #htmlpath存放生成的html文件
    htmlpath="D:\\code\\html\\"
    logfile=htmlpath+SHA1+".html"
    flog=open(logfile,'a')
    #flog.write(Banner)
    filepath='D:\\code\\1\\'+SHA1
    flog.write(zzline)
    flog.write('  SHA1:'+ChaHash.getSHA1(filepath)+'\r')
    flog.write('SHA256:'+ChaHash.getSHA256(filepath)+'\r')
    flog.write('SHA512:'+ChaHash.getSHA512(filepath)+'\r')
    flog.write('   MD5:'+ChaHash.getMD5(filepath)+'\r')
    flog.write(zzline)
    #SHA1path为存放解析后存放文件的目录
    SHA1path='D:\\code\\1\\'+SHA1+'.parsed'+'\\'

    head=open(SHA1path+"header.hdr").read()
    flog.write("File header:\r"+head+"\r\r")

    filelist=os.listdir(SHA1path)

    flog.write("Locality-Sensitive Hashing:\r")
    for file in filelist:
        if file[-3:]=='bin':
            flog.write(file[0:-4]+'-->')
            flog.write('SHA1:'+ChaHash.getSHA1(SHA1path+file)+'\r')
    flog.write("\r\r")

    for file in filelist:
        if file[-3:]=='txt':
            f=open(SHA1path+file,'r').read()
            flog.write(file[0:-4]+'\r')
            flog.write('SimHash:'+ChaHash.getssdeep(SHA1path+file)+'\r')
            #flog.write(f)
            flog.write('\r')