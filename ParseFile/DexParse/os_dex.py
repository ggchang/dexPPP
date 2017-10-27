#*_*coding:utf-8*_*
import os
import sys
import dexParser

def enum_and_parse(path):
    filelist =  os.listdir(path)
    for file in filelist:
        os.mkdir(path+'\\'+file+'.parsed')
        try:
			dexParser.writeDex(path+'\\'+file)
        except:
			print file+'error'
			pass

if __name__=="__main__":
    path=sys.argv[1]  ##sys.argv[1]=绝对路径
    enum_and_parse(path)