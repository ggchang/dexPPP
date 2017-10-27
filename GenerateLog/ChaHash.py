import hashlib
import os,sys

def getSHA1(filepath):
    with open(filepath,'rb') as f:
        sha1obj=hashlib.sha1()
        sha1obj.update(f.read())
        hash=sha1obj.hexdigest()
        return hash

def getSHA256(filepath):
    with open(filepath,'rb') as f:
        sha1obj=hashlib.sha256()
        sha1obj.update(f.read())
        hash=sha1obj.hexdigest()
        return hash

def getMD5(filepath):
    with open(filepath,'rb') as f:
        sha1obj=hashlib.md5()
        sha1obj.update(f.read())
        hash=sha1obj.hexdigest()
        return hash

def getSHA512(filepath):
    with open(filepath,'rb') as f:
        sha1obj=hashlib.sha512()
        sha1obj.update(f.read())
        hash=sha1obj.hexdigest()
        return hash