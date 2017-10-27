#*-*coding:utf-8*-*

def byte_to_buma(val):
    binVal = bin(val)[2:].zfill(8)
    if binVal[0:1] == '0':
        return val
    sb = ''
    for i in range(7):
        if binVal[i+1:i+2] == '0':
            sb += '1'
        else:
            sb += '0'

    return -(int(sb, 2) + 1)

def word_to_buma(val):
    binVal = bin(val)[2:].zfill(16)
    if binVal[0:1] == '0':
        return val
    sb = ''
    for i in range(15):
        if binVal[i+1:i+2] == '0':
            sb += '1'
        else:
            sb += '0'

    return -(int(sb, 2) + 1)

def dword_to_buma(val):
    binVal = bin(val)[2:].zfill(32)
    if binVal[0:1] == '0':
        return val
    sb = ''
    for i in range(31):
        if binVal[i+1:i+2] == '0':
            sb += '1'
        else:
            sb += '0'

    return -(int(sb, 2) + 1)