#!/usr/bin/env python
# -*- coding: utf-8 -*-

import struct

MatrixChSm = [
  0x1, 0xf, 0xd, 0x0, 0x5, 0x7, 0xa, 0x4, 0x9, 0x2, 0x3, 0xe, 0x6, 0xb, 0x8,
    0xc,
  0xd, 0xb, 0x4, 0x1, 0x3, 0xf, 0x5, 0x9, 0x0, 0xa, 0xe, 0x7, 0x6, 0x8, 0x2,
    0xc,
  0x4, 0xb, 0xa, 0x0, 0x7, 0x2, 0x1, 0xd, 0x3, 0x6, 0x8, 0x5, 0x9, 0xc, 0xf,
    0xe,
  0x6, 0xc, 0x7, 0x1, 0x5, 0xf, 0xd, 0x8, 0x4, 0xa, 0x9, 0xe, 0x0, 0x3, 0xb,
    0x2,
  0x7, 0xd, 0xa, 0x1, 0x0, 0x8, 0x9, 0xf, 0xe, 0x4, 0x6, 0xc, 0xb, 0x2, 0x5,
    0x3,
  0x5, 0x8, 0x1, 0xd, 0xa, 0x3, 0x4, 0x2, 0xe, 0xf, 0xc, 0x7, 0x6, 0x0, 0x9,
    0xb,
  0xe, 0xb, 0x4, 0xc, 0x6, 0xd, 0xf, 0xa, 0x2, 0x3, 0x8, 0x1, 0x0, 0x7, 0x5,
    0x9,
  0x4, 0xa, 0x9, 0x2, 0xd, 0x8, 0x0, 0xe, 0x6, 0xb, 0x1, 0xc, 0x7, 0xf, 0x5,
    0x3
]

def print_state():
    print('='*40)
    print("EXT_k:")
    print(", ".join(["0x%0x" % x for x in EXT_k]))

    print("PsRndHash:")
    print(", ".join(["0x%08X" % x for x in PsRndHash]))

    print("ChSm:")
    print(", ".join(["0x%X" % x for x in ChSm]))


    print("PsRndChSm:")
    print(", ".join(["0x%08X" % x for x in PsRndChSm]))

    print("ChSmCounter: {}".format(ChSmCounter))
    print('-' * 40)



class cbiCheckSum_32_bytes(object):
    PsRndChSm_default = [0x12345678l, 0xBABABABAl, 0xAAAAAAAAl, 0x87654321l]

    def __init__(self):
        self.clr()

    def clr(self):
        self.PsRndChSm = []
        self.PsRndChSm[:] = self.PsRndChSm_default
        self.ChSm = [0] * 8
        self.ChSmCounter = 0
        self.EXT_k = range(16)

    def add(self, vctr):
        for v in vctr:
            k = self.f(self.PsRndGenerator1())
            self.ChSm[self.ChSmCounter] = self.ChSm[self.ChSmCounter] + \
             self.f(self.ChSm[k & 7]) ^ k + self.f(v)
            self.ChSmCounter = (self.ChSmCounter + 1) & 0x7


    def gets(self, vctr):
        for i in xrange(8):
            for j in xrange(8):
                self.GetExtKey()
                self.ChSm[i] = self.f(self.ChSm[i] + self.PsRndGenerator1 () +\
                                 self.ChSm[j])
        vctr[:] = self.ChSm

    def sets(self, vctr):
        self.ChSm[:] = [0] * 8 #?
        self.ChSm[:] = vctr

    def password(self, password):
        length = 8*4
        pwd = password + '\0'*(length-len(password))
        for i in xrange(8):
            sub = pwd[i*4:i*4+4]
            self.ChSm[i] = struct.unpack("<I",sub)[0]

    def f(self, x):
        x = \
         ((MatrixChSm[0*16+self.EXT_k[(x >> 28) & 0xF]]) << 28) | \
         ((MatrixChSm[1*16+self.EXT_k[(x >> 24) & 0xF]]) << 24) | \
         ((MatrixChSm[2*16+self.EXT_k[(x >> 20) & 0xF]]) << 20) | \
         ((MatrixChSm[3*16+self.EXT_k[(x >> 16) & 0xF]]) << 16) | \
         ((MatrixChSm[4*16+self.EXT_k[(x >> 12) & 0xF]]) << 12) | \
         ((MatrixChSm[5*16+self.EXT_k[(x >>  8) & 0xF]]) <<  8) | \
         ((MatrixChSm[6*16+self.EXT_k[(x >>  4) & 0xF]]) <<  4) | \
         ((MatrixChSm[7*16+self.EXT_k[(x      ) & 0xF]])      )
        return 0xFFFFFFFF & ((x << 13) | (x >> (32 - 13)))

    def PsRndGenerator1(self):
        R1 = self.PsRndChSm[0] 
        R1 = R1 >> 1 
        R3 = self.PsRndChSm[1] & 1
        R3 = R3 << 31 
        R1 = R1 | R3  
        R2 = self.PsRndChSm[0] >> 8
        R3 = self.PsRndChSm[1] & 0xFF
        R3 = R3 << 24
        R2 = R2 | R3
        self.PsRndChSm[0] = self.PsRndChSm[1]
        self.PsRndChSm[1] = self.PsRndChSm[2]
        self.PsRndChSm[2] = self.PsRndChSm[3]
        self.PsRndChSm[3] = R1 ^ R2
        return R1

    def GetExtKey (self):
        self.EXT_k[:] = [0xFF]*16
        j = 0
        while True:
            x = self.PsRndGenerator1()
            f = any([x & 0xF == r for r in self.EXT_k])
            if not f:
                for i in xrange(16):
                    if self.EXT_k[i] == 0xFF:
                        self.EXT_k[i] = x & 0xF
                        j += 1
                        break
            if j >= 16:
                break

def reverse_order(i):
    return struct.unpack("<I", struct.pack(">I", i))[0]

bufflen = 0x7FFC 

ptr_file4 = [0]

def chsm32(fd, pwd = ""):
    midl = [0]*8
    res = [0]*8

    cbi = cbiCheckSum_32_bytes()
    if len(pwd) > 0:
        cbi.password(pwd)

    cnt = 1
    while True:
        data = fd.read(4)
        if len(data) == 0:
            break
        elif len(data) < 4:
            data += '\0'*(4-len(data))
        ptr_file4[0] = struct.unpack("I", data)[0]
        _NEED_REVERSE_ = False
        if _NEED_REVERSE_:
            ptr_file4[0] = reverse_order(ptr_file4[0])

        cbi.add(ptr_file4)
        cnt += 1
        if cnt == bufflen:
            cbi.gets(midl)
            cbi.sets(midl)
            cnt = 1

    cbi.gets(midl)
    cbi.sets(midl)
    cbi.gets(res)
    return res

def chsm32_file(fname, pwd = ""):
    with open(fname, 'rb') as f:
        return chsm32(f, pwd)

def short(h):
    return "%08X" % h[0]

def full(h):
    return "".join(["%0X" % x for x in h])


import sys
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: {} file password".format(sys.argv[0]))
    else:
        res = chsm32_file(sys.argv[1], sys.argv[2])
        print("{} {}".format(short(res), sys.argv[1]))
