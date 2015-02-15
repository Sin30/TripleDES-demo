#!/usr/bin/env python
#coding:utf-8

import binascii
import base64
import pyDes

#IV has to be 8bit long
iv = '2132435465768797'
#Key has to be 24bit long
key = '000000000000000000000000000000000000000000000000'
#here is the data you want to encrypt
data = "Jason Grant"

def encrypt(iv, key, data):
    iv = binascii.unhexlify(iv)
    key = binascii.unhexlify(key)
    k = pyDes.triple_des(key, pyDes.CBC, iv, pad=None, padmode=pyDes.PAD_PKCS5)
    d = k.encrypt(data)
    d = base64.encodestring(d)
    return d
    
def decrypt(iv, key, data):
    iv = binascii.unhexlify(iv)
    key = binascii.unhexlify(key)
    k = pyDes.triple_des(key, pyDes.CBC, iv, pad=None, padmode=pyDes.PAD_PKCS5)
    data = base64.decodestring(data)
    d = k.decrypt(data)
    return d

if __name__ == '__main__':
    print "Plan Text: %s" % data
    encryptdata = encrypt(iv, key, data)
    print "Encrypted Text: %s" % encryptdata
    decryptdata = decrypt(iv, key, encryptdata)
    print "Plan Text: %s" % decryptdata
