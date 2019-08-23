#!/usr/bin/env python
#flag format: d4rk{flag}c0de
from pwn import xor
c1 = '\x05F\x17\x12\x14\x18\x01\x0c\x0b4'
c2 = '>\x1f\x00\x14\n\x08\x07Q\n\x0e'

c = c1 + c2

key1 = xor(c1[:5],'d4rk{')
key2 = xor(c2[-5:],'}c0de')
key = key1+key2

print xor(c,key) #flag
