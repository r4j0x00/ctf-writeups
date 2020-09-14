#!/usr/bin/python2
#unintended but works
from pwn import remote
r = remote('crypto.chal.csaw.io', 5001)
def do(p, t):
    r.sendlineafter(':', p, timeout=1)
    r.sendlineafter('?', t)

x = ['ECB', 'CBC']
a = [0]

def con():
    for i in a:
        do('d', x[i])
con()
while 1:
    try:
        do('d', x[0])
        a.append(0)
    except:
        a = a[:-1]
        a.append(1)
        flag = ''
        for i in range(0, len(a), 8):
            flag += chr(int(''.join([str(b) for b in a[i:i+8]]), 2))
        print (flag)
        r = remote('crypto.chal.csaw.io', 5001)
        con()
        continue

r.interactive()
