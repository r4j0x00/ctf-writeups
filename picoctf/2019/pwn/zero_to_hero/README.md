# Zero To Hero
This was a fun challenge from picoctf 2019. It was rated 500 points and had very few solves during the ctf. Although it wasn't that tough.  

## Description
Now you're really cooking. Can you pwn this service?. Connect with `nc 2019shell1.picoctf.com 49929`. [libc.so.6](https://2019shell1.picoctf.com/static/40beb534349dda031d3c84a1ac1b4710/libc.so.6) [ld-2.29.so](https://2019shell1.picoctf.com/static/40beb534349dda031d3c84a1ac1b4710/ld-2.29.so)  

## Quick Overview
It's a 64 bit dynamically linked elf executable -
```console
root@kali:~/picoctf-2019/zero_to_hero# file ./zero_to_hero 
./zero_to_hero: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /root/picoctf-2019/ld-2.29.so, for GNU/Linux 3.2.0, BuildID[sha1]=cf8bd977ca01d23e9b004a6dc637d6ab7c56e656, stripped
```

Running checksec -
```console
root@kali:~/picoctf-2019/zero_to_hero# checksec ./zero_to_hero 
[*] '/root/picoctf-2019/zero_to_hero/zero_to_hero'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x3ff000)
    RUNPATH:  './'
```
Checksec shows us that Everything except PIE is enabled. We'll later see that our solution works regardless of PIE.

Running the binary -
```console
From Zero to Hero
So, you want to be a hero?
y
Really? Being a hero is hard.
Fine. I see I can't convince you otherwise.
It's dangerous to go alone. Take this: 0x7f777a154ff0
1. Get a superpower
2. Remove a superpower
3. Exit
>
```
When we run it, it asks us y/n we send y and it loads the main program. It leaks us an address (probably some libc address?).





