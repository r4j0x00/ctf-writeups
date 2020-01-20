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
* Option 1 leads to create super power and option 2 leads to delete superpower.
* We can only create chunks with size less then 0x408 and we can create only malloc 7 times which means we are limited to tcache sized chunks.
* Input is taken through the read function, So we can have null bytes in our payload.
* There is a null byte overflow or off by one bug while reading the description.
* We have a double free in the delete superpower function as the pointer is not nulled after its free'd.
