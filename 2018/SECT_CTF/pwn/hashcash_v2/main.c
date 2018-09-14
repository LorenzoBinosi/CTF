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