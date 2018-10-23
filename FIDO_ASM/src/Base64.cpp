#include "base64.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

static const char MimeBase64[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
    'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
    'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', '+', '/'
};

static int DecodeMimeBase64[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 00-0F */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 10-1F */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,  /* 20-2F */
    52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,  /* 30-3F */
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,  /* 40-4F */
    15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,  /* 50-5F */
    -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,  /* 60-6F */
    41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,  /* 70-7F */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 80-8F */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 90-9F */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* A0-AF */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* B0-BF */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* C0-CF */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* D0-DF */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* E0-EF */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1   /* F0-FF */
};

#pragma pack(push, 1)
typedef union
{
#pragma pack(push, 1)
    struct
    {
        unsigned char c1,c2,c3;
    };
#pragma pack(pop)
#pragma pack(push, 1)
    struct
    {
        unsigned int e1:6,e2:6,e3:6,e4:6;
    };
#pragma pack(pop)
} BF;
#pragma pack(pop)

char* base64_encode(char *dest, char *src, int len)
{
    int i, j = 0;
    BF temp;

    for(i = 0 ; i < len ; i = i+3, j = j+4)
    {
        temp.c3 = src[i];
        if((i+1) >= len)
        {
            temp.c2 = 0x00;
        }
        else
        {
            temp.c2 = src[i+1];
        }

        if((i+2) >= len)
        {
            temp.c1 = 0x00;
        }
        else
        {
            temp.c1 = src[i+2];
        }

        dest[j]   = MimeBase64[temp.e4];
        dest[j+1] = MimeBase64[temp.e3];
        dest[j+2] = MimeBase64[temp.e2];
        dest[j+3] = MimeBase64[temp.e1];

        if((i+1) >= len)
        {
            dest[j+2] = '=';
        }

        if((i+2) >= len)
        {
            dest[j+3] = '=';
        }
    }

    return dest;
}

char* base64_decode(char *dest, char *src, int *len)
{
    int i, j = 0, src_len, blank = 0;
    BF temp;

    src_len = (int)strlen(src);

    for(i = 0 ; i < src_len ; i = i+4, j = j+3)
    {
        temp.e4 = DecodeMimeBase64[(int)src[i]];
        temp.e3 = DecodeMimeBase64[(int)src[i+1]];
        if(src[i+2] == '=')
        {
            temp.e2 = 0x00;
            blank++;
        }
        else
        {
            temp.e2 = DecodeMimeBase64[(int)src[i+2]];
        }

        if(src[i+3] == '=')
        {
            temp.e1 = 0x00;
            blank++;
        }
        else
        {
            temp.e1 = DecodeMimeBase64[(int)src[i+3]];
        }

        dest[j]   = temp.c3;
        dest[j+1] = temp.c2;
        dest[j+2] = temp.c1;
    }
    *len = j-blank;

    return dest;
}
