#ifndef __BASE64_H__
#define __BASE64_H__

char* base64_encode(char *dest, char *src, int len);
char* base64_decode(char *dest, char *src, int *len);

#endif // __BASE64_H__
