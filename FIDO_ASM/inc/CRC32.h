#ifndef __CRC32_H__
#define __CRC32_H__

class CRC32
{
    public:
        CRC32();
        virtual ~CRC32();
        static unsigned int CalcCRC32(const unsigned char *buf, unsigned int size, unsigned int crc = 0);
};

#endif // __CRC32_H__
