#ifndef __AUTHENTICATORPROFILE_H__
#define __AUTHENTICATORPROFILE_H__

#include "ASM.h"
#include <cstdio>
#include "HIDComm.h"

// @todo wrap this
// UUID 36 characters
// https://uuid.js.org/
#define KHAT_ACCESSTOKEN     ("bbe2c799-295e-4648-806e-a8f862de72b0")
#define KHAT_ACCESSTOKEN_LEN (36)

#define USB_VID                 (0xE383)
#define USB_PID                 (0x0007)

#define HID_PACKET_SIZE         (64)         /* EP2, EP3 wMaxPacketSize */

#define HID_CID					(0x01020304)

#define HID_CMD_PACKET          (0x80)
#define HID_CMD_NONE            (0x00)
#define HID_CMD_UAF             (HID_CMD_PACKET | 0x41)
#define HID_CMD_FINGERPRINT     (HID_CMD_PACKET | 0x51)
#define HID_CMD_UTIL            (HID_CMD_PACKET | 0x52)

#pragma pack(push, 1)
typedef struct
{
	unsigned int  CID;                       // Channel identifier
	unsigned char CMD;                       // Command identifier(bit 7 always set)
	unsigned char BCNTH;                     // High part of payload length
	unsigned char BCNTL;                     // Low part of payload length
	unsigned char DATA[(HID_PACKET_SIZE-7)]; // Payload data(s is equal to the fixed packet size(:64))
} InitPacket_t;
#pragma pack(pop)
#pragma pack(push, 1)
typedef struct
{
	unsigned int  CID;                       // Channel identifier
	unsigned char SEQ;                       // Packet sequence 0x00..0x7f (bit 7 always cleared)
	unsigned char DATA[(HID_PACKET_SIZE-5)]; // Payload data (s is equal to the fixed packet size(:64))
} ContPacket_t;
#pragma pack(pop)


#define UPDATE_PACKET_BLOCK_SIZE    (1536)
#pragma pack(push, 1)
typedef struct
{
	unsigned int  blkTotal;
	unsigned int  blkCount;
	unsigned int  blkSize;
	unsigned int  verify;
	unsigned char data[UPDATE_PACKET_BLOCK_SIZE];
} UpdatePacket_t;
#pragma pack(pop)

using ASMType::ASMRequest_t;
using ASMType::ASMResponse_t;
using ASMType::TESTASMResponse_t;
using ASMType::RegisterIn_t;
using ASMType::AuthenticateIn_t;
using ASMType::DeregisterIn_t;
using ASMType::GetInfoOut_t;
using ASMType::RegisterOut_t;
using ASMType::AuthenticateOut_t;
using ASMType::DeregisterOut_t;
using ASMType::GetRegistrationsOut_t;

using ASMType::FINGER_INDEX_0;
using ASMType::FINGER_INDEX_1;
using ASMType::FINGER_INDEX_2;
using ASMType::FINGER_INDEX_MAX;
using ASMType::FPIndexAndName_t;
using ASMType::FP_Name_t;
using ASMType::FP_Image_t;
using ASMType::FingerInfo_t;
using ASMType::FP_Req_t;
using ASMType::FP_Rsp_t;
using ASMType::FP_Enroll_Rsp_t;
using ASMType::FPGetListOut_t;
using ASMType::FPGetImageOut_t;
using ASMType::FPTestImageOut_t;

using ASMType::FirmwareUpdateIn_t;
using ASMType::FirmwareUpdateOut_t;
using ASMType::GetDeviceIDOut_t;

class IeWBMCallback
{
    public:
        virtual ~IeWBMCallback() {};
		virtual int FPTESTCallback(TESTASMResponse_t* param) = 0;
        virtual int FPCallback(void* param) = 0;
        virtual int UtilCallback(void* param) = 0;
};

class AuthenticatorProfile
{
    public:
        AuthenticatorProfile(const char* deviceName, int authenticatorIndex, unsigned long cid = HID_CID);
        AuthenticatorProfile(AuthenticatorProfile& Other);
        virtual ~AuthenticatorProfile();

        const char* GetDeviceName(void);

        int  GetAuthenticatorIndex(void);
        void SetAuthenticatorIndex(unsigned int in);

        asmEnumerationType_t GetDeviceStatus(void);
        void SetDeviceStatus(asmEnumerationType_t in);

        int HIDRead(unsigned char*  readBuffer, const unsigned long readBufferLength, int cmdType);
        int HIDRead(unsigned char** readBuffer,  int cmdType);
        int HIDWrite(unsigned char* writeBuffer, const unsigned long payload, int cmdType);

        /* UAF */
        int GetInfo(const ASMRequest_t getInfoIn, GetInfoOut_t* getInfoOut);
        int Register(const RegisterIn_t registerIn, RegisterOut_t* registerOut);
        int Authenticate(const AuthenticateIn_t authenticateIn, AuthenticateOut_t* authenticateOut);
        int Deregister(const DeregisterIn_t deregisterIn, DeregisterOut_t* deregisterOut);
        int GetRegistrations(const ASMRequest_t getRegistrationsIn, GetRegistrationsOut_t* getRegistrationsOut);

        /* FP */
        int Enroll(const ASMRequest_t in, ASMResponse_t* out);
        int Verify(const ASMRequest_t in, ASMResponse_t* out);
        int EnrollCheck(const ASMRequest_t in, ASMResponse_t* out);
        int RemoveEnroll(const ASMRequest_t in, ASMResponse_t* out);
        int GetFPList(const ASMRequest_t in, FPGetListOut_t* out);
        int GetFPImage(const ASMRequest_t in, FPGetImageOut_t* out);
		int TestFPImage(const FingerInfo_t in, FPTestImageOut_t* out);
		int VerifyFPImage(const FingerInfo_t in, FPTestImageOut_t* out);

        /* Util */
        int FimrwareUpdate(const FirmwareUpdateIn_t in, FirmwareUpdateOut_t* out);
        int GetDeviceID(const ASMRequest_t in, GetDeviceIDOut_t* out);
		int SDBInit(const ASMRequest_t in, ASMResponse_t* out);
		int FIDOInit(const ASMRequest_t in, ASMResponse_t* out);

        bool operator==(const char* other);
        bool operator!=(const char* other);
        bool operator!=(const AuthenticatorProfile& other);

        int SetPlaceFingerCB(IeWBMCallback* callback);
        int SetFWUpdateCB(IeWBMCallback* callback);

    private:
        IeWBMCallback* fpPlaceFingerCallback;
        IeWBMCallback* utilFWUpdateCallback;

        char* deviceName = NULL;
        HIDComm* hidComm = NULL;
        int authenticatorIndex;
        unsigned long cid;
        asmEnumerationType_t deviceStatus = Unplugged;

        int createUpdatePacket(const char* fileName, unsigned char** updateBinary, unsigned int* updateBinarySize);
};

#endif // __AUTHENTICATORPROFILE_H__
