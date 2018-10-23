#include "AuthenticatorProfile.h"
#include "AuthenticatorManager.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <ctime>
#include <io.h>
#include <string>

#include "Debug.h"

#include "Base64.h"
#include "KISA_SHA256.h"

#include "CRC32.h"

using std::string;
using std::calloc;
using std::realloc;

#define UPDATE_AREA_SIZE (0x00080000) // 512Kb

/*************************************************************************
* ---------------------- Device Descriptor ----------------------
* bLength                  : 0x12 (18 bytes)
* bDescriptorType          : 0x01 (Device Descriptor)
* bcdUSB                   : 0x110 (USB Version 1.10)
* bDeviceClass             : 0x00 (defined by the interface descriptors)
* bDeviceSubClass          : 0x00
* bDeviceProtocol          : 0x00
* bMaxPacketSize0          : 0x08 (8 bytes)
* idVendor                 : 0xE383
* idProduct                : 0x0007
* bcdDevice                : 0x0000
* iManufacturer            : 0x01 (String Descriptor 1)
*  Language 0x0409         : "eWBM"
* iProduct                 : 0x02 (String Descriptor 2)
*  Language 0x0409         : "eWBM FIDO"
* iSerialNumber            : 0x03 (String Descriptor 3)
*  Language 0x0409         : "A00015:07:49"
* bNumConfigurations       : 0x01 (1 Configuration)
*
* ------------------ Configuration Descriptor -------------------
* bLength                  : 0x09 (9 bytes)
* bDescriptorType          : 0x02 (Configuration Descriptor)
* wTotalLength             : 0x0040 (64 bytes)
* bNumInterfaces           : 0x02 (2 Interfaces)
* bConfigurationValue      : 0x01 (Configuration 1)
* iConfiguration           : 0x00 (No String Descriptor)
* bmAttributes             : 0x80
*  D7: Reserved, set 1     : 0x01
*  D6: Self Powered        : 0x00 (no)
*  D5: Remote Wakeup       : 0x00 (no)
*  D4..0: Reserved, set 0  : 0x00
* MaxPower                 : 0x32 (100 mA)
*
*     ---------------- Interface Descriptor -----------------
*     bLength                  : 0x09 (9 bytes)
*     bDescriptorType          : 0x04 (Interface Descriptor)
*     bInterfaceNumber         : 0x00
*     bAlternateSetting        : 0x00
*     bNumEndpoints            : 0x02 (2 Endpoints)
*     bInterfaceClass          : 0x03 (HID - Human Interface Device)
*     bInterfaceSubClass       : 0x00 (None)
*     bInterfaceProtocol       : 0x00 (None)
*     iInterface               : 0x00 (No String Descriptor)
*
*     ------------------- HID Descriptor --------------------
*     bLength                  : 0x09 (9 bytes)
*     bDescriptorType          : 0x21 (HID Descriptor)
*     bcdHID                   : 0x0001 (HID Version 0.01)
*     bCountryCode             : 0x00 (00 = not localized)
*     bNumDescriptors          : 0x01
*     Descriptor 1:
*     bDescriptorType          : 0x22 (Class=Report)
*     wDescriptorLength        : 0x001C (28 bytes)
*     Error reading descriptor : ERROR_INVALID_PARAMETER
*
*     ----------------- Endpoint Descriptor -----------------
*     bLength                  : 0x07 (7 bytes)
*     bDescriptorType          : 0x05 (Endpoint Descriptor)
*     bEndpointAddress         : 0x82 (Direction=IN EndpointID=2)
*     bmAttributes             : 0x03 (TransferType=Interrupt)
*     wMaxPacketSize           : 0x0040 (64 bytes)
*     bInterval                : 0x01 (1 ms)
*
*     ----------------- Endpoint Descriptor -----------------
*     bLength                  : 0x07 (7 bytes)
*     bDescriptorType          : 0x05 (Endpoint Descriptor)
*     bEndpointAddress         : 0x03 (Direction=OUT EndpointID=3)
*     bmAttributes             : 0x03 (TransferType=Interrupt)
*     wMaxPacketSize           : 0x0040 (64 bytes)
*     bInterval                : 0x01 (1 ms)
*
*     ---------------- Interface Descriptor -----------------
*     bLength                  : 0x09 (9 bytes)
*     bDescriptorType          : 0x04 (Interface Descriptor)
*     bInterfaceNumber         : 0x01
*     bAlternateSetting        : 0x00
*     bNumEndpoints            : 0x02 (2 Endpoints)
*     bInterfaceClass          : 0x08 (Mass Storage)
*     bInterfaceSubClass       : 0x06 (SCSI transparent command set)
*     bInterfaceProtocol       : 0x50 (Bulk¡©Only Transport)
*     iInterface               : 0x00 (No String Descriptor)
*
*     ----------------- Endpoint Descriptor -----------------
*     bLength                  : 0x07 (7 bytes)
*     bDescriptorType          : 0x05 (Endpoint Descriptor)
*     bEndpointAddress         : 0x84 (Direction=IN EndpointID=4)
*     bmAttributes             : 0x02 (TransferType=Bulk)
*     wMaxPacketSize           : 0x0040 (64 bytes)
*     bInterval                : 0x00 (ignored)
*
*     ----------------- Endpoint Descriptor -----------------
*     bLength                  : 0x07 (7 bytes)
*     bDescriptorType          : 0x05 (Endpoint Descriptor)
*     bEndpointAddress         : 0x05 (Direction=OUT EndpointID=5)
*     bmAttributes             : 0x02 (TransferType=Bulk)
*     wMaxPacketSize           : 0x0040 (64 bytes)
*     bInterval                : 0x00 (ignored)
*
*     -------------------- String Descriptors -------------------
*         ------ String Descriptor 0 ------
*         bLength                  : 0x04 (4 bytes)
*         bDescriptorType          : 0x03 (String Descriptor)
*         Language ID[0]           : 0x0409 (English - United States)
*         ------ String Descriptor 1 ------
*         bLength                  : 0x0A (10 bytes)
*         bDescriptorType          : 0x03 (String Descriptor)
*         Language 0x0409          : "eWBM"
*         ------ String Descriptor 2 ------
*         bLength                  : 0x14 (20 bytes)
*         bDescriptorType          : 0x03 (String Descriptor)
*         Language 0x0409          : "eWBM FIDO"
*         ------ String Descriptor 3 ------
*         bLength                  : 0x1A (26 bytes)
*         bDescriptorType          : 0x03 (String Descriptor)
*         Language 0x0409          : "A00018:11:39"
*************************************************************************
*/

using ASMType::Version_t;
using ASMType::TLV_t;
using ASMType::AuthenticatorInfo_t;
using ASMType::DisplayPNGCharacteristicsDescriptor_t;
using ASMType::RGBPalletteEntry_t;
using ASMType::UserNameAndKeyHandle_t;
using ASMType::AppRegistration_t;
using ASMType::FingerInfo_t;

void dump(const unsigned char *data, int size, const char* tag)
{
#ifdef __DEBUG__
	if (data == NULL || size == 0)
	{
		return;
	}

	printf("---------------------------------------------------------\n");
	printf("%s(%04d): \r\n", tag, size);
	printf("%-10s", "Offset(h)");
	for (int i = 0; i < 0x10; i++)
	{
		printf("%02X ", i);
	}
	for (int i = 0; i < size; i++)
	{
		if (i % 0X10 == 0)
		{
			printf("\r\n%08X  ", i);
		}
		printf("%02X ", data[i]);
	}
	printf("\r\n");
	printf("---------------------------------------------------------\n");
#endif
}

AuthenticatorProfile::AuthenticatorProfile(const char* deviceName, int authenticatorIndex, unsigned long cid)
	: deviceName(NULL), authenticatorIndex(authenticatorIndex), cid(cid)
{
	int deviceNameLen = (int)strlen(deviceName);
	this->deviceName = new char[deviceNameLen + 1]{ 0, };
	if (this->deviceName != NULL)
		memcpy(this->deviceName, deviceName, deviceNameLen);

	hidComm = new HIDComm(deviceName);
}

AuthenticatorProfile::AuthenticatorProfile(AuthenticatorProfile& other)
{
	delete hidComm;
	hidComm = NULL;

	int deviceNameLen = (int)strlen(other.deviceName);
	this->deviceName = new char[deviceNameLen + 1]{ 0, };
	if (this->deviceName != NULL)
		memcpy(this->deviceName, other.deviceName, deviceNameLen);
	this->authenticatorIndex = other.authenticatorIndex;
}

AuthenticatorProfile::~AuthenticatorProfile()
{
	if (this->deviceName != NULL)
	{
		delete[] this->deviceName;
		this->deviceName = NULL;
	}
}

bool AuthenticatorProfile::operator==(const char* other)
{
	if (strcmp(this->deviceName, other) != 0)
	{
		return false;
	}
	return true;
}

bool AuthenticatorProfile::operator!=(const char* other)
{
	if (strcmp(this->deviceName, other) == 0)
	{
		return false;
	}
	return true;
}

bool AuthenticatorProfile::operator!=(const AuthenticatorProfile& other)
{
	if (strcmp(this->deviceName, other.deviceName) == 0)
	{
		return false;
	}
	return true;
}

int AuthenticatorProfile::GetAuthenticatorIndex(void)
{
	return authenticatorIndex;
}

void AuthenticatorProfile::SetAuthenticatorIndex(unsigned int in)
{
	authenticatorIndex = in;
}

const char* AuthenticatorProfile::GetDeviceName(void)
{
	return deviceName;
}

asmEnumerationType_t AuthenticatorProfile::GetDeviceStatus(void)
{
	return deviceStatus;
}

void AuthenticatorProfile::SetDeviceStatus(asmEnumerationType_t in)
{
	this->deviceStatus = in;
}

int AuthenticatorProfile::HIDRead(unsigned char* readBuffer, const unsigned long readBufferLength, int cmdType)
{
	int ret = 0;
	unsigned char readPacketBuffer[HID_PACKET_SIZE] = { 0, };
	unsigned int payload = 0;

	unsigned int timeOut = 0;
	switch (cmdType)
	{
		case HID_CMD_UAF:
			{
				timeOut = 5000;
			}
			break;

		case HID_CMD_FINGERPRINT:
			{
				timeOut = 100000;
			}
			break;

		case HID_CMD_UTIL:
			{
				timeOut = 20000;
			}
			break;
	}


	/* Check Parameter */
	if (readBuffer == NULL)
	{
		DBG_Log("error");
		return -1;
	}

	/* check Device */
	if (hidComm == NULL)
	{
		DBG_Log("error");
		return -1;
	}

	ret = hidComm->Read(readPacketBuffer, HID_PACKET_SIZE, timeOut);
	if (ret != 0)
	{
		DBG_Log("Read Fail");
		return -1;
	}

	/* read 64 Bytes(initial packet) */
	InitPacket_t* initPacket = (InitPacket_t*)readPacketBuffer;

	if (initPacket->CID != cid)
	{
		//dump(readPacketBuffer, HID_PACKET_SIZE, "receive Packet");
		DBG_Log("error");
		return -1;
	}

	if ((initPacket->CMD != HID_CMD_UAF) && (initPacket->CMD != HID_CMD_FINGERPRINT) && (initPacket->CMD != HID_CMD_UTIL))
	{
		//dump(readPacketBuffer, HID_PACKET_SIZE, "receive Packet");
		DBG_Log("error");
		return -1;
	}

	/* Check the Packet Header and Payload */
	payload = (((initPacket->BCNTH & 0xFF) << 8) | (initPacket->BCNTL & 0xFF));
	if (payload > readBufferLength)
	{
		//dump(readPacketBuffer, HID_PACKET_SIZE, "receive Packet");
		DBG_Log("error, payload is too big %d", payload);
		return -1;
	}

	/* copy var.. */
	unsigned int   copySize = 0;
	unsigned int   copyTotal = 0;
	unsigned char* copyDst = readBuffer;

	/* Copy to buffer */
	copySize = payload;
	if (copySize > sizeof(initPacket->DATA))
	{
		copySize = sizeof(initPacket->DATA);
	}
	copyTotal = 0;
	copyDst = readBuffer;
	if (memcpy(copyDst, initPacket->DATA, copySize) != copyDst)
	{
		DBG_Log("error");
		return -1;
	}
	copyTotal += copySize;
	copyDst += copySize;

	/* Reads continue while seq is lower than the totalSeuquence */
	const int totalSeuquence = ((copyTotal < payload) ? ((payload - (HID_PACKET_SIZE - 7)) / (HID_PACKET_SIZE - 5)) : 0);
	ContPacket_t* contPacket = (ContPacket_t*)readPacketBuffer;
	while ( copyTotal < payload )
	{
		/* read 64 Bytes(continue packet) */
		memset(readPacketBuffer, 0, sizeof(readPacketBuffer));
		ret = hidComm->Read(readPacketBuffer, HID_PACKET_SIZE, timeOut);
		if (ret != 0)
		{
			DBG_Log("Read Fail");
			return -1;
		}

		if (initPacket->CID != cid)
		{
			DBG_Log("error");
			return -1;
		}

		if (contPacket->SEQ > totalSeuquence)
		{
			DBG_Log("error, invalid sequence, seq: %d, total: %d", contPacket->SEQ, totalSeuquence);
			return -1;
		}

		/* Copy to buffer */
		copySize = payload - copyTotal;
		if (copySize > sizeof(contPacket->DATA))
		{
			copySize = sizeof(contPacket->DATA);
		}

		if (memcpy(copyDst, contPacket->DATA, copySize) != copyDst)
		{
			DBG_Log("error");
			return -1;
		}
		copyTotal += copySize;
		copyDst += copySize;
	}

	ret = copyTotal;
	return ret;
}

int AuthenticatorProfile::HIDRead(unsigned char** readBuffer, int cmdType)
{
	int ret = 0;
	unsigned char readPacketBuffer[HID_PACKET_SIZE] = { 0, };
	unsigned int payload = 0;

	unsigned int timeOut = 0;
	switch (cmdType)
	{
	case HID_CMD_UAF:
	{
		timeOut = 20000;
	}
	break;

	case HID_CMD_FINGERPRINT:
	{
		timeOut = 100000;
	}
	break;

	case HID_CMD_UTIL:
	{
		timeOut = 20000;
	}
	break;
	}


	/* Check Parameter */
	if (*readBuffer != NULL)
	{
		DBG_Log("error");
		return -1;
	}

	/* check Device */
	if (hidComm == NULL)
	{
		DBG_Log("error");
		return -1;
	}

	ret = hidComm->Read(readPacketBuffer, HID_PACKET_SIZE, timeOut);
	if (ret != 0)
	{
		DBG_Log("Read Fail");
		return -1;
	}

	/* read 64 Bytes(initial packet) */
	InitPacket_t* initPacket = (InitPacket_t*)readPacketBuffer;

	if (initPacket->CID != cid)
	{
		//dump(readPacketBuffer, HID_PACKET_SIZE, "receive Packet");
		DBG_Log("error");
		return -1;
	}

	if ((initPacket->CMD != HID_CMD_UAF) && (initPacket->CMD != HID_CMD_FINGERPRINT) && (initPacket->CMD != HID_CMD_UTIL))
	{
		//dump(readPacketBuffer, HID_PACKET_SIZE, "receive Packet");
		DBG_Log("error");
		return -1;
	}

	/* Check the Packet Header and Payload */
	payload = (((initPacket->BCNTH & 0xFF) << 8) | (initPacket->BCNTL & 0xFF));
	*readBuffer = new unsigned char[payload]{ 0, };
	if ( *readBuffer == NULL )
	{
		DBG_Log("new error");
		return -1;
	}

	/* copy var.. */
	unsigned int   copySize = 0;
	unsigned int   copyTotal = 0;
	unsigned char* copyDst = *readBuffer;

	/* Copy to buffer */
	copySize = payload;
	if (copySize > sizeof(initPacket->DATA))
	{
		copySize = sizeof(initPacket->DATA);
	}
	copyTotal = 0;
	copyDst = *readBuffer;
	if ( memcpy(copyDst, initPacket->DATA, copySize) != copyDst )
	{
		DBG_Log("error");
		return -1;
	}
	copyTotal += copySize;
	copyDst += copySize;

	/* Reads continue while seq is lower than the totalSeuquence */
	const int totalSeuquence = ((copyTotal < payload) ? ((payload - (HID_PACKET_SIZE - 7)) / (HID_PACKET_SIZE - 5)) : 0);
	ContPacket_t* contPacket = (ContPacket_t*)readPacketBuffer;
	while (copyTotal < payload)
	{
		/* read 64 Bytes(continue packet) */
		memset(readPacketBuffer, 0, sizeof(readPacketBuffer));
		ret = hidComm->Read(readPacketBuffer, HID_PACKET_SIZE, timeOut);
		if (ret != 0)
		{
			DBG_Log("Read Fail");
			return -1;
		}

		if (initPacket->CID != cid)
		{
			DBG_Log("error");
			return -1;
		}

		if (contPacket->SEQ > totalSeuquence)
		{
			DBG_Log("error, invalid sequence, seq: %d, total: %d", contPacket->SEQ, totalSeuquence);
			return -1;
		}

		/* Copy to buffer */
		copySize = payload - copyTotal;
		if (copySize > sizeof(contPacket->DATA))
		{
			copySize = sizeof(contPacket->DATA);
		}

		if (memcpy(copyDst, contPacket->DATA, copySize) != copyDst)
		{
			DBG_Log("error");
			return -1;
		}
		copyTotal += copySize;
		copyDst += copySize;
	}

	ret = copyTotal;
	return ret;
}

int AuthenticatorProfile::HIDWrite(unsigned char* writeBuffer, const unsigned long payload, int cmdType)
{
	int ret = 0;
	unsigned char writePacketBuffer[HID_PACKET_SIZE] = { 0, };

	/* Check Parameter */
	if (writeBuffer == NULL || !(cmdType == HID_CMD_UAF || cmdType == HID_CMD_FINGERPRINT || cmdType == HID_CMD_UTIL))
	{
		DBG_Log("error");
		return -1;
	}

	unsigned int timeOut = 0;
	switch (cmdType)
	{
		case HID_CMD_UAF:
			{
				timeOut = 5000;
			}
			break;

		case HID_CMD_FINGERPRINT:
			{
				timeOut = 5000;
			}
			break;

		case HID_CMD_UTIL:
			{
				timeOut = 5000;
			}
			break;
	}

	/* check Device */
	if (hidComm == NULL)
	{
		DBG_Log("error");
		return -1;
	}

	/* Make the initilal packet */
	InitPacket_t* initPacket = (InitPacket_t*)writePacketBuffer;
	memset(writePacketBuffer, 0, sizeof(writePacketBuffer));
	initPacket->CID = cid;
	initPacket->CMD = cmdType;
	initPacket->BCNTH = (payload >> 8) & 0xFF;
	initPacket->BCNTL = payload & 0xFF;

	/* copy var.. */
	unsigned int   copySize = 0;
	unsigned int   copyTotal = 0;
	unsigned char* copySrc = writeBuffer;

	copySize = payload;
	if (copySize > sizeof(initPacket->DATA))
	{
		copySize = sizeof(initPacket->DATA);
	}
	memset(initPacket->DATA, 0xcc, sizeof(initPacket->DATA));
	if (memcpy(initPacket->DATA, copySrc, copySize) != initPacket->DATA)
	{
		DBG_Log("error");
		return -1;
	}

	copyTotal += copySize;
	copySrc += copySize;

	/* send 64 Bytes(initial packet) */
	ret = hidComm->Write(writePacketBuffer, HID_PACKET_SIZE, timeOut);
	if (ret != 0)
	{
		DBG_Log("Write Fail");
		return -1;
	}

	/* write continue until seq is higher than the totalSeuquence */
	const int totalSeuquence = (payload - (HID_PACKET_SIZE - 7)) / (HID_PACKET_SIZE - 5);
	ContPacket_t* contPacket = (ContPacket_t*)writePacketBuffer;
	memset(writePacketBuffer, 0, sizeof(writePacketBuffer));
	contPacket->CID = cid;
	contPacket->SEQ = 0;
	while ( copyTotal < payload )
	{
		if (contPacket->SEQ > totalSeuquence || contPacket->SEQ > 127)
		{
			DBG_Log("error");
			return -1;
		}

		copySize = (payload - copyTotal);
		if (copySize > sizeof(contPacket->DATA))
		{
			copySize = sizeof(contPacket->DATA);
		}
		memset(contPacket->DATA, 0xcc, sizeof(contPacket->DATA));
		if (memcpy(contPacket->DATA, copySrc, copySize) != contPacket->DATA)
		{
			DBG_Log("error");
			return -1;
		}

		copyTotal += copySize;
		copySrc += copySize;

		/* send 64 Bytes(initial packet) */
		ret = hidComm->Write(writePacketBuffer, HID_PACKET_SIZE, timeOut);
		if (ret != 0)
		{
			DBG_Log("Write Fail");
			return -1;
		}

		contPacket->SEQ++;
	}

	ret = copyTotal;
	return ret;
}

int AuthenticatorProfile::SetPlaceFingerCB(IeWBMCallback* callback)
{
	fpPlaceFingerCallback = callback;
	return 0;
}


int AuthenticatorProfile::SetFWUpdateCB(IeWBMCallback* callback)
{
	utilFWUpdateCallback = callback;
	return 0;
}

int AuthenticatorProfile::GetInfo(const ASMRequest_t getInfoIn, GetInfoOut_t* getInfoOut)
{
	int ret = 0;

	unsigned char buffer[8192] = { 0, };
	TLV_t* request = (TLV_t*)buffer;
	request->t = TAG_UAF_REQ_GETINFO;
	request->l = 0;

	memset(getInfoOut, 0x00, sizeof(GetInfoOut_t));

	ret = HIDWrite(buffer, 4, HID_CMD_UAF);
	if (ret < 0)
	{
		DBG_Log("HIDWrite Fail");
		return -1;
	}

	ret = HIDRead(buffer, sizeof(buffer), HID_CMD_UAF);
	if (ret < 0)
	{
		DBG_Log("HIDRead Fail");
		return -1;
	}

	/* Start Parsing */
	TLV_t* response = (TLV_t*)buffer;
	if (response->t != TAG_UAF_RSP_GETINFO)
	{
		DBG_Log("invalid tag");
		return -1;
	}

	int statusCode = -1;
	int getInfoResponseOffset = 0;
	int getInfoResponseLength = response->l;
	DBG_Log("T: 0x%04X", response->t);
	DBG_Log("L: 0x%04X", response->l);
	dump(response->v, response->l, "V:");
	getInfoResponseOffset += 4;
	response = (TLV_t*)(buffer + getInfoResponseOffset);

	getInfoOut->Authenticators = new AuthenticatorInfo_t;
	memset(getInfoOut->Authenticators, 0x00, sizeof(AuthenticatorInfo_t));

	while ( getInfoResponseOffset < (getInfoResponseLength + 4) )
	{
		switch (response->t)
		{
			case TAG_UAF_STATUS_CODE:
				{
					statusCode = *((unsigned short*)response->v);
					switch (statusCode)
					{
						case UAF_STATUS_OK:
							{
								DBG_Log(" - UAF Status: OK");
								statusCode = UAF_ASM_STATUS_OK;
							}
							break;

						case UAF_STATUS_USER_NOT_ENROLLED:
						case UAF_STATUS_CANNOT_RENDER_TRANSACTION_CONTENT:
						case UAF_STATUS_CMD_NOT_SUPPORTED:
						case UAF_STATUS_ATTESTATION_NOT_SUPPORTED:
							{
								DBG_Log(" - UAF Status: Error(0x%02X)", statusCode);
								statusCode = UAF_ASM_STATUS_ERROR;
							}
							break;

						case UAF_STATUS_USER_CANCELLED:
							{
								DBG_Log(" - GetInfo Status: User Cancelled(0x%02X)", statusCode);
								statusCode = UAF_ASM_STATUS_USER_CANCELLED;
							}
							break;
					}

					dump(response->v, response->l, "Status Code");

					getInfoResponseOffset += (4 + response->l);
					response = (TLV_t*)(buffer + getInfoResponseOffset);
				}
				break;

			case TAG_UAF_API_VERSION:
				{
					if (response->l != 0x0001)
					{
						DBG_Log("API version length isn't 0x0001 (value: 0x%04X)", response->l);
						statusCode = UAF_ASM_STATUS_ERROR;
					}

					if (response->v[0] != 0x01)
					{
						DBG_Log("API version isn't 0x01 (value: 0x%02X)", response->v[0]);
						statusCode = UAF_ASM_STATUS_ERROR;
					}

					dump(response->v, response->l, "API Version");
					getInfoResponseOffset += (4 + response->l);
					response = (TLV_t*)(buffer + getInfoResponseOffset);
				}
				break;

			case TAG_UAF_AUTHENTICATOR_INFO:
				{
					int authenticatorInfoOffset = 0;
					int authenticatorInfoLength = response->l;
					dump(response->v, response->l, "Authenticator Info");
					authenticatorInfoOffset += 4;
					response = (TLV_t*)(buffer + (getInfoResponseOffset + authenticatorInfoOffset));

					while ( authenticatorInfoOffset < (authenticatorInfoLength + 4))
					{
						switch (response->t)
						{
							case TAG_UAF_AUTHENTICATOR_INDEX:
								{
									if (response->l != 0x0001)
									{
										DBG_Log("Authenticator Index length isn't 0x0001 (value: 0x%04X)", response->l);
										statusCode = UAF_ASM_STATUS_ERROR;
									}

									unsigned char authenticatorIndex = response->v[0];

									getInfoOut->Authenticators->authenticatorIndex = authenticatorIndex;
									if (getInfoIn.authenticatorIndex != authenticatorIndex)
									{
										DBG_Log("authenticatorIndex: 0x%02X, 0x%02X", getInfoIn.authenticatorIndex, authenticatorIndex);
										getInfoOut->Authenticators->authenticatorIndex = getInfoIn.authenticatorIndex;
									}

									dump(response->v, response->l, "Authenticator Index");
									authenticatorInfoOffset += (4 + response->l);
									response = (TLV_t*)(buffer + getInfoResponseOffset + authenticatorInfoOffset);
								}
								break;

							case TAG_AAID:
								{
									getInfoOut->Authenticators->aaid = new unsigned char[response->l + 1]{ 0, };
									memcpy(getInfoOut->Authenticators->aaid, response->v, response->l);

									dump(response->v, response->l, "AAID");
									authenticatorInfoOffset += (4 + response->l);
									response = (TLV_t*)(buffer + getInfoResponseOffset + authenticatorInfoOffset);
								}
								break;

							case TAG_UAF_AUTHENTICATOR_METADATA:
								{
									unsigned int   authenticatorMetadataOffset = 0;
									unsigned char* authenticatorMetadataBuffer = response->v;

									/* AuthenticatorType */
									unsigned short authenticatorType = *((unsigned short*)authenticatorMetadataBuffer);
									getInfoOut->Authenticators->isSecondFactorOnly = (authenticatorType & 0x0001) ? true : false;
									getInfoOut->Authenticators->isRoamingAuthenticator = (authenticatorType & 0x0002) ? true : false;
									getInfoOut->Authenticators->hasSettings = (authenticatorType & 0x0010) ? true : false;
									getInfoOut->Authenticators->isUserEnrolled = (authenticatorType & 0x0040) ? true : false;
									DBG_Log(" - AuthenticatorType: 0x%04X", authenticatorType);
									authenticatorMetadataOffset += 2;
									authenticatorMetadataBuffer += authenticatorMetadataOffset;

#ifdef __DEBUG__
									/* MaxKeyHandles */
									unsigned short maxKeyHandles = *((unsigned char*)authenticatorMetadataBuffer);
									DBG_Log(" - MaxKeyHandles:     0x%02X", maxKeyHandles);
#endif
									authenticatorMetadataOffset += 1;
									authenticatorMetadataBuffer += authenticatorMetadataOffset;

									/* UserVerification */
									unsigned int userVerification = *((unsigned int*)authenticatorMetadataBuffer);
									getInfoOut->Authenticators->userVerification = userVerification;
									DBG_Log(" - UserVerification:  0x%08X", userVerification);
									authenticatorMetadataOffset += 4;
									authenticatorMetadataBuffer += authenticatorMetadataOffset;

									/* KeyProtection */
									unsigned short keyProtection = *((unsigned short*)authenticatorMetadataBuffer);
									getInfoOut->Authenticators->keyProtection = keyProtection;
									DBG_Log(" - KeyProtection:     0x%04X", keyProtection);
									authenticatorMetadataOffset += 2;
									authenticatorMetadataBuffer += authenticatorMetadataOffset;

									/* MatcherProtection */
									unsigned short matcherProtection = *((unsigned short*)authenticatorMetadataBuffer);
									getInfoOut->Authenticators->matcherProtection = matcherProtection;
									DBG_Log(" - MatcherProtection: 0x%04X", matcherProtection);
									authenticatorMetadataOffset += 2;
									authenticatorMetadataBuffer += authenticatorMetadataOffset;

									/* TransactionConfirmationDisplay */
									unsigned short tcDisplay = *((unsigned short*)authenticatorMetadataBuffer);
									getInfoOut->Authenticators->tcDisplay = tcDisplay;
									DBG_Log(" - TransactionConfirmationDisplay: 0x%04X", tcDisplay);
									authenticatorMetadataOffset += 2;
									authenticatorMetadataBuffer += authenticatorMetadataOffset;

									/* AuthenticationAlg */
									unsigned short authenticationAlgorithm = *((unsigned short*)authenticatorMetadataBuffer);
									getInfoOut->Authenticators->authenticationAlgorithm = authenticationAlgorithm;
									DBG_Log(" - AuthenticationAlg: 0x%04X", authenticationAlgorithm);
									authenticatorMetadataOffset += 2;
									authenticatorMetadataBuffer += authenticatorMetadataOffset;

									dump(response->v, response->l, "Authenticator Metadata");
									authenticatorInfoOffset += (4 + response->l);
									response = (TLV_t*)(buffer + getInfoResponseOffset + authenticatorInfoOffset);
								}
								break;

							case TAG_UAF_TC_DISPLAY_CONTENT_TYPE:
								{
									getInfoOut->Authenticators->tcDisplayContentType = new unsigned char[response->l + 1]{ 0, };
									memcpy(getInfoOut->Authenticators->tcDisplayContentType, response->v, response->l);

									dump(response->v, response->l, "TC Display Content Type");
									authenticatorInfoOffset += (4 + response->l);
									response = (TLV_t*)(buffer + getInfoResponseOffset + authenticatorInfoOffset);
								}
								break;

							case TAG_UAF_TC_DISPLAY_PNG_CHARACTERISTICS:
								{
									getInfoOut->Authenticators->tcDisplayPNGCharacteristics = new DisplayPNGCharacteristicsDescriptor_t;
									memset(getInfoOut->Authenticators->tcDisplayPNGCharacteristics, 0x00, sizeof(DisplayPNGCharacteristicsDescriptor_t));

									getInfoOut->Authenticators->tcDisplayPNGCharacteristics->plte = new RGBPalletteEntry_t;
									memset(getInfoOut->Authenticators->tcDisplayPNGCharacteristics->plte, 0x00, sizeof(RGBPalletteEntry_t));

									getInfoOut->Authenticators->tcDisplayPNGCharacteristics->width = *((unsigned int*)&response->v[0]);
									getInfoOut->Authenticators->tcDisplayPNGCharacteristics->height = *((unsigned int*)&response->v[4]);
									getInfoOut->Authenticators->tcDisplayPNGCharacteristics->bitDepth = *((unsigned char*)&response->v[5]);
									getInfoOut->Authenticators->tcDisplayPNGCharacteristics->colorType = *((unsigned char*)&response->v[6]);
									getInfoOut->Authenticators->tcDisplayPNGCharacteristics->compression = *((unsigned char*)&response->v[7]);
									getInfoOut->Authenticators->tcDisplayPNGCharacteristics->filter = *((unsigned char*)&response->v[8]);
									getInfoOut->Authenticators->tcDisplayPNGCharacteristics->interlace = *((unsigned char*)&response->v[9]);
									getInfoOut->Authenticators->tcDisplayPNGCharacteristics->plte->r = *((unsigned short*)&response->v[10]);
									getInfoOut->Authenticators->tcDisplayPNGCharacteristics->plte->g = *((unsigned short*)&response->v[12]);
									getInfoOut->Authenticators->tcDisplayPNGCharacteristics->plte->b = *((unsigned short*)&response->v[14]);

									dump(response->v, response->l, "TC DISPLAY PNG CHARACTERISTICS");
									authenticatorInfoOffset += (4 + response->l);
									response = (TLV_t*)(buffer + getInfoResponseOffset + authenticatorInfoOffset);
								}
								break;

							case TAG_UAF_ASSERTION_SCHEME:
								{
									getInfoOut->Authenticators->assertionScheme = new unsigned char[response->l + 1]{ 0, };
									memcpy(getInfoOut->Authenticators->assertionScheme, response->v, response->l);

									dump(response->v, response->l, "TAG_UAF_ASSERTION_SCHEME");
									authenticatorInfoOffset += (4 + response->l);
									response = (TLV_t*)(buffer + getInfoResponseOffset + authenticatorInfoOffset);
								}
								break;

							case TAG_UAF_ATTESTATION_TYPE:
								{
									if (response->l != 0x0002)
									{
										DBG_Log("Attestation Types length isn't 0x0002 (value: 0x%04X)", response->l);
										statusCode = UAF_ASM_STATUS_ERROR;
									}

									getInfoOut->Authenticators->attestationTypes = *((unsigned short*)response->v);

									dump(response->v, response->l, "TAG_UAF_ATTESTATION_TYPE");
									authenticatorInfoOffset += (4 + response->l);
									response = (TLV_t*)(buffer + getInfoResponseOffset + authenticatorInfoOffset);
								}
								break;

							case TAG_UAF_SUPPORTED_EXTENSION_ID:
								{
									getInfoOut->Authenticators->supportedExtensionIDs = new unsigned char[response->l + 1]{ 0, };
									memcpy(getInfoOut->Authenticators->supportedExtensionIDs, response->v, response->l);

									dump(response->v, response->l, "TAG_UAF_SUPPORTED_EXTENSION_ID");
									authenticatorInfoOffset += (4 + response->l);
									response = (TLV_t*)(buffer + getInfoResponseOffset + authenticatorInfoOffset);
								}
								break;

							default:
								{
									DBG_Log("invalid TAG 0x%04X", response->t);
								}
								break;
							}
						}
						getInfoResponseOffset += authenticatorInfoOffset;
					}
					break;

				default:
					{
						DBG_Log("invalid TAG 0x%04X", response->t);
					}
					break;
		}
	}

	if (statusCode != UAF_ASM_STATUS_OK)
	{
		DBG_Log("error: statusCode is not a UAF_ASM_STATUS_OK");
		return -1;
	}

	return 0;
}

int AuthenticatorProfile::Register(const RegisterIn_t registerIn, RegisterOut_t* registerOut)
{
	int ret = 0;

	unsigned char buffer[8192] = { 0, };
	unsigned int  registerRequestOffset = 0;
	TLV_t* request = (TLV_t*)buffer;

	request->t = TAG_UAF_REQ_REGISTER;
	request->l = 0;
	registerRequestOffset += (4 + request->l);
	request = (TLV_t*)(buffer + registerRequestOffset);

	request->t = TAG_UAF_AUTHENTICATOR_INDEX;
	request->l = 1;
	request->v[0] = (unsigned char)(authenticatorIndex % 0xFF);
	registerRequestOffset += (4 + request->l);
	request = (TLV_t*)(buffer + registerRequestOffset);

	request->t = TAG_UAF_APPID;
	unsigned short appIDSize = (unsigned short)strlen((char*)registerIn.appID);
	if (appIDSize > APPID_MAX)
	{
		appIDSize = APPID_MAX;
	}
	request->l = appIDSize;
	memcpy(request->v, registerIn.appID, request->l);
	registerRequestOffset += (4 + request->l);
	request = (TLV_t*)(buffer + registerRequestOffset);

	request->t = TAG_FINAL_CHALLENGE_HASH;
	request->l = 32;
	unsigned short finalChallengeHashSize = (unsigned short)strlen((char*)registerIn.finalChallenge);
	if ( finalChallengeHashSize > FINALCHALLENGE_MAX )
	{
		finalChallengeHashSize = FINALCHALLENGE_MAX;
	}
	unsigned char* finalChallengeHashData = new unsigned char[finalChallengeHashSize] {0};
	if (finalChallengeHashData == NULL)
	{
		return -1;
	}
	memcpy(finalChallengeHashData, registerIn.finalChallenge, finalChallengeHashSize);
	SHA256_Encrpyt(finalChallengeHashData, finalChallengeHashSize, request->v);
	delete[] finalChallengeHashData;
	finalChallengeHashData = NULL;
	registerRequestOffset += (4 + request->l);
	request = (TLV_t*)(buffer + registerRequestOffset);

	request->t = TAG_UAF_USERNAME;
	unsigned short userNameSize = (unsigned short)strlen((char*)registerIn.username);
	if ( userNameSize > USERNAME_MAX )
	{
		userNameSize = USERNAME_MAX;
	}
	request->l = userNameSize;
	memcpy(request->v, registerIn.username, request->l);
	registerRequestOffset += (4 + request->l);
	request = (TLV_t*)(buffer + registerRequestOffset);

	request->t = TAG_UAF_ATTESTATION_TYPE;
	request->l = 2;
	memcpy(request->v, &registerIn.attestationType, request->l);
	registerRequestOffset += (4 + request->l);
	request = (TLV_t*)(buffer + registerRequestOffset);

	request->t = TAG_UAF_KEYHANDLE_ACCESS_TOKEN;
	request->l = 32;
	unsigned short khaccessTokenSize = KHAT_ACCESSTOKEN_LEN + appIDSize;
	unsigned char* khaccessTokenData = new unsigned char[khaccessTokenSize] {0};
	if ( khaccessTokenData == NULL )
	{
		return -1;
	}
	memcpy(khaccessTokenData, (unsigned char*)KHAT_ACCESSTOKEN, KHAT_ACCESSTOKEN_LEN);
	memcpy(khaccessTokenData + KHAT_ACCESSTOKEN_LEN, registerIn.appID, appIDSize);
	SHA256_Encrpyt(khaccessTokenData, khaccessTokenSize, request->v);
	delete[] khaccessTokenData;
	khaccessTokenData = NULL;

	registerRequestOffset += (4 + request->l);
	request = (TLV_t*)(buffer + registerRequestOffset);

	request->t = TAG_UAF_USERVERIFY_TOKEN;
	request->l = 0;
	registerRequestOffset += (4+request->l);
	request = (TLV_t*)(buffer+registerRequestOffset);

	request = (TLV_t*)buffer;
	request->l = registerRequestOffset - 4;

	memset(registerOut, 0x00, sizeof(RegisterOut_t));

	ret = HIDWrite(buffer, registerRequestOffset, HID_CMD_UAF);
	if (ret < 0)
	{
		DBG_Log("HIDWrite Fail");
		return -1;
	}

	int statusCode = -1;
	bool loop = true;
	while ( loop )
	{
		memset(buffer, 0x00, sizeof(buffer));
		ret = HIDRead(buffer, sizeof(buffer), HID_CMD_FINGERPRINT);
		if (ret < 0)
		{
			DBG_Log("HIDRead Fail");
			return -1;
		}


		/* Start Parsing */
		TLV_t* response = (TLV_t*)buffer;
		DBG_Log("T: 0x%04X", response->t);
		DBG_Log("L: 0x%04X", response->l);

		if (response->t == TAG_FP_RSP_VERIFY)
		{
			int fpResponse = -1;

			fpResponse = *((unsigned short*)response->v);

			if (fpResponse == FP_STATUS_PLACE_FINGER)
			{
				DBG_Log("Place Your Finger");
				if (fpPlaceFingerCallback != NULL)
				{
					unsigned short statusCode = TAG_FP_RSP_VERIFY;
					FP_Enroll_Rsp_t enrollResp;
					enrollResp.cmd = FP_STATUS_PLACE_FINGER;
					enrollResp.total = 0;
					enrollResp.count = 0;

					ASMResponse_t fpASMResponse;
					fpASMResponse.responseData = ((void*)&enrollResp);
					fpASMResponse.statusCode = statusCode;
					fpPlaceFingerCallback->FPCallback(&fpASMResponse);
				}
			}
		}
		else if (response->t == TAG_UAF_RSP_REGISTER)
		{
			int registerResponseOffset = 0;
			int registerResponseLength = response->l;
			dump(response->v, response->l, "V:");
			registerResponseOffset += 4;
			response = (TLV_t*)(buffer + registerResponseOffset);

			while ( registerResponseOffset < (registerResponseLength + 4) )
			{
				switch (response->t)
				{
					case TAG_UAF_STATUS_CODE:
						{
							statusCode = *((unsigned short*)response->v);
							switch (statusCode)
							{
								case UAF_STATUS_OK:
									{
										DBG_Log(" - UAF Status: OK");
										statusCode = UAF_ASM_STATUS_OK;
									}
									break;

								case UAF_STATUS_USER_NOT_ENROLLED:
								case UAF_STATUS_CANNOT_RENDER_TRANSACTION_CONTENT:
								case UAF_STATUS_CMD_NOT_SUPPORTED:
								case UAF_STATUS_ATTESTATION_NOT_SUPPORTED:
									{
										DBG_Log(" - UAF Status: Error(0x%02X)", statusCode);
										statusCode = UAF_ASM_STATUS_ERROR;
									}
									break;

								case UAF_STATUS_USER_CANCELLED:
									{
										DBG_Log(" - UAF Status: User Cancelled(0x%02X)", statusCode);
										statusCode = UAF_ASM_STATUS_USER_CANCELLED;
									}
									break;
							}

							dump(response->v, response->l, "Status Code");

							registerResponseOffset += (4 + response->l);
							response = (TLV_t*)(buffer + registerResponseOffset);
						}
						break;

					case TAG_UAF_AUTHENTICATOR_ASSERTION:
						{
							unsigned short assertionSize = ((4 * (response->l / 3)) + (response->l % 3 ? 4 : 0));
							registerOut->assertion = new unsigned char[assertionSize + 1]{ 0, };
							base64_encode((char*)registerOut->assertion, (char*)response->v, response->l);
							dump(response->v, response->l, "assertion");
							DBG_Log("%s", (char*)registerOut->assertion);

							registerResponseOffset += (4 + response->l);
							response = (TLV_t*)(buffer + registerResponseOffset);
						}
						break;

					case TAG_UAF_KEYHANDLE:
						{
							int keyHandleSize = ((4 * (response->l / 3)) + ((response->l % 3) ? 4 : 0));
							registerOut->keyHandle = new unsigned char[keyHandleSize + 1]{ 0, };
							if (registerOut->keyHandle == NULL)
							{
								DBG_Log("keyHandle memory address is NULL");
								return -1;
							}
							base64_encode((char*)registerOut->keyHandle, (char*)response->v, response->l);
							dump(response->v, response->l, "keyHandle");
							registerResponseOffset += (4 + response->l);
							response = (TLV_t*)(buffer + registerResponseOffset);
						}
						break;

					default:
						{
							DBG_Log("invalid TAG 0x%04X", response->t);
							registerResponseOffset += 1;
							response = (TLV_t*)(buffer + registerResponseOffset);
						}
						break;
				}
			}

			loop = false;

		}
		else
		{
			DBG_Log("invalid tag 0x%04X", response->t);
			dump(response->v, response->l, "invalid tag");

			loop = false;
		}
	}

	if (statusCode != UAF_ASM_STATUS_OK)
	{
		DBG_Log("error: statusCode is not a UAF_ASM_STATUS_OK");
		return statusCode;
	}

	return statusCode;
}

int AuthenticatorProfile::Authenticate(const AuthenticateIn_t authenticateIn, AuthenticateOut_t* authenticateOut)
{
	int ret = 0;

	unsigned char* buffer = new unsigned char[0x2000] { 0, };
	unsigned int   authenticateRequestOffset = 0;
	TLV_t* request = (TLV_t*)buffer;

	request->t = TAG_UAF_REQ_SIGN;
	request->l = 0;
	authenticateRequestOffset += (4 + request->l);
	request = (TLV_t*)(buffer + authenticateRequestOffset);

	request->t = TAG_UAF_AUTHENTICATOR_INDEX;
	request->l = 1;
	request->v[0] = (unsigned char)(authenticatorIndex % 0xFF);
	authenticateRequestOffset += (4 + request->l);
	request = (TLV_t*)(buffer + authenticateRequestOffset);

	request->t = TAG_UAF_APPID;
	unsigned short appIDSize = (unsigned short)strlen((char*)authenticateIn.appID);
	if (appIDSize > APPID_MAX)
	{
		appIDSize = APPID_MAX;
	}
	request->l = appIDSize;
	memcpy(request->v, authenticateIn.appID, request->l);
	authenticateRequestOffset += (4 + request->l);
	request = (TLV_t*)(buffer + authenticateRequestOffset);

	request->t = TAG_FINAL_CHALLENGE_HASH;
	request->l = 32;
	unsigned short finalChallengeHashSize = (unsigned short)strlen((char*)authenticateIn.finalChallenge);
	if ( finalChallengeHashSize > FINALCHALLENGE_MAX )
	{
		finalChallengeHashSize = FINALCHALLENGE_MAX;
	}
	unsigned char* finalChallengeHashData = new unsigned char[finalChallengeHashSize] {0};
	if ( finalChallengeHashData == NULL )
	{
		return -1;
	}
	memcpy(finalChallengeHashData, authenticateIn.finalChallenge, finalChallengeHashSize);
	SHA256_Encrpyt(finalChallengeHashData, finalChallengeHashSize, request->v);
	delete[] finalChallengeHashData;
	finalChallengeHashData = NULL;
	authenticateRequestOffset += (4 + request->l);
	request = (TLV_t*)(buffer + authenticateRequestOffset);

	request->t = TAG_UAF_TRANSACTION_CONTENT;
	request->l = 0;
	authenticateRequestOffset += (4+request->l);
	request = (TLV_t*)(buffer+authenticateRequestOffset);

	request->t = TAG_TRANSACTION_CONTENT_HASH;
	request->l = 0;
	authenticateRequestOffset += (4+request->l);
	request = (TLV_t*)(buffer+authenticateRequestOffset);

	request->t = TAG_UAF_KEYHANDLE_ACCESS_TOKEN;
	request->l = 32;
	unsigned short khaccessTokenSize = KHAT_ACCESSTOKEN_LEN + appIDSize;
	unsigned char* khaccessTokenData = new unsigned char[khaccessTokenSize] {0};
	if ( khaccessTokenData == NULL )
	{
		return -1;
	}
	memcpy(khaccessTokenData, (unsigned char*)KHAT_ACCESSTOKEN, KHAT_ACCESSTOKEN_LEN);
	memcpy(khaccessTokenData + KHAT_ACCESSTOKEN_LEN, authenticateIn.appID, appIDSize);
	SHA256_Encrpyt(khaccessTokenData, khaccessTokenSize, request->v);
	delete[] khaccessTokenData;
	khaccessTokenData = NULL;
	authenticateRequestOffset += (4 + request->l);
	request = (TLV_t*)(buffer + authenticateRequestOffset);

	request->t = TAG_UAF_USERVERIFY_TOKEN;
	request->l = 0;
	authenticateRequestOffset += (4+request->l);
	request = (TLV_t*)(buffer+authenticateRequestOffset);

	/* TAG_KEYHANDLE (optional, multiple occurrences permitted) */
	if (authenticateIn.keyHandle != NULL)
	{
		unsigned int keyHandleLen = (unsigned int)strlen((const char*)authenticateIn.keyHandle);
		if (keyHandleLen <= 0)
		{
			DBG_Log("keyHandle length error");
			return -1;
		}
		request->t = TAG_UAF_KEYHANDLE;
		int decodeKeyHandleSize = ((4 * (keyHandleLen / 3)) + (keyHandleLen % 3) ? 4 : 0);

		base64_decode((char*)request->v, (char*)authenticateIn.keyHandle, &decodeKeyHandleSize);
		request->l = (unsigned short)decodeKeyHandleSize;

		authenticateRequestOffset += (4 + request->l);
		request = (TLV_t*)(buffer + authenticateRequestOffset);
	}

	request = (TLV_t*)buffer;
	request->l = authenticateRequestOffset - 4;

	memset(authenticateOut, 0x00, sizeof(AuthenticateOut_t));

	dump(buffer, authenticateRequestOffset, "SendBuffer");

	ret = HIDWrite(buffer, authenticateRequestOffset, HID_CMD_UAF);
	if ( buffer != NULL )
	{
		delete[] buffer;
		buffer = NULL;
	}
	if (ret < 0)
	{
		DBG_Log("HIDWrite Fail");
		return -1;
	}

	int statusCode = -1;
	bool loop = true;
	while ( loop )
	{
		if (buffer != NULL)
		{
			delete[] buffer;
			buffer = NULL;
		}
		ret = HIDRead(&buffer, HID_CMD_FINGERPRINT);
		if (ret < 0)
		{
			DBG_Log("HIDRead Fail");
			return -1;
		}

		/* Start Parsing */
		TLV_t* response = (TLV_t*)buffer;
		DBG_Log("T: 0x%04X", response->t);
		DBG_Log("L: 0x%04X", response->l);

		if (response->t == TAG_FP_RSP_VERIFY)
		{
			int fpResponse = -1;

			fpResponse = *((unsigned short*)response->v);

			if (fpResponse == FP_STATUS_PLACE_FINGER)
			{
				DBG_Log("Place Your Finger");
				if (fpPlaceFingerCallback != NULL)
				{
					unsigned short statusCode = TAG_FP_RSP_VERIFY;
					FP_Enroll_Rsp_t enrollResp;
					enrollResp.cmd = FP_STATUS_PLACE_FINGER;
					enrollResp.total = 0;
					enrollResp.count = 0;

					ASMResponse_t fpASMResponse;
					fpASMResponse.responseData = ((void*)&enrollResp);
					fpASMResponse.statusCode = statusCode;

					fpPlaceFingerCallback->FPCallback(&fpASMResponse);
				}
			}
		}
		else if (response->t == TAG_UAF_RSP_SIGN)
		{
			int authenticateResponseOffset = 0;
			int authenticateResponseLength = response->l;
			dump(response->v, response->l, "V:");
			authenticateResponseOffset += 4;
			response = (TLV_t*)(buffer + authenticateResponseOffset);

			int userNameAndKeyHandleCount = 1;
			authenticateOut->userNameAndKeyHadleCount = -1;
			while ( authenticateResponseOffset < (authenticateResponseLength + 4) )
			{
				switch (response->t)
				{
					case TAG_UAF_STATUS_CODE:
						{
							statusCode = *((unsigned short*)response->v);
							switch (statusCode)
							{
								case UAF_STATUS_OK:
									{
										DBG_Log(" - UAF Status: OK");
										statusCode = UAF_ASM_STATUS_OK;
									}
									break;

								case UAF_STATUS_USER_NOT_ENROLLED:
								case UAF_STATUS_CANNOT_RENDER_TRANSACTION_CONTENT:
								case UAF_STATUS_CMD_NOT_SUPPORTED:
								case UAF_STATUS_ATTESTATION_NOT_SUPPORTED:
									{
										DBG_Log(" - UAF Status: Error(0x%02X)", statusCode);
										statusCode = UAF_ASM_STATUS_ERROR;
									}
									break;

								case UAF_STATUS_USER_CANCELLED:
									{
										DBG_Log(" - UAF Status: User Cancelled(0x%02X)", statusCode);
										statusCode = UAF_ASM_STATUS_USER_CANCELLED;
									}
									break;
							}

							dump(response->v, response->l, "Status Code:");
							authenticateResponseOffset += (4 + response->l);
							response = (TLV_t*)(buffer + authenticateResponseOffset);
						}
						break;

					/* choice 1 */
					case TAG_UAF_USERNAME_AND_KEYHANDLE:
						{
							int userNameAndKeyHandleOffset = 0;
							int userNameAndKeyHandleInfoLength = response->l;

							DBG_Log("User name and key Handle#%d", userNameAndKeyHandleCount);

							dump(response->v, response->l, "User name and key Handle:");
							userNameAndKeyHandleOffset += 4;
							response = (TLV_t*)(buffer + (authenticateResponseOffset + userNameAndKeyHandleOffset));

							while ( userNameAndKeyHandleOffset < (userNameAndKeyHandleInfoLength + 4) )
							{
								switch (response->t)
								{
									case TAG_UAF_USERNAME:
										{
											UserNameAndKeyHandle_t userNameAndKeyHandle;
											authenticateOut->userNameAndKeyHadle.push_back(userNameAndKeyHandle);
											authenticateOut->userNameAndKeyHadle[userNameAndKeyHandleCount - 1].userName = new unsigned char[response->l + 1]{ 0, };
											if (authenticateOut->userNameAndKeyHadle[userNameAndKeyHandleCount - 1].userName == NULL)
											{
												DBG_Log("userName memory address is NULL");
												return -1;
											}
											memcpy(authenticateOut->userNameAndKeyHadle[userNameAndKeyHandleCount - 1].userName, response->v, response->l);

											dump(response->v, response->l, "User name");
											userNameAndKeyHandleOffset += (4 + response->l);
											response = (TLV_t*)(buffer + authenticateResponseOffset + userNameAndKeyHandleOffset);

											authenticateOut->userNameAndKeyHadleCount = userNameAndKeyHandleCount;
										}
										break;

									case TAG_UAF_KEYHANDLE:
										{
											int keyHandleSize = ((4 * (response->l / 3)) + ((response->l % 3) ? 4 : 0));
											authenticateOut->userNameAndKeyHadle[userNameAndKeyHandleCount - 1].keyHandle = new unsigned char[keyHandleSize + 1]{ 0, };
											if (authenticateOut->userNameAndKeyHadle[userNameAndKeyHandleCount - 1].keyHandle == NULL)
											{
												DBG_Log("keyHandle memory address is NULL");
												return -1;
											}
											base64_encode((char*)authenticateOut->userNameAndKeyHadle[userNameAndKeyHandleCount - 1].keyHandle, (char*)response->v, response->l);
											dump(response->v, response->l, "keyHandle");
											DBG_Log("%s", (char*)authenticateOut->userNameAndKeyHadle[userNameAndKeyHandleCount - 1].keyHandle);

											userNameAndKeyHandleOffset += (4 + response->l);
											response = (TLV_t*)(buffer + authenticateResponseOffset + userNameAndKeyHandleOffset);

											authenticateOut->userNameAndKeyHadleCount = (userNameAndKeyHandleCount - 1);
											userNameAndKeyHandleCount++;
										}
										break;

									default:
										{
											DBG_Log("invalid TAG 0x%04X", response->t);
											userNameAndKeyHandleOffset += 1;
											response = (TLV_t*)(buffer + authenticateResponseOffset + userNameAndKeyHandleOffset);
										}
										break;
								}
							}
							authenticateResponseOffset += userNameAndKeyHandleOffset;
						}
						break;

					/* choice 2 */
					case TAG_UAF_AUTHENTICATOR_ASSERTION:
						{
							int assertionSize = ((4 * (response->l / 3)) + ((response->l % 3) ? 4 : 0));
							authenticateOut->assertion = new unsigned char[assertionSize + 1]{ 0, };
							base64_encode((char*)authenticateOut->assertion, (char*)response->v, response->l);
							dump(response->v, response->l, "assertion");
							DBG_Log("%s", (char*)authenticateOut->assertion);

							authenticateResponseOffset += (4 + response->l);
							response = (TLV_t*)(buffer + authenticateResponseOffset);
						}
						break;

					default:
						{
							DBG_Log("invalid TAG 0x%04X", response->t);
							authenticateResponseOffset += 1;
							response = (TLV_t*)(buffer + authenticateResponseOffset);
						}
						break;
				}
			}

			loop = false;

		}
		else
		{
			DBG_Log("invalid tag 0x%04X", response->t);
			dump(response->v, response->l, "invalid tag");

			loop = false;
		}
	}
	if ( buffer != NULL )
	{
		delete[] buffer;
		buffer = NULL;
	}

	if (statusCode != UAF_ASM_STATUS_OK)
	{
		DBG_Log("error: statusCode is not a UAF_ASM_STATUS_OK");
		return statusCode;
	}

	return statusCode;
}

int AuthenticatorProfile::Deregister(const DeregisterIn_t deregisterIn, DeregisterOut_t* deregisterOut)
{
	int ret = 0;

	unsigned char buffer[8192] = { 0, };
	unsigned int  deregisterRequestOffset = 0;
	TLV_t* request = (TLV_t*)buffer;

	request->t = TAG_UAF_REQ_DEREGISTER;
	request->l = 0;
	deregisterRequestOffset += (4 + request->l);
	request = (TLV_t*)(buffer + deregisterRequestOffset);

	request->t = TAG_UAF_AUTHENTICATOR_INDEX;
	request->l = 1;
	request->v[0] = (unsigned char)(authenticatorIndex % 0xFF);
	deregisterRequestOffset += (4 + request->l);
	request = (TLV_t*)(buffer + deregisterRequestOffset);

	request->t = TAG_UAF_APPID;
	unsigned short appIDSize = (unsigned short)strlen((char*)deregisterIn.appID);
	if (appIDSize > APPID_MAX)
	{
		appIDSize = APPID_MAX;
	}
	request->l = appIDSize;
	memcpy(request->v, deregisterIn.appID, request->l);
	deregisterRequestOffset += (4 + request->l);
	request = (TLV_t*)(buffer + deregisterRequestOffset);

    int keyIDLen = (int)strlen((const char*)deregisterIn.keyID);
    if ( keyIDLen <= 0 )
	{
		DBG_Log("key id length error");
		return -1;
	}
	request->t = TAG_KEYID;
    int decodeKeyIDSize = ((4 * keyIDLen / 3) + (keyIDLen % 3) ? 4 : 0);
	base64_decode((char*)request->v, (char*)deregisterIn.keyID, &decodeKeyIDSize);
	request->l = (unsigned short)decodeKeyIDSize;

	deregisterRequestOffset += (4 + request->l);
	request = (TLV_t*)(buffer + deregisterRequestOffset);

	request->t = TAG_UAF_KEYHANDLE_ACCESS_TOKEN;
	request->l = 32;
	unsigned short khaccessTokenSize = KHAT_ACCESSTOKEN_LEN + appIDSize;
	unsigned char* khaccessTokenData = new unsigned char[khaccessTokenSize] {0};
	if ( khaccessTokenData == NULL )
	{
		return -1;
	}
	memcpy(khaccessTokenData, (unsigned char*)KHAT_ACCESSTOKEN, KHAT_ACCESSTOKEN_LEN);
	memcpy(khaccessTokenData + KHAT_ACCESSTOKEN_LEN, deregisterIn.appID, appIDSize);
	SHA256_Encrpyt(khaccessTokenData, khaccessTokenSize, request->v);
	delete[] khaccessTokenData;
	khaccessTokenData = NULL;
	deregisterRequestOffset += (4 + request->l);
	request = (TLV_t*)(buffer + deregisterRequestOffset);

	request = (TLV_t*)buffer;
	request->l = deregisterRequestOffset - 4;

	memset(deregisterOut, 0x00, sizeof(DeregisterOut_t));

	ret = HIDWrite(buffer, deregisterRequestOffset, HID_CMD_UAF);
	if (ret < 0)
	{
		DBG_Log("HIDWrite Fail");
		return -1;
	}

	ret = HIDRead(buffer, sizeof(buffer), HID_CMD_UAF);

	/* Start Parsing */
	TLV_t* response = (TLV_t*)buffer;
	if (response->t != TAG_UAF_RSP_DEREGISTER)
	{
		DBG_Log("Invalid tag");
		return -1;
	}

	unsigned short statusCode = (unsigned short)-1;
	int deregisterResponseOffset = 0;
	int deregisterResponseLength = response->l;
	DBG_Log("T: 0x%04X", response->t);
	DBG_Log("L: 0x%04X", response->l);
	dump(response->v, response->l, "V:");
	deregisterResponseOffset += 4;
	response = (TLV_t*)(buffer + deregisterResponseOffset);

	while ( deregisterResponseOffset < (deregisterResponseLength + 4) )
	{
		switch (response->t)
		{
			case TAG_UAF_STATUS_CODE:
				{
					statusCode = *((unsigned short*)response->v);
					switch (statusCode)
					{
						case UAF_STATUS_OK:
							{
								DBG_Log(" - UAF Status: OK");
								statusCode = UAF_ASM_STATUS_OK;
							}
							break;

						case UAF_STATUS_USER_NOT_ENROLLED:
						case UAF_STATUS_CANNOT_RENDER_TRANSACTION_CONTENT:
						case UAF_STATUS_CMD_NOT_SUPPORTED:
						case UAF_STATUS_ATTESTATION_NOT_SUPPORTED:
							{
								DBG_Log(" - UAF Status: Error(0x%02X)", statusCode);
								statusCode = UAF_ASM_STATUS_ERROR;
							}
							break;

						case UAF_STATUS_USER_CANCELLED:
							{
								DBG_Log(" - UAF Status: User Cancelled(0x%02X)", statusCode);
								statusCode = UAF_ASM_STATUS_USER_CANCELLED;
							}
							break;
					}

					dump(response->v, response->l, "Status Code:");
					deregisterResponseOffset += (4 + response->l);
					response = (TLV_t*)(buffer + deregisterResponseOffset);
				}
				break;

			default:
				{
					DBG_Log("invalid TAG 0x%04X", response->t);
					deregisterResponseOffset += 1;
					response = (TLV_t*)(buffer + deregisterResponseOffset);
				}
				break;
		}
	}

	if (statusCode != UAF_ASM_STATUS_OK)
	{
		DBG_Log("error: statusCode is not a UAF_ASM_STATUS_OK");
		return statusCode;
	}

	return 0;
}

int AuthenticatorProfile::GetRegistrations(const ASMRequest_t getRegistrationsIn, GetRegistrationsOut_t* getRegistrationsOut)
{
	int ret = 0;

	unsigned char* buffer = new unsigned char[0x2000]{ 0, };
	unsigned int  getRegistrationsRequestOffset = 0;
	TLV_t* request = (TLV_t*)buffer;

	/* backward compatibility */
	unsigned short responseCountMax = 16;

	request->t = TAG_UAF_REQ_GETREGISTRATIONS;
	request->l = 2;
	memcpy(request->v, &responseCountMax, sizeof(responseCountMax));
	getRegistrationsRequestOffset += (4 + request->l);
	request = (TLV_t*)(buffer + getRegistrationsRequestOffset);

	ret = HIDWrite(buffer, getRegistrationsRequestOffset, HID_CMD_UAF);
	if ( buffer != NULL )
	{
		delete[] buffer;
		buffer = NULL;
	}
	if (ret < 0)
	{
		DBG_Log("HIDWrite Fail");
		return -1;
	}

	ret = HIDRead(&buffer, HID_CMD_UAF);
	if (ret < 0)
	{
		DBG_Log("HIDRead Fail");
		return -1;
	}

	/* Start Parsing */
	TLV_t* response = (TLV_t*)buffer;
	if (response->t != TAG_UAF_RSP_GETREGISTRATIONS)
	{
		DBG_Log("Invalid tag");
		return -1;
	}

	int statusCode = -1;
	int getRegistratiosResponseOffset = 0;
	int getRegistratiosResponseLength = response->l;
	DBG_Log("T: 0x%04X", response->t);
	DBG_Log("L: 0x%04X", response->l);
	dump(response->v, response->l, "V:");
	getRegistratiosResponseOffset += 4;
	response = (TLV_t*)(buffer + getRegistratiosResponseOffset);

	int getRegistrationsRecordCount = 1;
	getRegistrationsOut->appRegsCount = -1;
	while ( getRegistratiosResponseOffset < (getRegistratiosResponseLength + 4) )
	{
		switch ( response->t )
		{
			case TAG_UAF_STATUS_CODE:
				{
					statusCode = *((unsigned short*)response->v);
					switch ( statusCode )
					{
						case UAF_STATUS_OK:
							{
								DBG_Log(" - UAF Status: OK");
								statusCode = UAF_ASM_STATUS_OK;
							}
							break;

						case UAF_STATUS_USER_NOT_ENROLLED:
						case UAF_STATUS_CANNOT_RENDER_TRANSACTION_CONTENT:
						case UAF_STATUS_CMD_NOT_SUPPORTED:
						case UAF_STATUS_ATTESTATION_NOT_SUPPORTED:
							{
								DBG_Log(" - UAF Status: Error(0x%02X)", statusCode);
								statusCode = UAF_ASM_STATUS_ERROR;
							}
							break;

						case UAF_STATUS_USER_CANCELLED:
							{
								DBG_Log(" - UAF Status: User Cancelled(0x%02X)", statusCode);
								statusCode = UAF_ASM_STATUS_USER_CANCELLED;
							}
							break;
					}

					dump(response->v, response->l, "Status Code:");
					getRegistratiosResponseOffset += (4 + response->l);
					response = (TLV_t*)(buffer + getRegistratiosResponseOffset);
				}
				break;

			case TAG_UAF_GETREGLIST_RECORD:
				{
					int getRegistrationsRecordOffset = 0;
					int getRegistrationsRecordLength = response->l;

					DBG_Log("GetRegistrations Record#%d", getRegistrationsRecordCount);

					dump(response->v, response->l, "GetRegistrations Record:");
					getRegistrationsRecordOffset += 4;
					response = (TLV_t*)(buffer + (getRegistratiosResponseOffset + getRegistrationsRecordOffset));

					while ( getRegistrationsRecordOffset < (getRegistrationsRecordLength + 4) )
					{
						switch (response->t)
						{
							case TAG_UAF_USERNAME:
								{
									if (response->l > USERNAME_MAX)
									{
										DBG_Log("User name is too long");
										return -1;
									}

									AppRegistration_t appRegistration;
									getRegistrationsOut->appRegs.push_back(appRegistration);
									memset(getRegistrationsOut->appRegs[getRegistrationsRecordCount - 1].userName, 0x00, sizeof(getRegistrationsOut->appRegs[getRegistrationsRecordCount - 1].userName));
									memcpy(getRegistrationsOut->appRegs[getRegistrationsRecordCount - 1].userName, response->v, response->l);

									dump(response->v, response->l, "User name");
									getRegistrationsRecordOffset += (4 + response->l);
									response = (TLV_t*)(buffer + getRegistratiosResponseOffset + getRegistrationsRecordOffset);

									getRegistrationsOut->appRegsCount = getRegistrationsRecordCount;
								}
								break;

							case TAG_KEYID:
								{
									if (response->l > REGISTRATION_KEYID_SIZE_MAX)
									{
										DBG_Log("Key ID is too long");
										return -1;
									}

									memset(getRegistrationsOut->appRegs[getRegistrationsRecordCount - 1].keyID[0], 0x00, sizeof(getRegistrationsOut->appRegs[getRegistrationsRecordCount - 1].keyID[0]));

									base64_encode((char*)getRegistrationsOut->appRegs[getRegistrationsRecordCount - 1].keyID[0], (char*)response->v, response->l);
									dump(response->v, response->l, "KeyID");
									DBG_Log("%s", (const char*)getRegistrationsOut->appRegs[getRegistrationsRecordCount - 1].keyID);

									getRegistrationsRecordOffset += (4 + response->l);
									response = (TLV_t*)(buffer + getRegistratiosResponseOffset + getRegistrationsRecordOffset);

									getRegistrationsOut->appRegsCount = (getRegistrationsRecordCount - 1);
									getRegistrationsRecordCount++;
								}
								break;

							default:
								{
									DBG_Log("invalid TAG 0x%04X", response->t);
									getRegistrationsRecordOffset += 1;
									response = (TLV_t*)(buffer + getRegistratiosResponseOffset + getRegistrationsRecordOffset);
								}
								break;
						}
					}
					getRegistratiosResponseOffset += getRegistrationsRecordOffset;
				}
				break;

			default:
				{
					DBG_Log("invalid TAG 0x%04X", response->t);
					getRegistratiosResponseOffset += 1;
					response = (TLV_t*)(buffer + getRegistratiosResponseOffset);
				}
				break;
		}
	}
	if ( buffer != NULL )
	{
		delete[] buffer;
		buffer = NULL;
	}

	if (statusCode != UAF_ASM_STATUS_OK)
	{
		DBG_Log("error: statusCode is not a UAF_ASM_STATUS_OK");
		return statusCode;
	}

	return statusCode;
}

int AuthenticatorProfile::Enroll(const ASMRequest_t in, ASMResponse_t* out)
{
	int ret = 0;

	unsigned char buffer[8192] = { 0, };
	unsigned int  requestOffset = 0;
	TLV_t* request = (TLV_t*)buffer;

	request->t = TAG_FP_REQ_TAG_ENROLL;
	if (in.args == NULL)
	{
		DBG_Log("tag is NULL");
		return -1;
	}
	request->l = 0;

	FPIndexAndName_t* fpIndexAndName = (FPIndexAndName_t*)in.args;
	if (fpIndexAndName->index >= FINGER_INDEX_MAX)
	{
		DBG_Log("invalid finger print index");
		return -1;
	}
	memcpy(request->v + requestOffset, &fpIndexAndName->index, 2);
	requestOffset += sizeof(fpIndexAndName->index);

	unsigned short fingerPrintNameLength = (unsigned short)strlen(fpIndexAndName->name);
	memcpy(request->v + requestOffset, &fingerPrintNameLength, 2);
	requestOffset += 2;

	memcpy(request->v + requestOffset, fpIndexAndName->name, fingerPrintNameLength);
	requestOffset += fingerPrintNameLength;

	request->l = requestOffset;
	requestOffset += 4;

	memset(out, 0x00, sizeof(ASMResponse_t));

	ret = HIDWrite(buffer, requestOffset, HID_CMD_FINGERPRINT);
	if (ret < 0)
	{
		DBG_Log("HIDWrite Fail");
		return -1;
	}

	int statusCode = -1;
	bool loop = true;
	while ( loop )
	{
		memset(buffer, 0x00, sizeof(buffer));
		ret = HIDRead(buffer, sizeof(buffer), HID_CMD_FINGERPRINT);
		if (ret < 0)
		{
			DBG_Log("HIDRead Fail");
			return -1;
		}

		/* Start Parsing */
		FP_Rsp_t* response = (FP_Rsp_t*)buffer;
		DBG_Log("T: 0x%04X", response->tag);
		DBG_Log("L: 0x%04X", response->len);

		if (response->tag != TAG_FP_RSP_ENROLL)
		{
			DBG_Log("invalid tag 0x%04X", response->tag);
			loop = false;
			break;
		}
		else
		{
			unsigned short  tagName = response->tag;

			FP_Enroll_Rsp_t enrollResp;
			enrollResp.cmd = response->value;
			enrollResp.total = 0;
			enrollResp.count = 0;

			unsigned short responseType = enrollResp.cmd;
			switch (responseType)
			{
				case FP_STATUS_PLACE_FINGER:
				case FP_CMD_FINGER_DUPLICATE:
				case FP_CMD_FINGER_OK:
				case FP_CMD_FINGER_FAIL:
					{
						ASMResponse_t fpASMResponse;
						if (response->len == 4)
						{
							enrollResp.total = response->data[0];
							enrollResp.count = response->data[1];
						}
						fpASMResponse.responseData = ((void*)&enrollResp);
						fpASMResponse.statusCode = tagName;
						if (fpPlaceFingerCallback != NULL)
						{
							fpPlaceFingerCallback->FPCallback(&fpASMResponse);
						}
						else
						{
							DBG_Log("fpPlaceFingerCallback is NULL");
							statusCode = UAF_ASM_STATUS_ERROR;
						}

						statusCode = UAF_ASM_STATUS_OK;
					}
					break;

				case FP_STATUS_COMPLETE:
				case FP_STATUS_FAIL:
				case FP_STATUS_ALREADY:
					{
						unsigned short* responseData = new unsigned short;
						*responseData = responseType;
						out->responseData = ((void*)responseData);
						out->statusCode = tagName;

						statusCode = UAF_ASM_STATUS_OK;

						loop = false;
					}
					break;

				default:
					{
						out->responseData = NULL;
						out->statusCode = tagName;
						DBG_Log("invalid tag: 0x%04X", responseType);

						statusCode = -1;

						loop = false;
					}
					break;
			}
		}
	}

	if (statusCode != UAF_ASM_STATUS_OK)
	{
		DBG_Log("error: statusCode is not a UAF_ASM_STATUS_OK");
		return statusCode;
	}

	return statusCode;
}

int AuthenticatorProfile::Verify(const ASMRequest_t in, ASMResponse_t* out)
{
	int ret = 0;

	unsigned char buffer[8192] = { 0, };
	TLV_t* request = (TLV_t*)buffer;

	request->t = TAG_FP_REQ_TAG_VERIFY;
	request->l = 0;

	memset(out, 0x00, sizeof(ASMResponse_t));

	ret = HIDWrite(buffer, 4, HID_CMD_FINGERPRINT);
	if (ret < 0)
	{
		DBG_Log("HIDWrite Fail");
		return -1;
	}

	int statusCode = -1;
	bool loop = true;
	while ( loop )
	{
		memset(buffer, 0x00, sizeof(buffer));
		ret = HIDRead(buffer, sizeof(buffer), HID_CMD_FINGERPRINT);
		if (ret < 0)
		{
			DBG_Log("HIDRead Fail");
			return -1;
		}


		/* Start Parsing */
		FP_Rsp_t* response = (FP_Rsp_t*)buffer;
		DBG_Log("T: 0x%04X", response->tag);
		DBG_Log("L: 0x%04X", response->len);

		if (response->tag != TAG_FP_RSP_VERIFY)
		{
			DBG_Log("invalid tag 0x%04X", response->tag);
			loop = false;
			break;
		}
		else
		{
			unsigned short  tagName = response->tag;

			FP_Enroll_Rsp_t enrollResp;
			enrollResp.cmd = response->value;
			enrollResp.total = 0;
			enrollResp.count = 0;

			unsigned short responseType = enrollResp.cmd;
			switch (responseType)
			{
				case FP_STATUS_PLACE_FINGER:
					{
						ASMResponse_t fpASMResponse;
						fpASMResponse.responseData = ((void*)&enrollResp);
						fpASMResponse.statusCode = tagName;
						if (fpPlaceFingerCallback != NULL)
						{
							fpPlaceFingerCallback->FPCallback(&fpASMResponse);
						}
						else
						{
							DBG_Log("fpPlaceFingerCallback is NULL");
							statusCode = UAF_ASM_STATUS_ERROR;
						}

						statusCode = UAF_ASM_STATUS_OK;
					}
					break;

				case FP_STATUS_COMPLETE:
				case FP_STATUS_FAIL:
					{
						unsigned short* responseData = new unsigned short;
						*responseData = responseType;
						out->responseData = ((void*)responseData);
						out->statusCode = tagName;

						statusCode = UAF_ASM_STATUS_OK;

						loop = false;
					}
					break;

				default:
					{
						out->responseData = NULL;
						out->statusCode = tagName;
						DBG_Log("invalid tag: 0x%04X", responseType);

						statusCode = -1;

						loop = false;
					}
					break;
			}
		}
	}

	if (statusCode != UAF_ASM_STATUS_OK)
	{
		DBG_Log("error: statusCode is not a UAF_ASM_STATUS_OK");
		return statusCode;
	}

	return statusCode;
}

int AuthenticatorProfile::EnrollCheck(const ASMRequest_t in, ASMResponse_t* out)
{
	int ret = 0;

	unsigned char buffer[8192] = { 0, };
	unsigned int  requestOffset = 0;
	TLV_t* request = (TLV_t*)buffer;

	request->t = TAG_FP_REQ_TAG_IS_ENROLL;
	if (in.args == NULL)
	{
		DBG_Log("tag is NULL");
		return -1;
	}
	unsigned short fingerPrintIndex = *((unsigned short*)in.args);
	if (fingerPrintIndex >= FINGER_INDEX_MAX)
	{
		DBG_Log("invalid finger print index");
		return -1;
	}
	request->l = sizeof(fingerPrintIndex);
	memcpy(request->v, &fingerPrintIndex, request->l);

	requestOffset += (4 + request->l);
	request = (TLV_t*)(buffer + requestOffset);

	request = (TLV_t*)buffer;
	request->l = requestOffset - 4;

	memset(out, 0x00, sizeof(ASMResponse_t));

	ret = HIDWrite(buffer, requestOffset, HID_CMD_FINGERPRINT);
	if (ret < 0)
	{
		DBG_Log("HIDWrite Fail");
		return -1;
	}

	int statusCode = -1;
	bool loop = true;
	while ( loop )
	{
		memset(buffer, 0x00, sizeof(buffer));
		ret = HIDRead(buffer, sizeof(buffer), HID_CMD_FINGERPRINT);
		if (ret < 0)
		{
			DBG_Log("HIDRead Fail");
			return -1;
		}


		/* Start Parsing */
		TLV_t* response = (TLV_t*)buffer;
		DBG_Log("T: 0x%04X", response->t);
		DBG_Log("L: 0x%04X", response->l);

		if (response->t != TAG_FP_RSP_IS_ENROLL)
		{
			DBG_Log("invalid tag 0x%04X", response->t);
			dump(response->v, response->l, "invalid tag");

			loop = false;
			break;
		}
		else
		{
			if (response->l != 2)
			{
				statusCode = -1;
				DBG_Log("invalid fpResponseLength");
				return -1;
			}

			unsigned short tagName = response->t;
			unsigned short responseType = *((unsigned short*)response->v);

			switch (responseType)
			{
				case FP_STATUS_ENROLLED:
				case FP_STATUS_NOT_ENROLLED:
					{
						unsigned short* responseData = new unsigned short;
						*responseData = responseType;
						out->responseData = ((void*)responseData);
						out->statusCode = tagName;

						statusCode = UAF_ASM_STATUS_OK;

						loop = false;
					}
					break;

				default:
					{
						out->responseData = NULL;
						out->statusCode = tagName;
						DBG_Log("invalid tag: 0x%04X", responseType);

						statusCode = -1;

						loop = false;
					}
					break;
			}
		}
	}

	if (statusCode != UAF_ASM_STATUS_OK)
	{
		DBG_Log("error: statusCode is not a UAF_ASM_STATUS_OK");
		return statusCode;
	}

	return statusCode;
}

int AuthenticatorProfile::RemoveEnroll(const ASMRequest_t in, ASMResponse_t* out)
{
	int ret = 0;

	unsigned char buffer[8192] = { 0, };
	unsigned int  requestOffset = 0;
	TLV_t* request = (TLV_t*)buffer;

	request->t = TAG_FP_REQ_TAG_RM_ENROLL;
	if (in.args == NULL)
	{
		DBG_Log("tag is NULL");
		return -1;
	}
	unsigned short fingerPrintIndex = *((unsigned short*)in.args);
	if (fingerPrintIndex >= FINGER_INDEX_MAX)
	{
		DBG_Log("invalid finger print index");
		return -1;
	}
	request->l = sizeof(fingerPrintIndex);
	memcpy(request->v, &fingerPrintIndex, request->l);

	requestOffset += (4 + request->l);
	request = (TLV_t*)(buffer + requestOffset);

	request = (TLV_t*)buffer;
	request->l = requestOffset - 4;

	memset(out, 0x00, sizeof(ASMResponse_t));

	ret = HIDWrite(buffer, requestOffset, HID_CMD_FINGERPRINT);
	if (ret < 0)
	{
		DBG_Log("HIDWrite Fail");
		return -1;
	}

	int statusCode = -1;
	bool loop = true;
	while ( loop )
	{
		memset(buffer, 0x00, sizeof(buffer));
		ret = HIDRead(buffer, sizeof(buffer), HID_CMD_FINGERPRINT);
		if (ret < 0)
		{
			DBG_Log("HIDRead Fail");
			return -1;
		}


		/* Start Parsing */
		TLV_t* response = (TLV_t*)buffer;
		DBG_Log("T: 0x%04X", response->t);
		DBG_Log("L: 0x%04X", response->l);

		if (response->t != TAG_FP_RSP_RM_ENROLL)
		{
			DBG_Log("invalid tag 0x%04X", response->t);
			dump(response->v, response->l, "invalid tag");

			loop = false;
			break;
		}
		else
		{
			if (response->l != 2)
			{
				statusCode = -1;
				DBG_Log("invalid fpResponseLength");
				return -1;
			}

			unsigned short tagName = response->t;
			unsigned short responseType = *((unsigned short*)response->v);

			switch (responseType)
			{
				case FP_STATUS_COMPLETE:
				case FP_STATUS_FAIL:
					{
						unsigned short* responseData = new unsigned short;
						*responseData = responseType;
						out->responseData = ((void*)responseData);
						out->statusCode = tagName;

						statusCode = UAF_ASM_STATUS_OK;

						loop = false;
					}
					break;

				default:
					{
						out->responseData = NULL;
						out->statusCode = tagName;
						DBG_Log("invalid tag: 0x%04X", responseType);

						statusCode = -1;

						loop = false;
					}
					break;
			}
		}
	}

	if (statusCode != UAF_ASM_STATUS_OK)
	{
		DBG_Log("error: statusCode is not a UAF_ASM_STATUS_OK");
		return statusCode;
	}

	return statusCode;
}

int AuthenticatorProfile::GetFPList(const ASMRequest_t in, FPGetListOut_t* out)
{
	int ret = 0;

	unsigned char buffer[8192] = { 0, };
	TLV_t* request = (TLV_t*)buffer;

	request->t = TAG_FP_REQ_TAG_GET_ENROLL_LIST;
	request->l = 0;

	memset(out, 0x00, sizeof(FPGetListOut_t));

	ret = HIDWrite(buffer, 4, HID_CMD_FINGERPRINT);
	if (ret < 0)
	{
		DBG_Log("HIDWrite Fail");
		return -1;
	}

	int statusCode = -1;
	bool loop = true;
	while ( loop )
	{
		memset(buffer, 0x00, sizeof(buffer));
		ret = HIDRead(buffer, sizeof(buffer), HID_CMD_FINGERPRINT);
		if (ret < 0)
		{
			DBG_Log("HIDRead Fail");
			return -1;
		}

		/* Start Parsing */
		FP_Rsp_t* response = (FP_Rsp_t*)buffer;
		DBG_Log("T: 0x%04X", response->tag);
		DBG_Log("L: 0x%04X", response->len);

		if (response->tag != TAG_FP_RSP_GET_ENROLL_LIST)
		{
			DBG_Log("invalid tag 0x%04X", response->tag);
			loop = false;
			break;
		}
		else
		{
			switch (response->value)
			{
				case FP_STATUS_COMPLETE:
					{
						FP_Name_t* fpName = NULL;
						out->statusCode = response->value;
						out->responseType = -1;
						out->fpCount = 0;
						int offset = 0;
						while ( offset < (response->len - 2))
						{
							fpName = (FP_Name_t*)&response->data[offset];
							if (fpName->nameLen > FP_NAME_MAX)
							{
								DBG_Log("FP_NAME_MAX!!");
								loop = false;
								break;
							}
							else
							{
								out->fpIndexAndNameHandle[out->fpCount].index = fpName->index;
								memcpy(out->fpIndexAndNameHandle[out->fpCount].name, fpName->name, fpName->nameLen);
								out->fpCount++;
								offset += (4 + fpName->nameLen);
							}
						}

						out->responseType = UAF_ASM_STATUS_OK;
						statusCode = UAF_ASM_STATUS_OK;

						loop = false;
					}
					break;

				default:
					{
						DBG_Log("invalid value 0x%04X", response->value);
						loop = false;
						break;
					}
					break;
			}
		}
	}

	if (statusCode != UAF_ASM_STATUS_OK)
	{
		DBG_Log("error: statusCode is not a UAF_ASM_STATUS_OK");
		return statusCode;
	}

	return statusCode;
}

int AuthenticatorProfile::GetFPImage(const ASMRequest_t in, FPGetImageOut_t* out)
{
	if (out == NULL)
	{
		return -1;
	}

	int ret = 0;

	unsigned char buffer[8192] = { 0, };
	TLV_t* request = (TLV_t*)buffer;
	unsigned short count = 0;

	FP_Rsp_t* response = (FP_Rsp_t*)buffer;

	time_t timer;
	struct tm *t;
	timer = time(NULL);
	t = localtime(&timer);
	char fpName[64] = { 0, };
	sprintf(fpName, "./FPImage%04d%02d%02d%02d%02d%02d", t->tm_year + 1900, t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);

	sprintf(out->raw, "%s.raw", fpName);
	FILE *fp = fopen(out->raw, "wb");

	out->responseType = UAF_ASM_STATUS_ERROR;

	memset(buffer, 0x00, sizeof(buffer));
	request->t = TAG_FP_REQ_TAG_GET_IMAGE;
	request->l = 2;
	memcpy(request->v, &count, request->l);

	ret = HIDWrite(buffer, 6, HID_CMD_FINGERPRINT);
	if (ret < 0)
	{
		DBG_Log("HIDWrite Fail");
		return -1;
	}

	bool loop = true;
	while ( loop )
	{
		memset(buffer, 0x00, sizeof(buffer));
		ret = HIDRead(buffer, sizeof(buffer), HID_CMD_FINGERPRINT);
		if (ret < 0)
		{
			if (fp != NULL)
			{
				fclose(fp);
				fp = NULL;
			}
			DBG_Log("HIDRead Fail");
			return -1;
		}

		/* Start Parsing */
		DBG_Log("T: 0x%04X", response->tag);
		DBG_Log("L: 0x%04X", response->len);

		out->statusCode = response->tag;
		if (response->tag != TAG_FP_RSP_GET_IMAGE)
		{
			DBG_Log("invalid tag 0x%04X", response->tag);
			loop = false;
			break;
		}
		else
		{
			switch (response->value)
			{
				case FP_STATUS_FAIL:
					{
						out->responseType = UAF_ASM_STATUS_ERROR;
						DBG_Log("responseType is FP_STATUS_FAIL");
						loop = false;
					}
					break;

				case FP_STATUS_COMPLETE:
					{
						FP_Image_t* fpImage = (FP_Image_t*)response->data;
						if (count == fpImage->index)
						{
							fwrite(fpImage->image, 1, fpImage->imageSize, fp);

							out->responseType = UAF_ASM_STATUS_OK;
						}

						loop = false;
					}
					break;

				case FP_STATUS_CONTINUOUS:
					{
						FP_Image_t* fpImage = (FP_Image_t*)response->data;
						if (count == fpImage->index)
						{
							fwrite(fpImage->image, 1, fpImage->imageSize, fp);
							count++;

							memset(buffer, 0x00, sizeof(buffer));
							request->t = TAG_FP_REQ_TAG_GET_IMAGE;
							request->l = 2;
							memcpy(request->v, &count, request->l);

							ret = HIDWrite(buffer, 6, HID_CMD_FINGERPRINT);
							if (ret < 0)
							{
								if (fp != NULL)
								{
									fclose(fp);
									fp = NULL;
								}
								DBG_Log("HIDWrite Fail");
								return -1;
							}

						}
						else
						{
							DBG_Log("index / count error %d", fpImage->index);
							loop = false;
						}
					}
					break;

				case FP_STATUS_PLACE_FINGER:
					{
						if (count == 0)
						{
							FP_Enroll_Rsp_t enrollResp;
							memset(&enrollResp, 0, sizeof(FP_Enroll_Rsp_t));
							enrollResp.cmd = FP_STATUS_PLACE_FINGER;

							ASMResponse_t fpASMResponse;
							memset(&fpASMResponse, 0, sizeof(ASMResponse_t));

							fpASMResponse.responseData = ((void*)&enrollResp);
							fpASMResponse.statusCode = response->tag;
							if (fpPlaceFingerCallback != NULL)
							{
								fpPlaceFingerCallback->FPCallback(&fpASMResponse);
							}
						}
					}
					break;

				default:
					{
						out->responseType = UAF_ASM_STATUS_ERROR;
						DBG_Log("invalid value 0x%04X", response->value);
						loop = false;
					}
					break;
			}
		}
	}

	if (fp != NULL)
	{
		fclose(fp);
		fp = NULL;
	}

	if (out->responseType == UAF_ASM_STATUS_OK)
	{
		FILE *raw = fopen(out->raw, "rb");
		fseek(raw, 0, SEEK_END);
		int fpImageLength = ftell(raw);
		fseek(raw, 0, SEEK_SET);
		unsigned char* fpImage = new unsigned char[fpImageLength] {0, };
		fread(fpImage, 1, fpImageLength, raw);
		fclose(raw);
		raw = NULL;

		BITMAPFILEHEADER fh;
		memset(&fh, 0, sizeof(BITMAPFILEHEADER));
		fh.bfOffBits = sizeof(RGBQUAD) * 256 + sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER); // RGBQUAD + InfoHeader + FileHeader only 8bit mode if 24bit == 54; 40+ 14;
		fh.bfSize = fpImageLength + sizeof(RGBQUAD) * 256 + sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
		fh.bfType = 0x4D42;

		long widthHeight = (long)sqrt(fpImageLength);


		BITMAPINFOHEADER ih;
		memset(&ih, 0, sizeof(BITMAPINFOHEADER));
		ih.biBitCount = 8;
		ih.biHeight = widthHeight;
		ih.biPlanes = 1;
		ih.biSize = sizeof(BITMAPINFOHEADER);
		ih.biSizeImage = fpImageLength;
		ih.biWidth = widthHeight;
		ih.biXPelsPerMeter = 0;
		ih.biYPelsPerMeter = 0;

		RGBQUAD rgb[256];
		memset(&rgb, 0, sizeof(RGBQUAD) * 256);
		for (int i = 0; i < 256; i++)
		{
			rgb[i].rgbBlue = i;
			rgb[i].rgbGreen = i;
			rgb[i].rgbRed = i;
			rgb[i].rgbReserved = 0;
		}

		sprintf(out->bmp, "%s.bmp", fpName);
		FILE* bmp = fopen(out->bmp, "wb");

		fwrite(&fh, sizeof(BITMAPFILEHEADER), 1, bmp);
		fwrite(&ih, sizeof(BITMAPINFOHEADER), 1, bmp);
		fwrite(rgb, sizeof(RGBQUAD), 256, bmp);
		fwrite(fpImage, 1, fpImageLength, bmp);
		delete[] fpImage;
		fclose(bmp);
		bmp = NULL;
	}

	if (out->responseType != UAF_ASM_STATUS_OK)
	{
		DBG_Log("error: statusCode is not a UAF_ASM_STATUS_OK");
	}

	return out->responseType;
}

int VerifyCount = 0;
int AuthenticatorProfile::VerifyFPImage(const FingerInfo_t in, FPTestImageOut_t* out)
{
	VerifyCount = in.enrollCount;
	if (out == NULL)
	{
		return -1;
	}

	int ret = 0;

	unsigned char buffer[8192] = { 0, };
	TLV_t* request = (TLV_t*)buffer;
	unsigned short count = 0;

	FP_Rsp_t* response = (FP_Rsp_t*)buffer;

	time_t timer;
	struct tm *t;
	timer = time(NULL);
	t = localtime(&timer);
	char fpName[64] = { 0, };
	char fdName[64] = { 0, };
	char ftName[64] = { 0, };
		
	sprintf(ftName, "./FingerPrint/Test_%d", in.testUserid);
	if (_access("./FingerPrint", 0) == -1)
	{
		CreateDirectory("./FingerPrint", NULL);
		CreateDirectory(ftName, NULL);
	}

	sprintf(fdName, "./FingerPrint/Test_%d/Verify", in.testUserid);
	CreateDirectory(fdName, NULL);

	sprintf(fpName, "./FingerPrint/Test_%d/Verify/Verify_(%d)_(%d)_(%d)_(%d)_[%d]", in.testUserid, in.testUserid, in.handIndex, in.handCount, in.angle, VerifyCount);

	sprintf(out->raw, "%s.raw", fpName);
	FILE *fp = fopen(out->raw, "wb");
	sprintf(out->count, "%d", VerifyCount);
	sprintf(out->operation, "1");
	out->responseType = UAF_ASM_STATUS_ERROR;

	memset(buffer, 0x00, sizeof(buffer));
	request->t = TAG_FP_REQ_TAG_GET_IMAGE;
	request->l = 2;
	memcpy(request->v, &count, request->l);

	ret = HIDWrite(buffer, 6, HID_CMD_FINGERPRINT);
	if (ret < 0)
	{
		DBG_Log("HIDWrite Fail");
		return -1;
	}

	bool loop = true;
	while (loop)
	{
		memset(buffer, 0x00, sizeof(buffer));
		ret = HIDRead(buffer, sizeof(buffer), HID_CMD_FINGERPRINT);
		if (ret < 0)
		{
			if (fp != NULL)
			{
				fclose(fp);
				fp = NULL;
			}
			DBG_Log("HIDRead Fail");
			return -1;
		}

		/* Start Parsing */
		DBG_Log("T: 0x%04X", response->tag);
		DBG_Log("L: 0x%04X", response->len);

		out->statusCode = response->tag;
		if (response->tag != TAG_FP_RSP_GET_IMAGE)
		{
			DBG_Log("invalid tag 0x%04X", response->tag);
			loop = false;
			break;
		}
		else
		{
			switch (response->value)
			{
			case FP_STATUS_FAIL:
			{
				out->responseType = UAF_ASM_STATUS_ERROR;
				DBG_Log("responseType is FP_STATUS_FAIL");
				loop = false;
			}
			break;

			case FP_STATUS_COMPLETE:
			{
				FP_Image_t* fpImage = (FP_Image_t*)response->data;
				if (count == fpImage->index)
				{
					fwrite(fpImage->image, 1, fpImage->imageSize, fp);
					out->responseType = UAF_ASM_STATUS_OK;
				}
				loop = false;
			}
			break;

			case FP_STATUS_CONTINUOUS:
			{
				FP_Image_t* fpImage = (FP_Image_t*)response->data;
				if (count == fpImage->index)
				{
					fwrite(fpImage->image, 1, fpImage->imageSize, fp);
					count++;

					memset(buffer, 0x00, sizeof(buffer));
					request->t = TAG_FP_REQ_TAG_GET_IMAGE;
					request->l = 2;
					memcpy(request->v, &count, request->l);

					ret = HIDWrite(buffer, 6, HID_CMD_FINGERPRINT);
					if (ret < 0)
					{
						if (fp != NULL)
						{
							fclose(fp);
							fp = NULL;
						}
						DBG_Log("HIDWrite Fail");
						return -1;
					}

				}
				else
				{
					DBG_Log("index / count error %d", fpImage->index);
					loop = false;
				}
			}
			break;

			case FP_STATUS_PLACE_FINGER:
			{
				if (count == 0)
				{
					FP_Enroll_Rsp_t enrollResp;
					memset(&enrollResp, 0, sizeof(FP_Enroll_Rsp_t));
					enrollResp.cmd = FP_STATUS_PLACE_FINGER;

					ASMResponse_t fpASMResponse;
					memset(&fpASMResponse, 0, sizeof(ASMResponse_t));

					fpASMResponse.responseData = ((void*)&enrollResp);
					fpASMResponse.statusCode = response->tag;
					if (fpPlaceFingerCallback != NULL)
					{
						fpPlaceFingerCallback->FPCallback(&fpASMResponse);
					}
				}
			}
			break;

			default:
			{
				out->responseType = UAF_ASM_STATUS_ERROR;
				DBG_Log("invalid value 0x%04X", response->value);
				loop = false;
			}
			break;
			}
		}
	}

	if (fp != NULL)
	{
		fclose(fp);
		fp = NULL;
	}

	if (out->responseType == UAF_ASM_STATUS_OK)
	{
		FILE *raw = fopen(out->raw, "rb");
		fseek(raw, 0, SEEK_END);
		int fpImageLength = ftell(raw);
		fseek(raw, 0, SEEK_SET);
		unsigned char* fpImage = new unsigned char[fpImageLength] {0, };
		fread(fpImage, 1, fpImageLength, raw);
		fclose(raw);
		raw = NULL;

		BITMAPFILEHEADER fh;
		memset(&fh, 0, sizeof(BITMAPFILEHEADER));
		fh.bfOffBits = sizeof(RGBQUAD) * 256 + sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER); // RGBQUAD + InfoHeader + FileHeader only 8bit mode if 24bit == 54; 40+ 14;
		fh.bfSize = fpImageLength + sizeof(RGBQUAD) * 256 + sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
		fh.bfType = 0x4D42;

		long widthHeight = (long)sqrt(fpImageLength);


		BITMAPINFOHEADER ih;
		memset(&ih, 0, sizeof(BITMAPINFOHEADER));
		ih.biBitCount = 8;
		ih.biHeight = widthHeight;
		ih.biPlanes = 1;
		ih.biSize = sizeof(BITMAPINFOHEADER);
		ih.biSizeImage = fpImageLength;
		ih.biWidth = widthHeight;
		ih.biXPelsPerMeter = 0;
		ih.biYPelsPerMeter = 0;

		RGBQUAD rgb[256];
		memset(&rgb, 0, sizeof(RGBQUAD) * 256);
		for (int i = 0; i < 256; i++)
		{
			rgb[i].rgbBlue = i;
			rgb[i].rgbGreen = i;
			rgb[i].rgbRed = i;
			rgb[i].rgbReserved = 0;
		}

		sprintf(out->bmp, "%s.bmp", fpName);
		FILE* bmp = fopen(out->bmp, "wb");

		fwrite(&fh, sizeof(BITMAPFILEHEADER), 1, bmp);
		fwrite(&ih, sizeof(BITMAPINFOHEADER), 1, bmp);
		fwrite(rgb, sizeof(RGBQUAD), 256, bmp);
		fwrite(fpImage, 1, fpImageLength, bmp);
		delete[] fpImage;
		fclose(bmp);
		bmp = NULL;
	}

	return out->responseType;
}

int AuthenticatorProfile::TestFPImage(const FingerInfo_t in, FPTestImageOut_t* out)
{
	int EnrollCount = in.enrollCount;
	if (out == NULL)
	{
		return -1;
	}

	int ret = 0;
	unsigned char buffer[8192] = { 0, };
	TLV_t* request = (TLV_t*)buffer;
	unsigned short count = 0;

	FP_Rsp_t* response = (FP_Rsp_t*)buffer;

	time_t timer;
	struct tm *t;
	timer = time(NULL);
	t = localtime(&timer);
	char fpName[64] = { 0, };
	char fdName[64] = { 0, };
	char fdName_1[64] = { 0, };
	CreateDirectory("./FingerPrint", NULL);
	sprintf(fdName, "./FingerPrint/Test_%d", in.testUserid);
	CreateDirectory(fdName, NULL);
	sprintf(fdName_1, "./FingerPrint/Test_%d/Enroll", in.testUserid);
	CreateDirectory(fdName_1, NULL);

	sprintf(fpName, "./FingerPrint/Test_%d/Enroll/Enroll_%d_%d_%d_[%d]", in.testUserid, in.testUserid, in.handIndex, in.handCount, EnrollCount);

	sprintf(out->raw, "%s.raw", fpName);
	FILE *fp = fopen(out->raw, "wb");
	sprintf(out->operation, "0");
	sprintf(out->count, "%d", EnrollCount);
		
	out->responseType = UAF_ASM_STATUS_ERROR;

	memset(buffer, 0x00, sizeof(buffer));
	request->t = TAG_FP_REQ_TAG_GET_IMAGE;
	request->l = 2;
	memcpy(request->v, &count, request->l);


	ret = HIDWrite(buffer, 6, HID_CMD_FINGERPRINT);
	if (ret < 0)
	{
		DBG_Log("HIDWrite Fail");
		return -1;
	}
	bool loop = true;
	while (loop)
	{
		memset(buffer, 0x00, sizeof(buffer));
		ret = HIDRead(buffer, sizeof(buffer), HID_CMD_FINGERPRINT);
		if (ret < 0)
		{
			if (fp != NULL)
			{
				fclose(fp);
				fp = NULL;
			}
			DBG_Log("HIDRead Fail");
			return -1;
		}

		/* Start Parsing */
		DBG_Log("T: 0x%04X", response->tag);
		DBG_Log("L: 0x%04X", response->len);


		out->statusCode = response->tag;
		if (response->tag != TAG_FP_RSP_GET_IMAGE)
		{
			DBG_Log("invalid tag 0x%04X", response->tag);
			loop = false;
			break;
		}
		else
		{
			switch (response->value)
			{
			case FP_STATUS_FAIL:
			{
				out->responseType = UAF_ASM_STATUS_ERROR;
				DBG_Log("responseType is FP_STATUS_FAIL");
				loop = false;
			}
			break;

			case FP_STATUS_COMPLETE:
			{
				FP_Image_t* fpImage = (FP_Image_t*)response->data;
				if (count == fpImage->index)
				{
					fwrite(fpImage->image, 1, fpImage->imageSize, fp);
					out->responseType = UAF_ASM_STATUS_OK;
				}
				loop = false;

			}
			break;

			case FP_STATUS_CONTINUOUS:
			{
				FP_Image_t* fpImage = (FP_Image_t*)response->data;
				if (count == fpImage->index)
				{
					fwrite(fpImage->image, 1, fpImage->imageSize, fp);
					count++;

					memset(buffer, 0x00, sizeof(buffer));
					request->t = TAG_FP_REQ_TAG_GET_IMAGE;
					request->l = 2;
					memcpy(request->v, &count, request->l);

					ret = HIDWrite(buffer, 6, HID_CMD_FINGERPRINT);
					if (ret < 0)
					{
						if (fp != NULL)
						{
							fclose(fp);
							fp = NULL;
						}
						DBG_Log("HIDWrite Fail");
						return -1;
					}

				}
				else
				{
					DBG_Log("index / count error %d", fpImage->index);
					loop = false;
				}

			}
			break;

			case FP_STATUS_PLACE_FINGER:
			{
				if (count == 0)
				{
					FP_Enroll_Rsp_t enrollResp;
					memset(&enrollResp, 0, sizeof(FP_Enroll_Rsp_t));
					enrollResp.cmd = FP_STATUS_PLACE_FINGER;

					ASMResponse_t fpASMResponse;
					memset(&fpASMResponse, 0, sizeof(ASMResponse_t));

					fpASMResponse.responseData = ((void*)&enrollResp);
					fpASMResponse.statusCode = response->tag;
					if (fpPlaceFingerCallback != NULL)
					{
						fpPlaceFingerCallback->FPCallback(&fpASMResponse);
					}
				}
			}
			break;

			default:
			{
				out->responseType = UAF_ASM_STATUS_ERROR;
				DBG_Log("invalid value 0x%04X", response->value);
				loop = false;
			}
			break;
			}
		}
	}

	if (fp != NULL)
	{
		fclose(fp);
		fp = NULL;
	}

	if (out->responseType == UAF_ASM_STATUS_OK)
	{
		FILE *raw = fopen(out->raw, "rb");
		fseek(raw, 0, SEEK_END);
		int fpImageLength = ftell(raw);
		fseek(raw, 0, SEEK_SET);
		unsigned char* fpImage = new unsigned char[fpImageLength] {0, };
		fread(fpImage, 1, fpImageLength, raw);
		fclose(raw);
		raw = NULL;

		BITMAPFILEHEADER fh;
		memset(&fh, 0, sizeof(BITMAPFILEHEADER));
		fh.bfOffBits = sizeof(RGBQUAD) * 256 + sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER); // RGBQUAD + InfoHeader + FileHeader only 8bit mode if 24bit == 54; 40+ 14;
		fh.bfSize = fpImageLength + sizeof(RGBQUAD) * 256 + sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
		fh.bfType = 0x4D42;

		long widthHeight = (long)sqrt(fpImageLength);


		BITMAPINFOHEADER ih;
		memset(&ih, 0, sizeof(BITMAPINFOHEADER));
		ih.biBitCount = 8;
		ih.biHeight = widthHeight;
		ih.biPlanes = 1;
		ih.biSize = sizeof(BITMAPINFOHEADER);
		ih.biSizeImage = fpImageLength;
		ih.biWidth = widthHeight;
		ih.biXPelsPerMeter = 0;
		ih.biYPelsPerMeter = 0;

		RGBQUAD rgb[256];
		memset(&rgb, 0, sizeof(RGBQUAD) * 256);
		for (int i = 0; i < 256; i++)
		{
			rgb[i].rgbBlue = i;
			rgb[i].rgbGreen = i;
			rgb[i].rgbRed = i;
			rgb[i].rgbReserved = 0;
		}

		sprintf(out->bmp, "%s.bmp", fpName);
		FILE* bmp = fopen(out->bmp, "wb");

		fwrite(&fh, sizeof(BITMAPFILEHEADER), 1, bmp);
		fwrite(&ih, sizeof(BITMAPINFOHEADER), 1, bmp);
		fwrite(rgb, sizeof(RGBQUAD), 256, bmp);
		fwrite(fpImage, 1, fpImageLength, bmp);
		delete[] fpImage;
		fclose(bmp);
		bmp = NULL;
	}
	DBG_Log("bmpName: %s", out->raw);
	if (out->responseType != UAF_ASM_STATUS_OK)
	{
		DBG_Log("error: statusCode is not a UAF_ASM_STATUS_OK");
	}

	return out->responseType;
}

int AuthenticatorProfile::FimrwareUpdate(const FirmwareUpdateIn_t in, FirmwareUpdateOut_t* out)
{
	int ret = 0;
	unsigned char* fwBinaryBuffer = NULL;
	unsigned int   fwBinaryBufferSize = 0;
	ret = createUpdatePacket((const char*)in.fileName, &fwBinaryBuffer, &fwBinaryBufferSize);
	if (ret < 0)
	{
		DBG_Log("createUpdatePacket error");
		return -1;
	}
	if (fwBinaryBufferSize <= 0)
	{
		DBG_Log("invalid fwBinaryBufferSize");
		return -1;
	}
	if (fwBinaryBuffer == NULL)
	{
		DBG_Log("fwBinaryBuffer is NULL");
		return -1;
	}

	UpdatePacket_t updatePacketIn;
	memset(&updatePacketIn, 0x00, sizeof(UpdatePacket_t));
	updatePacketIn.blkSize = UPDATE_PACKET_BLOCK_SIZE;
	updatePacketIn.blkTotal = ((fwBinaryBufferSize + updatePacketIn.blkSize - 1) / updatePacketIn.blkSize);
	updatePacketIn.blkCount = 1;

	unsigned char buffer[8192] = { 0, };
	unsigned int  requestOffset = 0;
	TLV_t* request = (TLV_t*)buffer;

	request->t = FIDO_UTIL_REQ_TAG_WRITE_DATA;
	request->l = updatePacketIn.blkSize;
	request->l += sizeof(updatePacketIn.blkSize);
	request->l += sizeof(updatePacketIn.blkTotal);
	request->l += sizeof(updatePacketIn.blkCount);
	request->l += sizeof(updatePacketIn.verify);

	requestOffset += (4 + request->l);
	request = (TLV_t*)(buffer + requestOffset);

	request = (TLV_t*)buffer;
	request->l = requestOffset - 4;

	memset(out, 0x00, sizeof(FirmwareUpdateOut_t));

	TLV_t* response = (TLV_t*)buffer;
	unsigned short responseType = (unsigned short)-1;
	bool loop = true;
	while ( (updatePacketIn.blkCount <= updatePacketIn.blkTotal) && (loop == true) )
	{
		int sentCount = updatePacketIn.blkSize * (updatePacketIn.blkCount - 1);
		int copySize = fwBinaryBufferSize;
		if (fwBinaryBufferSize >= updatePacketIn.blkSize)
		{
			copySize = updatePacketIn.blkSize;
		}

		memset(updatePacketIn.data, 0x00, updatePacketIn.blkSize);
		memcpy(updatePacketIn.data, fwBinaryBuffer + sentCount, copySize);
		updatePacketIn.verify = CRC32::CalcCRC32(updatePacketIn.data, updatePacketIn.blkSize);

		request->t = FIDO_UTIL_REQ_TAG_WRITE_DATA;
		request->l = updatePacketIn.blkSize;
		request->l += sizeof(updatePacketIn.blkSize);
		request->l += sizeof(updatePacketIn.blkTotal);
		request->l += sizeof(updatePacketIn.blkCount);
		request->l += sizeof(updatePacketIn.verify);
		memcpy(request->v, &updatePacketIn, request->l);

		ret = HIDWrite(buffer, requestOffset, HID_CMD_UTIL);
		if (ret < 0)
		{
			DBG_Log("HIDWrite Fail");
			return -1;
		}

		ret = HIDRead((unsigned char*)response, 6, HID_CMD_UTIL);
		if (ret < 0)
		{
			DBG_Log("HIDRead Fail");
			return -1;
		}


		fwBinaryBufferSize -= copySize;

		/* Start Parsing */
		if (response->t != FIDO_UTIL_RSP_TAG_WRITE_DATA)
		{
			DBG_Log("invalid tag 0x%04X", response->t);
			dump(response->v, response->l, "invalid tag");
			loop = false;
			break;
		}

		if (response->l != 2)
		{
			responseType = -1;
			DBG_Log("invalid fpResponseLength");
			return -1;
		}

		int progress = 0;
		if (updatePacketIn.blkTotal != 0)
		{
			progress = (updatePacketIn.blkCount * 90) / updatePacketIn.blkTotal;
		}

		responseType = *((unsigned short*)response->v);

		out->responseType = responseType;
		out->statusCode = response->t;

		switch (responseType)
		{
			case FIDO_UTIL_STATUS_COMPLETE:
				{
					responseType = FIDO_UTIL_STATUS_COMPLETE;
					out->progress = (unsigned int)progress;
					if (utilFWUpdateCallback != 0)
					{
						/* last packet */
						if (updatePacketIn.blkCount >= updatePacketIn.blkTotal)
						{
							out->progress = (unsigned int)(100);
							loop = false;
							break;
						}

						if (utilFWUpdateCallback != NULL)
						{
							utilFWUpdateCallback->UtilCallback((void*)out);
						}
						utilFWUpdateCallback->UtilCallback((void*)out);
						updatePacketIn.blkCount++;
					}
				}
				break;

			case FIDO_UTIL_STATUS_FAIL:
				{
					responseType = FIDO_UTIL_STATUS_FAIL;
					out->progress = (unsigned int)(-1);
					if (utilFWUpdateCallback != NULL)
					{
						utilFWUpdateCallback->UtilCallback((void*)out);
					}

					loop = false;
				}
				break;


			default:
				{
					DBG_Log("invalid status 0x%04X", responseType);
					loop = false;
				}
				break;
		}
	}

	if (fwBinaryBuffer != NULL)
	{
		delete[] fwBinaryBuffer;
		fwBinaryBuffer = NULL;
	}

	if (responseType != FIDO_UTIL_STATUS_COMPLETE)
	{
		DBG_Log("error: responseType is not a FIDO_UTIL_STATUS_COMPLETE: 0x%04X", responseType);
		return responseType;
	}

	return responseType;
}

int AuthenticatorProfile::createUpdatePacket(const char* fileName, unsigned char** updateBinary, unsigned int* updateBinarySize)
{
	int ret = -1;

	if (updateBinarySize == NULL)
	{
		DBG_Log("updateBinarySize error");
		return -1;
	}

	const int invalidFile = 0;
	const int imgFile = 0x696D67;
	const int binFile = 0x62696E;
	int format = invalidFile;

	const char* fileFormat = fileName + strlen(fileName) - 4;

	if ((strcmp(fileFormat, ".img") == 0) || (strcmp(fileFormat, ".IMG") == 0))
	{
		format = imgFile;
	}
	else if ((strcmp(fileFormat, ".bin") == 0) || (strcmp(fileFormat, ".BIN") == 0))
	{
		format = binFile;
	}
	else
	{
		DBG_Log("file format error");
		return -1;
	}

	/* read file */
	FILE* imageFile = fopen(fileName, "rb");
	if (imageFile == NULL)
	{
		DBG_Log("fopen error");
		return -1;
	}
	unsigned int imageFileSize = 0;
	ret = fseek(imageFile, 0, SEEK_END);
	if (ret != 0)
	{
		fclose(imageFile);
		DBG_Log("fseek error");
		return -1;
	}
	imageFileSize = ftell(imageFile);
	if (imageFileSize < 0)
	{
		fclose(imageFile);
		DBG_Log("ftell error");
		return -1;
	}
	ret = fseek(imageFile, 0, SEEK_SET);
	if (ret != 0)
	{
		fclose(imageFile);
		DBG_Log("fseek error");
		return -1;
	}

	if ((0x2000 + imageFileSize) > UPDATE_AREA_SIZE)
	{
		DBG_Log("file size is too big");
		return -1;
	}

	unsigned char* imageFileBuffer = NULL;
	switch (format)
	{
		case imgFile:
			{
				imageFileBuffer = new unsigned char[imageFileSize] {0, };
				if (imageFileBuffer == NULL)
				{
					fclose(imageFile);
					DBG_Log("memory error");
					return -1;
				}
			}
			break;

		case binFile:
			{
				*updateBinarySize = imageFileSize + 0x2000;
				*updateBinary = new unsigned char[*updateBinarySize]{ 0, };
				imageFileBuffer = *updateBinary + 0x2000;
			}
			break;

		default:
			{
				fclose(imageFile);
				DBG_Log("format error");
				return -1;
			}
			break;
	}

	unsigned int readSize = (unsigned int)fread(imageFileBuffer, 1, imageFileSize, imageFile);
	if (readSize != imageFileSize)
	{
		fclose(imageFile);
		DBG_Log("fread error");
		return -1;
	}
	ret = fclose(imageFile);
	if (ret != 0)
	{
		DBG_Log("fclose error");
		return -1;
	}
	imageFile = NULL;

	if (format == imgFile)
	{
		bool isSecureBootEnableded = false;
		if (imageFileBuffer[5] == 1)
		{
			isSecureBootEnableded = true;
		}

		unsigned int appSize = 0;
		appSize += (imageFileBuffer[6] & 0xFF);
		appSize = appSize << 8;
		appSize += (imageFileBuffer[7] & 0xFF);
		appSize = appSize << 8;
		appSize += (imageFileBuffer[8] & 0xFF);
		appSize = appSize << 8;
		appSize += (imageFileBuffer[9] & 0xFF);
		const unsigned int headerSize = 14;
		const unsigned int block1Size = 0x2000; // Block#1: F/W IV ( 1KB ) + AKEY( 1KB ) + CURVE PARAM ( 2KB ) + CLP300 F/W ( 4KB ) = Total ( 8KB )
		const unsigned int block2Size = 0x2000; // Block#2 ~ Block #N: Signature S ( 1KB ) + Signature R ( 1KB ) + App size ( 1KB ) + Dummy ( 4KB ) = Total ( 8KB )
		*updateBinarySize = block2Size + appSize;

		*updateBinary = new unsigned char[(*updateBinarySize)]{ 0, };
		if (*updateBinary == NULL)
		{
			DBG_Log("memory error");
			return -1;
		}
		if (isSecureBootEnableded)
		{
			memcpy(*updateBinary, imageFileBuffer + headerSize + block1Size, block2Size);
		}
		else
		{
			memcpy(*updateBinary + block2Size, imageFileBuffer + headerSize, (*updateBinarySize) - block2Size);
		}

		if (imageFileBuffer != NULL)
		{
			delete[] imageFileBuffer;
			imageFileBuffer = NULL;
		}
	}

	return 0;
}

int AuthenticatorProfile::GetDeviceID(const ASMRequest_t in, GetDeviceIDOut_t* out)
{
	int ret = 0;

	unsigned char buffer[1024] = { 0, };
	TLV_t* request = (TLV_t*)buffer;

	request->t = FIDO_UTIL_REQ_TAG_READ_DID;
	request->l = 0;

	int statusCode = -1;
	ret = HIDWrite(buffer, 4, HID_CMD_UTIL);
	if (ret < 0)
	{
		DBG_Log("HIDWrite Fail");
		return -1;
	}

	memset(buffer, 0x00, sizeof(buffer));
	ret = HIDRead(buffer, sizeof(buffer), HID_CMD_UTIL);
	if (ret < 0)
	{
		DBG_Log("HIDRead Fail");
		return -1;
	}

	/* Start Parsing */
	TLV_t* response = (TLV_t*)buffer;
	DBG_Log("T: 0x%04X", response->t);
	DBG_Log("L: 0x%04X", response->l);



	memset(out, 0xcc, sizeof(GetDeviceIDOut_t));
	out->responseType = FIDO_UTIL_RSP_TAG_READ_DID;

	if (response->t != FIDO_UTIL_RSP_TAG_READ_DID)
	{
		DBG_Log("invalid tag 0x%04X", response->t);
		dump(response->v, response->l, "invalid tag");

		out->statusCode = FIDO_UTIL_STATUS_INVALID;
		statusCode = out->statusCode;
		return statusCode;
	}

	if (response->l > sizeof(out->deviceID))
	{
		DBG_Log("invalid length 0x%04X", response->l);
		dump(response->v, response->l, "invalid length");

		out->statusCode = FIDO_UTIL_STATUS_FAIL;
		statusCode = out->statusCode;
		return statusCode;
	}

	memcpy(out->deviceID, response->v, response->l);
	out->statusCode = FIDO_UTIL_STATUS_COMPLETE;
	statusCode = out->statusCode;

	if (statusCode != FIDO_UTIL_STATUS_COMPLETE)
	{
		DBG_Log("error: statusCode is not a FIDO_UTIL_STATUS_COMPLETE");
		return statusCode;
	}

	return statusCode;
}

int AuthenticatorProfile::SDBInit(const ASMRequest_t in, ASMResponse_t * out)
{
	int ret = 0;

	unsigned char buffer[1024] = { 0, };
	TLV_t* request = (TLV_t*)buffer;

	request->t = FIDO_UTIL_REQ_TAG_RM_DATA_BASE;
	request->l = 0;

	int statusCode = -1;
	ret = HIDWrite(buffer, 4, HID_CMD_UTIL);
	if (ret < 0)
	{
		DBG_Log("HIDWrite Fail");
		return -1;
	}

	memset(buffer, 0x00, sizeof(buffer));
	ret = HIDRead(buffer, sizeof(buffer), HID_CMD_UTIL);
	if (ret < 0)
	{
		DBG_Log("HIDRead Fail");
		return -1;
	}

	/* Start Parsing */
	TLV_t* response = (TLV_t*)buffer;
	DBG_Log("T: 0x%04X", response->t);
	DBG_Log("L: 0x%04X", response->l);

	memset(out, 0xcc, sizeof(ASMResponse_t));
	if (response->t != FIDO_UTIL_RSP_TAG_RM_DATA_BASE)
	{
		DBG_Log("invalid tag 0x%04X", response->t);
		dump(response->v, response->l, "invalid tag");

		out->statusCode = FIDO_UTIL_STATUS_INVALID;
		statusCode = out->statusCode;
		return statusCode;
	}

	if (response->l != 2)
	{
		DBG_Log("invalid length 0x%04X", response->l);
		dump(response->v, response->l, "invalid length");

		out->statusCode = FIDO_UTIL_STATUS_FAIL;
		statusCode = out->statusCode;
		return statusCode;
	}

	out->statusCode = FIDO_UTIL_STATUS_COMPLETE;
	statusCode = out->statusCode;

	if (statusCode != FIDO_UTIL_STATUS_COMPLETE)
	{
		DBG_Log("error: statusCode is not a FIDO_UTIL_STATUS_COMPLETE");
		return statusCode;
	}

	return statusCode;
}

int AuthenticatorProfile::FIDOInit(const ASMRequest_t in, ASMResponse_t * out)
{
	int ret = 0;

	unsigned char buffer[1024] = { 0, };
	TLV_t* request = (TLV_t*)buffer;

	request->t = FIDO_UTIL_REQ_TAG_INITIALIZE;
	request->l = 0;

	int statusCode = -1;
	ret = HIDWrite(buffer, 4, HID_CMD_UTIL);
	if (ret < 0)
	{
		DBG_Log("HIDWrite Fail");
		return -1;
	}

	memset(buffer, 0x00, sizeof(buffer));
	ret = HIDRead(buffer, sizeof(buffer), HID_CMD_UTIL);
	if (ret < 0)
	{
		DBG_Log("HIDRead Fail");
		return -1;
	}

	/* Start Parsing */
	TLV_t* response = (TLV_t*)buffer;
	DBG_Log("T: 0x%04X", response->t);
	DBG_Log("L: 0x%04X", response->l);

	memset(out, 0xcc, sizeof(ASMResponse_t));
	if (response->t != FIDO_UTIL_RSP_TAG_INITIALIZE)
	{
		DBG_Log("invalid tag 0x%04X", response->t);
		dump(response->v, response->l, "invalid tag");

		out->statusCode = FIDO_UTIL_STATUS_INVALID;
		statusCode = out->statusCode;
		return statusCode;
	}

	if (response->l != 2)
	{
		DBG_Log("invalid length 0x%04X", response->l);
		dump(response->v, response->l, "invalid length");

		out->statusCode = FIDO_UTIL_STATUS_FAIL;
		statusCode = out->statusCode;
		return statusCode;
	}

	out->statusCode = FIDO_UTIL_STATUS_COMPLETE;
	statusCode = out->statusCode;

	if (statusCode != FIDO_UTIL_STATUS_COMPLETE)
	{
		DBG_Log("error: statusCode is not a FIDO_UTIL_STATUS_COMPLETE");
		return statusCode;
	}

	return statusCode;
}
