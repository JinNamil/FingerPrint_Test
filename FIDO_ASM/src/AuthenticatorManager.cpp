#include "AuthenticatorManager.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>

using ASMType::Version_t;
using ASMType::FingerInfo_t;

#include "rapidjson/document.h"
#include "rapidjson/error/en.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"

#include "Debug.h"

using rapidjson::Value;
using rapidjson::Writer;
using rapidjson::StringBuffer;
using rapidjson::StringRef;
using std::string;

AuthenticatorManager::AuthenticatorManager()
{
}

AuthenticatorManager::~AuthenticatorManager()
{
    while( !authenticatorList.empty() )
    {
        if ( authenticatorList.back() )
        {
            delete authenticatorList.back();
            authenticatorList.back() = NULL;
        }
        authenticatorList.pop_back();
    }

}

ASM::ICallback* AuthenticatorManager::GetCallbackListener(void)
{
    return callbackListener;
}

void AuthenticatorManager::SetCallbackListener(ASM::ICallback* pListener)
{
    callbackListener = pListener;
}

ASM::IEnumerator* AuthenticatorManager::GetEnumeratorListener(void)
{
    return enumeratorListener;
}


void AuthenticatorManager::SetEnumeratorListener(ASM::IEnumerator* pEnumerationListener)
{
    enumeratorListener = pEnumerationListener;
}

int AuthenticatorManager::FPCallback(void* param)
{
    if ( param == NULL )
    {
        DBG_Log("param is NULL");
        return -1;
    }

    ASMResponse_t* response = (ASMResponse_t*)param;

    if ( response->responseData == NULL )
    {
        DBG_Log("responseData(=responseType) is NULL");
        return -1;
    }

    FP_Enroll_Rsp_t responseData = *((FP_Enroll_Rsp_t*)response->responseData);
    unsigned short  statusCode   = response->statusCode;

    StringBuffer jsonStringBuffer;
    Writer<StringBuffer> writer(jsonStringBuffer);
    writer.StartObject();
    writer.Key("statusCode");
    writer.Uint(statusCode);
    writer.Key("responseType");
    writer.Uint(responseData.cmd);
    if ( responseData.total > 0 )
    {
        writer.Key("total");
        writer.Uint(responseData.total);
        writer.Key("count");
        writer.Uint(responseData.count);
    }
    writer.EndObject();

    asmJSONData_t jsonData;
    jsonData.length = (int)jsonStringBuffer.GetLength()+1;
    jsonData.pData = new char[jsonData.length]{0,};
    memcpy(jsonData.pData, jsonStringBuffer.GetString(), jsonData.length-1);
    if ( GetCallbackListener() != NULL )
    {
        GetCallbackListener()->Callback(jsonData, jsonData);
    }
    delete[] jsonData.pData;
    jsonData.pData = NULL;

    return 0;
}

int AuthenticatorManager::FPTESTCallback(TESTASMResponse_t* param)
{
	if (param == NULL)
	{
		DBG_Log("param is NULL");
		return -1;
	}
	
	DBG_Log("%d", param->responseType);
	FPTestImageOut_t* response = (FPTestImageOut_t*)param;


	unsigned short  statusCode = response->statusCode;

	StringBuffer jsonStringBuffer;
	Writer<StringBuffer> writer(jsonStringBuffer);
	writer.StartObject();
	writer.Key("responseType");
	writer.Int(response->responseType);
	writer.Key("raw");
	writer.String(response->raw);
	writer.Key("bmp");
	writer.String(response->bmp);
	writer.Key("count");
	writer.String(response->count);
	writer.Key("operation");
	writer.String(response->operation);
	writer.Key("statusCode");
	writer.Int(response->statusCode);
	writer.EndObject();

	asmJSONData_t jsonData;
	jsonData.length = (int)jsonStringBuffer.GetLength() + 1;
	jsonData.pData = new char[jsonData.length]{ 0, };
	memcpy(jsonData.pData, jsonStringBuffer.GetString(), jsonData.length - 1);
	if (GetCallbackListener() != NULL)
	{
		GetCallbackListener()->Callback(jsonData, jsonData);
	}
	delete[] jsonData.pData;
	jsonData.pData = NULL;

	return 0;
}

int AuthenticatorManager::UtilCallback(void* param)
{
    if ( param == NULL )
    {
        DBG_Log("param is NULL");
        return -1;
    }

    FirmwareUpdateOut_t* response = (FirmwareUpdateOut_t*)param;

    StringBuffer jsonStringBuffer;
    Writer<StringBuffer> writer(jsonStringBuffer);
    writer.StartObject();
    writer.Key("responseType");
    writer.Uint(response->responseType);
    writer.Key("statusCode");
    writer.Uint(response->statusCode);
    writer.Key("progress");
    writer.Int((int)response->progress);
    writer.EndObject();

    asmJSONData_t jsonData;
    jsonData.length = (int)jsonStringBuffer.GetLength()+1;
    jsonData.pData = new char[jsonData.length]{0};
    memcpy(jsonData.pData, jsonStringBuffer.GetString(), jsonData.length-1);
    if ( GetCallbackListener() != NULL )
    {
        GetCallbackListener()->Callback(jsonData, jsonData);
    }
    delete[] jsonData.pData;
    jsonData.pData = NULL;

    return 0;
}

/* Change the Device Status to "Plugged" and notify when it needed */
int AuthenticatorManager::plugDevice(const char* in)
{
    int ret = -1;
    const int temp = 2;

    /* asmRequest Setting */
    ASMRequest_t asmRequest;
    GetInfoOut_t getInfoOut;

    /* Check the device is in the list */
    vector<AuthenticatorProfile*>::iterator it = authenticatorList.begin();
    while ( it != authenticatorList.end() )
    {
        if ( *(*it) == in )
        {
            for ( int i = 0; i < temp; i++ )
            {
            memset(&asmRequest, 0x00, sizeof(asmRequest));
            asmRequest.authenticatorIndex = (*it)->GetAuthenticatorIndex();
            memset(&getInfoOut, 0x00, sizeof(GetInfoOut_t));
            ret = (*it)->GetInfo(asmRequest, &getInfoOut);
            }

            if ( ret < 0 )
            {
                DBG_Log("Getinfo Fail");
                return -1;
            }
            DBG_Log("Getinfo Success");

            /* Device status: "Unplugged"=>"Plugged", do notify */
            if ( isDeviceStatus(in, Unplugged) )
            {
                notify(in, Plugged);
            }

            /* device status: "Unplugged"=>"Plugged", "Unknown(=Plugged)"=>"Plugged" */
            (*it)->SetDeviceStatus(Plugged);
            return 0;
        }
        it++;
    }

    /* The new Device is plugged, do notify */
    int authenticatorIndex = 0;
    if ( authenticatorList.empty() != true )
    {
        authenticatorIndex = (int)authenticatorList.size();
    }
    AuthenticatorProfile* newAuthenticator = new AuthenticatorProfile(in, authenticatorIndex);
    if ( newAuthenticator == NULL )
    {
        return -1;
    }

    for ( int i = 0; i < temp; i++ )
    {
        memset(&asmRequest, 0x00, sizeof(asmRequest));
        memset(&getInfoOut, 0x00, sizeof(GetInfoOut_t));
        asmRequest.authenticatorIndex = (unsigned short)(newAuthenticator->GetAuthenticatorIndex());
        ret = newAuthenticator->GetInfo(asmRequest, &getInfoOut);
    }
    if ( ret < 0 )
    {
        DBG_Log("Getinfo Fail");
        return -1;
    }
    DBG_Log("Getinfo Success");

    newAuthenticator->SetDeviceStatus(Plugged);
    authenticatorList.push_back(newAuthenticator);
    notify(in, Plugged);

    return 0;
}

/* Change the Device Status to "Plugged"=>"Unknown" for the Unplugged notify */
int AuthenticatorManager::unplugReady(void)
{
    vector<AuthenticatorProfile*>::iterator it = authenticatorList.begin();
    while ( it != authenticatorList.end() )
    {
        if ( (*it)->GetDeviceStatus() == Plugged )
        {
            (*it)->SetDeviceStatus(UnknownEventType);
        }
        it++;
    }
    return 0;
}

/* change the Device Status to "Unplugged" and notify when it needed */
int AuthenticatorManager::unplugDevice(void)
{
    vector<AuthenticatorProfile*>::iterator it = authenticatorList.begin();
    while ( it != authenticatorList.end() )
    {
        if ( (*it)->GetDeviceStatus() == UnknownEventType )
        {
            (*it)->SetDeviceStatus(Unplugged);
            notify((*it)->GetDeviceName(), Unplugged);
        }
        it++;
    }
    return 0;
}
/* check the device status */
int AuthenticatorManager::isDeviceStatus(const char* in, asmEnumerationType_t eventType)
{
    vector<AuthenticatorProfile*>::iterator it = authenticatorList.begin();
    while ( it != authenticatorList.end() )
    {
        if ( *(*it) == in && (*it)->GetDeviceStatus() == eventType )
        {
            return 1;
        }
        it++;
    }
    return 0;
}



extern void dump(const unsigned char *data, int size, const char* tag);

/* make a json message and send to client */
void AuthenticatorManager::notify(const char* in, asmEnumerationType_t eventType)
{
    /* Send Notify */
    char jsonMessage[4096] = {0,};
    sprintf(jsonMessage, "{\"deviceData\" : \"%s\", \"eventType\" : ", in);
    if ( eventType == Plugged )
    {
        strcat(jsonMessage, "\"plugged\"}");
    }
    else if( eventType == Unplugged )
    {
        strcat(jsonMessage, "\"unplugged\"}");
    }

    asmJSONData_t jsonData;
    jsonData.length = (int)strlen(jsonMessage) + 1;
    jsonData.pData = new char[jsonData.length] {0, };
    memcpy(jsonData.pData, jsonMessage, jsonData.length-1);
    if ( enumeratorListener != NULL )
    {
        GetEnumeratorListener()->Notify(eventType, jsonData);
    }
    delete[] jsonData.pData;
    jsonData.pData = NULL;
}

/* Find the all raw input devices and compare to the authenticator list */
unsigned int AuthenticatorManager::UpdateList(asmEnumerationType_t eventType)
{
    unsigned int ret = 0;
    unsigned int pluggedDevices = 0;

    /* Get the input device list size */
    unsigned int devicesNum = 0;
    GetRawInputDeviceList(NULL, &devicesNum, sizeof(RAWINPUTDEVICELIST));

    /* Allocate the memory for input device list */
    PRAWINPUTDEVICELIST deviceList = new RAWINPUTDEVICELIST[sizeof(RAWINPUTDEVICELIST)*devicesNum];

    /* Enumerates the input device list */
    ret = GetRawInputDeviceList(deviceList, &devicesNum, sizeof(RAWINPUTDEVICELIST));
    if ( ret != devicesNum || ret == (unsigned int)-1 )
    {
        delete[] deviceList;
        deviceList = NULL;
    }
	if ( deviceList == NULL )
	{
		return -1;
	}

    /* Update authenticatorManager ( Unplugged and "Plugged"=>"Unknown" ) */
    if ( eventType == Unplugged )
    {
        unplugReady();
    }

    /* Compare loop */
    for ( unsigned int i = 0; i < devicesNum; i++ )
    {
        /* Get the device name buffer size */
        unsigned int bufferSize = 0;
        ret = GetRawInputDeviceInfo(deviceList[i].hDevice, RIDI_DEVICENAME, NULL, &bufferSize);
        if ( ret < 0 )
        {
            DBG_Log("GetRawInputDeviceInfo Error");
            continue;
        }


        /* Allocate the memory for device name */
        char* inputDeviceName = new char[bufferSize*2]{0,};

        /* Get the name */
        ret = GetRawInputDeviceInfo(deviceList[i].hDevice, RIDI_DEVICENAME, inputDeviceName, &bufferSize);
        if ( ret < 0)
        {
            if ( inputDeviceName )
            {
                delete[] inputDeviceName;
                inputDeviceName = NULL;
            }
            continue;
        }

        /* Get device info buffer */
        RID_DEVICE_INFO deviceInfo;
        memset(&deviceInfo, 0, sizeof(RID_DEVICE_INFO));
        deviceInfo.cbSize = sizeof(RID_DEVICE_INFO);
        bufferSize        = sizeof(RID_DEVICE_INFO);
        ret = GetRawInputDeviceInfo(deviceList[i].hDevice, RIDI_DEVICEINFO, &deviceInfo, &bufferSize);
        if ( ret < 0)
        {
            if ( inputDeviceName )
            {
                delete[] inputDeviceName;
                inputDeviceName = NULL;
            }
            continue;
        }

        /* Check the HID type */
        if ( deviceInfo.dwType != RIM_TYPEHID )
        {
            if ( inputDeviceName )
            {
                delete[] inputDeviceName;
                inputDeviceName = NULL;
            }
            continue;
        }

        /* Check VID and PID */
        if (deviceInfo.hid.dwVendorId != USB_VID || deviceInfo.hid.dwProductId != USB_PID)
        {
            if ( inputDeviceName )
            {
                delete[] inputDeviceName;
                inputDeviceName = NULL;
            }
            continue;
        }

        /* Update authenticatorManager ( Unplugged and Unknown => Plugged ) */
        /* if the device status change to Unplugged => Plugged, do Plugged notify */
        plugDevice(inputDeviceName);
        pluggedDevices++;
        if ( inputDeviceName )
        {
            delete[] inputDeviceName;
            inputDeviceName = NULL;
        }
    }

    /* if the device status change to Unplugged => Plugged, do Plugged notify */
    if ( eventType == Unplugged )
    {
        unplugDevice();
    }

    /* free a deviceList memory */
    if ( deviceList != NULL )
    {
        delete[] deviceList;
        deviceList = NULL;
    }

    return pluggedDevices;
}

int AuthenticatorManager::ASMProcess(const asmJSONData_t *pInData)
{
    int ret = -1;
    int requestNumber = -1;

    DBG_Log("JSON Request %s", pInData->pData);

    Document request;
    ret = request.Parse(pInData->pData).HasParseError();
    if ( ret != (int)false )
    {
        DBG_Log("JSON Parse Error: %s", pInData->pData);
        DBG_Log("Error(offset 0x%04X): %s", request.GetErrorOffset(), GetParseError_En(request.GetParseError()));
        return Failure;
    }

    ret = request.HasMember("requestType");
    if ( ret != (int)true )
    {
        DBG_Log("JSON requestType error");
        return Failure;
    }
    ret = request["requestType"].IsString();
    if ( ret != (int)true )
    {
        DBG_Log("JSON requestType error");
        return Failure;
    }

    char* requestType = new char[(strlen((char*)request["requestType"].GetString())+1)]{0,};
	if ( requestType == NULL )
	{
		DBG_Log("new error");
		return Failure;
	}
    sprintf(requestType, "%s", (char*)request["requestType"].GetString());
    DBG_Log("JSON requestType: %s", requestType);
    for ( int i = 0; i < ASMType::RequestMax; i++ )
    {
        ret = strcmp(ASMType::asmRequest[i], requestType);
        if ( ret == 0 )
        {
            requestNumber = i;
            break;
        }
		
        ret = -1;
    }
    DBG_Log("requestType: %d", requestNumber);
    delete[] requestType;
    requestType = NULL;

    switch ( requestNumber )
    {
        case ASMType::GetInfo:
            {
                ret = this->getInfo(request);
                if ( ret < 0 )
                {
                    DBG_Log("getInfo error");
                    return -1;
                }
            }
            break;

        case ASMType::Register:
            {
                ret = this->registration(request);
                if ( ret < 0 )
                {
                    DBG_Log("registration error");
                    return -1;
                }
            }
            break;

        case ASMType::Authenticate:
            {
                ret = this->authenticate(request);
                if ( ret < 0 )
                {
                    DBG_Log("authenticate error");
                    return -1;
                }
            }
            break;

        case ASMType::Deregister:
            {
                ret = this->deregister(request);
                if ( ret < 0 )
                {
                    DBG_Log("deregister error");
                    return -1;
                }
            }
            break;

        case ASMType::GetRegistrations:
            {
                ret = this->getRegistration(request);
                if ( ret < 0 )
                {
                    DBG_Log("getRegistration error");
                    return -1;
                }
            }
            break;

        case ASMType::FPEnroll:
            {
                ret = this->fpEnroll(request);
                if ( ret < 0 )
                {
                    DBG_Log("fpEnroll error");
                    return -1;
                }
            }
            break;

        case ASMType::FPVerify:
            {
                ret = this->fpVerify(request);
                if ( ret < 0 )
                {
                    DBG_Log("fpVerify error");
                    return -1;
                }
            }
            break;

        case ASMType::FPEnrollCheck:
            {
                ret = this->fpEnrollCheck(request);
                if ( ret < 0 )
                {
                    DBG_Log("fpEnrollCheck error");
                    return -1;
                }
            }
            break;

        case ASMType::FPRemove:
            {
                ret = this->fpRemove(request);
                if ( ret < 0 )
                {
                    DBG_Log("FPRemove error");
                    return -1;
                }
            }
            break;

        case ASMType::FPGetList:
            {
                ret = this->fpGetList(request);
                if ( ret < 0 )
                {
                    DBG_Log("FPGetList error");
                    return -1;
                }
            }
            break;

        case ASMType::FPGetImage:
            {
                ret = this->fpGetImage(request);
                if ( ret < 0 )
                {
                    DBG_Log("FPGetImage error");
                    return -1;
                }
            }
            break;

		case ASMType::FPTestImage:
		{
			ret = this->fpTestImage(request);
			if (ret < 0)
			{
				DBG_Log("FPTestImage error");
				return -1;
			}
		}
		break;

		case ASMType::FPVerifyImage:
		{
			ret = this->VerifyFPImage(request);
			if (ret < 0)
			{
				DBG_Log("FPTestImage error");
				return -1;
			}
		}
		break; 

        case ASMType::FWUpdate:
            {
                ret = this->utilFWUpdate(request);
                if ( ret < 0 )
                {
                    DBG_Log("utilFWUpdate error");
                    return -1;
                }
            }
            break;

        case ASMType::GetDeviceID:
            {
                ret = this->utilGetDeviceID(request);
                if ( ret < 0 )
                {
                    DBG_Log("utilGetDeviceID error");
                    return -1;
                }
            }
            break;

        case ASMType::SDBInit:
            {
                ret = this->utilSDBInit(request);
                if ( ret < 0 )
                {
                    DBG_Log("utilSDBInit error");
                    return -1;
                }
            }
            break;

        case ASMType::FIDOInit:
            {
                ret = this->utilFIDOInit(request);
                if ( ret < 0 )
                {
                    DBG_Log("utilFIDOInit error");
                    return -1;
                }
            }
            break;

        case ASMType::OpenSettings:
            {
            }
            break;

        default:
            {
                DBG_Log("Invalid requestType: 0x%02X", ret);
            }
            break;

    }

    return 0;
}

int AuthenticatorManager::getInfo(Document& request)
{
    int ret = -1;

    /* asmRequest Setting */
    ASMRequest_t asmRequest;
    memset(&asmRequest, 0x00, sizeof(asmRequest));

    /* asmRequest Setting - 1. requestType */
    asmRequest.requestType = ASMType::GetInfo;

    /* asmRequest Setting - 2. version */
    Version_t version;
    memset(&version, 0x00, sizeof(version));

    ret = request.HasMember("asmVersion");
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    ret = request["asmVersion"].IsObject();
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    const Value& asmVersion = request["asmVersion"].GetObjectA();

    ret = asmVersion.HasMember("major");
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    ret = asmVersion["major"].IsInt();
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    version.major = asmVersion["major"].GetInt();

    ret = asmVersion.HasMember("minor");
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    ret = asmVersion["minor"].IsInt();
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    version.minor = asmVersion["minor"].GetInt();
    asmRequest.asmVersion = version;

    /* asmRequest Setting - 3. exts*/
    asmRequest.exts = NULL;

    GetInfoOut_t getInfoOut;
    memset(&getInfoOut, 0x00, sizeof(GetInfoOut_t));

    /* send request */
    vector<AuthenticatorProfile*>::iterator it = authenticatorList.begin();
    while (  it != authenticatorList.end() )
    {
        if ( (*it)->GetDeviceStatus() == Unplugged )
        {
            it++;
            continue;
        }

        /* asmRequest Setting - 4. authenticatorIndex */
        asmRequest.authenticatorIndex = (*it)->GetAuthenticatorIndex();
        ret = (*it)->GetInfo(asmRequest, &getInfoOut);
        if ( ret < 0 )
        {
            DBG_Log("GetInfo error");
            return -1;
        }

        StringBuffer jsonStringBuffer;
        Writer<StringBuffer> writer(jsonStringBuffer);
        writer.StartObject();
        writer.Key("responseData");
        if ( getInfoOut.Authenticators != NULL )
        {
            writer.StartObject();
            writer.Key("Authenticators");
            writer.StartArray();
            writer.StartObject();
            writer.Key("aaid");
            if ( getInfoOut.Authenticators->aaid != NULL )
            {
                writer.String((char*)getInfoOut.Authenticators->aaid);
                delete[] getInfoOut.Authenticators->aaid;
                getInfoOut.Authenticators->aaid = NULL;
            }
            else
            {
                writer.Null();
            }

            writer.Key("asmVersions");
            writer.StartArray();
            writer.StartObject();
            if ( getInfoOut.Authenticators->asmVersions != NULL )
            {
                writer.Key("major");
                if ( getInfoOut.Authenticators->asmVersions->major > 1 )
                {
                    writer.Int(getInfoOut.Authenticators->asmVersions->major);
                }
                else
                {
                    writer.Int(1);
                }

                writer.Key("minor");
                writer.Int(0);

                delete getInfoOut.Authenticators->asmVersions;
                getInfoOut.Authenticators->asmVersions = NULL;
            }
            else
            {
                writer.Key("major");
                writer.Int(1);
                writer.Key("minor");
                writer.Int(0);
            }
            writer.EndObject();
            writer.EndArray();

            writer.Key("assertionScheme");
            if ( getInfoOut.Authenticators->assertionScheme != NULL )
            {
                writer.String((char*)getInfoOut.Authenticators->assertionScheme);
            }
            else
            {
                writer.Null();
            }


            writer.Key("title");
            if ( getInfoOut.Authenticators->title != NULL )
            {
                writer.String((char*)getInfoOut.Authenticators->title);
            }
            else
            {
                writer.String("UAF Title Empty");
            }


            writer.Key("attestationTypes");
            writer.StartArray();
            writer.Uint(getInfoOut.Authenticators->attestationTypes);
            writer.EndArray();

            writer.Key("tcDisplayContentType");
            if ( getInfoOut.Authenticators->tcDisplayContentType != NULL )
            {
                writer.String((char*)getInfoOut.Authenticators->tcDisplayContentType);
                delete[] getInfoOut.Authenticators->tcDisplayContentType;
                getInfoOut.Authenticators->tcDisplayContentType = NULL;
            }
            else
            {
                writer.String("text/plain");
            }

            writer.Key("description");
            if ( getInfoOut.Authenticators->description != NULL )
            {
                writer.String((char*)getInfoOut.Authenticators->description);
            }
            else
            {
                writer.String("Pretty long description");
            }

            /* To do */
            writer.Key("attachmentHint");
            writer.Uint(1);
            writer.Key("authenticationAlgorithm");
            writer.Uint(2);
            writer.Key("authenticatorIndex");
            writer.Uint(getInfoOut.Authenticators->authenticatorIndex);
            writer.Key("hasSettings");
            writer.Bool(false);
            writer.Key("icon");
            writer.String("data:image/png;base64,iVBORw0KGgoAAA");
            writer.Key("isRoamingAuthenticator");
            writer.Bool(true);
            writer.Key("isSecondFactorOnly");
            writer.Bool(false);
            writer.Key("isUserEnrolled");
            writer.Bool(false);
            writer.Key("keyProtection");
            writer.Uint(2);
            writer.Key("matcherProtection");
            writer.Uint(4);
            writer.Key("supportedExtensionIDs");
            writer.StartArray();
            writer.String("abc");
            writer.EndArray();
            writer.Key("tcDisplay");
            writer.Uint(0);
            writer.Key("userVerification");
            writer.Uint(3);

            writer.EndObject();
            writer.EndArray();
            writer.EndObject();
        }

        writer.Key("statusCode");
        writer.Uint(ret);
        writer.EndObject();

        asmJSONData_t jsonData;
        jsonData.length = (int)strlen(jsonStringBuffer.GetString())+1;
        jsonData.pData = new char[jsonData.length]{0};
        memcpy(jsonData.pData, jsonStringBuffer.GetString(), jsonData.length-1);
        if ( GetCallbackListener() != NULL )
        {
            GetCallbackListener()->Callback(jsonData, jsonData);
        }
        delete[] jsonData.pData;
        jsonData.pData = NULL;

        it++;
    }

    return 0;
}

int AuthenticatorManager::registration(Document& request)
{
    int ret = -1;
    ASMRequest_t asmRequest;

    /* asmRequest Setting */
    memset(&asmRequest, 0x00, sizeof(asmRequest));

    /* asmRequest Setting - 1. requestType */
    asmRequest.requestType = ASMType::Register;

    /* asmRequest Setting - 2. version */
    Version_t version;
    memset(&version, 0x00, sizeof(version));

    ret = request.HasMember("asmVersion");
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    ret = request["asmVersion"].IsObject();
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    const Value& asmVersion = request["asmVersion"].GetObjectA();

    ret = asmVersion.HasMember("major");
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    ret = asmVersion["major"].IsInt();
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    version.major = asmVersion["major"].GetInt();

    ret = asmVersion.HasMember("minor");
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    ret = asmVersion["minor"].IsInt();
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    version.minor = asmVersion["minor"].GetInt();
    asmRequest.asmVersion = version;

    /* asmRequest Setting - 3. exts*/
    asmRequest.exts = NULL;

    /* asmRequest Setting - 4. authenticatorIndex */
    ret = request.HasMember("authenticatorIndex");
    if ( ret != (int)true )
    {
        DBG_Log("authenticatorIndex error");
        return -1;
    }
    ret = request["authenticatorIndex"].IsInt();
    if ( ret != (int)true )
    {
        DBG_Log("authenticatorIndex error");
        return -1;
    }
    asmRequest.authenticatorIndex = request["authenticatorIndex"].GetInt();

    /* asmRequest Setting - 5. args */
    RegisterIn_t registerRequest;
    memset(&registerRequest, 0x00, sizeof(registerRequest));

    ret = request.HasMember("args");
    if ( ret != (int)true )
    {
        DBG_Log("args error");
        return -1;
    }
    ret = request["args"].IsObject();
    if ( ret != (int)true )
    {
        DBG_Log("args error");
        return -1;
    }
    const Value& args = request["args"].GetObjectA();

    ret = args.HasMember("appID");
    if ( ret != (int)true )
    {
        DBG_Log("appID error");
        return -1;
    }
    ret = args["appID"].IsString();
    if ( ret != (int)true )
    {
        DBG_Log("appID error");
        return -1;
    }

    int appIDLen = (int)strlen(args["appID"].GetString());
    registerRequest.appID = new unsigned char[appIDLen+1]{0,};
    memcpy((char*)registerRequest.appID, args["appID"].GetString(), appIDLen);

    ret = args.HasMember("username");
    if ( ret != (int)true )
    {
        DBG_Log("username error");
        return -1;
    }
    ret = args["username"].IsString();
    if ( ret != (int)true )
    {
        DBG_Log("username error");
        return -1;
    }

    int userNameLen = (int)strlen(args["username"].GetString());
    registerRequest.username = new unsigned char[userNameLen+1]{0,};
    memcpy((char*)registerRequest.username, args["username"].GetString(), userNameLen);

    ret = args.HasMember("finalChallenge");
    if ( ret != (int)true )
    {
        DBG_Log("finalChallenge error");
        return -1;
    }
    ret = args["finalChallenge"].IsString();
    if ( ret != (int)true )
    {
        DBG_Log("finalChallenge error");
        return -1;
    }

    int finalChallengeLen = (int)strlen(args["finalChallenge"].GetString());
    registerRequest.finalChallenge = new unsigned char[finalChallengeLen+1]{0,};
    memcpy((char*)registerRequest.finalChallenge, args["finalChallenge"].GetString(), finalChallengeLen);

    ret = args.HasMember("attestationType");
    if ( ret != (int)true )
    {
        DBG_Log("attestationType error");
        return -1;
    }
    ret = args["attestationType"].IsInt();
    if ( ret != (int)true )
    {
        DBG_Log("attestationType error");
        return -1;
    }
    registerRequest.attestationType = args["attestationType"].GetInt();

    RegisterOut_t registerResponse;
    memset(&registerResponse, 0x00, sizeof(registerResponse));

    /* send request */
    vector<AuthenticatorProfile*>::iterator it = authenticatorList.begin();
    while (  it != authenticatorList.end() )
    {
        if ( (*it)->GetAuthenticatorIndex() == asmRequest.authenticatorIndex )
        {
            ret = (*it)->SetPlaceFingerCB(this);
            if ( ret < 0 )
            {
                DBG_Log("SetPlaceFingerCB error 0x%04X", ret);
            }
            ret = (*it)->Register(registerRequest, &registerResponse);
            if ( ret < 0 )
            {
                DBG_Log("Register error 0x%04X", ret);
            }

            StringBuffer jsonStringBuffer;
            Writer<StringBuffer> writer(jsonStringBuffer);

            writer.StartObject();
            if ( ret == UAF_ASM_STATUS_OK )
            {
                writer.Key("responseData");
                writer.StartObject();
                if ( registerResponse.assertion != NULL )
                {
                    writer.Key("assertion");
                    writer.String((char*)registerResponse.assertion);
                    delete[] registerResponse.assertion;
                    registerResponse.assertion = NULL;
                    writer.Key("assertionScheme");
                    writer.String((char*)"UAFV1TLV");
                    writer.Key("keyHandle");
                    writer.String((char*)registerResponse.keyHandle);
                    delete[] registerResponse.keyHandle;
                }
                writer.EndObject();
            }
            writer.Key("statusCode");
            writer.Int(ret);
            writer.EndObject();

            asmJSONData_t jsonData;
            jsonData.length = (int)strlen(jsonStringBuffer.GetString())+1;
            jsonData.pData = new char[jsonData.length]{0};
            memcpy(jsonData.pData, jsonStringBuffer.GetString(), jsonData.length-1);
            if ( GetCallbackListener() != NULL )
            {
                GetCallbackListener()->Callback(jsonData, jsonData);
            }
            delete[] jsonData.pData;
            jsonData.pData = NULL;
        }
        it++;
    }

    delete[] registerRequest.appID;
    registerRequest.appID = NULL;
    delete[] registerRequest.username;
    registerRequest.username = NULL;
    delete[] registerRequest.finalChallenge;
    registerRequest.finalChallenge = NULL;

    return 0;
}

int AuthenticatorManager::authenticate(Document& request)
{
    int ret = -1;
    ASMRequest_t asmRequest;

    /* asmRequest Setting */
    memset(&asmRequest, 0x00, sizeof(asmRequest));

    /* asmRequest Setting - 1. requestType */
    asmRequest.requestType = ASMType::Authenticate;

    /* asmRequest Setting - 2. version */
    Version_t version;
    memset(&version, 0x00, sizeof(version));

    ret = request.HasMember("asmVersion");
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    ret = request["asmVersion"].IsObject();
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    const Value& asmVersion = request["asmVersion"].GetObjectA();

    ret = asmVersion.HasMember("major");
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    ret = asmVersion["major"].IsInt();
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    version.major = asmVersion["major"].GetInt();

    ret = asmVersion.HasMember("minor");
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    ret = asmVersion["minor"].IsInt();
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    version.minor = asmVersion["minor"].GetInt();
    asmRequest.asmVersion = version;

    /* asmRequest Setting - 3. exts*/
    asmRequest.exts = NULL;

    /* asmRequest Setting - 4. authenticatorIndex */
    ret = request.HasMember("authenticatorIndex");
    if ( ret != (int)true )
    {
        DBG_Log("authenticatorIndex error");
        return -1;
    }
    ret = request["authenticatorIndex"].IsInt();
    if ( ret != (int)true )
    {
        DBG_Log("authenticatorIndex error");
        return -1;
    }
    asmRequest.authenticatorIndex = request["authenticatorIndex"].GetInt();

    /* asmRequest Setting - 5. args */
    AuthenticateIn_t authenticateRequest;
    memset(&authenticateRequest, 0x00, sizeof(authenticateRequest));

    ret = request.HasMember("args");
    if ( ret != (int)true )
    {
        DBG_Log("args error");
        return -1;
    }
    ret = request["args"].IsObject();
    if ( ret != (int)true )
    {
        DBG_Log("args error");
        return -1;
    }
    const Value& args = request["args"].GetObjectA();

    ret = args.HasMember("appID");
    if ( ret != (int)true )
    {
        DBG_Log("appID error");
        return -1;
    }
    ret = args["appID"].IsString();
    if ( ret != (int)true )
    {
        DBG_Log("appID error");
        return -1;
    }

    int appIDLen = (int)strlen(args["appID"].GetString());
    authenticateRequest.appID = new unsigned char[appIDLen+1]{0,};
    memcpy((char*)authenticateRequest.appID, args["appID"].GetString(), appIDLen);

    ret = args.HasMember("finalChallenge");
    if ( ret != (int)true )
    {
        DBG_Log("finalChallenge error");
        return -1;
    }
    ret = args["finalChallenge"].IsString();
    if ( ret != (int)true )
    {
        DBG_Log("finalChallenge error");
        return -1;
    }

    int finalChallengeLen = (int)strlen(args["finalChallenge"].GetString());
    authenticateRequest.finalChallenge = new unsigned char[finalChallengeLen+1]{0,};
    memcpy((char*)authenticateRequest.finalChallenge, args["finalChallenge"].GetString(), finalChallengeLen);

    ret = args.HasMember("keyHandle");
    if ( ret == (int)true )
    {
        ret = args["keyHandle"].IsString();
        if ( ret == (int)true )
        {
            int keyHandleLen = (int)strlen(args["keyHandle"].GetString());
            authenticateRequest.keyHandle = new unsigned char[keyHandleLen+1]{0,};
            memcpy((char*)authenticateRequest.keyHandle, args["keyHandle"].GetString(), keyHandleLen);
        }
    }

    AuthenticateOut_t authenticateResponse;
    memset(&authenticateResponse, 0x00, sizeof(authenticateResponse));

    /* send request */
    vector<AuthenticatorProfile*>::iterator it = authenticatorList.begin();
    while (  it != authenticatorList.end() )
    {
        if ( (*it)->GetAuthenticatorIndex() == asmRequest.authenticatorIndex )
        {
            ret = (*it)->SetPlaceFingerCB(this);
            if ( ret < 0 )
            {
                DBG_Log("SetPlaceFingerCB error 0x%04X", ret);
            }
            ret = (*it)->Authenticate(authenticateRequest, &authenticateResponse);
            if ( ret < 0 )
            {
                DBG_Log("Authenticate error 0x%04X", ret);
            }

            StringBuffer jsonStringBuffer;
            Writer<StringBuffer> writer(jsonStringBuffer);
            writer.StartObject();
            if ( ret == UAF_ASM_STATUS_OK )
            {
                writer.Key("responseData");
                writer.StartObject();
                if ( authenticateResponse.userNameAndKeyHadleCount != -1 )
                {
                    char jsonTagBuffer[256];
                    int UserNameAndKeyHandleCount = 0;
                    while ( UserNameAndKeyHandleCount <= authenticateResponse.userNameAndKeyHadleCount )
                    {
                        memset(jsonTagBuffer, 0x00, sizeof(jsonTagBuffer));
                        sprintf(jsonTagBuffer, "userName%04d", UserNameAndKeyHandleCount);

                        if ( authenticateResponse.userNameAndKeyHadle[UserNameAndKeyHandleCount].userName != NULL )
                        {
                            writer.Key(StringRef(jsonTagBuffer, strlen(jsonTagBuffer)));
                            writer.String((char*)authenticateResponse.userNameAndKeyHadle[UserNameAndKeyHandleCount].userName);
                            delete[] authenticateResponse.userNameAndKeyHadle[UserNameAndKeyHandleCount].userName;
                        }
                        else
                        {
                            DBG_Log("%s is Empty", jsonTagBuffer);
                            return -1;
                        }

                        memset(jsonTagBuffer, 0x00, sizeof(jsonTagBuffer));
                        sprintf(jsonTagBuffer, "keyHandle%04d", UserNameAndKeyHandleCount);

                        if ( authenticateResponse.userNameAndKeyHadle[UserNameAndKeyHandleCount].keyHandle != NULL )
                        {
                            writer.Key(StringRef(jsonTagBuffer, strlen(jsonTagBuffer)));
                            writer.String((char*)authenticateResponse.userNameAndKeyHadle[UserNameAndKeyHandleCount].keyHandle);
                            delete[] authenticateResponse.userNameAndKeyHadle[UserNameAndKeyHandleCount].keyHandle;
                        }
                        else
                        {
                            DBG_Log("%s is Empty", jsonTagBuffer);
                            return -1;
                        }

                        UserNameAndKeyHandleCount++;
                    }
                }
                else if ( authenticateResponse.assertion != NULL )
                {
                    writer.Key("assertion");
                    writer.String((char*)authenticateResponse.assertion);
                }
                else
                {
                    DBG_Log("response error");
                }
                writer.EndObject();
            }
            writer.Key("statusCode");
            writer.Int(ret);
            writer.EndObject();

            asmJSONData_t jsonData;
            jsonData.length = (int)strlen(jsonStringBuffer.GetString())+1;
            jsonData.pData = new char[jsonData.length]{0};
            memcpy(jsonData.pData, jsonStringBuffer.GetString(), jsonData.length-1);
            if ( GetCallbackListener() != NULL )
            {
                GetCallbackListener()->Callback(jsonData, jsonData);
            }
            delete[] jsonData.pData;
            jsonData.pData = NULL;
        }
        it++;
    }

    return 0;
}

int AuthenticatorManager::deregister(Document& request)
{
    int ret = -1;
    ASMRequest_t asmRequest;

    /* asmRequest Setting */
    memset(&asmRequest, 0x00, sizeof(asmRequest));

    /* asmRequest Setting - 1. requestType */
    asmRequest.requestType = ASMType::Deregister;

    /* asmRequest Setting - 2. version */
    Version_t version;
    memset(&version, 0x00, sizeof(version));

    ret = request.HasMember("asmVersion");
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    ret = request["asmVersion"].IsObject();
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    const Value& asmVersion = request["asmVersion"].GetObjectA();

    ret = asmVersion.HasMember("major");
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    ret = asmVersion["major"].IsInt();
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    version.major = asmVersion["major"].GetInt();

    ret = asmVersion.HasMember("minor");
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    ret = asmVersion["minor"].IsInt();
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    version.minor = asmVersion["minor"].GetInt();
    asmRequest.asmVersion = version;

    /* asmRequest Setting - 3. exts*/
    asmRequest.exts = NULL;

    /* asmRequest Setting - 4. authenticatorIndex */
    ret = request.HasMember("authenticatorIndex");
    if ( ret != (int)true )
    {
        DBG_Log("authenticatorIndex error");
        return -1;
    }
    ret = request["authenticatorIndex"].IsInt();
    if ( ret != (int)true )
    {
        DBG_Log("authenticatorIndex error");
        return -1;
    }
    asmRequest.authenticatorIndex = request["authenticatorIndex"].GetInt();

    /* asmRequest Setting - 5. args */
    DeregisterIn_t deregisterRequest;
    memset(&deregisterRequest, 0x00, sizeof(deregisterRequest));

    ret = request.HasMember("args");
    if ( ret != (int)true )
    {
        DBG_Log("args error");
        return -1;
    }
    ret = request["args"].IsObject();
    if ( ret != (int)true )
    {
        DBG_Log("args error");
        return -1;
    }
    const Value& args = request["args"].GetObjectA();

    ret = args.HasMember("appID");
    if ( ret != (int)true )
    {
        DBG_Log("appID error");
        return -1;
    }
    ret = args["appID"].IsString();
    if ( ret != (int)true )
    {
        DBG_Log("appID error");
        return -1;
    }
    int appIDLen = (int)strlen(args["appID"].GetString());
    deregisterRequest.appID = new unsigned char[appIDLen+1]{0,};
    memcpy((char*)deregisterRequest.appID, args["appID"].GetString(), appIDLen);

    ret = args.HasMember("keyID");
    if ( ret != (int)true )
    {
        DBG_Log("keyID error");
        return -1;
    }
    ret = args["keyID"].IsString();
    if ( ret != (int)true )
    {
        DBG_Log("keyID error");
        return -1;
    }

    int keyIDLen = (int)strlen(args["keyID"].GetString());
    deregisterRequest.keyID = new unsigned char[keyIDLen+1]{0,};
    memcpy((char*)deregisterRequest.keyID, args["keyID"].GetString(), keyIDLen);
    DeregisterOut_t deregisterResponse;
    memset(&deregisterResponse, 0x00, sizeof(deregisterResponse));

    /* send request */
    vector<AuthenticatorProfile*>::iterator it = authenticatorList.begin();
    while (  it != authenticatorList.end() )
    {
        if ( (*it)->GetAuthenticatorIndex() == asmRequest.authenticatorIndex )
        {
            ret = (*it)->Deregister(deregisterRequest, &deregisterResponse);
            if ( ret < 0 )
            {
                DBG_Log("Deregister error 0x%04X", ret);
            }

            StringBuffer jsonStringBuffer;
            Writer<StringBuffer> writer(jsonStringBuffer);
            writer.StartObject();
            writer.Key("statusCode");
            writer.Int(ret);
            writer.EndObject();

            asmJSONData_t jsonData;
            jsonData.length = (int)strlen(jsonStringBuffer.GetString())+1;
            jsonData.pData = new char[jsonData.length]{0};
            memcpy(jsonData.pData, jsonStringBuffer.GetString(), jsonData.length-1);
            if ( GetCallbackListener() != NULL )
            {
                GetCallbackListener()->Callback(jsonData, jsonData);
            }
            delete[] jsonData.pData;
            jsonData.pData = NULL;
        }
        it++;
    }

    return 0;
}

int AuthenticatorManager::getRegistration(Document& request)
{
    int ret = -1;
    ASMRequest_t asmRequest;

    /* asmRequest Setting */
    memset(&asmRequest, 0x00, sizeof(asmRequest));

    /* asmRequest Setting - 1. requestType */
    asmRequest.requestType = ASMType::GetRegistrations;

    /* asmRequest Setting - 2. version */
    Version_t version;
    memset(&version, 0x00, sizeof(version));

    ret = request.HasMember("asmVersion");
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    ret = request["asmVersion"].IsObject();
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    const Value& asmVersion = request["asmVersion"].GetObjectA();

    ret = asmVersion.HasMember("major");
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    ret = asmVersion["major"].IsInt();
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    version.major = asmVersion["major"].GetInt();

    ret = asmVersion.HasMember("minor");
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    ret = asmVersion["minor"].IsInt();
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    version.minor = asmVersion["minor"].GetInt();
    asmRequest.asmVersion = version;

    /* asmRequest Setting - 3. exts*/
    asmRequest.exts = NULL;

    /* asmRequest Setting - 4. authenticatorIndex */
    ret = request.HasMember("authenticatorIndex");
    if ( ret != (int)true )
    {
        DBG_Log("authenticatorIndex error");
        return -1;
    }
    ret = request["authenticatorIndex"].IsInt();
    if ( ret != (int)true )
    {
        DBG_Log("authenticatorIndex error");
        return -1;
    }
    asmRequest.authenticatorIndex = request["authenticatorIndex"].GetInt();

    /* asmRequest Setting - 5. args */
    asmRequest.args = NULL;

    /* send request */
    vector<AuthenticatorProfile*>::iterator it = authenticatorList.begin();
    while (  it != authenticatorList.end() )
    {
		GetRegistrationsOut_t getRegistrationsResponse;
        if ( (*it)->GetAuthenticatorIndex() == asmRequest.authenticatorIndex )
        {
            ret = (*it)->GetRegistrations(asmRequest, &getRegistrationsResponse);
            if ( ret < 0 )
            {
                DBG_Log("GetRegistrations error 0x%04X", ret);
            }

            StringBuffer jsonStringBuffer;
            Writer<StringBuffer> writer(jsonStringBuffer);

            writer.StartObject();
            writer.Key("responseData");
            writer.StartObject();
            if ( ret == UAF_ASM_STATUS_OK )
            {
                if ( getRegistrationsResponse.appRegsCount != -1 )
                {
                    char jsonTagBuffer[256];
                    int valueLen = -1;
					for ( int i = 0; (i <= getRegistrationsResponse.appRegsCount); i++ )
					{
                        memset(jsonTagBuffer, 0x00, sizeof(jsonTagBuffer));
                        sprintf(jsonTagBuffer, "userName%04d", i);
                        valueLen = (int)strlen((char*)getRegistrationsResponse.appRegs[i].userName);
                        if ( valueLen < 0 )
                        {
                            DBG_Log("%s is too small(0x%08X)", jsonTagBuffer, valueLen);
                            valueLen = 0;
                        }
                        writer.Key(StringRef(jsonTagBuffer, strlen(jsonTagBuffer)));
                        writer.String((char*)getRegistrationsResponse.appRegs[i].userName, valueLen);

                        memset(jsonTagBuffer, 0x00, sizeof(jsonTagBuffer));
                        sprintf(jsonTagBuffer, "keyID%04d", i);
                        valueLen = (int)strlen((char*)getRegistrationsResponse.appRegs[i].keyID[0]);
                        if ( valueLen < 0 )
                        {
                            DBG_Log("%s is too small(0x%08X)", jsonTagBuffer, valueLen);
                            valueLen = 0;
                        }
                        writer.Key(StringRef(jsonTagBuffer, strlen(jsonTagBuffer)));
                        writer.String((char*)getRegistrationsResponse.appRegs[i].keyID[0], valueLen);
                    }
                }
                else
                {
                    DBG_Log("User name and key handle is Empty");
                }
            }
            writer.EndObject();
            writer.Key("statusCode");
            writer.Int(ret);
            writer.EndObject();

            asmJSONData_t jsonData;
            jsonData.length = (int)strlen(jsonStringBuffer.GetString())+1;
            jsonData.pData = new char[jsonData.length]{0};
            memcpy(jsonData.pData, jsonStringBuffer.GetString(), jsonData.length-1);
            if ( GetCallbackListener() != NULL )
            {
                GetCallbackListener()->Callback(jsonData, jsonData);
            }
            delete[] jsonData.pData;
            jsonData.pData = NULL;
        }
        it++;
    }

    return 0;
}

int AuthenticatorManager::fpEnroll(Document& request)
{
    int ret = -1;
    ASMRequest_t asmRequest;

    /* asmRequest Setting */
    memset(&asmRequest, 0x00, sizeof(asmRequest));

    /* asmRequest Setting - 1. requestType */
    asmRequest.requestType = ASMType::FPEnroll;

    /* asmRequest Setting - 2. version */
    Version_t version;
    memset(&version, 0x00, sizeof(version));

    ret = request.HasMember("asmVersion");
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    ret = request["asmVersion"].IsObject();
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    const Value& asmVersion = request["asmVersion"].GetObjectA();

    ret = asmVersion.HasMember("major");
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    ret = asmVersion["major"].IsInt();
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    version.major = asmVersion["major"].GetInt();

    ret = asmVersion.HasMember("minor");
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    ret = asmVersion["minor"].IsInt();
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    version.minor = asmVersion["minor"].GetInt();
    asmRequest.asmVersion = version;

    /* asmRequest Setting - 3. exts*/
    asmRequest.exts = NULL;

    /* asmRequest Setting - 4. authenticatorIndex */
    ret = request.HasMember("authenticatorIndex");
    if ( ret != (int)true )
    {
        DBG_Log("authenticatorIndex error");
        return -1;
    }
    ret = request["authenticatorIndex"].IsInt();
    if ( ret != (int)true )
    {
        DBG_Log("authenticatorIndex error");
        return -1;
    }
    asmRequest.authenticatorIndex = request["authenticatorIndex"].GetInt();

    /* asmRequest Setting - 5. args(fpIndexAndName) */
    FPIndexAndName_t fpIndexAndName;
    memset(&fpIndexAndName, 0x00, sizeof(fpIndexAndName));

    ret = request.HasMember("fingerPrintIndex");
    if ( ret != (int)true )
    {
        DBG_Log("fingerPrintIndex error");
        return -1;
    }
    ret = request["fingerPrintIndex"].IsInt();
    if ( ret != (int)true )
    {
        DBG_Log("fingerPrintIndex error");
        return -1;
    }
    fpIndexAndName.index = request["fingerPrintIndex"].GetInt();
    if ( fpIndexAndName.index >= FINGER_INDEX_MAX )
    {
        DBG_Log("invalid finger print index");
        return -1;
    }

    ret = request.HasMember("fingerPrintName");
    if ( ret != (int)true )
    {
        DBG_Log("invalid finger print name");
        return -1;
    }
    ret = request["fingerPrintName"].IsString();
    if ( ret != (int)true )
    {
        DBG_Log("finger print name is not a string");
        return -1;
    }
    unsigned int fpNameLength = request["fingerPrintName"].GetStringLength();
    if ( fpNameLength > 0 )
        strcpy(fpIndexAndName.name, request["fingerPrintName"].GetString());

    asmRequest.args = (void*)&fpIndexAndName;

    ASMResponse_t asmResponse;
    memset(&asmResponse, 0x00, sizeof(asmResponse));

    /* send request */
    vector<AuthenticatorProfile*>::iterator it = authenticatorList.begin();
    while (  it != authenticatorList.end() )
    {
        if ( (*it)->GetAuthenticatorIndex() == asmRequest.authenticatorIndex )
        {
            ret = (*it)->SetPlaceFingerCB(this);
            if ( ret < 0 )
            {
                DBG_Log("SetPlaceFingerCB error 0x%04X", ret);
            }
            ret = (*it)->Enroll(asmRequest, &asmResponse);
            if ( ret < 0 )
            {
                DBG_Log("Enroll error 0x%04X", ret);
            }

            unsigned short responseType = (unsigned short)-1;
            if ( asmResponse.responseData != NULL )
            {
                responseType = *((unsigned short*)asmResponse.responseData);
				delete (unsigned short*)asmResponse.responseData;
            }

            StringBuffer jsonStringBuffer;
            Writer<StringBuffer> writer(jsonStringBuffer);
            writer.StartObject();
            if ( responseType != -1 )
            {
                writer.Key("responseType");
                writer.Int(responseType);
            }
            writer.Key("statusCode");
            writer.Int(asmResponse.statusCode);
            writer.EndObject();

            asmJSONData_t jsonData;
            jsonData.length = (int)strlen(jsonStringBuffer.GetString())+1;
            jsonData.pData = new char[jsonData.length]{0};
            memcpy(jsonData.pData, jsonStringBuffer.GetString(), jsonData.length-1);
            if ( GetCallbackListener() != NULL )
            {
                GetCallbackListener()->Callback(jsonData, jsonData);
            }
            delete[] jsonData.pData;
            jsonData.pData = NULL;
        }
        it++;
    }

    return 0;
}

int AuthenticatorManager::fpVerify(Document& request)
{
    int ret = -1;
    ASMRequest_t asmRequest;

    /* asmRequest Setting */
    memset(&asmRequest, 0x00, sizeof(asmRequest));

    /* asmRequest Setting - 1. requestType */
    asmRequest.requestType = ASMType::FPVerify;

    /* asmRequest Setting - 2. version */
    Version_t version;
    memset(&version, 0x00, sizeof(version));

    ret = request.HasMember("asmVersion");
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    ret = request["asmVersion"].IsObject();
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    const Value& asmVersion = request["asmVersion"].GetObjectA();

    ret = asmVersion.HasMember("major");
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    ret = asmVersion["major"].IsInt();
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    version.major = asmVersion["major"].GetInt();

    ret = asmVersion.HasMember("minor");
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    ret = asmVersion["minor"].IsInt();
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    version.minor = asmVersion["minor"].GetInt();
    asmRequest.asmVersion = version;

    /* asmRequest Setting - 3. exts*/
    asmRequest.exts = NULL;

    /* asmRequest Setting - 4. authenticatorIndex */
    ret = request.HasMember("authenticatorIndex");
    if ( ret != (int)true )
    {
        DBG_Log("authenticatorIndex error");
        return -1;
    }
    ret = request["authenticatorIndex"].IsInt();
    if ( ret != (int)true )
    {
        DBG_Log("authenticatorIndex error");
        return -1;
    }
    asmRequest.authenticatorIndex = request["authenticatorIndex"].GetInt();

    ASMResponse_t asmResponse;
    memset(&asmResponse, 0x00, sizeof(asmResponse));

    /* send request */
    vector<AuthenticatorProfile*>::iterator it = authenticatorList.begin();
    while (  it != authenticatorList.end() )
    {
        if ( (*it)->GetAuthenticatorIndex() == asmRequest.authenticatorIndex )
        {
            ret = (*it)->SetPlaceFingerCB(this);
            if ( ret < 0 )
            {
                DBG_Log("SetPlaceFingerCB error 0x%04X", ret);
            }
            ret = (*it)->Verify(asmRequest, &asmResponse);
            if ( ret < 0 )
            {
                DBG_Log("Enroll error 0x%04X", ret);
            }
            ret = (*it)->SetPlaceFingerCB(NULL);
            if ( ret < 0 )
            {
                DBG_Log("SetPlaceFingerCB error 0x%04X", ret);
            }

            unsigned short responseType = -1;
            if ( asmResponse.responseData != NULL )
            {
                responseType = *((unsigned short*)asmResponse.responseData);
				delete (unsigned short*)asmResponse.responseData;
            }

            StringBuffer jsonStringBuffer;
            Writer<StringBuffer> writer(jsonStringBuffer);
            writer.StartObject();
            if ( responseType != -1 )
            {
                writer.Key("responseType");
                writer.Int(responseType);
            }
            writer.Key("statusCode");
            writer.Int(asmResponse.statusCode);
            writer.EndObject();

            asmJSONData_t jsonData;
            jsonData.length = (int)strlen(jsonStringBuffer.GetString())+1;
            jsonData.pData = new char[jsonData.length]{0};
            memcpy(jsonData.pData, jsonStringBuffer.GetString(), jsonData.length);
            if ( GetCallbackListener() != NULL )
            {
                GetCallbackListener()->Callback(jsonData, jsonData);
            }
            delete[] jsonData.pData;
            jsonData.pData = NULL;
        }
        it++;
    }

    return 0;
}

int AuthenticatorManager::fpEnrollCheck(Document& request)
{
    int ret = -1;
    ASMRequest_t asmRequest;

    /* asmRequest Setting */
    memset(&asmRequest, 0x00, sizeof(asmRequest));

    /* asmRequest Setting - 1. requestType */
    asmRequest.requestType = ASMType::FPEnrollCheck;

    /* asmRequest Setting - 2. version */
    Version_t version;
    memset(&version, 0x00, sizeof(version));

    ret = request.HasMember("asmVersion");
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    ret = request["asmVersion"].IsObject();
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    const Value& asmVersion = request["asmVersion"].GetObjectA();

    ret = asmVersion.HasMember("major");
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    ret = asmVersion["major"].IsInt();
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    version.major = asmVersion["major"].GetInt();

    ret = asmVersion.HasMember("minor");
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    ret = asmVersion["minor"].IsInt();
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    version.minor = asmVersion["minor"].GetInt();
    asmRequest.asmVersion = version;

    /* asmRequest Setting - 3. exts*/
    asmRequest.exts = NULL;

    /* asmRequest Setting - 4. authenticatorIndex */
    ret = request.HasMember("authenticatorIndex");
    if ( ret != (int)true )
    {
        DBG_Log("authenticatorIndex error");
        return -1;
    }
    ret = request["authenticatorIndex"].IsInt();
    if ( ret != (int)true )
    {
        DBG_Log("authenticatorIndex error");
        return -1;
    }
    asmRequest.authenticatorIndex = request["authenticatorIndex"].GetInt();

    /* asmRequest Setting - 5. args(fingerPrintIndex) */
    ret = request.HasMember("fingerPrintIndex");
    if ( ret != (int)true )
    {
        DBG_Log("fingerPrintIndex error");
        return -1;
    }
    ret = request["fingerPrintIndex"].IsInt();
    if ( ret != (int)true )
    {
        DBG_Log("fingerPrintIndex error");
        return -1;
    }
    unsigned short fingerPrintIndex = request["fingerPrintIndex"].GetInt();
    if ( fingerPrintIndex >= FINGER_INDEX_MAX )
    {
        DBG_Log("invalid finger print index");
        return -1;
    }
    asmRequest.args = (void*)&fingerPrintIndex;

    ASMResponse_t asmResponse;
    memset(&asmResponse, 0x00, sizeof(asmResponse));

    /* send request */
    vector<AuthenticatorProfile*>::iterator it = authenticatorList.begin();
    while (  it != authenticatorList.end() )
    {
        if ( (*it)->GetAuthenticatorIndex() == asmRequest.authenticatorIndex )
        {
            ret = (*it)->EnrollCheck(asmRequest, &asmResponse);
            if ( ret < 0 )
            {
                DBG_Log("Enroll error 0x%04X", ret);
            }

            unsigned short responseType = -1;
            if ( asmResponse.responseData != NULL )
            {
                responseType = *((unsigned short*)asmResponse.responseData);
				delete (unsigned short*)asmResponse.responseData;
            }

            StringBuffer jsonStringBuffer;
            Writer<StringBuffer> writer(jsonStringBuffer);
            writer.StartObject();
            if ( responseType != -1 )
            {
                writer.Key("responseType");
                writer.Int(responseType);
            }
            writer.Key("statusCode");
            writer.Int(asmResponse.statusCode);
            writer.EndObject();

            asmJSONData_t jsonData;
            jsonData.length = (int)strlen(jsonStringBuffer.GetString())+1;
            jsonData.pData = new char[jsonData.length]{0};
            memcpy(jsonData.pData, jsonStringBuffer.GetString(), jsonData.length-1);
            if ( GetCallbackListener() != NULL )
            {
                GetCallbackListener()->Callback(jsonData, jsonData);
            }
            delete[] jsonData.pData;
            jsonData.pData = NULL;
        }
        it++;
    }

    return 0;
}

int AuthenticatorManager::fpRemove(Document& request)
{
    int ret = -1;
    ASMRequest_t asmRequest;

    /* asmRequest Setting */
    memset(&asmRequest, 0x00, sizeof(asmRequest));

    /* asmRequest Setting - 1. requestType */
    asmRequest.requestType = ASMType::FPRemove;

    /* asmRequest Setting - 2. version */
    Version_t version;
    memset(&version, 0x00, sizeof(version));

    ret = request.HasMember("asmVersion");
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    ret = request["asmVersion"].IsObject();
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    const Value& asmVersion = request["asmVersion"].GetObjectA();

    ret = asmVersion.HasMember("major");
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    ret = asmVersion["major"].IsInt();
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    version.major = asmVersion["major"].GetInt();

    ret = asmVersion.HasMember("minor");
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    ret = asmVersion["minor"].IsInt();
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    version.minor = asmVersion["minor"].GetInt();
    asmRequest.asmVersion = version;

    /* asmRequest Setting - 3. exts*/
    asmRequest.exts = NULL;

    /* asmRequest Setting - 4. authenticatorIndex */
    ret = request.HasMember("authenticatorIndex");
    if ( ret != (int)true )
    {
        DBG_Log("authenticatorIndex error");
        return -1;
    }
    ret = request["authenticatorIndex"].IsInt();
    if ( ret != (int)true )
    {
        DBG_Log("authenticatorIndex error");
        return -1;
    }
    asmRequest.authenticatorIndex = request["authenticatorIndex"].GetInt();

    /* asmRequest Setting - 5. args(fingerPrintIndex) */
    ret = request.HasMember("fingerPrintIndex");
    if ( ret != (int)true )
    {
        DBG_Log("fingerPrintIndex error");
        return -1;
    }
    ret = request["fingerPrintIndex"].IsInt();
    if ( ret != (int)true )
    {
        DBG_Log("fingerPrintIndex error");
        return -1;
    }
    unsigned short fingerPrintIndex = request["fingerPrintIndex"].GetInt();
    if ( fingerPrintIndex >= FINGER_INDEX_MAX )
    {
        DBG_Log("invalid finger print index");
        return -1;
    }
    asmRequest.args = (void*)&fingerPrintIndex;

    ASMResponse_t asmResponse;
    memset(&asmResponse, 0x00, sizeof(asmResponse));

    /* send request */
    vector<AuthenticatorProfile*>::iterator it = authenticatorList.begin();
    while (  it != authenticatorList.end() )
    {
        if ( (*it)->GetAuthenticatorIndex() == asmRequest.authenticatorIndex )
        {
            ret = (*it)->RemoveEnroll(asmRequest, &asmResponse);
            if ( ret < 0 )
            {
                DBG_Log("Enroll error 0x%04X", ret);
            }

            unsigned short responseType = -1;
            if ( asmResponse.responseData != NULL )
            {
                responseType = *((unsigned short*)asmResponse.responseData);
				delete (unsigned short*)asmResponse.responseData;
            }

            StringBuffer jsonStringBuffer;
            Writer<StringBuffer> writer(jsonStringBuffer);
            writer.StartObject();
            if ( responseType != -1 )
            {
                writer.Key("responseType");
                writer.Int(responseType);
            }
            writer.Key("statusCode");
            writer.Int(asmResponse.statusCode);
            writer.EndObject();

            asmJSONData_t jsonData;
            jsonData.length = (int)strlen(jsonStringBuffer.GetString())+1;
            jsonData.pData = new char[jsonData.length]{0};
            memcpy(jsonData.pData, jsonStringBuffer.GetString(), jsonData.length-1);
            if ( GetCallbackListener() != NULL )
            {
                GetCallbackListener()->Callback(jsonData, jsonData);
            }
            delete[] jsonData.pData;
            jsonData.pData = NULL;
        }
        it++;
    }

    return 0;
}

int AuthenticatorManager::fpGetList(Document& request)
{
    int ret = -1;
    ASMRequest_t asmRequest;

    /* asmRequest Setting */
    memset(&asmRequest, 0x00, sizeof(asmRequest));

    /* asmRequest Setting - 1. requestType */
    asmRequest.requestType = ASMType::FPRemove;

    /* asmRequest Setting - 2. version */
    Version_t version;
    memset(&version, 0x00, sizeof(version));

    ret = request.HasMember("asmVersion");
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    ret = request["asmVersion"].IsObject();
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    const Value& asmVersion = request["asmVersion"].GetObjectA();

    ret = asmVersion.HasMember("major");
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    ret = asmVersion["major"].IsInt();
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    version.major = asmVersion["major"].GetInt();

    ret = asmVersion.HasMember("minor");
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    ret = asmVersion["minor"].IsInt();
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    version.minor = asmVersion["minor"].GetInt();
    asmRequest.asmVersion = version;

    /* asmRequest Setting - 3. exts*/
    asmRequest.exts = NULL;

    /* asmRequest Setting - 4. authenticatorIndex */
    ret = request.HasMember("authenticatorIndex");
    if ( ret != (int)true )
    {
        DBG_Log("authenticatorIndex error");
        return -1;
    }
    ret = request["authenticatorIndex"].IsInt();
    if ( ret != (int)true )
    {
        DBG_Log("authenticatorIndex error");
        return -1;
    }
    asmRequest.authenticatorIndex = request["authenticatorIndex"].GetInt();

    FPGetListOut_t response;
    memset(&response, 0x00, sizeof(response));

    /* send request */
    vector<AuthenticatorProfile*>::iterator it = authenticatorList.begin();
    while (  it != authenticatorList.end() )
    {
        if ( (*it)->GetAuthenticatorIndex() == asmRequest.authenticatorIndex )
        {
            ret = (*it)->GetFPList(asmRequest, &response);
            if ( ret < 0 )
            {
                DBG_Log("Get FP List error 0x%04X", ret);
            }

            StringBuffer jsonStringBuffer;
            Writer<StringBuffer> writer(jsonStringBuffer);
            writer.StartObject();
            writer.Key("responseType");
            writer.Int(response.responseType);
            writer.Key("statusCode");
            writer.Int(TAG_FP_RSP_GET_ENROLL_LIST);
            char jsonTag[128] = {0,};
            for ( int i = 0; i < response.fpCount; i++ )
            {
                sprintf(jsonTag, "Index%04d", response.fpIndexAndNameHandle[i].index);
                writer.Key(jsonTag);
                writer.String(response.fpIndexAndNameHandle[i].name);
            }
            writer.EndObject();

            asmJSONData_t jsonData;
            jsonData.length = (int)strlen(jsonStringBuffer.GetString())+1;
            jsonData.pData = new char[jsonData.length]{0};
            memcpy(jsonData.pData, jsonStringBuffer.GetString(), jsonData.length-1);
            if ( GetCallbackListener() != NULL )
            {
                GetCallbackListener()->Callback(jsonData, jsonData);
            }
            delete[] jsonData.pData;
            jsonData.pData = NULL;
        }
        it++;
    }

    return 0;
}

int AuthenticatorManager::fpGetImage(Document& request)
{
    int ret = -1;
    ASMRequest_t asmRequest;

    /* asmRequest Setting */
    memset(&asmRequest, 0x00, sizeof(asmRequest));

    /* asmRequest Setting - 1. requestType */
    asmRequest.requestType = ASMType::FPGetImage;

    /* asmRequest Setting - 2. version */
    Version_t version;
    memset(&version, 0x00, sizeof(version));

    ret = request.HasMember("asmVersion");
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    ret = request["asmVersion"].IsObject();
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    const Value& asmVersion = request["asmVersion"].GetObjectA();

    ret = asmVersion.HasMember("major");
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    ret = asmVersion["major"].IsInt();
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    version.major = asmVersion["major"].GetInt();

    ret = asmVersion.HasMember("minor");
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    ret = asmVersion["minor"].IsInt();
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    version.minor = asmVersion["minor"].GetInt();
    asmRequest.asmVersion = version;

    /* asmRequest Setting - 3. exts*/
    asmRequest.exts = NULL;

    /* asmRequest Setting - 4. authenticatorIndex */
    ret = request.HasMember("authenticatorIndex");
    if ( ret != (int)true )
    {
        DBG_Log("authenticatorIndex error");
        return -1;
    }
    ret = request["authenticatorIndex"].IsInt();
    if ( ret != (int)true )
    {
        DBG_Log("authenticatorIndex error");
        return -1;
    }
    asmRequest.authenticatorIndex = request["authenticatorIndex"].GetInt();

    FPGetImageOut_t response;
    memset(&response, 0x00, sizeof(response));

    /* send request */
    vector<AuthenticatorProfile*>::iterator it = authenticatorList.begin();
    while ( it != authenticatorList.end() )
    {
        if ( (*it)->GetAuthenticatorIndex() == asmRequest.authenticatorIndex )
        {
            ret = (*it)->SetPlaceFingerCB(this);
            if ( ret < 0 )
            {
                DBG_Log("SetPlaceFingerCB error 0x%04X", ret);
            }
            ret = (*it)->GetFPImage(asmRequest, &response);
            if ( ret < 0 )
            {
                DBG_Log("Save error 0x%04X", ret);
            }

            StringBuffer jsonStringBuffer;
            Writer<StringBuffer> writer(jsonStringBuffer);
            writer.StartObject();
            writer.Key("responseType");
            writer.Int(response.responseType);
            if ( response.responseType == UAF_ASM_STATUS_OK )
            {
                writer.Key("raw");
                writer.String(response.raw);
                writer.Key("bmp");
                writer.String(response.bmp);
            }
            writer.Key("statusCode");
            writer.Int(response.statusCode);
            writer.EndObject();

            asmJSONData_t jsonData;
            jsonData.length = (int)strlen(jsonStringBuffer.GetString())+1;
            jsonData.pData = new char[jsonData.length]{0};
            strcpy(jsonData.pData, jsonStringBuffer.GetString());
            if ( GetCallbackListener() != NULL )
            {
                GetCallbackListener()->Callback(jsonData, jsonData);
            }
            delete[] jsonData.pData;
            jsonData.pData = NULL;
        }
        it++;
    }

    return 0;
}
int TestIndex;
int AuthenticatorManager::fpTestImage(Document& request)
{
	FingerInfo_t Fingerinfo;
	memset(&Fingerinfo, 0x00, sizeof(Fingerinfo));

	/*while (Fingerinfo.enrollCount == FP_ENROLL_MAX - 1)
	{*/
	int ret = -1;
	ASMRequest_t asmRequest;

	/* asmRequest Setting */
	memset(&asmRequest, 0x00, sizeof(asmRequest));

	/* asmRequest Setting - 1. requestType */
	asmRequest.requestType = ASMType::FPTestImage;

	/* asmRequest Setting - 2. version */
	Version_t version;
	memset(&version, 0x00, sizeof(version));

	ret = request.HasMember("asmVersion");
	if (ret != (int)true)
	{
		DBG_Log("asmVersion error");
		return -1;
	}
	ret = request["asmVersion"].IsObject();
	if (ret != (int)true)
	{
		DBG_Log("asmVersion error");
		return -1;
	}
	const Value& asmVersion = request["asmVersion"].GetObjectA();

	ret = asmVersion.HasMember("major");
	if (ret != (int)true)
	{
		DBG_Log("asmVersion error");
		return -1;
	}
	ret = asmVersion["major"].IsInt();
	if (ret != (int)true)
	{
		DBG_Log("asmVersion error");
		return -1;
	}
	version.major = asmVersion["major"].GetInt();

	ret = asmVersion.HasMember("minor");
	if (ret != (int)true)
	{
		DBG_Log("asmVersion error");
		return -1;
	}
	ret = asmVersion["minor"].IsInt();
	if (ret != (int)true)
	{
		DBG_Log("asmVersion error");
		return -1;
	}
	version.minor = asmVersion["minor"].GetInt();
	asmRequest.asmVersion = version;

	/* asmRequest Setting - 3. exts*/
	asmRequest.exts = NULL;

	/* asmRequest Setting - 4. authenticatorIndex */
	ret = request.HasMember("authenticatorIndex");
	if (ret != (int)true)
	{
		DBG_Log("authenticatorIndex error");
		return -1;
	}
	ret = request["authenticatorIndex"].IsInt();
	if (ret != (int)true)
	{
		DBG_Log("authenticatorIndex error");
		return -1;
	}
	asmRequest.authenticatorIndex = request["authenticatorIndex"].GetInt();



	/* asmRequest Setting - 5. FingerInfo */



	ret = request.HasMember("FingerInformation");
	if (ret != (int)true)
	{
		DBG_Log("asmVersion error");
		return -1;
	}
	ret = request["FingerInformation"].IsObject();
	if (ret != (int)true)
	{
		DBG_Log("asmVersion error");
		return -1;
	}
	const Value& Fingerinformation = request["FingerInformation"].GetObjectA();

	ret = Fingerinformation.HasMember("testUserid");
	if (ret != (int)true)
	{
		DBG_Log("asmVersion error");
		return -1;
	}

	Fingerinfo.testUserid = Fingerinformation["testUserid"].GetInt();

	ret = Fingerinformation.HasMember("handIndex");
	if (ret != (int)true)
	{
		DBG_Log("asmVersion error");
		return -1;
	}

	ret = Fingerinformation["handIndex"].IsInt();
	if (ret != (int)true)
	{
		DBG_Log("asmVersion error");
		return Failure;
	}

	Fingerinfo.handIndex = Fingerinformation["handIndex"].GetInt();

	ret = Fingerinformation.HasMember("handCount");
	if (ret != (int)true)
	{
		DBG_Log("asmVersion error");
		return -1;
	}

	Fingerinfo.handCount = Fingerinformation["handCount"].GetInt();

	ret = Fingerinformation.HasMember("EnrollCount");
	if (ret != (int)true)
	{
		DBG_Log("asmVersion error");
		return -1;
	}

	Fingerinfo.enrollCount = Fingerinformation["EnrollCount"].GetInt();

	//ret = Fingerinformation.HasMember("angleIndex");
	//if (ret != (int)true)
	//{
	//	DBG_Log("asmVersion error");
	//	return -1;
	//}
	//ret = Fingerinformation["angleIndex"].IsObject();
	//if (ret != (int)true)
	//{
	//	DBG_Log("asmVersion error");
	//	return -1;
	//}
	//char* angleIndex = new char[(strlen((char*)request["angleIndex"].GetString()) + 1)]{ 0, };
	//if (angleIndex == NULL)
	//{
	//	DBG_Log("new error");
	//	return Failure;
	//}
	//sprintf(angleIndex, "%s", (char*)request["angleIndex"].GetString());
	//Fingerinfo.angleIndex = (unsigned char)angleIndex;


	FPTestImageOut_t response;
	memset(&response, 0x00, sizeof(FPTestImageOut_t));

	
		/* send request */
		vector<AuthenticatorProfile*>::iterator it = authenticatorList.begin();
		/*while (it != authenticatorList.end())
		{*/
			while (Fingerinfo.enrollCount < FP_ENROLL_MAX)
			{
				if ((*it)->GetAuthenticatorIndex() == asmRequest.authenticatorIndex)
				{
					ret = (*it)->SetPlaceFingerCB(this);
					if (ret < 0)
					{
						DBG_Log("SetPlaceFingerCB error 0x%04X", ret);
					}
					ret = (*it)->TestFPImage(Fingerinfo, &response);
					if (ret < 0)
					{
						DBG_Log("Save error 0x%04X", ret);
					}

					StringBuffer jsonStringBuffer;
					Writer<StringBuffer> writer(jsonStringBuffer);
					writer.StartObject();
					writer.Key("responseType");
					writer.Int(response.responseType);
					if (response.responseType == UAF_ASM_STATUS_OK)
					{
						writer.Key("raw");
						writer.String(response.raw);
						writer.Key("bmp");
						writer.String(response.bmp);
						writer.Key("count");
						writer.String(response.count);
						writer.Key("operation");
						writer.String(response.operation);
					}
					writer.Key("statusCode");
					writer.Int(response.statusCode);
					writer.EndObject();

					asmJSONData_t jsonData;
					jsonData.length = (int)strlen(jsonStringBuffer.GetString()) + 1;
					jsonData.pData = new char[jsonData.length]{ 0 };
					strcpy(jsonData.pData, jsonStringBuffer.GetString());
					if (GetCallbackListener() != NULL)
					{
						GetCallbackListener()->Callback(jsonData, jsonData);
					}
					delete[] jsonData.pData;
					jsonData.pData = NULL;
					
					TestIndex = atoi(response.count);
					DBG_Log("TestIndex: %d", TestIndex);
					if (TestIndex == FP_ENROLL_MAX - 1)
					{
						break;
					}
				}
				/*if (Fingerinfo.enrollCount == FP_ENROLL_MAX-1)
				{
					return 0;
				}*/
				Fingerinfo.enrollCount++;
				
			}
		/*	it++;
		}*/
		return 0;
	}

int AuthenticatorManager::VerifyFPImage(Document& request)
{
	int ret = -1;
	ASMRequest_t asmRequest;

	/* asmRequest Setting */
	memset(&asmRequest, 0x00, sizeof(asmRequest));

	/* asmRequest Setting - 1. requestType */
	asmRequest.requestType = ASMType::FPVerifyImage;

	/* asmRequest Setting - 2. version */
	Version_t version;
	memset(&version, 0x00, sizeof(version));

	ret = request.HasMember("asmVersion");
	if (ret != (int)true)
	{
		DBG_Log("asmVersion error");
		return -1;
	}
	ret = request["asmVersion"].IsObject();
	if (ret != (int)true)
	{
		DBG_Log("asmVersion error");
		return -1;
	}
	const Value& asmVersion = request["asmVersion"].GetObjectA();

	ret = asmVersion.HasMember("major");
	if (ret != (int)true)
	{
		DBG_Log("asmVersion error");
		return -1;
	}
	ret = asmVersion["major"].IsInt();
	if (ret != (int)true)
	{
		DBG_Log("asmVersion error");
		return -1;
	}
	version.major = asmVersion["major"].GetInt();

	ret = asmVersion.HasMember("minor");
	if (ret != (int)true)
	{
		DBG_Log("asmVersion error");
		return -1;
	}
	ret = asmVersion["minor"].IsInt();
	if (ret != (int)true)
	{
		DBG_Log("asmVersion error");
		return -1;
	}
	version.minor = asmVersion["minor"].GetInt();
	asmRequest.asmVersion = version;

	/* asmRequest Setting - 3. exts*/
	asmRequest.exts = NULL;

	/* asmRequest Setting - 4. authenticatorIndex */
	ret = request.HasMember("authenticatorIndex");
	if (ret != (int)true)
	{
		DBG_Log("authenticatorIndex error");
		return -1;
	}
	ret = request["authenticatorIndex"].IsInt();
	if (ret != (int)true)
	{
		DBG_Log("authenticatorIndex error");
		return -1;
	}
	asmRequest.authenticatorIndex = request["authenticatorIndex"].GetInt();



	/* asmRequest Setting - 5. FingerInfo */
	FingerInfo_t Fingerinfo;

	memset(&Fingerinfo, 0x00, sizeof(Fingerinfo));

	ret = request.HasMember("FingerInformation");
	if (ret != (int)true)
	{
		DBG_Log("asmVersion error");
		return -1;
	}
	ret = request["FingerInformation"].IsObject();
	if (ret != (int)true)
	{
		DBG_Log("asmVersion error");
		return -1;
	}
	const Value& Fingerinformation = request["FingerInformation"].GetObjectA();

	ret = Fingerinformation.HasMember("testUserid");
	if (ret != (int)true)
	{
		DBG_Log("asmVersion error");
		return -1;
	}

	Fingerinfo.testUserid = Fingerinformation["testUserid"].GetInt();

	ret = Fingerinformation.HasMember("handIndex");
	if (ret != (int)true)
	{
		DBG_Log("asmVersion error");
		return -1;
	}

	ret = Fingerinformation["handIndex"].IsInt();
	if (ret != (int)true)
	{
		DBG_Log("asmVersion error");
		return Failure;
	}

	Fingerinfo.handIndex = Fingerinformation["handIndex"].GetInt();

	ret = Fingerinformation.HasMember("handCount");
	if (ret != (int)true)
	{
		DBG_Log("asmVersion error");
		return -1;
	}

	Fingerinfo.handCount = Fingerinformation["handCount"].GetInt();

	ret = Fingerinformation.HasMember("angleIndex");
	if (ret != (int)true)
	{
		DBG_Log("asmVersion error");
		return -1;
	}

	Fingerinfo.angle = Fingerinformation["angleIndex"].GetInt();

	ret = Fingerinformation.HasMember("EnrollCount");
	if (ret != (int)true)
	{
		DBG_Log("asmVersion error");
		return -1;
	}

	Fingerinfo.enrollCount = Fingerinformation["EnrollCount"].GetInt();

	//ret = Fingerinformation.HasMember("angleIndex");
	//if (ret != (int)true)
	//{
	//	DBG_Log("asmVersion error");
	//	return -1;
	//}
	//ret = Fingerinformation["angleIndex"].IsObject();
	//if (ret != (int)true)
	//{
	//	DBG_Log("asmVersion error");
	//	return -1;
	//}
	//char* angleIndex = new char[(strlen((char*)request["angleIndex"].GetString()) + 1)]{ 0, };
	//if (angleIndex == NULL)
	//{
	//	DBG_Log("new error");
	//	return Failure;
	//}
	//sprintf(angleIndex, "%s", (char*)request["angleIndex"].GetString());
	//Fingerinfo.angleIndex = (unsigned char)angleIndex;


	FPTestImageOut_t response;
	memset(&response, 0x00, sizeof(response));

	/* send request */
	vector<AuthenticatorProfile*>::iterator it = authenticatorList.begin();
	/*while (it != authenticatorList.end())
	{*/
	while (1)
	{
		memset(&response, 0x00, sizeof(response));
		if ((*it)->GetAuthenticatorIndex() == asmRequest.authenticatorIndex)
		{
			ret = (*it)->SetPlaceFingerCB(this);
			if (ret < 0)
			{
				DBG_Log("SetPlaceFingerCB error 0x%04X", ret);
			}
			ret = (*it)->VerifyFPImage(Fingerinfo, &response);
			if (ret < 0)
			{
				DBG_Log("Save error 0x%04X", ret);
			}

			StringBuffer jsonStringBuffer;
			Writer<StringBuffer> writer(jsonStringBuffer);
			writer.StartObject();
			writer.Key("responseType");
			writer.Int(response.responseType);
			if (response.responseType == UAF_ASM_STATUS_OK)
			{
				writer.Key("raw");
				writer.String(response.raw);
				writer.Key("bmp");
				writer.String(response.bmp);
				writer.Key("count");
				writer.String(response.count);
				writer.Key("operation");
				writer.String(response.operation);
			}
			writer.Key("statusCode");
			writer.Int(response.statusCode);
			writer.EndObject();

			asmJSONData_t jsonData;
			jsonData.length = (int)strlen(jsonStringBuffer.GetString()) + 1;
			jsonData.pData = new char[jsonData.length]{ 0 };
			strcpy(jsonData.pData, jsonStringBuffer.GetString());
			if (GetCallbackListener() != NULL)
			{
				GetCallbackListener()->Callback(jsonData, jsonData);
			}
			delete[] jsonData.pData;
			jsonData.pData = NULL;

			TestIndex = atoi(response.count);
			DBG_Log("TestIndex: %d", TestIndex);
			if (TestIndex == 9 || TestIndex == 19 || TestIndex == 29)
			{
				break;
			}
		}
		Fingerinfo.enrollCount++;
	}
		//it++;
	//}

	return 0;
}

int AuthenticatorManager::utilFWUpdate(Document& request)
{
    int ret = -1;
    ASMRequest_t asmRequest;

    /* asmRequest Setting */
    memset(&asmRequest, 0x00, sizeof(asmRequest));

    /* asmRequest Setting - 1. requestType */
    asmRequest.requestType = ASMType::FWUpdate;

    /* asmRequest Setting - 2. authenticatorIndex */
    ret = request.HasMember("authenticatorIndex");
    if ( ret != (int)true )
    {
        DBG_Log("authenticatorIndex error");
        return -1;
    }
    ret = request["authenticatorIndex"].IsInt();
    if ( ret != (int)true )
    {
        DBG_Log("authenticatorIndex error");
        return -1;
    }
    asmRequest.authenticatorIndex = request["authenticatorIndex"].GetInt();


    FirmwareUpdateIn_t firmwareUpdateRequest;
    memset(&firmwareUpdateRequest, 0x00, sizeof(FirmwareUpdateIn_t));

    /* firmwareUpdateRequest Setting - 1. fileName */
    ret = request.HasMember("fileName");
    if ( ret != (int)true )
    {
        DBG_Log("fileName error");
        return -1;
    }
    ret = request["fileName"].IsString();
    if ( ret != (int)true )
    {
        DBG_Log("fileName error");
        return -1;
    }

    int fileNameLength = request["fileName"].GetStringLength();
    firmwareUpdateRequest.fileName = new unsigned char[fileNameLength+1]{0,};
    if ( firmwareUpdateRequest.fileName == NULL )
    {
        DBG_Log("memory error");
        return -1;
    }
    memcpy(firmwareUpdateRequest.fileName, request["fileName"].GetString(), fileNameLength);

    FirmwareUpdateOut_t response;
    memset(&response, 0x00, sizeof(FirmwareUpdateOut_t));

    /* send request */
    vector<AuthenticatorProfile*>::iterator it = authenticatorList.begin();
    while (  it != authenticatorList.end() )
    {
        if ( (*it)->GetAuthenticatorIndex() == asmRequest.authenticatorIndex )
        {
            ret = (*it)->SetFWUpdateCB(this);
            if ( ret < 0 )
            {
                DBG_Log("SetPlaceFingerCB error 0x%04X", ret);
            }

            ret = (*it)->FimrwareUpdate(firmwareUpdateRequest, &response);
            if ( ret < 0 )
            {
                DBG_Log("FimrwareUpdate error 0x%04X", ret);
            }

            UtilCallback(&response);

            ret = (*it)->SetFWUpdateCB(NULL);
            if ( ret < 0 )
            {
                DBG_Log("SetPlaceFingerCB error 0x%04X", ret);
            }
        }
        it++;
    }

    if ( firmwareUpdateRequest.fileName != NULL )
    {
        delete[] firmwareUpdateRequest.fileName;
        firmwareUpdateRequest.fileName = NULL;
    }

    return 0;
}


int AuthenticatorManager::utilGetDeviceID(Document& request)
{
    int ret = -1;
    ASMRequest_t asmRequest;

    /* asmRequest Setting */
    memset(&asmRequest, 0x00, sizeof(asmRequest));

    /* asmRequest Setting - 1. requestType */
    asmRequest.requestType = ASMType::GetDeviceID;

    /* asmRequest Setting - 2. version */
    Version_t version;
    memset(&version, 0x00, sizeof(version));

    ret = request.HasMember("asmVersion");
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    ret = request["asmVersion"].IsObject();
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    const Value& asmVersion = request["asmVersion"].GetObjectA();

    ret = asmVersion.HasMember("major");
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    ret = asmVersion["major"].IsInt();
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    version.major = asmVersion["major"].GetInt();

    ret = asmVersion.HasMember("minor");
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    ret = asmVersion["minor"].IsInt();
    if ( ret != (int)true )
    {
        DBG_Log("asmVersion error");
        return -1;
    }
    version.minor = asmVersion["minor"].GetInt();
    asmRequest.asmVersion = version;

    /* asmRequest Setting - 3. exts*/
    asmRequest.exts = NULL;

    /* asmRequest Setting - 4. authenticatorIndex */
    ret = request.HasMember("authenticatorIndex");
    if ( ret != (int)true )
    {
        DBG_Log("authenticatorIndex error");
        return -1;
    }
    ret = request["authenticatorIndex"].IsInt();
    if ( ret != (int)true )
    {
        DBG_Log("authenticatorIndex error");
        return -1;
    }
    asmRequest.authenticatorIndex = request["authenticatorIndex"].GetInt();

    /* asmRequest Setting - 5. args(fingerPrintIndex) */
    asmRequest.args = NULL;

    GetDeviceIDOut_t getDIDResponse;
    memset(&getDIDResponse, 0x00, sizeof(getDIDResponse));

    /* send request */
    vector<AuthenticatorProfile*>::iterator it = authenticatorList.begin();
    while (  it != authenticatorList.end() )
    {
        if ( (*it)->GetAuthenticatorIndex() == asmRequest.authenticatorIndex )
        {
            ret = (*it)->GetDeviceID(asmRequest, &getDIDResponse);
            if ( ret < 0 )
            {
                DBG_Log("GetDeviceID error 0x%04X", ret);
            }

            StringBuffer jsonStringBuffer;
            Writer<StringBuffer> writer(jsonStringBuffer);
            writer.StartObject();
            writer.Key("responseData");
            writer.StartObject();
            writer.Key("responseType");
            writer.Int(getDIDResponse.responseType);
            if ( getDIDResponse.statusCode == FIDO_UTIL_STATUS_COMPLETE )
            {
                char deviceID[(sizeof(getDIDResponse.deviceID)*2)+3] = {0,};
				sprintf(&deviceID[0], "0x%08X", *((unsigned int*)&getDIDResponse.deviceID[4]));
				sprintf(&deviceID[10],  "%08X", *((unsigned int*)&getDIDResponse.deviceID[0]));
                writer.Key("deviceID");
                writer.String((char*)deviceID);
            }
            writer.EndObject();
            writer.Key("statusCode");
            writer.Int(getDIDResponse.statusCode);
            writer.EndObject();

            asmJSONData_t jsonData;
            jsonData.length = (int)strlen(jsonStringBuffer.GetString())+1;
            jsonData.pData = new char[jsonData.length]{0};
            memcpy(jsonData.pData, jsonStringBuffer.GetString(), jsonData.length-1);
            if ( GetCallbackListener() != NULL )
            {
                GetCallbackListener()->Callback(jsonData, jsonData);
            }
            delete[] jsonData.pData;
            jsonData.pData = NULL;
        }
        it++;
    }

    return 0;
}


int AuthenticatorManager::utilSDBInit(Document& request)
{
	int ret = -1;
	ASMRequest_t asmRequest;

	/* asmRequest Setting */
	memset(&asmRequest, 0x00, sizeof(asmRequest));

	/* asmRequest Setting - 1. requestType */
	asmRequest.requestType = ASMType::SDBInit;

	/* asmRequest Setting - 2. version */
	Version_t version;
	memset(&version, 0x00, sizeof(version));

	ret = request.HasMember("asmVersion");
	if (ret != (int)true)
	{
		DBG_Log("asmVersion error");
		return -1;
	}
	ret = request["asmVersion"].IsObject();
	if (ret != (int)true)
	{
		DBG_Log("asmVersion error");
		return -1;
	}
	const Value& asmVersion = request["asmVersion"].GetObjectA();

	ret = asmVersion.HasMember("major");
	if (ret != (int)true)
	{
		DBG_Log("asmVersion error");
		return -1;
	}
	ret = asmVersion["major"].IsInt();
	if (ret != (int)true)
	{
		DBG_Log("asmVersion error");
		return -1;
	}
	version.major = asmVersion["major"].GetInt();

	ret = asmVersion.HasMember("minor");
	if (ret != (int)true)
	{
		DBG_Log("asmVersion error");
		return -1;
	}
	ret = asmVersion["minor"].IsInt();
	if (ret != (int)true)
	{
		DBG_Log("asmVersion error");
		return -1;
	}
	version.minor = asmVersion["minor"].GetInt();
	asmRequest.asmVersion = version;

	/* asmRequest Setting - 3. exts*/
	asmRequest.exts = NULL;

	/* asmRequest Setting - 4. authenticatorIndex */
	ret = request.HasMember("authenticatorIndex");
	if (ret != (int)true)
	{
		DBG_Log("authenticatorIndex error");
		return -1;
	}
	ret = request["authenticatorIndex"].IsInt();
	if (ret != (int)true)
	{
		DBG_Log("authenticatorIndex error");
		return -1;
	}
	asmRequest.authenticatorIndex = request["authenticatorIndex"].GetInt();

	/* asmRequest Setting - 5. args(fingerPrintIndex) */
	asmRequest.args = NULL;

	ASMResponse_t asmResponse;
	memset(&asmResponse, 0x00, sizeof(asmResponse));

	/* send request */
	vector<AuthenticatorProfile*>::iterator it = authenticatorList.begin();
	while (it != authenticatorList.end())
	{
		if ((*it)->GetAuthenticatorIndex() == asmRequest.authenticatorIndex)
		{
			ret = (*it)->SDBInit(asmRequest, &asmResponse);
			if (ret < 0)
			{
				DBG_Log("SDBInit error 0x%04X", ret);
			}

			StringBuffer jsonStringBuffer;
			Writer<StringBuffer> writer(jsonStringBuffer);
			writer.StartObject();
			writer.Key("responseData");
			writer.StartObject();
			writer.Key("responseType");
			writer.Int((unsigned short)FIDO_UTIL_RSP_TAG_RM_DATA_BASE);
			writer.EndObject();
			writer.Key("statusCode");
			writer.Int(asmResponse.statusCode);
			writer.EndObject();

			asmJSONData_t jsonData;
			jsonData.length = (int)strlen(jsonStringBuffer.GetString()) + 1;
			jsonData.pData = new char[jsonData.length]{ 0 };
			memcpy(jsonData.pData, jsonStringBuffer.GetString(), jsonData.length - 1);
			if (GetCallbackListener() != NULL)
			{
				GetCallbackListener()->Callback(jsonData, jsonData);
			}
			delete[] jsonData.pData;
			jsonData.pData = NULL;
		}
		it++;
	}
	return 0;
}

int AuthenticatorManager::utilFIDOInit(Document& request)
{
	int ret = -1;
	ASMRequest_t asmRequest;

	/* asmRequest Setting */
	memset(&asmRequest, 0x00, sizeof(asmRequest));

	/* asmRequest Setting - 1. requestType */
	asmRequest.requestType = ASMType::GetDeviceID;

	/* asmRequest Setting - 2. version */
	Version_t version;
	memset(&version, 0x00, sizeof(version));

	ret = request.HasMember("asmVersion");
	if (ret != (int)true)
	{
		DBG_Log("asmVersion error");
		return -1;
	}
	ret = request["asmVersion"].IsObject();
	if (ret != (int)true)
	{
		DBG_Log("asmVersion error");
		return -1;
	}
	const Value& asmVersion = request["asmVersion"].GetObjectA();

	ret = asmVersion.HasMember("major");
	if (ret != (int)true)
	{
		DBG_Log("asmVersion error");
		return -1;
	}
	ret = asmVersion["major"].IsInt();
	if (ret != (int)true)
	{
		DBG_Log("asmVersion error");
		return -1;
	}
	version.major = asmVersion["major"].GetInt();

	ret = asmVersion.HasMember("minor");
	if (ret != (int)true)
	{
		DBG_Log("asmVersion error");
		return -1;
	}
	ret = asmVersion["minor"].IsInt();
	if (ret != (int)true)
	{
		DBG_Log("asmVersion error");
		return -1;
	}
	version.minor = asmVersion["minor"].GetInt();
	asmRequest.asmVersion = version;

	/* asmRequest Setting - 3. exts*/
	asmRequest.exts = NULL;

	/* asmRequest Setting - 4. authenticatorIndex */
	ret = request.HasMember("authenticatorIndex");
	if (ret != (int)true)
	{
		DBG_Log("authenticatorIndex error");
		return -1;
	}
	ret = request["authenticatorIndex"].IsInt();
	if (ret != (int)true)
	{
		DBG_Log("authenticatorIndex error");
		return -1;
	}
	asmRequest.authenticatorIndex = request["authenticatorIndex"].GetInt();

	/* asmRequest Setting - 5. args(fingerPrintIndex) */
	asmRequest.args = NULL;

	ASMResponse_t asmResponse;
	memset(&asmResponse, 0x00, sizeof(asmResponse));

	/* send request */
	vector<AuthenticatorProfile*>::iterator it = authenticatorList.begin();
	while (it != authenticatorList.end())
	{
		if ((*it)->GetAuthenticatorIndex() == asmRequest.authenticatorIndex)
		{
			ret = (*it)->FIDOInit(asmRequest, &asmResponse);
			if (ret < 0)
			{
				DBG_Log("FIDOInit error 0x%04X", ret);
			}

			StringBuffer jsonStringBuffer;
			Writer<StringBuffer> writer(jsonStringBuffer);
			writer.StartObject();
			writer.Key("responseData");
			writer.StartObject();
			writer.Key("responseType");
			writer.Int((unsigned short)FIDO_UTIL_RSP_TAG_INITIALIZE);
			writer.EndObject();
			writer.Key("statusCode");
			writer.Int(asmResponse.statusCode);
			writer.EndObject();

			asmJSONData_t jsonData;
			jsonData.length = (int)strlen(jsonStringBuffer.GetString()) + 1;
			jsonData.pData = new char[jsonData.length]{ 0 };
			memcpy(jsonData.pData, jsonStringBuffer.GetString(), jsonData.length - 1);
			if (GetCallbackListener() != NULL)
			{
				GetCallbackListener()->Callback(jsonData, jsonData);
			}
			delete[] jsonData.pData;
			jsonData.pData = NULL;
		}
		it++;
	}
	return 0;
}
