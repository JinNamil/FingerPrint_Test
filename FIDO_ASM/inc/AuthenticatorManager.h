#ifndef __AUTHENTICATORMANAGER_H__
#define __AUTHENTICATORMANAGER_H__

#include "AuthenticatorProfile.h"

#include "rapidjson/document.h"

#include <vector>

using rapidjson::Document;
using std::vector;

class AuthenticatorManager : public IeWBMCallback
{
    public:
        AuthenticatorManager();
        virtual ~AuthenticatorManager();

        unsigned int UpdateList(asmEnumerationType_t eventType);

        int ASMProcess(const asmJSONData_t *pInData);

        ASM::ICallback* GetCallbackListener(void);
        void SetCallbackListener(ASM::ICallback* pListener);
        ASM::IEnumerator* GetEnumeratorListener(void);
        void SetEnumeratorListener(ASM::IEnumerator* pEnumerationListener);

        virtual int FPCallback(void* param);
		virtual int FPTESTCallback(TESTASMResponse_t* param);
        virtual int UtilCallback(void* param);

    private:
        int plugDevice(const char* in);
        int unplugReady(void);
        int unplugDevice(void);
        int isDeviceStatus(const char* in, asmEnumerationType_t eventType);
        void notify(const char* deviceName, asmEnumerationType_t eventType);

        int getInfo(Document& request);
        int registration(Document& request);
        int authenticate(Document& request);
        int deregister(Document& request);
        int getRegistration(Document& request);

        int fpEnroll(Document& request);
        int fpVerify(Document& request);
        int fpRemove(Document& request);
        int fpEnrollCheck(Document& request);
        int fpGetList(Document& request);
        int fpGetImage(Document& request);
		int fpTestImage(Document& request);
		int VerifyFPImage(Document& request);

        int utilFWUpdate(Document& request);
        int utilGetDeviceID(Document& request);
		int utilSDBInit(Document& request);
		int utilFIDOInit(Document& request);

        ASM::ICallback* callbackListener = NULL;
        ASM::IEnumerator* enumeratorListener = NULL;

        vector<AuthenticatorProfile*> authenticatorList;
};

#endif // __AUTHENTICATORMANAGER_H__
