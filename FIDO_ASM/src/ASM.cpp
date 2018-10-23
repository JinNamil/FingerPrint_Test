#include "ASM.h"
#include "AuthenticatorManager.h"
#include <cstdio>

#include "Debug.h"

using namespace ASM;

AuthenticatorManager* authenticatorManager = NULL;

void PluggedThread(void* param)
{
    if ( authenticatorManager != NULL )
    {
        authenticatorManager->UpdateList(Plugged);
    }
}

void UnpluggedThread(void* param)
{
    if ( authenticatorManager != NULL )
    {
        authenticatorManager->UpdateList(Unplugged);
    }
}

ASM_FUNC asmResult_t asmInit(ASM::IEnumerator *pEnumerationListener)
{
    DBG_Log("start");

    if ( pEnumerationListener == NULL )
    {
        return Failure;
    }

    if ( authenticatorManager != NULL )
    {
        return Failure;
    }
    authenticatorManager = new AuthenticatorManager();
    if ( authenticatorManager == NULL )
    {
        return Failure;
    }

    authenticatorManager->SetEnumeratorListener(pEnumerationListener);
    authenticatorManager->UpdateList(Plugged);

    return Success;
}

ASM_FUNC asmResult_t asmProcess(const asmJSONData_t *pInData, ASM::ICallback *pListener)
{
    int ret = -1;

    DBG_Log("start");

    if ( authenticatorManager == NULL )
    {
        return Failure;
    }

    if ( pListener != NULL )
    {
        authenticatorManager->SetCallbackListener(pListener);
    }

    DBG_Log("JSON string: %s", pInData->pData);

    ret = authenticatorManager->ASMProcess(pInData);
    if ( ret < 0 )
    {
        DBG_Log("ASMProcess Fail");
        return Failure;
    }

    return Success;
}

ASM_FUNC asmResult_t asmUninit(void)
{
    DBG_Log("start");
    if ( authenticatorManager == NULL )
    {
        return Failure;
    }

    delete authenticatorManager;
    authenticatorManager = NULL;

    return Success;
}
