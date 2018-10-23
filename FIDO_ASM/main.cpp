#include <cstdio>
#include <process.h>
#include "Debug.h"

#include <windows.h>
#include <dbt.h>

#ifdef BUILD_DLL
#define DLL_EXPORT __declspec(dllexport)
#else
#define DLL_EXPORT __declspec(dllimport)
#endif

#ifdef __cplusplus
#define DLL_FUNC extern "C" DLL_EXPORT
#else
#define DLL_FUNC DLL_EXPORT
#endif

extern void PluggedThread(void* param);
extern void UnpluggedThread(void* param);

static WNDPROC originProc;
LRESULT CALLBACK WndProc(HWND hwnd, unsigned int msg, WPARAM wParam, LPARAM lParam)
{
    switch ( msg )
    {
        case WM_DEVICECHANGE:
            {
                switch ( wParam )
                {
                    case DBT_DEVICEARRIVAL:
                        {
                            _beginthread(&PluggedThread, 0, NULL);
                        }
                        break;

                    case DBT_DEVICEREMOVECOMPLETE:
                        {
                            _beginthread(&UnpluggedThread, 0, NULL);
                        }
                        break;

                    default:
                        {
                        }
                        break;
                }
            }
            break;
    }
    return CallWindowProc(originProc, hwnd, msg, wParam, lParam);
}

static HWND hWnd = NULL;
static HWND GetWinHandle(void)
{
    ULONG pid = GetCurrentProcessId();
    for ( HWND tempHwnd = FindWindow(NULL,NULL); tempHwnd != NULL; tempHwnd = GetWindow(tempHwnd, GW_HWNDNEXT) )
    {
        if ( GetParent(tempHwnd) == NULL )
        {
            ULONG procID = 0;
            GetWindowThreadProcessId(tempHwnd, &procID);
            if ( pid == procID )
            {
                return tempHwnd;
            }
        }
    }
    return NULL;
}

BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
#ifdef __DEBUG__
    unsigned int err = 0;
#endif
    switch ( fdwReason )
    {
        case DLL_PROCESS_ATTACH:
            {
                if ( hWnd == NULL )
                {
                    hWnd = GetWinHandle();
                    if ( (hWnd != INVALID_HANDLE_VALUE) && (hWnd != NULL) )
                    {
                        originProc = (WNDPROC)SetWindowLong(hWnd, GWLP_WNDPROC, (LONG)WndProc);
                        if ( originProc == 0 )
                        {
#ifdef __DEBUG__
                            err = GetLastError();
                            DBG_Log("SetWindowLong Fail: 0x%08X", err);
#endif
                        }
                    }
                }
            }
            break;

        case DLL_PROCESS_DETACH:
            {
                if ( hWnd != NULL )
                {
                    SetWindowLong(hWnd, GWLP_WNDPROC, (LONG)originProc);
                    hWnd = NULL;
                }
            }
            break;

        default:
            {
            }
            break;
    }

    return TRUE;
}
