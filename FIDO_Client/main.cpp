#include "resource.h"
#include <cstdio>
#include <string>
#include <ctime>
#include <tchar.h>
#include <process.h>
#include <windows.h>
#include <Commdlg.h>
#include <commctrl.h>

#include "ASM.h"
#include "Debug.h"

#include "rapidjson/document.h"

//#define REGISTRY_ENABLE

using std::string;

using namespace ASMType;

using rapidjson::Document;
using rapidjson::Value;

int gLastRequest = -1;

void sendRequest(void*);
void sendJSONMessage(void*);

HWND  gHwnd = NULL;
HWND  gHwnd2 = NULL;
HHOOK gKeyboardHook;

int	startIndex;
int EnableWindowIndex;
int a;
int AutoClick = 0;
int CountInt;
char TestCount[10]{ 0, };
int Operation = 0;
int EnrollCount = 0;
int i = 0;

void AutoBtnClick(int count)
{
	if (count == 1)
	{
		SendMessage(GetDlgItem(gHwnd, ID_FPT_ENROLL_1), BM_CLICK, 0, 0);
	}
	count = 0;
}

void AddLog(char* logMessage)
{
    if ( gHwnd == NULL )
    {
        return;
    }

    char logHeader[128] = {0,};
    char logFooter[128] = {0,};

    time_t rawtime;
    struct tm* timeinfo;
    time(&rawtime);
    timeinfo = localtime(&rawtime);

    strftime(logHeader, sizeof(logHeader), "[LOG %H:%M:%S] ", timeinfo);
    sprintf(logFooter, "\r\n");

    int bufferSize = (int)strlen(logHeader)+strlen(logMessage)+strlen(logFooter)+1;
    char *logBuffer = new char[bufferSize];
    if ( logBuffer == NULL )
    {
        DBG_Log("Memory Error");
        return;
    }
    sprintf(logBuffer, "%s%s%s", logHeader, logMessage, logFooter);

    int textLength = (int)SendMessage(GetDlgItem(gHwnd, ID_LOG), WM_GETTEXTLENGTH, 0, 0);
    if ( (bufferSize + textLength) >= 64000 )
    {
        SetWindowText(GetDlgItem(gHwnd, ID_LOG), "");
        textLength = (int)SendMessage(GetDlgItem(gHwnd, ID_LOG), WM_GETTEXTLENGTH, 0, 0);
    }
    SendMessage(GetDlgItem(gHwnd, ID_LOG), EM_SETSEL, textLength, textLength);
    SendMessage(GetDlgItem(gHwnd, ID_LOG), EM_REPLACESEL, (WPARAM)0, (LPARAM)logBuffer);

    if ( logBuffer != NULL )
    {
        delete[] logBuffer;
        logBuffer = NULL;
    }
}

#define IMAGE_FILE_PATH_MAX    (1024)

class FIDOCallback : public ASM::ICallback
{
    public:
        virtual void Callback(const asmJSONData_t &response, asmJSONData_t &exchangeData)
        {
            int ret = -1;

            DBG_Log("%s", response.pData);
            SendMessage(GetDlgItem(gHwnd, ID_UAF_RESPONSE), WM_SETTEXT, 0, (LPARAM)response.pData);

            Document document;
            ret = document.Parse(response.pData).HasParseError();
            if ( ret != false )
            {
                DBG_Log("JSON Parse Error");
                SendMessage(GetDlgItem(gHwnd, ID_UAF_RESPONSE), WM_SETTEXT, 0, (LPARAM)response.pData);
                return;
            }

            ret = document.HasMember("statusCode");
            if ( ret != (int)true )
            {
                DBG_Log("statusCode error");
                return;
            }
            ret = document["statusCode"].IsUint();
            if ( ret != (int)true )
            {
                DBG_Log("statusCode error");
                return;
            }
            unsigned short status = document["statusCode"].GetUint();

            ret = document.HasMember("responseType");
            if ( ret == (int)true )
            {
                ret = document["responseType"].IsUint();
                if ( ret == (int)true )
                {
                    if ( gLastRequest == FWUpdate )
                    {
                        unsigned int progress = document["progress"].GetUint();

                        char log[128] = {0,};
                        sprintf(log, "progress: %d%%", progress);
                        DBG_Log("%s", log);

                        //AddLog(log);

                        if ( progress >= 100 )
                        {
                            AddLog((char*)"Update Done");
                        }

                        SendMessage(GetDlgItem(gHwnd, ID_FIRMWARE_PROGRESSBAR), PBM_SETPOS, progress, 0);

                        return;
                    }
                    else
                    {
                        int lastRequest = gLastRequest;

                        unsigned short responseType = document["responseType"].GetUint();

                        unsigned short fpTotal = 0;
                        ret = document.HasMember("total");
                        if ( ret == (int)true )
                        {
                            ret = document["total"].IsUint();
                            if ( ret == (int)true )
                            {
                                fpTotal = document["total"].GetUint();
                            }
                        }

                        unsigned short fpCount = 0;
                        ret = document.HasMember("count");
                        if ( ret == (int)true )
                        {
                            ret = document["count"].IsUint();
                            if ( ret == (int)true )
                            {
                                fpCount = document["count"].GetUint();
                            }
                        }

                        switch ( status )
                        {
                            case TAG_FP_RSP_ENROLL:
                                {
                                    DBG_Log("FP Response - enroll");
                                    gLastRequest = FPEnroll;
                                }
                                break;

                            case TAG_FP_RSP_VERIFY:
                                {
                                    DBG_Log("FP Response - verify");
                                    gLastRequest = FPVerify;
                                }
                                break;

                            case TAG_FP_RSP_IS_ENROLL:
                                {
                                    DBG_Log("FP Response - is_enroll");
                                    gLastRequest = FPEnrollCheck;
                                }
                                break;

                            case TAG_FP_RSP_RM_ENROLL:
                                {
                                    DBG_Log("FP Response - rm_enroll");
                                    gLastRequest = FPRemove;
                                }
                                break;

                            case TAG_FP_RSP_GET_ENROLL_LIST:
                                {
                                    DBG_Log("FP Response - get Enroll List");

                                    SendMessage(GetDlgItem(gHwnd, ID_FP_LIST), CB_RESETCONTENT, 0, 0);

                                    char jsonMemberKey[512] = {0,};
                                    int  fpIndex = 0;
                                    while ( 1 )
                                    {
                                        sprintf(jsonMemberKey, "Index%04d", fpIndex);
                                        ret = document.HasMember(jsonMemberKey);
                                        if ( ret != (int)true )
                                        {
                                            break;
                                        }
                                        ret = document[jsonMemberKey].IsString();
                                        if ( ret != (int)true )
                                        {
                                            break;
                                        }
                                        unsigned int fpNameLength = document[jsonMemberKey].GetStringLength();
                                        if ( fpNameLength == 0 )
                                        {
                                            sprintf(jsonMemberKey, "%s : Empty", jsonMemberKey);
                                        }
                                        else
                                        {
                                            sprintf(jsonMemberKey, "%s : %s", jsonMemberKey, document[jsonMemberKey].GetString());
                                        }
                                        SendMessage(GetDlgItem(gHwnd, ID_FP_LIST), CB_ADDSTRING, 0, (LPARAM)jsonMemberKey);
                                        fpIndex++;
                                    }
                                    SendMessage(GetDlgItem(gHwnd, ID_FP_LIST), CB_SETCURSEL, 0, 0);
                                    gLastRequest = FPGetList;
                                }
                                break;

								
                            case TAG_FP_RSP_GET_IMAGE:
                                {	
									EnableWindowIndex = 0;
									int   handIndexLength = (int)SendMessage(GetDlgItem(gHwnd, IDC_COMBO_HAND), WM_GETTEXTLENGTH, 0, 0);
									int   testUseridLength = (int)SendMessage(GetDlgItem(gHwnd, IDC_EDIT_USERID), WM_GETTEXTLENGTH, 0, 0);
									int   angleIndexLength = (int)SendMessage(GetDlgItem(gHwnd, IDC_COMBO_ANGLE), WM_GETTEXTLENGTH, 0, 0);
									int   handCountLength = (int)SendMessage(GetDlgItem(gHwnd, IDC_COMBO_COUNT), WM_GETTEXTLENGTH, 0, 0);
									int   verifyCountLength = (int)SendMessage(GetDlgItem(gHwnd, IDC_EDIT_COUNT), WM_GETTEXTLENGTH, 0, 0);
									int   operationLength = (int)SendMessage(GetDlgItem(gHwnd, IDC_COMBO_START), WM_GETTEXTLENGTH, 0, 0);
									int   operationNum;

									char* userCount = NULL;
									char* handCount = NULL;
									char* angleIndex = NULL;
									char* testUserid = NULL;
									char* handIndex = NULL;
									char* operationIndex = NULL;

									userCount = new char[verifyCountLength + 1]{ 0, };
									handCount = new char[handCountLength + 1]{ 0, };
									angleIndex = new char[angleIndexLength + 1]{ 0, };
									testUserid = new char[testUseridLength + 1]{ 0, };
									handIndex = new char[handIndexLength + 1]{ 0, };
									operationIndex = new char[operationLength + 1]{ 0, };

									
									
									
                                    DBG_Log("FP Response - get image");
									if (responseType == FP_STATUS_COMPLETE)
									{
										if (gLastRequest == FPGetImage || gLastRequest == FPVerifyImage || gLastRequest == FPTestImage)
										{
											if (document.HasMember("bmp") == true)
											{
												if (document["bmp"].IsString() == true)
												{
													if (document["bmp"].GetStringLength() > 0)
													{
														/* BMP File Load */
														HBITMAP hbitmap = (HBITMAP)LoadImage(NULL, document["bmp"].GetString(), IMAGE_BITMAP, 0, 0, LR_LOADFROMFILE | LR_CREATEDIBSECTION | LR_SHARED);
														if (hbitmap == INVALID_HANDLE_VALUE)
														{
															DBG_Log("BMP File Not Exist\n");
															break;
														}

														/* SendMessage to Print */
														HDC hdc = CreateCompatibleDC(GetDC(gHwnd));
														if (hdc == INVALID_HANDLE_VALUE)
														{
#ifdef __DEBUG__
															int error = GetLastError();
															DBG_Log("Memory is NULL, 0x%08X", error);
#endif //__DEBUG__
															break;
														}

														SendMessage(GetDlgItem(gHwnd, IDC_FP_IMAGE), STM_SETIMAGE, 0, (LPARAM)hbitmap);
														SelectObject(hdc, hbitmap);
														DeleteDC(hdc);
														hdc = NULL;

														EnrollCount = atoi(document["count"].GetString());
														Operation = atoi(document["operation"].GetString());

														if (Operation == 0)
														{
															if (EnrollCount == FP_ENROLL_MAX - 1)
															{
																SetWindowText(GetDlgItem(gHwnd, IDC_EDIT_COUNT), "0");

																int currentFinger = SendMessage(GetDlgItem(gHwnd, IDC_COMBO_COUNT), CB_GETCURSEL, 0, 0);
																int currentHand = SendMessage(GetDlgItem(gHwnd, IDC_COMBO_HAND), CB_GETCURSEL, 0, 0);
																if (currentFinger == 3)
																{
																	if (currentHand == 0)
																	{
																		SendMessage(GetDlgItem(gHwnd, IDC_COMBO_COUNT), CB_SETCURSEL, 0, 0);
																		SendMessage(GetDlgItem(gHwnd, IDC_COMBO_HAND), CB_SETCURSEL, 1, 0);
																		MessageBox(gHwnd, "왼손이 완료되었습니다.\n오른손으로 넘어갑니다.\nSTART버튼을 눌러주세요.", "Hand Change", MB_OK);

																	}
																	else
																	{
																		SendMessage(GetDlgItem(gHwnd, IDC_COMBO_START), CB_SETCURSEL, Operation + 1, 0);
																		SendMessage(GetDlgItem(gHwnd, IDC_COMBO_HAND), CB_SETCURSEL, 0, 0);
																		SendMessage(GetDlgItem(gHwnd, IDC_COMBO_COUNT), CB_SETCURSEL, 0, 0);
																		SendMessage(GetDlgItem(gHwnd, IDC_COMBO_ANGLE), CB_SETCURSEL, 0, 0);
																		MessageBox(gHwnd, "Enroll Test가 완료되었습니다. Verify로 넘어갑니다.\nSTART버튼을 눌러주세요.", "Enroll Finish", MB_OK);
																		EnableWindow(gHwnd, TRUE);
																	}
																}
																else
																{
																	SendMessage(GetDlgItem(gHwnd, IDC_COMBO_COUNT), CB_SETCURSEL, currentFinger + 1, 0);
																	MessageBox(gHwnd, "다음손가락으로 넘어갑니다.\nSTART버튼을 눌러주세요.", "EnrollCount Over", MB_OK);
																}
															}
															else
															{
																char countStr[256] = { 0, };
																sprintf(countStr, "%d", EnrollCount + 1);
																SetWindowText(GetDlgItem(gHwnd, IDC_EDIT_COUNT), countStr);
															}
														}
														else
														{
															int currentAngle;
															int currentFinger;
															int currentHand;

															currentAngle = SendMessage(GetDlgItem(gHwnd, IDC_COMBO_ANGLE), CB_GETCURSEL, 0, 0);
															if (EnrollCount == 9)
															{
																currentAngle = SendMessage(GetDlgItem(gHwnd, IDC_COMBO_ANGLE), CB_GETCURSEL, 0, 0);
																if (currentAngle == 0)
																{
																	SendMessage(GetDlgItem(gHwnd, IDC_COMBO_ANGLE), CB_SETCURSEL, currentAngle + 1, 0);
																}
																MessageBox(gHwnd, "다음으로 각도로 넘어갑니다.\nSTART버튼을 눌러주세요.", "EnrollCount Over", MB_OK);
																EnableWindow(gHwnd, TRUE);
															}

															if (EnrollCount == 19)
															{
																currentAngle = SendMessage(GetDlgItem(gHwnd, IDC_COMBO_ANGLE), CB_GETCURSEL, 0, 0);
																if (currentAngle == 1)
																{
																	SendMessage(GetDlgItem(gHwnd, IDC_COMBO_ANGLE), CB_SETCURSEL, currentAngle + 1, 0);
																}

																MessageBox(gHwnd, "다음으로 각도로 넘어갑니다.\nSTART버튼을 눌러주세요.", "EnrollCount Over", MB_OK);
																EnableWindow(gHwnd, TRUE);
															}

															if (EnrollCount >= 29)
															{
																EnrollCount = 0;
																i++;
																SetWindowText(GetDlgItem(gHwnd, IDC_EDIT_COUNT), "0");
																currentAngle = SendMessage(GetDlgItem(gHwnd, IDC_COMBO_ANGLE), CB_GETCURSEL, 0, 0);
																currentFinger = SendMessage(GetDlgItem(gHwnd, IDC_COMBO_COUNT), CB_GETCURSEL, 0, 0);
																currentHand = SendMessage(GetDlgItem(gHwnd, IDC_COMBO_HAND), CB_GETCURSEL, 0, 0);

																if ((currentFinger == 3))
																{
																	if (currentAngle == 2)
																	{
																		if (currentHand == 1)
																		{
																			MessageBox(gHwnd, "테스트가 완료되었습니다.", "Test Finish", MB_OK);
																			SendMessage(GetDlgItem(gHwnd, IDC_COMBO_HAND), CB_SETCURSEL, 0, 0);
																			SendMessage(GetDlgItem(gHwnd, IDC_COMBO_COUNT), CB_SETCURSEL, 0, 0);
																			SendMessage(GetDlgItem(gHwnd, IDC_COMBO_ANGLE), CB_SETCURSEL, 0, 0);
																			SendMessage(GetDlgItem(gHwnd, IDC_COMBO_START), CB_SETCURSEL, 0, 0);
																			unsigned int useridCount;
																			char* UserID = NULL;
																			int UseridLength = (int)SendMessage(GetDlgItem(gHwnd, IDC_EDIT_USERID), WM_GETTEXTLENGTH, 0, 0);
																			UserID = new char[UseridLength + 1]{ 0, };
																			SendMessage(GetDlgItem(gHwnd, IDC_EDIT_USERID), WM_GETTEXT, (WPARAM)(UseridLength + 1), (LPARAM)UserID);
																			useridCount = atoi(UserID);
																			useridCount++;
																			UserID = new char[UseridLength + 1]{ 0, };
																			_itoa(useridCount, UserID, 10);
																			SetWindowText(GetDlgItem(gHwnd, IDC_EDIT_USERID), UserID);
																			Operation = 0;
																			EnrollCount = 0;
																			EnableWindow(gHwnd, TRUE);
																			break;
																		}
																		else
																		{
																			SendMessage(GetDlgItem(gHwnd, IDC_COMBO_COUNT), CB_SETCURSEL, 0, 0);
																			SendMessage(GetDlgItem(gHwnd, IDC_COMBO_HAND), CB_SETCURSEL, 1, 0);
																			SendMessage(GetDlgItem(gHwnd, IDC_COMBO_ANGLE), CB_SETCURSEL, 0, 0);
																			MessageBox(gHwnd, "왼손이 완료되었습니다.\n오른손으로 넘어갑니다.\nSTART버튼을 눌러주세요.", "Hand Change", MB_OK);
																			EnableWindow(gHwnd, TRUE);
																			
																		}
																	}
																}
																else
																{
																	SendMessage(GetDlgItem(gHwnd, IDC_COMBO_COUNT), CB_SETCURSEL, currentFinger + 1, 0);
																	SendMessage(GetDlgItem(gHwnd, IDC_COMBO_ANGLE), CB_SETCURSEL, 0, 0);
																	MessageBox(gHwnd, "다음손가락으로 넘어갑니다.\nSTART버튼을 눌러주세요.", "EnrollCount Over", MB_OK);
																	EnableWindow(gHwnd, TRUE);
																}
															}
															else
															{
																char countStr[256] = { 0, };
																sprintf(countStr, "%d", EnrollCount + 1);
																SetWindowText(GetDlgItem(gHwnd, IDC_EDIT_COUNT), countStr);
															}
														}
															//EnableWindow(gHwnd, TRUE);
														SendMessage(GetDlgItem(gHwnd, IDC_EDIT_COUNT), WM_GETTEXT, (WPARAM)(verifyCountLength + 1), (LPARAM)userCount);
														SendMessage(GetDlgItem(gHwnd, IDC_COMBO_COUNT), WM_GETTEXT, (WPARAM)(handCountLength + 1), (LPARAM)handCount);
														SendMessage(GetDlgItem(gHwnd, IDC_COMBO_ANGLE), WM_GETTEXT, (WPARAM)(angleIndexLength + 1), (LPARAM)angleIndex);
														SendMessage(GetDlgItem(gHwnd, IDC_EDIT_USERID), WM_GETTEXT, (WPARAM)(testUseridLength + 1), (LPARAM)testUserid);
														SendMessage(GetDlgItem(gHwnd, IDC_COMBO_HAND), WM_GETTEXT, (WPARAM)(handIndexLength + 1), (LPARAM)handIndex);
														SendMessage(GetDlgItem(gHwnd, IDC_COMBO_START), WM_GETTEXT, (WPARAM)(operationLength + 1), (LPARAM)operationIndex);

														char* statictext = new char[256]{ 0, };
														int angle = atoi(angleIndex);
														if (strcmp(operationIndex, "Enroll") == 0)
														{
															sprintf(statictext, "[%s]  [%s 손가락]", handIndex, handCount);
															if (EnrollCount == FP_ENROLL_MAX - 1)
															{
																EnableWindow(gHwnd, TRUE);
															}
														}
														else
														{
															sprintf(statictext, "[%s]  [%s 손가락]  [%d 도]", handIndex, handCount, angle);
															if (EnrollCount == 9 || EnrollCount == 19 || EnrollCount == 29)
															{
																EnableWindow(gHwnd, TRUE);
															}
														}
														SetWindowText(GetDlgItem(gHwnd, IDC_STATIC_EVENT), statictext);
													}
													
												}
											}
										}
									}
                                }
                                break;

                            case TAG_FP_RSP_INVALID:
                                {
                                    DBG_Log("FP Response - invalid");
                                    gLastRequest = -1;
                                }
                                break;

                            default:
                                {
                                    DBG_Log("invalid fp/util response: 0x%04X", status);
                                    gLastRequest = -1;
                                }
                                break;
                        }
                        fpStatusPrint(responseType, fpTotal, fpCount);

                        gLastRequest = lastRequest;

                        return;
                    }
                }
            }

            char log[128] = {0,};
            sprintf(log, "Recv %s Response", asmRequest[gLastRequest]);
            AddLog(log);

            switch ( gLastRequest )
            {
                case GetInfo:
                    {
                        /* Get Authenticator Index */
                        ret = document.HasMember("responseData");
                        if ( ret != (int)true )
                        {
                            DBG_Log("responseData error");
                            return;
                        }
                        ret = document["responseData"].IsObject();
                        if ( ret != (int)true )
                        {
                            DBG_Log("responseData error");
                            return;
                        }
                        const Value& responseData = document["responseData"].GetObjectA();

                        ret = responseData.HasMember("Authenticators");
                        if ( ret != (int)true )
                        {
                            DBG_Log("Authenticators error");
                            return;
                        }
                        const Value& Authenticators = responseData["Authenticators"];
                        ret = Authenticators.IsArray();
                        if ( ret != (int)true )
                        {
                            DBG_Log("Authenticators error");
                            return;
                        }

                        ret = Authenticators[0].HasMember("authenticatorIndex");
                        if ( ret != (int)true )
                        {
                            DBG_Log("Authenticators error");
                            return;
                        }
                        ret = Authenticators[0]["authenticatorIndex"].IsInt();
                        if ( ret != (int)true )
                        {
                            DBG_Log("Authenticators error");
                            return;
                        }
                        int authenticatorIndex = Authenticators[0]["authenticatorIndex"].GetInt();
                        int authenticatorIndexDigit = 0;
                        for ( int i = 1; ((authenticatorIndex + 1) / i) > 0; i *= 10 )
                        {
                            authenticatorIndexDigit++;
                        }

                        char* authenticatorIndexBuffer = new char[authenticatorIndexDigit+1]{0,};
                        if ( authenticatorIndexBuffer == NULL )
                        {
                            DBG_Log("memory error");
                            return;
                        }
                        sprintf(authenticatorIndexBuffer, "%d", authenticatorIndex);

                        long didCount = (int)SendMessage(GetDlgItem(gHwnd, ID_DID_COMBOBOX), CB_GETCOUNT, 0, 0);
                        if ( didCount < 0 )
                        {
                            DBG_Log("CB_GETCOUNT error");
                            return;
                        }
                        else if ( didCount == 0 )
                        {
                            SendMessage(GetDlgItem(gHwnd, ID_DID_COMBOBOX), CB_ADDSTRING, 0, (LPARAM)authenticatorIndexBuffer);
                            SendMessage(GetDlgItem(gHwnd, ID_DID_COMBOBOX), CB_SETCURSEL, (WPARAM)didCount, 0);
                        }
                        else
                        {
                            int findAuthenticatorIndex = false;
                            for ( int i = 0; i < didCount; i++)
                            {
                                long authenticatorIndexOldBufferLength = (int)SendMessage(GetDlgItem(gHwnd, ID_DID_COMBOBOX), CB_GETLBTEXTLEN, (WPARAM)i, 0);
                                char* authenticatorIndexOldBuffer = new char[authenticatorIndexOldBufferLength+1]{0,};
                                if ( authenticatorIndexOldBuffer == NULL )
                                {
                                    DBG_Log("memory error");
                                    return;
                                }
                                SendMessage(GetDlgItem(gHwnd, ID_DID_COMBOBOX), CB_GETLBTEXT, (WPARAM)i, (LPARAM)authenticatorIndexOldBuffer);
                                if ( !strcmp(authenticatorIndexOldBuffer, authenticatorIndexBuffer) )
                                {
                                    SendMessage(GetDlgItem(gHwnd, ID_DID_COMBOBOX), CB_SETCURSEL, (WPARAM)i, 0);
                                    findAuthenticatorIndex = true;
                                }
                                if ( authenticatorIndexOldBuffer != NULL )
                                {
                                    delete[] authenticatorIndexOldBuffer;
                                    authenticatorIndexOldBuffer = NULL;
                                }
                                if ( findAuthenticatorIndex != false )
                                {
                                    break;
                                }

                            }
                            if ( findAuthenticatorIndex != (int)true )
                            {
                                SendMessage(GetDlgItem(gHwnd, ID_DID_COMBOBOX), CB_ADDSTRING, 0, (LPARAM)authenticatorIndexBuffer);
                                SendMessage(GetDlgItem(gHwnd, ID_DID_COMBOBOX), CB_SETCURSEL, (WPARAM)didCount, 0);
                            }
                        }

                        if ( authenticatorIndexBuffer != NULL )
                        {
                            delete[] authenticatorIndexBuffer;
                            authenticatorIndexBuffer = NULL;
                        }
                        uafStatusPrint(status);
                    }
                    break;

                case Register:
                    {
                        uafStatusPrint(status);
                    }
                    break;

                case Authenticate:
                    {
                        uafStatusPrint(status);

                        ret = document.HasMember("responseData");
                        if ( ret != (int)true )
                        {
                            DBG_Log("responseData error");
                            return;
                        }
                        ret = document["responseData"].IsObject();
                        if ( ret != (int)true )
                        {
                            DBG_Log("responseData error");
                            return;
                        }
                        const Value& responseData = document["responseData"].GetObjectA();

                        char jsonMemberKey[128] = {0,};
                        for ( int i = 0; i < 128; i++ )
                        {
                            sprintf(jsonMemberKey, "keyHandle%04d", i);
                            ret = responseData.HasMember(jsonMemberKey);
                            if ( ret != (int)true )
                            {
                                break;
                            }

                            char* keyHandle = new char[(responseData[jsonMemberKey].GetStringLength() + 1)]{0,};
                            if ( keyHandle == NULL )
                            {
                                DBG_Log("memory error");
                                return;
                            }
                            memcpy(keyHandle, responseData[jsonMemberKey].GetString(), responseData[jsonMemberKey].GetStringLength());
                            SendMessage(GetDlgItem(gHwnd, ID_UAF_KEYHANDLE), CB_ADDSTRING, 0, (LPARAM)keyHandle);
                            if ( keyHandle != NULL )
                            {
                                delete[] keyHandle;
                                keyHandle = NULL;
                            }
                        }

                        SendMessage(GetDlgItem(gHwnd, ID_UAF_KEYHANDLE), CB_SETCURSEL, 0, 0);
                    }
                    break;

                case GetRegistrations:
                    {
                        uafStatusPrint(status);
                        ret = document.HasMember("responseData");
                        if ( ret != (int)true )
                        {
                            DBG_Log("responseData error");
                            return;
                        }
                        ret = document["responseData"].IsObject();
                        if ( ret != (int)true )
                        {
                            DBG_Log("responseData error");
                            return;
                        }
                        const Value& responseData = document["responseData"].GetObjectA();


                        char jsonIdKey[256] = {0, };
                        SendMessage(GetDlgItem(gHwnd, ID_UAF_KEYID), CB_RESETCONTENT, 0, 0);
                        for(int i=0; i<256; i++)
                        {
                            sprintf(jsonIdKey, "keyID%04d", i);

                            ret = responseData.HasMember(jsonIdKey);
                            if ( ret != (int)true )
                            {
                                break;
                            }

                            char* keyID = new char[(responseData[jsonIdKey].GetStringLength() + 1)]{0,};
                            if ( keyID == NULL )
                            {
                                DBG_Log("memory error");
                                return;
                            }
                            memcpy(keyID, responseData[jsonIdKey].GetString(), responseData[jsonIdKey].GetStringLength());
                            SendMessage(GetDlgItem(gHwnd, ID_UAF_KEYID), CB_ADDSTRING, 0, (LPARAM)keyID);

                            if ( keyID != NULL )
                            {
                            delete[] keyID;
                            keyID = NULL;
                            }
                        }
                        SendMessage(GetDlgItem(gHwnd, ID_UAF_KEYID), CB_SETCURSEL, 0, 0);
                    }
                    break;

                case Deregister:
                    {
                        uafStatusPrint(status);
                    }
                    break;

                case OpenSettings:
                    {
                        uafStatusPrint(status);
                    }
                    break;

                case FWUpdate:
                case GetDeviceID:
                    {
                        ret = document.HasMember("responseData");
                        if ( ret != (int)true )
                        {
                            DBG_Log("responseData error");
                            return;
                        }
                        ret = document["responseData"].IsObject();
                        if ( ret != (int)true )
                        {
                            DBG_Log("responseData error");
                            return;
                        }
                        const Value& responseData = document["responseData"].GetObjectA();

                        char jsonDevice[256] = {0, };
                        {
                            sprintf(jsonDevice, "deviceID");

                            ret = responseData.HasMember(jsonDevice);
                            if ( ret != (int)true )
                            {
                                break;
                            }

                            char* DeviceID = new char[(responseData[jsonDevice].GetStringLength() + 1)]{0,};
                            if ( DeviceID == NULL )
                            {
                                DBG_Log("memory error");
                                return;
                            }
                            memcpy(DeviceID, responseData[jsonDevice].GetString(), responseData[jsonDevice].GetStringLength());
                            SendMessage(GetDlgItem(gHwnd, ID_DEVICE_ID), WM_SETTEXT, 0, (LPARAM)DeviceID);
                            delete[] DeviceID;
                        }
                        utilStatusPrint(status);
                    }
                    break;

                default:
                    {
                        DBG_Log("invalid request");
                    }
                    break;
            }

            return;
        }

    private:
        void uafStatusPrint(int status)
        {
            switch ( status )
            {
                case UAF_ASM_STATUS_OK:
                    {
                        DBG_Log("UAF - status_ok");
                        AddLog((char*)" - OK");
						EnableWindow(gHwnd, TRUE);
                    }
                    break;

                case UAF_ASM_STATUS_ERROR:
                    {
                        DBG_Log("UAF - status_error");
                        AddLog((char*)" - Error");
                    }
                    break;

                case UAF_ASM_STATUS_ACCESS_DENIED:
                    {
                        DBG_Log("UAF - status_access_denied");
                        AddLog((char*)" - Access Denied");
                    }
                    break;

                case UAF_ASM_STATUS_USER_CANCELLED:
                    {
                        DBG_Log("UAF - status_user_cancelled");
                        AddLog((char*)" - User Cancelled");
                    }
                    break;

                case UAF_ASM_STATUS_CANNOT_RENDER_TRANSACTION_CONTENT:
                    {
                        DBG_Log("UAF - status_cannot_render_transaction_content");
                        AddLog((char*)" - User Cannot Render Transaction Content");
                    }
                    break;

                case UAF_ASM_STATUS_KEY_DISAPPEARED_PERMANENTLY:
                    {
                        DBG_Log("UAF - status_key_disappeared_permanently");
                        AddLog((char*)" - Key Disappeared Permanently");
                    }
                    break;

                case UAF_ASM_STATUS_AUTHENTICATOR_DISCONNECTED:
                    {
                        DBG_Log("UAF - status_authenticator_disconnected");
                        AddLog((char*)" - Authenticator Disconnected");
                    }
                    break;

                case UAF_ASM_STATUS_USER_NOT_RESPONSIVE:
                    {
                        DBG_Log("UAF - status_user_not_responsive");
                        AddLog((char*)" - User Not Responsive");
                    }
                    break;

                case UAF_ASM_STATUS_INSUFFICIENT_AUTHENTICATOR_RESOURCES:
                    {
                        DBG_Log("UAF - status_insufficient_authenticator_resources");
                        AddLog((char*)" - Insufficient Authenticator Resources");
                    }
                    break;

                case UAF_ASM_STATUS_USER_LOCKOUT:
                    {
                        DBG_Log("UAF - status_user_lockout");
                        AddLog((char*)" - User Lockout");
                    }
                    break;

                case UAF_ASM_STATUS_USER_NOT_ENROLLED:
                    {
                        DBG_Log("UAF - status_user_not_enrolled");
                        AddLog((char*)" - User Not Enrolled");
                    }
                    break;

                default:
                    {
                        DBG_Log("Invalid status");
                        AddLog((char*)"Invalid status");
                    }
                    break;
            }
        }

        void fpStatusPrint(int status, int total, int count)
		{
            char fpLog[128] = {0};
            switch ( status )
            {
                case FP_STATUS_PLACE_FINGER:
                    {
                        DBG_Log("FP - place_finger");

						a = 0;
						SetWindowText(GetDlgItem(gHwnd, IDC_STATIC_EVENT2), "손가락 올려놓기");
                        if ( total > 0 )
                            sprintf(fpLog, " - Place Finger (%d/%d)", count, total);
                        else
                            sprintf(fpLog, " - Place Finger");
                        AddLog(fpLog);
                    }
                    break;
					
                case FP_CMD_FINGER_DUPLICATE:
                    {
                        DBG_Log("FP - DUPLICATE");
                        sprintf(fpLog, " - Duplicate Finger (%d/%d)", count, total);
                        AddLog(fpLog);
                    }
                    break;

                case FP_CMD_FINGER_OK:
                    {
                        DBG_Log("FP - OK");
                        sprintf(fpLog, " - Finger OK (%d/%d)", count, total);
                        AddLog(fpLog);
                    }
                    break;

                case FP_CMD_FINGER_FAIL:
                    {
                        DBG_Log("FP - FAIL");
                        sprintf(fpLog, " - Finger Fail(%d/%d)", count, total);
                        AddLog(fpLog);
						EnableWindow(gHwnd, TRUE);
                    }
                    break;

                case FP_STATUS_COMPLETE/* ( = FP_STATUS_ENROLLED ) */:
                    {
                        if ( gLastRequest == FPEnrollCheck )
                        {
                            DBG_Log("FP - enrolled");
                            AddLog((char*)" - Enrolled");
                        }
                        else
                        {
							a = 1;
							SetWindowText(GetDlgItem(gHwnd, IDC_STATIC_EVENT2), "완료");
							
                            DBG_Log("FP - complete");
                            AddLog((char*)" - Complete");
							a = 2;
							SetWindowText(GetDlgItem(gHwnd, IDC_STATIC_EVENT2), "START버튼을 눌러주세요.");
                        }
                    }
                    break;

                case FP_STATUS_FAIL/* ( = FP_STATUS_NOT_ENROLLED ) */:
                    {
                        if ( gLastRequest == FPEnrollCheck )
                        {
                            DBG_Log("FP - not_enrolled");
                            AddLog((char*)" - Not Enrolled");
                        }
                        else
                        {
                            DBG_Log("FP - fail");
                            AddLog((char*)" - Fail");
							EnableWindow(gHwnd, TRUE);
                        }
                    }
                    break;

                case FP_STATUS_ALREADY:
                    {
                        DBG_Log("FP - already");
                        AddLog((char*)" - Already Enrolled");
                    }
                    break;

                case FP_STATUS_INVALID:
                    {
                        DBG_Log("FP - invalid");
                        AddLog((char*)" - Invalid status");
                    }
                    break;

                default:
                    {
                        DBG_Log("Invalid status");
                        AddLog((char*)" - Invalid status");
                    }
                    break;
            }
        }

        void utilStatusPrint(int status)
        {
            switch ( status )
            {
                case FIDO_UTIL_STATUS_COMPLETE:
                    {
                        DBG_Log("UTIL - status_complete");
                        AddLog((char*)" - Complete");
						EnableWindow(gHwnd, TRUE);
                    }
                    break;

                case FIDO_UTIL_STATUS_FAIL:
                    {
                        DBG_Log("UTIL - status_fail");
                        AddLog((char*)" - Fail");
						EnableWindow(gHwnd, TRUE);
                    }
                    break;

                case FIDO_UTIL_STATUS_INVALID:
                    {
                        DBG_Log("UTIL - status_invalid");
                        AddLog((char*)" - Invalid status");
                    }
                    break;

                default:
                    {
                        DBG_Log("invalid status");
                        AddLog((char*)" - Invalid status");
                    }
                    break;
            }
        }
};
FIDOCallback* eWBMCallback = NULL;

class FIDOEnumerator : public ASM::IEnumerator
{
    public:
        virtual void Notify(const asmEnumerationType_t eventType, const asmJSONData_t &AuthenticatorInfo)
        {
            switch ( eventType )
            {
                case Plugged:
                    {
                        char log[256] = {0,};
                        sprintf(log, "%s Plugged", AuthenticatorInfo.pData);
                        DBG_Log("%s", log);
                        AddLog(log);
						AddLog("Connect Success");
                    }
                    break;

                case Unplugged:
                    {
                        char log[256] = {0,};
                        sprintf(log, "%s Unplugged", AuthenticatorInfo.pData);
                        DBG_Log("%s", log);
                        AddLog(log);
						MessageBox(NULL, "연결이 끊어졌습니다.", "Connect Error", MB_OK);
                    }
                    break;

                default:
                    {

                    }
                    break;
            }
        }
};
FIDOEnumerator* eWBMEnumerator = NULL;

HINSTANCE hInst;
/* library handle for ASM.dll */
HINSTANCE hInstLib = NULL;
int freeASMDLL(void)
{
    int ret = -1;

    if ( asmUninit != NULL )
    {
        ret = asmUninit();
        if ( ret != Success )
        {
            DBG_Log("asmUninit error");
            return -1;
        }
    }

    asmInit    = NULL;
    asmProcess = NULL;
    asmUninit  = NULL;

    if ( hInstLib != NULL )
    {
        hInstLib = NULL;
    }

    if ( eWBMEnumerator != NULL )
    {
        delete eWBMEnumerator;
        eWBMEnumerator = NULL;
    }

    if ( eWBMCallback != NULL )
    {
        delete eWBMCallback;
        eWBMCallback = NULL;
    }

    return 0;
}

int loadASMDll(void)
{
    int ret = -1;

    ret = freeASMDLL();
    if ( ret != 0 )
    {
        DBG_Log(" - freeASMDLL error");
        return -1;
    }

#ifdef REGISTRY_ENABLE
    /* REG open */
	HKEY hKey = NULL;
    char dllPath[512] = {0,};
    ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\FIDO\\UAF\\ASM", 0, KEY_ALL_ACCESS | KEY_WOW64_64KEY, &hKey);
    if ( ret == ERROR_SUCCESS )
    {
		DWORD  type;
		DWORD  dllPathLength = sizeof(dllPath);
        ret = RegQueryValueEx(hKey, "path", NULL, &type, (BYTE*)dllPath, &dllPathLength);
        if ( ret == ERROR_SUCCESS )
        {
            ret = GetFileAttributes(dllPath);
            if ( ret != (int)INVALID_FILE_ATTRIBUTES )
            {
                hInstLib = LoadLibrary(dllPath);
                if ( hInstLib == NULL )
                {
                    ret = GetLastError();
                    DBG_Log(" - LoadLibrary error, code: 0x%08X", ret);
                    return -1;
                }
                DBG_Log(" - Load done ( REG )");
            }
        }
    }
    else
    {
        DBG_Log(" - RegOpenKeyEx Fail(%08X)", ret);
    }

    if ( hKey != NULL )
    {
        RegCloseKey(hKey);
    }
#endif
    if ( hInstLib == NULL )
    {
        ret = SetDllDirectory("C:\\FIDO\\UAF\\ASM");
        if ( ret == 0 )
        {
            ret = GetLastError();
            DBG_Log(" - SetDllDirectory(path) error, code: 0x%08X", ret);
            return -1;
        }

        hInstLib = LoadLibrary("ASM.dll");
        if ( hInstLib == NULL )
        {
            ret = GetLastError();
            DBG_Log(" - LoadLibrary error, code: 0x%08X", ret);
            return -1;
        }

        ret = SetDllDirectory(NULL);
        if ( ret == 0 )
        {
            ret = GetLastError();
            DBG_Log(" - SetDllDirectory(NULL) error, code: 0x%08X", ret);
            return -1;
        }
        DBG_Log(" - Load done ( Local )");
    }

    asmInit = (pAsmInit)GetProcAddress(hInstLib, "asmInit");
    if ( asmInit == NULL )
    {
        ret = GetLastError();
        DBG_Log("GetProcAddress error");
        return -1;
    }
    eWBMEnumerator = new FIDOEnumerator;
    if ( eWBMEnumerator == NULL )
    {
        DBG_Log("memory error");
        return -1;
    }

    asmProcess = (pAsmProcess)GetProcAddress(hInstLib, "asmProcess");
    if ( asmProcess == NULL )
    {
        ret = GetLastError();
        DBG_Log("GetProcAddress error");
        return -1;
    }
    eWBMCallback = new FIDOCallback;
    if ( eWBMCallback == NULL )
    {
        DBG_Log("memory error");
        return -1;
    }

    asmUninit = (pAsmUninit)GetProcAddress(hInstLib, "asmUninit");
    if ( asmUninit == NULL )
    {
        ret = GetLastError();
        DBG_Log("GetProcAddress error");
        return -1;
    }

    return 0;
}

HBRUSH hBrush = NULL;

/* Client Entry */
BOOL CALLBACK DlgMain(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    int ret = FALSE;
    switch(uMsg)
    {
		case WM_CTLCOLORSTATIC:
			if (hBrush) { DeleteObject(hBrush); hBrush = NULL; }

			if (lParam == (LPARAM)GetDlgItem(gHwnd, IDC_STATIC_EVENT2) && a == 0)
			{
				if (hBrush) { DeleteObject(hBrush); hBrush = NULL; }
					SetBkColor((HDC)wParam, RGB(0, 0, 255));
					SetTextColor((HDC)wParam, RGB(255, 255, 255));
					return (BOOL)(hBrush = CreateSolidBrush(RGB(0, 0, 255)));
			}
			else if(lParam == (LPARAM)GetDlgItem(gHwnd, IDC_STATIC_EVENT2) && a == 1)
			{
				if (hBrush) { DeleteObject(hBrush); hBrush = NULL; }
				SetBkColor((HDC)wParam, RGB(0, 255, 0));
				return (BOOL)(hBrush = CreateSolidBrush(RGB(0, 255, 0)));
			}
			else if (lParam == (LPARAM)GetDlgItem(gHwnd, IDC_STATIC_EVENT2) && a == 2)
			{
				if (hBrush) { DeleteObject(hBrush); hBrush = NULL; }
				SetBkColor((HDC)wParam, RGB(0, 0, 0));
				SetTextColor((HDC)wParam, RGB(255, 255, 255));
				return (BOOL)(hBrush = CreateSolidBrush(RGB(0, 0, 0)));
			}
			
			else
				return FALSE;

        case WM_INITDIALOG:
            {
			
                DBG_Log("UI init");
                gHwnd = hwndDlg;
				
                /* init icon*/
                HICON icon;
                icon = LoadIcon(hInst, MAKEINTRESOURCE(IDI_ICON));
                if ( icon != NULL )
                {
                    SendMessage(hwndDlg, WM_SETICON, ICON_BIG, (LPARAM)icon);
                    SendMessage(hwndDlg, WM_SETICON, ICON_SMALL, (LPARAM)icon);
                }
				
				SetWindowText(GetDlgItem(hwndDlg, IDC_STATIC_EVENT), "조건창");
				a = 3;
				SetWindowText(GetDlgItem(hwndDlg, IDC_STATIC_EVENT2), "START를 눌러주세요.");
				
				/* Count init */
				SetWindowText(GetDlgItem(hwndDlg, IDC_EDIT_COUNT), "0");
				
               
				/* Left or Right */
				SendMessage(GetDlgItem(hwndDlg, IDC_COMBO_HAND), CB_ADDSTRING, 0, (LPARAM)"왼손");
				SendMessage(GetDlgItem(hwndDlg, IDC_COMBO_HAND), CB_ADDSTRING, 0, (LPARAM)"오른손");
				SendMessage(GetDlgItem(hwndDlg, IDC_COMBO_HAND), CB_SETCURSEL, 0, 0);
				

				/* ANGLE */
				SendMessage(GetDlgItem(hwndDlg, IDC_COMBO_ANGLE), CB_ADDSTRING, 0, (LPARAM)"0");
				SendMessage(GetDlgItem(hwndDlg, IDC_COMBO_ANGLE), CB_ADDSTRING, 0, (LPARAM)"45");
				SendMessage(GetDlgItem(hwndDlg, IDC_COMBO_ANGLE), CB_ADDSTRING, 0, (LPARAM)"90");
				SendMessage(GetDlgItem(hwndDlg, IDC_COMBO_ANGLE), CB_SETCURSEL, 0, 0);

				/* Hand Count */
				SendMessage(GetDlgItem(hwndDlg, IDC_COMBO_COUNT), CB_ADDSTRING, 0, (LPARAM)"엄지");
				SendMessage(GetDlgItem(hwndDlg, IDC_COMBO_COUNT), CB_ADDSTRING, 0, (LPARAM)"검지");
				SendMessage(GetDlgItem(hwndDlg, IDC_COMBO_COUNT), CB_ADDSTRING, 0, (LPARAM)"중지");
				SendMessage(GetDlgItem(hwndDlg, IDC_COMBO_COUNT), CB_ADDSTRING, 0, (LPARAM)"약지");
				SendMessage(GetDlgItem(hwndDlg, IDC_COMBO_COUNT), CB_SETCURSEL, 0, 0);
				
				/* Start Index */
				SendMessage(GetDlgItem(hwndDlg, IDC_COMBO_START), CB_ADDSTRING, 0, (LPARAM)"Enroll");
				SendMessage(GetDlgItem(hwndDlg, IDC_COMBO_START), CB_ADDSTRING, 0, (LPARAM)"Verify");
				SendMessage(GetDlgItem(hwndDlg, IDC_COMBO_START), CB_SETCURSEL, 0, 0);

                /* Request */
                SendMessage(GetDlgItem(hwndDlg, ID_UAF_REQUEST), EM_LIMITTEXT, (WPARAM)0, 0);

                /* Response */
                SendMessage(GetDlgItem(hwndDlg, ID_UAF_RESPONSE), EM_LIMITTEXT, (WPARAM)0, 0);

                /* Log Message buffer size setting*/
                SendMessage(GetDlgItem(hwndDlg, ID_LOG), EM_LIMITTEXT, (WPARAM)0, 0);


                DBG_Log("Load ASM");
                ret = loadASMDll();
                if ( ret < 0 )
                {
                    DBG_Log("loadASMDll error");
                    MessageBox(NULL, "DLL Error!!!", "Error", MB_OK);
                    exit(1);
                }

                if ( asmInit != NULL )
                {
                    ret = asmInit(eWBMEnumerator);
                    if ( ret != Success )
                    {
                        DBG_Log("asmInit error");
                        exit(1);
                    }
                }
            }
            return TRUE;

        case WM_CLOSE:
            {
                ret = freeASMDLL();
                if ( ret != 0 )
                {
                    DBG_Log(" - freeASMDLL error");
                    exit(1);
                }

                ret = EndDialog(hwndDlg, 0);
                if ( ret == 0 )
                {
                    ret = GetLastError();
                    DBG_Log("EndDialog Error(0x%08X)", ret);
				}
				if (hBrush)
					DeleteObject(hBrush);
				EndDialog(hwndDlg, IDOK);


            }
            return TRUE;
			

        case WM_COMMAND:
            {
                switch(LOWORD(wParam))
                {
					
					/*case ID_FPT_Verify_1:
						{
						SetFocus(GetDlgItem(gHwnd, ID_BUTTON_KILL));
						EnableWindow(gHwnd, FALSE);
						
						int currentAngle;
						int currentFinger;
						int currentHand;
						if (EnrollCount >= 9 && EnrollCount < 19)
							{
								MessageBox(gHwnd, "다음으로 각도로 넘어갑니다.", "EnrollCount Over", MB_OK);
								currentAngle = SendMessage(GetDlgItem(gHwnd, IDC_COMBO_ANGLE), CB_GETCURSEL, 0, 0);
								SendMessage(GetDlgItem(gHwnd, IDC_COMBO_ANGLE), CB_SETCURSEL, currentAngle + 1, 0);
							}
						if (EnrollCount >= 19 && EnrollCount < 29)
							{
								MessageBox(gHwnd, "다음으로 각도로 넘어갑니다.", "EnrollCount Over", MB_OK);
								currentAngle = SendMessage(GetDlgItem(gHwnd, IDC_COMBO_ANGLE), CB_GETCURSEL, 0, 0);
								SendMessage(GetDlgItem(gHwnd, IDC_COMBO_ANGLE), CB_SETCURSEL, currentAngle + 1, 0);
							}
						if (EnrollCount >= 29)
							{
								EnrollCount = 0;
								i++;
								SetWindowText(GetDlgItem(gHwnd, IDC_EDIT_COUNT), "0");
								currentAngle = SendMessage(GetDlgItem(gHwnd, IDC_COMBO_ANGLE), CB_GETCURSEL, 0, 0);
								currentFinger = SendMessage(GetDlgItem(gHwnd, IDC_COMBO_COUNT), CB_GETCURSEL, 0, 0);
								currentHand = SendMessage(GetDlgItem(gHwnd, IDC_COMBO_HAND), CB_GETCURSEL, 0, 0);
								
								if ((currentFinger == 3))
								{
									if (currentAngle == 2)
									{
										if (currentHand == 1)
										{
											MessageBox(gHwnd, "완료버튼을 눌러주세요.", "Test Finish", MB_OK);
											SendMessage(GetDlgItem(gHwnd, IDC_COMBO_HAND), CB_SETCURSEL, 0, 0);
											SendMessage(GetDlgItem(gHwnd, IDC_COMBO_COUNT), CB_SETCURSEL, 0, 0);
											SendMessage(GetDlgItem(gHwnd, IDC_COMBO_ANGLE), CB_SETCURSEL, 0, 0);
											EnableWindow(gHwnd, TRUE);
											break;
										}
										else
										{
											MessageBox(gHwnd, "오른손으로 넘어갑니다.", "Hand Change", MB_OK);
											SendMessage(GetDlgItem(gHwnd, IDC_COMBO_COUNT), CB_SETCURSEL, 0, 0);
											SendMessage(GetDlgItem(gHwnd, IDC_COMBO_HAND), CB_SETCURSEL, 1, 0);
											SendMessage(GetDlgItem(gHwnd, IDC_COMBO_ANGLE), CB_SETCURSEL, 0, 0);
											EnableWindow(gHwnd, TRUE);
										}
									}
								}
								else
								{
									SendMessage(GetDlgItem(gHwnd, IDC_COMBO_COUNT), CB_SETCURSEL, currentFinger + 1, 0);
									SendMessage(GetDlgItem(gHwnd, IDC_COMBO_ANGLE), CB_SETCURSEL, 0, 0);
									MessageBox(gHwnd, "다음손가락으로 넘어갑니다.", "EnrollCount Over", MB_OK);
									EnableWindow(gHwnd, TRUE);
								}
							}
						if (EnrollCount > 30)
							{
								MessageBox(gHwnd, "EnrollCount > 30", "Count Error", MB_OK);
								EnableWindow(gHwnd, TRUE);
								return -1;
							}
								gLastRequest = (int)FPVerifyImage;
								_beginthread(&sendRequest, 0, NULL);
							}
						break;*/

					case ID_FPT_ENROLL_1:
					{
						startIndex = SendMessage(GetDlgItem(gHwnd, IDC_COMBO_START), CB_GETCURSEL, 0, 0);
						DBG_Log("startIndex: %d ", startIndex);
						SetFocus(GetDlgItem(gHwnd, ID_BUTTON_KILL));						
						if (startIndex == 0)
						{	
							EnableWindow(gHwnd, FALSE);
							
							gLastRequest = (int)FPTestImage;
							_beginthread(&sendRequest, 0, NULL);
						}
						else
						{
							EnableWindow(gHwnd, FALSE);
							
							gLastRequest = (int)FPVerifyImage;
							_beginthread(&sendRequest, 0, NULL);
						}
					}
					break;

					/*case ID_RETURN_BUTTON:
						{
						int currentAngle;
						int currentFinger;
						int currentHand;

						currentAngle = SendMessage(GetDlgItem(gHwnd, IDC_COMBO_ANGLE), CB_GETCURSEL, 0, 0);
						currentFinger = SendMessage(GetDlgItem(gHwnd, IDC_COMBO_COUNT), CB_GETCURSEL, 0, 0);
						currentHand = SendMessage(GetDlgItem(gHwnd, IDC_COMBO_HAND), CB_GETCURSEL, 0, 0);
						if ((currentAngle == 2) && (currentFinger == 3) && (currentHand == 1))
						{
							SetWindowText(GetDlgItem(gHwnd, IDC_EDIT_COUNT), "0");
							SendMessage(GetDlgItem(gHwnd, IDC_COMBO_HAND), CB_SETCURSEL, 0, 0);
							SendMessage(GetDlgItem(gHwnd, IDC_COMBO_COUNT), CB_SETCURSEL, 0, 0);
							SendMessage(GetDlgItem(gHwnd, IDC_COMBO_ANGLE), CB_SETCURSEL, 0, 0);
							SendMessage(GetDlgItem(gHwnd, IDC_COMBO_START), CB_SETCURSEL, 0, 0);
							unsigned int useridCount;
							char* UserID = NULL;
							int UseridLength = (int)SendMessage(GetDlgItem(gHwnd, IDC_EDIT_USERID), WM_GETTEXTLENGTH, 0, 0);
							UserID = new char[UseridLength + 1]{ 0, };
							SendMessage(GetDlgItem(gHwnd, IDC_EDIT_USERID), WM_GETTEXT, (WPARAM)(UseridLength + 1), (LPARAM)UserID);
							useridCount = atoi(UserID);
							useridCount++;

							UserID = new char[UseridLength + 1]{ 0, };
							_itoa(useridCount, UserID, 10);
							SetWindowText(GetDlgItem(gHwnd, IDC_EDIT_USERID), UserID);
							Operation = 0;
							EnrollCount = 0;
						}
						else
						{
							MessageBox(gHwnd, "완료되지않았습니다.", "Complete Error", MB_OK);
						}
						}
						break;*/

                   
                    case ID_UAF_CLEARBUTTON:
                        {
                            SetWindowText(GetDlgItem(hwndDlg, ID_UAF_REQUEST), "");
                            SetWindowText(GetDlgItem(hwndDlg, ID_UAF_RESPONSE), "");
                        }
                        break;


                    case ID_LOG_CLEAR_BUTTON:
                        {
                            SetWindowText(GetDlgItem(hwndDlg, ID_LOG), "");
                        }
                        break;

                   
                    case ID_LOG:
                        {
                            if ( LOWORD(wParam) == EN_MAXTEXT )
                            {
                                AddLog((char*)"Message size has exceeded the max buffer");
                            }
                        }
                        break;
                }
            }

            return TRUE;
    }
    return FALSE;
}


int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
    hInst=hInstance;
    InitCommonControls();
    return DialogBox(hInst, MAKEINTRESOURCE(DLG_MAIN), NULL, (DLGPROC)DlgMain);
}


void sendRequest(void* param)
{
    int ret = -1;

    char jsonBuffer[2048] = {0,};
    asmJSONData_t jsonData;

    memset(jsonBuffer, 0x0, sizeof(jsonBuffer));
    memset(&jsonData,  0x0, sizeof(jsonData));
    jsonData.length = 0;
    jsonData.pData  = NULL;

    int request = gLastRequest;
    switch ( request )
    {
        case GetInfo:
            {
                sprintf(jsonBuffer,
                        "{\"asmVersion\":{\"major\":1,\"minor\":0},\"requestType\":\"%s\"}",
                        asmRequest[request]);
            }
            break;

        case Register:
            {
                int   authenticatorIndexLength = (int)SendMessage(GetDlgItem(gHwnd, ID_DID_COMBOBOX), WM_GETTEXTLENGTH, 0, 0);
                char* authenticatorIndex = NULL;
                if ( authenticatorIndexLength > 0 )
                {
                    authenticatorIndex = new char[authenticatorIndexLength+1]{0,};
                    if ( authenticatorIndex == NULL )
                    {
                        DBG_Log("memory error");
                        return;
                    }
                    SendMessage(GetDlgItem(gHwnd, ID_DID_COMBOBOX), WM_GETTEXT, (WPARAM)(authenticatorIndexLength+1), (LPARAM)authenticatorIndex);
                }
                else
                {
                    authenticatorIndex = new char[2]{0,};
                    sprintf(authenticatorIndex, "0");
                }

                long appIDLength = (int)SendMessage(GetDlgItem(gHwnd, ID_UAF_APPID), WM_GETTEXTLENGTH, 0, 0);
                char* appID     = NULL;
                if ( appIDLength > 0 )
                {
                    appID = new char[appIDLength+1]{0,};
                    if ( appID == NULL )
                    {
                        DBG_Log("memory error");
                        return;
                    }
                    SendMessage(GetDlgItem(gHwnd, ID_UAF_APPID), WM_GETTEXT, (WPARAM)(appIDLength+1), (LPARAM)appID);
                    DBG_Log("%s", appID);
                }
                else
                {
                    appID = new char[66]{0,};
                    sprintf(appID, "https://qa-egypt.noknoktest.com:443/UAFSampleProxy/uaf/facets.uaf");
                }

                long userIDLength = (int)SendMessage(GetDlgItem(gHwnd, ID_UAF_USERID), WM_GETTEXTLENGTH, 0, 0);
                char* userID     = NULL;
                if ( userIDLength > 0 )
                {
                    userID = new char[userIDLength+1]{0,};
                    if ( userID == NULL )
                    {
                        DBG_Log("memory error");
                        return;
                    }
                    SendMessage(GetDlgItem(gHwnd, ID_UAF_USERID), WM_GETTEXT, (WPARAM)(userIDLength+1), (LPARAM)userID);
                    DBG_Log("%s", userID);
                }
                else
                {
                    userID = new char[6]{0,};
                    sprintf(userID, "user1");
                }

                sprintf(jsonBuffer,
                        "{\"args\":{\"appID\":\"%s\",\"username\":\"%s\",\"finalChallenge\":\"eyJhcHBJRCI6Imh0dHBzOi8vcWEtZWd5cHQubm9rbm9rdGVzdC5jb206NDQzL1VBRlNhbXBsZVByb3h5L3VhZi9mYWNldHMudWFmIiwiY2hhbGxlbmdlIjoidVlCdUdRZjdyLUxORDE2UTBHVXBQUmkxMTJVakN0Y3ltM2F3am0tTW1tSSIsImNoYW5uZWxCaW5kaW5nIjp7fSwiZmFjZXRJRCI6ImNvbS5ub2tub2suYW5kcm9pZC5zYW1wbGVhcHAifQ\",\"attestationType\":15879},\"asmVersion\":{\"major\":1,\"minor\":0},\"authenticatorIndex\":%s,\"requestType\":\"%s\"}",
                        appID,
                        userID,
                        authenticatorIndex,
                        asmRequest[request]);

                if( userID !=NULL )
                {
                    delete[] userID;
                    userID = NULL;
                }

                if( appID !=NULL )
                {
                    delete[] appID;
                    appID = NULL;
                }

                if ( authenticatorIndex != NULL )
                {
                    delete[] authenticatorIndex;
                    authenticatorIndex = NULL;
                }
            }
            break;

        case Authenticate:
            {
                int   authenticatorIndexLength = (int)SendMessage(GetDlgItem(gHwnd, ID_DID_COMBOBOX), WM_GETTEXTLENGTH, 0, 0);
                char* authenticatorIndex = NULL;
                if ( authenticatorIndexLength > 0 )
                {
                    authenticatorIndex = new char[authenticatorIndexLength+1]{0,};
                    if ( authenticatorIndex == NULL )
                    {
                        DBG_Log("memory error");
                        return;
                    }
                    SendMessage(GetDlgItem(gHwnd, ID_DID_COMBOBOX), WM_GETTEXT, (WPARAM)(authenticatorIndexLength+1), (LPARAM)authenticatorIndex);
                }
                else
                {
                    authenticatorIndex = new char[2]{0,};
                    sprintf(authenticatorIndex, "0");
                }

                long appIDLength = (int)SendMessage(GetDlgItem(gHwnd, ID_UAF_APPID), WM_GETTEXTLENGTH, 0, 0);
                char* appID     = NULL;
                if ( appIDLength > 0 )
                {
                    appID = new char[appIDLength+1]{0,};
                    if ( appID == NULL )
                    {
                        DBG_Log("memory error");
                        return;
                    }
                    SendMessage(GetDlgItem(gHwnd, ID_UAF_APPID), WM_GETTEXT, (WPARAM)(appIDLength+1), (LPARAM)appID);
                    DBG_Log("%s", appID);
                }
                else
                {
                    appID = new char[66]{0,};
					sprintf(appID, "https://qa-egypt.noknoktest.com:443/UAFSampleProxy/uaf/facets.uaf");
                }

                int   keyHandleLength = (int)SendMessage(GetDlgItem(gHwnd, ID_UAF_KEYHANDLE), WM_GETTEXTLENGTH, 0, 0);
                char* keyHandle = NULL;
                if ( keyHandleLength > 0 )
                {
                    keyHandle = new char[keyHandleLength+1]{0,};
                    if ( keyHandle == NULL )
                    {
                        DBG_Log("memory error");
                        return;
                    }
                    SendMessage(GetDlgItem(gHwnd, ID_UAF_KEYHANDLE), WM_GETTEXT, (WPARAM)(keyHandleLength+1), (LPARAM)keyHandle);
                    DBG_Log("%s", keyHandle);
                }


                if ( (keyHandle != NULL) && (SendMessage(GetDlgItem(gHwnd, ID_UAF_KEY_HANDEL_ENABLE), BM_GETCHECK, 0, 0) == BST_CHECKED) )
                {
                    sprintf(jsonBuffer,
                              "{\"args\":{\"appID\":\"%s\",\"finalChallenge\":\"eyJhcHBJRCI6Imh0dHBzOi8vcWEtZWd5cHQubm9rbm9rdGVzdC5jb206NDQzL1VBRlNhbXBsZVByb3h5L3VhZi9mYWNldHMudWFmIiwiY2hhbGxlbmdlIjoiM3otaVN2TndENFFLd01kV1NCS0hGT2hNNDN4M1dGOHI1eU9yd0pmVzljSSIsImNoYW5uZWxCaW5kaW5nIjp7fSwiZmFjZXRJRCI6ImNvbS5ub2tub2suYW5kcm9pZC5zYW1wbGVhcHAifQ\",\"keyHandle\":\"%s\"},\"asmVersion\":{\"major\":1,\"minor\":0},\"authenticatorIndex\":%s,\"requestType\":\"%s\"}",
                              appID,
                              keyHandle,
                              authenticatorIndex,
                              asmRequest[request]);
                }
                else
                {
                    SendMessage(GetDlgItem(gHwnd, ID_UAF_KEYHANDLE), CB_RESETCONTENT, 0, 0);
                    sprintf(jsonBuffer,
                       "{\"args\":{\"appID\":\"%s\",\"finalChallenge\":\"eyJhcHBJRCI6Imh0dHBzOi8vcWEtZWd5cHQubm9rbm9rdGVzdC5jb206NDQzL1VBRlNhbXBsZVByb3h5L3VhZi9mYWNldHMudWFmIiwiY2hhbGxlbmdlIjoiM3otaVN2TndENFFLd01kV1NCS0hGT2hNNDN4M1dGOHI1eU9yd0pmVzljSSIsImNoYW5uZWxCaW5kaW5nIjp7fSwiZmFjZXRJRCI6ImNvbS5ub2tub2suYW5kcm9pZC5zYW1wbGVhcHAifQ\"},\"asmVersion\":{\"major\":1,\"minor\":0},\"authenticatorIndex\":%s,\"requestType\":\"%s\"}",
                              appID,
                              authenticatorIndex,
                              asmRequest[request]);
                }

                if( appID !=NULL )
                {
                    delete[] appID;
                    appID = NULL;
                }

                if ( authenticatorIndex != NULL )
                {
                    delete[] authenticatorIndex;
                    authenticatorIndex = NULL;
                }

                if ( keyHandle != NULL )
                {
                    delete[] keyHandle;
                    keyHandle = NULL;
                }
            }
            break;

        case Deregister:
            {
                int   authenticatorIndexLength = (int)SendMessage(GetDlgItem(gHwnd, ID_DID_COMBOBOX), WM_GETTEXTLENGTH, 0, 0);
                char* authenticatorIndex = NULL;
                if ( authenticatorIndexLength > 0 )
                {
                    authenticatorIndex = new char[authenticatorIndexLength+1]{0,};
                    if ( authenticatorIndex == NULL )
                    {
                        DBG_Log("memory error");
                        return;
                    }
                    SendMessage(GetDlgItem(gHwnd, ID_DID_COMBOBOX), WM_GETTEXT, (WPARAM)(authenticatorIndexLength+1), (LPARAM)authenticatorIndex);
                }
                else
                {
                    authenticatorIndex = new char[2]{0,};
                    sprintf(authenticatorIndex, "0");
                }

                int appIDLength = (int)SendMessage(GetDlgItem(gHwnd, ID_UAF_APPID), WM_GETTEXTLENGTH, 0, 0);
                char* appID     = NULL;
                if ( appIDLength > 0 )
                {
                    appID = new char[appIDLength+1]{0,};
                    if ( appID == NULL )
                    {
                        DBG_Log("memory error");
                        return;
                    }
                    SendMessage(GetDlgItem(gHwnd, ID_UAF_APPID), WM_GETTEXT, (WPARAM)(appIDLength+1), (LPARAM)appID);
                    DBG_Log("%s", appID);
                }
                else
                {
                    appID = new char[66]{0,};
					sprintf(appID, "https://qa-egypt.noknoktest.com:443/UAFSampleProxy/uaf/facets.uaf");
                }

                int keyidLength = (int)SendMessage(GetDlgItem(gHwnd, ID_UAF_KEYID), WM_GETTEXTLENGTH, 0, 0);
                char* keyID = NULL;
                if ( keyidLength > 0 )
                {
                    keyID = new char[keyidLength+1]{0,};
                    if ( keyID == NULL )
                    {
                        DBG_Log("memory error");
                        return;
                    }
                    SendMessage(GetDlgItem(gHwnd, ID_UAF_KEYID), WM_GETTEXT, (WPARAM)(keyidLength+1), (LPARAM)keyID);
                }

                int index = (int)SendMessage(GetDlgItem(gHwnd, ID_UAF_KEYID), CB_GETCURSEL, 0, 0);
                SendMessage(GetDlgItem(gHwnd, ID_UAF_KEYID), CB_DELETESTRING, (WPARAM)index, 0);
                SendMessage(GetDlgItem(gHwnd, ID_UAF_KEYID), CB_SETCURSEL, (WPARAM)0, 0);

                sprintf(jsonBuffer,
                        "{\"args\":{\"appID\":\"%s\",\"keyID\":\"%s\"},\"asmVersion\":{\"major\":1,\"minor\":0},\"authenticatorIndex\":%s,\"requestType\":\"%s\"}",
                        appID,
                        keyID,
                        authenticatorIndex,
                        asmRequest[request]);

                if( appID !=NULL )
                {
                    delete[] appID;
                    appID = NULL;
                }

                if ( authenticatorIndex != NULL )
                {
                    delete[] authenticatorIndex;
                    authenticatorIndex = NULL;
                }

                if ( keyID != NULL )
                {
                    delete[] keyID;
                    keyID = NULL;
                }
            }
            break;

        case GetRegistrations:
            {
                int   authenticatorIndexLength = (int)SendMessage(GetDlgItem(gHwnd, ID_DID_COMBOBOX), WM_GETTEXTLENGTH, 0, 0);
                char* authenticatorIndex = NULL;
                if ( authenticatorIndexLength > 0 )
                {
                    authenticatorIndex = new char[authenticatorIndexLength+1]{0,};
                    if ( authenticatorIndex == NULL )
                    {
                        DBG_Log("memory error");
                        return;
                    }
                    SendMessage(GetDlgItem(gHwnd, ID_DID_COMBOBOX), WM_GETTEXT, (WPARAM)(authenticatorIndexLength+1), (LPARAM)authenticatorIndex);
                }
                else
                {
                    authenticatorIndex = new char[2]{0,};
                    sprintf(authenticatorIndex, "0");
                }

                sprintf(jsonBuffer,
                        "{\"asmVersion\":{\"major\":1,\"minor\":0},\"authenticatorIndex\":%s,\"requestType\":\"%s\"}",
                        authenticatorIndex,
                        asmRequest[request]);

                if ( authenticatorIndex != NULL )
                {
                    delete[] authenticatorIndex;
                    authenticatorIndex = NULL;
                }
            }
            break;

        case FPEnroll:
            {
                int   authenticatorIndexLength = (int)SendMessage(GetDlgItem(gHwnd, ID_DID_COMBOBOX), WM_GETTEXTLENGTH, 0, 0);
                char* authenticatorIndex = NULL;
                if ( authenticatorIndexLength > 0 )
                {
                    authenticatorIndex = new char[authenticatorIndexLength+1]{0,};
                    if ( authenticatorIndex == NULL )
                    {
                        DBG_Log("memory error");
                        return;
                    }
                    SendMessage(GetDlgItem(gHwnd, ID_DID_COMBOBOX), WM_GETTEXT, (WPARAM)(authenticatorIndexLength+1), (LPARAM)authenticatorIndex);
                }
                else
                {
                    authenticatorIndex = new char[2]{0,};
                    sprintf(authenticatorIndex, "0");
                }

                char* fingerPrintIndex = NULL;
                int   fingerPrintIndexLength = (int)SendMessage(GetDlgItem(gHwnd, ID_FP_INDEX), WM_GETTEXTLENGTH, 0, 0);
                if ( fingerPrintIndexLength > 0 )
                {
                    fingerPrintIndex = new char[fingerPrintIndexLength+1]{0,};
                    if ( fingerPrintIndex == NULL )
                    {
                        DBG_Log("memory error");
                        return;
                    }
                    SendMessage(GetDlgItem(gHwnd, ID_FP_INDEX), WM_GETTEXT, (WPARAM)fingerPrintIndexLength+1, (LPARAM)fingerPrintIndex);
                }
                else
                {
                    fingerPrintIndex = new char[2]{0,};
                    if ( fingerPrintIndex == NULL )
                    {
                        DBG_Log("memory error");
                        return;
                    }
                    sprintf(fingerPrintIndex, "%d", 0);
                }

                char* fingerPrintName = NULL;
                int   fingerPrintNameLength = (int)SendMessage(GetDlgItem(gHwnd, ID_FP_ID), WM_GETTEXTLENGTH, 0, 0);
                if ( fingerPrintNameLength > FP_NAME_MAX )
                {
                    if ( authenticatorIndex != NULL )
                    {
                        delete[] authenticatorIndex;
                        authenticatorIndex = NULL;
                    }

                    if ( fingerPrintIndex != NULL )
                    {
                        delete[] fingerPrintIndex;
                        fingerPrintIndex = NULL;
                    }

                    DBG_Log("fingerPrintNameLength error");

                    return;
                }
                else if ( fingerPrintNameLength > 0 )
                {
                    fingerPrintName = new char[fingerPrintNameLength+1]{0,};
                    if ( fingerPrintName == NULL )
                    {
                        DBG_Log("memory error");
                        return;
                    }
                    SendMessage(GetDlgItem(gHwnd, ID_FP_ID), WM_GETTEXT, (WPARAM)fingerPrintNameLength+1, (LPARAM)fingerPrintName);
                }
                else
                {
                    fingerPrintName = new char[8]{0,};
                    if ( fingerPrintName == NULL )
                    {
                        DBG_Log("memory error");
                        return;
                    }
                    sprintf(fingerPrintName, "Finger%s", fingerPrintIndex);
                }
                sprintf(jsonBuffer,
                        "{\"asmVersion\":{\"major\":1,\"minor\":0},\"authenticatorIndex\":%s,\"requestType\":\"%s\",\"fingerPrintIndex\":%s,\"fingerPrintName\":\"%s\"}",
                        authenticatorIndex,
                        asmRequest[request],
                        fingerPrintIndex,
                        fingerPrintName);

                if ( authenticatorIndex != NULL )
                {
                    delete[] authenticatorIndex;
                    authenticatorIndex = NULL;
                }

                if ( fingerPrintIndex != NULL )
                {
                    delete[] fingerPrintIndex;
                    fingerPrintIndex = NULL;
                }

                if ( fingerPrintName != NULL )
                {
                    delete[] fingerPrintName;
                    fingerPrintName = NULL;
                }
            }
            break;

        case FPRemove:
        case FPEnrollCheck:
            {
                int   authenticatorIndexLength = (int)SendMessage(GetDlgItem(gHwnd, ID_DID_COMBOBOX), WM_GETTEXTLENGTH, 0, 0);
                char* authenticatorIndex = NULL;
                if ( authenticatorIndexLength > 0 )
                {
                    authenticatorIndex = new char[authenticatorIndexLength+1]{0,};
                    if ( authenticatorIndex == NULL )
                    {
                        DBG_Log("memory error");
                        return;
                    }
                    SendMessage(GetDlgItem(gHwnd, ID_DID_COMBOBOX), WM_GETTEXT, (WPARAM)(authenticatorIndexLength+1), (LPARAM)authenticatorIndex);
                }
                else
                {
                    authenticatorIndex = new char[2]{0,};
                    sprintf(authenticatorIndex, "0");
                }

                char* fingerPrintIndex = NULL;
                int   fingerPrintIndexLength = (int)SendMessage(GetDlgItem(gHwnd, ID_FP_INDEX), WM_GETTEXTLENGTH, 0, 0);
                if ( fingerPrintIndexLength > 0 )
                {
                    fingerPrintIndex = new char[fingerPrintIndexLength+1]{0,};
                    if ( fingerPrintIndex == NULL )
                    {
                        DBG_Log("memory error");
                        return;
                    }
                    SendMessage(GetDlgItem(gHwnd, ID_FP_INDEX), WM_GETTEXT, (WPARAM)fingerPrintIndexLength+1, (LPARAM)fingerPrintIndex);
                }
                else
                {
                    fingerPrintIndex = new char[2]{0,};
                    if ( fingerPrintIndex == NULL )
                    {
                        DBG_Log("memory error");
                        return;
                    }
                    sprintf(fingerPrintIndex, "%d", 0);
                }
                sprintf(jsonBuffer,
                        "{\"asmVersion\":{\"major\":1,\"minor\":0},\"authenticatorIndex\":%s,\"requestType\":\"%s\",\"fingerPrintIndex\":%s}",
                        authenticatorIndex,
                        asmRequest[request],
                        fingerPrintIndex);

                if ( authenticatorIndex != NULL )
                {
                    delete[] authenticatorIndex;
                    authenticatorIndex = NULL;
                }

                if ( fingerPrintIndex != NULL )
                {
                    delete[] fingerPrintIndex;
                    fingerPrintIndex = NULL;
                }
            }
            break;

        case FPVerify:
        case FPGetList:
        case FPGetImage:
            {
                int   authenticatorIndexLength = (int)SendMessage(GetDlgItem(gHwnd, ID_DID_COMBOBOX), WM_GETTEXTLENGTH, 0, 0);
                char* authenticatorIndex = NULL;
                if ( authenticatorIndexLength > 0 )
                {
                    authenticatorIndex = new char[authenticatorIndexLength+1]{0,};
                    if ( authenticatorIndex == NULL )
                    {
                        DBG_Log("memory error");
                        return;
                    }
                    SendMessage(GetDlgItem(gHwnd, ID_DID_COMBOBOX), WM_GETTEXT, (WPARAM)(authenticatorIndexLength+1), (LPARAM)authenticatorIndex);
                }
                else
                {
                    authenticatorIndex = new char[2]{0,};
                    sprintf(authenticatorIndex, "0");
                }

                sprintf(jsonBuffer,
                        "{\"asmVersion\":{\"major\":1,\"minor\":0},\"authenticatorIndex\":%s,\"requestType\":\"%s\"}",
                        authenticatorIndex,
                        asmRequest[request]);

                if ( authenticatorIndex != NULL )
                {
                    delete[] authenticatorIndex;
                    authenticatorIndex = NULL;
                }
            }
            break;

		case FPTestImage:
			{
				/*if (EnrollCount == 8)
				{
					MessageBox(gHwnd, "다음으로 넘어가주세요.", "Count Over", MB_OK);
					EnrollCount = 0;
					EnableWindow(gHwnd, TRUE);
					break;
				}*/
				int   enrollCountLength = (int)SendMessage(GetDlgItem(gHwnd, IDC_EDIT_COUNT), WM_GETTEXTLENGTH, 0, 0);
				int   authenticatorIndexLength = (int)SendMessage(GetDlgItem(gHwnd, ID_DID_COMBOBOX), WM_GETTEXTLENGTH, 0, 0);
				int   handIndexLength = (int)SendMessage(GetDlgItem(gHwnd, IDC_COMBO_HAND), WM_GETTEXTLENGTH, 0, 0);
				int   testUseridLength = (int)SendMessage(GetDlgItem(gHwnd, IDC_EDIT_USERID), WM_GETTEXTLENGTH, 0, 0);
				int   handCountLength = (int)SendMessage(GetDlgItem(gHwnd, IDC_COMBO_COUNT), WM_GETTEXTLENGTH, 0, 0);
				
				unsigned int   handNumber;
				unsigned int   handCountNum;
				char* enrollCount = NULL;
				char* handCount = NULL;
				char* angleIndex = NULL;
				char* testUserid = NULL;
				char* handIndex = NULL;
				char* authenticatorIndex = NULL;

				if (enrollCountLength > 0)
				{
					enrollCount = new char[enrollCountLength + 1]{ 0, };					
					SendMessage(GetDlgItem(gHwnd, IDC_EDIT_COUNT), WM_GETTEXT, (WPARAM)(enrollCountLength + 1), (LPARAM)enrollCount);
					EnrollCount = atoi(enrollCount);
					if ((EnrollCount < 0 ) || (EnrollCount >= FP_ENROLL_MAX))
					{
						EnrollCount = 0;
						SetWindowText(GetDlgItem(gHwnd, IDC_EDIT_COUNT), "0");
					}
				}

				if (handCountLength > 0)
				{
					handCount = new char[handCountLength + 1]{ 0, };
					if (handCount == NULL)
					{
						DBG_Log("hand Count error");
						return;
					}
					SendMessage(GetDlgItem(gHwnd, IDC_COMBO_COUNT), WM_GETTEXT, (WPARAM)(handCountLength + 1), (LPARAM)handCount);
					if (strcmp(handCount, "엄지") == 0)
					{
						handCountNum = 0;
					}
					else if (strcmp(handCount, "검지") == 0)
					{
						handCountNum = 1;
					}
					else if (strcmp(handCount, "중지") == 0)
					{
						handCountNum = 2;
					}
					else if (strcmp(handCount, "약지") == 0)
					{
						handCountNum = 3;
					}
				}


				if (testUseridLength > 0)
				{
					testUserid = new char[testUseridLength + 1]{ 0, };
					if (testUserid == NULL)
					{
						DBG_Log("hand user id error");
						return;
					}
					SendMessage(GetDlgItem(gHwnd, IDC_EDIT_USERID), WM_GETTEXT, (WPARAM)(testUseridLength + 1), (LPARAM)testUserid);
				}
				else
				{
					MessageBox(gHwnd, "UserID값을 입력해주세요.", "UserID Error", MB_OK);
					EnableWindow(gHwnd, TRUE);
				}

				if (handIndexLength > 0)
				{
					handIndex = new char[handIndexLength + 1]{ 0, };
					if (handIndex == NULL)
					{
						DBG_Log("hand error");
						return;
					}
						SendMessage(GetDlgItem(gHwnd, IDC_COMBO_HAND), WM_GETTEXT, (WPARAM)(handIndexLength + 1), (LPARAM)handIndex);
						
						if (strcmp(handIndex, "왼손") == 0)
						{
							handNumber = 0;
						}
						else
						{
							handNumber = 1;
						}
				}

				if (authenticatorIndexLength > 0)
				{
					authenticatorIndex = new char[authenticatorIndexLength + 1]{ 0, };
					if (authenticatorIndex == NULL)
					{
						DBG_Log("memory error");
						return;
					}
					SendMessage(GetDlgItem(gHwnd, ID_DID_COMBOBOX), WM_GETTEXT, (WPARAM)(authenticatorIndexLength + 1), (LPARAM)authenticatorIndex);
				}
				else
				{
					authenticatorIndex = new char[2]{ 0, };
					sprintf(authenticatorIndex, "0");
				}

				sprintf(jsonBuffer,
					"{\"asmVersion\":{\"major\":1,\"minor\":0},\"FingerInformation\":{\"testUserid\":%s,\"EnrollCount\":%d,\"handIndex\":%d,\"handCount\":%d},\"authenticatorIndex\":%s,\"requestType\":\"%s\"}",
					testUserid,
					EnrollCount,
					handNumber,
					handCountNum,
					authenticatorIndex,
					asmRequest[request]);

				if (authenticatorIndex != NULL)
				{
					delete[] authenticatorIndex;
					authenticatorIndex = NULL;
				}

				if (testUserid != NULL)
				{
					delete[] testUserid;
					testUserid = NULL;
				}

				if (handIndex != NULL)
				{
					delete[] handIndex;
					handIndex = NULL;
				}

				if (angleIndex != NULL)
				{
					delete[] angleIndex;
					angleIndex = NULL;
				}

				
			}
			break;

			case FPVerifyImage:
			{
				int   authenticatorIndexLength = (int)SendMessage(GetDlgItem(gHwnd, ID_DID_COMBOBOX), WM_GETTEXTLENGTH, 0, 0);
				int   handIndexLength = (int)SendMessage(GetDlgItem(gHwnd, IDC_COMBO_HAND), WM_GETTEXTLENGTH, 0, 0);
				int   testUseridLength = (int)SendMessage(GetDlgItem(gHwnd, IDC_EDIT_USERID), WM_GETTEXTLENGTH, 0, 0);
				int   angleIndexLength = (int)SendMessage(GetDlgItem(gHwnd, IDC_COMBO_ANGLE), WM_GETTEXTLENGTH, 0, 0);
				int   handCountLength = (int)SendMessage(GetDlgItem(gHwnd, IDC_COMBO_COUNT), WM_GETTEXTLENGTH, 0, 0);
				int   verifyCountLength = (int)SendMessage(GetDlgItem(gHwnd, IDC_EDIT_COUNT), WM_GETTEXTLENGTH, 0, 0);
				unsigned int   handNumber;
				unsigned int   handCountNum;
				unsigned int   angle;				
				char* verifyCount = NULL;
				char* handCount = NULL;
				char* angleIndex = NULL;
				char* testUserid = NULL;
				char* handIndex = NULL;
				char* authenticatorIndex = NULL;

				if (verifyCountLength > 0)
				{
					verifyCount = new char[verifyCountLength + 1]{ 0, };
					SendMessage(GetDlgItem(gHwnd, IDC_EDIT_COUNT), WM_GETTEXT, (WPARAM)(verifyCountLength+1), (LPARAM)verifyCount);
					EnrollCount = atoi(verifyCount);
					if ((EnrollCount < 0) || (EnrollCount >= 30))
					{
						EnrollCount = 0;
						SetWindowText(GetDlgItem(gHwnd, IDC_EDIT_COUNT), "0");
						SendMessage(GetDlgItem(gHwnd, IDC_COMBO_ANGLE), CB_SETCURSEL, 0, 0);
					}
				}

				if (handCountLength > 0)
				{
					handCount = new char[handCountLength + 1]{ 0, };
					if (handCount == NULL)
					{
						DBG_Log("hand Count error");
						return;
					}
					SendMessage(GetDlgItem(gHwnd, IDC_COMBO_COUNT), WM_GETTEXT, (WPARAM)(handCountLength + 1), (LPARAM)handCount);
					if (strcmp(handCount, "엄지") == 0)
					{
						handCountNum = 0;
					}
					else if (strcmp(handCount, "검지") == 0)
					{
						handCountNum = 1;
					}
					else if (strcmp(handCount, "중지") == 0)
					{
						handCountNum = 2;
					}
					else if (strcmp(handCount, "약지") == 0)
					{
						handCountNum = 3;
					}
				}

				if (angleIndexLength > 0)
				{
					angleIndex = new char[angleIndexLength + 1]{ 0, };
					if (angleIndex == NULL)
					{
						DBG_Log("angle error");
						return;
					}
					SendMessage(GetDlgItem(gHwnd, IDC_COMBO_ANGLE), WM_GETTEXT, (WPARAM)(angleIndexLength + 1), (LPARAM)angleIndex);
					if (strcmp(angleIndex, "0") == 0)
					{
						if (EnrollCount > 9)
						{
							EnrollCount = 0;
							SetWindowText(GetDlgItem(gHwnd, IDC_EDIT_COUNT), "0");
						}

						angle = 0;
					}
					else if (strcmp(angleIndex, "45") == 0)
					{
						if (( EnrollCount < 10 ) || (EnrollCount > 19))
						{
							EnrollCount = 10;
							SetWindowText(GetDlgItem(gHwnd, IDC_EDIT_COUNT), "10");
						}

						angle = 45;
					}
					else if (strcmp(angleIndex, "90") == 0)
					{
						if (EnrollCount < 20)
						{
							EnrollCount = 20;
							SetWindowText(GetDlgItem(gHwnd, IDC_EDIT_COUNT), "20");
						}

						angle = 90;
					}
				}

				if (testUseridLength > 0)
				{
					testUserid = new char[testUseridLength + 1]{ 0, };
					if (testUserid == NULL)
					{
						DBG_Log("hand user id error");
						return;
					}
					SendMessage(GetDlgItem(gHwnd, IDC_EDIT_USERID), WM_GETTEXT, (WPARAM)(testUseridLength + 1), (LPARAM)testUserid);
				}
				else
				{
					MessageBox(gHwnd, "UserID값을 입력해주세요.", "UserID Error", MB_OK);
					EnableWindow(gHwnd, TRUE);
				}

				if (handIndexLength > 0)
				{
					handIndex = new char[handIndexLength + 1]{ 0, };
					if (handIndex == NULL)
					{
						DBG_Log("hand error");
						return;
					}
					SendMessage(GetDlgItem(gHwnd, IDC_COMBO_HAND), WM_GETTEXT, (WPARAM)(handIndexLength + 1), (LPARAM)handIndex);

					if (strcmp(handIndex, "왼손") == 0)
					{
						DBG_Log("Left handIndex :%s", handIndex);
						handNumber = 0;
					}
					else
					{
						DBG_Log("Right handIndex :%s", handIndex);
						handNumber = 1;
					}
				}

				if (authenticatorIndexLength > 0)
				{
					authenticatorIndex = new char[authenticatorIndexLength + 1]{ 0, };
					if (authenticatorIndex == NULL)
					{
						DBG_Log("memory error");
						return;
					}
					SendMessage(GetDlgItem(gHwnd, ID_DID_COMBOBOX), WM_GETTEXT, (WPARAM)(authenticatorIndexLength + 1), (LPARAM)authenticatorIndex);
				}
				else
				{
					authenticatorIndex = new char[2]{ 0, };
					sprintf(authenticatorIndex, "0");
				}

				sprintf(jsonBuffer,
					"{\"asmVersion\":{\"major\":1,\"minor\":0},\"FingerInformation\":{\"testUserid\":%s,\"EnrollCount\":%d,\"handIndex\":%d,\"handCount\":%d,\"angleIndex\":%d},\"authenticatorIndex\":%s,\"requestType\":\"%s\"}",
					testUserid,
					EnrollCount,
					handNumber,
					handCountNum,
					angle,
					authenticatorIndex,
					asmRequest[request]);

				if (authenticatorIndex != NULL)
				{
					delete[] authenticatorIndex;
					authenticatorIndex = NULL;
				}

				if (testUserid != NULL)
				{
					delete[] testUserid;
					testUserid = NULL;
				}

				if (handIndex != NULL)
				{
					delete[] handIndex;
					handIndex = NULL;
				}

				if (angleIndex != NULL)
				{
					delete[] angleIndex;
					angleIndex = NULL;
				}/*
				EnrollCount++;

				verifyCount = new char[verifyCountLength + 1]{ 0, };

				_itoa(EnrollCount, verifyCount, 10);

				SetWindowText(GetDlgItem(gHwnd, IDC_EDIT_COUNT), verifyCount);*/
				
			}
			break;

        case FWUpdate:
            {
                int   filePathLength = (int)SendMessage(GetDlgItem(gHwnd, ID_FIRMWARE_FILEPATH), WM_GETTEXTLENGTH, 0, 0);
                char* filePath = NULL;
                if ( filePathLength > 0 )
                {
                    filePath = new char[filePathLength+1]{0,};
                    if ( filePath == NULL )
                    {
                        DBG_Log("memory error");
                        return;
                    }
                    SendMessage(GetDlgItem(gHwnd, ID_FIRMWARE_FILEPATH), WM_GETTEXT, (WPARAM)(filePathLength+1), (LPARAM)filePath);
                }
                else
                {
                    DBG_Log("File Path is Empty");
                    return;
                }

                string fileName = filePath;
                string pattern  = "\\";
                string replace  = "\\\\";

                string::size_type pos = 0;
                string::size_type offset = 0;

                while ( (pos = fileName.find(pattern, offset)) != string::npos )
                {
                    fileName.replace(fileName.begin() + pos, fileName.begin() + pos + pattern.size(), replace);
                    offset = pos + replace.size();
                }

                int   authenticatorIndexLength = (int)SendMessage(GetDlgItem(gHwnd, ID_DID_COMBOBOX), WM_GETTEXTLENGTH, 0, 0);
                char* authenticatorIndex = NULL;
                if ( authenticatorIndexLength > 0 )
                {
                    authenticatorIndex = new char[authenticatorIndexLength+1]{0,};
                    if ( authenticatorIndex == NULL )
                    {
                        DBG_Log("memory error");
                        return;
                    }
                    SendMessage(GetDlgItem(gHwnd, ID_DID_COMBOBOX), WM_GETTEXT, (WPARAM)(authenticatorIndexLength+1), (LPARAM)authenticatorIndex);
                }
                else
                {
                    authenticatorIndex = new char[2]{0,};
                    sprintf(authenticatorIndex, "0");
                }

                sprintf(jsonBuffer,
                        "{\"authenticatorIndex\":%s,\"fileName\":\"%s\",\"requestType\":\"%s\"}",
                        authenticatorIndex,
                        fileName.c_str(),
                        asmRequest[request]);

                if ( authenticatorIndex != NULL )
                {
                    delete[] authenticatorIndex;
                    authenticatorIndex = NULL;
                }

                if ( filePath != NULL )
                {
                    delete[] filePath;
                    filePath = NULL;
                }
            }
            break;

        case GetDeviceID:
		case SDBInit:
		case FIDOInit:
            {
                int   authenticatorIndexLength = (int)SendMessage(GetDlgItem(gHwnd, ID_DID_COMBOBOX), WM_GETTEXTLENGTH, 0, 0);
                char* authenticatorIndex = NULL;
                if ( authenticatorIndexLength > 0 )
                {
                    authenticatorIndex = new char[authenticatorIndexLength+1]{0,};
                    if ( authenticatorIndex == NULL )
                    {
                        DBG_Log("memory error");
                        return;
                    }
                    SendMessage(GetDlgItem(gHwnd, ID_DID_COMBOBOX), WM_GETTEXT, (WPARAM)(authenticatorIndexLength+1), (LPARAM)authenticatorIndex);
                }
                else
                {
                    authenticatorIndex = new char[2]{0,};
                    sprintf(authenticatorIndex, "0");
                }

                sprintf(jsonBuffer,
                        "{\"asmVersion\":{\"major\":1,\"minor\":0},\"authenticatorIndex\":%s,\"requestType\":\"%s\"}",
                        authenticatorIndex,
                        asmRequest[request]);

                if ( authenticatorIndex != NULL )
                {
                    delete[] authenticatorIndex;
                    authenticatorIndex = NULL;
                }
            }
            break;

        default:
            {
                DBG_Log("invalid command");
            }
            break;

    }

    char log[128] = {0,};
    sprintf(log, "Send %s Request", asmRequest[gLastRequest]);
    AddLog(log);

    if ( jsonBuffer == NULL )
    {
        DBG_Log("jsonBuffer is empty");
        return;
    }


    jsonData.length = (int)strlen(jsonBuffer)+1;
    jsonData.pData  = new char[jsonData.length]{0,};
    if ( jsonData.pData == NULL )
    {
        DBG_Log("memory error");
        return;
    }
    memcpy(jsonData.pData, jsonBuffer, jsonData.length-1);

    SendMessage(GetDlgItem(gHwnd, ID_UAF_REQUEST), WM_SETTEXT, 0, (LPARAM)jsonBuffer);

    if ( asmProcess == NULL )
    {
        DBG_Log("asmProcess is NULL");
        return;
    }
    ret = asmProcess(&jsonData, eWBMCallback);
    if ( ret != Success )
    {
        DBG_Log("asmProcess fail");
    }

    if ( jsonData.pData != NULL )
    {
        delete[] jsonData.pData;
        jsonData.pData = NULL;
    }
    gLastRequest = -1;

    return;
}


void sendJSONMessage(void* param)
{
    int ret = -1;

    asmJSONData_t jsonData;
    memset(&jsonData,  0x0, sizeof(jsonData));
    jsonData.length = 0;
    jsonData.pData  = NULL;

    jsonData.length = (int)SendMessage(GetDlgItem(gHwnd, ID_UAF_REQUEST), WM_GETTEXTLENGTH, 0, 0);
    if ( jsonData.length <= 0 )
    {
        DBG_Log("request is empty: do nothing");
        return;
    }
    jsonData.pData  = new char[(jsonData.length + 1)]{0,};
    if ( jsonData.pData == NULL )
    {
        DBG_Log("memory error");
        return;
    }
    SendMessage(GetDlgItem(gHwnd, ID_UAF_REQUEST), WM_GETTEXT, (WPARAM)(jsonData.length+1), (LPARAM)jsonData.pData);

    Document document;
    ret = document.Parse(jsonData.pData).HasParseError();
    if ( ret != false )
    {
        DBG_Log("JSON Parse Error");
        return;
    }

    ret = document.HasMember("requestType");
    if ( ret != (int)true )
    {
        DBG_Log("requestType error");
        return;
    }
    ret = document["requestType"].IsString();
    if ( ret != (int)true )
    {
        DBG_Log("requestType error");
        return;
    }

    unsigned int requestTypeLength = document["requestType"].GetStringLength();
    if ( requestTypeLength <= 0 )
    {
        if ( jsonData.pData != NULL )
        {
            delete[] jsonData.pData;
            jsonData.pData = NULL;
        }
        DBG_Log("requestType is empty");
        return;
    }

    char* requestTypeBuffer = new char[(document["requestType"].GetStringLength() + 1)]{0,};
    if ( requestTypeBuffer == NULL )
    {
        DBG_Log("memory error");
        return;
    }
    memcpy(requestTypeBuffer, document["requestType"].GetString(), requestTypeLength);

    bool findRequest = false;
    for ( int i = 0; i < RequestMax; i++ )
    {
        ret = strcmp(requestTypeBuffer, asmRequest[i]);
        if ( ret != 0 )
        {
            continue;
        }
        findRequest = true;
        gLastRequest = i;
        break;
    }

    if ( requestTypeBuffer != NULL )
    {
        delete[] requestTypeBuffer;
        requestTypeBuffer = NULL;
    }

    if ( findRequest != true )
    {
        DBG_Log("invalid request: %d(%s)", gLastRequest, asmRequest[gLastRequest]);
        gLastRequest = -1;
        if ( jsonData.pData != NULL )
        {
            delete[] jsonData.pData;
            jsonData.pData = NULL;
        }
        return;
    }

    if ( asmProcess == NULL )
    {
        DBG_Log("asmProcess is NULL");
        return;
    }
    ret = asmProcess(&jsonData, eWBMCallback);
    if ( ret != Success )
    {
        DBG_Log("asmProcess fail");
    }

    if ( jsonData.pData != NULL )
    {
        delete[] jsonData.pData;
        jsonData.pData = NULL;
    }
    gLastRequest = -1;

    return;
}
