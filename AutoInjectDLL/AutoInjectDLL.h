#include "stdafx.h"

#ifndef _AUTOINJECTDLL
#define _AUTOINJECTDLL

//������~��������
int HooksToInject(_TCHAR* DLLName, DWORD ProcessID);
int RemoteToInject(_TCHAR* DLLName, DWORD ProcessID);
DWORD GetTIDbyPID(DWORD PID);
char* wchar2char(_TCHAR* widechar);
int APCCallbacktoInject(_TCHAR* DLLName, DWORD ProcessID);//APC�ص�ע��
int EnablePrivilege();//������ȡ
_TCHAR* GetDllLocation(_TCHAR* DLLName);

#endif