#include "stdafx.h"

#ifndef _AUTOINJECTDLL
#define _AUTOINJECTDLL

//呼啦啦~函数声明
int HooksToInject(_TCHAR* DLLName, DWORD ProcessID);
int RemoteToInject(_TCHAR* DLLName, DWORD ProcessID);
DWORD GetTIDbyPID(DWORD PID);
char* wchar2char(_TCHAR* widechar);
int APCCallbacktoInject(_TCHAR* DLLName, DWORD ProcessID);//APC回调注入
int EnablePrivilege();//进程提取
_TCHAR* GetDllLocation(_TCHAR* DLLName);

#endif