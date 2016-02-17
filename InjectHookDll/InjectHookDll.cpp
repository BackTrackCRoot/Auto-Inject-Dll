// InjectHookDll.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"
#include "InjectHookDll.h"

int InjectHook()
{
	MessageBox(NULL, L"Hell Hook!", L"Test Hook Dll", MB_OK);
	return 0;
}