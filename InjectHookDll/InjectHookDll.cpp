// InjectHookDll.cpp : ���� DLL Ӧ�ó���ĵ���������
//

#include "stdafx.h"
#include "InjectHookDll.h"

int InjectHook()
{
	MessageBox(NULL, L"Hell Hook!", L"Test Hook Dll", MB_OK);
	return 0;
}