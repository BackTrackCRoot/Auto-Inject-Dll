// AutoInjectDLL.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "AutoInjectDLL.h"
/* 注入方式 1、SetWindowsHooksEx注入 √
 *          2、CreateRemoteThread注入√
 *          3、APCCallbacktoInject注入√
 * 形式 AutoInjectDLL [method] [DllName] [进程ID]
 */


int _tmain(int argc, _TCHAR* argv[])
{
	//printf("%d", argc);
	int errmsg = 0;
	if (argc >= 2)
	{
		//wprintf(L"%d", _wtoi(argv[1]));
		switch (_wtoi(argv[1]))
		{
		case 1:
		{
				   errmsg = HooksToInject(argv[2], _wtol(argv[3]));
				   if (errmsg != 0)
				   {
					   wprintf(L"errmsg:%d\n", errmsg);
				   }
		}; break;
		case 2:
		{
				  errmsg = RemoteToInject(argv[2], _wtol(argv[3]));
				  if (errmsg != 0)
				  {
					  wprintf(L"errmsg:%d\n", errmsg);
				  }
		}; break;
		case 3:
		{
				  errmsg = APCCallbacktoInject(argv[2], _wtol(argv[3]));
				  if (errmsg != 0)
				  {
					  wprintf(L"errmsg:%d\n", errmsg);
				  }
		}break;
		default:
			wprintf(L"No it method!");
			break;
		}
	}
	else
	{
		wprintf(L"%s\n", GetDllLocation(L"ABC.dll"));
		wprintf(L"!!");
	}
	return 0;
}

//Hook 注入大法好
int HooksToInject(_TCHAR* DLLName, DWORD ProcessID)
{
	//wprintf(L"\n%s\n%d", DLLName, ProcessID);
	HHOOK InjectHook = NULL;
	HMODULE InjectDll = LoadLibrary(DLLName);
	if (InjectDll != NULL)
	{
		HOOKPROC InjectMethod = (HOOKPROC)GetProcAddress(InjectDll, "InjectHook");
		if (InjectMethod != NULL)
		{
			DWORD ThreadId = GetTIDbyPID(ProcessID);
			if (ThreadId!=NULL)
			{
				InjectHook = SetWindowsHookEx(WH_KEYBOARD, InjectMethod, InjectDll, ThreadId);
				if (InjectHook != NULL)
				{
					wprintf(L"%s\n", L"Hook Process Success!");
				}
				else
				{
					return GetLastError();
				}
			}
		}
		else
		{
			return GetLastError();
		}

	}
	else
	{
		return GetLastError();
	}
	wprintf(L"%s\n",L"Wait you unhook, press any key to unhook.");
	getchar();
	UnhookWindowsHookEx(InjectHook);
	return 0;
}

int RemoteToInject(_TCHAR* DLLName, DWORD ProcessID)
{
	//DWORD ThreadId = GetTIDbyPID(ProcessID);
	//进程提取
	if (int rt = EnablePrivilege() != 0)
		return rt;
	HANDLE hOprocess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessID);
	if (hOprocess != NULL)
	{
		_TCHAR* pLibFileRemote = (_TCHAR*)VirtualAllocEx(hOprocess, NULL, 2 * wcslen(DLLName) + 1, MEM_COMMIT, PAGE_READWRITE);
		if (pLibFileRemote != NULL)
		{
			if (!WriteProcessMemory(hOprocess, (void*)pLibFileRemote, DLLName, 2 * wcslen(DLLName) + 1, NULL))
				return GetLastError();

			//Get LoadLibraryW Address
			PTHREAD_START_ROUTINE pfnStartAddr = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(L"Kernel32"), "LoadLibraryW");
			if (pfnStartAddr != NULL)
			{
				HANDLE hRemote = CreateRemoteThread(hOprocess, NULL, 0, pfnStartAddr, (PVOID)pLibFileRemote, 0, NULL);
				if (hRemote != NULL)
				{
					wprintf(L"%s\n", L"Inject sucessful!");
					WaitForSingleObject(hRemote, INFINITE);
					wprintf(L"%s\n", L"The inject was killed!");
					if (!VirtualFreeEx(hOprocess, pLibFileRemote, 0, MEM_RELEASE))
						return GetLastError();
				}
				else
					return GetLastError();
			}
		}
		else
			return GetLastError();
	}
	else
		return GetLastError();
	return 0;
}

//通过进程PID获取线程TID
DWORD GetTIDbyPID(DWORD PID)
{
	if (PID != NULL)
	{
		DWORD dwThreadID=NULL;
		THREADENTRY32 te32 = { sizeof(te32) };
		HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (Thread32First(hThreadSnap, &te32))
		{
			do
			{
				if (PID == te32.th32OwnerProcessID)
				{
					dwThreadID = te32.th32ThreadID;
					break;
				}
			} while (Thread32Next(hThreadSnap, &te32));
		}
		wprintf(L"ThreadId:%d\n", dwThreadID);
		return dwThreadID;
	}
	else
		return NULL;
}

//wchar_t 转char
char* wchar2char(_TCHAR* widechar)
{
	size_t wcharlen = wcslen(widechar);
	size_t charlen = 0;
	char* rtChar = (char*)malloc(wcharlen*sizeof(char));
	wcstombs_s(&charlen, rtChar, wcharlen, widechar, _TRUNCATE);
	return rtChar;
}
int APCCallbacktoInject(_TCHAR* DLLName, DWORD ProcessID)
{
	//提升进程权限
	if (int rtMsg = EnablePrivilege() != 0)
		return rtMsg;
	HANDLE hOProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessID);
	if (hOProcess != NULL)
	{
		_TCHAR* pLibRemote = (_TCHAR*)VirtualAllocEx(hOProcess, NULL, 2 * wcslen(DLLName) + 1, MEM_COMMIT, PAGE_READWRITE);
		if (pLibRemote != NULL)
		{
			if (!WriteProcessMemory(hOProcess, pLibRemote, DLLName, 2 * wcslen(DLLName) + 1, NULL))
			{
				PAPCFUNC pAPCFuncAddr = (PAPCFUNC)GetProcAddress(GetModuleHandle(L"Kernel32"), "LoadLibraryW");
				DWORD dTid = GetTIDbyPID(ProcessID);
				if (dTid != NULL && pAPCFuncAddr != NULL)
				{
					HANDLE hoThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dTid);
					if (!QueueUserAPC(pAPCFuncAddr, hoThread, (ULONG_PTR)pLibRemote))
					{
						wprintf(L"%s\n", L"Inject sucessful!");
					}
				}
			}
		}
	}
	return 0;
}
int EnablePrivilege()
{
	//获取调试进程权限
	TOKEN_PRIVILEGES tp;
	HANDLE hToken;
	if (!LookupPrivilegeValue(NULL, SE_SECURITY_NAME, &tp.Privileges[0].Luid))
		return GetLastError();

	//Get current process's token
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
		return GetLastError();
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	//Update process tonkn privilrges
	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL))
		return GetLastError();
	CloseHandle(hToken);
	return 0;
}
_TCHAR* GetDllLocation(_TCHAR* DLLName)
{
	DWORD PathLen = GetCurrentDirectory(NULL, NULL);
	DWORD fPathLen = 2 * (PathLen + wcslen(DLLName)) + 4;
	_TCHAR* DllPath = (_TCHAR*)malloc(fPathLen);
	GetCurrentDirectory(PathLen, DllPath);
	wcscat_s(DllPath, 4, L"\\");
	wcscat_s(DllPath, wcslen(DLLName)*2, DLLName);
	return DllPath;
}