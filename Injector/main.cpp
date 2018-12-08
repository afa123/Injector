#include "injection.h"

DWORD getProcessID(const char* process);
void retError(const char* str, DWORD err);
HANDLE getThreadToken();
bool SetPrivilege(HANDLE hToken, LPCTSTR privilege, bool bEnablePrivilege);

const char szDllFile[] = "C:\\Users\\IEUser\\Desktop\\Dll_test.dll";
const char szProc[] = "lsass.exe";
//const char szDllFile[] = "C:\\Users\\andandersen\\Desktop\\Dll_test.dll";
//const char szProc[] = "ac_client.exe";

int main()
{
	DWORD PID = getProcessID(szProc);
	HANDLE hToken = getThreadToken();

	// Enable SeDebug privileges for thread
	if (!SetPrivilege(hToken, SE_DEBUG_NAME, true))
	{
		CloseHandle(hToken);
		retError("Enable SeDebug", GetLastError());
	}

	printf("Opening handle to %s\n", szProc);
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	if (!hProc)
	{
		CloseHandle(hToken);
		retError("OpenProcess", GetLastError());
	}
	printf("Handle: 0x%X\n", hProc);

	// Disable SeDebug privileges for thread
	if (!SetPrivilege(hToken, SE_DEBUG_NAME, false))
	{
		CloseHandle(hToken);
		retError("Disable SeDebug", GetLastError());
	}
	CloseHandle(hToken);

	if (!ManualMap(hProc, szDllFile))
	{
		CloseHandle(hProc);
		printf("Error: ManualMap\n");
	}
	
	CloseHandle(hProc);
	system("PAUSE");
	return 0;
}

void retError(const char* str, DWORD err)
{
	printf("Error: %s: 0x%X\n", str, err);
	system("PAUSE");
	exit(-1);
}

DWORD getProcessID(const char* process)
{
	PROCESSENTRY32 PE32{ 0 };
	PE32.dwSize = sizeof(PROCESSENTRY32); // 1/4 12:00 migth need to change this

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE)
	{
		// Should i close handle here??? 
		retError("CreateToolhelp32Snapshot", GetLastError());
	}

	// Optimize this function
	DWORD PID = NULL;
	BOOL bRet = Process32First(hSnap, &PE32);
	while (bRet)
	{
		if (!strcmp(szProc, PE32.szExeFile))
		{
			PID = PE32.th32ProcessID;
			break;
		}
		bRet = Process32Next(hSnap, &PE32);
	}
	CloseHandle(hSnap);
	return PID;
}

HANDLE getThreadToken()
{
	HANDLE hToken;

	// https://docs.microsoft.com/en-us/windows/desktop/secauthz/access-rights-for-access-token-objects
	// retrieve thread token
	if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, false, &hToken))
	{
		// If function failed because no token exists, create one
		if (GetLastError() == ERROR_NO_TOKEN)
		{
			if (!ImpersonateSelf(SecurityImpersonation))
				retError("ImpersonateSelf", GetLastError());

			if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken)) {
				retError("OpenThreadToken2", GetLastError());
			}
		}
		else
			retError("OpenThreadToken1", GetLastError());
	}
	return hToken;
}

bool SetPrivilege(HANDLE hToken, LPCTSTR privilege, bool bEnablePrivilege)
{
	// https://support.microsoft.com/en-us/help/131065/how-to-obtain-a-handle-to-any-process-with-sedebugprivilege
	TOKEN_PRIVILEGES tp;
	LUID luid;
	TOKEN_PRIVILEGES tpPrevious;
	DWORD cbPrevious = sizeof(TOKEN_PRIVILEGES);

	if (!LookupPrivilegeValue(NULL, privilege, &luid)) 
		retError("SetPrivilege1", GetLastError());

	// 
	// first pass.  get current privilege setting
	// 
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = 0;

	AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		&tpPrevious,
		&cbPrevious
	);

	if (GetLastError() != ERROR_SUCCESS) 
		retError("SetPrivilege2", GetLastError());

	// 
	// second pass.  set privilege based on previous setting
	// 
	tpPrevious.PrivilegeCount = 1;
	tpPrevious.Privileges[0].Luid = luid;

	if (bEnablePrivilege) {
		tpPrevious.Privileges[0].Attributes |= (SE_PRIVILEGE_ENABLED);
	}
	else {
		tpPrevious.Privileges[0].Attributes ^= (SE_PRIVILEGE_ENABLED &
			tpPrevious.Privileges[0].Attributes);
	}

	AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tpPrevious,
		cbPrevious,
		NULL,
		NULL
	);

	if (GetLastError() != ERROR_SUCCESS) 
		retError("SetPrivilege3", GetLastError());

	return TRUE;
}