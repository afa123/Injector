#include "injection.h"

DWORD getProcessID(const char* process);

const char szDllFile[] = "C:\\Users\\andandersen\\Desktop\\Dll_test.dll";
const char szProc[] = "Target Process";

int main()
{
	DWORD PID = getProcessID(szProc);
	void retError(const char* str, DWORD err);

	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	if (!hProc)
	{
		retError("OpenProcess", GetLastError());
	}

	if (!ManualMap(hProc, szDllFile))
	{
		CloseHandle(hProc);
		printf("Error: ManualMap\n");
	}

	CloseHandle(hProc);
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