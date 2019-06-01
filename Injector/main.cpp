#include <stdio.h> 
#include <tchar.h>
#include <strsafe.h>
#include <future>
#include <thread>
#include "injection.h"

// --------------------------Named pipes windows start-------------------------
bool pipeTest = false;
#define BUFSIZE 512
DWORD WINAPI InstanceThread(LPVOID);
VOID GetAnswerToRequest(LPTSTR, LPTSTR, LPDWORD);
int startPipeServer();
// ---------------------------Named pipes windows end-----------------------
HANDLE getThreadToken();
HANDLE seDebugGetHandle(DWORD processID);
DWORD getProcessID(const char* process);
void retError(const char* str, DWORD err);
HANDLE getHandle(DWORD processID);
bool SetPrivilege(HANDLE hToken, LPCTSTR privilege, bool bEnablePrivilege);

bool seDebug = true;

// Define process name
const char szProc[] = "ac_client.exe";
//const char szProc[] = "lsass.exe";

// Define path to DLL
//const char szDllFile[] = "C:\\Users\\IEUser\\Desktop\\hashGrab.dll";
//const char szDllFile[] = "C:\\Users\\IEUser\\Desktop\\Dll_test.dll";
const char szDllFile[] = "C:\\Users\\andandersen\\Desktop\\Dll_test.dll";



int main()
{
	std::thread pipeThread;
	if (pipeTest)
	{
		pipeThread = std::thread(startPipeServer);
	}
	
	DWORD processID = getProcessID(szProc);
	HANDLE hProc = getHandle(processID);
	
	if (!ManualMap(hProc, szDllFile))
	{
		CloseHandle(hProc);
		printf("Error: ManualMap\n");
	}
	
	CloseHandle(hProc);
	pipeThread.join();
	
	system("PAUSE");
	return 0;

}

HANDLE getHandle(DWORD processID)
{
	HANDLE hProc = NULL;
	if (seDebug)
	{
		hProc = seDebugGetHandle(processID);
	}
	else
	{
		hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
		if (!hProc)
		{
			retError("OpenProcess", GetLastError());
		}
	}
	return hProc;
}

HANDLE seDebugGetHandle(DWORD processID)
{
	HANDLE hToken = getThreadToken();

	// Enable SeDebug privileges for thread
	if (!SetPrivilege(hToken, SE_DEBUG_NAME, true))
	{
		CloseHandle(hToken);
		retError("Enable SeDebug", GetLastError());
	}

	printf("Opening handle to %s\n", szProc);
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
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
	return hProc;
}

int startPipeServerTest()
{
	BOOL   fConnected = FALSE;
	DWORD  dwThreadId = 0;
	HANDLE hPipe = INVALID_HANDLE_VALUE, hThread = NULL;
	const char* lpszPipename = "\\\\.\\pipe\\mynamedpipe";

	while (true)
	{
		printf("Pipe Server : Main thread awaiting client connection on %s\n", lpszPipename);
		hPipe = CreateNamedPipe(
			lpszPipename,             // pipe name 
			PIPE_ACCESS_DUPLEX,       // read/write access 
			PIPE_TYPE_MESSAGE |       // message type pipe 
			PIPE_READMODE_MESSAGE |   // message-read mode 
			PIPE_WAIT,                // blocking mode 
			PIPE_UNLIMITED_INSTANCES, // max. instances  
			BUFSIZE,                  // output buffer size 
			BUFSIZE,                  // input buffer size 
			0,                        // client time-out 
			NULL);                    // default security attribute 

		if (hPipe == INVALID_HANDLE_VALUE)
		{
			printf("CreateNamedPipe failed, GLE=%d.\n", GetLastError());
			return -1;
		}

		// Wait for the client to connect; if it succeeds, 
		// the function returns a nonzero value. If the function
		// returns zero, GetLastError returns ERROR_PIPE_CONNECTED. 

		fConnected = ConnectNamedPipe(hPipe, NULL) ?
			TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);

		if (fConnected)
		{
			printf("Client connected, creating a processing thread.\n");

			// Create a thread for this client. 
			hThread = CreateThread(
				NULL,              // no security attribute 
				0,                 // default stack size 
				InstanceThread,    // thread proc
				(LPVOID)hPipe,    // thread parameter 
				0,                 // not suspended 
				&dwThreadId);      // returns thread ID 

			if (hThread == NULL)
			{
				printf("CreateThread failed, GLE=%d.\n", GetLastError);
				return -1;
			}
			else CloseHandle(hThread);
		}
		else
			// The client could not connect, so close the pipe. 
			CloseHandle(hPipe);
	}
	return 0;
}

int startPipeServer()
{
	// https://docs.microsoft.com/en-us/windows/desktop/ipc/multithreaded-pipe-server
	BOOL   fConnected = FALSE;
	DWORD  dwThreadId = 0;
	HANDLE hPipe = INVALID_HANDLE_VALUE, hThread = NULL;
	LPTSTR lpszPipename = (LPTSTR)TEXT("\\\\.\\pipe\\mynamedpipe");

	// The main loop creates an instance of the named pipe and 
	// then waits for a client to connect to it. When the client 
	// connects, a thread is created to handle communications 
	// with that client, and this loop is free to wait for the
	// next client connect request. It is an infinite loop.

	while(true)
	{
		_tprintf((LPTSTR)TEXT("\nPipe Server: Main thread awaiting client connection on %s\n"), lpszPipename);
		hPipe = CreateNamedPipe(
			lpszPipename,             // pipe name 
			PIPE_ACCESS_DUPLEX,       // read/write access 
			PIPE_TYPE_MESSAGE |       // message type pipe 
			PIPE_READMODE_MESSAGE |   // message-read mode 
			PIPE_WAIT,                // blocking mode 
			PIPE_UNLIMITED_INSTANCES, // max. instances  
			BUFSIZE,                  // output buffer size 
			BUFSIZE,                  // input buffer size 
			0,                        // client time-out 
			NULL);                    // default security attribute 

		if (hPipe == INVALID_HANDLE_VALUE)
		{
			_tprintf(TEXT("CreateNamedPipe failed, GLE=%d.\n"), GetLastError());
			return -1;
		}

		// Wait for the client to connect; if it succeeds, 
		// the function returns a nonzero value. If the function
		// returns zero, GetLastError returns ERROR_PIPE_CONNECTED. 

		fConnected = ConnectNamedPipe(hPipe, NULL) ?
			TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);

		if (fConnected)
		{
			printf("Client connected, creating a processing thread.\n");

			// Create a thread for this client. 
			hThread = CreateThread(
				NULL,              // no security attribute 
				0,                 // default stack size 
				InstanceThread,    // thread proc
				(LPVOID)hPipe,    // thread parameter 
				0,                 // not suspended 
				&dwThreadId);      // returns thread ID 

			if (hThread == NULL)
			{
				_tprintf(TEXT("CreateThread failed, GLE=%d.\n"), GetLastError());
				return -1;
			}
			else CloseHandle(hThread);
		}
		else
			// The client could not connect, so close the pipe. 
			CloseHandle(hPipe);
	}
	return 0;
}

DWORD WINAPI InstanceThread(LPVOID lpvParam)
// This routine is a thread processing function to read from and reply to a client
// via the open pipe connection passed from the main loop. Note this allows
// the main loop to continue executing, potentially creating more threads of
// of this procedure to run concurrently, depending on the number of incoming
// client connections.
{
	HANDLE hHeap = GetProcessHeap();
	TCHAR* pchRequest = (TCHAR*)HeapAlloc(hHeap, 0, BUFSIZE * sizeof(TCHAR));
	TCHAR* pchReply = (TCHAR*)HeapAlloc(hHeap, 0, BUFSIZE * sizeof(TCHAR));

	DWORD cbBytesRead = 0, cbReplyBytes = 0, cbWritten = 0;
	BOOL fSuccess = FALSE;
	HANDLE hPipe = NULL;

	// Do some extra error checking since the app will keep running even if this
	// thread fails.

	if (lpvParam == NULL)
	{
		printf("\nERROR - Pipe Server Failure:\n");
		printf("   InstanceThread got an unexpected NULL value in lpvParam.\n");
		printf("   InstanceThread exitting.\n");
		if (pchReply != NULL) HeapFree(hHeap, 0, pchReply);
		if (pchRequest != NULL) HeapFree(hHeap, 0, pchRequest);
		return (DWORD)-1;
	}

	if (pchRequest == NULL)
	{
		printf("\nERROR - Pipe Server Failure:\n");
		printf("   InstanceThread got an unexpected NULL heap allocation.\n");
		printf("   InstanceThread exitting.\n");
		if (pchReply != NULL) HeapFree(hHeap, 0, pchReply);
		return (DWORD)-1;
	}

	if (pchReply == NULL)
	{
		printf("\nERROR - Pipe Server Failure:\n");
		printf("   InstanceThread got an unexpected NULL heap allocation.\n");
		printf("   InstanceThread exitting.\n");
		if (pchRequest != NULL) HeapFree(hHeap, 0, pchRequest);
		return (DWORD)-1;
	}

	// Print verbose messages. In production code, this should be for debugging only.
	printf("InstanceThread created, receiving and processing messages.\n");

	// The thread's parameter is a handle to a pipe object instance. 

	hPipe = (HANDLE)lpvParam;

	// Loop until done reading
	while (1)
	{
		// Read client requests from the pipe. This simplistic code only allows messages
		// up to BUFSIZE characters in length.
		fSuccess = ReadFile(
			hPipe,        // handle to pipe 
			pchRequest,    // buffer to receive data 
			BUFSIZE * sizeof(WCHAR), // size of buffer 
			&cbBytesRead, // number of bytes read 
			NULL);        // not overlapped I/O 

		if (!fSuccess || cbBytesRead == 0)
		{
			if (GetLastError() == ERROR_BROKEN_PIPE)
			{
				_tprintf(TEXT("InstanceThread: client disconnected.\n"), GetLastError());
			}
			else
			{
				_tprintf(TEXT("InstanceThread ReadFile failed, GLE=%d.\n"), GetLastError());
			}
			break;
		}

		// Process the incoming message.
		GetAnswerToRequest(pchRequest, pchReply, &cbReplyBytes);

		// Write the reply to the pipe. 
		fSuccess = WriteFile(
			hPipe,        // handle to pipe 
			pchReply,     // buffer to write from 
			cbReplyBytes, // number of bytes to write 
			&cbWritten,   // number of bytes written 
			NULL);        // not overlapped I/O 

		if (!fSuccess || cbReplyBytes != cbWritten)
		{
			_tprintf(TEXT("InstanceThread WriteFile failed, GLE=%d.\n"), GetLastError());
			break;
		}
	}

	// Flush the pipe to allow the client to read the pipe's contents 
	// before disconnecting. Then disconnect the pipe, and close the 
	// handle to this pipe instance. 

	FlushFileBuffers(hPipe);
	DisconnectNamedPipe(hPipe);
	CloseHandle(hPipe);

	HeapFree(hHeap, 0, pchRequest);
	HeapFree(hHeap, 0, pchReply);

	printf("InstanceThread exitting.\n");
	return 1;
}

VOID GetAnswerToRequest(LPTSTR pchRequest, LPTSTR pchReply, LPDWORD pchBytes)
	// This routine is a simple function to print the client request to the console
	// and populate the reply buffer with a default data string. This is where you
	// would put the actual client request processing code that runs in the context
	// of an instance thread. Keep in mind the main thread will continue to wait for
	// and receive other client connections while the instance thread is working.
{
	_tprintf(TEXT("Client Request String:\"%s\"\n"), pchRequest);

	// Check the outgoing message to make sure it's not too long for the buffer.
	if (FAILED(StringCchCopy(pchReply, BUFSIZE, TEXT("default answer from server"))))
	{
		*pchBytes = 0;
		pchReply[0] = 0;
		printf("StringCchCopy failed, no outgoing message.\n");
		return;
	}
	*pchBytes = (lstrlen(pchReply) + 1) * sizeof(TCHAR);
}

void retError(const char* str, DWORD err)
{
	printf("Error: %s: 0x%X\n", str, err);
	system("PAUSE");
	exit(EXIT_FAILURE);
}

DWORD getProcessID(const char* process)
{
	PROCESSENTRY32 PE32{ 0 };
	PE32.dwSize = sizeof(PROCESSENTRY32); 

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE)
	{
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
	HANDLE hToken = NULL;

	// retrieve access token for thread
	if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, false, &hToken))
	{
		// If function failed because no token exists, create one
		if (GetLastError() == ERROR_NO_TOKEN)
		{
			if (!ImpersonateSelf(SecurityImpersonation))
				retError("ImpersonateSelf", GetLastError());

			if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken))
				retError("OpenThreadToken2", GetLastError());
		}
		else
			retError("OpenThreadToken1", GetLastError());
	}
	return hToken;
}

bool SetPrivilege(HANDLE hToken, LPCTSTR privilege, bool bEnablePrivilege)
{
	TOKEN_PRIVILEGES tokenPrivilege;
	LUID luid;

	// Locate the Locally Unique Identifier (LUID) That belongs 
	// to SE_DEBUG on the local system, and store it in luid
	if (!LookupPrivilegeValue(NULL, privilege, &luid))
		retError("LookupPrivilegeValue", GetLastError());

	tokenPrivilege.PrivilegeCount = 1;
	tokenPrivilege.Privileges[0].Luid = luid;

	// Enable or disable
	if (bEnablePrivilege)
		tokenPrivilege.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tokenPrivilege.Privileges[0].Attributes = 0;

	// Enable or disable privileges in specified access token.
	if(!AdjustTokenPrivileges(hToken, FALSE, &tokenPrivilege, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
		retError("AdjustTokenPrivileges", GetLastError());

	return TRUE;
}