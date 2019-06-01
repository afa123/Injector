#include "injection.h"

// Macro which defines the Relocation flag based on OS
#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN63
#define RELOC_FLAG RELOC_FLAG65
#else
#define RELOC_FLAG RELOC_FLAG32
#endif



bool ManualMap(HANDLE hProc, const char* szDllFile)
{
	BYTE* pSrcData = nullptr;
	IMAGE_NT_HEADERS* pOldNtHeader = nullptr;
	IMAGE_OPTIONAL_HEADER* pOldOptionalHeader = nullptr;
	IMAGE_FILE_HEADER* pOldFileHeader = nullptr;
	BYTE* pTargetBase = nullptr;
	bool ntCreateThread = true;

	// Load file into memory
	pSrcData = getFile(szDllFile);

	// Validate that it is a PE File
	if (reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_magic != 0x5A4D) // check if MZ Field exists
	{
		printf("Error: Couldn't find MZ field, invalid file\n");
		delete[] pSrcData;
		return false;
	}

	// Get headers from pSrcData which points to base of DOS Header
	pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pSrcData + reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_lfanew);
	pOldFileHeader = &pOldNtHeader->FileHeader;
	pOldOptionalHeader = &pOldNtHeader->OptionalHeader;

	/*
	// Validate that it is a DLL
	if (reinterpret_cast<IMAGE_FILE_HEADER*>(pOldFileHeader)->Characteristics != IMAGE_FILE_DLL)
	{
		printf("Error: Characteristics != IMAGE_FILE_DLL, File is not a Dll\n");
		delete[] pSrcData;
		return false;
	}
	*/
	// Check if file matches platform
#ifdef _WIN64
	if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_AMD64)
	{
		printf("File doesn't match 64bit platform\n");
		delete[] pSrcData;
		return false;
	}
#else
	if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_I386)
	{
		printf("File doesn't match 32bit platform\n");
		delete[] pSrcData;
		return false;
	}
#endif // _WIN64

	// Try to allocate memory at prefered memory location
	pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(
											hProc, 
											reinterpret_cast<void*>(pOldOptionalHeader->ImageBase), 
											pOldOptionalHeader->SizeOfImage, 
											MEM_COMMIT | MEM_RESERVE, 
											PAGE_EXECUTE_READWRITE));
	printf("Address of data: 0x%X");
	if (!pTargetBase)
	{	// Failed to allocate memory at prefered location, try to allocate at random location instead
		pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(
												hProc,
												nullptr,
												pOldOptionalHeader->SizeOfImage,
												MEM_COMMIT | MEM_RESERVE,
												PAGE_EXECUTE_READWRITE));
		if (!pTargetBase)
		{
			printf("Failed to allocate memory for file in target process\n");
			delete[] pSrcData;
			return false;
		}
	}
	MANUAL_MAPPING_DATA data{ 0 };
	data.pLoadLibraryA = LoadLibraryA;
	data.pGetProcAddress = reinterpret_cast<f_GetProcAddress>(GetProcAddress);

	auto* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
	for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader)
	{
		if (pSectionHeader->PointerToRawData)
		{
			// Write sections to the allocated memory
			if (!WriteProcessMemory(hProc, pTargetBase + pSectionHeader->VirtualAddress, pSrcData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr))
			{
				printf("Couldn't map sections: 0x%X\n", GetLastError());
				delete[] pSrcData;
				VirtualFreeEx(hProc, pTargetBase, 0 ,MEM_RELEASE); 
				return false;
			}
		}
	}

	memcpy(pSrcData, &data, sizeof(data));

	// write MANUAL_MAPPING_DATA struct to allocated memory 4/4 18:30
	WriteProcessMemory(hProc, pTargetBase, pSrcData, 0x1000, nullptr);

	delete[] pSrcData;

	// Allocate 0x1000 bytes for the shellcode function in target process
	void* pShellcode = VirtualAllocEx(hProc, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pShellcode)
	{
		printf("Error: Memory allocation for shellcode function failed, 0x%X\n", GetLastError());
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		return false;
	}

	// Write shellcode into target process memory
	WriteProcessMemory(hProc, pShellcode, shellcode, 0x1000, nullptr);

	printf("Start Thread\n");
	if (ntCreateThread)
	{
		// NtCreateThread here
		HANDLE hThread = nullptr;
		auto p_NtCreateThreadEx = reinterpret_cast<f_NtCreateThreadEx>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx"));
		if (!p_NtCreateThreadEx)
		{
			printf("Error: failed getting function address for NtCreateThread, 0x%X\n", GetLastError());
			VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
			VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
			return false;
		}

		printf("shellcode is located at: 0x%X\n", pShellcode);
		p_NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, nullptr, hProc, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode), pTargetBase, NULL, 0, 0, 0, nullptr);
		if (hThread == nullptr)
		{
			printf("Error: failed starting thread with NtCreateThread, 0x%X\n", GetLastError());
			VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
			VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
			return false;
		}
	}
	else
	{
		// Create thread with start address at pShellcode
		HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode), pTargetBase, 0, nullptr);
		if (!hThread)
		{
			printf("Error: Failed to create thread at pShellcode, 0x%X\n", GetLastError());
			VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
			VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
			return false;
		}
		CloseHandle(hThread);
	}
	
	// check if shellcode has finished
	HINSTANCE hCheck = NULL;
	while (!hCheck)
	{
		MANUAL_MAPPING_DATA data_checked{ 0 };
		ReadProcessMemory(hProc, pTargetBase, &data_checked, sizeof(data_checked), nullptr);
		hCheck = data_checked.hMod; // 4/4 20:50
		Sleep(10);
	}
	VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);

	return true;
}

void __stdcall shellcode(MANUAL_MAPPING_DATA* pData)
{
	// pData is a pointer to our baseAddress openmodule and contain the data we need for relocation etc. 3/4 4:40
	if (!pData)
	{
		return;
	}
	BYTE* pBase = reinterpret_cast<BYTE*>(pData);
	auto* pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>(pData)->e_lfanew)->OptionalHeader;

	auto _LoadLibraryA = pData->pLoadLibraryA;
	auto _GetProcAddress = pData->pGetProcAddress;
	auto _DllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(pBase + pOpt->AddressOfEntryPoint);

	// Relocation, if located at preferred image base, then there's no need to relocate
	BYTE* locationDelta = pBase - pOpt->ImageBase;
	if (locationDelta)
	{
		// Check if it's possible to relocate the image, flag can be specified to disable this during compilation
		if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size == 0)
		{
			return;
		}
		// First entry of many relocation entries
		auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		while (pRelocData->VirtualAddress)
		{
			// Find number of entries
			UINT amountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
			WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);
			// Actually relocate the image 
			for (UINT i = 0; i != amountOfEntries; ++i, ++pRelativeInfo)
			{
				// Check for relocation bit using macro
				if (RELOC_FLAG(*pRelativeInfo))
				{
					UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
					*pPatch += reinterpret_cast<UINT_PTR>(locationDelta); 
				}
			}
			
			pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
		}
	}

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
	{
		auto* pImportDescriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (pImportDescriptor->Name)
		{
			 // Get name of currently loaded module
			char* szMod = reinterpret_cast<char*>(pBase + pImportDescriptor->Name);
			
			// Load import
			HINSTANCE hDll = _LoadLibraryA(szMod);

			ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescriptor->OriginalFirstThunk);
			ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescriptor->FirstThunk);

			// Add check to see if original firstthunk is defined
			if (!pThunkRef)
				pThunkRef = pFuncRef;

			// Loop through the references
			for (; *pThunkRef; ++pThunkRef, ++pFuncRef)
			{
				// two ways for functions to be stored which is by name or by ordinal number
				if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef))
				{
					// Get by Ordinal                         Ordinal number is stored at pThunkRef
					*pFuncRef = _GetProcAddress(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF));
				}
				else
				{
					// Grab pointer to the image import by name structure
					auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef));

					*pFuncRef = _GetProcAddress(hDll, pImport->Name);
				}
			}
			++pImportDescriptor;
		}
		// TLS CALLBACKS
		if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) // If not 0, we have to do TLS callbacks
		{
			auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
			auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
			
			for (; pCallback && *pCallback; ++pCallback)
			{
				(*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
			}
		}
		// call dll main
		_DllMain(pBase, DLL_PROCESS_ATTACH, nullptr);

		
		pData->hMod = reinterpret_cast<HINSTANCE>(pBase);
	}
	
}

BYTE* getFile(const char* szDllFile)
{

	// Check if file exists
	if (GetFileAttributesA(szDllFile) == INVALID_FILE_ATTRIBUTES)
	{
		printf("Error: File Dosen't exist: %s\n", szDllFile);
		exit(-1);
	}

	std::ifstream File(szDllFile, std::ios_base::binary | std::ios_base::ate);
	if (File.fail())
	{
		printf("Error: Opening file: %s, ECode: %X\n", szDllFile, (DWORD)File.rdstate());
		File.close();
		exit(-1);
	}

	auto fileSize = File.tellg();
	if (fileSize < 0x1000)
	{
		printf("Error: Filesize is invalid\n");
		File.close();
		exit(-1);
	}

	BYTE* pSrcData = new BYTE[static_cast<UINT_PTR>(fileSize)];
	if (!pSrcData)
	{
		printf("Memory allocation failed\n");
		File.close();
		exit(-1);
	}

	File.seekg(0, std::ios_base::beg);
	File.read(reinterpret_cast<char*>(pSrcData), fileSize);
	File.close();

	return pSrcData;
}