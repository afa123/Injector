#include "injection.h"

void __stdcall shellcode(MANUAL_MAPPING_DATA*);

bool ManualMap(HANDLE hProc, const char* szDllFile)
{
	BYTE* pSrcData = nullptr;
	IMAGE_NT_HEADERS* pOldNtHeader = nullptr;
	IMAGE_OPTIONAL_HEADER* pOldOptionalHeader = nullptr;
	IMAGE_FILE_HEADER* pOldFileHeader = nullptr;
	BYTE* pTargetBase = nullptr;

	// Check if file exists
	if (GetFileAttributesA(szDllFile) == INVALID_FILE_ATTRIBUTES)
	{
		printf("Error: File Dosen't exist: %s\n",szDllFile);
		return false;
	}

	std::ifstream File(szDllFile, std::ios_base::binary | std::ios_base::ate);
	if (File.fail())
	{
		printf("Error: Opening file: %s, ECode: %X\n", szDllFile, (DWORD)File.rdstate());
		File.close();
		return false;
	}

	auto fileSize = File.tellg();
	if (fileSize < 0x1000)
	{
		printf("Error: Filesize is invalid\n");
		File.close();
		return false;
	}

	pSrcData = new BYTE[static_cast<UINT_PTR>(fileSize)];
	if (!pSrcData)
	{
		printf("Memory allocation failed\n");
		File.close();
		return false;
	}

	File.seekg(0, std::ios_base::beg);
	File.read(reinterpret_cast<char*>(pSrcData), fileSize);
	File.close();

	// Validate that it is a correct file
	if (reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_magic != 0x5A4D) // check if MZ Field exists, change this at some point to check if its a DLL aswell
	{
		printf("Error: Couldn't find MZ field, invalid file\n");
		delete[] pSrcData; // is it neccasary to use a array delete here?
		return false;
	}

	// Get headers from pSrcData which points to base of DOS Header
	pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pSrcData + reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_lfanew);
	pOldFileHeader = &pOldNtHeader->FileHeader;
	pOldOptionalHeader = &pOldNtHeader->OptionalHeader;
	
	// Check if file matches platform
#ifdef _WIN64
	if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_AMD64)
	{
		printf("File doesn't match 64bit platform\n");
		delete[] pSrcData;
		return;
	}
#else
	if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_I386)
	{
		printf("File doesn't match 32bit platform\n");
		delete[] pSrcData;
		return;
	}
#endif // _WIN64

	// Try to allocate memory at prefered memory location
	pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(
											hProc, 
											reinterpret_cast<void*>(pOldOptionalHeader->ImageBase), 
											pOldOptionalHeader->SizeOfImage, 
											MEM_COMMIT | MEM_RESERVE, 
											PAGE_EXECUTE_READWRITE));
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
			if (!WriteProcessMemory(hProc, pTargetBase + pSectionHeader->VirtualAddress, pSrcData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr))
			{
				printf("Couldn't map sections: 0x%X\n", GetLastError());
				delete[] pSrcData;
				VirtualFreeEx(hProc, pTargetBase, "SIZE HERE" ,MEM_RELEASE); // error here !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
				return false;
			}
		}
	}
	delete[] pSrcData;
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

	auto _LoadLibrary = pData->pLoadLibraryA;
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
		// First entry of many relocation entries 3/4 10:00
		auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		while (pRelocData->VirtualAddress)
		{
			// Find number of entries 3/4 12:00
			UINT amountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
			WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);
			// Actually relocate the image 3/4 14:00

		}
	}


	
}