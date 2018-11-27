#include "injection.h"


bool ManualMap(HANDLE hProc, const char* szDllFile)
{
	BYTE* pSrcData = nullptr;
	IMAGE_NT_HEADERS* pOldNtHeader = nullptr;
	IMAGE_OPTIONAL_HEADER* pOldOptionalHeader = nullptr;
	IMAGE_FILE_HEADER* pOldFileHeader = nullptr;
	BYTE* pTargetBase = nullptr;

	// Check if file exists
	if (!GetFileAttributesA)
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
	// 2/4 10:32
}