
#include <Windows.h>
#include <stdio.h>

//hash of messageboxa
#define HASH 944706740




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
		Hash = ((Hash << 5) + Hash) + c;

	return Hash;
}



FARPROC GetProcAdd(IN HMODULE hBase, IN LPCSTR lpApHash) {
	//Avoid casting
	PBYTE pPE = (PBYTE) hBase; 

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

FARPROC WINAPI GetProcAddressReplacement(HMODULE hBase, LPCSTR lpApName) {
	//Get the hash of the function name
	DWORD lpApHash = HashStringDjb2A(lpApName);
	//Get the function's address
	FARPROC pAddress = GetProcAdd(hBase, lpApHash);
	//Return the function's address
	return pAddress;
}

int main() {
	//Get the address of the function
	FARPROC pAddress = GetProcAddressReplacement(GetModuleHandleA("user32.dll"), "MessageBoxA");
	//Call the function
	((int(__stdcall*)(HWND, LPCSTR, LPCSTR, UINT))pAddress)(NULL, "Hello", "Hello", MB_OK);
	return 0;
}
