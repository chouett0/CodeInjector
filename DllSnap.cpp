#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>

typedef struct injectionParam {
	TCHAR szTartExe[MAX_PATH];
	TCHAR szInjectionDll[MAX_PATH];

} INJECTION_PARAM;

void InjectionDll(DWORD pid, LPCSTR dll) {
	printf("[*] ========== In InjectionDll Function========\n");
	HANDLE hProcess;
	HANDLE hThread;
	LPTHREAD_START_ROUTINE pfnLoadLibrary;
	LPVOID lpAddr;
	
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProcess == NULL) {
		printf("[!] Filed OpenProcess(%d)...\n", pid);
		return;
	}
	printf("[*] OpenProcess(%d) Success.\n", pid);
	
	lpAddr = VirtualAllocEx(hProcess, NULL, strlen(dll)+1, MEM_COMMIT, PAGE_READWRITE);
	if (lpAddr) {
		printf("[*] Alloc Virtual Address success.\n");
		if (WriteProcessMemory(hProcess, lpAddr, dll, strlen(dll), NULL)) {
			printf("[*] Write to Process success.\n");

		}
		pfnLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle("kernel32"), "LoadLibraryA");
		if (pfnLoadLibrary) {
			printf("[*] Find LoadLibraryA\n");
			hThread = CreateRemoteThread(hProcess, NULL, 0, pfnLoadLibrary, lpAddr, 0, NULL);
			if (hThread) {
				printf("Injection Dll success\n");
				WaitForSingleObject(hThread, INFINITE);
				CloseHandle(hThread);
				
			}
		
		}
		
		VirtualFreeEx(lpAddr, lpAddr, 0, MEM_RELEASE);

	}
	
	CloseHandle(hProcess);

	printf("[*] ========== End InjectionDll function =========\n");
		
}

int InjectionThread(LPVOID pParam) {
	printf("[*] ========== In InjectionThread function ==========\n");

	HANDLE hProcessSnap;
	HANDLE hProcess;
		
	INJECTION_PARAM *pInject = (INJECTION_PARAM *)pParam;
	BOOL bDetect = FALSE;

	printf("[*] szTartExe => %s\n", pInject->szTartExe);
	printf("[*] szInjectionDll => %s\n", pInject->szInjectionDll);
	
	while (1) {
		if (bDetect) {
			break;
		
		}
		
		hProcessSnap = NULL;
		PROCESSENTRY32 pe32 = {0,};
		
		hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		
		if (hProcessSnap == INVALID_HANDLE_VALUE) {
			printf("[!] Cannot Create hProcessSnap\n");
			return 1;
		
		}
		
		pe32.dwSize = sizeof(PROCESSENTRY32);
		
		if (Process32First(hProcessSnap, &pe32)) {

			do {
				if (strcmpi(pe32.szExeFile, pInject->szTartExe) == 0) {
					printf("[*] Find Target EXE.\n");
					hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
					if (hProcess) {
						printf("[*] OpenProcess(pe32.th32ProcessID[%d]) success.\n", pe32.th32ProcessID);
						InjectionDll(pe32.th32ProcessID, pInject->szInjectionDll);
						
						bDetect = TRUE;
					
					}
					
					CloseHandle(hProcess);
				}
			
			} while (Process32Next(hProcessSnap, &pe32));
		
		}
		
		CloseHandle(hProcessSnap);
		
		Sleep(500);
	
	}

    return 0;

}

int main(int argc, char *argv[]) {
    INJECTION_PARAM *pParam = new INJECTION_PARAM;
    strcpy(pParam->szTartExe, argv[1]);
    strcpy(pParam->szInjectionDll, argv[2]);
	
	printf("[*] ======================= Start Injection =========================\n");
	InjectionThread((LPVOID)pParam);
	
	printf("[*] ========================= End Injection =========================\n");
    return 0;
	
}