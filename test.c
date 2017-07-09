#include <windows.h>
#pragma comment(lib, "user32")

BOOL WINAPI DllMain(HINSTANCE hInstDLL, DWORD fdwReason, LPVOID lpvReserved) {
char filename[MAX_PATH];

switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        //DisableThreadLibraryCalls((HMODULE)hInstDLL);
        GetModuleFileName(NULL, filename, sizeof(filename));
        MessageBoxA(NULL, filename, "TestDLL", MB_SYSTEMMODAL);

}

    return TRUE;

}