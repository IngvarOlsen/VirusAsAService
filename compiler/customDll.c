#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH: // When the DLL is loaded
            // Launch Notepad
            WinExec("notepad.exe", SW_SHOW);
            break;

        case DLL_PROCESS_DETACH: // When the DLL is unloaded
        case DLL_THREAD_ATTACH: // When a thread is created
        case DLL_THREAD_DETACH: // When a thread is destroyed
            break;
    }
    return TRUE;
}