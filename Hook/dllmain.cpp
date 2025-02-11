// dllmain.cpp : DLL アプリケーションのエントリ ポイントを定義します。
#include "pch.h"

#define HOOK_EXPORTS__
#include "Hook.h"

#include <Windows.h>
#include <stdio.h>




HHOOK hHook = NULL;
HINSTANCE hInstance = NULL;
CallbackFunc g_callback = NULL;

void Print(const wchar_t* format, ...) {
    wchar_t str[256];
	va_list args;
	va_start(args, format);
	vswprintf_s(str, format, args);
	OutputDebugString(str);
	va_end(args);
}

void SetCallback(CallbackFunc callback) {
	g_callback = callback;
	Hook::SetHook();
}

LRESULT CALLBACK CallWndProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION) {
        CWPSTRUCT* pCwp = (CWPSTRUCT*)lParam;
        Print(L"window: 0x%08X\n", (int)pCwp->hwnd);
        if (pCwp->message == WM_SETFOCUS && g_callback) {
            Print(L"WM_SETFOCUS received by window: 0x%08X\n", (int)pCwp->hwnd);
            g_callback(TRUE);
        }
        else if (pCwp->message == WM_KILLFOCUS && g_callback) {
            Print(L"WM_KILLFOCUS received by window: 0x%08X\n", (int)pCwp->hwnd);
            g_callback(FALSE);
        }
    }
    return CallNextHookEx(hHook, nCode, wParam, lParam);
}

void Hook::SetHook() {
    hHook = SetWindowsHookEx(WH_CALLWNDPROC, CallWndProc, hInstance, 0);
    if (!hHook) {
        const int size = 100;
        wchar_t str[size];
        DWORD dw = GetLastError();
        if (!FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM,
            0,
            dw,
            0,
            str,
            size,
            0)) {
            swprintf_s(str, size, L"Failed to install hook!: %#010x", dw);
        }
        MessageBox(NULL, (LPCWSTR)str, L"Error", MB_ICONERROR);
    }
}

void Hook::Unhook() {
    if (hHook != NULL) {
        UnhookWindowsHookEx(hHook);
        hHook = NULL;
    }
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		hInstance = hModule;
		Print(L"Hook DLL loaded\n");
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
		Hook::Unhook();
        break;
    }
    return TRUE;
}