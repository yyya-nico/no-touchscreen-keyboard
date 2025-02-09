// dllmain.cpp : DLL アプリケーションのエントリ ポイントを定義します。
#include "pch.h"
#include "Hook.h"
#include <Windows.h>
#include <stdio.h>

#define DLLEXPORT extern "C" __declspec(dllexport)

typedef void (*CallbackFunc)(BOOL isFocus);

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

//LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
//    if (nCode == HC_ACTION) {
//        CWPSTRUCT* pCwp = (CWPSTRUCT*)lParam;
//		if (wParam == WM_SETFOCUS && g_callback) {
//            Print(L"WM_SETFOCUS received by window: 0x%08X\n", (int)pCwp->hwnd);
//			g_callback(TRUE);
//		}
//		else if (wParam == WM_KILLFOCUS && g_callback) {
//            Print(L"WM_KILLFOCUS received by window: 0x%08X\n", (int)pCwp->hwnd);
//			g_callback(FALSE);
//        }
//    }
//    return CallNextHookEx(hHook, nCode, wParam, lParam);
//}

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

extern "C" __declspec(dllexport) void SetHook(CallbackFunc callback) {
	g_callback = callback;
    //hHook = SetWindowsHookEx(WH_KEYBOARD, KeyboardProc, hInstance, 0);
    hHook = SetWindowsHookEx(WH_CALLWNDPROC, CallWndProc, hInstance, 0);
    if (!hHook) {
        DWORD error = GetLastError();
        Print(L"Failed to set hook. Error code: %lu\n", error);
    }
}

extern "C" __declspec(dllexport) void Unhook() {
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
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}