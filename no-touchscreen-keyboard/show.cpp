// https://stackoverflow.com/questions/38774139/show-touch-keyboard-tabtip-exe-in-windows-10-anniversary-edition/40921638#40921638

#include <windows.h> 
#include <assert.h> 

#include <shellapi.h>
#include <strsafe.h>

#include <shlwapi.h> 
#include <stdio.h>
#include <tlhelp32.H>
#include <dwmapi.h>
#include <Psapi.h>

#include <initguid.h>
#include <Objbase.h>

#include <UIAutomation.h>
#include <wrl/client.h>

using namespace Microsoft::WRL;

#pragma hdrstop

// 4ce576fa-83dc-4F88-951c-9d0782b4e376
DEFINE_GUID(CLSID_UIHostNoLaunch, 0x4CE576FA, 0x83DC, 0x4f88, 0x95, 0x1C, 0x9D, 0x07, 0x82, 0xB4, 0xE3, 0x76);

// 37c994e7_432b_4834_a2f7_dce1f13b834b
DEFINE_GUID(IID_ITipInvocation, 0x37c994e7, 0x432b, 0x4834, 0xa2, 0xf7, 0xdc, 0xe1, 0xf1, 0x3b, 0x83, 0x4b);
#pragma once

#include <winternl.h>
#include <winnt.h>

#define STATUS_SUCCESS              ((NTSTATUS) 0x00000000)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS) 0xC0000004)

enum KWAIT_REASON
{
    Executive,
    FreePage,
    PageIn,
    PoolAllocation,
    DelayExecution,
    Suspended,
    UserRequest,
    WrExecutive,
    WrFreePage,
    WrPageIn,
    WrPoolAllocation,
    WrDelayExecution,
    WrSuspended,
    WrUserRequest,
    WrEventPair,
    WrQueue,
    WrLpcReceive,
    WrLpcReply,
    WrVirtualMemory,
    WrPageOut,
    WrRendezvous,
    Spare2,
    Spare3,
    Spare4,
    Spare5,
    Spare6,
    WrKernel,
    MaximumWaitReason
};

enum THREAD_STATE
{
    Running = 2,
    Waiting = 5,
};

#pragma pack(push,8)

#ifndef _WINTERNL_
struct CLIENT_ID
{
    HANDLE UniqueProcess; // Process ID
    HANDLE UniqueThread;  // Thread ID
};
#endif

// http://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/thread.htm
// Size = 0x40 for Win32
// Size = 0x50 for Win64
struct SYSTEM_THREAD
{
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;  
    LARGE_INTEGER CreateTime;
    ULONG         WaitTime;
    PVOID         StartAddress;
    CLIENT_ID     ClientID;           // process/thread ids
    LONG          Priority;
    LONG          BasePriority;
    ULONG         ContextSwitches;
    THREAD_STATE  ThreadState;
    KWAIT_REASON  WaitReason;
};

struct VM_COUNTERS // virtual memory of process
{
    ULONG_PTR PeakVirtualSize;
    ULONG_PTR VirtualSize;
    ULONG     PageFaultCount;
    ULONG_PTR PeakWorkingSetSize;
    ULONG_PTR WorkingSetSize;
    ULONG_PTR QuotaPeakPagedPoolUsage;
    ULONG_PTR QuotaPagedPoolUsage;
    ULONG_PTR QuotaPeakNonPagedPoolUsage;
    ULONG_PTR QuotaNonPagedPoolUsage;
    ULONG_PTR PagefileUsage;
    ULONG_PTR PeakPagefileUsage;
};

// http://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/process.htm
// See also SYSTEM_PROCESS_INROMATION in Winternl.h
// Size = 0x00B8 for Win32
// Size = 0x0100 for Win64
struct SYSTEM_PROCESS
{
    ULONG          NextEntryOffset; // relative offset
    ULONG          ThreadCount;
    LARGE_INTEGER  WorkingSetPrivateSize;
    ULONG          HardFaultCount;
    ULONG          NumberOfThreadsHighWatermark;
    ULONGLONG      CycleTime;
    LARGE_INTEGER  CreateTime;
    LARGE_INTEGER  UserTime;  
    LARGE_INTEGER  KernelTime;
    UNICODE_STRING ImageName;
    LONG           BasePriority;
    PVOID          UniqueProcessId;
    PVOID          InheritedFromUniqueProcessId;
    ULONG          HandleCount;
    ULONG          SessionId;
    ULONG_PTR      UniqueProcessKey;
    VM_COUNTERS    VmCounters;
    ULONG_PTR      PrivatePageCount;
    IO_COUNTERS    IoCounters;   // defined in winnt.h
};

#pragma pack(pop)

typedef NTSTATUS (WINAPI* t_NtQueryInfo)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);

void Print(const wchar_t* format, ...) {
    wchar_t str[256];
    va_list args;
    va_start(args, format);
	vswprintf_s(str, format, args);
    OutputDebugString(str);
    va_end(args);
}

class cProcInfo
{
public:
    cProcInfo()
    {
        #ifdef WIN64
            assert(sizeof(SYSTEM_THREAD) == 0x50 && sizeof(SYSTEM_PROCESS) == 0x100);
        #else
            assert(sizeof(SYSTEM_THREAD) == 0x40 && sizeof(SYSTEM_PROCESS) == 0xB8);
        #endif

        mu32_DataSize  = 1000;
        mp_Data        = NULL;
        mf_NtQueryInfo = NULL;
    }
    virtual ~cProcInfo()
    {
        if (mp_Data) LocalFree(mp_Data);
    }

    // Capture all running processes and all their threads.
    // returns an API or NTSTATUS Error code or zero if successfull
    DWORD Capture()
    {
        if (!mf_NtQueryInfo)
        {
            mf_NtQueryInfo = (t_NtQueryInfo)GetProcAddress(GetModuleHandleA("NtDll.dll"), "NtQuerySystemInformation");
            if (!mf_NtQueryInfo)
                return GetLastError();
        }

        // This must run in a loop because in the mean time a new process may have started 
        // and we need more buffer than u32_Needed !!
        while (true)
        {
            if (!mp_Data) 
            {
                mp_Data = (BYTE*)LocalAlloc(LMEM_FIXED, mu32_DataSize);
                if (!mp_Data)
                    return GetLastError();
            }

            ULONG u32_Needed = 0;
            NTSTATUS s32_Status = mf_NtQueryInfo(SystemProcessInformation, mp_Data, mu32_DataSize, &u32_Needed);

            if (s32_Status == STATUS_INFO_LENGTH_MISMATCH) // The buffer was too small
            {
                mu32_DataSize = u32_Needed + 4000;
                LocalFree(mp_Data);
                mp_Data = NULL;
                continue;
            }
            return s32_Status;
        }
    }

    // Searches a process by a given Process Identifier
    // Capture() must have been called before!
    SYSTEM_PROCESS* FindProcessByPid(DWORD u32_PID)
    {
        if (!mp_Data)
        {
            assert(mp_Data);
            return NULL;
        }

        SYSTEM_PROCESS* pk_Proc = (SYSTEM_PROCESS*)mp_Data;
        while (TRUE)
        {
            if ((DWORD)(DWORD_PTR)pk_Proc->UniqueProcessId == u32_PID)
                return pk_Proc;

            if (!pk_Proc->NextEntryOffset)
                return NULL;

            pk_Proc = (SYSTEM_PROCESS*)((BYTE*)pk_Proc + pk_Proc->NextEntryOffset);
        }
    }

    SYSTEM_THREAD* FindThreadByTid(SYSTEM_PROCESS* pk_Proc, DWORD u32_TID)
    {
        if (!pk_Proc)
        {
            assert(pk_Proc);
            return NULL;
        }

        // The first SYSTEM_THREAD structure comes immediately after the SYSTEM_PROCESS structure
        SYSTEM_THREAD* pk_Thread = (SYSTEM_THREAD*)((BYTE*)pk_Proc + sizeof(SYSTEM_PROCESS));

        for (DWORD i=0; i<pk_Proc->ThreadCount; i++)
        {
            if (pk_Thread->ClientID.UniqueThread == (HANDLE)(DWORD_PTR)u32_TID)
                return pk_Thread;

            pk_Thread++;
        }
        return NULL;
    }

    BOOL IsThreadSuspended(SYSTEM_THREAD* pk_Thread)
    {
        return (pk_Thread->ThreadState == Waiting &&
                pk_Thread->WaitReason  == Suspended);
    }

    BOOL HasSuspendedThreads(SYSTEM_PROCESS* pk_Proc) {
        if (!pk_Proc)
        {
            assert(pk_Proc);
            return FALSE;
        }


        // The first SYSTEM_THREAD structure comes immediately after the SYSTEM_PROCESS structure
        SYSTEM_THREAD* pk_Thread = (SYSTEM_THREAD*)((BYTE*)pk_Proc + sizeof(SYSTEM_PROCESS));

        DWORD totalNumber = pk_Proc->ThreadCount;
        DWORD suspended = 0;
        

        for (DWORD i=0; i<pk_Proc->ThreadCount; i++)
        {
            BOOL isSuspended = this->IsThreadSuspended(pk_Thread);

            Print(L"Thread %d/%d. Suspended %d\n", i+1, totalNumber, isSuspended);
            
            if( isSuspended ) {
              suspended ++;
            }

            pk_Thread++;
        }

        return suspended > 0 ? TRUE : FALSE;
    }

private:
    BYTE*         mp_Data;
    DWORD       mu32_DataSize;
    t_NtQueryInfo mf_NtQueryInfo;
};

// Based on the 32 bit code of Sven B. Schreiber on:
// http://www.informit.com/articles/article.aspx?p=22442&seqNum=5
int HasSuspendedThreads(DWORD processID) {
    cProcInfo c;
    c.Capture();
    auto process = c.FindProcessByPid(processID);
    return c.HasSuspendedThreads(process);
}

int IsRunningAndNotSuspended(const WCHAR *nameOfExecutable)
{
  int foundExecutable = FALSE;
  int hasSuspendedThreads = FALSE;

  HANDLE PIDs;
  PROCESSENTRY32W aPID = { sizeof aPID };
  
  PIDs = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  Process32First(PIDs, &aPID);
  
  for (;;) {
    foundExecutable = !StrCmpI(aPID.szExeFile, nameOfExecutable);

    if (foundExecutable) {
      Print(L"Found %s\n", nameOfExecutable);
      hasSuspendedThreads |= HasSuspendedThreads(aPID.th32ProcessID);
      break;
    }

    if (!Process32Next(PIDs, &aPID)) {
      break;
    }
  }

  CloseHandle(PIDs);

  return foundExecutable && !hasSuspendedThreads;
}

struct ITipInvocation : IUnknown
{
    virtual HRESULT STDMETHODCALLTYPE Toggle(HWND wnd) = 0;
};

BOOL KeyboardVisible() {
  LPCWSTR WINDOW_PARENT_CLASS = L"ApplicationFrameWindow";
  LPCWSTR WINDOW_CLASS = L"Windows.UI.Core.CoreWindow";
  LPCWSTR MODULE_NAME = L"TextInputHost.exe";

  HWND parent = NULL;

  for (;;) {
    parent = FindWindowEx(NULL, parent, WINDOW_PARENT_CLASS, NULL);

    if (!parent) {
      Print(L"Unknown keyboard state. Could not find window\n");
      break;
    }

    HWND window = FindWindowEx(parent, NULL, WINDOW_CLASS, NULL);

    if (window) {
      DWORD processId;
      GetWindowThreadProcessId(window, &processId);
      HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
      if (hProcess) {
        HMODULE hMod;
        DWORD cbNeeded;
        if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
          WCHAR szModName[MAX_PATH];
          if (GetModuleBaseName(hProcess, hMod, szModName, sizeof(szModName) / sizeof(WCHAR))) {
            if (wcscmp(szModName, MODULE_NAME) == 0) {
              CloseHandle(hProcess);
              int cloaked = 0;
              if (DwmGetWindowAttribute(window, DWMWA_CLOAKED, &cloaked, sizeof(cloaked)) == S_OK && cloaked == 0) {
                Print(L"Keyboard is visible\n");
                return TRUE;
              }
              break;
            }
          }
        }
        CloseHandle(hProcess);
      }
    }
  }

  Print(L"Keyboard is not visible\n");
  return FALSE;
}

BOOL KeyboardVisibleLegacy(BOOL* pVisible) {
  LPCWSTR WINDOW_CLASS = L"IPTip_Main_Window";

  HWND window = FindWindowEx(NULL, NULL, WINDOW_CLASS, NULL);

  if (!window) {
    return FALSE;
  }

  if (IsWindowVisible(window) && IsWindowEnabled(window)) {
    *pVisible = TRUE;
    return TRUE;
  } 
   
  unsigned int style = (unsigned int)GetWindowLong(window, GWL_STYLE);
  
  BOOL isVisible = (style & WS_VISIBLE) == WS_VISIBLE;
  BOOL isDisabled = (style & WS_DISABLED) == WS_DISABLED;

  if (isVisible || !isDisabled) {
    *pVisible = FALSE;
    return TRUE;
  }

  // DWM Window can be cloaked
  // see https://social.msdn.microsoft.com/Forums/vstudio/en-US/f8341376-6015-4796-8273-31e0be91da62/difference-between-actually-visible-and-not-visiblewhich-are-there-but-we-cant-see-windows-of?forum=vcgeneral
  int cloaked;
  
  if (DwmGetWindowAttribute(window, DWMWA_CLOAKED, &cloaked, 4) == 0)
  {
    if (cloaked == 0)
    {
        *pVisible = TRUE;
        return TRUE;
    }
  }

  *pVisible = FALSE;

  return TRUE;
}

ITipInvocation* tip;
HWND hwnd;

void onFocus() {
  BOOL isVisible = FALSE;
  BOOL showIt = TRUE;
  if (KeyboardVisible()) {
    showIt = FALSE;
  }
  if (KeyboardVisibleLegacy(&isVisible)) {
    showIt = !isVisible;
  } else if (!IsRunningAndNotSuspended(L"WindowsInternal.ComposableShell.Experiences.TextInput.InputApp.exe")) {
    showIt = TRUE;
  }
  if (showIt) {
    tip->Toggle(hwnd);
    Print(L"Keyboard shown\n");
  }
}

void onBlur() {
  BOOL isVisible = FALSE;
  BOOL hideIt = FALSE;
  if (KeyboardVisible()) {
    hideIt = TRUE;
  } else if (KeyboardVisibleLegacy(&isVisible)) {
    hideIt = isVisible;
  } else if (IsRunningAndNotSuspended(L"WindowsInternal.ComposableShell.Experiences.TextInput.InputApp.exe")) {
    hideIt = TRUE;
  }
  if (hideIt) {
    tip->Toggle(hwnd);
    Print(L"Keyboard hidden\n");
  }
}

void FocusCallback(BOOL isFocus) {
	if (isFocus) {
		onFocus();
	}
	else {
		onBlur();
	}
}

ComPtr<IUIAutomation> pAutomation;

HRESULT InitializeUIAutomation() {
    return CoCreateInstance(CLSID_CUIAutomation, NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pAutomation));
}

class FocusChangedEventHandler : public IUIAutomationFocusChangedEventHandler {
public:
    FocusChangedEventHandler() : refCount(1) {}

    // IUnknown methods
    ULONG STDMETHODCALLTYPE AddRef() {
        return InterlockedIncrement(&refCount);
    }

    ULONG STDMETHODCALLTYPE Release() {
        ULONG count = InterlockedDecrement(&refCount);
        if (count == 0) {
            delete this;
        }
        return count;
    }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppvObject) {
        if (riid == IID_IUnknown || riid == IID_IUIAutomationFocusChangedEventHandler) {
            *ppvObject = static_cast<IUIAutomationFocusChangedEventHandler*>(this);
            AddRef();
            return S_OK;
        }
        *ppvObject = NULL;
        return E_NOINTERFACE;
    }

    // IUIAutomationFocusChangedEventHandler method
    HRESULT STDMETHODCALLTYPE HandleFocusChangedEvent(IUIAutomationElement* sender) {
		BSTR controlType;
		sender->get_CurrentLocalizedControlType(&controlType);
		if (wcscmp(controlType, L"edit") == 0) {
			FocusCallback(TRUE);
		} else {
			FocusCallback(FALSE);
		}
        return S_OK;
    }

private:
    LONG refCount;
};

HRESULT RegisterFocusChangedEventHandler() {
    ComPtr<IUIAutomationFocusChangedEventHandler> pHandler = new FocusChangedEventHandler();
    return pAutomation->AddFocusChangedEventHandler(NULL, pHandler.Get());
}

LRESULT CALLBACK WindowProc(HWND trayHwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_USER + 1:
        if (lParam == WM_RBUTTONUP || lParam == WM_LBUTTONUP) {
            POINT pt;
            GetCursorPos(&pt);
            SetForegroundWindow(trayHwnd);
            HMENU hMenu = CreatePopupMenu();
            AppendMenu(hMenu, MF_STRING, WM_CLOSE, L"Exit(&X)");
            TrackPopupMenu(hMenu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, trayHwnd, NULL);
            DestroyMenu(hMenu);
        }
        break;
    case WM_COMMAND:
        if (LOWORD(wParam) == WM_CLOSE) {
            PostQuitMessage(0);
        }
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(trayHwnd, uMsg, wParam, lParam);
    }
    return 0;
}

int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int)
{
  HRESULT hr = CoInitialize(0);
  hr = CoCreateInstance(CLSID_UIHostNoLaunch, 0, CLSCTX_INPROC_HANDLER | CLSCTX_LOCAL_SERVER, IID_ITipInvocation, (void**)&tip);
  hwnd = GetDesktopWindow();

  HRESULT hr2 = CoInitialize(NULL);
  if (FAILED(hr2)) {
      return 1;
  }

  hr2 = InitializeUIAutomation();
  if (FAILED(hr2)) {
      CoUninitialize();
      return 1;
  }

  hr2 = RegisterFocusChangedEventHandler();
  if (FAILED(hr2)) {
      CoUninitialize();
      return 1;
  }

  WNDCLASS wc = { 0 };
  wc.lpfnWndProc = WindowProc;
  wc.hInstance = hInstance;
  wc.lpszClassName = L"TrayWindowClass";
  RegisterClass(&wc);

  HWND trayHwnd = CreateWindowEx(0, L"TrayWindowClass", L"Tray", 0, 0, 0, 0, 0, NULL, NULL, hInstance, NULL);

  NOTIFYICONDATA nid;
  ZeroMemory(&nid, sizeof(nid));
  nid.cbSize = sizeof(NOTIFYICONDATA);
  nid.hWnd = trayHwnd;
  nid.uID = 1;
  nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
  nid.uCallbackMessage = WM_USER + 1;
  nid.hIcon = LoadIcon(NULL, IDI_APPLICATION);
  wcscpy_s(nid.szTip, L"No Touchscreen Keyboard");

  Shell_NotifyIcon(NIM_ADD, &nid);

  MSG msg;
  while (GetMessage(&msg, NULL, 0, 0)) {
      TranslateMessage(&msg);
      DispatchMessage(&msg);
  }

  Shell_NotifyIcon(NIM_DELETE, &nid);
  DestroyWindow(trayHwnd);

  if (tip != NULL) {
      tip->Release();
      tip = NULL;
  }
  pAutomation->RemoveAllEventHandlers();
  CoUninitialize();

  return 0;
}