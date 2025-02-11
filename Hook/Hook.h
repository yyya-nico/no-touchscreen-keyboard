#pragma once

#ifdef HOOK_EXPORTS__
#undef HOOK_EXPORTS__
#define DECLSPEC extern "C" __declspec(dllexport)
#else
#define DECLSPEC extern "C" __declspec(dllimport)
#endif

typedef void (*CallbackFunc)(BOOL isFocus);
DECLSPEC void SetCallback(CallbackFunc callback);

class Hook {

public:
	static void SetHook();
	static void Unhook();
};