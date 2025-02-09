#pragma once

// toggle this to use only windows 8 wm_pointer events instead of wm_touch
#define USE_WM_POINTER_EVENTS


class Hook {

public:
	static void EnableTouch();
	static void DisableTouch();
};