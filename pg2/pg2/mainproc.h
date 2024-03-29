/*
	Copyright (C) 2004-2005 Cory Nelson

	This software is provided 'as-is', without any express or implied
	warranty.  In no event will the authors be held liable for any damages
	arising from the use of this software.

	Permission is granted to anyone to use this software for any purpose,
	including commercial applications, and to alter it and redistribute it
	freely, subject to the following restrictions:

	1. The origin of this software must not be misrepresented; you must not
		claim that you wrote the original software. If you use this software
		in a product, an acknowledgment in the product documentation would be
		appreciated but is not required.
	2. Altered source versions must be plainly marked as such, and must not be
		misrepresented as being the original software.
	3. This notice may not be removed or altered from any source distribution.
	
	CVS Info :
		$Author: phrostbyte $
		$Date: 2005/06/17 03:20:40 $
		$Revision: 1.9 $
*/

#pragma once

#include <boost/shared_ptr.hpp>
#include <windows.h>

#ifdef _WIN32_WINNT
#if _WIN32_WINNT >= 0x0600
#include "pgfilter_wfp.h"
#else
#include "pgfilter_nt.h"
#endif
#else
#include "pgfilter_9x.h"
#endif

#define WM_MAIN_VISIBLE	(WM_APP+1)

struct TabData {
	UINT Title;
	LPCTSTR Template;
	DLGPROC Proc;
	HWND Tab;
};

INT_PTR CALLBACK Main_DlgProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

void SetBlock(bool block);
void SetBlockHttp(bool block);

extern TabData g_tabs[];
extern boost::shared_ptr<pgfilter> g_filter;
extern DWORD g_blinkstart;
extern HWND g_main;

extern bool g_trayactive;
extern NOTIFYICONDATA g_nid;
