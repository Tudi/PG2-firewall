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
		$Date: 2005/04/18 00:49:20 $
		$Revision: 1.14 $
*/

#pragma once

#include <list>
#include <utility>
#include <p2p/range.hpp>
#include <windows.h>
#include "threaded_sqlite3x.hpp"

#ifdef _WIN32_WINNT
#if _WIN32_WINNT >= 0x0600
#include "pgfilter_wfp.h"
#else
#include "pgfilter_nt.h"
#endif
#else
#include "pgfilter_9x.h"
#endif

#define WM_LOG_HOOK		(WM_APP+1)
#define WM_LOG_RANGES	(WM_APP+2)
#define TIMER_UPDATE		1

INT_PTR CALLBACK Log_DlgProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

typedef std::list<std::pair<time_t,p2p::range> > allowlist_t;

extern allowlist_t g_allowlist;
extern allowlist_t g_blocklist;

extern threaded_sqlite3_connection g_con;
