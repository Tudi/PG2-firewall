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
		$Date: 2005/05/24 00:58:16 $
		$Revision: 1.5 $
*/

#include "stdafx.h"
#include "resource.h"
using namespace std;

HWND g_about=NULL;

static void About_OnClose(HWND hwnd) {
	DestroyWindow(hwnd);
}

static void About_OnCommand(HWND hwnd, int id, HWND hwndCtl, UINT codeNotify) {
	switch(id) {
		case IDC_HOMEPAGE:
			ShellExecute(NULL, NULL, _T("http://peerguardian.sourceforge.net/"), NULL, NULL, SW_SHOW);
			break;
		case IDC_FORUMS:
			ShellExecute(NULL, NULL, _T("http://peerguardian.sourceforge.net/forums/"), NULL, NULL, SW_SHOW);
			break;
		case IDOK:
			DestroyWindow(hwnd);
			break;
	}
}

static void About_OnDestroy(HWND hwnd) {
	g_about=NULL;
}

static BOOL About_OnInitDialog(HWND hwnd, HWND hwndFocus, LPARAM lParam) {
	HMODULE mod=GetModuleHandle(NULL);
	HRSRC res=FindResource(mod, MAKEINTRESOURCE(IDR_LICENSE), _T("TEXT"));
	DWORD ressize=SizeofResource(mod, res);
	HGLOBAL resdata=LoadResource(mod, res);

	const string s((const char*)LockResource(resdata), ressize);
	UnlockResource(resdata);

	SetDlgItemTextA(hwnd, IDC_LICENSE, s.c_str());

	return TRUE;
}

INT_PTR CALLBACK About_DlgProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
	try {
		switch(msg) {
			HANDLE_MSG(hwnd, WM_CLOSE, About_OnClose);
			HANDLE_MSG(hwnd, WM_COMMAND, About_OnCommand);
			HANDLE_MSG(hwnd, WM_DESTROY, About_OnDestroy);
			HANDLE_MSG(hwnd, WM_INITDIALOG, About_OnInitDialog);
			default: return 0;
		}
	}
	catch(exception &ex) {
		UncaughtExceptionBox(hwnd, ex, __FILE__, __LINE__);
		return 0;
	}
	catch(...) {
		UncaughtExceptionBox(hwnd, __FILE__, __LINE__);
		return 0;
	}
}
