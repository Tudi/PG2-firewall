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
		$Date: 2005/07/13 05:45:02 $
		$Revision: 1.48 $
*/

#include "stdafx.h"
using namespace std;

Configuration g_config;

Configuration::Configuration() :
Block(true),BlockHttp(true),AllowLocal(true),UpdatePeerGuardian(true),
	UpdateLists(true),ShowSplash(true),WindowHidden(false),UpdateInterval(2),
	LogSize(12),LastUpdate(0),CleanupInterval(0),LogAllowed(true),LogBlocked(true),
	ShowAllowed(true),CacheCrc(0),UpdateCountdown(-1),UpdateProxyType(CURLPROXY_HTTP),
	UpdateWindowPos(RECT()),ListManagerWindowPos(RECT()),StayHidden(false),
	ListEditorWindowPos(RECT()),HistoryWindowPos(RECT()),HideOnClose(true),
	AlwaysOnTop(false),HideTrayIcon(false),FirstBlock(true),FirstHide(true),
	BlinkOnBlock(OnHttpBlock),NotifyOnBlock(Never),CleanupType(None),
	ArchivePath(_T("archives")),StartMinimized(false),ColorCode(true) {
		HistoryColumns[0]=64;
		HistoryColumns[1]=128;
		HistoryColumns[2]=124;
		HistoryColumns[3]=124;
		HistoryColumns[4]=64;
		HistoryColumns[5]=64;

		LogColumns[0]=64;
		LogColumns[1]=128;
		LogColumns[2]=124;
		LogColumns[3]=124;
		LogColumns[4]=64;
		LogColumns[5]=64;

		ListEditorColumns[0]=256;
		ListEditorColumns[1]=128;
		ListEditorColumns[2]=128;

		ListManagerColumns[0]=192;
		ListManagerColumns[1]=64;
		ListManagerColumns[2]=192;

		UpdateColumns[0]=128;
		UpdateColumns[1]=102;
		UpdateColumns[2]=128;

		AllowedColor.Text=RGB(192, 192, 192);
		AllowedColor.Background=RGB(255, 255, 255);

		BlockedColor.Text=RGB(0, 0, 0);
		BlockedColor.Background=RGB(255, 255, 255);

		HttpColor.Text=RGB(0, 0, 192);
		HttpColor.Background=RGB(255, 255, 255);
}

static bool GetChild(const TiXmlElement *root, const string &node, string &value) {
	const TiXmlElement *e=root->FirstChildElement(node);
	if(!e) return false;

	const TiXmlNode *n=e->FirstChild();
	if(!n) return false;

	const TiXmlText *t=n->ToText();
	if(!t) return false;

	const char *v=t->Value();
	if(!v) return false;

	value=UTF8_MBS(v);
	return true;
}

#ifdef _UNICODE
static bool GetChild(const TiXmlElement *root, const string &node, wstring &value) {
	const TiXmlElement *e=root->FirstChildElement(node);
	if(!e) return false;

	const TiXmlNode *n=e->FirstChild();
	if(!n) return false;

	const TiXmlText *t=n->ToText();
	if(!t) return false;

	const char *v=t->Value();
	if(!v) return false;

	value=UTF8_TSTRING(v);
	return true;
}
#endif

static bool GetChild(const TiXmlElement *root, const string &node, bool &value) {
	string v;
	if(!GetChild(root, node, v)) return false;

	value=(v=="yes");
	return true;
}

template<class InT>
static bool GetChild(const TiXmlElement *root, const string &node, InT &value) {
	string v;
	if(!GetChild(root, node, v)) return false;

	try {
		value=boost::lexical_cast<InT>(v);
	}
	catch(...) {
		return false;
	}

	return true;
}

static bool GetChild(const TiXmlElement *root, const string &node, RECT &rc) {
	const TiXmlElement *e=root->FirstChildElement(node);
	if(!e) return false;

	bool ret=true;

	if(!GetChild(e, "Top", rc.top)) ret=false;
	if(!GetChild(e, "Left", rc.left)) ret=false;
	if(!GetChild(e, "Bottom", rc.bottom)) ret=false;
	if(!GetChild(e, "Right", rc.right)) ret=false;

	rc.top=max(rc.top, 0L);
	rc.left=max(rc.left, 0L);
	rc.bottom=max(rc.bottom, 0L);
	rc.right=max(rc.right, 0L);

	return ret;
}

static bool GetChild(const TiXmlElement *root, const string &node, COLORREF &c) {
	string v;
	if(!GetChild(root, node, v)) return false;

	unsigned short r, g, b;
	if(sscanf(v.c_str(), "%2hx%2hx%2hx", &r, &g, &b)!=3) return false;

	c=RGB(r, g, b);
	return true;
}

static bool GetChild(const TiXmlElement *root, const string &node, Color &c) {
	const TiXmlElement *e=root->FirstChildElement(node);
	if(!e) return false;

	bool ret=true;

	if(!GetChild(e, "Text", c.Text)) ret=false;
	if(!GetChild(e, "Background", c.Background)) ret=false;

	return ret;
}

static bool GetChild(const TiXmlElement *root, const string &node, NotifyType &nt) {
	string v;
	if(!GetChild(root, node, v)) return false;

	if(v=="Never") nt=Never;
	else if(v=="OnHttpBlock") nt=OnHttpBlock;
	else if(v=="OnBlock") nt=OnBlock;
	else return false;

	return true;
}

static bool GetChild(const TiXmlElement *root, const string &node, CleanType &nt) {
	string v;
	if(!GetChild(root, node, v)) return false;

	if(v=="None") nt=None;
	else if(v=="Delete") nt=Delete;
	else if(v=="ArchiveDelete") nt=ArchiveDelete;
	else return false;

	return true;
}

static TiXmlElement *InsertChild(TiXmlNode *root, const string &node) {
	return root->InsertEndChild(TiXmlElement(node))->ToElement();
}

static TiXmlElement *InsertChild(TiXmlNode *root, const string &node, const string &value) {
	TiXmlElement *e=InsertChild(root, node);
	if(value.length()) e->InsertEndChild(TiXmlText(value));

	return e;
}

#ifdef _UNICODE
static TiXmlElement *InsertChild(TiXmlNode *root, const string &node, const wstring &value) {
	return InsertChild(root, node, TSTRING_UTF8(value));
}
#endif

static TiXmlElement *InsertChild(TiXmlNode *root, const string &node, const char *value) {
	return InsertChild(root, node, string(value));
}

static TiXmlElement *InsertChild(TiXmlNode *root, const string &node, bool value) {
	return InsertChild(root, node, value?"yes":"no");
}

template<class InT>
static TiXmlElement *InsertChild(TiXmlNode *root, const string &node, InT value) {
	return InsertChild(root, node, boost::lexical_cast<string>(value));
}

static TiXmlElement *InsertChild(TiXmlNode *root, const string &node, const RECT &rc) {
	TiXmlElement *e=InsertChild(root, node);

	InsertChild(e, "Top", rc.top);
	InsertChild(e, "Left", rc.left);
	InsertChild(e, "Bottom", rc.bottom);
	InsertChild(e, "Right", rc.right);

	return e;
}

static TiXmlElement *InsertChild(TiXmlNode *root, const string &node, COLORREF c) {
	char buf[7];
	StringCbPrintfA(buf, sizeof(buf), "%02x%02x%02x", GetRValue(c), GetGValue(c), GetBValue(c));
	return InsertChild(root, node, buf);
}

static TiXmlElement *InsertChild(TiXmlNode *root, const string &node, const Color &c) {
	TiXmlElement *e=InsertChild(root, node);

	InsertChild(e, "Text", c.Text);
	InsertChild(e, "Background", c.Background);

	return e;
}

static TiXmlElement *InsertChild(TiXmlNode *root, const string &node, NotifyType nt) {
	const char *v;

	switch(nt) {
		case Never: v="Never"; break;
		case OnHttpBlock: v="OnHttpBlock"; break;
		case OnBlock: v="OnBlock"; break;
		default: __assume(0);
	}

	return InsertChild(root, node, v);
}

static TiXmlElement *InsertChild(TiXmlNode *root, const string &node, CleanType nt) {
	const char *v;

	switch(nt) {
		case None: v="None"; break;
		case Delete: v="Delete"; break;
		case ArchiveDelete: v="ArchiveDelete"; break;
		default: __assume(0);
	}

	return InsertChild(root, node, v);
}

class UpgradeUrlPred {
private:
	vector<DynamicList> &newlists;

public:
	UpgradeUrlPred(vector<DynamicList> &nl) : newlists(nl) {}

	bool operator()(DynamicList &l) const {
		if(l.Url.find(_T("http://blocklist.org/p2b.php?cats="))!=tstring::npos) {
			set<tstring> cats;
			boost::split(cats, l.Url.substr(34), bind1st(equal_to<TCHAR>(), _T(',')));

			for(set<tstring>::const_iterator iter=cats.begin(); iter!=cats.end(); iter++) {
				DynamicList nl;
				nl.Description=*iter;
				nl.Type=l.Type;
				nl.Url=_T("http://peerguardian.sourceforge.net/lists/")+(*iter)+_T(".php");
				nl.Enabled=l.Enabled;

				this->newlists.push_back(nl);
			}

			return true;
		}
		else if(l.Url.find(_T("http://blocklist.org"))!=tstring::npos) {
			boost::replace_first(l.Url, _T("http://blocklist.org"), _T("http://peerguardian.sourceforge.net/lists"));
			boost::replace_last(l.Url, _T(".p2b.gz"), _T(".php"));
		}
		else if(l.Url.find(_T("http://lists.blocklist.org"))!=tstring::npos) {
			boost::replace_first(l.Url, _T("http://lists.blocklist.org"), _T("http://peerguardian.sourceforge.net/lists"));
			boost::replace_last(l.Url, _T(".p2b.gz"), _T(".php"));
			boost::replace_last(l.Url, _T(".7z"), _T(".php"));
		}

		return false;
	}
};

bool Configuration::Load() {
	TiXmlDocument doc;
	{
		const path p=path::base_dir()/_T("pg2.conf");

		HANDLE fp=CreateFile(p.file_str().c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
		if(fp==INVALID_HANDLE_VALUE) return false;
		boost::shared_ptr<void> fp_safe(fp, CloseHandle);

		HANDLE map=CreateFileMapping(fp, NULL, PAGE_READONLY, 0, 0, NULL);
		if(map==NULL) throw win32_error("CreateFileMapping");
		boost::shared_ptr<void> map_safe(map, CloseHandle);

		const void *view=MapViewOfFile(map, FILE_MAP_READ, 0, 0, 0);
		if(view==NULL) throw win32_error("MapViewOfFile");
		boost::shared_ptr<const void> view_safe(view, UnmapViewOfFile);

		doc.Parse((const char*)view);

		if(doc.Error()) throw runtime_error("unable to parse configuration");
	}

	const TiXmlElement *root=doc.RootElement();
	if(!root || strcmp(root->Value(), "PeerGuardian2")) return false;

	if(const TiXmlElement *settings=root->FirstChildElement("Settings")) {
		GetChild(settings, "Block", this->Block);
		GetChild(settings, "BlockHttp", this->BlockHttp);
		GetChild(settings, "AllowLocal", this->AllowLocal);
		GetChild(settings, "CacheCrc", this->CacheCrc);
		GetChild(settings, "BlinkOnBlock", this->BlinkOnBlock);
		GetChild(settings, "NotifyOnBlock", this->NotifyOnBlock);
	}

	if(const TiXmlElement *logging=root->FirstChildElement("Logging")) {
		GetChild(logging, "LogSize", this->LogSize);
		GetChild(logging, "LogAllowed", this->LogAllowed);
		GetChild(logging, "LogBlocked", this->LogBlocked);
		GetChild(logging, "ShowAllowed", this->ShowAllowed);

		GetChild(logging, "Cleanup", this->CleanupType);
		if(const TiXmlElement *c=logging->FirstChildElement("Cleanup")) {
			int i=0;
			if(c->Attribute("Interval", &i))
				this->CleanupInterval=(unsigned short)i;
		}

		tstring p;
		if(GetChild(logging, "ArchivePath", p))
			this->ArchivePath=p;
	}

	if(const TiXmlElement *colors=root->FirstChildElement("Colors")) {
		GetChild(colors, "ColorCode", this->ColorCode);
		GetChild(colors, "Blocked", this->BlockedColor);
		GetChild(colors, "Allowed", this->AllowedColor);
		GetChild(colors, "Http", this->HttpColor);
	}

	if(const TiXmlElement *windowing=root->FirstChildElement("Windowing")) {
		GetChild(windowing, "Main", this->WindowPos);
		GetChild(windowing, "Update", this->UpdateWindowPos);
		GetChild(windowing, "ListManager", this->ListManagerWindowPos);
		GetChild(windowing, "ListEditor", this->ListEditorWindowPos);
		GetChild(windowing, "History", this->HistoryWindowPos);
		
		GetChild(windowing, "StartMinimized", this->StartMinimized);
		GetChild(windowing, "ShowSplash", this->ShowSplash);
		GetChild(windowing, "StayHidden", this->StayHidden);
		GetChild(windowing, "HideOnClose", this->HideOnClose);
		
		GetChild(windowing, "HideMain", this->WindowHidden);
		GetChild(windowing, "AlwaysOnTop", this->AlwaysOnTop);
		GetChild(windowing, "HideTrayIcon", this->HideTrayIcon);

		if(const TiXmlElement *hcol=windowing->FirstChildElement("HistoryColumns")) {
			int cols[6]={0};

			GetChild(hcol, "Time", cols[0]);
			GetChild(hcol, "Range", cols[1]);
			GetChild(hcol, "Source", cols[2]);
			GetChild(hcol, "Destination", cols[3]);
			GetChild(hcol, "Protocol", cols[4]);
			GetChild(hcol, "Action", cols[5]);

			SaveListColumns(cols, this->HistoryColumns);
		}

		if(const TiXmlElement *lcol=windowing->FirstChildElement("LogColumns")) {
			int cols[6]={0};

			GetChild(lcol, "Time", cols[0]);
			GetChild(lcol, "Range", cols[1]);
			GetChild(lcol, "Source", cols[2]);
			GetChild(lcol, "Destination", cols[3]);
			GetChild(lcol, "Protocol", cols[4]);
			GetChild(lcol, "Action", cols[5]);

			SaveListColumns(cols, this->LogColumns);
		}

		if(const TiXmlElement *lcol=windowing->FirstChildElement("ListEditorColumns")) {
			int cols[3]={0};

			GetChild(lcol, "Range", cols[0]);
			GetChild(lcol, "StartingIp", cols[1]);
			GetChild(lcol, "EndingIp", cols[2]);

			SaveListColumns(cols, this->ListEditorColumns);
		}

		if(const TiXmlElement *lcol=windowing->FirstChildElement("ListManagerColumns")) {
			int cols[3]={0};

			GetChild(lcol, "File", cols[0]);
			GetChild(lcol, "Type", cols[1]);
			GetChild(lcol, "Description", cols[2]);

			SaveListColumns(cols, this->ListManagerColumns);
		}

		if(const TiXmlElement *ucol=windowing->FirstChildElement("UpdateColumns")) {
			int cols[3]={0};

			GetChild(ucol, "Description", cols[0]);
			GetChild(ucol, "Task", cols[1]);
			GetChild(ucol, "Status", cols[2]);

			SaveListColumns(cols, this->UpdateColumns);
		}
	}

	if(const TiXmlElement *updates=root->FirstChildElement("Updates")) {
		string lastupdate;

		GetChild(updates, "UpdatePeerGuardian", this->UpdatePeerGuardian);
		GetChild(updates, "UpdateLists", this->UpdateLists);
		GetChild(updates, "UpdateInterval", this->UpdateInterval);
		GetChild(updates, "UpdateCountdown", this->UpdateCountdown);

		GetChild(updates, "UpdateProxy", this->UpdateProxy);
		if(const TiXmlElement *proxy=updates->FirstChildElement("UpdateProxy")) {
			const char *t=proxy->Attribute("Type");

			this->UpdateProxyType=(t!=NULL && !strcmp(t, "http"))?CURLPROXY_HTTP:CURLPROXY_SOCKS5;
		}

		GetChild(updates, "LastUpdate", lastupdate);

		if(lastupdate.length()>0) {
			try {
				this->LastUpdate=boost::lexical_cast<int>(lastupdate);
			}
			catch(...) {
				// keep going
			}
		}
	}

	if(const TiXmlElement *messages=root->FirstChildElement("Messages")) {
		GetChild(messages, "FirstBlock", this->FirstBlock);
		GetChild(messages, "FirstHide", this->FirstHide);
	}

	if(const TiXmlElement *lists=root->FirstChildElement("Lists")) {
		for(const TiXmlElement *list=lists->FirstChildElement("List"); list!=NULL; list=list->NextSiblingElement("List")) {
			string file, url, type, description, lastupdate;
			bool enabled, failedupdate=false;

			GetChild(list, "File", file);
			GetChild(list, "Url", url);
			GetChild(list, "Type", type);
			GetChild(list, "Description", description);
			GetChild(list, "LastUpdate", lastupdate);
			GetChild(list, "FailedUpdate", failedupdate);
			if(!GetChild(list, "Enabled", enabled))
				enabled=true;

			if(file.length()>0) {
				StaticList l;

				l.Type=(type=="allow")?List::Allow:List::Block;
				l.File=UTF8_TSTRING(file);
				l.Description=UTF8_TSTRING(description);
				l.Enabled=enabled;

				this->StaticLists.push_back(l);
			}
			else {
				DynamicList l;

				l.Type=(type=="allow")?List::Allow:List::Block;
				l.Url=UTF8_TSTRING(url);
				l.Description=UTF8_TSTRING(description);
				l.Enabled=enabled;
				l.FailedUpdate=failedupdate;

				if(lastupdate.length()>0) {
					try {
						l.LastUpdate=boost::lexical_cast<int>(lastupdate);
					}
					catch(...) {
						// keep going
					}
				}

				this->DynamicLists.push_back(l);
			}	
		}
	}

	vector<DynamicList> nl;
	vector<DynamicList>::iterator new_end=remove_if(this->DynamicLists.begin(), this->DynamicLists.end(), UpgradeUrlPred(nl));

	this->DynamicLists.erase(new_end, this->DynamicLists.end());
	this->DynamicLists.insert(this->DynamicLists.end(), nl.begin(), nl.end());

	return true;
}

static bool RectValid(const RECT &rc) {
	return (rc.top!=0 || rc.left!=0 || rc.bottom!=0 || rc.right!=0);
}

void Configuration::Save() {
	TiXmlDocument doc;
	doc.InsertEndChild(TiXmlDeclaration("1.0", "UTF-8", "yes"));

	TiXmlElement *root=InsertChild(&doc, "PeerGuardian2");

	{
		TiXmlElement *settings=InsertChild(root, "Settings");

		InsertChild(settings, "Block", this->Block);
		InsertChild(settings, "BlockHttp", this->BlockHttp);
		InsertChild(settings, "AllowLocal", this->AllowLocal);
		InsertChild(settings, "CacheCrc", this->CacheCrc);
		InsertChild(settings, "BlinkOnBlock", this->BlinkOnBlock);
		InsertChild(settings, "NotifyOnBlock", this->NotifyOnBlock);
	}

	{
		TiXmlElement *logging=InsertChild(root, "Logging");

		InsertChild(logging, "LogSize", this->LogSize);
		InsertChild(logging, "LogAllowed", this->LogAllowed);
		InsertChild(logging, "LogBlocked", this->LogBlocked);
		InsertChild(logging, "ShowAllowed", this->ShowAllowed);

		{
			TiXmlElement *e=InsertChild(logging, "Cleanup", this->CleanupType);
			e->SetAttribute("Interval", (int)this->CleanupInterval);
		}

		InsertChild(logging, "ArchivePath", this->ArchivePath.directory_str());
	}

	{
		TiXmlElement *colors=InsertChild(root, "Colors");

		InsertChild(colors, "ColorCode", this->ColorCode);
		InsertChild(colors, "Blocked", this->BlockedColor);
		InsertChild(colors, "Allowed", this->AllowedColor);
		InsertChild(colors, "Http", this->HttpColor);
	}

	{
		TiXmlElement *windowing=InsertChild(root, "Windowing");

		if(RectValid(this->WindowPos))
			InsertChild(windowing, "Main", this->WindowPos);
		
		if(RectValid(this->UpdateWindowPos))
			InsertChild(windowing, "Update", this->UpdateWindowPos);

		if(RectValid(this->ListManagerWindowPos))
			InsertChild(windowing, "ListManager", this->ListManagerWindowPos);

		if(RectValid(this->ListEditorWindowPos))
			InsertChild(windowing, "ListEditor", this->ListEditorWindowPos);

		if(RectValid(this->HistoryWindowPos))
			InsertChild(windowing, "History", this->HistoryWindowPos);

		InsertChild(windowing, "StartMinimized", this->StartMinimized);
		InsertChild(windowing, "ShowSplash", this->ShowSplash);
		InsertChild(windowing, "StayHidden", this->StayHidden);
		InsertChild(windowing, "HideOnClose", this->HideOnClose);

		InsertChild(windowing, "HideMain", this->WindowHidden);
		InsertChild(windowing, "AlwaysOnTop", this->AlwaysOnTop);
		InsertChild(windowing, "HideTrayIcon", this->HideTrayIcon);
		

		{
			TiXmlElement *hcol=InsertChild(windowing, "HistoryColumns");

			InsertChild(hcol, "Time", this->HistoryColumns[0]);
			InsertChild(hcol, "Range", this->HistoryColumns[1]);
			InsertChild(hcol, "Source", this->HistoryColumns[2]);
			InsertChild(hcol, "Destination", this->HistoryColumns[3]);
			InsertChild(hcol, "Protocol", this->HistoryColumns[4]);
			InsertChild(hcol, "Action", this->HistoryColumns[5]);
		}

		{
			TiXmlElement *lcol=InsertChild(windowing, "LogColumns");

			InsertChild(lcol, "Time", this->LogColumns[0]);
			InsertChild(lcol, "Range", this->LogColumns[1]);
			InsertChild(lcol, "Source", this->LogColumns[2]);
			InsertChild(lcol, "Destination", this->LogColumns[3]);
			InsertChild(lcol, "Protocol", this->LogColumns[4]);
			InsertChild(lcol, "Action", this->LogColumns[5]);
		}

		{
			TiXmlElement *lcol=InsertChild(windowing, "ListEditorColumns");

			InsertChild(lcol, "Range", this->ListEditorColumns[0]);
			InsertChild(lcol, "StartingIp", this->ListEditorColumns[1]);
			InsertChild(lcol, "EndingIp", this->ListEditorColumns[2]);
		}

		{
			TiXmlElement *lcol=InsertChild(windowing, "ListManagerColumns");

			InsertChild(lcol, "File", this->ListManagerColumns[0]);
			InsertChild(lcol, "Type", this->ListManagerColumns[1]);
			InsertChild(lcol, "Description", this->ListManagerColumns[2]);
		}

		{
			TiXmlElement *ucol=InsertChild(windowing, "UpdateColumns");

			InsertChild(ucol, "Description", this->UpdateColumns[0]);
			InsertChild(ucol, "Task", this->UpdateColumns[1]);
			InsertChild(ucol, "Status", this->UpdateColumns[2]);
		}
	}

	{
		TiXmlElement *updates=InsertChild(root, "Updates");

		InsertChild(updates, "UpdatePeerGuardian", this->UpdatePeerGuardian);
		InsertChild(updates, "UpdateLists", this->UpdateLists);
		InsertChild(updates, "UpdateInterval", this->UpdateInterval);
		InsertChild(updates, "UpdateCountdown", this->UpdateCountdown);
		
		{
			TiXmlElement *proxy=InsertChild(updates, "UpdateProxy", this->UpdateProxy);
			proxy->SetAttribute("Type", (this->UpdateProxyType==CURLPROXY_HTTP)?"http":"socks5");
		}

		TiXmlElement *lastupdate=InsertChild(updates, "LastUpdate");

		if(this->LastUpdate) {
			string t=boost::lexical_cast<string>((int)this->LastUpdate);
			lastupdate->InsertEndChild(TiXmlText(t));
		}
	}

	{
		TiXmlElement *messages=InsertChild(root, "Messages");

		InsertChild(messages, "FirstBlock", this->FirstBlock);
		InsertChild(messages, "FirstHide", this->FirstHide);
	}

	{
		TiXmlElement *lists=InsertChild(root, "Lists");

		for(vector<StaticList>::size_type i=0; i<this->StaticLists.size(); i++) {
			TiXmlElement *list=InsertChild(lists, "List");

			InsertChild(list, "File", TSTRING_UTF8(this->StaticLists[i].File.file_str()));
			InsertChild(list, "Type", (this->StaticLists[i].Type==List::Allow)?"allow":"block");
			InsertChild(list, "Description", this->StaticLists[i].Description);
			InsertChild(list, "Enabled", this->StaticLists[i].Enabled);
		}

		for(vector<DynamicList>::size_type i=0; i<this->DynamicLists.size(); i++) {
			TiXmlElement *list=InsertChild(lists, "List");

			InsertChild(list, "Url", this->DynamicLists[i].Url);
			InsertChild(list, "Type", (this->DynamicLists[i].Type==List::Allow)?"allow":"block");
			InsertChild(list, "Description", this->DynamicLists[i].Description);
			InsertChild(list, "Enabled", this->DynamicLists[i].Enabled);
			InsertChild(list, "FailedUpdate", this->DynamicLists[i].FailedUpdate);

			TiXmlElement *lastupdate=InsertChild(list, "LastUpdate");
			if(this->DynamicLists[i].LastUpdate) {
				string s=boost::lexical_cast<string>((int)this->DynamicLists[i].LastUpdate);
				lastupdate->InsertEndChild(TiXmlText(s));
			}
		}
	}

	FILE *fp=_tfopen((path::base_dir()/_T("pg2.conf")).file_str().c_str(), _T("w"));
	if(!fp) throw runtime_error("unable to save configuration");

	boost::shared_ptr<void> ptr(fp, fclose);

	doc.Print(fp);
}
