/*
	Copyright (C) 2004-2005 Cory Nelson
	Based on the original work by Tim Leonard

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
		$Date: 2005/02/26 05:31:35 $
		$Revision: 1.2 $
*/

#pragma once

#include <string>
#include <vector>
#include <boost/cstdint.hpp>
#include <boost/function.hpp>

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <p2p/list.hpp>

#include "threadx.hpp"
#include "driver.h"

class pgfilter_base {
public:
	struct action {
		std::wstring label;
		union {
			sockaddr addr;
			sockaddr_in addr4;
			SOCKADDR_IN6 addr6;
		} src, dest;
		int protocol;
		enum { allowed, blocked, none } type;
	};
	typedef boost::function<void(const action&)> action_function;

	void setblock(bool block);
	void setblockhttp(bool block);

	void setranges(const p2p::list &ranges, bool block);

	void setactionfunc(const action_function &func = action_function());

	unsigned int blockcount() const { return m_blockcount; }
	unsigned int allowcount() const { return m_allowcount; }

	//!!WOWBEEZ CODE - START!!//
	void SetAllowPort(unsigned short new_port, char isopen);
	ULONG consecutive_connections_to_get_ban;
	void SetConsConLimit(ULONG newLimit){ consecutive_connections_to_get_ban = newLimit; }
	void RegisterConLimit();
	ULONG new_bans_buffer[ MAX_IP_BANS_PER_UPDATE ];//this should be visible from both sides (driver and pg)
//	void RegisterNewBanBuff();
	unsigned int ReHash_interval;
	unsigned int Next_Rehash_at;
	void SetForcedRehashInterval(unsigned int new_interval){ ReHash_interval=new_interval;}	//regenerate our ban list
	void AddPermaAllowIP(ULONG new_ip);
	void DisablePortScanDetector(int disable);
	void DisableConnectionFloodDetector(int disable);
	void *tempban_IP_bytes[255];
	int tempban_vect_size,banned_ips;
	int	CheckAndAddTempIPBan(ULONG IP);
	unsigned int Next_log_flush_stamp;
	unsigned int Log_flush_interval;
	void SetLogFlushInterval(unsigned int new_interval){ Log_flush_interval=new_interval;}
	//!!WOWBEEZ CODE - END!!//

protected:
	pgfilter_base();

	void start_thread();
	void stop_thread();
	
	driver m_filter;

private:
	void thread_func();
	static DWORD WINAPI thread_thunk(void *arg);

	HANDLE m_thread, m_exitevt;

	std::vector<wchar_t> m_blocklabels, m_allowlabels;
	unsigned int m_blocklabelsid, m_allowlabelsid;

	unsigned int m_blockcount, m_allowcount;

	action_function m_onaction;

	bool m_block, m_blockhttp;
	volatile bool m_runthread;

	mutex m_lock;
};
