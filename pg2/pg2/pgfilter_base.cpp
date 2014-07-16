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

#include "stdafx.h"
#include "../pgfilter/filter.h"
#include "win32_error.h"

static const wchar_t* PGFILTER_NAME = L"pgfilter";
static const wchar_t* PGFILTER_PATH = L"pgfilter.sys";

#define INVALID_LOG_FLUSH_INTERVAL 0xEFFFFFFF

pgfilter_base::pgfilter_base() : m_block(false),m_blockhttp(true),m_blockcount(0),m_allowcount(0) 
{
	//!!WOWBEEZ CODE - START!!//
	consecutive_connections_to_get_ban = 0xeFFFFFFF;
	ReHash_interval = 5000;
	Next_Rehash_at = 0;
	tempban_vect_size = 0;
	banned_ips = 0;
	memset(tempban_IP_bytes,0,sizeof(void*)*255);
	Next_log_flush_stamp = 0;
	Log_flush_interval = INVALID_LOG_FLUSH_INTERVAL;
	//!!WOWBEEZ CODE - END!!//
}

//!!WOWBEEZ CODE - START!!//
int	pgfilter_base::CheckAndAddTempIPBan(ULONG IP)
{
	int byte_selector,bit_selector,byte,is_already_in,bitmask;
	void **tp;
	unsigned int *tbyte1;
	//for byte 4
	tp = tempban_IP_bytes;
	byte = (IP >> 0 ) & 0xFF;
	if( tp[ byte ] == NULL )
	{
		tp[ byte ] = malloc( 255 * sizeof(void*) );
		if( tp[ byte ] == NULL )
			return 1;
		memset(tp[ byte ],0,sizeof(void*)*255);
		tempban_vect_size += 255 * sizeof(void*);
	}
	//for byte 3
	tp = (void **)tp[ byte ];
	byte = (IP >> 8 ) & 0xFF;
	if( tp[ byte ] == NULL )
	{
		tp[ byte ] = malloc( 255 * sizeof(void*) );
		if( tp[ byte ] == NULL )
			return 1;
		memset(tp[ byte ],0,sizeof(void*)*255);
		tempban_vect_size += 255 * sizeof(void*);
	}
	//for byte 2
	tp = (void **)tp[ byte ];
	byte = (IP >> 16 ) & 0xFF;
	if( tp[ byte ] == NULL )
	{
		tp[ byte ] = malloc( 8 * sizeof(unsigned int) );
		if( tp[ byte ] == NULL )
			return 1;
		memset(tp[ byte ],0,sizeof(unsigned int) * 8);
		tempban_vect_size += 8 * sizeof(unsigned int);
	}
	//for byte 1
	tbyte1 = (unsigned int *)tp[ byte ];
	byte = (IP >> 24 ) & 0xFF;
	byte_selector = byte / 32;
	bit_selector = byte % 32;
	bitmask = 1 << bit_selector;
	is_already_in = tbyte1[ byte_selector ] & bitmask;
	tbyte1[ byte_selector ] |= bitmask;
	if( is_already_in == 0 )
		banned_ips++;
	return is_already_in;
}

void pgfilter_base::DisablePortScanDetector(int disable)
{
	mutex::scoped_lock lock(m_lock);

	int data = disable;
	DWORD ret = m_filter.write(IOCTL_PEERGUARDIAN_SET_PORT_DET, &data, sizeof(int));
	if(ret != ERROR_SUCCESS) 
		throw win32_error("DeviceIoControl - cannot disable port scan detector", ret);
}
void pgfilter_base::DisableConnectionFloodDetector(int disable)
{
	mutex::scoped_lock lock(m_lock);

	int data = disable;
	DWORD ret = m_filter.write(IOCTL_PEERGUARDIAN_SET_FLOOD_DET, &data, sizeof(int));
	if(ret != ERROR_SUCCESS) 
		throw win32_error("DeviceIoControl - cannot disable port scan detector", ret);
}
void pgfilter_base::SetAllowPort(unsigned short new_port, char isopen)
{
	mutex::scoped_lock lock(m_lock);

	int data = (new_port<<16) | ( isopen + 1 );
	DWORD ret = m_filter.write(IOCTL_PEERGUARDIAN_SET_PORT, &data, sizeof(int));
	if(ret != ERROR_SUCCESS) 
		throw win32_error("DeviceIoControl - assign port list", ret);
}
void pgfilter_base::RegisterConLimit()
{
	mutex::scoped_lock lock(m_lock);

	int data = consecutive_connections_to_get_ban;
	DWORD ret = m_filter.write(IOCTL_PEERGUARDIAN_CONNECTION_LIMIT, &data, sizeof(int));
	if(ret != ERROR_SUCCESS) 
		throw win32_error("DeviceIoControl - set conn limit", ret);
}
void pgfilter_base::AddPermaAllowIP(ULONG new_ip)
{
	mutex::scoped_lock lock(m_lock);

	ULONG data = new_ip;
	DWORD ret = m_filter.write(IOCTL_PEERGUARDIAN_ADD_PERMA_ALLLOW, &data, sizeof(ULONG));
	if(ret != ERROR_SUCCESS) 
		throw win32_error("DeviceIoControl - add allow IP", ret);
}

/*
void pgfilter_base::RegisterNewBanBuff()
{
	mutex::scoped_lock lock(m_lock);

	DWORD ret = m_filter.write(IOCTL_PEERGUARDIAN_ASSIGN_BANLIST_BUFF, new_bans_buffer, sizeof(ULONG *));
	if(ret != ERROR_SUCCESS) 
		throw win32_error("DeviceIoControl - assign ban list buff", ret);
}
*/
//!!WOWBEEZ CODE - END!!//


void pgfilter_base::start_thread() {
	m_runthread = true;

	m_exitevt = CreateEvent(0, TRUE, FALSE, 0);
	if(!m_exitevt) throw win32_error("CreateEvent", 0);

	m_thread = CreateThread(0, 0, thread_thunk, this, 0, 0);
	if(!m_thread) {
		DWORD err = GetLastError();

		CloseHandle(m_exitevt);
		throw win32_error("CreateThread", err);
	}
}

void pgfilter_base::stop_thread() {
	m_runthread = false;
	SetEvent(m_exitevt);

	WaitForSingleObject(m_thread, INFINITE);

	CloseHandle(m_thread);
	CloseHandle(m_exitevt);
}

void pgfilter_base::setblock(bool block) {
	mutex::scoped_lock lock(m_lock);

	if(block != m_block) {
		m_block = block;

		int data = block ? 1 : 0;

		DWORD ret = m_filter.write(IOCTL_PEERGUARDIAN_HOOK, &data, sizeof(data));
		if(ret != ERROR_SUCCESS) throw win32_error("DeviceIoControl", ret);
	}
}

void pgfilter_base::setblockhttp(bool block) {
	mutex::scoped_lock lock(m_lock);

	if(block != m_blockhttp) {
		m_blockhttp = block;

		int data = block ? 1 : 0;

		DWORD ret = m_filter.write(IOCTL_PEERGUARDIAN_HTTP, &data, sizeof(data));
		if(ret != ERROR_SUCCESS) throw win32_error("DeviceIoControl", ret);
	}
}

void pgfilter_base::setranges(const p2p::list &ranges, bool block)
{
	typedef stdext::hash_map<std::wstring, const wchar_t*> hmap_type;

	hmap_type labels;
	std::vector<wchar_t> labelsbuf;
	unsigned int ipcount = 0;

	for(p2p::list::const_iterator iter = ranges.begin(); iter != ranges.end(); ++iter)
	{
		const wchar_t* &label = labels[iter->name];

		if(!label)
		{
			label = (const wchar_t*)labelsbuf.size();

			labelsbuf.insert(labelsbuf.end(), iter->name.begin(), iter->name.end());
			labelsbuf.push_back(L'\0');
		}
	}

	for(hmap_type::iterator iter = labels.begin(); iter != labels.end(); ++iter)
	{
		iter->second = (&labelsbuf.front()) + (std::vector<wchar_t>::size_type)iter->second;
	}

	DWORD pgrsize = (DWORD)offsetof(PGRANGES, ranges[ranges.size()]);

	PGRANGES *pgr = (PGRANGES*)malloc(pgrsize);
	if(!pgr) throw std::bad_alloc("unable to allocate memory for IP ranges");

	pgr->block = block ? 1 : 0;
	pgr->count = (ULONG)ranges.size();

	unsigned int i = 0;
	for(p2p::list::const_iterator iter = ranges.begin(); iter != ranges.end(); ++iter) {
		pgr->ranges[i].label = labels[iter->name];
		pgr->ranges[i].start = iter->start.ipl;
		pgr->ranges[i++].end = iter->end.ipl;

		ipcount += iter->end.ipl - iter->start.ipl + 1;
	}

	DWORD ret;
	{
		mutex::scoped_lock lock(m_lock);
		
		pgr->labelsid = block ? (m_blocklabelsid + 1) : (m_allowlabelsid + 1);

		ret = m_filter.write(IOCTL_PEERGUARDIAN_SETRANGES, pgr, pgrsize);
		if(ret == ERROR_SUCCESS) {
			if(block) {
				++m_blocklabelsid;
				m_blockcount = ipcount;
				m_blocklabels.swap(labelsbuf);
			}
			else {
				++m_allowlabelsid;
				m_allowcount = ipcount;
				m_allowlabels.swap(labelsbuf);
			}
		}
	}

	free(pgr);
	
	if(ret != ERROR_SUCCESS) {
		throw win32_error("DeviceIoControl", ret);
	}
}

void pgfilter_base::setactionfunc(const action_function &func) {
	mutex::scoped_lock lock(m_lock);
	m_onaction = func;
}

void pgfilter_base::thread_func() {
	HANDLE evts[2];

	evts[0] = CreateEvent(0, TRUE, FALSE, 0);
	evts[1] = m_exitevt;

	while(m_runthread) {
		OVERLAPPED ovl = {0};
		ovl.hEvent = evts[0];

		PGNOTIFICATION pgn;

		DWORD ret = m_filter.read(IOCTL_PEERGUARDIAN_GETNOTIFICATION, &pgn, sizeof(pgn), &ovl);
		if(ret != ERROR_SUCCESS) {
			if(ret == ERROR_OPERATION_ABORTED) break;
			else {
				std::wcout << L"error: read failed." << std::endl;
			}
		}

		ret = WaitForMultipleObjects(2, evts, FALSE, INFINITE);
		if(ret < WAIT_OBJECT_0 || ret > (WAIT_OBJECT_0 + 1)) {
			std::wcout << L"error: WaitForMultipleObjects failed." << std::endl;
		}

		if(!m_runthread) {
			m_filter.cancelio();
			m_filter.getresult(&ovl);
			break;
		}

		ret = m_filter.getresult(&ovl);
		if(ret == ERROR_SUCCESS) 
		{
			action a;

			if( Log_flush_interval != INVALID_LOG_FLUSH_INTERVAL )
			{
				unsigned int ticknow = GetTickCount();
				if( ticknow > Next_log_flush_stamp )
				{
					FILE *tf;
					Next_log_flush_stamp = Log_flush_interval + ticknow;
					tf=fopen("Port_scanners.log","w");
					if( tf ) fclose( tf );
					tf=fopen("Connection_flooder.log","w");
					if( tf ) fclose( tf );
					tf=fopen("Autodetect.p2g","w");
					if( tf ) fclose( tf );
				}
			}
			if( ( pgn.action == 20 || pgn.action == 30 ) && CheckAndAddTempIPBan( pgn.source.addr4.sin_addr.s_addr ) == 0 )
			{
				unsigned char sb1,sb2,sb3,sb4;
				unsigned char db1,db2,db3,db4;
				sb1 = (unsigned char )((pgn.source.addr4.sin_addr.s_addr >> 0 ) & 0xFF);
				sb2 = (unsigned char )((pgn.source.addr4.sin_addr.s_addr >> 8 ) & 0xFF);
				sb3 = (unsigned char )((pgn.source.addr4.sin_addr.s_addr >> 16 ) & 0xFF);
				sb4 = (unsigned char )((pgn.source.addr4.sin_addr.s_addr >> 24 ) & 0xFF);
				db1 = (unsigned char )((pgn.dest.addr4.sin_addr.s_addr >> 0 ) & 0xFF);
				db2 = (unsigned char )((pgn.dest.addr4.sin_addr.s_addr >> 8 ) & 0xFF);
				db3 = (unsigned char )((pgn.dest.addr4.sin_addr.s_addr >> 16 ) & 0xFF);
				db4 = (unsigned char )((pgn.dest.addr4.sin_addr.s_addr >> 24 ) & 0xFF);
				if( Log_flush_interval != INVALID_LOG_FLUSH_INTERVAL )
				{
					FILE *tf;
					if(pgn.action == 20)
						tf=fopen("Port_scanners.log","a");
					else if(pgn.action == 30)
						tf=fopen("Connection_flooder.log","a");
					else
						tf=NULL;
					if( tf )
					{
						fprintf(tf,"%u.%u.%u.%u:%u -> %u.%u.%u.%u:%u\n",sb1,sb2,sb3,sb4,pgn.source.addr4.sin_port,db1,db2,db3,db4,pgn.dest.addr4.sin_port);
						fclose(tf);
					}
					tf=fopen("Autodetect.p2g","a");
					if( tf )
					{
						if( pgn.action == 20 )
							fprintf(tf,"Port scanner:%u.%u.%u.%u-%u.%u.%u.%u\n",sb1,sb2,sb3,sb4,sb1,sb2,sb3,sb4);
						else if( pgn.action == 30 )
							fprintf(tf,"Connection flooder:%u.%u.%u.%u-%u.%u.%u.%u\n",sb1,sb2,sb3,sb4,sb1,sb2,sb3,sb4);
						fclose(tf);
					}
					tf=fopen("debug.txt","w");
					if( tf )
					{
						fprintf(tf,"For %u bans IP mask is eating %uMb = %uKb =%uByte\n",banned_ips,tempban_vect_size/1024/1024,tempban_vect_size/1024,tempban_vect_size);
						fclose(tf);
					}
				}
	//!!WOWBEEZ CODE - END!!//
			}

			if(pgn.action == 0)	a.type = action::blocked;
			else if(pgn.action == 1) a.type = action::allowed;
	//!!WOWBEEZ CODE - START!!//
			//port filter caught an IP scanning our ports : ban it
			else if(pgn.action == 20) a.type = action::blocked;
			//connection filter caught an IP connecting multiple times
			else if(pgn.action == 30) a.type = action::blocked;
	//!!WOWBEEZ CODE - END!!//
			else a.type = action::none;

			a.protocol = pgn.protocol;

			if(pgn.source.addr.sa_family == AF_INET) {
				a.src.addr4 = pgn.source.addr4;
				a.dest.addr4 = pgn.dest.addr4;
			}
			else {
				a.src.addr6 = pgn.source.addr6;
				a.dest.addr6 = pgn.dest.addr6;
			}

			{
				mutex::scoped_lock lock(m_lock);

				if(pgn.label && ((a.type == action::blocked && pgn.labelsid == m_blocklabelsid) || (a.type == action::allowed && pgn.labelsid == m_allowlabelsid))) 
					a.label = pgn.label;
	//!!WOWBEEZ CODE - START!!//
				if( pgn.action == 20 )
					a.label = L"AutoBlock : possible Portscanner";
				else if( pgn.action == 30 )
					a.label = L"AutoBlock : possible connection flooder";
	//!!WOWBEEZ CODE - END!!//

				if(m_onaction) {
					m_onaction(a);
				}
			}
		}
		else if(ret == ERROR_OPERATION_ABORTED) break;
		else {
			std::wcout << L"error: getresult failed." << std::endl;
		}

		ResetEvent(evts[0]);
	}

	CloseHandle(evts[0]);
}

DWORD WINAPI pgfilter_base::thread_thunk(void *arg) {
	reinterpret_cast<pgfilter_base*>(arg)->thread_func();
	return 0;
}
