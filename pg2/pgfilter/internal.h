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
		$Date: 2005/03/01 02:18:53 $
		$Revision: 1.3 $
*/

#pragma once

#define INITGUID

#include <wsk.h>
#include <ws2ipdef.h>
#include <guiddef.h>

#include "filter.h"
#include "notifyqueue.h"

#define NT_DEVICE_NAME L"\\Device\\pgfilter"
#define DOS_DEVICE_NAME L"\\DosDevices\\pgfilter"

/*#define HTONL(l) (\
	(((l) & 0xff000000) >> 24) | \
	(((l) & 0x00ff0000) >> 8) | \
	(((l) & 0x0000ff00) << 8) | \
	(((l) & 0x000000ff) << 24) \
)
#define NTOHL(l) HTONL(l)

#define HTONS(s) (\
	(((s) & 0xff00) >> 8) | \
	(((s) & 0x00ff) << 8) \
)
#define NTOHS(s) HTONS(s)*/

// these are intrisics for the BSWAP instruction, much faster than the above macros.
#define HTONL(l) _byteswap_ulong(l)
#define NTOHL(l) HTONL(l)
#define HTONS(s) _byteswap_ushort(s)
#define NTOHS(s) HTONS(s)

#pragma pack(push, 1)

typedef struct __ip_header {
	UCHAR		iphVerLen;		// Version and length 
	UCHAR		ipTOS;			// Type of service 
	USHORT	ipLength;		// Total datagram length 
	USHORT	ipID;				// Identification 
	USHORT	ipFlags;			// Flags
	UCHAR		ipTTL;			// Time to live 
	UCHAR		ipProtocol;		// Protocol 
	USHORT	ipChecksum;		// Header checksum 
	ULONG		ipSource;		// Source address 
	ULONG		ipDestination;	// Destination address 
} IP_HEADER;

typedef struct __tcp_header {
	USHORT	sourcePort;
	USHORT	destinationPort;
	ULONG		sequence;
	ULONG		ack;
} TCP_HEADER, UDP_HEADER;

typedef union TAG_FAKEV6ADDR {
	IN6_ADDR addr6;
	struct {
		unsigned int prefix; // 0x00000120
		unsigned int server;
		unsigned short flags;
		unsigned short clientport;
		unsigned int clientip;
	} teredo;
	struct {
		unsigned short prefix; // 0x0220
		unsigned int clientip;
		unsigned short subnet;
		unsigned __int64 address;
	} sixtofour;
} FAKEV6ADDR;

#pragma pack(pop)

#define TEMP_BLOCK_LIST			16		//make this a hexa round number ( old vas 128 and was ok)
#define TEMP_BLOCK_LIST_MASK	(TEMP_BLOCK_LIST-1)
#define PERMA_ALLOW_MAX_LENGTH	20
#define USE_FIXED_LIST			1

typedef struct __pg_internal
{
	NOTIFICATION_QUEUE queue;

	KSPIN_LOCK rangeslock;

	PGIPRANGE *blockedranges;
	ULONG blockedcount, blockedlabelsid;

	PGIPRANGE *allowedranges;
	ULONG allowedcount, allowedlabelsid;

	int block;
	int blockhttp;
	
	UINT32 connect4;
	UINT32 accept4;
	UINT32 connect6;
	UINT32 accept6;

	//port filter 
	char f_port_open_ports[65535]; //external list to open ports
	int disable_port_scan_detector;

	//consecutiv filter
	int disable_connection_flood_detector;
	ULONG f_cons_last_received_IP;
	ULONG f_cons_last_received_IP_count;
	ULONG f_cons_last_received_IP_count_limit;

	//we added these IPs to ban list and we share the list with some other program
	//list is length based list, first element stores the length of the list
#ifdef USE_FIXED_LIST
	ULONG temp_connection_flood_banns[TEMP_BLOCK_LIST],temp_block_count;
#else
	void *tempban_IP_bytes[255];
#endif
	//perma allow list cause internal is not working
	ULONG perma_allow_list_length;
	ULONG perma_allow_list[ PERMA_ALLOW_MAX_LENGTH ];
} PGINTERNAL;

extern PGINTERNAL *g_internal;

const PGIPRANGE* inranges(const PGIPRANGE *ranges, int count, ULONG ip);
void SetRanges(const PGRANGES *ranges, int block);
#ifdef USE_FIXED_LIST
int CheckInsertedAndAddIPForBan(ULONG new_IP);
#else
int checkbanned(ULONG new_IP);
void Addbanned(ULONG new_IP);
void FreeAllocatedBanList();
#endif
