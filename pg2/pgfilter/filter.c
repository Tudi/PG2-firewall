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
		$Date: 2005/04/18 17:47:46 $
		$Revision: 1.9 $
*/

#include <stddef.h>

#pragma warning(push)
#pragma warning(disable:4103)
#include <wdm.h>
#pragma warning(pop)

#include <ntddk.h>
#include <ntstrsafe.h>
#include <ntddndis.h>
#include <pfhook.h>
#include "internal.h"

static void setfilter(PacketFilterExtensionPtr fn) {
	UNICODE_STRING name;
	PDEVICE_OBJECT device=NULL;
	PFILE_OBJECT file=NULL;
	NTSTATUS status;

	RtlInitUnicodeString(&name, DD_IPFLTRDRVR_DEVICE_NAME);
	status=IoGetDeviceObjectPointer(&name, STANDARD_RIGHTS_ALL, &file, &device);

	if(NT_SUCCESS(status)) {
		KEVENT event;
		IO_STATUS_BLOCK iostatus;
		PF_SET_EXTENSION_HOOK_INFO hookinfo;
		PIRP irp;

		hookinfo.ExtensionPointer=fn;
		KeInitializeEvent(&event, NotificationEvent, FALSE);

		irp=IoBuildDeviceIoControlRequest(
			IOCTL_PF_SET_EXTENSION_POINTER, device, &hookinfo,
			sizeof(PF_SET_EXTENSION_HOOK_INFO), NULL, 0, FALSE, &event, &iostatus);

		if(irp && IoCallDriver(device, irp)==STATUS_PENDING)
			KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);

		if(file) ObDereferenceObject(file);
	}
}

static PF_FORWARD_ACTION filter_cb(unsigned char *header, unsigned char *packet, unsigned int len, unsigned int recvindex, unsigned int sendindex, IPAddr nextrecvhop, IPAddr nextsendhop)
{
	PGNOTIFICATION pgn={0};
	const IP_HEADER *iph=(IP_HEADER*)header;
	const PGIPRANGE *range=NULL;
	const ULONG src=NTOHL(iph->ipSource);
	const ULONG dest=NTOHL(iph->ipDestination);
	USHORT srcport=0;
	USHORT destport=0;
	int opening=1;
	int http = 0;
	int forced_log = 0;

	//if the protocol is TCP or UDP
	if(iph->ipProtocol==6 || iph->ipProtocol==17)
	{
		const TCP_HEADER *tcp=(TCP_HEADER*)packet;
		srcport=NTOHS(tcp->sourcePort);
		destport=NTOHS(tcp->destinationPort);

		if(iph->ipProtocol==6)
		{
			opening=(tcp->ack==0);

			if(!g_internal->blockhttp && (srcport==80 || srcport==443 || destport==80 || destport==443))
			{
				http = 1;
			}
		}
	}

	if(!http)
	{
		KIRQL irq;

		KeAcquireSpinLock(&g_internal->rangeslock, &irq);

		//TODO: test allowed ranges.
		// -> beez : this is not working
		if(g_internal->allowedcount) 
		{
			range = inranges(g_internal->allowedranges, g_internal->allowedcount, src);
			if(!range) 
				range = inranges(g_internal->allowedranges, g_internal->allowedcount, dest);

			if(range)
			{
				pgn.label = range->label;
				pgn.labelsid = g_internal->allowedlabelsid;
				pgn.action = 1;
			}
		}

		if(!range && g_internal->blockedcount)
		{
			range=inranges(g_internal->blockedranges, g_internal->blockedcount, src);
			if(!range) 
				range=inranges(g_internal->blockedranges, g_internal->blockedcount, dest);

			if(range)
			{
				pgn.label = range->label;
				pgn.labelsid = g_internal->blockedlabelsid;
				pgn.action = 0;
			}
		}

		KeReleaseSpinLock(&g_internal->rangeslock, irq);
	}
	
	//seems like connection is oppening up. This means no special action
	if(!range)
	{
		pgn.action = 2;
	}

	//we filter only incomming and not already processed trafic for ports and connections
	if( sendindex == INVALID_PF_IF_INDEX && range == NULL && http == 0 )
	{
		unsigned int i;
		for(i=0;i<g_internal->perma_allow_list_length;i++)
			if( src == g_internal->perma_allow_list[ i ] )
				break;
		if( i == g_internal->perma_allow_list_length )
		{
			//he is sending us a TCP or UDP packet and we test if our port is open. 
			//If not he does not know about our open ports then we can ban him since he is scanning us
			if( destport != 0 && g_internal->f_port_open_ports[ destport ] == 0 && g_internal->disable_port_scan_detector == 0)
			{
#ifdef USE_FIXED_LIST
				CheckInsertedAndAddIPForBan( src );
#else
				Addbanned( src );
#endif
				forced_log = 1;
				pgn.action = 20;

			}
			//a new tcp connection. See if he is spamming connections
			else if( opening && g_internal->disable_connection_flood_detector == 0 ) 
			{
				//check if we are already banning this IP
#ifdef USE_FIXED_LIST
				int i;
				for(i=0;i<TEMP_BLOCK_LIST;i++)
					if( g_internal->temp_connection_flood_banns[ i ] == src )
					{
						forced_log = 1;
						pgn.action = 30;
						break;
					}
#else
				if( checkbanned( src ) != 0 )
				{
					forced_log = 1;
					pgn.action = 30;
				}
#endif
				//not yet in banlist then check if we should add it
				if( forced_log == 0 )
				{
					if( src == g_internal->f_cons_last_received_IP )
					{
						g_internal->f_cons_last_received_IP_count++;
						if( g_internal->f_cons_last_received_IP_count >= g_internal->f_cons_last_received_IP_count_limit )
						{
							//yes he is a flooder
#ifdef USE_FIXED_LIST
							g_internal->temp_connection_flood_banns[ g_internal->temp_block_count ] = src;
							g_internal->temp_block_count = (g_internal->temp_block_count + 1) & TEMP_BLOCK_LIST_MASK;
#else
							Addbanned( src );
#endif
							forced_log = 1;
							pgn.action = 30;
						}
					}
					else
					{
						//memorize new IP to see how many times it will consecutively connect
						g_internal->f_cons_last_received_IP = src;
						g_internal->f_cons_last_received_IP_count = 0;
					}
				}
			}
		}
	}

	if( range || opening 
		|| ( forced_log == 1 && IsListEmpty( &g_internal->queue.irp_list ) && g_internal->blockhttp == 0 ) //this is required or on DDOS CPU usage will go to 100%..
		) 
	{
		pgn.protocol=iph->ipProtocol;

		pgn.source.addr4.sin_family = AF_INET;
		pgn.source.addr4.sin_addr.s_addr = iph->ipSource;
		pgn.source.addr4.sin_port = HTONS(srcport);

		pgn.dest.addr4.sin_family = AF_INET;
		pgn.dest.addr4.sin_addr.s_addr = iph->ipDestination;
		pgn.dest.addr4.sin_port = HTONS(destport);

		Notification_Send(&g_internal->queue, &pgn);

		if( pgn.action != 1 && pgn.action != 2 )
			return PF_DROP;
	}

	return PF_FORWARD;
}

static NTSTATUS drv_create(PDEVICE_OBJECT device, PIRP irp) {
	irp->IoStatus.Status=STATUS_SUCCESS;
	irp->IoStatus.Information=0;

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

static NTSTATUS drv_cleanup(PDEVICE_OBJECT device, PIRP irp) {
	setfilter(NULL);
	SetRanges(NULL, 0);
	SetRanges(NULL, 1);
#ifndef USE_FIXED_LIST
	FreeAllocatedBanList();
#endif

	DestroyNotificationQueue(&g_internal->queue);

	irp->IoStatus.Status=STATUS_SUCCESS;
	irp->IoStatus.Information=0;

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

static NTSTATUS drv_control(PDEVICE_OBJECT device, PIRP irp) {
	PIO_STACK_LOCATION irpstack;
	ULONG controlcode;
	NTSTATUS status;

	irp->IoStatus.Status=STATUS_SUCCESS;
	irp->IoStatus.Information=0;

	irpstack=IoGetCurrentIrpStackLocation(irp);
	controlcode=irpstack->Parameters.DeviceIoControl.IoControlCode;

	switch(controlcode) {
		case IOCTL_PEERGUARDIAN_HOOK:
			if(irp->AssociatedIrp.SystemBuffer!=NULL && irpstack->Parameters.DeviceIoControl.InputBufferLength==sizeof(int)) {
				int *hook=(int*)irp->AssociatedIrp.SystemBuffer;
				setfilter((*hook)?filter_cb:NULL);
			}
			else irp->IoStatus.Status=STATUS_INVALID_PARAMETER;
			break;
		case IOCTL_PEERGUARDIAN_HTTP:
			if(irp->AssociatedIrp.SystemBuffer!=NULL && irpstack->Parameters.DeviceIoControl.InputBufferLength==sizeof(int)) {
				g_internal->blockhttp=*((int*)irp->AssociatedIrp.SystemBuffer);
			}
			else irp->IoStatus.Status=STATUS_INVALID_PARAMETER;
			break;
		case IOCTL_PEERGUARDIAN_SETRANGES: {
			PGRANGES *ranges;
			ULONG inputlen;

			ranges = irp->AssociatedIrp.SystemBuffer;
			inputlen = irpstack->Parameters.DeviceIoControl.InputBufferLength;

			if(inputlen >= offsetof(PGRANGES, ranges[0]) && inputlen >= offsetof(PGRANGES, ranges[ranges->count])) {
				SetRanges(ranges, ranges->block);
			}
			else {
				irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			}
		} break;
		case IOCTL_PEERGUARDIAN_GETNOTIFICATION:
			return Notification_Recieve(&g_internal->queue, irp);
		case IOCTL_PEERGUARDIAN_CONNECTION_LIMIT:
			if(irp->AssociatedIrp.SystemBuffer!=NULL && irpstack->Parameters.DeviceIoControl.InputBufferLength==sizeof(int)) {
				g_internal->f_cons_last_received_IP_count_limit=*((int*)irp->AssociatedIrp.SystemBuffer);
			}
			else irp->IoStatus.Status=STATUS_INVALID_PARAMETER;
			break;
		case IOCTL_PEERGUARDIAN_SET_PORT:
			if(irp->AssociatedIrp.SystemBuffer!=NULL && irpstack->Parameters.DeviceIoControl.InputBufferLength==sizeof(int))
			{
				int param = *((int*)irp->AssociatedIrp.SystemBuffer);
				char openstatus = (char)(0xFF & param);
				unsigned short portnumber = param >> 16;
				if( portnumber == 0 || openstatus == 0)
					irp->IoStatus.Status=STATUS_INVALID_PARAMETER;
				g_internal->f_port_open_ports[ portnumber ] = openstatus - 1;
			}
			else irp->IoStatus.Status=STATUS_INVALID_PARAMETER;
			break;
		case IOCTL_PEERGUARDIAN_ADD_PERMA_ALLLOW:
			if( g_internal->perma_allow_list_length < PERMA_ALLOW_MAX_LENGTH 
				&& irp->AssociatedIrp.SystemBuffer!=NULL 
				&& irpstack->Parameters.DeviceIoControl.InputBufferLength==sizeof(ULONG))
			{
				g_internal->perma_allow_list[ g_internal->perma_allow_list_length++ ]=*((ULONG*)irp->AssociatedIrp.SystemBuffer);
			}
			else irp->IoStatus.Status=STATUS_INVALID_PARAMETER;
			break;
		case IOCTL_PEERGUARDIAN_SET_PORT_DET:
			if(irp->AssociatedIrp.SystemBuffer!=NULL && irpstack->Parameters.DeviceIoControl.InputBufferLength==sizeof(int)) {
				g_internal->disable_port_scan_detector=*(int*)irp->AssociatedIrp.SystemBuffer;
			}
			else irp->IoStatus.Status=STATUS_INVALID_PARAMETER;
			break;
		case IOCTL_PEERGUARDIAN_SET_FLOOD_DET:
			if(irp->AssociatedIrp.SystemBuffer!=NULL && irpstack->Parameters.DeviceIoControl.InputBufferLength==sizeof(int)) {
				g_internal->disable_connection_flood_detector=*(int*)irp->AssociatedIrp.SystemBuffer;
			}
			else irp->IoStatus.Status=STATUS_INVALID_PARAMETER;
			break;
/*		case IOCTL_PEERGUARDIAN_ASSIGN_BANLIST_BUFF:
			if(irp->AssociatedIrp.SystemBuffer!=NULL && irpstack->Parameters.DeviceIoControl.InputBufferLength==sizeof(ULONG *)) {
				g_internal->list_of_newly_banned_IPs=*((ULONG **)irp->AssociatedIrp.SystemBuffer);
			}
			else irp->IoStatus.Status=STATUS_INVALID_PARAMETER;
			break;*/
		default:
			irp->IoStatus.Status=STATUS_INVALID_PARAMETER;
	}

	status=irp->IoStatus.Status;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
}

static void drv_unload(PDRIVER_OBJECT driver) {
	UNICODE_STRING devlink;

	RtlInitUnicodeString(&devlink, DOS_DEVICE_NAME);
	IoDeleteSymbolicLink(&devlink);

	IoDeleteDevice(driver->DeviceObject);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registrypath) {
	UNICODE_STRING devicename;
	PDEVICE_OBJECT device=NULL;
	NTSTATUS status;

	RtlInitUnicodeString(&devicename, NT_DEVICE_NAME);
	status=IoCreateDevice(driver, sizeof(PGINTERNAL), &devicename, FILE_DEVICE_PEERGUARDIAN, 0, FALSE, &device);

	if(NT_SUCCESS(status)) {
		UNICODE_STRING devicelink;

		RtlInitUnicodeString(&devicelink, DOS_DEVICE_NAME);
		status=IoCreateSymbolicLink(&devicelink, &devicename);

		driver->MajorFunction[IRP_MJ_CREATE]=
		driver->MajorFunction[IRP_MJ_CLOSE]=drv_create;
		driver->MajorFunction[IRP_MJ_CLEANUP]=drv_cleanup;
		driver->MajorFunction[IRP_MJ_DEVICE_CONTROL]=drv_control;
		driver->DriverUnload=drv_unload;
		device->Flags|=DO_BUFFERED_IO;

		g_internal=device->DeviceExtension;

		KeInitializeSpinLock(&g_internal->rangeslock);
		InitNotificationQueue(&g_internal->queue);

		g_internal->blockedcount = 0;
		g_internal->allowedcount = 0;

		g_internal->blockhttp=1;
	}

	if(!NT_SUCCESS(status))
		drv_unload(driver);

	return status;
}
