#pragma warning(push)
#pragma warning(disable:4103)
#include <wdm.h>
#pragma warning(pop)

#include <ntddk.h>
#include "internal.h"

PGINTERNAL *g_internal;

const PGIPRANGE* inranges(const PGIPRANGE *ranges, int count, ULONG ip) {
	const PGIPRANGE *iter = ranges;
	const PGIPRANGE *last = ranges + count;

	while(0 < count) {
		int count2 = count / 2;
		const PGIPRANGE *mid = iter + count2;
		
		if(mid->start < ip) {
			iter = mid + 1;
			count -= count2 + 1;
		}
		else {
			count = count2;
		}
	}

	if(iter != last) {
		if(iter->start != ip) --iter;
	}
	else {
		--iter;
	}

	return (iter >= ranges && iter->start <= ip && ip <= iter->end) ? iter : NULL;
}

void SetRanges(const PGRANGES *ranges, int block) {
	PGIPRANGE *nranges, *oldranges;
	ULONG ncount, labelsid;
	KIRQL irq;

	if(ranges && ranges->count > 0) {
		ncount = ranges->count;
		labelsid = ranges->labelsid;
		nranges = ExAllocatePoolWithTag(NonPagedPool, ranges->count * sizeof(PGIPRANGE), '02GP');
		RtlCopyMemory(nranges, ranges->ranges, ranges->count * sizeof(PGIPRANGE));
	}
	else {
		ncount = 0;
		labelsid = 0xFFFFFFFF;
		nranges = NULL;
	}

	KeAcquireSpinLock(&g_internal->rangeslock, &irq);

	if(block) {
		oldranges = g_internal->blockedcount ? g_internal->blockedranges : NULL;

		g_internal->blockedcount = ncount;
		g_internal->blockedranges = nranges;
		g_internal->blockedlabelsid = labelsid;
	}
	else {
		oldranges = g_internal->allowedcount ? g_internal->allowedranges : NULL;

		g_internal->allowedcount = ncount;
		g_internal->allowedranges = nranges;
		g_internal->allowedlabelsid = labelsid;
	}

	KeReleaseSpinLock(&g_internal->rangeslock, irq);

	if(oldranges) {
		ExFreePoolWithTag(oldranges, '02GP');
	}
}
#ifdef USE_FIXED_LIST
int CheckInsertedAndAddIPForBan(ULONG new_IP)
{
	ULONG i,found=0;
	for(i=0;i<TEMP_BLOCK_LIST;i++)
		if( g_internal->temp_connection_flood_banns[ i ] == new_IP )
		{
			found=1;
			break;
		}
	if( found == 0 )
	{
		g_internal->temp_connection_flood_banns[ g_internal->temp_block_count ] = new_IP;
		g_internal->temp_block_count = (g_internal->temp_block_count + 1) & TEMP_BLOCK_LIST_MASK;
	}
	return found;
}
#else
int checkbanned(ULONG IP)
{
	int byte_selector,bit_selector,byte,bitmask;
	void **tp;
	unsigned int *tbyte1;
	//for byte 4
	tp = g_internal->tempban_IP_bytes;
	byte = (IP >> 0 ) & 0xFF;
	if( tp[ byte ] == NULL )
	{
		tp[ byte ] = ExAllocatePoolWithTag( PagedPool, 255 * sizeof(void*), '02GP' );
		if( tp[ byte ] == NULL )
			return 0;
		memset(tp[ byte ],0,sizeof(void*)*255);
	}
	//for byte 3
	tp = (void **)tp[ byte ];
	byte = (IP >> 8 ) & 0xFF;
	if( tp[ byte ] == NULL )
	{
		tp[ byte ] = ExAllocatePoolWithTag( PagedPool, 255 * sizeof(void*), '02GP' );
		if( tp[ byte ] == NULL )
			return 0;
		memset(tp[ byte ],0,sizeof(void*)*255);
	}
	//for byte 2
	tp = (void **)tp[ byte ];
	byte = (IP >> 16 ) & 0xFF;
	if( tp[ byte ] == NULL )
	{
		tp[ byte ] = ExAllocatePoolWithTag( PagedPool, 8 * sizeof(unsigned int), '02GP' );
		if( tp[ byte ] == NULL )
			return 0;
		memset(tp[ byte ],0,sizeof(unsigned int) * 8);
	}
	//for byte 1
	tbyte1 = (unsigned int *)tp[ byte ];
	byte = (IP >> 24 ) & 0xFF;
	byte_selector = byte / 32;
	bit_selector = byte % 32;
	bitmask = 1 << bit_selector;
	return tbyte1[ byte_selector ] & bitmask;

}
void Addbanned(ULONG IP)
{
	int byte_selector,bit_selector,byte,bitmask;
	void **tp;
	unsigned int *tbyte1;
	//for byte 4
	tp = g_internal->tempban_IP_bytes;
	byte = (IP >> 0 ) & 0xFF;
	if( tp[ byte ] == NULL )
	{
		tp[ byte ] = ExAllocatePoolWithTag( PagedPool, 255 * sizeof(void*), '02GP' );
		if( tp[ byte ] == NULL )
			return;
		memset(tp[ byte ],0,sizeof(void*)*255);
	}
	//for byte 3
	tp = (void **)tp[ byte ];
	byte = (IP >> 8 ) & 0xFF;
	if( tp[ byte ] == NULL )
	{
		tp[ byte ] = ExAllocatePoolWithTag( PagedPool, 255 * sizeof(void*), '02GP' );
		if( tp[ byte ] == NULL )
			return;
		memset(tp[ byte ],0,sizeof(void*)*255);
	}
	//for byte 2
	tp = (void **)tp[ byte ];
	byte = (IP >> 16 ) & 0xFF;
	if( tp[ byte ] == NULL )
	{
		tp[ byte ] = ExAllocatePoolWithTag( PagedPool, 8 * sizeof(unsigned int), '02GP' );
		if( tp[ byte ] == NULL )
			return;
		memset(tp[ byte ],0,sizeof(unsigned int) * 8);
	}
	//for byte 1
	tbyte1 = (unsigned int *)tp[ byte ];
	byte = (IP >> 24 ) & 0xFF;
	byte_selector = byte / 32;
	bit_selector = byte % 32;
	bitmask = 1 << bit_selector;
	tbyte1[ byte_selector ] |= bitmask;
}
void FreeAllocatedBanList()
{
	int i,j,k;
	void **tp1,**tp2,**tp3;
	tp1 = g_internal->tempban_IP_bytes;
	for( i=0; i < 255; i++ )
		if( tp1[i] )
		{
			tp2 = (void **)tp1[i];
			for( j=0; j < 255; j++ )
				if( tp2[j] )
				{
					tp3 = (void **)tp2[j];
					for( k=0; k < 255; k++ )
						if( tp3[k] )
							ExFreePoolWithTag(tp3[k], '02GP');
					ExFreePoolWithTag(tp3, '02GP');
				}
			ExFreePoolWithTag(tp2, '02GP');
		}
}
#endif