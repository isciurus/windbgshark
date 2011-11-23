#include "ntddk.h"

#include "fwpsk.h"
#include "mstcpip.h"
#include "ntstrsafe.h"

#include "windbgshark_drv.h"
#include "analyzer.h"


NTSTATUS dumpPacketData(PBYTE data, SIZE_T dataLength)
{
	PBYTE	dump = NULL;
	SIZE_T offset, block;

	if(dataLength == 0)
	{
		return STATUS_UNSUCCESSFUL;
	}

	dump = ExAllocatePoolWithTag(
					NonPagedPool, 
					dataLength + 1, 
					'dmp');
	
	if (dump == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlZeroMemory(dump, dataLength + 1);
	RtlCopyMemory(dump, data, dataLength);

	for(offset = 0; offset < dataLength; offset++)
	{
		// dot instead of non-printable chars
		if(dump[offset] <= ' ' || dump[offset] > 0x7F)
		{
			dump[offset] = '.';
		}

	}

	for(offset = 0; offset < dataLength; offset += 0x200)
	{
#ifdef DEBUG
		DbgPrintEx(
			DPFLTR_IHVNETWORK_ID, 
			DPFLTR_ERROR_LEVEL, 
			"%s",
			dump + offset);
#endif
	}

	ExFreePoolWithTag(dump, 'dmp');

	return STATUS_SUCCESS;
}

NTSTATUS debugPacket(PENDED_PACKET*	packet)
{
	NTSTATUS					ntstatus;
	IO_STATUS_BLOCK				ioStatusBlock;
	size_t						offset, cb;
	UCHAR						ipv4SrcBufStr[32], ipv4DstBufStr[32];
	DWORD						dwBytesWritten = 0;
	LARGE_INTEGER				EndOfFile;
	
	RtlZeroMemory(ipv4SrcBufStr, sizeof(ipv4SrcBufStr));
	RtlIpv4AddressToStringA(
		(IN_ADDR*) &(packet->ipv4SrcAddr), 
		ipv4SrcBufStr);

	RtlZeroMemory(ipv4DstBufStr, sizeof(ipv4DstBufStr));
	RtlIpv4AddressToStringA(
		(IN_ADDR*) &(packet->ipv4DstAddr), 
		ipv4DstBufStr);
	
#ifdef DEBUG
	DbgPrintEx(
			DPFLTR_IHVNETWORK_ID, 
			DPFLTR_ERROR_LEVEL, 
			"flowHandle: 0x%x, flags: 0x%x, src: %s:%d, dst: %s:%d \t", 
			packet->flowContext->flowHandle,
			packet->flags,
			ipv4SrcBufStr,
			packet->srcPort, 
			ipv4DstBufStr,
			packet->dstPort);


	dumpPacketData(packet->data, packet->dataLength);
#endif

	return STATUS_SUCCESS;
}
