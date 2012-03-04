/*
* Windbg extension for VM traffic manipulation and analysis
* 
* Copyright 2011, isciurus. All rights reserved.
* 
* Redistribution and use in source and binary forms, with or without modification,
* are permitted provided that the following conditions are met:
* 
* - Redistributions of source code must retain the above copyright notice, this
*   list of conditions and the following disclaimer.
*
* - Redistributions in binary form must reproduce the above copyright notice, this
*   list of conditions and the following disclaimer in the documentation and/or
*   other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
* IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
* INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
* BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
* LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
* OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
* OF THE POSSIBILITY OF SUCH DAMAGE.
*
*/

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
			"h:0x%I64x,\tfl:0x%x,\t%s:%d->%s:%d\tl=%d\td=",
			packet->flowContext->flowHandle,
			packet->flags,
			ipv4SrcBufStr,
			packet->srcPort, 
			ipv4DstBufStr,
			packet->dstPort,
			packet->dataLength);


	dumpPacketData(packet->data, packet->dataLength);
#endif

	return STATUS_SUCCESS;
}
