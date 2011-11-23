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

#pragma once

KSTART_ROUTINE thAnalyzer;
KEVENT gWorkerEvent;

typedef struct _FLOW_DATA
{
	UINT64			flowHandle;
	UINT64			flowContext;

	USHORT			ipProto;

	FWP_DIRECTION	direction;

	ULONG			localAddressV4;
	USHORT			localPort;

	ULONG			remoteAddressV4;
	USHORT			remotePort;

	// TCP sequence numbering
	
	// Sequence number (for the local machine), or Acknowledgement number (for the remote party) 
	UINT32 localCounter;
	// The opposite
	UINT32 remoteCounter;
	
	LIST_ENTRY		listEntry;
	BOOLEAN			deleting;
} FLOW_DATA;

typedef struct PENDED_PACKET_
{
	LIST_ENTRY listEntry;

	FLOW_DATA *flowContext;

	ULONG dataLength;
	PBYTE data;

	UINT32 flags;

	LARGE_INTEGER localTime;
	ULONG timestamp;

	UINT32 ipv4SrcAddr;
	UINT16 srcPort;

	UINT32 ipv4DstAddr;
	UINT16 dstPort;

	UINT32 sequenceNumber;
	UINT32 acknowledgementNumber;
	
	// Defines virtual FIN packet, received by thAnalyzer when TCP flow
	// had already been closed by OS
	BOOLEAN close;

	// Pointer to mdl is used, whenever memory for a packet is freed 
	// after reinjection
	PMDL mdl;

	// This flag, if set, allows thAnalyzer thread to reinject the 
	// packet after inspecting it by protocol parsers. If not set, the
	// packet shouldn't be reinjected, at least right now
	BOOLEAN permitted;

	// The original size of the pool for the "data"
	ULONG allocatedBytes;
} PENDED_PACKET;

#define TAG_PENDEDPACKET 'pPaL'
#define TAG_PENDEDPACKETDATA 'dPaL'

void FreePendedPacket(IN OUT PENDED_PACKET* packet);

PENDED_PACKET* AllocateAndInitializeStreamPendedPacket(
	IN const FWPS_INCOMING_VALUES0* inFixedValues,
	IN const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
	IN FLOW_DATA* flowContext,
	IN PLARGE_INTEGER localTime,
	IN OUT FWPS_STREAM_CALLOUT_IO_PACKET0* packet);

NTSTATUS
ReinjectPendedPacket(
	IN PENDED_PACKET *packet,
	IN FLOW_DATA *flowData);