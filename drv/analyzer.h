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