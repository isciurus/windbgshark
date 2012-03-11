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

typedef struct EXT_PENDED_PACKET_OFFSETS_
{
	ULONG dataRvaOffset;
	ULONG dataLengthOffset;
	ULONG allocatedBytesOffset;
	ULONG localTimeOffset;
	ULONG timestampOffset;
	ULONG ipv4SrcAddrOffset;
	ULONG srcPortOffset;
	ULONG ipv4DstAddrOffset;
	ULONG dstPortOffset;
	ULONG sequenceNumberOffset;
	ULONG acknowledgementNumberOffset;
} EXT_PENDED_PACKET_OFFSETS;

typedef struct EXT_PENDED_PACKET_
{
	ULONG64 packetRva;
	ULONG64 dataRva;
	ULONG dataLength;
	ULONG allocatedBytes;
	LARGE_INTEGER localTime;
	ULONG timestamp;
	UINT32 ipv4SrcAddr;
	UINT16 srcPort;
	UINT32 ipv4DstAddr;
	UINT16 dstPort;
	UINT32 sequenceNumber;
	UINT32 acknowledgementNumber;
} EXT_PENDED_PACKET;

HRESULT openPcap();
void closePcap();
void fixCurrentPcapSize();
void composePcapRecords(EXT_PENDED_PACKET *packet);

void feedPcapWatchdog();
void terminateWatchdog();

HRESULT startWireshark();
void stopWireshark();

HRESULT getPacketOffsets();
void showPacket();
void setPacketSize(UINT32 size);
void setDataAtPacketOffset(UINT32 offset, PCSTR str, UINT32 len);
void insertDataAtPacketOffset(UINT32 offset, PCSTR str, UINT32 len);
void cutDataAtPacketOffset(UINT32 offset, UINT32 len);