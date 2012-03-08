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

#include "windows.h"
#include "SHELLAPI.H"
#include "Winternl.h"

#include "../dbgexts.h"

extern IDebugClient* pDebugClient;
extern IDebugControl* pDebugControl;

#include "windbgshark.h"

extern HANDLE hPcapWatchdog;
extern HANDLE hWatchdogTerminateEvent;
extern BOOL Debug;
extern IDebugSymbols *pDebugSymbols;
extern IDebugDataSpaces *pDebugDataSpaces;
extern IDebugRegisters *pDebugRegisters;
extern ULONG packetFastcallRegIdx;
extern BOOLEAN is64Target;

#define SIGN_EXTEND(_x_) (ULONG64)(LONG)(_x_)

#include "pcap.h"

#define guint8	UINT8
#define gint8	INT8
#define guint16	UINT16
#define gint16	INT16
#define guint32	UINT32
#define gint32	INT32

// To avoid writing a packet larger, than pcap fomat allows
#define MAX_PCAP_DATA_SIZE 0xFFFF

WCHAR pcapFilepath[MAX_PATH];
ULONG prevPcapSize;
HANDLE hSharkPcap = INVALID_HANDLE_VALUE;
HANDLE hWiresharkProcess = INVALID_HANDLE_VALUE;

ULONG64 getRegisterVal(PDEBUG_VALUE Register)
{
	if (is64Target)
    {
        return Register->I64;
    }

    return SIGN_EXTEND(Register->I32);
}

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

EXT_PENDED_PACKET_OFFSETS packetOffsets;

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


typedef struct pcap_hdr_s {
        guint32 magic_number;   /* magic number */
        guint16 version_major;  /* major version number */
        guint16 version_minor;  /* minor version number */
        gint32  thiszone;       /* GMT to local correction */
        guint32 sigfigs;        /* accuracy of timestamps */
        guint32 snaplen;        /* max length of captured packets, in octets */
        guint32 network;        /* data link type */
} pcap_hdr_t;

typedef struct pcaprec_hdr_s {
        guint32 ts_sec;         /* timestamp seconds */
        guint32 ts_usec;        /* timestamp microseconds */
        guint32 incl_len;       /* number of octets of packet saved in file */
        guint32 orig_len;       /* actual length of packet */
} pcaprec_hdr_t;


typedef struct ether_hdr_s {
		guint8  ether_dhost[6];
		guint8  ether_shost[6];
		guint16	ether_type;
} ether_hdr_t;

typedef struct ip_hdr_s {
		guint8 ip_hl:4; /* both fields are 4 bits */
		guint8 ip_v:4;
		guint8  ip_tos;
		guint16 ip_len;
		guint16 ip_id;
		guint16 ip_off;
		guint8  ip_ttl;
		guint8  ip_p;
		guint16 ip_sum;
		guint32	ip_src;
		guint32	ip_dst;
} ip_hdr_t;

typedef struct tcp_hdr_s {
        unsigned short source;
        unsigned short dest;
        unsigned long seq;
        unsigned long ack_seq;       
        unsigned short res1:4;
        unsigned short doff:4;
        unsigned short fin:1;
        unsigned short syn:1;
        unsigned short rst:1;
        unsigned short psh:1;
        unsigned short ack:1;
        unsigned short urg:1;
        unsigned short res2:2;
        unsigned short window;       
        unsigned short check;
        unsigned short urg_ptr;
} tcp_hdr_t;


HRESULT openPcap()
{
	WCHAR tmpDir[MAX_PATH + 5];
	if(GetTempPathW(sizeof(tmpDir) / sizeof(WCHAR), tmpDir) == 0)
	{
		myDprintf("[windbgshark] openPcap: error\n");
		return E_FAIL;
	}

	if(GetTempFileNameW(tmpDir, L"wdbgshrk_", 0, pcapFilepath) == 0)
	{
		myDprintf("[windbgshark] openPcap: error\n");
		return E_FAIL;
	}

	for(WCHAR *fileExt = pcapFilepath + wcslen(pcapFilepath) - 1;
		fileExt > 0;
		fileExt--)
	{
		if(fileExt[0] == L'.')
		{
			wcscpy(fileExt, L".pcap\0");
			break;
		}
	}

	hSharkPcap = CreateFileW(
		pcapFilepath,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hSharkPcap == INVALID_HANDLE_VALUE)
	{
		myDprintf("[windbgshark] openPcap: error\n");
		printLastError();
		return E_FAIL;
	}

	pcap_hdr_t pcap_hdr;
	pcap_hdr.magic_number = 0xa1b2c3d4;
	pcap_hdr.version_major = 2;
	pcap_hdr.version_minor = 4;
	pcap_hdr.thiszone = 0;
	pcap_hdr.sigfigs = 0;
	pcap_hdr.snaplen = 0xffff;
	pcap_hdr.network = 1;
	
	DWORD cbWritten = 0;
	WriteFile(
		hSharkPcap,
		&pcap_hdr,
		sizeof(pcap_hdr),
		&cbWritten,
		NULL);

	myDprintf("[windbgshark] openPcap: %d bytes written\n", cbWritten);

	return S_OK;
}

void closePcap()
{
	CloseHandle(hSharkPcap);
	hSharkPcap = INVALID_HANDLE_VALUE;
}

HRESULT startWireshark()
{
	SHELLEXECUTEINFOW info;
	ZeroMemory(&info, sizeof(info));

	info.cbSize = sizeof(SHELLEXECUTEINFOA);
	info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_DOENVSUBST;
	info.hwnd = NULL;
	info.lpVerb = NULL;
	info.lpFile = L"Wireshark.exe";
	info.lpParameters = pcapFilepath;
	info.nShow = SW_SHOWNORMAL;
	info.lpIDList = NULL;
	info.lpClass = NULL;
	info.hkeyClass = NULL;
	info.dwHotKey = NULL;
	info.hIcon = NULL;

	if(!ShellExecuteExW(&info))
	{
		info.lpFile = L"%ProgramFiles%\\Wireshark\\Wireshark.exe";

		if(!ShellExecuteExW(&info))
		{
			info.lpFile = L"%%ProgramW6432%%\\Wireshark\\Wireshark.exe";

			if(!ShellExecuteExW(&info))
			{
				dprintf("[windbgshark] Error starting Wireshark. Please, ensure that Wireshark.exe "
						"is located at %%ProgramFiles%%\\Wireshark, "
						"%%ProgramW6432%%\\Wireshark or anywhere in %%PATH%%\n");
				
				return E_FAIL;
			}
		}
	}

	hWiresharkProcess = info.hProcess;

	myDprintf("[windbgshark] startWireshark: hWiresharkProcess = %p\n", hWiresharkProcess);

	return S_OK;
}

void stopWireshark()
{
	if(hWiresharkProcess != INVALID_HANDLE_VALUE)
	{
		TerminateProcess(hWiresharkProcess, 0);
	}
}

void fixCurrentPcapSize()
{
	LARGE_INTEGER liPrevPcapSize;
	BOOL result;

	// myDprintf("[windbgshark] fixCurrentPcapSize: enter\n");

	if(hSharkPcap == INVALID_HANDLE_VALUE)
	{
		myDprintf("[windbgshark] hSharkPcap: error\n");
		printLastError();
		return;
	}

	result = GetFileSizeEx(hSharkPcap, &liPrevPcapSize);

	// Pray for dump < 4gb
	prevPcapSize = liPrevPcapSize.LowPart;

	// myDprintf("[windbgshark] prevPcapSize = %p, result = %d\n", prevPcapSize, result);
}

HRESULT getPacketOffsets()
{
	ULONG packetTypeID = 0;
	ULONG64 moduleBase = 0;
	pDebugSymbols->GetSymbolTypeId("windbgshark_drv!PENDED_PACKET", &packetTypeID, &moduleBase);

	pDebugSymbols->GetFieldOffset(moduleBase, packetTypeID, "data", &packetOffsets.dataRvaOffset);
	pDebugSymbols->GetFieldOffset(moduleBase, packetTypeID, "dataLength", &packetOffsets.dataLengthOffset);
	pDebugSymbols->GetFieldOffset(moduleBase, packetTypeID, "allocatedBytes", &packetOffsets.allocatedBytesOffset);
	pDebugSymbols->GetFieldOffset(moduleBase, packetTypeID, "timestamp", &packetOffsets.timestampOffset);
	pDebugSymbols->GetFieldOffset(moduleBase, packetTypeID, "localTime", &packetOffsets.localTimeOffset);
	pDebugSymbols->GetFieldOffset(moduleBase, packetTypeID, "ipv4SrcAddr", &packetOffsets.ipv4SrcAddrOffset);
	pDebugSymbols->GetFieldOffset(moduleBase, packetTypeID, "ipv4DstAddr", &packetOffsets.ipv4DstAddrOffset);
	pDebugSymbols->GetFieldOffset(moduleBase, packetTypeID, "srcPort", &packetOffsets.srcPortOffset);
	pDebugSymbols->GetFieldOffset(moduleBase, packetTypeID, "dstPort", &packetOffsets.dstPortOffset);
	pDebugSymbols->GetFieldOffset(moduleBase, packetTypeID, "sequenceNumber", &packetOffsets.sequenceNumberOffset);
	pDebugSymbols->GetFieldOffset(moduleBase, packetTypeID, "acknowledgementNumber", &packetOffsets.acknowledgementNumberOffset);

	return S_OK;
}

void parsePacket(EXT_PENDED_PACKET *packet)
{
	DEBUG_VALUE packetFastcallReg;
	pDebugRegisters->GetValue(packetFastcallRegIdx, &packetFastcallReg);
	packet->packetRva = getRegisterVal(&packetFastcallReg);
	
	pDebugDataSpaces->ReadPointersVirtual(1, packet->packetRva + packetOffsets.dataRvaOffset, &packet->dataRva);
	pDebugDataSpaces->ReadVirtual(packet->packetRva + packetOffsets.dataLengthOffset, &packet->dataLength, sizeof(packet->dataLength), NULL);
	pDebugDataSpaces->ReadVirtual(packet->packetRva + packetOffsets.allocatedBytesOffset, &packet->allocatedBytes, sizeof(packet->allocatedBytes), NULL);
	pDebugDataSpaces->ReadVirtual(packet->packetRva + packetOffsets.timestampOffset, &packet->timestamp, sizeof(packet->timestamp), NULL);
	pDebugDataSpaces->ReadVirtual(packet->packetRva + packetOffsets.localTimeOffset, &packet->localTime, sizeof(packet->localTime), NULL);
	pDebugDataSpaces->ReadVirtual(packet->packetRva + packetOffsets.ipv4SrcAddrOffset, &packet->ipv4SrcAddr, sizeof(packet->ipv4SrcAddr), NULL);
	pDebugDataSpaces->ReadVirtual(packet->packetRva + packetOffsets.ipv4DstAddrOffset, &packet->ipv4DstAddr, sizeof(packet->ipv4DstAddr), NULL);
	pDebugDataSpaces->ReadVirtual(packet->packetRva + packetOffsets.srcPortOffset, &packet->srcPort, sizeof(packet->srcPort), NULL);
	pDebugDataSpaces->ReadVirtual(packet->packetRva + packetOffsets.dstPortOffset, &packet->dstPort, sizeof(packet->dstPort), NULL);
	pDebugDataSpaces->ReadVirtual(packet->packetRva + packetOffsets.sequenceNumberOffset, &packet->sequenceNumber, sizeof(packet->sequenceNumber), NULL);
	pDebugDataSpaces->ReadVirtual(packet->packetRva + packetOffsets.acknowledgementNumberOffset, &packet->acknowledgementNumber, sizeof(packet->acknowledgementNumber), NULL);
}


void composePcapRecord(PBYTE fullPacketSegment, EXT_PENDED_PACKET* packet, ULONG dataOffset, ULONG dataLength, UINT32 ts_sec, UINT32 ts_usec, PULONG pcapFileOffset)
{
	HRESULT result;
	ULONG pcapEntrySize = 0;
	PBYTE pcapEntry = NULL;

	pcapEntrySize = sizeof(pcaprec_hdr_t) + sizeof(ether_hdr_t) + sizeof(ip_hdr_t) + sizeof(tcp_hdr_t) + dataLength;
	pcapEntry = new BYTE[pcapEntrySize];
	memset(pcapEntry, 0, pcapEntrySize);


	pcaprec_hdr_s pcaprec_hdr;

	pcaprec_hdr.ts_sec = ts_sec;
	pcaprec_hdr.ts_usec = ts_usec;
	pcaprec_hdr.incl_len = pcapEntrySize - sizeof(pcaprec_hdr);
	pcaprec_hdr.orig_len = pcapEntrySize - sizeof(pcaprec_hdr);
	memcpy(pcapEntry, &pcaprec_hdr, sizeof(pcaprec_hdr));


	ether_hdr_t ether_hdr;

	memcpy(&ether_hdr.ether_shost, "\xaa\xaa\xaa\xaa\xaa\xaa", 6); // fake
	memcpy(&ether_hdr.ether_dhost, "\xbb\xbb\xbb\xbb\xbb\xbb", 6); // fake
	ether_hdr.ether_type = 8; // Type: IP
	memcpy(pcapEntry + sizeof(pcaprec_hdr), &ether_hdr, sizeof(ether_hdr));


	ip_hdr_t ip_hdr;

	memset(&ip_hdr, 0, sizeof(ip_hdr));		
	ip_hdr.ip_hl = 5;
	ip_hdr.ip_v = 4;
	ip_hdr.ip_tos = 0;
	ip_hdr.ip_len = _byteswap_ushort(sizeof(ip_hdr) + sizeof(tcp_hdr_t) + dataLength);
	ip_hdr.ip_id = 0;
	ip_hdr.ip_off = 0;
	ip_hdr.ip_ttl = 128;
	ip_hdr.ip_p = 6;
	ip_hdr.ip_src = packet->ipv4SrcAddr;
	ip_hdr.ip_dst = packet->ipv4DstAddr;
	UINT32 sum = 0;
	for(int i = 0; i < sizeof(ip_hdr) / 2; i++)
	{
		sum += (UINT32) (((UINT16*) &ip_hdr)[i]);
	}
	while (sum>>16)
	{
	  sum = (sum & 0xFFFF) + (sum >> 16);
	}
	ip_hdr.ip_sum = ~sum;
	memcpy(pcapEntry + sizeof(pcaprec_hdr) + sizeof(ether_hdr), &ip_hdr, sizeof(ip_hdr));


	tcp_hdr_t tcp_hdr;

	memset(&tcp_hdr, 0, sizeof(tcp_hdr));	
	tcp_hdr.source = _byteswap_ushort(packet->srcPort);
	tcp_hdr.dest = _byteswap_ushort(packet->dstPort);
	tcp_hdr.seq = _byteswap_ulong(packet->sequenceNumber);
	tcp_hdr.ack_seq = _byteswap_ulong(packet->acknowledgementNumber);
	// Keep correct sequence numbers
	packet->sequenceNumber += dataLength;
	tcp_hdr.ack = 1;
	tcp_hdr.psh = 1;
	tcp_hdr.doff = 5;
	tcp_hdr.window = 0x100;
	memcpy(pcapEntry + sizeof(pcaprec_hdr) + sizeof(ether_hdr) + sizeof(ip_hdr), &tcp_hdr, sizeof(tcp_hdr));

	// myDprintf("[windbgshark] dataRva = %p\n", dataRva);
	// myDprintf("[windbgshark] pcapEntry = %x\n", pcapEntry);
	// myDprintf("[windbgshark] buffer = %x\n", pcapEntry + sizeof(pcaprec_hdr) + sizeof(ether_hdr) + sizeof(ip_hdr) + sizeof(tcp_hdr));

	RtlCopyMemory(
		pcapEntry + sizeof(pcaprec_hdr) + sizeof(ether_hdr) + sizeof(ip_hdr) + sizeof(tcp_hdr),
		fullPacketSegment + dataOffset,
		dataLength);

	// myDprintf("[windbgshark] feedPcapWatchdog: ReadVirtual result = %d.n", result);

	if (hSharkPcap == INVALID_HANDLE_VALUE)
	{
		// myDprintf("[windbgshark] feedPcapWatchdog: error\n");
		printLastError();

		goto Cleanup;
	}


	OVERLAPPED overlapped;
	DWORD cbWritten;

	memset(&overlapped, 0, sizeof(overlapped));
	overlapped.Offset = prevPcapSize + *pcapFileOffset;
		
	WriteFile(
		hSharkPcap,
		pcapEntry,
		pcapEntrySize,
		&cbWritten,
		&overlapped);

	SetEndOfFile(hSharkPcap);

	*pcapFileOffset += pcapEntrySize;

	myDprintf("[windbgshark] composePcapRecord: wrote %d byte at offset %d\n", cbWritten, overlapped.Offset);

Cleanup:

	if(pcapEntry != NULL)
	{
		delete [] pcapEntry;
		pcapEntry = NULL;
	}


	return;
}

void composePcapRecords()
{
	EXT_PENDED_PACKET packet;
	parsePacket(&packet);
	
	if(packet.dataLength == 0)
	{
		myDprintf("[windbgshark] composePcapRecords: dataLength == 0, continue...\n");
		goto Cleanup;
	}

	ULONG maxPayloadSize = MAX_PCAP_DATA_SIZE - (sizeof(pcaprec_hdr_t) + sizeof(ether_hdr_t) + sizeof(ip_hdr_t) + sizeof(tcp_hdr_t));
	ULONG totalFramesNum = packet.dataLength / maxPayloadSize;
	if(packet.dataLength % maxPayloadSize)
	{
			totalFramesNum++;
	}
	
	PBYTE fullPacketSegment = new BYTE[packet.dataLength];

	if(pDebugDataSpaces->ReadVirtual(
		packet.dataRva,
		fullPacketSegment,
		packet.dataLength,
		NULL) != S_OK)
	{
		goto Cleanup;
	}

	ULONG pcapFileOffset = 0;

	for(int currFrameNum = 0; currFrameNum < totalFramesNum; currFrameNum++)
	{
		ULONG dataLength = maxPayloadSize;
		if(currFrameNum == totalFramesNum - 1)
		{
			dataLength = packet.dataLength % maxPayloadSize;
		}

		ULONG ts_sec = 0, ts_usec = 0;
		FILETIME systemTimeAsFileTime, localTimeAsFileTime;
		GetSystemTimeAsFileTime(&systemTimeAsFileTime);
		FileTimeToLocalFileTime(&systemTimeAsFileTime, &localTimeAsFileTime);
		RtlTimeToSecondsSince1970((PLARGE_INTEGER) &localTimeAsFileTime, &ts_sec);
		TIME_ZONE_INFORMATION TimeZoneInfo;
		GetTimeZoneInformation(&TimeZoneInfo);
		ts_sec += TimeZoneInfo.Bias * 60;
		SYSTEMTIME systemTime;
		FileTimeToSystemTime(&localTimeAsFileTime, &systemTime);
		ts_usec = systemTime.wMilliseconds * 1000;
		ts_usec += (localTimeAsFileTime.dwLowDateTime / 10) % 1000;

		composePcapRecord(fullPacketSegment, &packet, currFrameNum * maxPayloadSize, dataLength, ts_sec, ts_usec, &pcapFileOffset);
	}

Cleanup:

	if(fullPacketSegment != NULL)
	{
		delete [] fullPacketSegment;
	}

	return;
}

void feedPcapWatchdog()
{
	myDprintf("[windbgshark] feedPcapWatchdog: enter\n");

	do
	{
		myDprintf("[windbgshark] feedPcapWatchdog: loop start\n");
		composePcapRecords();
	}
	while(WaitForSingleObject(hWatchdogTerminateEvent, 1000) != WAIT_OBJECT_0);

	myDprintf("[windbgshark] feedPcapWatchdog: return\n");

	return;
}

void terminateWatchdog()
{
	DWORD dwWaitResult = 0;

	myDprintf("[windbgshark] terminateWatchdog: enter\n");
	

	if(hWatchdogTerminateEvent != INVALID_HANDLE_VALUE)
	{
		myDprintf("[windbgshark] terminateWatchdog: SetEvent\n");
		SetEvent(hWatchdogTerminateEvent);
	}

	if(hPcapWatchdog != INVALID_HANDLE_VALUE)
	{
		myDprintf("[windbgshark] terminateWatchdog: WaitForSingleObject\n");

		dwWaitResult = WaitForSingleObject(hPcapWatchdog, 3000);

		if(dwWaitResult != WAIT_OBJECT_0)
		{
			myDprintf("[windbgshark] terminateWatchdog: thread did not terminate by self, now killing it\n");

			TerminateThread(hPcapWatchdog, 0);
		}

		hPcapWatchdog = INVALID_HANDLE_VALUE;
	}

	if(hWatchdogTerminateEvent != INVALID_HANDLE_VALUE)
	{
		ResetEvent(hWatchdogTerminateEvent);
	}

	fixCurrentPcapSize();
}

void showPacket()
{
	EXT_PENDED_PACKET packet;
	parsePacket(&packet);

	char cmd[0x100] = "";
	sprintf(cmd, "db %p L%x", packet.dataRva, packet.dataLength);

	pDebugControl->Execute(
			DEBUG_OUTCTL_ALL_CLIENTS,
			cmd,
			DEBUG_EXECUTE_ECHO);
}

void setPacketSize(UINT32 size)
{
	EXT_PENDED_PACKET packet;
	parsePacket(&packet);

	if(size > packet.allocatedBytes)
	{
		dprintf("[windbgshark] Sorry, too big packet size\n");
		return;
	}

	pDebugDataSpaces->WriteVirtual(packet.packetRva + packetOffsets.dataLengthOffset, (PVOID) &size, sizeof(size), NULL);
}

void setDataAtPacketOffset(UINT32 offset, PCSTR str, UINT32 len)
{
	EXT_PENDED_PACKET packet;
	parsePacket(&packet);

	if(offset > packet.dataLength)
	{
		return;
	}

	if(len > packet.allocatedBytes || offset + len > packet.allocatedBytes)
	{
		dprintf("[windbgshark] Sorry, too big packet\n");
		return;
	}

	pDebugDataSpaces->WriteVirtual(packet.dataRva + offset, (PVOID) str, len, NULL);

	if(offset + len > packet.dataLength)
	{
		packet.dataLength = offset + len;
		pDebugDataSpaces->WriteVirtual(packet.packetRva + packetOffsets.dataLengthOffset, &packet.dataLength, sizeof(packet.dataLength), NULL);
	}
}

void insertDataAtPacketOffset(UINT32 offset, PCSTR str, UINT32 len)
{
	EXT_PENDED_PACKET packet;
	parsePacket(&packet);

	if(len > packet.allocatedBytes || packet.dataLength + len > packet.allocatedBytes)
	{
		dprintf("[windbgshark] Sorry, too big packet\n");
		return;
	}

	if(offset > packet.dataLength)
	{
		return;
	}


	packet.dataLength += len;

	PBYTE data = new BYTE[packet.dataLength];	
	ZeroMemory(data, packet.dataLength);

	pDebugDataSpaces->ReadVirtual(packet.dataRva, data, packet.dataLength - len, NULL);

	memmove_s(data + offset + len, packet.dataLength - offset - len, data + offset, packet.dataLength - offset - len);
	memmove_s(data + offset, len, (VOID*) str, len);

	pDebugDataSpaces->WriteVirtual(packet.packetRva + packetOffsets.dataLengthOffset, &packet.dataLength, sizeof(packet.dataLength), NULL);
	pDebugDataSpaces->WriteVirtual(packet.dataRva, data, packet.dataLength, NULL);
	

	if(data != NULL)
	{
		delete [] data;
	}
}

void cutDataAtPacketOffset(UINT32 offset, UINT32 len)
{
	EXT_PENDED_PACKET packet;
	parsePacket(&packet);

	if(offset >= packet.dataLength)
	{
		return;
	}

	len = min(len, packet.dataLength - offset);

	PBYTE data = new BYTE[packet.dataLength];	
	ZeroMemory(data, packet.dataLength);

	pDebugDataSpaces->ReadVirtual(packet.dataRva, data, packet.dataLength, NULL);
	
	memmove_s(data + offset, packet.dataLength - offset - len, data + offset + len, packet.dataLength - offset - len);
	packet.dataLength -= len;

	pDebugDataSpaces->WriteVirtual(packet.packetRva + packetOffsets.dataLengthOffset, &packet.dataLength, sizeof(packet.dataLength), NULL);
	pDebugDataSpaces->WriteVirtual(packet.dataRva, data, packet.dataLength, NULL);

	if(data != NULL)
	{
		delete [] data;
	}
}