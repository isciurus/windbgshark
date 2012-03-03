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

#include "dbgexts.h"

extern IDebugClient* pDebugClient;
extern IDebugControl* pDebugControl;

#include "windbgshark.h"

extern HANDLE hPcapWatchdog;
extern HANDLE hWatchdogTerminateEvent;
extern BOOL Debug;


#include "pcap.h"

#define guint8	UINT8
#define gint8	INT8
#define guint16	UINT16
#define gint16	INT16
#define guint32	UINT32
#define gint32	INT32

WCHAR pcapFilepath[MAX_PATH];
ULONG prevPcapSize;
HANDLE hSharkPcap = INVALID_HANDLE_VALUE;
HANDLE hWiresharkProcess = INVALID_HANDLE_VALUE;

#define DATA_OFFSET 0x20
#define DATA_LENGTH_OFFSET 0x18
#define ALLOCATED_BYTES_OFFSET 0x64
#define TIMESTAMP_OFFSET 0x38
#define LOCALTIME_OFFSET 0x30
#define IP_SRC_OFFSET 0x3c
#define IP_DST_OFFSET 0x44
#define TCP_SRC_OFFSET 0x40
#define TCP_DST_OFFSET 0x48
#define TCP_SEQ_OFFSET 0x4c
#define TCP_ACK_OFFSET 0x50


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
	WCHAR tmpDir[MAX_PATH];
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
						"%%ProgramW6432%%\\Wireshark or enywhere in %%PATH%%\n");
				
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

void composePcapRecord()
{
	HRESULT result;
	ULONG pcapEntrySize = 0;
	PBYTE pcapEntry = NULL;


	IDebugSymbols *pDebugSymbols = NULL;
	pDebugClient->QueryInterface(__uuidof(IDebugSymbols), (PVOID*) &pDebugSymbols);

	IDebugDataSpaces *pDebugDataSpaces = NULL;
	pDebugClient->QueryInterface(__uuidof(IDebugDataSpaces), (PVOID*) &pDebugDataSpaces);


	ULONG64 pPacketRva = 0;
	pDebugSymbols->GetOffsetByName("windbgsharkPacket", &pPacketRva);

	ULONG64 packetRva = 0;
	pDebugDataSpaces->ReadVirtual(pPacketRva, &packetRva, sizeof(packetRva), NULL);

	ULONG64 dataRva = 0;
	pDebugDataSpaces->ReadVirtual(packetRva + DATA_OFFSET, &dataRva, sizeof(dataRva), NULL);

	UINT16 dataLength = 0;
	pDebugDataSpaces->ReadVirtual(packetRva + DATA_LENGTH_OFFSET, &dataLength, sizeof(dataLength), NULL);
	

	if(dataLength == 0)
	{
		myDprintf("[windbgshark] composePcapRecord: dataLength == 0, continue...\n");
		goto Cleanup;
	}

	pcapEntrySize = sizeof(pcaprec_hdr_t) + sizeof(ether_hdr_t) + sizeof(ip_hdr_t) + sizeof(tcp_hdr_t) + dataLength;
	pcapEntry = new BYTE[pcapEntrySize];
	memset(pcapEntry, 0, pcapEntrySize);


	pcaprec_hdr_s pcaprec_hdr;

	pDebugDataSpaces->ReadVirtual(
		packetRva + TIMESTAMP_OFFSET,
		&pcaprec_hdr.ts_sec,
		sizeof(pcaprec_hdr.ts_sec), NULL);
	TIME_ZONE_INFORMATION TimeZoneInfo;
	GetTimeZoneInformation(&TimeZoneInfo);
	pcaprec_hdr.ts_sec += TimeZoneInfo.Bias * 60;
	LARGE_INTEGER localTime = {0, 0};
	pDebugDataSpaces->ReadVirtual(packetRva + LOCALTIME_OFFSET, &localTime, sizeof(localTime), NULL);
	pcaprec_hdr.ts_usec = (localTime.LowPart / 10) % 1000000;
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
	pDebugDataSpaces->ReadVirtual(packetRva + IP_SRC_OFFSET, &ip_hdr.ip_src, sizeof(ip_hdr.ip_src), NULL);
	pDebugDataSpaces->ReadVirtual(packetRva + IP_DST_OFFSET, &ip_hdr.ip_dst, sizeof(ip_hdr.ip_dst), NULL);
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
	pDebugDataSpaces->ReadVirtual(packetRva + TCP_SRC_OFFSET, &tcp_hdr.source, sizeof(tcp_hdr.source), NULL);
	tcp_hdr.source = _byteswap_ushort(tcp_hdr.source);
	pDebugDataSpaces->ReadVirtual(packetRva + TCP_DST_OFFSET, &tcp_hdr.dest, sizeof(tcp_hdr.dest), NULL);
	tcp_hdr.dest = _byteswap_ushort(tcp_hdr.dest);
	pDebugDataSpaces->ReadVirtual(packetRva + TCP_SEQ_OFFSET, &tcp_hdr.seq, sizeof(tcp_hdr.seq), NULL);
	tcp_hdr.seq = _byteswap_ulong(tcp_hdr.seq);
	pDebugDataSpaces->ReadVirtual(packetRva + TCP_ACK_OFFSET, &tcp_hdr.ack_seq, sizeof(tcp_hdr.ack_seq), NULL);
	tcp_hdr.ack_seq = _byteswap_ulong(tcp_hdr.ack_seq);
	tcp_hdr.ack = 1;
	tcp_hdr.psh = 1;
	tcp_hdr.doff = 5;
	tcp_hdr.window = 0x100;
	memcpy(pcapEntry + sizeof(pcaprec_hdr) + sizeof(ether_hdr) + sizeof(ip_hdr), &tcp_hdr, sizeof(tcp_hdr));

	// myDprintf("[windbgshark] dataRva = %p\n", dataRva);
	// myDprintf("[windbgshark] pcapEntry = %x\n", pcapEntry);
	// myDprintf("[windbgshark] buffer = %x\n", pcapEntry + sizeof(pcaprec_hdr) + sizeof(ether_hdr) + sizeof(ip_hdr) + sizeof(tcp_hdr));

	if(pDebugDataSpaces->ReadVirtual(
		dataRva,
		pcapEntry + sizeof(pcaprec_hdr) + sizeof(ether_hdr) + sizeof(ip_hdr) + sizeof(tcp_hdr),
		dataLength,
		NULL) != S_OK)
	{
		goto Cleanup;
	}

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
	overlapped.Offset = prevPcapSize;
		
	WriteFile(
		hSharkPcap,
		pcapEntry,
		pcapEntrySize,
		&cbWritten,
		&overlapped);

	SetEndOfFile(hSharkPcap);

	myDprintf("[windbgshark] feedPcapWatchdog: wrote %d byte at offset %d\n", cbWritten, prevPcapSize);


Cleanup:

	if(pcapEntry != NULL)
	{
		delete [] pcapEntry;
		pcapEntry = NULL;
	}

	if(pDebugSymbols != NULL)
	{
		pDebugSymbols->Release();
	}

	if(pDebugDataSpaces != NULL)
	{
		pDebugDataSpaces->Release();
	}

	return;
}

void feedPcapWatchdog()
{
	myDprintf("[windbgshark] feedPcapWatchdog: enter\n");

	do
	{
		myDprintf("[windbgshark] feedPcapWatchdog: loop start\n");
		composePcapRecord();
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
	IDebugSymbols *pDebugSymbols = NULL;
	pDebugClient->QueryInterface(__uuidof(IDebugSymbols), (PVOID*) &pDebugSymbols);

	IDebugDataSpaces *pDebugDataSpaces = NULL;
	pDebugClient->QueryInterface(__uuidof(IDebugDataSpaces), (PVOID*) &pDebugDataSpaces);


	ULONG64 pPacketRva = 0;
	pDebugSymbols->GetOffsetByName("windbgsharkPacket", &pPacketRva);

	ULONG64 packetRva = 0;
	pDebugDataSpaces->ReadVirtual(pPacketRva, &packetRva, sizeof(packetRva), NULL);

	ULONG64 dataRva = 0;
	pDebugDataSpaces->ReadVirtual(packetRva + DATA_OFFSET, &dataRva, sizeof(dataRva), NULL);

	UINT16 dataLength = 0;
	pDebugDataSpaces->ReadVirtual(packetRva + DATA_LENGTH_OFFSET, &dataLength, sizeof(dataLength), NULL);

	char cmd[0x100] = "";
	sprintf(cmd, "db %p L%x", dataRva, dataLength);

	pDebugControl->Execute(
			DEBUG_OUTCTL_ALL_CLIENTS,
			cmd,
			DEBUG_EXECUTE_ECHO);

	if(pDebugSymbols != NULL)
	{
		pDebugSymbols->Release();
	}

	if(pDebugDataSpaces != NULL)
	{
		pDebugDataSpaces->Release();
	}
}

void setPacketSize(UINT32 size)
{
	

	IDebugSymbols *pDebugSymbols = NULL;
	pDebugClient->QueryInterface(__uuidof(IDebugSymbols), (PVOID*) &pDebugSymbols);

	IDebugDataSpaces *pDebugDataSpaces = NULL;
	pDebugClient->QueryInterface(__uuidof(IDebugDataSpaces), (PVOID*) &pDebugDataSpaces);


	ULONG64 pPacketRva = 0;
	pDebugSymbols->GetOffsetByName("windbgsharkPacket", &pPacketRva);

	ULONG64 packetRva = 0;
	pDebugDataSpaces->ReadVirtual(pPacketRva, &packetRva, sizeof(packetRva), NULL);

	ULONG allocatedBytes = 0;
	pDebugDataSpaces->ReadVirtual(packetRva + ALLOCATED_BYTES_OFFSET, (PVOID) &allocatedBytes, sizeof(allocatedBytes), NULL);

	if(size > allocatedBytes)
	{
		dprintf("[windbgshark] Sorry, too big packet size\n");
		return;
	}

	pDebugDataSpaces->WriteVirtual(packetRva + DATA_LENGTH_OFFSET, (PVOID) &size, sizeof(size), NULL);

	if(pDebugSymbols != NULL)
	{
		pDebugSymbols->Release();
	}

	if(pDebugDataSpaces != NULL)
	{
		pDebugDataSpaces->Release();
	}
}

void insertDataAtPacketOffset(UINT32 offset, PCSTR str, UINT32 len)
{
	IDebugSymbols *pDebugSymbols = NULL;
	pDebugClient->QueryInterface(__uuidof(IDebugSymbols), (PVOID*) &pDebugSymbols);

	IDebugDataSpaces *pDebugDataSpaces = NULL;
	pDebugClient->QueryInterface(__uuidof(IDebugDataSpaces), (PVOID*) &pDebugDataSpaces);


	ULONG64 pPacketRva = 0;
	pDebugSymbols->GetOffsetByName("windbgsharkPacket", &pPacketRva);

	ULONG64 packetRva = 0;
	pDebugDataSpaces->ReadVirtual(pPacketRva, &packetRva, sizeof(packetRva), NULL);

	ULONG64 dataRva = 0;
	pDebugDataSpaces->ReadVirtual(packetRva + DATA_OFFSET, &dataRva, sizeof(dataRva), NULL);

	UINT16 dataLength = 0;
	pDebugDataSpaces->ReadVirtual(packetRva + DATA_LENGTH_OFFSET, &dataLength, sizeof(dataLength), NULL);

	ULONG allocatedBytes = 0;
	pDebugDataSpaces->ReadVirtual(packetRva + ALLOCATED_BYTES_OFFSET, (PVOID) &allocatedBytes, sizeof(allocatedBytes), NULL);

	if(len > allocatedBytes || dataLength + len > allocatedBytes)
	{
		dprintf("[windbgshark] Sorry, too big packet\n");
		return;
	}

	if(offset >= dataLength)
	{
		return;
	}


	dataLength += len;

	PBYTE data = new BYTE[dataLength];	
	ZeroMemory(data, dataLength);

	pDebugDataSpaces->ReadVirtual(dataRva, data, dataLength - len, NULL);

	memmove_s(data + offset + len, dataLength - offset - len, data + offset, dataLength - offset - len);
	memmove_s(data + offset, len, (VOID*) str, len);

	pDebugDataSpaces->WriteVirtual(packetRva + DATA_LENGTH_OFFSET, &dataLength, sizeof(dataLength), NULL);
	pDebugDataSpaces->WriteVirtual(dataRva, data, dataLength, NULL);
	


	if(pDebugSymbols != NULL)
	{
		pDebugSymbols->Release();
	}

	if(pDebugDataSpaces != NULL)
	{
		pDebugDataSpaces->Release();
	}

	if(data != NULL)
	{
		delete [] data;
	}
}

void cutDataAtPacketOffset(UINT32 offset, UINT32 len)
{
	IDebugSymbols *pDebugSymbols = NULL;
	pDebugClient->QueryInterface(__uuidof(IDebugSymbols), (PVOID*) &pDebugSymbols);

	IDebugDataSpaces *pDebugDataSpaces = NULL;
	pDebugClient->QueryInterface(__uuidof(IDebugDataSpaces), (PVOID*) &pDebugDataSpaces);


	ULONG64 pPacketRva = 0;
	pDebugSymbols->GetOffsetByName("windbgsharkPacket", &pPacketRva);

	ULONG64 packetRva = 0;
	pDebugDataSpaces->ReadVirtual(pPacketRva, &packetRva, sizeof(packetRva), NULL);

	ULONG64 dataRva = 0;
	pDebugDataSpaces->ReadVirtual(packetRva + DATA_OFFSET, &dataRva, sizeof(dataRva), NULL);

	UINT16 dataLength = 0;
	pDebugDataSpaces->ReadVirtual(packetRva + DATA_LENGTH_OFFSET, &dataLength, sizeof(dataLength), NULL);

	if(offset >= dataLength)
	{
		return;
	}


	len = min(len, dataLength - offset - 1);

	PBYTE data = new BYTE[dataLength];	
	ZeroMemory(data, dataLength);

	pDebugDataSpaces->ReadVirtual(dataRva, data, dataLength, NULL);
	
	memmove_s(data + offset, dataLength - offset - len, data + offset + len, dataLength - offset - len);
	dataLength -= len;

	pDebugDataSpaces->WriteVirtual(packetRva + DATA_LENGTH_OFFSET, &dataLength, sizeof(dataLength), NULL);
	pDebugDataSpaces->WriteVirtual(dataRva, data, dataLength, NULL);


	if(pDebugSymbols != NULL)
	{
		pDebugSymbols->Release();
	}

	if(pDebugDataSpaces != NULL)
	{
		pDebugDataSpaces->Release();
	}

	if(data != NULL)
	{
		delete [] data;
	}
}