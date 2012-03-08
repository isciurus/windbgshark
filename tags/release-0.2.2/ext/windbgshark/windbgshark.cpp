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

#include "../dbgexts.h"
extern IDebugClient* pDebugClient;
extern IDebugControl* pDebugControl;

#include "windbgshark.h"

IDebugSymbols *pDebugSymbols;
IDebugDataSpaces *pDebugDataSpaces;
IDebugRegisters *pDebugRegisters;

ULONG packetFastcallRegIdx = 0;
BOOLEAN is64Target = TRUE;

#include "pcap.h"

extern WCHAR pcapFilepath[MAX_PATH];

#include "crashflt.h"
#include "utils.h"

// See TARGETNAME in ../drv/sources
#define DRIVER_NAME "windbgshark_drv"

EXTERN_C IMAGE_DOS_HEADER __ImageBase;

void printLastError();

IDebugBreakpoint *bpIn, *bpOut, *bpIo;

HANDLE hPcapWatchdog = INVALID_HANDLE_VALUE;
HANDLE hWatchdogTerminateEvent = INVALID_HANDLE_VALUE;

HRESULT prepareDebuggingSymbols();
HRESULT prepareDriverModule();

HRESULT setBreakpoints(PDEBUG_CONTROL Control);
HRESULT removeBreakpoints(PDEBUG_CONTROL Control);

BOOL modeStepTrace = FALSE;
BOOL Debug = FALSE;

#undef _CTYPE_DISABLE_MACROS

HRESULT CALLBACK onpacketinspect(PDEBUG_CLIENT4 Client, PCSTR args);
HRESULT CALLBACK onpacketinject(PDEBUG_CLIENT4 Client, PCSTR args);

class myEventCallbacks : public DebugBaseEventCallbacks
{
public:

    // IUnknown.
    STDMETHOD_(ULONG, AddRef)(
        THIS
    )
	{
		return 1;
	}

    STDMETHOD_(ULONG, Release)(
        THIS
    )
	{
		return 0;
	}

    // IDebugEventCallbacks.
    STDMETHOD(GetInterestMask)(
        THIS_
        OUT PULONG Mask
    )
	{
		*Mask = DEBUG_EVENT_BREAKPOINT;
		return S_OK;
	}

    STDMETHOD(Breakpoint)(
        THIS_
        __in PDEBUG_BREAKPOINT Bp
        )
    {
        UNREFERENCED_PARAMETER(Bp);
				
		// dprintf("[windbgshark] Breakpoint %s res = %d\n", Buffer, res);
		
		if(Bp == bpIn)
		{
			myDprintf("[windbghsark] Breakpoint in catched\n");

			onpacketinspect(NULL, NULL);

			if(modeStepTrace)
			{
				dprintf("[windbghsark] !packet\n");
				showPacket();
				return DEBUG_STATUS_BREAK;
			}
			// return DEBUG_STATUS_GO;
			return DEBUG_STATUS_NO_CHANGE;
		} 
		else if(Bp == bpOut)
		{
			myDprintf("[windbghsark] Breakpoint out catched\n");

			onpacketinject(NULL, NULL);
			//return DEBUG_STATUS_GO;
			return DEBUG_STATUS_NO_CHANGE;
		} 
		//else if(Bp == bpIo)
		//{

		//}
		else
		{
			myDprintf("[windbghsark] Breakpoint catched\n");

			return DEBUG_STATUS_NO_CHANGE;
		}
    }
};

myEventCallbacks g_EventCb;

void printIncorrectArgs(PCSTR args)
{
	dprintf("[windbgshark] Sorry, cannot parse arguments: %s", args);
}

void printLastError()
{
    LPCTSTR lpMsgBuf;

    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
        NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR) & lpMsgBuf, 0, NULL);

	myDprintf(lpMsgBuf);

    LocalFree((HLOCAL) lpMsgBuf);
}


HRESULT extensionInit()
{
	HRESULT result = S_OK;

	pDebugClient->QueryInterface(__uuidof(IDebugSymbols), (PVOID*) &pDebugSymbols);
	pDebugClient->QueryInterface(__uuidof(IDebugDataSpaces), (PVOID*) &pDebugDataSpaces);
	pDebugClient->QueryInterface(__uuidof(IDebugRegisters), (PVOID*) &pDebugRegisters);	

	myDprintf("[windbgshark] extensionInit...\n");

	ULONG targetMachine = 0;
	result = pDebugControl->GetActualProcessorType(&targetMachine);
	if (result == S_OK)
    {                                                     
        switch (targetMachine)
        {
        case IMAGE_FILE_MACHINE_I386:
            is64Target = FALSE;
            break;

        case IMAGE_FILE_MACHINE_AMD64:
            is64Target = TRUE;
            break;

        default:
			dprintf("[windbgshark] unknown arch...\n");
            break;
        }
    }

	if(pDebugRegisters->GetIndexByName("rcx", &packetFastcallRegIdx) != S_OK &&
		pDebugRegisters->GetIndexByName("ecx", &packetFastcallRegIdx) != S_OK) 
	{
		myDprintf("[windbgshark] neither rcx nor ecx register found. "
			"What is your target machine architecture?\n");
	}

	myDprintf("[windbgshark] prepareDebuggingSymbols...\n");
	result = prepareDebuggingSymbols();
	if(result != S_OK)
	{
		return result;
	}

	result = pDebugClient->SetEventCallbacks(&g_EventCb);
    if(result != S_OK)
    {
        return result;
    }

	myDprintf("[windbgshark] prepareDriverModule...\n");
	result = prepareDriverModule();
	if(result != S_OK)
	{
		return result;
	}

	myDprintf("[windbgshark] getPacketOffsets...\n");
	result = getPacketOffsets();

	myDprintf("[windbgshark] setBreakpoints...\n");
	result = setBreakpoints(pDebugControl);
	if(result != S_OK)
	{
		return result;
	}

	myDprintf("[windbgshark] openPcap...\n");
	result = openPcap();
	if(result != S_OK)
	{
		return result;
	}

	myDprintf("[windbgshark] starting wireshark...\n");
	result = startWireshark();
	if(result != S_OK)
	{
		return result;
	}

	myDprintf("[windbgshark] Creating sync objects...\n");
	hWatchdogTerminateEvent = CreateEvent(NULL, FALSE, FALSE, NULL); 

	if(hWatchdogTerminateEvent == NULL)
	{
		dprintf("[windbgshark] Unable to create hWatchdogTerminateEvent\n");
		return E_FAIL;
	}

	return S_OK;
}

void extensionUninitialize()
{
	myDprintf("[windbgshark] extensionUninitialize: calling removeBreakpoints...\n");
	removeBreakpoints(pDebugControl);

	myDprintf("[windbgshark] extensionUninitialize: calling hPcapWatchdog...\n");
	terminateWatchdog();

	myDprintf("[windbgshark] extensionUninitialize: releasing the objects...\n");
	if(pDebugClient) pDebugClient->Release();
    if(pDebugControl) pDebugControl->Release();
	if(pDebugSymbols) pDebugSymbols->Release();
	if(pDebugDataSpaces) pDebugDataSpaces->Release();
	if(pDebugRegisters) pDebugRegisters->Release();

	stopWireshark();

	closePcap();
}



// Extension commands


HRESULT CALLBACK
help(PDEBUG_CLIENT4 Client, PCSTR args)
{
    dprintf("Heya, I'm Windbgshark.\n\n");
	dprintf("You may user the following commands:\n");

	dprintf("!strace \t\t\t show help\n");
	dprintf("!strace \t\t\t show the current mode (step-trace or pass-through)\n");
	dprintf("!strace {on|off} \t\t turn on/off the step-trace mode \n");
	dprintf("!packet \t\t\t show the current packet in hex dump \n");
	dprintf("!packet <size> \t\t set the current packet size (either truncates or enlarges the packet)\n");
	dprintf("!packet <offset> <string> \t replace the contents at <offset> by <string>\n");
	dprintf("!packet <offset> +<string> \t insert the <string> at <offset> (enlarges the packet)\n");
	dprintf("!packet <offset> -<size> \t remove <size> characters at <offset> (reduces packet size)\n");
	
	dprintf("\nHints for !strace and !packet commands:\n");
	dprintf("- all input numbers are treated as hex\n");
	dprintf("- all standard escape sequences (\\n, \\x41 and so on) in input strings are converterted in to the corresponding characters\n\n");

	dprintf("!crashflt \t\t\t show current filename filter for guest crash handler\n");
	dprintf("!crashflt <string> \t\t set the filename filter for guest crash handler\n");

	dprintf("\nHints for !crashflt command:\n");
	dprintf("- crash is handled if process full path equals the filter string\n");
	dprintf("- you can also use asterisk * as a wildcard character in filter\n");

	return S_OK;
}


HRESULT CALLBACK
packet(PDEBUG_CLIENT4 Client, PCSTR args)
{
	UINT32 argsLen = strlen(args);

	// ex: !packet
	if(args == NULL || argsLen == 0)
	{
		showPacket();
		return S_OK;
	}

	// ex: !packet abc
	if(!isxdigit(args[0]))
	{
		printIncorrectArgs(args);
		return S_OK;
	}

	char *endSizePtr = NULL;
	UINT32 offset = strtol(args, &endSizePtr, 16);

	// ex: !packet 20
	if(endSizePtr == NULL || *endSizePtr == '\0')
	{
		setPacketSize(offset);
	}
	else if(*endSizePtr == ' ')
	{
		if(endSizePtr + 1 < args + argsLen && *(endSizePtr + 1) == '+')
		{
			// ex: !packet 20 +quick brown fox\x41\x41\x41
			if(endSizePtr + 2 < args + argsLen)
			{
				UINT32 unescapeDataLength = argsLen - (endSizePtr - args) - 2;
				char *unescapeData = new char[unescapeDataLength + 1];
				unescape(unescapeData, endSizePtr + 2);
				unescapeDataLength = strlen(unescapeData);
				insertDataAtPacketOffset(offset, unescapeData, unescapeDataLength);

				if(unescapeData != NULL)
				{
					delete [] unescapeData;
				}
			}
		}
		else if(endSizePtr + 1 < args + argsLen && *(endSizePtr + 1) == '-')
		{
			// ex: !packet 20 -10
			if(endSizePtr + 2 < args + argsLen && isxdigit(*(endSizePtr + 2)))
			{
				char *endCutSizePtr = NULL;
				UINT32 cutSize = strtol(endSizePtr + 2, &endCutSizePtr, 16);
				cutDataAtPacketOffset(offset, cutSize);
			}
			else
			{
				printIncorrectArgs(args);
				return S_OK;
			}
		}
		else if(endSizePtr + 1 < args + argsLen)
		{
			// ex: !packet 20 quickbrown fox \n\n\x41
			UINT32 unescapeDataLength = argsLen - (endSizePtr - args) - 1;
			char *unescapeData = new char[unescapeDataLength + 1];
			unescape(unescapeData, endSizePtr + 1);
			unescapeDataLength = strlen(unescapeData);
			setDataAtPacketOffset(offset, unescapeData, unescapeDataLength);
		}
		else
		{
			printIncorrectArgs(args);
			return S_OK;
		}
	}
	else
	{
		printIncorrectArgs(args);
		return S_OK;
	}
	
	

	showPacket();


	return S_OK;
}

HRESULT CALLBACK
strace(PDEBUG_CLIENT4 Client, PCSTR args)
{
	INIT_API();
	
	// myDprintf("[windbgshark] strace: args = %s (%p), strlen(args) = %d, strcmp(args, \"on\") = %d\n", args, args, strlen(args), strcmp(args, "on"));

	if(args != NULL && strlen(args) > 0)
	{
		if(strlen(args) == 2 && strcmp(args, "on") == 0)
		{
			dprintf("[windbgshark] enabled packet step tracing (break)\n");
			modeStepTrace = TRUE;
		}
		else if(strlen(args) == 3 && strcmp(args, "off") == 0)
		{
			dprintf("[windbgshark] disabled packet step tracing (pass-through)\n");
			modeStepTrace = FALSE;
		}
	}
	else
	{
		dprintf("[windbgshark] packet step tracing - ");

		if(modeStepTrace)
		{
			dprintf("enabled (break)\n");
		}
		else
		{
			dprintf("disabled (pass-through)\n");
		}
	}

	EXIT_API();

	return S_OK;
}

HRESULT CALLBACK
onpacketinspect(PDEBUG_CLIENT4 Client, PCSTR args)
{

	myDprintf("[windbgshark] onpacketinspect: Enter----------------------------------------\n");

	fixCurrentPcapSize();

	composePcapRecords();

	if(modeStepTrace)
	{
		if(hPcapWatchdog != INVALID_HANDLE_VALUE)
		{
			terminateWatchdog();
		}

		ResetEvent(hWatchdogTerminateEvent);

		hPcapWatchdog = CreateThread(
			NULL,
			0,
			(LPTHREAD_START_ROUTINE ) &feedPcapWatchdog,
			NULL,
			0,
			0);	
	}

	myDprintf("[windbgshark] onpacketinspect: Cleanup--------------------------------------\n");

	return S_OK;
}

HRESULT CALLBACK
onpacketinject(PDEBUG_CLIENT4 Client, PCSTR args)
{
	myDprintf("[windbgshark] onpacketinject: Enter---------------------------------------\n");

	terminateWatchdog();

	myDprintf("[windbgshark] onpacketinject: Cleanup-------------------------------------\n");

	return S_OK;
}

HRESULT CALLBACK
onioctl(PDEBUG_CLIENT4 Client, PCSTR args)
{
	UINT64 pcDumpFileNameRva = NULL;
	pDebugSymbols->GetOffsetByName("cDumpFileName", &pcDumpFileNameRva);
	
	UINT64 cDumpFileNameRva = NULL;
	pDebugDataSpaces->ReadPointersVirtual(1, pcDumpFileNameRva, &cDumpFileNameRva);

	PCHAR cDumpFileName[MAX_PATH] = {0};
	pDebugDataSpaces->ReadVirtual(cDumpFileNameRva, cDumpFileName, sizeof(cDumpFileName), NULL);


	UINT64 pcProcessNameRva = NULL;
	pDebugSymbols->GetOffsetByName("cProcessName", &pcProcessNameRva);
	
	UINT64 cProcessNameRva = NULL;
	pDebugDataSpaces->ReadPointersVirtual(1, pcProcessNameRva, &cProcessNameRva);

	CHAR cProcessName[MAX_PATH] = {0};
	pDebugDataSpaces->ReadVirtual(cProcessNameRva, cProcessName, sizeof(cProcessName), NULL);

	if(crashfltFilterMatch(cProcessName))
	{
		WCHAR crashPcapFilepath[MAX_PATH + 5];
		WCHAR tmpDir[MAX_PATH];
		if(GetTempPathW(sizeof(tmpDir) / sizeof(WCHAR), tmpDir) == 0)
		{
			myDprintf("[windbgshark] onioctl: GetTempPathW error\n");
			return E_FAIL;
		}

		if(GetTempFileNameW(tmpDir, L"wcr", 0, crashPcapFilepath) == 0)
		{
			myDprintf("[windbgshark] onioctl: GetTempFileNameW error\n");
			return E_FAIL;
		}

		for(WCHAR *fileExt = crashPcapFilepath + wcslen(crashPcapFilepath) - 1;
			fileExt > 0;
			fileExt--)
		{
			if(fileExt[0] == L'.')
			{
				wcscpy(fileExt, L".pcap\0");
				break;
			}
		}

		if(CopyFileW(pcapFilepath, crashPcapFilepath, FALSE) == 0)
		{
			myDprintf("[windbgshark] onioctl: CopyFileW error\n");
			return E_FAIL;
		}

		CHAR crashPcapFilepathA[MAX_PATH + 5];
		wcstombs(crashPcapFilepathA, crashPcapFilepath, sizeof(crashPcapFilepathA));

		dprintf("[windbgshark] [crash] process = %s, pcap trace on host at %s, dump on guest at %s\n",
			cProcessName, crashPcapFilepathA, cDumpFileName);
	}

	return S_OK;
}

HRESULT CALLBACK
crashflt(PDEBUG_CLIENT4 Client, PCSTR args)
{
	if(args != NULL && strlen(args) > 0)
	{
		crashfltSetFilter((PCHAR) args);
	}

	crashfltPrintFilter();
	return S_OK;
}

HRESULT prepareDebuggingSymbols()
{
	CHAR symbol_path[MAX_PATH] = {0};
	ULONG path_size = 0;
	pDebugSymbols->GetSymbolPath(symbol_path, sizeof(symbol_path), &path_size);

	myDprintf("[windbgshark] prepareDebuggingSymbols: symbol_path = %s\n", symbol_path);

	CHAR modulePath[MAX_PATH] = {0};
	GetModuleFileNameA(((HINSTANCE)&__ImageBase), modulePath, sizeof(modulePath));
	myDprintf("[windbgshark] module path: %s\n", modulePath);

	for(size_t i = strlen(modulePath) - 1; i > 0; i--)
	{
		if(strstr(modulePath + i - 1, "x64") != NULL ||
			strstr(modulePath + i - 1, "x86") != NULL)
		{
			modulePath[i - 1] = 0;
			myDprintf("[windbgshark] prepareDebuggingSymbols: windbgshark ./host path = %s\n", modulePath);
			break;
		}
	}


	// Are paths to symbols correctly set?
	
	if(strstr(symbol_path, "windbgshark_symbols_x86") == NULL)
	{

		CHAR appendedSymbolPath[MAX_PATH] = {0};
		_snprintf(
			appendedSymbolPath,
			sizeof(appendedSymbolPath),
			"%swindbgshark_symbols_x86",
			modulePath);
		pDebugSymbols->AppendSymbolPath(appendedSymbolPath);
	}

	if(strstr(symbol_path, "windbgshark_symbols_x64") == NULL)
	{
		CHAR appendedSymbolPath[MAX_PATH] = {0};
		_snprintf(
			appendedSymbolPath,
			sizeof(appendedSymbolPath),
			"%swindbgshark_symbols_x64",
			modulePath);		
		pDebugSymbols->AppendSymbolPath(appendedSymbolPath);
	}

	myDprintf("[windbgshark] reloading debugging symbols\n");
	pDebugControl->Execute(
			DEBUG_OUTCTL_IGNORE | DEBUG_OUTCTL_NOT_LOGGED,
				".reload "
				DRIVER_NAME
				"sys",
			DEBUG_EXECUTE_NOT_LOGGED);

	return S_OK;
}

HRESULT
prepareDriverModule()
{
	myDprintf("[windbgshark] checking if driver is loaded...\n");
	ULONG moduleIdx = 0;
	pDebugSymbols->GetModuleByModuleName(
		DRIVER_NAME,
		0,
		&moduleIdx,
		NULL);
	if(moduleIdx == NULL)
	{
		dprintf("[windbgshark] driver module not found, reloading all the symbols "
			"(.reload)...");
		pDebugControl->Execute(
			DEBUG_OUTCTL_IGNORE | DEBUG_OUTCTL_NOT_LOGGED,
			".reload",
			DEBUG_EXECUTE_NOT_LOGGED);
		pDebugSymbols->GetModuleByModuleName(
			DRIVER_NAME,
			0,
			&moduleIdx,
			NULL);
		if(moduleIdx == NULL)
		{
			dprintf("\n[windbgshark] driver module is not loaded yet! breakpoints will "
				"be deffered until the module is loaded\n");
		}
		else
		{
			dprintf("module found\n");
		}
	}

	return S_OK;
}

HRESULT
setBreakpoints(PDEBUG_CONTROL Control)
{
	HRESULT result = Control->AddBreakpoint(
		DEBUG_BREAKPOINT_CODE,
		DEBUG_ANY_ID,
		&bpIn);
	result = bpIn->SetOffsetExpression("windbgshark_drv!onpacketinspect_stub");
	result = bpIn->SetCommand("g");
	result = bpIn->SetFlags(DEBUG_BREAKPOINT_ENABLED);

	result = Control->AddBreakpoint(
		DEBUG_BREAKPOINT_CODE,
		DEBUG_ANY_ID,
		&bpOut);
	result = bpOut->SetOffsetExpression("windbgshark_drv!onpacketinject_stub");
	result = bpOut->SetCommand("g");
	result = bpOut->SetFlags(DEBUG_BREAKPOINT_ENABLED);

	result = Control->AddBreakpoint(
		DEBUG_BREAKPOINT_CODE,
		DEBUG_ANY_ID,
		&bpIo);
	result = bpIo->SetOffsetExpression("windbgshark_drv!onioctl_stub");
	result = bpIo->SetCommand("!onioctl; g");
	result = bpIo->SetFlags(DEBUG_BREAKPOINT_ENABLED);

	return S_OK;
}

HRESULT
removeBreakpoints(PDEBUG_CONTROL Control)
{
	HRESULT result;

	result = Control->RemoveBreakpoint(bpIn);
	result = Control->RemoveBreakpoint(bpOut);
	result = Control->RemoveBreakpoint(bpIo);

	return S_OK;
}


