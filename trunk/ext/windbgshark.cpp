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

#include "dbgexts.h"
extern IDebugClient* pDebugClient;
extern IDebugControl* pDebugControl;

#include "windbgshark.h"

#include "pcap.h"

#include "utils.h"

// See TARGETNAME in ../drv/sources
#define DRIVER_NAME "windbgshark_drv"

EXTERN_C IMAGE_DOS_HEADER __ImageBase;

void printLastError();

IDebugBreakpoint *bpIn, *bpOut;

HANDLE hPcapWatchdog = INVALID_HANDLE_VALUE;
HANDLE hWatchdogTerminateEvent = INVALID_HANDLE_VALUE;

HRESULT prepareDriverModule();

HRESULT setBreakpoints(PDEBUG_CONTROL Control);
HRESULT removeBreakpoints(PDEBUG_CONTROL Control);

BOOL modeStepTrace = FALSE;
BOOL Debug = TRUE;

#undef _CTYPE_DISABLE_MACROS

HRESULT windbgsharkInit()
{
	HRESULT result = S_OK;

	myDprintf("windbgsharkInit...\n");

	myDprintf("prepareDriverModule...\n");
	result = prepareDriverModule();
	if(result != S_OK)
	{
		return result;
	}

	myDprintf("setBreakpoints...\n");
	result = setBreakpoints(pDebugControl);
	if(result != S_OK)
	{
		return result;
	}

	myDprintf("openPcap...\n");
	result = openPcap();
	if(result != S_OK)
	{
		return result;
	}

	myDprintf("starting wireshark...\n");
	result = startWireshark();
	if(result != S_OK)
	{
		return result;
	}

	myDprintf("Creating sync objects...\n");
	hWatchdogTerminateEvent = CreateEvent(NULL, FALSE, FALSE, NULL); 

	if(hWatchdogTerminateEvent == NULL)
	{
		dprintf("Unable to create hWatchdogTerminateEvent\n");
		return E_FAIL;
	}

	return S_OK;
}

void windbgsharkUninitialize()
{
	myDprintf("windbgsharkUninitialize: calling removeBreakpoints...\n");
	removeBreakpoints(pDebugControl);

	myDprintf("windbgsharkUninitialize: calling hPcapWatchdog...\n");
	terminateWatchdog();

	myDprintf("windbgsharkUninitialize: releasing the objects...\n");
	if(pDebugClient) pDebugClient->Release();
    if(pDebugControl) pDebugControl->Release();

	stopWireshark();

	closePcap();
}


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
	
	dprintf("\nHints:\n");
	dprintf("- all input numbers are treated as hex\n");
	dprintf("- all standard escape sequences (\\n, \\x41 and so on) in input strings are converterted in to the corresponding characters\n");

	return S_OK;
}

void printIncorrectArgs(PCSTR args)
{
	dprintf("Sorry, cannot parse arguments: %s", args);
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
			cutDataAtPacketOffset(offset, unescapeDataLength);
			insertDataAtPacketOffset(offset, unescapeData, unescapeDataLength);
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
	
	// myDprintf("strace: args = %s (%p), strlen(args) = %d, strcmp(args, \"on\") = %d\n", args, args, strlen(args), strcmp(args, "on"));

	if(args != NULL && strlen(args) > 0)
	{
		if(strlen(args) == 2 && strcmp(args, "on") == 0)
		{
			dprintf("enabled packet step tracing (break)\n");
			modeStepTrace = TRUE;
			bpIn->SetCommand("!onpacketinspect; .printf \"!packet\\n\"; !packet");
		}
		else if(strlen(args) == 3 && strcmp(args, "off") == 0)
		{
			dprintf("disabled packet step tracing (pass-through)\n");
			modeStepTrace = FALSE;
			bpIn->SetCommand("!onpacketinspect; g");
		}
	}
	else
	{
		dprintf("packet step tracing - ");

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
	INIT_API();

	myDprintf("onpacketinspect: Enter----------------------------------------\n");

	fixCurrentPcapSize();

	composePcapRecord();

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

	myDprintf("onpacketinspect: Cleanup--------------------------------------\n");
	EXIT_API();

	return S_OK;
}

HRESULT CALLBACK
onpacketinject(PDEBUG_CLIENT4 Client, PCSTR args)
{
	INIT_API();

	myDprintf("onpacketinject: Enter---------------------------------------\n");

	terminateWatchdog();

	myDprintf("onpacketinject: Cleanup-------------------------------------\n");

	EXIT_API();

	return S_OK;
}

HRESULT
prepareDriverModule()
{
	IDebugSymbols *pDebugSymbols = NULL;
	pDebugClient->QueryInterface(__uuidof(IDebugSymbols), (PVOID*) &pDebugSymbols);

	CHAR symbol_path[MAX_PATH] = {0};
	ULONG path_size = 0;
	pDebugSymbols->GetSymbolPath(symbol_path, sizeof(symbol_path), &path_size);

	myDprintf("setDebugSymbols: symbol_path = %s\n", symbol_path);

	CHAR modulePath[MAX_PATH] = {0};
	GetModuleFileNameA(((HINSTANCE)&__ImageBase), modulePath, sizeof(modulePath));
	myDprintf("module path: %s\n", modulePath);

	for(size_t i = strlen(modulePath) - 1; i > 0 && modulePath[i] != '\\'; i--)
	{
		modulePath[i] = 0;
	}


	// Are paths to symbols correctly set?

	if(strstr(symbol_path, "windbgshark_drv_symbols_x86") == NULL)
	{
		CHAR appendedSymbolPath[MAX_PATH] = {0};
		_snprintf(
			appendedSymbolPath,
			sizeof(appendedSymbolPath),
			"%swindbgshark_drv_symbols_x86",
			modulePath);		
		pDebugSymbols->AppendSymbolPath(appendedSymbolPath);
	}

	if(strstr(symbol_path, "windbgshark_drv_symbols_x64") == NULL)
	{
		CHAR appendedSymbolPath[MAX_PATH] = {0};
		_snprintf(
			appendedSymbolPath,
			sizeof(appendedSymbolPath),
			"%swindbgshark_drv_symbols_x64",
			modulePath);		
		pDebugSymbols->AppendSymbolPath(appendedSymbolPath);
	}


	myDprintf("checking if driver is loaded...\n");
	ULONG moduleIdx = 0;
	pDebugSymbols->GetModuleByModuleName(
		DRIVER_NAME,
		0,
		&moduleIdx,
		NULL);
	if(moduleIdx == NULL)
	{
		dprintf("driver module is not loaded yet! breakpoints will be deffered until "
			"the module is loaded\n");
	}

	myDprintf("loading symbols for the driver\n");
	pDebugControl->Execute(
			DEBUG_OUTCTL_IGNORE | DEBUG_OUTCTL_NOT_LOGGED,
				".reload "
				DRIVER_NAME
				".sys",
			DEBUG_EXECUTE_NOT_LOGGED);


	if(pDebugSymbols != NULL)
	{
		pDebugSymbols->Release();
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

	result = bpIn->SetOffsetExpression("windbgshark_drv!inspectPacket+0xd4");

	if(modeStepTrace)
	{
		result = bpIn->SetCommand("!onpacketinspect; .printf \"!packet\\n\"; !packet");
	}
	else
	{
		result = bpIn->SetCommand("!onpacketinspect; g");
	}

	result = bpIn->SetFlags(DEBUG_BREAKPOINT_ENABLED);

	result = Control->AddBreakpoint(
		DEBUG_BREAKPOINT_CODE,
		DEBUG_ANY_ID,
		&bpOut);

	result = bpOut->SetOffsetExpression("windbgshark_drv!inspectPacket+0xcf");
	result = bpOut->SetCommand("!onpacketinject; g");
	result = bpOut->SetFlags(DEBUG_BREAKPOINT_ENABLED);

	return S_OK;
}

HRESULT
removeBreakpoints(PDEBUG_CONTROL Control)
{
	HRESULT result;

	result = Control->RemoveBreakpoint(bpIn);
	result = Control->RemoveBreakpoint(bpOut);

	return S_OK;
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


