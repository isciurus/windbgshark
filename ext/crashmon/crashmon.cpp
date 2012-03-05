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

void printLastError();

#undef _CTYPE_DISABLE_MACROS

HRESULT extensionInit()
{
	/*pDebugControl->Execute(
			DEBUG_OUTCTL_IGNORE | DEBUG_OUTCTL_NOT_LOGGED,
			".reload windbgshark_drv.sys",
			DEBUG_EXECUTE_NOT_LOGGED);*/

	return S_OK;
}

void extensionUninitialize()
{
	if(pDebugClient)
	{
		pDebugClient->Release();
	}

	if(pDebugControl)
	{
		pDebugControl->Release();
	}
}

HRESULT sendIoctl(char *buffer, ULONG size)
{
	HANDLE hHandle = CreateFileA( "\\\\.\\WindbgsharkDrv",
						GENERIC_READ | GENERIC_WRITE,
						FILE_SHARE_READ | FILE_SHARE_WRITE,
						NULL,
						OPEN_EXISTING,
						FILE_ATTRIBUTE_NORMAL,
						NULL );

	dprintf("sendIoctl hHandle = %p\n", hHandle);
	printLastError();

	if(hHandle == INVALID_HANDLE_VALUE)
	{
		return E_FAIL;
	}

	DWORD bytesReturned = 0;
	BOOL result = DeviceIoControl(hHandle,
					0,
					buffer, size,
					NULL, 0,
					&bytesReturned,
					NULL );	

	dprintf("sendIoctl result = %d\n", result);

	return S_OK;
}

HRESULT CALLBACK
notifykdbg(PDEBUG_CLIENT4 Client, PCSTR args)
{
	INIT_API();

	if (Client->IsKernelDebuggerEnabled() == S_OK)
	{
		ULONG			uTargetProcessID = 0;
		char			cDumpFileName[2 * MAX_PATH] = {0};
		SYSTEMTIME		stLocalTime = {0};
		char			cLocalTime[50] = {0};

		GetTempPath(MAX_PATH, cDumpFileName);
		strcat(cDumpFileName, "windbgshark_crash_dumps");

		if (CreateDirectory(cDumpFileName, NULL) != TRUE)
		{
			if (GetLastError() == ERROR_ALREADY_EXISTS)
			{
				strcat(cDumpFileName, "\\");
			}
			else
			{
				memset(cDumpFileName, 0, MAX_PATH);
			}
		}
		else
		{
			strcat(cDumpFileName, "\\");
		}
		
		GetLocalTime(&stLocalTime);
		sprintf(cLocalTime, "%02d%02d%02d_%02d%02d%04d", stLocalTime.wHour, stLocalTime.wMinute, stLocalTime.wSecond,
		stLocalTime.wDay, stLocalTime.wMonth, stLocalTime.wYear);
		strcat(cDumpFileName, cLocalTime);
		strcat(cDumpFileName, ".dmp");

		Client->WriteDumpFile(cDumpFileName, DEBUG_DUMP_DEFAULT);

		// Get filename
		IDebugSystemObjects* pDebugSystemObjects = NULL;
		char     cProcessName[MAX_PATH] = {0};
		ULONG     exeSize = 0;
          
		Client->QueryInterface(__uuidof(IDebugSystemObjects), (PVOID*) &pDebugSystemObjects);

		if (pDebugSystemObjects != NULL)
		{
			pDebugSystemObjects->GetCurrentProcessExecutableName(cProcessName, MAX_PATH, &exeSize);
			pDebugSystemObjects->Release();
		}

		strncpy(cDumpFileName + strlen(cDumpFileName) + 1, cProcessName, exeSize + 1);

		dprintf("sendIoctl %s, %s\n", cDumpFileName, cProcessName);
		sendIoctl(cDumpFileName, strlen(cDumpFileName) + 1 + strlen(cProcessName) + 1);
	}

	EXIT_API();

	Client->TerminateProcesses();

	if(pDebugClient)
	{
		pDebugClient->Release();
	}

	if(pDebugControl)
	{
		pDebugControl->Release();
	}

	TerminateProcess(GetCurrentProcess(), 0);

	return S_OK;
}

void printLastError()
{
    LPCTSTR lpMsgBuf;

    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
        NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR) & lpMsgBuf, 0, NULL);

#ifdef DEBUG
	dprintf(lpMsgBuf);
#endif

    LocalFree((HLOCAL) lpMsgBuf);
}


