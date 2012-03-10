#include "filter.h"


PWCHAR tsharkPath = L"C:\\Program Files\\Wireshark\\tshark.exe";

PWCHAR pcapFilePath = L"C:\\Users\\Ivan\\Documents\\Visual Studio 2010\\Projects\\example\\Debug\\http.cap";

#define FILTER_MAX_SIZE 1024
#define COMMAND_MAX_SIZE 1024

CHAR _filter[FILTER_MAX_SIZE];

HANDLE hTsharkProcess = INVALID_HANDLE_VALUE;
HANDLE hChildStdoutWr = INVALID_HANDLE_VALUE;
HANDLE hChildStdoutRdDup = INVALID_HANDLE_VALUE;
HANDLE hSharkPcap = INVALID_HANDLE_VALUE;

BOOLEAN restartTshark();

#include <string>
std::string getFilteredContent();

void init()
{
	hSharkPcap = CreateFileW(
			pcapFilePath,
			GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ,
			NULL,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			NULL);
}

void close()
{
	if(hChildStdoutWr!=INVALID_HANDLE_VALUE)
	{
		CloseHandle(hChildStdoutWr);
	}
	if(hChildStdoutRdDup!=INVALID_HANDLE_VALUE)
	{
		CloseHandle(hChildStdoutRdDup);
	}
	if(hSharkPcap!=INVALID_HANDLE_VALUE)
	{	
		CloseHandle(hSharkPcap);
	}
}

void setPacketBpFilter(PCHAR filter)
{
	strcpy_s(_filter, filter);
	
	restartTshark();
}

// the function compares two outputs from tshark
// before and after appending the packet into pcap file

BOOLEAN checkPacketUsingFilter(PBYTE packet, ULONG packetLength)
{
	// every packet satisfied empty filter
	if(strlen(_filter) == 0) return TRUE;

	std::string prev = getFilteredContent();

	
	// write the packet into pcap file
	
	SetFilePointer(hSharkPcap, 0, NULL, FILE_END);

	DWORD cbWritten;

	WriteFile(
		hSharkPcap,
		packet,
		packetLength,
		&cbWritten,
		NULL);
	
	SetEndOfFile(hSharkPcap);



	restartTshark();

	std::string post = getFilteredContent();
	int compRes = prev.compare(post);

	// if contents are equal then packet not matching 
	return compRes != 0;
}


// start the tshark process and create the pipe
// for redirection output from tshark

BOOLEAN startTshark(PWCHAR tsharkCommand)
{
	HANDLE hChildStdoutRd, hSaveStdout; 
	SECURITY_ATTRIBUTES saAttr; 
	BOOL fSuccess; 

	// Set the bInheritHandle flag so pipe handles are inherited. 
	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES); 
	saAttr.bInheritHandle = TRUE; 
	saAttr.lpSecurityDescriptor = NULL; 

	// Save the handle to the current STDOUT. 
	hSaveStdout = GetStdHandle(STD_OUTPUT_HANDLE); 
  
	// Create a pipe for the child process's STDOUT. 
	if (! CreatePipe(&hChildStdoutRd, &hChildStdoutWr, &saAttr, 0)) 
	  return FALSE;

	// Set a write handle to the pipe to be STDOUT. 
	if (! SetStdHandle(STD_OUTPUT_HANDLE, hChildStdoutWr)) 
	  return FALSE;
  
	// Create noninheritable read handle and close the inheritable read handle. 
	fSuccess = DuplicateHandle(GetCurrentProcess(), hChildStdoutRd, 
			GetCurrentProcess(), &hChildStdoutRdDup , 0, 
			FALSE, 
			DUPLICATE_SAME_ACCESS); 
	if( !fSuccess ) return FALSE;
	
	CloseHandle(hChildStdoutRd); 

	// Now create the child process. 
	PROCESS_INFORMATION piProcInfo; 
	STARTUPINFOW siStartInfo; 

	// Set up members of the PROCESS_INFORMATION structure. 
	ZeroMemory( &piProcInfo, sizeof(PROCESS_INFORMATION) ); 

	// Set up members of the STARTUPINFO structure. 
	ZeroMemory( &siStartInfo, sizeof(STARTUPINFOW) ); 
	siStartInfo.cb = sizeof(STARTUPINFOW); 

	//TCHAR Command[1024] = TEXT(tsharkCommand);
	// Create the child process. 
	fSuccess = CreateProcess(NULL, 
	  tsharkCommand,  // command line 
	  NULL,          // process security attributes 
	  NULL,          // primary thread security attributes 
	  TRUE,          // handles are inherited 
	  0,             // creation flags 
	  NULL,          // use parent's environment 
	  NULL,          // use parent's current directory 
	  &siStartInfo,  // STARTUPINFO pointer 
	  &piProcInfo);  // receives PROCESS_INFORMATION 
  
	if (! fSuccess) 
	  return FALSE;
  
	hTsharkProcess = piProcInfo.hProcess;
	// After process creation, restore the saved STDIN and STDOUT. 
	if (! SetStdHandle(STD_OUTPUT_HANDLE, hSaveStdout)) 
	  return FALSE; 

	return TRUE;
}

// reads data from pipe

// it's possible that using of std::string implies some lack of performance
// therefore recommended to replaced it by PCHAR
std::string getFilteredContent()
{
	std::string result;

		// Read from pipe that is the standard output for child process. 
	DWORD dwRead; 
	CHAR chBuf[4096]; 
	HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE); 

	// Close the write end of the pipe before reading from the 
	// read end of the pipe. 
	if(hChildStdoutWr!=INVALID_HANDLE_VALUE)
	{
		if (!CloseHandle(hChildStdoutWr)) 
			return result; 
	}
	for (;;) 
	{
		if( !ReadFile(hChildStdoutRdDup, chBuf, 4096, &dwRead, NULL) || dwRead == 0) 
			break; 
		result.append(chBuf,dwRead); 
	} 
  
	return result; 
}
	


  

void stopTshark()
{
	if(hTsharkProcess != INVALID_HANDLE_VALUE)
	{
		TerminateProcess(hTsharkProcess, 0);
	}
}

BOOLEAN restartTshark()
{
	stopTshark();
	WCHAR comm[COMMAND_MAX_SIZE];

	// add quotation marks for correctness
	wcscpy_s(comm, L"\"");
	wcscat_s(comm, tsharkPath);
	wcscat_s(comm, L"\"");

	// argument for reading from file
	wcscat_s(comm, L" -r \"");
	wcscat_s(comm, pcapFilePath);
	wcscat_s(comm, L"\"");

	return startTshark(comm);
}
