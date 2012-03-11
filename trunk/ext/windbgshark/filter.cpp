#include "filter.h"
#define USING_PIPE

PWCHAR tsharkPath = L"C:\\Program Files\\Wireshark\\tshark.exe";

#ifdef USING_PIPE
PWCHAR pcapPipeName = L"tsharkPipe";
#else
PWCHAR pcapFilePath = L"C:\\Users\\Ivan\\Documents\\Visual Studio 2010\\Projects\\example\\Debug\\http.cap";
#endif

#define FILTER_MAX_SIZE 1024
#define COMMAND_MAX_SIZE 2048

WCHAR _filter[FILTER_MAX_SIZE];

HANDLE hTsharkProcess = INVALID_HANDLE_VALUE;
HANDLE hChildStdoutWr = INVALID_HANDLE_VALUE;
HANDLE hChildStdoutRdDup = INVALID_HANDLE_VALUE;
HANDLE hSharkPcap = INVALID_HANDLE_VALUE;
HANDLE hSharkPipe = INVALID_HANDLE_VALUE;

HANDLE readSharkPipe = INVALID_HANDLE_VALUE;
HANDLE writeSharkPipe = INVALID_HANDLE_VALUE;

BOOLEAN restartTshark();

#include <string>
std::string getFilteredContent();

void init()
{
#ifdef USING_PIPE
	// Create a pipe for using with tshark
	hSharkPipe = CreateNamedPipeW(pcapPipeName, 
		PIPE_ACCESS_OUTBOUND,  // from this to tshark
		PIPE_TYPE_BYTE,
		1,
		1024,
		1024,
		0,
		NULL);
#else
	hSharkPcap = CreateFileW(
			pcapFilePath,
			GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ,
			NULL,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			NULL);
#endif
	
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
#ifdef USING_PIPE
	if(hSharkPipe != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hSharkPipe);
	}
#else
	if(hSharkPcap!=INVALID_HANDLE_VALUE)
	{	
		CloseHandle(hSharkPcap);
	}
#endif
	
}

void setPacketBpFilter(PWCHAR filter)
{
	wcscpy_s(_filter, filter);
	
	restartTshark();
}

// the function compares two outputs from tshark
// before and after appending the packet into pcap file
//
// TODO: for every packet append it to tshark active pipe
// and after that verify output
// add #define USING_PIPE and change the restart tshark
BOOLEAN checkPacketUsingFilter(PBYTE packet, ULONG packetLength)
{
	// every packet satisfied empty filter
	if(wcslen(_filter) == 0) return TRUE;

	std::string prev = getFilteredContent();

	DWORD cbWritten;
	
#ifdef USING_PIPE
	WriteFile(
		hSharkPipe,
		packet,
		packetLength,
		&cbWritten,
		NULL);
#else
	// write the packet into pcap file
	
	SetFilePointer(hSharkPcap, 0, NULL, FILE_END);


	WriteFile(
		hSharkPcap,
		packet,
		packetLength,
		&cbWritten,
		NULL);
	
	SetEndOfFile(hSharkPcap);
	restartTshark();
#endif	


	
	std::string post = getFilteredContent();
#ifdef USING_PIPE
	// if no additional output then packet not matching
	return !post.empty();
#endif	
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
	fSuccess = CreateProcessW(NULL, 
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
	
	// tshark command sample: 
	// c:\Program Files\Wireshark\tshark.exe" -r "c:\http.cap" -T fields -e frame.number  -R udp.port==53
	// c:\Program Files\Wireshark\tshark.exe" -i tsharkPipe	   -T fields -e frame.number  -f udp.port==53
	// where 
	// -r					specified file to caprure/read from
	// -i					specified interface or pipe to caprure/read from
	// -T fields			show captures in custom format
	// -e frame.number		show only Layer 2 frames numbers
	// -R					specified display filter (when reading from file)
	// -f					specified capture filter (in case of capturing from interface or pipe)
	

	// add quotation marks for correctness
	wcscpy_s(comm, L"\"");
	wcscat_s(comm, tsharkPath);
	wcscat_s(comm, L"\" -T fields -e frame.number");


#ifdef USING_PIPE
	// argument for reading from pipe
	wcscat_s(comm, L" -i ");
	wcscat_s(comm, pcapPipeName);
	wcscat_s(comm, L" -f ");
	wcscat_s(comm, _filter);
#else
	// argument for reading from file
	wcscat_s(comm, L" -r \"");
	wcscat_s(comm, pcapFilePath);
	wcscat_s(comm, L"\"");
#endif

	

	return startTshark(comm);
}
