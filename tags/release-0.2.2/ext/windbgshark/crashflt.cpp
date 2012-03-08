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
#include <stdlib.h>

#include "../dbgexts.h"

#include "windbgshark.h"

extern BOOL Debug;

#include "crashflt.h"

PCHAR crashfltFilter;


BOOLEAN wildcard_match(PCHAR pattern, PCHAR string)
{
	if(pattern == NULL)
	{
		// Every string matches empty filter
		return TRUE;
	}

	if(string == NULL)
	{
		// Empty string does not match any pattern
		return FALSE;
	}

	while(*string) 
	{
		switch(*pattern)
		{
		case '*': 
			do 
			{
				++pattern;
			}
			while(*pattern == '*');

			if(!*pattern) return TRUE;
		
			while(*string)
			{
				if(wildcard_match(pattern,string++)==TRUE)
					return TRUE;
			}
			return FALSE;
		
		default:
			if(*string!=*pattern)return(FALSE); break;
		}

		++pattern;
		++string;
	}

	while (*pattern == '*') ++pattern;
	return !*pattern;

	// possible tests
	/*
	PWCHAR filter1 = L"C:\\*some*something.e*";
	PWCHAR filter2 = L"*C:\\*some*something.e*";
	PWCHAR filter3 = L"*C:\\*some*something.ed*";
	PWCHAR filter4 = L"C:\\*some*something.e";
	PWCHAR filter5 = L"*C:\\*somet*something.e*";
	PWCHAR filter6 = L"C:\\*somer*something.e*";
	PWCHAR path = L"C:\\foo\\somebar\\something.exe";

	assert(wildcard_match(filter1, path));
	assert(wildcard_match(filter2, path));
	assert(!wildcard_match(filter3, path));
	assert(!wildcard_match(filter4, path));
	assert(!wildcard_match(filter5, path));
	assert(!wildcard_match(filter6, path));
	*/
}

void crashfltPrintFilter()
{
	dprintf("[windbgshark] crash monitor process name filter: %s\n", 
		crashfltFilter != NULL ? crashfltFilter : "");
}

void crashfltSetFilter(PCHAR filter)
{
	crashfltFilter = (PCHAR) realloc(crashfltFilter, strlen(filter) + 1);

	if(crashfltFilter != NULL)
	{
		memset(crashfltFilter, 0, strlen(filter) + 1);
		strncpy(crashfltFilter, filter, strlen(filter));
	}
}

BOOLEAN crashfltFilterMatch(PCHAR full_path)
{
	myDprintf("[windbgshark] crashfltFilterMatch called for %s\n", full_path);
	return wildcard_match(crashfltFilter, full_path);
}

void crashfltFilterCleanup()
{
	if(crashfltFilter != NULL)
	{
		delete [] crashfltFilter;
	}
}


// here you can set some rules about
// symbols' equality
// e.g. case insensetivity
BOOLEAN is_equal_symbols(WCHAR a, WCHAR b)
{
	return a==b;
}