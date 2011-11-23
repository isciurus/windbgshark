#include "ntifs.h"
#include "ntstrsafe.h"


volatile UINT32 nop()
{
	return 0xff;
}

BOOLEAN myRtlTimeToSecondsSince1970(PLARGE_INTEGER localTime, PULONG timestamp)
{
	return RtlTimeToSecondsSince1970(localTime, timestamp);
}