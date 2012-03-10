#include <Windows.h>

void setPacketBpFilter(PCHAR filter);

BOOLEAN checkPacketUsingFilter(PBYTE packet, ULONG packetLength);

//#include <string>
//std::string getFilteredContent();