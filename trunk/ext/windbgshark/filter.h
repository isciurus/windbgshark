#include <Windows.h>

void init();
void close();

void setPacketBpFilter(PCHAR filter);
BOOLEAN checkPacketUsingFilter(PBYTE packet, ULONG packetLength);

//#include <string>
//std::string getFilteredContent();