void openPcap();
void closePcap();
void fixCurrentPcapSize();
void composePcapRecord();

void feedPcapWatchdog();
void terminateWatchdog();

void startWireshark();
void stopWireshark();

void showPacket();
void setPacketSize(UINT32 size);
void insertDataAtPacketOffset(UINT32 offset, PCSTR str, UINT32 len);
void cutDataAtPacketOffset(UINT32 offset, UINT32 len);