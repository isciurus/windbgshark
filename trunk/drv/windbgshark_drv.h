BOOLEAN gDriverUnloading;

LIST_ENTRY gPacketQueue;
KSPIN_LOCK gPacketQueueLock;

LIST_ENTRY flowContextList;
KSPIN_LOCK flowContextListLock;

HANDLE gInjectionHandle;
NDIS_HANDLE gNetBufferListPool;