UINT32 gStreamCalloutIdV4, gFlowEstablishedCalloutIdV4;
HANDLE gFwpmEngineHandle;

NTSTATUS RegisterCallouts(IN void* deviceObject);
NTSTATUS UnregisterCallouts();
void CleanupFlowContextList();