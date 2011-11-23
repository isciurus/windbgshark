#define TAG_FLOWCONTEXT 'nEaL'

void CleanupFlowContext(
	IN FLOW_DATA* flowContext);

NTSTATUS drvFlowEstablishedClassify(
	IN const FWPS_INCOMING_VALUES* inFixedValues,
	IN const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	IN VOID* layerData,
	IN const FWPS_FILTER* filter,
	IN UINT64 flowContext,
	OUT FWPS_CLASSIFY_OUT* classifyOut);

NTSTATUS NTAPI drvFlowEstablishedNotify(
   IN FWPS_CALLOUT_NOTIFY_TYPE notifyType,
   IN const GUID* filterKey,
   IN const FWPS_FILTER0* filter);

NTSTATUS drvStreamClassify(
	IN const FWPS_INCOMING_VALUES* inFixedValues,
	IN const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	IN VOID* layerData,
	IN const FWPS_FILTER* filter,
	IN UINT64 flowContext,
	OUT FWPS_CLASSIFY_OUT* classifyOut);

NTSTATUS drvStreamNotify(
	IN FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	IN const GUID* filterKey,
	IN const FWPS_FILTER0* filter);

NTSTATUS drvStreamDeletion(
	IN  UINT16 layerId,
	IN  UINT32 calloutId,
	IN  UINT64 flowContext);