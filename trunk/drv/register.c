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

#include "ntddk.h"

#include "fwpmk.h"
#include "fwpsk.h"

#include "register.h"
#include "analyzer.h"
#include "callout.h"
#include "windbgshark_drv.h"

#define INITGUID
#include <guiddef.h>

// bb6e405b-19f4-4ff3-b501-1a3dc01aae01
DEFINE_GUID(
    LA_STREAM_CALLOUT_V4_KEY,
    0xbb6e405b,
    0x19f4,
    0x4ff3,
    0xb5, 0x01, 0x1a, 0x3d, 0xc0, 0x1a, 0xae, 0x01
);

// cabf7559-7c60-46c8-9d3b-2155ad5cf83f
DEFINE_GUID(
    LA_FLOW_ESTABLISHED_CALLOUT_V4_KEY,
    0xcabf7559,
    0x7c60,
    0x46c8,
    0x9d, 0x3b, 0x21, 0x55, 0xad, 0x5c, 0xf8, 0x3f
);

// 2e207682-d951-4525-b966-969f26587f03
DEFINE_GUID(
    LA_ENGINE_SUBLAYER,
    0x2e207682,
    0xd951,
    0x4525,
    0xb9, 0x66, 0x96, 0x9f, 0x26, 0x58, 0x7f, 0x03
);

void CleanupFlowContextList()
{
	KLOCK_QUEUE_HANDLE flowContextListLockHandle;

	KeAcquireInStackQueuedSpinLock(
		&flowContextListLock, 
		&flowContextListLockHandle);

	while (!IsListEmpty(&flowContextList))
	{
		FLOW_DATA* flowContext;
		LIST_ENTRY* entry;
		NTSTATUS status;

		entry = RemoveHeadList(&flowContextList);

		flowContext = CONTAINING_RECORD(entry, FLOW_DATA, listEntry);

		if(flowContext->deleting == FALSE)
		{
			// We don't want our flow deletion function
			// to try to remove this from the list.
			flowContext->deleting = TRUE;

			status = FwpsFlowRemoveContext(
				flowContext->flowHandle,
				FWPS_LAYER_STREAM_V4,
				gStreamCalloutIdV4);

			ASSERT(NT_SUCCESS(status));
		}
	}

	KeReleaseInStackQueuedSpinLock(&flowContextListLockHandle);
}

NTSTATUS AddFilter(
   IN const wchar_t* filterName,
   IN const wchar_t* filterDesc,
   IN const UINT8* remoteAddr,
   IN UINT64 context,
   IN const GUID* layerKey,
   IN const GUID* calloutKey
   )
{
   NTSTATUS status = STATUS_SUCCESS;

   FWPM_FILTER0 filter = {0};

   filter.layerKey = *layerKey;
   filter.displayData.name = (wchar_t*)filterName;
   filter.displayData.description = (wchar_t*)filterDesc;

   filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
   filter.action.calloutKey = *calloutKey;
   filter.filterCondition = NULL;
   filter.subLayerKey = LA_ENGINE_SUBLAYER;
   filter.weight.type = FWP_EMPTY; // auto-weight.
   filter.rawContext = context;
   filter.numFilterConditions = 0;

   status = FwpmFilterAdd0(
               gFwpmEngineHandle,
               &filter,
               NULL,
               NULL);

   return status;
}

NTSTATUS RegisterCallout(
   IN const GUID* layerKey,
   IN const GUID* calloutKey,
   FWPS_CALLOUT_CLASSIFY_FN0 classifyFn,
   FWPS_CALLOUT_NOTIFY_FN0 notifyFn,
   FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN0 flowDeleteFn,
   PWCHAR name,
   PWCHAR description,
   UINT32 flags,
   IN void* deviceObject,
   OUT UINT32* calloutId)
/* ++

		This function registers a callout and a filter that intercept 
		transport traffic at the following layers:

			FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4
			FWPM_LAYER_STEAM_V4

-- */
{
	NTSTATUS status = STATUS_SUCCESS;

	FWPS_CALLOUT0 sCallout = {0};
	FWPM_CALLOUT0 mCallout = {0};

	FWPM_DISPLAY_DATA0 displayData = {0};

	BOOLEAN calloutRegistered = FALSE;

	sCallout.calloutKey = *calloutKey;
	sCallout.flags = flags;
	sCallout.classifyFn = classifyFn;
	sCallout.flowDeleteFn = flowDeleteFn;
	sCallout.notifyFn = notifyFn;

	status = FwpsCalloutRegister0(
				deviceObject,
				&sCallout,
				calloutId);

	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}
	calloutRegistered = TRUE;

	displayData.name = name;
	displayData.description = description;

	mCallout.calloutKey = *calloutKey;
	mCallout.displayData = displayData;
	mCallout.applicableLayer = *layerKey;

	status = FwpmCalloutAdd0(
				gFwpmEngineHandle,
				&mCallout,
				NULL,
				NULL);

	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}

	status = AddFilter(
				name,
				description,
				NULL,
				0,
				layerKey,
				calloutKey);

	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}

Exit:

	if (!NT_SUCCESS(status))
	{
		if (calloutRegistered)
		{
			FwpsCalloutUnregisterById0(*calloutId);
			*calloutId = 0;
		}
	}

	return status;
}

NTSTATUS RegisterCallouts(
   IN void* deviceObject)
/* ++

   This function registers dynamic callouts and filters that intercept 
   transport traffic at stream layer.

   Callouts and filters will be removed during DriverUnload.

-- */
{
	NTSTATUS status = STATUS_SUCCESS;
	FWPM_SUBLAYER0 drvSubLayer;

	BOOLEAN engineOpened = FALSE;
	BOOLEAN inTransaction = FALSE;

	FWPM_SESSION0 session = {0};

	session.flags = FWPM_SESSION_FLAG_DYNAMIC;

	status = FwpmEngineOpen0(
				NULL,
				RPC_C_AUTHN_WINNT,
				NULL,
				&session,
				&gFwpmEngineHandle);

	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}

	engineOpened = TRUE;

	status = FwpmTransactionBegin0(gFwpmEngineHandle, 0);
	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}
	inTransaction = TRUE;

	RtlZeroMemory(&drvSubLayer, sizeof(FWPM_SUBLAYER0)); 

	drvSubLayer.subLayerKey = LA_ENGINE_SUBLAYER;
	drvSubLayer.displayData.name = L"Windbgshark Stream Sub-Layer";
	drvSubLayer.displayData.description = 
		L"Sub-Layer for use by Stream Inspect callouts";
	drvSubLayer.flags = 0;
	drvSubLayer.weight = 0;

	status = FwpmSubLayerAdd0(gFwpmEngineHandle, &drvSubLayer, NULL);
	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}

	// flow established callout
	status = RegisterCallout(
			&FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4,
			&LA_FLOW_ESTABLISHED_CALLOUT_V4_KEY,
			(FWPS_CALLOUT_CLASSIFY_FN0) drvFlowEstablishedClassify,
			drvFlowEstablishedNotify,
			NULL,
			L"Windbgshark flow established classify",
			L"Windbgshark flow established classify",
			0,
			deviceObject,
			&gFlowEstablishedCalloutIdV4);

	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}

	// stream callout
	status = RegisterCallout(
				&FWPM_LAYER_STREAM_V4,
				&LA_STREAM_CALLOUT_V4_KEY,
				(FWPS_CALLOUT_CLASSIFY_FN0) drvStreamClassify,
				drvStreamNotify,
				drvStreamDeletion,
				L"Windbgshark stream classify",
				L"Windbgshark stream classify",
				FWP_CALLOUT_FLAG_CONDITIONAL_ON_FLOW,
				deviceObject,
				&gStreamCalloutIdV4);

	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}
	
	status = FwpmTransactionCommit0(gFwpmEngineHandle);
	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}
	inTransaction = FALSE;

Exit:

	if (!NT_SUCCESS(status))
	{
		if (inTransaction)
		{
			FwpmTransactionAbort0(gFwpmEngineHandle);
		}

		if (engineOpened)
		{
			FwpmEngineClose0(gFwpmEngineHandle);
			gFwpmEngineHandle = NULL;
		}
	}

	return status;
}

NTSTATUS UnregisterCallouts()
{
	FwpmEngineClose0(gFwpmEngineHandle);
	gFwpmEngineHandle = NULL;

	FwpsCalloutUnregisterById0(gFlowEstablishedCalloutIdV4);
	FwpsCalloutUnregisterById0(gStreamCalloutIdV4);

	return STATUS_SUCCESS;
}