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

#include "analyzer.h"
#include "callout.h"
#include "windbgshark_drv.h"
#include "register.h"
#include "ctl.h"

void CleanupFlowContext(IN FLOW_DATA *flowContext)
{
	if(flowContext == NULL)
	{
		// Something went wrong
		return;
	}

	// Rough attempt to catch double free case, checking for NULL
	if(flowContext->flowHandle == 0)
	{
		return;
	}

	// If we're already being deleted from the list then we mustn't
	// try to remove ourselves here.
	if(!flowContext->deleting)
	{
		RemoveEntryList(&(flowContext->listEntry));
	}

	// Rough attempt to catch double free case, zero memory
	RtlZeroMemory(flowContext, sizeof(FLOW_DATA));
	
	ExFreePoolWithTag(flowContext, TAG_FLOWCONTEXT);
}

UINT64 CreateFlowContext(
   IN const FWPS_INCOMING_VALUES* inFixedValues,
   IN const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
   OUT UINT64* flowHandle)
{
	FLOW_DATA*     flowContext = NULL;
	NTSTATUS       status;
	UINT32         index;
	KLOCK_QUEUE_HANDLE lockHandle;

	// If flow handle is not set, don't create the context
	if((inMetaValues->currentMetadataValues & 
		FWPS_METADATA_FIELD_FLOW_HANDLE) == 0)
	{
		goto Exit;
	}

	// flowContext gets deleted in CleanupFlowContext 
	#pragma warning( suppress : 28197 )
	flowContext = ExAllocatePoolWithTag(NonPagedPool,
										sizeof(FLOW_DATA),
										TAG_FLOWCONTEXT);

	if (!flowContext)
	{
		goto Exit;
	}

	RtlZeroMemory(flowContext, sizeof(FLOW_DATA));

	flowContext->flowHandle = inMetaValues->flowHandle;
	*flowHandle = flowContext->flowHandle;

	index = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_PROTOCOL;
	flowContext->ipProto = 
		inFixedValues->incomingValue[index].value.uint16;

	index = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_ADDRESS;
	flowContext->localAddressV4 = 
		inFixedValues->incomingValue[index].value.uint32;

	index = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_PORT;
	flowContext->localPort = 
		inFixedValues->incomingValue[index].value.uint16;

	index = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_ADDRESS;
	flowContext->remoteAddressV4 = 
		inFixedValues->incomingValue[index].value.uint32;

	index = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_PORT;
	flowContext->remotePort = 
		inFixedValues->incomingValue[index].value.uint16;

	index = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_DIRECTION;
	flowContext->direction = 
		inFixedValues->incomingValue[index].value.uint16;

	flowContext->localCounter = 0;
	flowContext->remoteCounter = 0;

	// Notice, that we have not inserted this entry in flowContextList 
	// yet (which is equal to flowContext deleting by anyone else from 
	// the CleanupFlowContext's point of view)
	flowContext->deleting = TRUE;

	KeAcquireInStackQueuedSpinLock(&flowContextListLock, &lockHandle);
	if(!gDriverUnloading)
	{
		// Search for the pairwise localhost connection of opposite direction
		
		BOOLEAN pairwiseFound = FALSE;

		if(flowContext->localAddressV4 == 0x7f000001 // localhost
			&& flowContext->remoteAddressV4 == 0x7f000001 //localhost
			&& !IsListEmpty(&flowContextList))
		{
			PLIST_ENTRY flowContextListEntry = NULL;
			
			for(flowContextListEntry = flowContextList.Flink;
				flowContextListEntry != &flowContextList;
				flowContextListEntry = flowContextListEntry->Flink)
			{
				FLOW_DATA *flowContextIter = CONTAINING_RECORD(
						flowContextListEntry,
						FLOW_DATA,
						listEntry);

				if(flowContextIter->ipProto == flowContext->ipProto
					&& (flowContextIter->direction == FWP_DIRECTION_OUTBOUND && flowContext->direction == FWP_DIRECTION_INBOUND
						|| flowContextIter->direction == FWP_DIRECTION_INBOUND && flowContext->direction == FWP_DIRECTION_OUTBOUND)
					&& flowContextIter->localPort == flowContext->remotePort
					&& flowContextIter->remotePort == flowContext->localPort)
				{
					pairwiseFound = TRUE;
					break;
				}
			}
		}

		if(!pairwiseFound)
		{
			InsertTailList(&flowContextList, &flowContext->listEntry);
			flowContext->deleting = FALSE;
			status = STATUS_SUCCESS;
		}
		else
		{
			status = STATUS_UNSUCCESSFUL;
		}
	}
	else
	{
		// driver is being unloaded, abandon any flow creation
		status = STATUS_SHUTDOWN_IN_PROGRESS;
	}
	KeReleaseInStackQueuedSpinLock(&lockHandle);

Exit:

   if (!NT_SUCCESS(status) && flowContext)
   {
      CleanupFlowContext(flowContext);
	  flowContext = NULL;
   }

   return (UINT64) flowContext;
}




NTSTATUS drvFlowEstablishedClassify(
   IN const FWPS_INCOMING_VALUES* inFixedValues,
   IN const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
   IN VOID* layerData,
   IN const FWPS_FILTER* filter,
   IN UINT64 flowContext,
   OUT FWPS_CLASSIFY_OUT* classifyOut)
{
	NTSTATUS status = STATUS_SUCCESS;
	UINT64   flowHandle;
	UINT64   flowContextLocal;
	KLOCK_QUEUE_HANDLE	lockHandle;
	BOOLEAN localInspectEnabled = FALSE;

	UNREFERENCED_PARAMETER(layerData);
	
	flowContextLocal = CreateFlowContext(inFixedValues, inMetaValues, &flowHandle);

	if (!flowContextLocal)
	{
		classifyOut->actionType = FWP_ACTION_PERMIT;
		goto cleanup;
	}

	status = FwpsFlowAssociateContext(flowHandle,
		FWPS_LAYER_STREAM_V4,
		gStreamCalloutIdV4,
		flowContextLocal);

	if (!NT_SUCCESS(status))
	{
		classifyOut->actionType = FWP_ACTION_CONTINUE;
		goto cleanup;
	}

	classifyOut->actionType = FWP_ACTION_PERMIT;

cleanup:

	return status;
}

NTSTATUS drvFlowEstablishedNotify(
   IN FWPS_CALLOUT_NOTIFY_TYPE notifyType,
   IN const GUID* filterKey,
   IN const FWPS_FILTER0* filter)
{
   UNREFERENCED_PARAMETER(notifyType);
   UNREFERENCED_PARAMETER(filterKey);
   UNREFERENCED_PARAMETER(filter);

   return STATUS_SUCCESS;
}


NTSTATUS drvStreamClassify(
   IN const FWPS_INCOMING_VALUES* inFixedValues,
   IN const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
   IN FWPS_STREAM_CALLOUT_IO_PACKET0* packet,
   IN const FWPS_FILTER* filter,
   IN UINT64 flowContext,
   OUT FWPS_CLASSIFY_OUT* classifyOut)
{
	KLOCK_QUEUE_HANDLE packetQueueLockHandle;
	PENDED_PACKET *pendedPacket = NULL;
	BOOLEAN signalWorkerThread;
	LARGE_INTEGER	systemTime, localTime;
	TIME_FIELDS	timeFields;
	KLOCK_QUEUE_HANDLE lockHandle;
	BOOLEAN localInspectEnabled;

	KeQuerySystemTime(&systemTime);
	ExSystemTimeToLocalTime(&systemTime, &localTime);

	// We don't have the necessary right to alter the classify, exit.
	if ((classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0)
	{
		goto Exit;
	}

	// We don't edit TCP urgent data
	if ((packet->streamData->flags & FWPS_STREAM_FLAG_SEND_EXPEDITED) 
		|| (packet->streamData->flags & FWPS_STREAM_FLAG_RECEIVE_EXPEDITED) 
		//|| (packet->streamData->flags & 
		) 
	{
		packet->streamAction = FWPS_STREAM_ACTION_NONE;
		classifyOut->actionType = FWP_ACTION_PERMIT;
		goto Exit;
	}

	ASSERT(packet != NULL);

	pendedPacket = AllocateAndInitializeStreamPendedPacket(
		inFixedValues,
		inMetaValues,
		(FLOW_DATA*) flowContext,
		&localTime,
		packet);

	if (pendedPacket == NULL)
	{
		// Insufficient resources?
		classifyOut->actionType = FWP_ACTION_CONTINUE;
		goto Exit;
	}


	KeAcquireInStackQueuedSpinLock(
		&gPacketQueueLock,
		&packetQueueLockHandle);

	if (!gDriverUnloading)
	{
		signalWorkerThread = IsListEmpty(&gPacketQueue);

		InsertTailList(&gPacketQueue, &pendedPacket->listEntry);
		pendedPacket = NULL; // ownership transferred

		classifyOut->actionType = FWP_ACTION_BLOCK;
		classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
	}
	else
	{
		// Driver is being unloaded, permit any connect classify.
		signalWorkerThread = FALSE;

		classifyOut->actionType = FWP_ACTION_PERMIT;
	}

	KeReleaseInStackQueuedSpinLock(&packetQueueLockHandle);

	if (signalWorkerThread)
	{
		KeSetEvent(
			&gWorkerEvent, 
			0, 
			FALSE);
	}

Exit:

	if (pendedPacket != NULL)
	{
		FreePendedPacket(pendedPacket);
	}

	return STATUS_SUCCESS;
}

NTSTATUS drvStreamNotify(
   IN FWPS_CALLOUT_NOTIFY_TYPE notifyType,
   IN const GUID* filterKey,
   IN const FWPS_FILTER0* filter)
{
   UNREFERENCED_PARAMETER(notifyType);
   UNREFERENCED_PARAMETER(filterKey);
   UNREFERENCED_PARAMETER(filter);

   return STATUS_SUCCESS;
}

NTSTATUS drvStreamDeletion(
	IN  UINT16 layerId,
	IN  UINT32 calloutId,
	IN  UINT64 flowContext)
{
	// We can't free the memory of the corresponding FLOW_DATA 
	// disposition here, while thAnalyzer thread may use it. Stream 
	// deletion is handled in the thAnalyzer thread, while processing
	// the "close" packet, which is sent from here

	KLOCK_QUEUE_HANDLE packetQueueLockHandle;
	PENDED_PACKET *pendedPacket;
	BOOLEAN signalWorkerThread;

	// pendedPacket gets deleted in FreePendedPacket
	#pragma warning( suppress : 28197 )
	pendedPacket = ExAllocatePoolWithTag(
		NonPagedPool,
		sizeof(PENDED_PACKET),
		TAG_PENDEDPACKET);

	if (pendedPacket == NULL)
	{
		return STATUS_UNSUCCESSFUL;
	}

	RtlZeroMemory(pendedPacket, sizeof(PENDED_PACKET));

	pendedPacket->flowContext = (FLOW_DATA *) flowContext;
	pendedPacket->close = TRUE;

	KeAcquireInStackQueuedSpinLock(
		&gPacketQueueLock,
		&packetQueueLockHandle);

	if (!gDriverUnloading)
	{
		signalWorkerThread = IsListEmpty(&gPacketQueue);

		InsertTailList(&gPacketQueue, &pendedPacket->listEntry);
		pendedPacket = NULL; // ownership transferred
	}
	else
	{
		// Driver is being unloaded, permit any connect classify.
		signalWorkerThread = FALSE;
	}

	KeReleaseInStackQueuedSpinLock(&packetQueueLockHandle);

	if (signalWorkerThread)
	{
		KeSetEvent(
			&gWorkerEvent, 
			0, 
			FALSE);
	}

	return STATUS_SUCCESS;
}