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

#include "fwpsk.h"

#include "ndis.h"

#include "ctl.h"
#include "windbgshark_drv.h"
#include "register.h"
#include "analyzer.h"


PETHREAD gThreadObj;
PDEVICE_OBJECT gDeviceObject;
HANDLE gFwpmEngineHandle;
PNDIS_GENERIC_OBJECT gNdisGenericObj;

#define TAG_NDIS_OBJ 'oneS'
#define TAG_NBL_POOL 'pneS'

#define DEVICE_NAME L"\\Device\\WindbgsharkDrv"

DRIVER_UNLOAD DriverUnload;

NTSTATUS DriverEntry(
	IN  PDRIVER_OBJECT  driverObject,
	IN  PUNICODE_STRING registryPath)
{
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING deviceName;
	HANDLE threadHandle;
	NET_BUFFER_LIST_POOL_PARAMETERS nblPoolParams = {0};

#ifdef DEBUG
	DbgBreakPoint();
#endif

	status = drvCtlInit(driverObject);

	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}

	gDriverUnloading = FALSE;

	RtlInitUnicodeString(&deviceName, DEVICE_NAME);

	status = IoCreateDevice(
		driverObject, 
		0, 
		&deviceName, 
		FILE_DEVICE_NETWORK, 
		0, 
		FALSE, 
		&gDeviceObject);

	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}

	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}

	status = FwpsInjectionHandleCreate0(
		AF_UNSPEC,
		FWPS_INJECTION_TYPE_STREAM,
		&gInjectionHandle);

	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}

	gNdisGenericObj = NdisAllocateGenericObject(
			driverObject, 
			TAG_NDIS_OBJ,
			0);

	if (gNdisGenericObj == NULL)
	{
		status = STATUS_NO_MEMORY;
		goto Exit;
	}

	nblPoolParams.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
	nblPoolParams.Header.Revision = 
		NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
	nblPoolParams.Header.Size = 
		NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;

	nblPoolParams.fAllocateNetBuffer = TRUE;
	nblPoolParams.DataSize = 0;

	nblPoolParams.PoolTag = TAG_NBL_POOL;

	gNetBufferListPool = NdisAllocateNetBufferListPool(
                        gNdisGenericObj,
                        &nblPoolParams);

	if(gNetBufferListPool == NULL)
	{
		status = STATUS_NO_MEMORY;
		goto Exit;
	}

	InitializeListHead(&gPacketQueue);
	KeInitializeSpinLock(&gPacketQueueLock);  

	InitializeListHead(&flowContextList);
	KeInitializeSpinLock(&flowContextListLock);

	KeInitializeEvent(
		&gWorkerEvent,
		NotificationEvent,
		FALSE
	);
	
	status = RegisterCallouts(gDeviceObject);

	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}

	status = PsCreateSystemThread(
			&threadHandle,
			THREAD_ALL_ACCESS,
			NULL,
			NULL,
			NULL,
			thAnalyzer,
			NULL);

	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}

	status = ObReferenceObjectByHandle(
		threadHandle,
		0,
		NULL,
		KernelMode,
		(PVOID*) &gThreadObj,
		NULL);

	ASSERT(NT_SUCCESS(status));
	
	KeSetBasePriorityThread(
		(PKTHREAD) gThreadObj,
		-2);

	ZwClose(threadHandle);

	driverObject->DriverUnload = DriverUnload;

Exit:
   
	if (!NT_SUCCESS(status))
	{
		if (gFwpmEngineHandle != NULL)
		{
			UnregisterCallouts();
		}

		if (gInjectionHandle != NULL)
		{
			FwpsInjectionHandleDestroy0(gInjectionHandle);
		}

		if (gDeviceObject)
		{
			IoDeleteDevice(gDeviceObject);
		}

		if (gNetBufferListPool != NULL)
		{
			NdisFreeNetBufferListPool(gNetBufferListPool);
		}
			
		if (gNdisGenericObj != NULL)
		{
			NdisFreeGenericObject(gNdisGenericObj);
		}
	}

return status;
}

VOID DriverUnload(
	IN  PDRIVER_OBJECT driverObject)
{
	UNICODE_STRING dosDeviceName;
	UNREFERENCED_PARAMETER(driverObject);

	// set the unloading marker
	{
		KLOCK_QUEUE_HANDLE packetQueueLockHandle;
		KeAcquireInStackQueuedSpinLock(
			&gPacketQueueLock,
			&packetQueueLockHandle
			);

		gDriverUnloading = TRUE;

		KeReleaseInStackQueuedSpinLock(&packetQueueLockHandle);
	}

	CleanupFlowContextList();

	if (IsListEmpty(&gPacketQueue))
	{
		KeSetEvent(
			&gWorkerEvent,
			IO_NO_INCREMENT, 
			FALSE);
	}

	ASSERT(gThreadObj != NULL);

	KeWaitForSingleObject(
		gThreadObj,
		Executive,
		KernelMode,
		FALSE,
		NULL);

	ObDereferenceObject(gThreadObj);

	UnregisterCallouts();

	NdisFreeNetBufferListPool(gNetBufferListPool);
	NdisFreeGenericObject(gNdisGenericObj);

	FwpsInjectionHandleDestroy0(gInjectionHandle);

	IoDeleteDevice(gDeviceObject);
}