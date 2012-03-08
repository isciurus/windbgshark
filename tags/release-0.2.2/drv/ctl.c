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
#include "ntstrsafe.h"

#include "windbgshark_drv.h"
#include "ctl.h"
#include "analyzer.h"



DRIVER_DISPATCH drvCtlDispatchRequest;

__drv_dispatchType(IRP_MJ_CREATE) 
DRIVER_DISPATCH drvCtlCreate;

__drv_dispatchType(IRP_MJ_CLOSE) 
DRIVER_DISPATCH drvCtlClose;

__drv_dispatchType(IRP_MJ_CLEANUP) 
DRIVER_DISPATCH drvCtlCleanup;

__drv_dispatchType(IRP_MJ_DEVICE_CONTROL) 
DRIVER_DISPATCH drvCtlDeviceControl;

NTSTATUS drvCtlInit(PDRIVER_OBJECT driverObject)
	/*++

Routine Description:

   Initializes the Dispatch information for our driver.

Arguments:
   
   [in]  PDRIVER_OBJECT driverObject - Our driver.

Return Value:

   STATUS_SUCCESS

--*/
{
    long l;

    // suppress "The 'MajorFunction' member of _DRIVER_OBJECT should not be accessed by a driver warnings"                        
    #pragma warning(push)
    #pragma warning(disable:28175) 
    for (l = 0; l <= IRP_MJ_MAXIMUM_FUNCTION; l++)
    {
        driverObject->MajorFunction[l] = drvCtlDispatchRequest;
    }

    driverObject->MajorFunction[IRP_MJ_CREATE] = drvCtlCreate;
    driverObject->MajorFunction[IRP_MJ_CLOSE] = drvCtlClose;
    driverObject->MajorFunction[IRP_MJ_CLEANUP] = drvCtlCleanup;
	driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = drvCtlDeviceControl;
    #pragma warning(pop)

    return STATUS_SUCCESS;
}

NTSTATUS drvCtlDispatchRequest (
    IN PDEVICE_OBJECT deviceObject,
    IN PIRP irp)
/*++

Routine Description:

   Handles all requests that are not dealt with by other dispatch handlers.

Arguments:
   
   [in]  PDRIVER_OBJECT driverObject - Our driver.
   [in]  IRP irp - The IO request packet to process

Return Value:

   STATUS_SUCCESS

--*/
{
    NTSTATUS    status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(deviceObject);
    
    IoCompleteRequest(irp, IO_NO_INCREMENT);

    return status;
}	

NTSTATUS drvCtlCreate (
    IN PDEVICE_OBJECT deviceObject,
    IN PIRP irp)
/*++

Routine Description:

   Handles create requests (we don't do any additional processing at this point).

Arguments:
   
   [in]  PDRIVER_OBJECT driverObject - Our driver.
   [in]  IRP irp - The IO request packet to process

Return Value:

   STATUS_SUCCESS

--*/
{
    NTSTATUS    status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(deviceObject);

    IoCompleteRequest(irp, IO_NO_INCREMENT);

    return status;
}

NTSTATUS drvCtlClose (
    IN PDEVICE_OBJECT deviceObject,
    IN PIRP irp)
/*++

Routine Description:

   Handles close requests (we don't do any additional processing at this point).

Arguments:
   
   [in]  PDRIVER_OBJECT driverObject - Our driver.
   [in]  IRP irp - The IO request packet to process

Return Value:

   STATUS_SUCCESS

--*/
{
    NTSTATUS    status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(deviceObject);
    
    IoCompleteRequest(irp, IO_NO_INCREMENT);

    return status;
}

NTSTATUS drvCtlCleanup (
    IN PDEVICE_OBJECT deviceObject,
    IN PIRP irp)
/*++

Routine Description:

   Handles cleanup requests (we don't do any additional processing at this point).

Arguments:
   
   [in]  PDRIVER_OBJECT driverObject - Our driver.
   [in]  IRP irp - The IO request packet to process

Return Value:

   STATUS_SUCCESS

--*/
{
    NTSTATUS    status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(deviceObject);
    
    IoCompleteRequest(irp, IO_NO_INCREMENT);

    return status;
}

volatile NTSTATUS onioctl_stub(PCHAR cDumpFileName, PCHAR cProcessName)
{
	return STATUS_SUCCESS;
}

NTSTATUS drvCtlDeviceControl (
    IN PDEVICE_OBJECT deviceObject,
    IN PIRP irp)
/*++

Routine Description:

   Handles device IO control requests. This function drives all communication
   between the usermode exe and this driver.

Arguments:
   
   [in]  PDRIVER_OBJECT driverObject - Our driver.
   [in]  IRP irp - The IO request packet to process

Return Value:

   STATUS_SUCCESS

--*/
{
	NTSTATUS            status = STATUS_SUCCESS;
	PIO_STACK_LOCATION  irpSp;
	ULONG               ioControlCode;
	KLOCK_QUEUE_HANDLE	lockHandle;

	ULONG				size;
	PCHAR				buffer;

	ULONG				uDumpFileNameLength = 0;
	PCHAR				cDumpFileName = NULL, cProcessName = NULL;

	UNREFERENCED_PARAMETER(deviceObject);

	irpSp = IoGetCurrentIrpStackLocation(irp);

	size = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	buffer = (PCHAR) irp->AssociatedIrp.SystemBuffer;

	if(size == 0 || buffer == 0)
	{
		irp->IoStatus.Information = 0L;
		irp->IoStatus.Status = status = STATUS_INVALID_PARAMETER;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return status;
	}

	cDumpFileName = buffer;
	uDumpFileNameLength = strlen(cDumpFileName);

	if(uDumpFileNameLength >= size)
	{
		irp->IoStatus.Information = 0L;
		irp->IoStatus.Status = status = STATUS_INVALID_PARAMETER;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return status;
	}

	cProcessName = (PCHAR) ((ULONG64) cDumpFileName + 1 + (ULONG64) uDumpFileNameLength);

	onioctl_stub(cDumpFileName, cProcessName);

	irp->IoStatus.Information = 0L;
	irp->IoStatus.Status = status = STATUS_SUCCESS;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
}