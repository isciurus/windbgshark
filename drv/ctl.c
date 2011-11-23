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
    for (l = 0; l < IRP_MJ_MAXIMUM_FUNCTION; l++)
    {
        driverObject->MajorFunction[l] = drvCtlDispatchRequest;
    }

    driverObject->MajorFunction[IRP_MJ_CREATE] = drvCtlCreate;
    driverObject->MajorFunction[IRP_MJ_CLOSE] = drvCtlClose;
    driverObject->MajorFunction[IRP_MJ_CLEANUP] = drvCtlCleanup;
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