#include"entry.h"

/**************************************************
@author		  : Sunr
@create time  : 20200730
@last   time  : 20200730
@description  : Print some debug info,then executive attach or detach operation
**************************************************/
#pragma PAGEDCODE
VOID FSChangeNotify(IN PDEVICE_OBJECT pDeviceObject, IN BOOLEAN FSActive)
{
	PAGED_CODE();
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PUNICODE_STRING pustrDeviceObjectName = NULL;

	status = FSGetObjectName(pDeviceObject, &pustrDeviceObjectName);
	if (!NT_SUCCESS(status))
	{
		return;
	}

	KdPrint(("Device Name: %wZ\r\n", pustrDeviceObjectName));
	KdPrint(((FSActive) ? "Activating file system\n" : "Deactivating file system\n"));

	if (FSActive)
	{
		FSAttachToFileSystemControlDevice(pDeviceObject,pustrDeviceObjectName);
	}
	else
	{
		FSDetachFromFileSystemControlDevice(pDeviceObject);
	}

	if (NULL != pustrDeviceObjectName)
	{
		POBJECT_NAME_INFORMATION pstObjectNameInfo = CONTAINING_RECORD(pustrDeviceObjectName, OBJECT_NAME_INFORMATION, Name);
		ExFreePoolWithTag(pstObjectNameInfo, OBJECT_NAME_TAG);
		pstObjectNameInfo = NULL;
	}
}

/**************************************************
@author		  : Sunr
@create time  : 20200730
@last   time  : 20200730
@description  : Set the complete event.
**************************************************/
#pragma PAGEDCODE
NTSTATUS FSCreateComplete(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp, IN PVOID pContext)
{
	UNREFERENCED_PARAMETER(pDeviceObject);
	UNREFERENCED_PARAMETER(pIrp);

	ASSERT(IS_MY_DEVICE_OBJECT(pDeviceObject));
	ASSERT(NULL != pContext);

	KeSetEvent((PKEVENT)pContext, IO_NO_INCREMENT, FALSE);

	return STATUS_MORE_PROCESSING_REQUIRED;
}

/**************************************************
@author		  : Sunr
@create time  : 20200730
@last   time  : 20200730
@description  : Set the complete event.
**************************************************/
#pragma PAGEDCODE
NTSTATUS FSCloseComplete(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp, IN PVOID pContext)
{
	UNREFERENCED_PARAMETER(pDeviceObject);
	UNREFERENCED_PARAMETER(pIrp);

	ASSERT(IS_MY_DEVICE_OBJECT(pDeviceObject));
	ASSERT(NULL != pContext);

	/*
	PIO_STACK_LOCATION pStackLocation = IoGetCurrentIrpStackLocation(pIrp);
	KdPrint(("Close 		"));
	FSGetFileName(pStackLocation->FileObject);
	*/

	KeSetEvent((PKEVENT)pContext, IO_NO_INCREMENT, FALSE);

	return STATUS_MORE_PROCESSING_REQUIRED;
}

/**************************************************
@author		  : Sunr
@create time  : 20200730
@last   time  : 20200730
@description  : Set the complete event.
**************************************************/
#pragma PAGEDCODE
NTSTATUS FSReadComplete(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp, IN PVOID pContext)
{
	UNREFERENCED_PARAMETER(pDeviceObject);
	UNREFERENCED_PARAMETER(pIrp);

	ASSERT(IS_MY_DEVICE_OBJECT(pDeviceObject));
	ASSERT(NULL != pContext);

	KeSetEvent((PKEVENT)pContext, IO_NO_INCREMENT, FALSE);

	return STATUS_MORE_PROCESSING_REQUIRED;
}

/**************************************************
@author		  : Sunr
@create time  : 20200730
@last   time  : 20200730
@description  : Set the complete event.
**************************************************/
#pragma PAGEDCODE
NTSTATUS FSMountDeviceComplete(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp, IN PVOID pContext)
{
	UNREFERENCED_PARAMETER(pDeviceObject);
	UNREFERENCED_PARAMETER(pIrp);

	ASSERT(IS_MY_DEVICE_OBJECT(pDeviceObject));
	ASSERT(NULL != pContext);

	KeSetEvent((PKEVENT)pContext, IO_NO_INCREMENT, FALSE);

	return STATUS_MORE_PROCESSING_REQUIRED;
}

/**************************************************
@author		  : Sunr
@create time  : 20200730
@last   time  : 20200730
@description  : Set the complete event.
**************************************************/
#pragma PAGEDCODE
NTSTATUS FSLoadFileSystemComplete(IN PDEVICE_OBJECT pDeviceObject,IN PIRP pIrp,IN PVOID pContext)
{
	UNREFERENCED_PARAMETER(pDeviceObject);
	UNREFERENCED_PARAMETER(pIrp);

	ASSERT(IS_MY_DEVICE_OBJECT(pDeviceObject));
	ASSERT(NULL != pContext);

	KeSetEvent((PKEVENT)pContext, IO_NO_INCREMENT, FALSE);

	return STATUS_MORE_PROCESSING_REQUIRED;
} 









