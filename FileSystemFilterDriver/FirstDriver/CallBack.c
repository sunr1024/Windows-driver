#include"entry.h"


#pragma PAGEDCODE
VOID FSChangeNotify(IN PDEVICE_OBJECT pDeviceObject, IN BOOLEAN FSActive)
{
	PAGED_CODE();
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
	PUNICODE_STRING pustrDeviceObjectName = NULL;

	ntStatus = FSGetObjectName(pDeviceObject, &pustrDeviceObjectName);
	if (!NT_SUCCESS(ntStatus))
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


#pragma PAGEDCODE
NTSTATUS FSLoadFileSystemComplete(IN PDEVICE_OBJECT pDeviceObject,IN PIRP pIrp,IN PVOID pContext)
{
	UNREFERENCED_PARAMETER(pDeviceObject);
	UNREFERENCED_PARAMETER(pIrp);

	ASSERT(IS_MY_DEVICE_OBJECT(pDeviceObject));
	ASSERT(NULL != pContext);

	KeSetEvent((PKEVENT)pContext, IO_NO_INCREMENT, FALSE);

	return STATUS_MORE_PROCESSING_REQUIRED;
} //! FSFilterLoadFileSystemComplete() END









