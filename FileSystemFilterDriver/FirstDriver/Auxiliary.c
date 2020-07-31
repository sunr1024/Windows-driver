#include"entry.h"

/**************************************************
@author		  : Sunr
@create time  : 20200730
@last   time  : 20200730
@description  : Querry the length of object name,then allocate memory and get the name.
**************************************************/
#pragma PAGEDCODE
NTSTATUS FSGetObjectName(IN PVOID pObject,IN OUT PUNICODE_STRING *pName)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	POBJECT_NAME_INFORMATION pNameInfo = NULL;
	ULONG retLength = 0;

	status = ObQueryNameString(pObject, NULL, 0, &retLength);
	
	if (!NT_SUCCESS(status) && STATUS_INFO_LENGTH_MISMATCH != status)
	{
		KdPrint(("FileSystemFilter!FSGetObjectName: "
			"Get length of object name string failed.\r\n"));
		return status;
	}

	pNameInfo = (POBJECT_NAME_INFORMATION)ExAllocatePoolWithTag(PagedPool, retLength, OBJECT_NAME_TAG);

	if (NULL == pNameInfo){
		KdPrint(("FileSystemFilter!FSGetObjectName: "
			"Allocate memory for object name string failed.\r\n"));
		return STATUS_INVALID_ADDRESS;
	}

	status = ObQueryNameString(pObject, pNameInfo, retLength, &retLength);

	if (!NT_SUCCESS(status)){
		KdPrint(("FileSystemFilter!FSGetObjectName: "
			"Get object's name failed.\r\n"));
		return status;
	}

	*pName = &(pNameInfo->Name);

	return status;
}

/**************************************************
@author		  : Sunr
@create time  : 20200730
@last   time  : 20200730
@description  : Querry the length of file object name, then allocate memory and get the name.
**************************************************/
#pragma PAGEDCODE
VOID FSGetFileName(IN PDEVICE_OBJECT pDeviceObject)
{
	PAGED_CODE();
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
	PUNICODE_STRING pustrDeviceObjectName = NULL;

	ntStatus = FSGetObjectName(pDeviceObject, &pustrDeviceObjectName);
	if (!NT_SUCCESS(ntStatus))
	{
		return;
	}

	KdPrint(("File Name: %wZ\r\n", pustrDeviceObjectName));
	
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
@description  : Traversing the all object in device in device stack to look for our filter device object.
**************************************************/
#pragma PAGEDCODE
BOOLEAN FSIsAttachedDevice(IN PDEVICE_OBJECT pDeviceObject)
{
	PAGED_CODE();
	PDEVICE_OBJECT pCurrentDeviceObject = IoGetAttachedDeviceReference(pDeviceObject);
	PDEVICE_OBJECT pNextDeviceObject = NULL;

	//Find filter device
	do
	{
		if (IS_MY_DEVICE_OBJECT(pCurrentDeviceObject)) {
			ObDereferenceObject(pCurrentDeviceObject);
			return TRUE;
		}

		pNextDeviceObject = IoGetLowerDeviceObject(pCurrentDeviceObject);

		//All object will decrease the reference
		ObDereferenceObject(pCurrentDeviceObject);
		pCurrentDeviceObject = pNextDeviceObject;
	} while (NULL != pCurrentDeviceObject);
	
	return FALSE;
}

