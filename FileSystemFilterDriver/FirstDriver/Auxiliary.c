#include"entry.h"


//querry the length of object name,then allocate memory and get the name
#pragma PAGEDCODE
NTSTATUS FSGetObjectName(IN PVOID pObject,IN OUT PUNICODE_STRING *pName)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	POBJECT_NAME_INFORMATION pNameInfo = NULL;
	ULONG retLength = 0;

	status = ObQueryNameString(pObject, NULL, 0, &retLength);
	
	if (!NT_SUCCESS(status) && STATUS_INFO_LENGTH_MISMATCH != status){
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

	status = ObQueryNameString(pObject,
		pNameInfo,
		retLength,
		&retLength);
	if (!NT_SUCCESS(status)){
		KdPrint(("FileSystemFilter!FSGetObjectName: "
			"Get object's name failed.\r\n"));
		return status;
	}

	*pName = &(pNameInfo->Name);

	return status;
}



#pragma PAGEDCODE
BOOLEAN FSIsAttachedDevice(IN PDEVICE_OBJECT pDeviceObject)
{
	PAGED_CODE();
	PDEVICE_OBJECT pCurrentDeviceObject = IoGetAttachedDeviceReference(pDeviceObject);
	PDEVICE_OBJECT pNextDeviceObject = NULL;

	//find filter device
	do
	{
		if (IS_MY_DEVICE_OBJECT(pCurrentDeviceObject)) {
			ObDereferenceObject(pCurrentDeviceObject);
			return TRUE;
		}

		pNextDeviceObject = IoGetLowerDeviceObject(pCurrentDeviceObject);

		//all object will decrease the rederence
		ObDereferenceObject(pCurrentDeviceObject);
		pCurrentDeviceObject = pNextDeviceObject;
	} while (NULL != pCurrentDeviceObject);
	
	return FALSE;
}




