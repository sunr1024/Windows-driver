#include"entry.h"


PDRIVER_OBJECT g_pstDriverObject = NULL;
PDEVICE_OBJECT g_pstControlDeviceObject = NULL;
FAST_MUTEX g_stAttachLock;

/**************************************************
@author		  : Sunr
@create time  : 0200730
@last   time  : 20200730
@description  : Set Unload routine, irp dispatch routine, fast io routine, callback function and create device
**************************************************/
#pragma INITCODE
NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject, IN PUNICODE_STRING pRegistryPath)
{
	PAGED_CODE();


	UNREFERENCED_PARAMETER(pRegistryPath);
	KdPrint(("Enter DriverEntry\n"));


	// Initialize the fast mutex.
	ExInitializeFastMutex(&g_stAttachLock);

	g_pstDriverObject = pDriverObject;
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	pDriverObject->DriverUnload = DriverUnload;

	//Set irp routine
	for ( ULONG i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++) {
		pDriverObject->MajorFunction[i] = FSIrpDefault;
	}

	pDriverObject->MajorFunction[IRP_MJ_FILE_SYSTEM_CONTROL] = FSIrpFileSystemControl;
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = FSIrpCreate;
	pDriverObject->MajorFunction[IRP_MJ_READ] = FSIrpRead;
	pDriverObject->MajorFunction[IRP_MJ_WRITE] = FSIrpWrite;
	//pDriverObject->MajorFunction[IRP_MJ_CLEANUP] = FSIrpClose;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = FSIrpClose;
	pDriverObject->MajorFunction[IRP_MJ_SET_INFORMATION] = FSIrpSetInfo;

	
	//Set Fast I/O routine
	PFAST_IO_DISPATCH pFastIoDispatch = NULL;
	pFastIoDispatch = (PFAST_IO_DISPATCH)ExAllocatePoolWithTag( NonPagedPool, sizeof(FAST_IO_DISPATCH), FAST_IO_DISPATCH_TAG);

	if (NULL == pFastIoDispatch) {
		KdPrint(("FileSystemFilter!DriverEntry: "
			"Allocate memory for fast io dispatch failed.\r\n"));
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlZeroMemory(pFastIoDispatch, sizeof(FAST_IO_DISPATCH));
	pFastIoDispatch->SizeOfFastIoDispatch = sizeof(FAST_IO_DISPATCH);

	pFastIoDispatch->FastIoCheckIfPossible = FSFastIoCheckIfPossible;
	pFastIoDispatch->FastIoRead = FSFastIoRead;
	pFastIoDispatch->FastIoWrite = FSFastIoWrite;
	pFastIoDispatch->FastIoQueryBasicInfo = FSFastIoQueryBasicInfo;
	pFastIoDispatch->FastIoQueryStandardInfo = FSFastIoQueryStandardInfo;
	pFastIoDispatch->FastIoQueryOpen = FSFastIoQueryOpen;
	pFastIoDispatch->FastIoQueryNetworkOpenInfo = FSFastIoQueryNetworkOpenInfo;
	pFastIoDispatch->FastIoLock = FSFastIoLock;
	pFastIoDispatch->FastIoUnlockAll = FSFastIoUnlockAll;
	pFastIoDispatch->FastIoUnlockSingle = FSFastIoUnlockSingle;
	pFastIoDispatch->FastIoUnlockAllByKey = FSFastIoUnlockAllByKey;
	pFastIoDispatch->FastIoDeviceControl = FSFastIoDeviceControl;
	pFastIoDispatch->FastIoDetachDevice = FSFastIoDetachDevice;
	pFastIoDispatch->MdlRead = FSFastIoMdlRead;
	pFastIoDispatch->MdlReadComplete = FSFastIoMdlReadComplete;
	pFastIoDispatch->MdlReadCompleteCompressed = FSFastIoMdlReadCompleteCompressed;
	pFastIoDispatch->PrepareMdlWrite = FSFastIoPrepareMdlWrite;
	pFastIoDispatch->MdlWriteComplete = FSFastIoMdlWriteComplete;
	pFastIoDispatch->MdlWriteCompleteCompressed = FSFastIoMdlWriteCompleteCompressed;
	pFastIoDispatch->FastIoReadCompressed = FSFastIoReadCompressed;
	pFastIoDispatch->FastIoWriteCompressed = FSFastIoWriteCompressed;

	pDriverObject->FastIoDispatch = pFastIoDispatch;

	//Register the call back when file system has change
	status = IoRegisterFsRegistrationChange(pDriverObject, FSChangeNotify);

	if (!NT_SUCCESS(status))
	{
		KdPrint(("FileSystemFilter!DriverEntry: "
			"Register file system change routine failed.\r\n"));
		return status;
	}

	status = FSCreateDevice(pDriverObject);

	KdPrint(("DriverEntry end\n"));
	return status;
}


/**************************************************
@author		  : Sunr
@create time  : 20200730
@last   time  : 20200730
@description  : Free memory
**************************************************/

#pragma PAGEDCODE
VOID DriverUnload(IN PDRIVER_OBJECT pDriverObject)
{
	PAGED_CODE();

	PDEVICE_EXTENSION pDeviceExtension = NULL;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	ULONG ulDeviceObjectNumber = 0;
	PDEVICE_OBJECT *apstDeviceObjectList = NULL;
	ULONG ulDeviceObjectListSize = 0;

	KdPrint(("Enter DriverUnload\n"));

	IoUnregisterFsRegistrationChange(pDriverObject, FSChangeNotify);

	//delete device and symbol
	do
	{
		//get number of device object
		status = IoEnumerateDeviceObjectList(pDriverObject, NULL, 0, &ulDeviceObjectNumber);

		if (!NT_SUCCESS(status) && STATUS_BUFFER_TOO_SMALL != status) {
			KdPrint(("FileSystemFilter!FSFilterUnload: "
				"Get number of device object failed.\r\n"));
			break;
		}

		ulDeviceObjectListSize = sizeof(PDEVICE_OBJECT)*ulDeviceObjectNumber;

		//allocate memory
		apstDeviceObjectList = (PDEVICE_OBJECT *)ExAllocatePoolWithTag(PagedPool, ulDeviceObjectListSize, DEVICE_OBJECT_LIST_TAG);
		if (NULL == apstDeviceObjectList) {
			KdPrint(("ExAllocatePoolWithTag failed.\r\n"));
			break;
		}

		//get device object list
		status = IoEnumerateDeviceObjectList(pDriverObject, apstDeviceObjectList, ulDeviceObjectListSize, &ulDeviceObjectNumber);

		if (!NT_SUCCESS(status)) {
			KdPrint(("IoEnumerateDeviceObjectList failed.\r\n"));
			break;
		}


		//detach all device
		for (ULONG i = 0; i < ulDeviceObjectNumber; i++)
		{
			//normal check
			if (NULL == apstDeviceObjectList[i]) {
				continue;
			}

			pDeviceExtension = (PDEVICE_EXTENSION)apstDeviceObjectList[i]->DeviceExtension;

			if (NULL != pDeviceExtension) {
				IoDetachDevice(pDeviceExtension->pstNextDeviceObject);
			}
		}


		//wait for irp
		LARGE_INTEGER stInterval;
		stInterval.QuadPart = (5 * DELAY_ONE_SECOND);
		KeDelayExecutionThread(KernelMode, FALSE, &stInterval);

		//delete all device
		for (ULONG i = 0; i < ulDeviceObjectNumber; i++)
		{
			// Normal check.
			if (NULL == apstDeviceObjectList[i])
			{
				continue;
			}

			IoDeleteDevice(apstDeviceObjectList[i]);
			ObDereferenceObject(apstDeviceObjectList[i]);
		}
	} while (FALSE);
	
	//free memory
	if (NULL != apstDeviceObjectList) {
		ExFreePoolWithTag(apstDeviceObjectList, DEVICE_OBJECT_LIST_TAG);
	}

	//free memory of fast io dispatch table
	PFAST_IO_DISPATCH pFastIoDispatch = pDriverObject->FastIoDispatch;
	pDriverObject->FastIoDispatch = NULL;
	if (NULL != pFastIoDispatch) {
		ExFreePoolWithTag(pFastIoDispatch, FAST_IO_DISPATCH_TAG);
		pFastIoDispatch = NULL;
	}
}


/**************************************************
@author		  : Sunr
@create time  : 20200730
@last   time  : 20200730
@description  : Create device
**************************************************/

NTSTATUS FSCreateDevice(PDRIVER_OBJECT pDriverObject)
{
	PAGED_CODE();

	NTSTATUS status;
	UNICODE_STRING nameString;
	RtlInitUnicodeString(&nameString, CONTROL_DEVICE_NAME);

	//Create device object
	status = IoCreateDevice(pDriverObject, 0, &nameString, FILE_DEVICE_DISK_FILE_SYSTEM, FILE_DEVICE_SECURE_OPEN, FALSE, &g_pstControlDeviceObject);

	//Path not find
	if (status == STATUS_OBJECT_PATH_NOT_FOUND) 
	{
		RtlInitUnicodeString(&nameString, OLD_CONTROL_DEVICE_NAME);
		status = IoCreateDevice(pDriverObject, 0, &nameString, FILE_DEVICE_DISK_FILE_SYSTEM, FILE_DEVICE_SECURE_OPEN, FALSE, &g_pstControlDeviceObject);


		if (!NT_SUCCESS(status)) 
		{
			KdPrint(("FileSystemFilter!FsFilterAddDevice: "
				"Create \"%wZ\" deivce failed.\r\n",
				&nameString));
			return status;
		}
	}
	else if (!NT_SUCCESS(status)) 
	{
		KdPrint(("FileSystemFilter!FsFilterAddDevice: "
			"Create \"%wZ\" deivce failed.\r\n",
			&nameString));
		return status;
	}
	return STATUS_SUCCESS;
}


/**************************************************
@author		  : Sunr
@create time  : 20200730
@last   time  : 20200730
@description  : Get device object list of file system driver, create filter and attach to the device if it is my target device, then save the name of device free the resource, until all device has been operated.
**************************************************/
#pragma PAGEDCODE
NTSTATUS FSAttachToMountedVolumeDevice(IN PDEVICE_OBJECT pFSControlDeviceObject)
{
	PAGED_CODE();

	NTSTATUS status = STATUS_UNSUCCESSFUL;
	ULONG ulDeviceObjectNumber = 0;
	PDEVICE_OBJECT *apstDeviceObjectList = NULL;
	ULONG ulDeviceObjectListSize = 0;

	do
	{
		//Get number of device object
		status = IoEnumerateDeviceObjectList(pFSControlDeviceObject->DriverObject, NULL, 0, &ulDeviceObjectNumber);

		if (!NT_SUCCESS(status) && STATUS_BUFFER_TOO_SMALL != status) 
		{
			KdPrint(("FileSystemFilter!FSAttachToMountedVolumeDevice: "
				"Get number device objectk failed.\r\n"));
			break;
		}

		ulDeviceObjectListSize = sizeof(PDEVICE_OBJECT)*ulDeviceObjectNumber;

		//Allocate memory
		apstDeviceObjectList = (PDEVICE_OBJECT *)ExAllocatePoolWithTag(PagedPool, ulDeviceObjectListSize, DEVICE_OBJECT_LIST_TAG);

		if (NULL == apstDeviceObjectList) 
		{
			KdPrint(("ExAllocatePoolWithTag failed.\r\n"));
			break;
		}

		//get device object list
		status = IoEnumerateDeviceObjectList(pFSControlDeviceObject->DriverObject, apstDeviceObjectList, ulDeviceObjectListSize, &ulDeviceObjectNumber);

		if (!NT_SUCCESS(status)) 
		{
			KdPrint(("IoEnumerateDeviceObjectList failed.\r\n"));
			break;
		}

		//Get lock
		ExAcquireFastMutex(&g_stAttachLock);
		//Create filter device and attach
		for (ULONG i = 0; i < ulDeviceObjectNumber; i++) 
		{
			//Normal check
			if (NULL == apstDeviceObjectList[i]) 
			{
				continue;
			}

			//Check the device is my target and it's  not a control device
			if (pFSControlDeviceObject == apstDeviceObjectList[i] || (pFSControlDeviceObject->DeviceType != apstDeviceObjectList[i]->DeviceType) || FSIsAttachedDevice(apstDeviceObjectList[i])) 
			{
				continue;
			}

			//Create device
			PDEVICE_OBJECT pFilterDeviceObject = NULL;
			status = IoCreateDevice(g_pstDriverObject, sizeof(DEVICE_EXTENSION), NULL, apstDeviceObjectList[i]->DeviceType, 0, FALSE, &pFilterDeviceObject);

			if (!NT_SUCCESS(status)) {
				KdPrint(("FileSystemFilter!"
					"FSAttachToMountedVolumeDevice: "
					"Crate filter device failed.\r\n"));
				continue;
			}

			//Set flags same as device is attached
			if (FlagOn(pFSControlDeviceObject->Flags, DO_BUFFERED_IO))
			{
				SetFlag(pFilterDeviceObject->Flags, DO_BUFFERED_IO);
			}

			if (FlagOn(pFSControlDeviceObject->Flags, DO_DIRECT_IO))
			{
				SetFlag(pFilterDeviceObject->Flags, DO_DIRECT_IO);
			}

			if (FlagOn(pFSControlDeviceObject->Characteristics,FILE_DEVICE_SECURE_OPEN))
			{
				SetFlag(pFilterDeviceObject->Characteristics,FILE_DEVICE_SECURE_OPEN);
			}

			//Get device extension of filter device
			PDEVICE_EXTENSION pFilterDeviceExtension = (PDEVICE_EXTENSION)pFilterDeviceObject->DeviceExtension;

			//Get real device
			status = IoGetDiskDeviceObject(apstDeviceObjectList[i], &pFilterDeviceExtension->pstStorageDeviceObject);

			if (!NT_SUCCESS(status)) 
			{
				KdPrint(("FileSystemFilter!"
					"FSAttachToMountedVolumeDevice: "
					"Get real device failed.\r\n"));
				IoDeleteDevice(pFilterDeviceObject);
				continue;
			}

			//Get name of volume device
			PUNICODE_STRING pVolumeDeviceName = NULL;
			status = FSGetObjectName(apstDeviceObjectList[i], &pVolumeDeviceName);

			if (!NT_SUCCESS(status)) 
			{
				KdPrint(("FileSystemFilter!"
					"FSAttachToMountedVolumeDevice: "
					"Get name of volume deivce failed.\r\n"));
			}

			//Attach filter device to mounted volume device
			ASSERT(NULL != pVolumeDeviceName);
			ASSERT(NULL != pFilterDeviceExtension);

			status = IoAttachDeviceToDeviceStackSafe(pFilterDeviceObject, apstDeviceObjectList[i], &pFilterDeviceExtension->pstNextDeviceObject);

			if (!NT_SUCCESS(status)) 
			{
				KdPrint(("FileSystemFilter!"
					"FSAttachToMountedVolumeDevice: "
					"Attach to %wZ failed.\r\n",
					pVolumeDeviceName));
			}

			//Save the name of volume device
			RtlCopyUnicodeString(&pFilterDeviceExtension->ustrDeviceName, pVolumeDeviceName);

			//Free the resource of device name
			if (NULL != pVolumeDeviceName) 
			{
				POBJECT_NAME_INFORMATION pObjectNameInfo = CONTAINING_RECORD(pVolumeDeviceName, OBJECT_NAME_INFORMATION, Name);
				ExFreePoolWithTag(pObjectNameInfo, OBJECT_NAME_TAG);
				pObjectNameInfo = NULL;
			}

			//Set initialization has finished
			ClearFlag(pFilterDeviceObject->Flags, DO_DEVICE_INITIALIZING);
		}

		//Release lock
		ExReleaseFastMutex(&g_stAttachLock);

		return STATUS_SUCCESS;
	} while (FALSE);

	return status;
}

/**************************************************
@author		  : Sunr
@create time  : 20200730
@last   time  : 20200730
@description  : Get the file system driver's object name,directly return if it's a recognizer.Then , create filter device object and attach.Record the name of device is attached.
**************************************************/
#pragma PAGEDCODE
NTSTATUS FSAttachToFileSystemControlDevice(IN PDEVICE_OBJECT pDeviceObject, IN PUNICODE_STRING pDeviceObjectName)
{
	PAGED_CODE();

	if (!IS_TARGET_DEVICE_TYPE(pDeviceObject->DeviceType)) 
	{
		return STATUS_SUCCESS;
	}

	PDEVICE_OBJECT pFilterDeviceObject = NULL;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PUNICODE_STRING pustrDriverObjectName = NULL;
	UNICODE_STRING ustrFSRecName;

	do
	{
		status = FSGetObjectName(pDeviceObject->DriverObject, &pustrDriverObjectName);

		if (!NT_SUCCESS(status)) 
		{
			break;
		}
		RtlInitUnicodeString(&ustrFSRecName, FILE_SYSTEM_REC_NAME);

		if (RtlCompareUnicodeString(pustrDriverObjectName, &ustrFSRecName, TRUE) == 0) 
		{
			return STATUS_SUCCESS;
		}

		//Create filter device for control device of file system
		status = IoCreateDevice(g_pstDriverObject, sizeof(DEVICE_EXTENSION), NULL, pDeviceObject->DeviceType, 0, FALSE, &pFilterDeviceObject);
		if (!NT_SUCCESS(status)) 
		{
			KdPrint(("FileSystemFilter!FSAttachFileSystemControlDevice: "
				"Create filter device object filed.\r\n"));
			break;
		}

		//Set flags same as device is attached
		if (FlagOn(pDeviceObject->Flags, DO_BUFFERED_IO)) 
		{
			SetFlag(pFilterDeviceObject->Flags, DO_BUFFERED_IO);
		}
		if (FlagOn(pDeviceObject->Flags, DO_DIRECT_IO)) 
		{
			SetFlag(pFilterDeviceObject->Flags, DO_DIRECT_IO);
		}
		if (FlagOn(pDeviceObject->Characteristics, FILE_DEVICE_SECURE_OPEN)) 
		{
			SetFlag(pFilterDeviceObject->Characteristics, FILE_DEVICE_SECURE_OPEN);
		}

		PDEVICE_EXTENSION pDeviceExtension = (PDEVICE_EXTENSION)pFilterDeviceObject->DeviceExtension;
		if ( NULL == pDeviceExtension) 
		{
			KdPrint(("FileSystemFilter!FSAttachFileSystemControlDevice: "
				"The device extension's address is invalid.\r\n"));
			status = STATUS_INVALID_ADDRESS;
			break;
		}

		status = IoAttachDeviceToDeviceStackSafe(pFilterDeviceObject, pDeviceObject, &pDeviceExtension->pstNextDeviceObject);

		if (!NT_SUCCESS(status)) 
		{
			KdPrint(("FileSystemFilter!FSAttachFileSystemControlDevice: "
				"Attach device failed.\r\n"));
			break;
		}

		//Record  name of device is attached
		RtlInitEmptyUnicodeString(&pDeviceExtension->ustrDeviceName, pDeviceExtension->awcDeviceObjectBuffer, sizeof(pDeviceExtension->awcDeviceObjectBuffer));
		RtlCopyUnicodeString(&pDeviceExtension->ustrDeviceName, pDeviceObjectName);


		//Set the device initialized finished
		ClearFlag(pFilterDeviceObject->Flags, DO_DEVICE_INITIALIZING);

		status = FSAttachToMountedVolumeDevice(pDeviceObject);
		if (!NT_SUCCESS(status)) 
		{
			KdPrint(("FileSystemFilter!FSAttachFileSystemControlDevice: "
				"Attach volume device failed.\r\n"));
		}
		status = STATUS_SUCCESS;
	} while (FALSE);

	if ( NULL != pustrDriverObjectName) {
		POBJECT_NAME_INFORMATION pObjectNameInfo = CONTAINING_RECORD(pustrDriverObjectName, OBJECT_NAME_INFORMATION, Name);
		ExFreePoolWithTag(pObjectNameInfo, OBJECT_NAME_TAG);
		pObjectNameInfo = NULL;
	}
	return status;
}

/**************************************************
@author		  : Sunr
@create time  : 20200730
@last   time  : 20200730
@description  : Traversing all attached device to find our filter device,detach and delete it.
**************************************************/
#pragma PAGEDCODE
NTSTATUS FSDetachFromFileSystemControlDevice(IN PDEVICE_OBJECT pDeviceObject)
{
	if (!ARGUMENT_PRESENT(pDeviceObject)) 
	{
		KdPrint(("FilterSystemFilter!FSDetachFromFileSystemControlDevice: "
				"The file system device object is invalid.\r\n"));
		return STATUS_INVALID_PARAMETER;
	}

	PAGED_CODE();

	PDEVICE_OBJECT pAttachedDeviceObject = NULL;
	PDEVICE_EXTENSION pDeviceExtension = NULL;

	pAttachedDeviceObject = IoGetAttachedDeviceReference(pDeviceObject);
	while (pDeviceObject != pAttachedDeviceObject) 
	{
		if (IS_MY_DEVICE_OBJECT(pAttachedDeviceObject)) 
		{
			KdPrint(("Detach control deivce filter of %wZ",
				&pDeviceExtension->ustrDeviceName));

			IoDetachDevice(pDeviceObject);
			IoDeleteDevice(pAttachedDeviceObject);
		}

		pDeviceObject = pAttachedDeviceObject;
		pAttachedDeviceObject = IoGetAttachedDeviceReference(pDeviceObject);
		ObDereferenceObject(pDeviceObject);
	}
	return STATUS_SUCCESS;
}


