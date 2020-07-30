#include"entry.h"

#pragma PAGEDCODE
NTSTATUS FSIrpDefault(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp)
{
	PAGED_CODE();
	ASSERT(!IS_MY_CONTROL_DEVICE_OBJECT(pDeviceObject));
	ASSERT(IS_MY_DEVICE_OBJECT(pDeviceObject));


	PDEVICE_EXTENSION pDeviceExtension = (PDEVICE_EXTENSION)pDeviceObject->DeviceExtension;

	IoSkipCurrentIrpStackLocation(pIrp);

	return IoCallDriver(pDeviceExtension->pstNextDeviceObject, pIrp);
}



//do some check, then set complete routine and print size of data block when read successful. 
#pragma PAGEDCODE
NTSTATUS FSIrpRead(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp)
{
	PAGED_CODE();
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	if (IS_MY_CONTROL_DEVICE_OBJECT(pDeviceObject)) {
		pIrp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
		pIrp->IoStatus.Information = 0;
		IoCompleteRequest(pIrp, IO_NO_INCREMENT);
		return STATUS_INVALID_DEVICE_REQUEST;
	}

	PDEVICE_EXTENSION pDeviceExtension = (PDEVICE_EXTENSION)pDeviceObject->DeviceExtension;

	//check  it's a volume device or not
	if (NULL == pDeviceExtension->pstStorageDeviceObject) {
		return FSIrpDefault(pDeviceObject, pIrp);
	}

	PIO_STACK_LOCATION pStackLocation = IoGetCurrentIrpStackLocation(pIrp);
	LARGE_INTEGER stOffset = { 0 };
	ULONG ulLength = 0;

	//get offset and length
	stOffset.QuadPart = pStackLocation->Parameters.Read.ByteOffset.QuadPart;
	ulLength = pStackLocation->Parameters.Read.Length;

	//set complete routine and wait event complete
	KEVENT waitEvent;
	KeInitializeEvent(&waitEvent, NotificationEvent, FALSE);

	IoCopyCurrentIrpStackLocationToNext(pIrp);
	IoSetCompletionRoutine(pIrp, FSReadComplete, &waitEvent, TRUE, TRUE, TRUE);

	status = IoCallDriver(pDeviceExtension->pstNextDeviceObject, pIrp);

	if (STATUS_PENDING == status) {
		status = KeWaitForSingleObject(&waitEvent, Executive, KernelMode, FALSE, NULL);
		ASSERT(STATUS_SUCCESS == status);
	}

	if (NT_SUCCESS(pIrp->IoStatus.Status)) {
		PVOID pBuffer = NULL;
		if (NULL != pIrp->MdlAddress) {
			pBuffer = MmGetSystemAddressForMdlSafe(pIrp->MdlAddress, NormalPagePriority);
		}
		else {
			pBuffer = pIrp->UserBuffer;
		}

		if (NULL != pBuffer) {
			ulLength = pIrp->IoStatus.Information;

			KdPrint(("Read irp: the size is %ul \r\n", ulLength));
		}
	}

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return pIrp->IoStatus.Information;
}


#pragma PAGEDCODE
NTSTATUS FSIrpWrite(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp)
{
	PAGED_CODE();
	if (IS_MY_DEVICE_OBJECT(pDeviceObject)) {
		pIrp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
		pIrp->IoStatus.Information = 0;
		IoCompleteRequest(pIrp, IO_NO_INCREMENT);
		return STATUS_INVALID_DEVICE_REQUEST;
	}

	PDEVICE_EXTENSION pDeviceExtension = (PDEVICE_EXTENSION)pDeviceObject->DeviceExtension;

	//check  it's a volume device or not
	if (NULL == pDeviceExtension->pstStorageDeviceObject) {
		return FSIrpDefault(pDeviceObject, pIrp);
	}

	PIO_STACK_LOCATION pStackLocation = IoGetCurrentIrpStackLocation(pIrp);
	//LARGE_INTEGER stOffset = { 0 };
	ULONG ulLength = 0;

	//get offset and length
	ulLength = pStackLocation->Parameters.Write.Length;
	PVOID pBuffer = NULL;

	
	if (NULL != pIrp->MdlAddress) {
		pBuffer = MmGetSystemAddressForMdlSafe(pIrp->MdlAddress, NormalPagePriority);
	}
	else {
		pBuffer = pIrp->UserBuffer;
	}

	if (NULL != pBuffer) {
		KdPrint(("Wirte irp: The request size is %u\r\n",
			pStackLocation->Parameters.Write.Length));
	}

	IoSkipCurrentIrpStackLocation(pIrp);
	return IoCallDriver(pDeviceExtension->pstNextDeviceObject, pIrp);
}

//call routine to deal with target minor irp,other irp will pass through to next device.
#pragma PAGEDCODE
NTSTATUS FSIrpFileSystemControl(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp)
{
	PAGED_CODE();
	ASSERT(!IS_MY_CONTROL_DEVICE_OBJECT(pDeviceObject));
	ASSERT(IS_MY_DEVICE_OBJECT(pDeviceObject));

	PIO_STACK_LOCATION pStackLocation = IoGetCurrentIrpStackLocation(pIrp);
	PDEVICE_EXTENSION pDeviceExtension = (PDEVICE_EXTENSION)pDeviceObject->DeviceExtension;

	//deal with minior irp
	switch (pStackLocation->MinorFunction) {
	case IRP_MN_MOUNT_VOLUME: {
		return FSMinorIrpMountVolume(pDeviceObject, pIrp);
	}
	case IRP_MN_LOAD_FILE_SYSTEM: {
		return FSMinorIrpLoadFileSystem(pDeviceObject, pIrp);
	}
	case IRP_MN_USER_FS_REQUEST: {
		switch (pStackLocation->Parameters.FileSystemControl.FsControlCode){
		case FSCTL_DISMOUNT_VOLUME: {
			KdPrint(("FileSystemFilter!FSIrpFileSystemControl: "
				"Dismounting volumn %wZ\r\n",
				&pDeviceExtension->ustrDeviceName));

			break;
		}
		}
		break;
	}
	default: {
		break;
	}
	}
	IoSkipCurrentIrpStackLocation(pIrp);
	return IoCallDriver(pDeviceExtension->pstNextDeviceObject, pIrp);
}

//create filter device object and wait the volume has mounted successful.Then executive the attached active in complete routine.
#pragma PAGEDCODE
NTSTATUS FSMinorIrpMountVolume(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp)
{
	PAGED_CODE();
	ASSERT(!IS_MY_CONTROL_DEVICE_OBJECT(pDeviceObject));
	ASSERT(IS_MY_DEVICE_OBJECT(pDeviceObject));
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	PIO_STACK_LOCATION pStackLocation = IoGetCurrentIrpStackLocation(pIrp);

	//create volume filter device
	PDEVICE_OBJECT pFilterDeviceObject = NULL;
	status = IoCreateDevice(g_pstDriverObject, sizeof(DEVICE_EXTENSION), NULL, pDeviceObject->DeviceType, 0, FALSE, &pFilterDeviceObject);

	if (!NT_SUCCESS(status)) {
		KdPrint(("FileSystemFilter!FSAttachFileSystemControlDevice: "
			"Create filter device object failed.\r\n"));

		pIrp->IoStatus.Information = 0;
		pIrp->IoStatus.Status = status;
		IoCompleteRequest(pIrp, IO_NO_INCREMENT);
		return status;
	}

	//save storage device object
	PDEVICE_EXTENSION pDeviceExtension = (PDEVICE_EXTENSION)pFilterDeviceObject->DeviceExtension;

	//get real device of storage
	KIRQL currentIRQL;
	IoAcquireVpbSpinLock(&currentIRQL);
	pDeviceExtension->pstStorageDeviceObject = pStackLocation->Parameters.MountVolume.Vpb->RealDevice;
	IoReleaseVpbSpinLock(currentIRQL);

	//get and save  storage device name
	RtlInitEmptyUnicodeString(&pDeviceExtension->ustrDeviceName, pDeviceExtension->awcDeviceObjectBuffer, sizeof(pDeviceExtension->awcDeviceObjectBuffer));

	PUNICODE_STRING pStorageDeviceName = NULL;
	FSGetObjectName(pDeviceExtension->pstStorageDeviceObject, &pStorageDeviceName);

	if (NULL != pStorageDeviceName) {
		RtlCopyUnicodeString(&pDeviceExtension->ustrDeviceName, pStorageDeviceName);

		ExFreePool(pStorageDeviceName);
		pStorageDeviceName = NULL;
	}

	//set completion routine and wait
	KEVENT waitEvent;
	KeInitializeEvent(&waitEvent, NotificationEvent, FALSE);

	IoCopyCurrentIrpStackLocationToNext(pIrp);
	IoSetCompletionRoutine(pIrp, FSMountDeviceComplete, &waitEvent, TRUE, TRUE, TRUE);
	status = IoCallDriver(pDeviceExtension->pstNextDeviceObject, pIrp);

	if (STATUS_PENDING == status) {
		status = KeWaitForSingleObject(&waitEvent, Executive, KernelMode, FALSE, NULL);
		ASSERT(STATUS_SUCCESS == status);
	}

	//attach the filter device to target device
	status = FSAttachMountedVolume(pFilterDeviceObject, pDeviceObject, pIrp);

	status = pIrp->IoStatus.Status;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return status;
}

//get volume device object, check it has attached or not.Delete the filter device if it has attached, or begin to attach.
#pragma PAGEDCODE
NTSTATUS FSAttachMountedVolume(IN PDEVICE_OBJECT pFilterDeviceObject, IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp)
{
	PAGED_CODE();
	ASSERT(IS_MY_DEVICE_OBJECT(pFilterDeviceObject));

	NTSTATUS status = STATUS_UNSUCCESSFUL;

	//get lock
	ExAcquireFastMutex(&g_stAttachLock);

	do
	{
		//check the volume install successful or not
		if (!NT_SUCCESS(pIrp->IoStatus.Status)) {
			IoDeleteDevice(pFilterDeviceObject);
			break;
		}

		//check the volume has attached or not
		if (FSIsAttachedDevice(pDeviceObject)) {
			IoDeleteDevice(pFilterDeviceObject);
			break;
		}


		//set flag and characteristic
		{
			SetFlag(pFilterDeviceObject->Flags, DO_BUFFERED_IO);
		}

		if (FlagOn(pDeviceObject->Flags, DO_DIRECT_IO))
		{
			SetFlag(pFilterDeviceObject->Flags, DO_DIRECT_IO);
		}

		if (FlagOn(pDeviceObject->Characteristics, FILE_DEVICE_SECURE_OPEN))
		{
			SetFlag(pFilterDeviceObject->Characteristics,
				FILE_DEVICE_SECURE_OPEN);
		}
		
		PDEVICE_EXTENSION pDeviceExtension = (PDEVICE_EXTENSION)pFilterDeviceObject->DeviceExtension;

		KIRQL currentIRQL;
		IoAcquireVpbSpinLock(&currentIRQL);
		PDEVICE_OBJECT pVolumeDeviceObject = pDeviceExtension->pstStorageDeviceObject->Vpb->DeviceObject;
		IoReleaseVpbSpinLock(currentIRQL);

		//try to attach the volume device.The binding may fail because other users happen to be trying to do something special with the disk, such as mount or unmount it.Try again and again to avoid these coincidences as much as possible
		for (ULONG i = 0; i < ATTACH_VOLUME_DEVICE_TRY_NUM; i++)
		{
			status = IoAttachDeviceToDeviceStackSafe(
				pFilterDeviceObject,
				pVolumeDeviceObject,
				&pDeviceExtension->pstNextDeviceObject
			);
			if (NT_SUCCESS(status))
			{
				ClearFlag(pFilterDeviceObject->Flags, DO_DEVICE_INITIALIZING);
				KdPrint(("FileSystemFilter!FSAttachMountedVolume: "
					"%wZ has attached successful.\r\n",
					&pDeviceExtension->ustrDeviceName));
				break;
			}

			LARGE_INTEGER stInterval;
			stInterval.QuadPart = (500 * DELAY_ONE_MILLISECOND);
			KeDelayExecutionThread(KernelMode, FALSE, &stInterval);
		} 
	} while (FALSE);

	//release lock
	ExReleaseFastMutex(&g_stAttachLock);

	return status;
}


//detach the filter of file system recognizer,then delete the filter device.Reattach the filter device if load file system failed.
#pragma PAGEDCODE
NTSTATUS FSMinorIrpLoadFileSystem(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp)
{
	PAGED_CODE();
	ASSERT(IS_MY_DEVICE_OBJECT(pDeviceObject));

	NTSTATUS status = STATUS_SUCCESS;
	PDEVICE_EXTENSION pDeviceExtension = (PDEVICE_EXTENSION)pDeviceObject->DeviceExtension;

	//detach filter device from recognizer device.
	IoDetachDevice(pDeviceExtension->pstNextDeviceObject);

	KEVENT waitEvent;
	KeInitializeEvent(&waitEvent, NotificationEvent, FALSE);

	// Set completion routine.
	IoSetCompletionRoutine(pIrp,
		FSLoadFileSystemComplete,
		&waitEvent,
		TRUE,
		TRUE,
		TRUE);

	IoCopyCurrentIrpStackLocationToNext(pIrp);
	status = IoCallDriver(pDeviceExtension->pstNextDeviceObject, pIrp);

	if (STATUS_PENDING == status) {
		status = KeWaitForSingleObject(&waitEvent, Executive, KernelMode, FALSE, NULL);
		ASSERT(NT_SUCCESS(status));
	}

	if (!NT_SUCCESS(pIrp->IoStatus.Status) && STATUS_IMAGE_ALREADY_LOADED != pIrp->IoStatus.Status){
		//reattach to recongizer
		status = IoAttachDeviceToDeviceStackSafe(pDeviceObject, pDeviceExtension->pstNextDeviceObject, &pDeviceExtension->pstNextDeviceObject);
		ASSERT(NT_SUCCESS(status));

	}
	else {
		IoDeleteDevice(pDeviceObject);
	}

	status = pIrp->IoStatus.Status;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return status;
}