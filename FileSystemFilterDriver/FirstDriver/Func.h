#pragma once
//#include<ntifs.h>

NTSTATUS FSCreateDevice(PDRIVER_OBJECT pDriverObject);
VOID DriverUnload(IN PDRIVER_OBJECT pDriverObject);

NTSTATUS FSIrpDefault(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);
NTSTATUS FSGetObjectName(IN PVOID pObject, IN OUT PUNICODE_STRING *pName);
VOID FSChangeNotify(IN PDEVICE_OBJECT pDeviceObject, IN BOOLEAN FSActive);
NTSTATUS FSAttachToFileSystemControlDevice(IN PDEVICE_OBJECT pDeviceObject, IN PUNICODE_STRING pDeviceObjectName);
NTSTATUS FSDetachFromFileSystemControlDevice(IN PDEVICE_OBJECT pDeviceObject);
BOOLEAN FSIsAttachedDevice(IN PDEVICE_OBJECT pDeviceObject);
NTSTATUS FSAttachToMountedVolumeDevice(IN PDEVICE_OBJECT pFSControlDeviceObject);
NTSTATUS FSAttachMountedVolume(IN PDEVICE_OBJECT pFilterDeviceObject, IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);

NTSTATUS FSMinorIrpLoadFileSystem(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);
NTSTATUS FSMinorIrpMountVolume(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);




NTSTATUS FSIrpFileSystemControl(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);
NTSTATUS FSIrpRead(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);
NTSTATUS FSIrpWrite(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);
NTSTATUS FSReadComplete(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp, IN PVOID pContext);
NTSTATUS FSMountDeviceComplete(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp, IN PVOID pContext);
NTSTATUS FSLoadFileSystemComplete(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp, IN PVOID pContext);



BOOLEAN FSFastIoCheckIfPossible(IN PFILE_OBJECT pFileObject,
	IN PLARGE_INTEGER pFileOffset,
	IN ULONG ulLength,
	IN BOOLEAN bWait,
	IN ULONG ulLockKey,
	IN BOOLEAN bCheckForReadOperation,
	OUT PIO_STATUS_BLOCK pIoStatus,
	IN PDEVICE_OBJECT pDeviceObject);

BOOLEAN FSFastIoRead(IN PFILE_OBJECT pFileObject,
	IN PLARGE_INTEGER pFileOffset,
	IN ULONG ulLength,
	IN BOOLEAN bWait,
	IN ULONG ulLockKey,
	OUT PVOID pBuffer,
	OUT PIO_STATUS_BLOCK pIoStatus,
	IN PDEVICE_OBJECT pDeviceObject);

BOOLEAN FSFastIoWrite(IN PFILE_OBJECT pFileObject,
	IN PLARGE_INTEGER pFileOffset,
	IN ULONG ulLength,
	IN BOOLEAN bWait,
	IN ULONG ulLockKey,
	OUT PVOID pBuffer,
	OUT PIO_STATUS_BLOCK pIoStatus,
	IN PDEVICE_OBJECT pDeviceObject);

BOOLEAN FSFastIoQueryBasicInfo(IN PFILE_OBJECT FileObject,
	IN BOOLEAN Wait,
	OUT PFILE_BASIC_INFORMATION Buffer,
	OUT PIO_STATUS_BLOCK IoStatus,
	IN PDEVICE_OBJECT DeviceObject);

BOOLEAN FSFastIoQueryStandardInfo(
	IN PFILE_OBJECT pFileObject,
	IN BOOLEAN bWait,
	OUT PFILE_STANDARD_INFORMATION pBuffer,
	OUT PIO_STATUS_BLOCK pIoStatus,
	IN PDEVICE_OBJECT pDeviceObject
);

BOOLEAN FSFastIoQueryOpen(
	IN PIRP pIrp,
	OUT PFILE_NETWORK_OPEN_INFORMATION pNetworkInformation,
	IN PDEVICE_OBJECT pDeviceObject
);

BOOLEAN FSFastIoQueryNetworkOpenInfo(
	IN PFILE_OBJECT pFileObject,
	IN BOOLEAN bWait,
	OUT PFILE_NETWORK_OPEN_INFORMATION pBuffer,
	OUT PIO_STATUS_BLOCK pIoStatus,
	IN PDEVICE_OBJECT pDeviceObject
);

BOOLEAN FSFastIoLock(IN PFILE_OBJECT pFileObject,
	IN PLARGE_INTEGER pFileOffset,
	IN PLARGE_INTEGER pLength,
	IN PEPROCESS pProcessId,
	IN ULONG ulKey,
	IN BOOLEAN bFailImmediately,
	IN BOOLEAN bExclusiveLock,
	OUT PIO_STATUS_BLOCK pIoStatus,
	IN PDEVICE_OBJECT pDeviceObject);

BOOLEAN FSFastIoUnlockAll(IN PFILE_OBJECT pFileObject,
	IN PEPROCESS pProcessId,
	OUT PIO_STATUS_BLOCK pIoStatus,
	IN PDEVICE_OBJECT pDeviceObject
);

BOOLEAN FSFastIoUnlockSingle(IN PFILE_OBJECT pFileObject,
	IN PLARGE_INTEGER pFileOffset,
	IN PLARGE_INTEGER pLength,
	IN PEPROCESS pProcessId,
	IN ULONG ulKey,
	OUT PIO_STATUS_BLOCK pIoStatus,
	IN PDEVICE_OBJECT pDeviceObject);

BOOLEAN FSFastIoUnlockAllByKey(IN PFILE_OBJECT pFileObject,
	IN PVOID pProcessId,
	IN ULONG pKey,
	OUT PIO_STATUS_BLOCK pIoStatus,
	IN PDEVICE_OBJECT pDeviceObject);

BOOLEAN FSFastIoDeviceControl(IN PFILE_OBJECT pFileObject,
	IN BOOLEAN bWait,
	IN PVOID pInputBuffer OPTIONAL,
	IN ULONG ulInputBufferLength,
	OUT PVOID pOutputBuffer OPTIONAL,
	IN ULONG ulOutputBufferLength,
	IN ULONG ulIoControlCode,
	OUT PIO_STATUS_BLOCK pIoStatus,
	IN PDEVICE_OBJECT pDeviceObject);

VOID FSFastIoDetachDevice(IN PDEVICE_OBJECT pSourceDevice,
	IN PDEVICE_OBJECT pTargetDevice);

BOOLEAN FSFastIoMdlRead(IN PFILE_OBJECT pFileObject,
	IN PLARGE_INTEGER pFileOffset,
	IN ULONG ulLength,
	IN ULONG ulLockKey,
	OUT PMDL *ppMdlChain,
	OUT PIO_STATUS_BLOCK pIoStatus,
	IN PDEVICE_OBJECT pDeviceObject);

BOOLEAN FSFastIoMdlReadComplete(IN PFILE_OBJECT pFileObject,
	IN PMDL pMdlChain,
	IN PDEVICE_OBJECT pDeviceObject);

BOOLEAN FSFastIoMdlReadCompleteCompressed(
	IN PFILE_OBJECT pFileObject,
	IN PMDL pMdlChain,
	IN PDEVICE_OBJECT pDeviceObject
);

BOOLEAN FSFastIoPrepareMdlWrite(IN PFILE_OBJECT pFileObject,
	IN PLARGE_INTEGER pFileOffset,
	IN ULONG ulLength,
	IN ULONG ulLockKey,
	OUT PMDL *pMdlChain,
	OUT PIO_STATUS_BLOCK pIoStatus,
	IN PDEVICE_OBJECT pDeviceObject);

BOOLEAN FSFastIoMdlWriteComplete(IN PFILE_OBJECT pFileObject,
	IN PLARGE_INTEGER pFileOffset,
	IN PMDL pMdlChain,
	IN PDEVICE_OBJECT pDeviceObject);

BOOLEAN FSFastIoMdlWriteCompleteCompressed(
	IN PFILE_OBJECT pFileObject,
	IN PLARGE_INTEGER pFileOffset,
	IN PMDL pMdlChain,
	IN PDEVICE_OBJECT pDeviceObject
);

BOOLEAN FSFastIoReadCompressed(
	IN PFILE_OBJECT pFileObject,
	IN PLARGE_INTEGER pFileOffset,
	IN ULONG ulLength,
	IN ULONG ulLockKey,
	OUT PVOID pBuffer,
	OUT PMDL *pMdlChain,
	OUT PIO_STATUS_BLOCK pIoStatus,
	OUT COMPRESSED_DATA_INFO *pCompressedDataInfo,
	IN ULONG ulCompressedDataInfoLength,
	IN PDEVICE_OBJECT pDeviceObject
);

BOOLEAN FSFastIoWriteCompressed(
	IN PFILE_OBJECT pFileObject,
	IN PLARGE_INTEGER pFileOffset,
	IN ULONG ulLength,
	IN ULONG ulLockKey,
	IN PVOID pBuffer,
	OUT PMDL *pMdlChain,
	OUT PIO_STATUS_BLOCK pIoStatus,
	IN COMPRESSED_DATA_INFO *pCompressedDataInfo,
	IN ULONG ulCompressedDataInfoLength,
	IN PDEVICE_OBJECT pDeviceObject
);