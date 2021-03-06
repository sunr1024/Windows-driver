#include"entry.h"
/**************************************************
@author		  : Sunr
@create time  : 20200730
@last   time  : 20200730
@description  : Noting to do..
**************************************************/
BOOLEAN FSFastIoCheckIfPossible(IN PFILE_OBJECT pFileObject,
	IN PLARGE_INTEGER pFileOffset,
	IN ULONG ulLength,
	IN BOOLEAN bWait,
	IN ULONG ulLockKey,
	IN BOOLEAN bCheckForReadOperation,
	OUT PIO_STATUS_BLOCK pstIoStatus,
	IN PDEVICE_OBJECT pstDeviceObject)
{
	UNREFERENCED_PARAMETER(pFileObject);
	UNREFERENCED_PARAMETER(pFileOffset);
	UNREFERENCED_PARAMETER(ulLength);
	UNREFERENCED_PARAMETER(bWait);
	UNREFERENCED_PARAMETER(ulLockKey);
	UNREFERENCED_PARAMETER(bCheckForReadOperation);
	UNREFERENCED_PARAMETER(pstIoStatus);
	UNREFERENCED_PARAMETER(pstDeviceObject);

	return FALSE;
}


/**************************************************
@author		  : Sunr
@create time  : 20200730
@last   time  : 20200730
@description  : Noting to do..
**************************************************/
#pragma PAGEDCODE
BOOLEAN FSFastIoRead(IN PFILE_OBJECT pFileObject,
	IN PLARGE_INTEGER pFileOffset,
	IN ULONG ulLength,
	IN BOOLEAN bWait,
	IN ULONG ulLockKey,
	OUT PVOID pBuffer,
	OUT PIO_STATUS_BLOCK pIoStatus,
	IN PDEVICE_OBJECT pDeviceObject)
{
	UNREFERENCED_PARAMETER(pFileObject);
	UNREFERENCED_PARAMETER(pFileOffset);
	UNREFERENCED_PARAMETER(ulLength);
	UNREFERENCED_PARAMETER(bWait);
	UNREFERENCED_PARAMETER(ulLockKey);
	UNREFERENCED_PARAMETER(pBuffer);
	UNREFERENCED_PARAMETER(pIoStatus);
	UNREFERENCED_PARAMETER(pDeviceObject);

	return FALSE;
} 


/**************************************************
@author		  : Sunr
@create time  : 20200730
@last   time  : 20200730
@description  : Noting to do..
**************************************************/
#pragma PAGEDCODE
BOOLEAN FSFastIoWrite(IN PFILE_OBJECT pFileObject,
	IN PLARGE_INTEGER pFileOffset,
	IN ULONG ulLength,
	IN BOOLEAN bWait,
	IN ULONG ulLockKey,
	OUT PVOID pBuffer,
	OUT PIO_STATUS_BLOCK pIoStatus,
	IN PDEVICE_OBJECT pDeviceObject)
{
	UNREFERENCED_PARAMETER(pFileObject);
	UNREFERENCED_PARAMETER(pFileOffset);
	UNREFERENCED_PARAMETER(ulLength);
	UNREFERENCED_PARAMETER(bWait);
	UNREFERENCED_PARAMETER(ulLockKey);
	UNREFERENCED_PARAMETER(pBuffer);
	UNREFERENCED_PARAMETER(pIoStatus);
	UNREFERENCED_PARAMETER(pDeviceObject);

	return FALSE;
}


/**************************************************
@author		  : Sunr
@create time  : 20200730
@last   time  : 20200730
@description  : Noting to do..
**************************************************/
#pragma PAGEDCODE
BOOLEAN FSFastIoQueryBasicInfo(IN PFILE_OBJECT FileObject,
	IN BOOLEAN Wait,
	OUT PFILE_BASIC_INFORMATION Buffer,
	OUT PIO_STATUS_BLOCK IoStatus,
	IN PDEVICE_OBJECT DeviceObject)
{
	UNREFERENCED_PARAMETER(FileObject);
	UNREFERENCED_PARAMETER(Wait);
	UNREFERENCED_PARAMETER(Buffer);
	UNREFERENCED_PARAMETER(IoStatus);
	UNREFERENCED_PARAMETER(DeviceObject);

	return FALSE;
} 



/**************************************************
@author		  : Sunr
@create time  : 20200730
@last   time  : 20200730
@description  : Noting to do..
**************************************************/
#pragma PAGEDCODE
BOOLEAN FSFastIoQueryStandardInfo(
	IN PFILE_OBJECT pFileObject,
	IN BOOLEAN bWait,
	OUT PFILE_STANDARD_INFORMATION pBuffer,
	OUT PIO_STATUS_BLOCK pIoStatus,
	IN PDEVICE_OBJECT pDeviceObject
)
{
	UNREFERENCED_PARAMETER(pFileObject);
	UNREFERENCED_PARAMETER(bWait);
	UNREFERENCED_PARAMETER(pBuffer);
	UNREFERENCED_PARAMETER(pIoStatus);
	UNREFERENCED_PARAMETER(pDeviceObject);

	return FALSE;
} 



/**************************************************
@author		  : Sunr
@create time  : 20200730
@last   time  : 20200730
@description  : Noting to do..
**************************************************/
#pragma PAGEDCODE
BOOLEAN FSFastIoQueryOpen(
	IN PIRP pIrp,
	OUT PFILE_NETWORK_OPEN_INFORMATION pNetworkInformation,
	IN PDEVICE_OBJECT pDeviceObject
)
{
	UNREFERENCED_PARAMETER(pIrp);
	UNREFERENCED_PARAMETER(pNetworkInformation);
	UNREFERENCED_PARAMETER(pDeviceObject);

	return FALSE;
}




/**************************************************
@author		  : Sunr
@create time  : 20200730
@last   time  : 20200730
@description  : Noting to do..
**************************************************/
#pragma PAGEDCODE
BOOLEAN FSFastIoQueryNetworkOpenInfo(
	IN PFILE_OBJECT pFileObject,
	IN BOOLEAN bWait,
	OUT PFILE_NETWORK_OPEN_INFORMATION pBuffer,
	OUT PIO_STATUS_BLOCK pIoStatus,
	IN PDEVICE_OBJECT pDeviceObject
)
{
	UNREFERENCED_PARAMETER(pFileObject);
	UNREFERENCED_PARAMETER(bWait);
	UNREFERENCED_PARAMETER(pBuffer);
	UNREFERENCED_PARAMETER(pIoStatus);
	UNREFERENCED_PARAMETER(pDeviceObject);

	return FALSE;
}




/**************************************************
@author		  : Sunr
@create time  : 20200730
@last   time  : 20200730
@description  : Noting to do..
**************************************************/
#pragma PAGEDCODE
BOOLEAN FSFastIoLock(IN PFILE_OBJECT pFileObject,
	IN PLARGE_INTEGER pFileOffset,
	IN PLARGE_INTEGER pLength,
	IN PEPROCESS pProcessId,
	IN ULONG ulKey,
	IN BOOLEAN bFailImmediately,
	IN BOOLEAN bExclusiveLock,
	OUT PIO_STATUS_BLOCK pIoStatus,
	IN PDEVICE_OBJECT pDeviceObject)
{
	UNREFERENCED_PARAMETER(pFileObject);
	UNREFERENCED_PARAMETER(pFileOffset);
	UNREFERENCED_PARAMETER(pLength);
	UNREFERENCED_PARAMETER(pProcessId);
	UNREFERENCED_PARAMETER(ulKey);
	UNREFERENCED_PARAMETER(bFailImmediately);
	UNREFERENCED_PARAMETER(bExclusiveLock);
	UNREFERENCED_PARAMETER(pIoStatus);
	UNREFERENCED_PARAMETER(pDeviceObject);

	return FALSE;
}




/**************************************************
@author		  : Sunr
@create time  : 20200730
@last   time  : 20200730
@description  : Noting to do..
**************************************************/
#pragma PAGEDCODE
BOOLEAN FSFastIoUnlockAll(IN PFILE_OBJECT pFileObject,
	IN PEPROCESS pProcessId,
	OUT PIO_STATUS_BLOCK pIoStatus,
	IN PDEVICE_OBJECT pDeviceObject)
{
	UNREFERENCED_PARAMETER(pFileObject);
	UNREFERENCED_PARAMETER(pProcessId);
	UNREFERENCED_PARAMETER(pIoStatus);
	UNREFERENCED_PARAMETER(pDeviceObject);

	return FALSE;
}





/**************************************************
@author		  : Sunr
@create time  : 20200730
@last   time  : 20200730
@description  : Noting to do..
**************************************************/
#pragma PAGEDCODE
BOOLEAN FSFastIoUnlockSingle(IN PFILE_OBJECT pFileObject,
	IN PLARGE_INTEGER pFileOffset,
	IN PLARGE_INTEGER pLength,
	IN PEPROCESS pProcessId,
	IN ULONG ulKey,
	OUT PIO_STATUS_BLOCK pIoStatus,
	IN PDEVICE_OBJECT pDeviceObject)
{
	UNREFERENCED_PARAMETER(pFileObject);
	UNREFERENCED_PARAMETER(pFileOffset);
	UNREFERENCED_PARAMETER(pLength);
	UNREFERENCED_PARAMETER(pProcessId);
	UNREFERENCED_PARAMETER(ulKey);
	UNREFERENCED_PARAMETER(pIoStatus);
	UNREFERENCED_PARAMETER(pDeviceObject);

	return FALSE;
}





/**************************************************
@author		  : Sunr
@create time  : 20200730
@last   time  : 20200730
@description  : Noting to do..
**************************************************/
#pragma PAGEDCODE
BOOLEAN FSFastIoUnlockAllByKey(IN PFILE_OBJECT pFileObject,
	IN PVOID pProcessId,
	IN ULONG pKey,
	OUT PIO_STATUS_BLOCK pIoStatus,
	IN PDEVICE_OBJECT pDeviceObject)
{
	UNREFERENCED_PARAMETER(pFileObject);
	UNREFERENCED_PARAMETER(pProcessId);
	UNREFERENCED_PARAMETER(pKey);
	UNREFERENCED_PARAMETER(pIoStatus);
	UNREFERENCED_PARAMETER(pDeviceObject);

	return FALSE;
} 




/**************************************************
@author		  : Sunr
@create time  : 20200730
@last   time  : 20200730
@description  : Noting to do..
**************************************************/
#pragma PAGEDCODE
BOOLEAN FSFastIoDeviceControl(IN PFILE_OBJECT pFileObject,
	IN BOOLEAN bWait,
	IN PVOID pInputBuffer OPTIONAL,
	IN ULONG ulInputBufferLength,
	OUT PVOID pOutputBuffer OPTIONAL,
	IN ULONG ulOutputBufferLength,
	IN ULONG ulIoControlCode,
	OUT PIO_STATUS_BLOCK pIoStatus,
	IN PDEVICE_OBJECT pDeviceObject)
{
	UNREFERENCED_PARAMETER(pFileObject);
	UNREFERENCED_PARAMETER(bWait);
	UNREFERENCED_PARAMETER(pInputBuffer);
	UNREFERENCED_PARAMETER(ulInputBufferLength);
	UNREFERENCED_PARAMETER(pOutputBuffer);
	UNREFERENCED_PARAMETER(ulOutputBufferLength);
	UNREFERENCED_PARAMETER(ulIoControlCode);
	UNREFERENCED_PARAMETER(pIoStatus);
	UNREFERENCED_PARAMETER(pDeviceObject);

	return FALSE;
}




/**************************************************
@author		  : Sunr
@create time  : 20200730
@last   time  : 20200730
@description  : Noting to do..
**************************************************/
#pragma PAGEDCODE
VOID FSFastIoDetachDevice(IN PDEVICE_OBJECT pSourceDevice,
	IN PDEVICE_OBJECT pTargetDevice)
{
	UNREFERENCED_PARAMETER(pSourceDevice);
	UNREFERENCED_PARAMETER(pTargetDevice);
} //! FSFastIoDetachDevice() END






/**************************************************
@author		  : Sunr
@create time  : 20200730
@last   time  : 20200730
@description  : Noting to do..
**************************************************/
#pragma PAGEDCODE
BOOLEAN FSFastIoMdlRead(IN PFILE_OBJECT pFileObject,
	IN PLARGE_INTEGER pFileOffset,
	IN ULONG ulLength,
	IN ULONG ulLockKey,
	OUT PMDL *ppMdlChain,
	OUT PIO_STATUS_BLOCK pIoStatus,
	IN PDEVICE_OBJECT pDeviceObject
)
{
	UNREFERENCED_PARAMETER(pFileObject);
	UNREFERENCED_PARAMETER(pFileOffset);
	UNREFERENCED_PARAMETER(ulLength);
	UNREFERENCED_PARAMETER(ulLockKey);
	UNREFERENCED_PARAMETER(ppMdlChain);
	UNREFERENCED_PARAMETER(pIoStatus);
	UNREFERENCED_PARAMETER(pDeviceObject);

	return FALSE;
} //! FSFastIoMdlRead() END




/**************************************************
@author		  : Sunr
@create time  : 20200730
@last   time  : 20200730
@description  : Noting to do..
**************************************************/
#pragma PAGEDCODE
BOOLEAN FSFastIoMdlReadComplete(IN PFILE_OBJECT pFileObject,
	IN PMDL pMdlChain,
	IN PDEVICE_OBJECT pDeviceObject)
{
	UNREFERENCED_PARAMETER(pFileObject);
	UNREFERENCED_PARAMETER(pMdlChain);
	UNREFERENCED_PARAMETER(pDeviceObject);

	return FALSE;
}





/**************************************************
@author		  : Sunr
@create time  : 20200730
@last   time  : 20200730
@description  : Noting to do..
**************************************************/
#pragma PAGEDCODE
BOOLEAN FSFastIoMdlReadCompleteCompressed(
	IN PFILE_OBJECT pFileObject,
	IN PMDL pMdlChain,
	IN PDEVICE_OBJECT pDeviceObject
)
{
	UNREFERENCED_PARAMETER(pFileObject);
	UNREFERENCED_PARAMETER(pMdlChain);
	UNREFERENCED_PARAMETER(pDeviceObject);

	return FALSE;
} 



/**************************************************
@author		  : Sunr
@create time  : 20200730
@last   time  : 20200730
@description  : Noting to do..
**************************************************/
#pragma PAGEDCODE
BOOLEAN FSFastIoPrepareMdlWrite(IN PFILE_OBJECT pFileObject,
	IN PLARGE_INTEGER pFileOffset,
	IN ULONG ulLength,
	IN ULONG ulLockKey,
	OUT PMDL *pMdlChain,
	OUT PIO_STATUS_BLOCK pIoStatus,
	IN PDEVICE_OBJECT pDeviceObject)
{
	UNREFERENCED_PARAMETER(pFileObject);
	UNREFERENCED_PARAMETER(pFileOffset);
	UNREFERENCED_PARAMETER(ulLength);
	UNREFERENCED_PARAMETER(ulLockKey);
	UNREFERENCED_PARAMETER(pMdlChain);
	UNREFERENCED_PARAMETER(pIoStatus);
	UNREFERENCED_PARAMETER(pDeviceObject);

	return FALSE;
}



/**************************************************
@author		  : Sunr
@create time  : 20200730
@last   time  : 20200730
@description  : Noting to do..
**************************************************/
#pragma PAGEDCODE
BOOLEAN FSFastIoMdlWriteComplete(IN PFILE_OBJECT pFileObject,
	IN PLARGE_INTEGER pFileOffset,
	IN PMDL pMdlChain,
	IN PDEVICE_OBJECT pDeviceObject)
{
	UNREFERENCED_PARAMETER(pFileObject);
	UNREFERENCED_PARAMETER(pFileOffset);
	UNREFERENCED_PARAMETER(pMdlChain);
	UNREFERENCED_PARAMETER(pDeviceObject);

	return FALSE;
} 




/**************************************************
@author		  : Sunr
@create time  : 20200730
@last   time  : 20200730
@description  : Noting to do..
**************************************************/
#pragma PAGEDCODE
BOOLEAN FSFastIoMdlWriteCompleteCompressed(
	IN PFILE_OBJECT pFileObject,
	IN PLARGE_INTEGER pFileOffset,
	IN PMDL pMdlChain,
	IN PDEVICE_OBJECT pDeviceObject
)
{
	UNREFERENCED_PARAMETER(pFileObject);
	UNREFERENCED_PARAMETER(pFileOffset);
	UNREFERENCED_PARAMETER(pMdlChain);
	UNREFERENCED_PARAMETER(pDeviceObject);

	return FALSE;
}





/**************************************************
@author		  : Sunr
@create time  : 20200730
@last   time  : 20200730
@description  : Noting to do..
**************************************************/
#pragma PAGEDCODE
BOOLEAN FSFastIoReadCompressed(
	IN PFILE_OBJECT pFileObject,
	IN PLARGE_INTEGER pFileOffset,
	IN ULONG ulLength,
	IN ULONG ulLockKey,
	OUT PVOID pBuffer,
	OUT PMDL *ppMdlChain,
	OUT PIO_STATUS_BLOCK pIoStatus,
	OUT struct _COMPRESSED_DATA_INFO *pCompressedDataInfo,
	IN ULONG ulCompressedDataInfoLength,
	IN PDEVICE_OBJECT pDeviceObject
)
{
	UNREFERENCED_PARAMETER(pFileObject);
	UNREFERENCED_PARAMETER(pFileOffset);
	UNREFERENCED_PARAMETER(ulLength);
	UNREFERENCED_PARAMETER(ulLockKey);
	UNREFERENCED_PARAMETER(pBuffer);
	UNREFERENCED_PARAMETER(ppMdlChain);
	UNREFERENCED_PARAMETER(pIoStatus);
	UNREFERENCED_PARAMETER(pCompressedDataInfo);
	UNREFERENCED_PARAMETER(ulCompressedDataInfoLength);
	UNREFERENCED_PARAMETER(pDeviceObject);

	return FALSE;
}

/**************************************************
@author		  : Sunr
@create time  : 20200730
@last   time  : 20200730
@description  : Noting to do..
**************************************************/
#pragma PAGEDCODE
BOOLEAN FSFastIoWriteCompressed(
	IN PFILE_OBJECT pFileObject,
	IN PLARGE_INTEGER pFileOffset,
	IN ULONG ulLength,
	IN ULONG ulLockKey,
	IN PVOID pBuffer,
	OUT PMDL *ppMdlChain,
	OUT PIO_STATUS_BLOCK pIoStatus,
	IN struct _COMPRESSED_DATA_INFO *pCompressedDataInfo,
	IN ULONG ulCompressedDataInfoLength,
	IN PDEVICE_OBJECT pDeviceObject
)
{
	UNREFERENCED_PARAMETER(pFileObject);
	UNREFERENCED_PARAMETER(pFileOffset);
	UNREFERENCED_PARAMETER(ulLength);
	UNREFERENCED_PARAMETER(ulLockKey);
	UNREFERENCED_PARAMETER(pBuffer);
	UNREFERENCED_PARAMETER(ppMdlChain);
	UNREFERENCED_PARAMETER(pIoStatus);
	UNREFERENCED_PARAMETER(pCompressedDataInfo);
	UNREFERENCED_PARAMETER(ulCompressedDataInfoLength);
	UNREFERENCED_PARAMETER(pDeviceObject);

	return FALSE;
} 

