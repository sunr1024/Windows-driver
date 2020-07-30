#pragma once


#define ATTACH_VOLUME_DEVICE_TRY_NUM 16
#define MAX_DEVICENAME_LEN 512
#define FAST_IO_DISPATCH_TAG 'FIDT'
#define OBJECT_NAME_TAG 'ONT'
#define DEVICE_OBJECT_LIST_TAG 'DOLT'

#define DELAY_ONE_MICROSECOND	(-10)
#define DELAY_ONE_MILLISECOND	(DELAY_ONE_MICROSECOND*1000)
#define DELAY_ONE_SECOND		(DELAY_ONE_MILLISECOND*1000)

#define CONTROL_DEVICE_NAME L"\\FileSystem\\Filters\\SFilter"
#define OLD_CONTROL_DEVICE_NAME L"\\FileSystem\\SFilter"
#define FILE_SYSTEM_REC_NAME L"\\FileSystem\\Fs_Rec"



#define IS_MY_CONTROL_DEVICE_OBJECT(_pDeviceObject) \
    ((NULL != (_pDeviceObject)) && \
        ((_pDeviceObject)->DriverObject == g_pstDriverObject) && \
            (NULL == (_pDeviceObject)->DeviceExtension))

#define IS_MY_DEVICE_OBJECT(_pDeviceObject) \
    ((NULL != (_pDeviceObject)) && \
        ((_pDeviceObject)->DriverObject == g_pstDriverObject) && \
            (NULL != (_pDeviceObject)->DeviceExtension))   


#define IS_TARGET_DEVICE_TYPE(_type) \
    (FILE_DEVICE_DISK_FILE_SYSTEM == (_type))

