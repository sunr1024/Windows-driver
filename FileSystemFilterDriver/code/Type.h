#pragma once
//#include<ntddk.h>
//#include"Macro.h"



typedef struct tagDeviceExtension
{
	PDEVICE_OBJECT  pstDeviceObject;
	PDEVICE_OBJECT  pstNextDeviceObject;
	PDEVICE_OBJECT  pstStorageDeviceObject;
	UNICODE_STRING  ustrDeviceName;
	WCHAR           awcDeviceObjectBuffer[MAX_DEVICENAME_LEN];
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;
