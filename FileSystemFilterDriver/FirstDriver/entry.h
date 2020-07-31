#pragma once
#include<ntifs.h>
#include<ntddk.h>
#include<ntdef.h>

#include"Macro.h"
#include"Type.h"
#include"Func.h"



extern PDRIVER_OBJECT g_pstDriverObject;
extern PDEVICE_OBJECT g_pstControlDeviceObject;
extern FAST_MUTEX g_stAttachLock;







