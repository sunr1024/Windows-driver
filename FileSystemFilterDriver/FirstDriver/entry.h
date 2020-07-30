#pragma once
#include<ntifs.h>
#include<ntddk.h>
#include<ntdef.h>

#include"Macro.h"
#include"Type.h"
#include"Func.h"


PDRIVER_OBJECT g_pstDriverObject;
PDEVICE_OBJECT g_pstControlDeviceObject;
FAST_MUTEX g_stAttachLock;







