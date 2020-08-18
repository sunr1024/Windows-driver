#include "irphead.h"
#include"framehead.h"

VOID GetDeviceObjectInfo(PDEVICE_OBJECT pDeviceObj)
{
	POBJECT_HEADER ObjHeader = NULL;
	POBJECT_HEADER_NAME_INFO ObjName = NULL;


	//得到对象头
	ObjHeader = OBJECT_TO_OBJECT_HEADER(pDeviceObj);
	ASSERT(pDeviceObj != NULL);



	if (ObjHeader)
	{

		//查询设备名称
		ObjName = OBJECT_HEADER_TO_NAME_INFO(ObjHeader);

		if (ObjName && ObjName->Name.Buffer)
		{

			//KdPrint(("驱动名称:%wZ 驱动地址:%p 设备地址:%p\n",&pDeviceObj->DriverObject->DriverName, pDeviceObj->DriverObject, pDeviceObj));
		}
	}

	return;
}

VOID GetAttachedDeviceObjectInfo(PDEVICE_OBJECT pDeviceObj)
{
	PDEVICE_OBJECT pAttrDeviceObj = NULL;

	ASSERT(pDeviceObj != NULL);

	//获取绑定设备的地址
	pAttrDeviceObj = pDeviceObj->AttachedDevice;

	while (pAttrDeviceObj)
	{
		KdPrint(("\tBinding Driver Name:%wZ  Binding Driver Addr:%p Binding Device Addr:%p\n\n",
			&pAttrDeviceObj->DriverObject->DriverName,
			pAttrDeviceObj->DriverObject, pAttrDeviceObj));
		FileWriteExA("Binding Driver Addr: 0x");
		FileWriteInt(pAttrDeviceObj->DriverObject,16);
		FileWriteExA("  Binding Driver Addr: 0x");
		FileWriteInt(pAttrDeviceObj, 16);
		FileWriteExA("\r\n");

		//往上遍历
		pAttrDeviceObj = pAttrDeviceObj->AttachedDevice;
	}
}

NTSTATUS EnumDeviceStack(PUNICODE_STRING pUSzDriverName)
{
	NTSTATUS Status;
	PDEVICE_OBJECT pDeviceObj = NULL;
	PDRIVER_OBJECT pDriverObj = NULL;
	int i = 0;


	//通过驱动对象名称获取驱动对象指针
	Status = ObReferenceObjectByName(pUSzDriverName, OBJ_CASE_INSENSITIVE, NULL, 0,
		*IoDriverObjectType, KernelMode, NULL, &pDriverObj);
	if (!NT_SUCCESS(Status) || !pDriverObj)
	{
		return STATUS_UNSUCCESSFUL;
	}

	//通过驱动对象得到其设备对象指针
	pDeviceObj = pDriverObj->DeviceObject;

	__try
	{

		while (pDeviceObj)
		{

			//获取设备信息
			GetDeviceObjectInfo(pDeviceObj);

			//如果还有绑定在其之上的设备
			if (pDeviceObj->AttachedDevice)
			{
				KdPrint(("IRP HOOK!\n"));
				FileWriteExA("IRP HOOK!\r\n");
				i++;
				//获取绑定在设备之上的的设备信息
				GetAttachedDeviceObjectInfo(pDeviceObj);
			}
			else
			{
				KdPrint(("NO IRP HOOK.\n"));
				FileWriteExA("NO IRP HOOK.\r\n");
			}
			pDeviceObj = pDeviceObj->NextDevice;
			
		}



	}
	__finally
	{
		if (pDriverObj)
		{
			ObDereferenceObject(pDriverObj);
		}

	}
	return Status;
}
