#include "irphead.h"
#include"framehead.h"

VOID GetDeviceObjectInfo(PDEVICE_OBJECT pDeviceObj)
{
	POBJECT_HEADER ObjHeader = NULL;
	POBJECT_HEADER_NAME_INFO ObjName = NULL;


	//�õ�����ͷ
	ObjHeader = OBJECT_TO_OBJECT_HEADER(pDeviceObj);
	ASSERT(pDeviceObj != NULL);



	if (ObjHeader)
	{

		//��ѯ�豸����
		ObjName = OBJECT_HEADER_TO_NAME_INFO(ObjHeader);

		if (ObjName && ObjName->Name.Buffer)
		{

			//KdPrint(("��������:%wZ ������ַ:%p �豸��ַ:%p\n",&pDeviceObj->DriverObject->DriverName, pDeviceObj->DriverObject, pDeviceObj));
		}
	}

	return;
}

VOID GetAttachedDeviceObjectInfo(PDEVICE_OBJECT pDeviceObj)
{
	PDEVICE_OBJECT pAttrDeviceObj = NULL;

	ASSERT(pDeviceObj != NULL);

	//��ȡ���豸�ĵ�ַ
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

		//���ϱ���
		pAttrDeviceObj = pAttrDeviceObj->AttachedDevice;
	}
}

NTSTATUS EnumDeviceStack(PUNICODE_STRING pUSzDriverName)
{
	NTSTATUS Status;
	PDEVICE_OBJECT pDeviceObj = NULL;
	PDRIVER_OBJECT pDriverObj = NULL;
	int i = 0;


	//ͨ�������������ƻ�ȡ��������ָ��
	Status = ObReferenceObjectByName(pUSzDriverName, OBJ_CASE_INSENSITIVE, NULL, 0,
		*IoDriverObjectType, KernelMode, NULL, &pDriverObj);
	if (!NT_SUCCESS(Status) || !pDriverObj)
	{
		return STATUS_UNSUCCESSFUL;
	}

	//ͨ����������õ����豸����ָ��
	pDeviceObj = pDriverObj->DeviceObject;

	__try
	{

		while (pDeviceObj)
		{

			//��ȡ�豸��Ϣ
			GetDeviceObjectInfo(pDeviceObj);

			//������а�����֮�ϵ��豸
			if (pDeviceObj->AttachedDevice)
			{
				KdPrint(("IRP HOOK!\n"));
				FileWriteExA("IRP HOOK!\r\n");
				i++;
				//��ȡ�����豸֮�ϵĵ��豸��Ϣ
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
