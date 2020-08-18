#include"ssdthead.h"
#include"idthead.h"
#include"irphead.h"
#include"framehead.h"

BOOLEAN IsGetSSDT = FALSE;
ULONG SSDTNumber = 0;
extern g_Timer;


VOID SSDTdet()
{
	if (NT_SUCCESS(GetKernelModuleInfo()))  //获取当前内核信息
	{
		if (LoadKernel())  //加载内核
		{
			if (GetSSDTName())
			{
				int n = 0;
				KdPrint(("-------------SSDT---------------\n"));
				FileWriteExA("-------------SSDT---------------\r\n");
				for (int i = 0; i < SSDTNumber; i++)
				{
					if (SSDT[i].CurrentAddress != SSDT[i].OriginalAddress)
					{
						
						DbgPrint("SSDT HOOK!\n");
						FileWriteExA("SSDT HOOK!\r\n");
						DbgPrint("Index: %d\n", SSDT[i].index);
						FileWriteExA("Index: ");
						FileWriteInt(SSDT[i].index, 10);
						FileWriteExA("\r\n");
						DbgPrint("Current  Addr: %08x\n", SSDT[i].CurrentAddress);
						FileWriteExA("Current  Addr: 0x");
						FileWriteInt(SSDT[i].CurrentAddress, 16);
						FileWriteExA("\r\n");
						DbgPrint("Original Addr: %08x\n", SSDT[i].OriginalAddress);
						FileWriteExA("Original Addr: 0x");
						FileWriteInt(SSDT[i].OriginalAddress, 16);
						FileWriteExA("\r\n");
						DbgPrint("Function Name: %s\n", SSDT[i].FunctionName);
						FileWriteExA("Function Name: ");
						FileWriteExA(SSDT[i].FunctionName);
						FileWriteExA("\r\n");
						DbgPrint("Module Name: %s\n", SSDT[i].KernelMouduleName);
						FileWriteExA("Module Name: ");
						FileWriteExA(SSDT[i].KernelMouduleName);
						FileWriteExA("\r\n");
						DbgPrint("Module Base: %08x\n\n", SSDT[i].KernelMouduleBase);
						FileWriteExA("Module Base: 0x");
						FileWriteInt(SSDT[i].KernelMouduleBase, 16);
						FileWriteExA("\r\n");
						n++;
					}						
				}
				if (!n)
					KdPrint(("NO SSDT HOOK.\n"));
				FileWriteExA("NO SSDT HOOK.\r\n");
			}
			else
			{
				//DbgPrint("GetSSDTName failed!\n");
			}
		}
		else
		{
			//DbgPrint("LoadKernel failed!\n");
		}

	}
	else
	{
		//DbgPrint("GetKernelModuleInfo failed!\n");
	}

	//DbgPrint("Driver Onload...\n");
}

VOID IRPdet()
{

	UNICODE_STRING USzDriverName = RTL_CONSTANT_STRING(L"\\Driver\\kbdclass");

	KdPrint(("-------------IRP----------------\n"));
	FileWriteExA("-------------IRP----------------\r\n");
	Status = EnumDeviceStack(&USzDriverName);
	if (!NT_SUCCESS(Status))
	{
		KdPrint(("枚举设备失败!\n"));
		return Status;
	}
}


void DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	if (IsGetSSDT)
	{
		ExFreePool(SSDT);
	}

	DestroyTimer();
	KdPrint(("********************************\n"));
	DbgPrint("Detect Close...\n");
	KdPrint(("********************************\n\n"));
}



NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegsiterPath)
{
	UNREFERENCED_PARAMETER(pDriverObject);
	UNREFERENCED_PARAMETER(pRegsiterPath);
	NTSTATUS status = STATUS_SUCCESS;
	pRegsiterPath;

	pDriverObject->DriverUnload = DriverUnload;

	IDTOrg();

	if (CreateTimer(5000, TimerFunc))
	{
		//KdPrint(("创建成功:%#x\n", g_Timer));
	}
	else
	{
		//KdPrint(("创建失败:%#x\n", g_Timer));
	}

	return STATUS_SUCCESS;
}

