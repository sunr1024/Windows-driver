#pragma once
#ifndef __ssdthead_h__
#define __ssdthead_h__
#include "ntddk.h"
#include <WinDef.h>
#include "ntimage.h"

int NtosVersion;  //判断操作系统内核标志

KIRQL Irql;




#pragma pack(1)
typedef struct ServiceDescriptorEntry {
	unsigned int *ServiceTableBase;
	unsigned int *ServiceCounterTableBase;
	unsigned int NumberOfServices;
	unsigned char *ParamTableBase;
} ServiceDescriptorTableEntry_t, *PServiceDescriptorTableEntry_t;
#pragma pack()


__declspec(dllimport) ServiceDescriptorTableEntry_t KeServiceDescriptorTable;

ServiceDescriptorTableEntry_t  *pNewSSDT;




typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemModuleInformation = 11,
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG Reserved[2];
	PBYTE Base;
	ULONG Size;
	ULONG Flags;
	USHORT Index;
	USHORT Unknown;
	USHORT LoadCount;
	USHORT ModuleNameOffset;
	CHAR ImageName[256];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef struct _SYSTEM_MODULE_INFO_LIST
{
	ULONG ulCount;
	SYSTEM_MODULE_INFORMATION smi[1];
} SYSTEM_MODULE_INFO_LIST, *PSYSTEM_MODULE_INFO_LIST;

typedef struct _MY_IMAGE_BASE_RELOCATION {
	ULONG   VirtualAddress;
	ULONG   SizeOfBlock;
	USHORT  TypeOffset[1];
} MY_IMAGE_BASE_RELOCATION;


NTSTATUS Status;
HANDLE FileHandle;
IO_STATUS_BLOCK ioStatus;
FILE_STANDARD_INFORMATION FileInformation;



typedef struct _SSDTInformation
{
	ULONG index;
	ULONG CurrentAddress;
	ULONG OriginalAddress;
	char FunctionName[16];  //函数名
	char KernelMouduleName[64];  //内核模块名
	ULONG KernelMouduleBase;  //内核模块基址
}SSDTInformation, *PSSDTInformation;
PSSDTInformation SSDT;



void PageProtectOn();
void PageProtectOff();

VOID SetNewSSDT(PVOID pNewImage);
BOOLEAN LoadKernel();
NTSTATUS GetKernelModuleInfo();
BOOLEAN GetSSDTName();
void DriverUnload(PDRIVER_OBJECT pDriverObject);

#endif