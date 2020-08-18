#include<ntddk.h>
#include<string.h>
#include<wdm.h>
#include"ssdthead.h"
#include"idthead.h"
#include"irphead.h"
#include"framehead.h"

HANDLE g_FileHandle = NULL;
const WCHAR* g_wzFileName = L"\\??\\C:\\DetectLog.txt";


NTSTATUS FileCreate()
{
	UNICODE_STRING usFileNme;
	OBJECT_ATTRIBUTES obj;
	IO_STATUS_BLOCK ioSB;
	LARGE_INTEGER lFileAllocationSize;
	NTSTATUS status = STATUS_SUCCESS;
	RtlInitUnicodeString(&usFileNme, g_wzFileName);
	InitializeObjectAttributes(&obj, &usFileNme, OBJ_CASE_INSENSITIVE, NULL, NULL);
	lFileAllocationSize = RtlConvertLongToLargeInteger((ULONG)1024);
	status = ZwCreateFile(&g_FileHandle, FILE_ALL_ACCESS, &obj, &ioSB, &lFileAllocationSize, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ| FILE_SHARE_WRITE| FILE_SHARE_DELETE, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
	
	if (!NT_SUCCESS(status))
		KdPrint(("zwCreatFile Error"));
	else
		KdPrint(("zwCreatFile successed"));
	return STATUS_SUCCESS;
}
NTSTATUS FileWriteExA(char *str)
{
	NTSTATUS status;
	IO_STATUS_BLOCK ioSB;
	LARGE_INTEGER kOffset = RtlConvertLongToLargeInteger((ULONG)0);
	UNICODE_STRING usWriteData;
	ANSI_STRING asWriteData;

	RtlInitAnsiString(&asWriteData, str);	

	status = ZwWriteFile(g_FileHandle, NULL, NULL, NULL, &ioSB, asWriteData.Buffer, asWriteData.Length, NULL, NULL);

	return STATUS_SUCCESS;
}


NTSTATUS FileWriteExW(wchar_t *str)
{
	NTSTATUS status;
	IO_STATUS_BLOCK ioSB;
	LARGE_INTEGER kOffset = RtlConvertLongToLargeInteger((ULONG)0);
	UNICODE_STRING usWriteData;
	ANSI_STRING asWriteData;
	RtlInitUnicodeString(&usWriteData, str);
	RtlUnicodeStringToAnsiString(&asWriteData, &usWriteData, TRUE);
	status = ZwWriteFile(g_FileHandle, NULL, NULL, NULL, &ioSB, asWriteData.Buffer, asWriteData.Length, NULL, NULL);
	RtlFreeAnsiString(&asWriteData);
	return STATUS_SUCCESS;
}

NTSTATUS FileWriteInt(ULONG n,int i)
{
	NTSTATUS status;
	IO_STATUS_BLOCK ioSB;
	LARGE_INTEGER kOffset = RtlConvertLongToLargeInteger((ULONG)0);
	UNICODE_STRING usWriteData;
	ANSI_STRING asWriteData;

	usWriteData.Buffer = (PWSTR)ExAllocatePool(PagedPool, 1024);
	usWriteData.MaximumLength = 1024;


	RtlIntegerToUnicodeString(n, i, &usWriteData);

	RtlUnicodeStringToAnsiString(&asWriteData, &usWriteData, TRUE);
	status = ZwWriteFile(g_FileHandle, NULL, NULL, NULL, &ioSB, asWriteData.Buffer, asWriteData.Length, NULL, NULL);

	RtlFreeUnicodeString(&usWriteData);
	RtlFreeAnsiString(&asWriteData);
	return STATUS_SUCCESS;
}

NTSTATUS FileClose()
{
	if (g_FileHandle)
	{
		ZwClose(g_FileHandle);
		g_FileHandle = NULL;
	}
	KdPrint(("Close File Handle..."));
}
