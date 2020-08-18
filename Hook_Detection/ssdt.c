#include"ssdthead.h"

wchar_t NtosVersionName[4][128] = { L"\\??\\C:\\WINDOWS\\system32\\ntoskrnl.exe",L"\\??\\C:\\WINDOWS\\system32\\ntkrnlpa.exe",L"\\??\\C:\\WINDOWS\\system32\\ntkrnlmp.exe",L"\\??\\C:\\WINDOWS\\system32\\ntkrpamp.exe" };
char NtosVersionNameA[4][128] = { "C:\\WINDOWS\\system32\\ntoskrnl.exe","C:\\WINDOWS\\system32\\ntkrnlpa.exe","C:\\WINDOWS\\system32\\ntkrnlmp.exe","C:\\WINDOWS\\system32\\ntkrpamp.exe" };

ULONG OldImageBase = 0;  //��ǰ�ں����ڴ��еĵ�ַ
ULONG ImageBase = 0;  //�ļ��еĻ�ַ


extern IsGetSSDT;

extern SSDTNumber;




//�ָ��ڴ汣��
void PageProtectOn()
{
	__asm {
		mov  eax, cr0
		or eax, 10000h
		mov  cr0, eax
		sti
	}
}

//ȥ���ڴ汣��
void PageProtectOff()
{
	__asm {
		cli
		mov  eax, cr0
		and  eax, not 10000h
		mov  cr0, eax
	}
}

NTSTATUS __stdcall ZwQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
);



VOID SetNewSSDT(PVOID pNewImage)
{

	ULONG              uIndex;
	ULONG              uNewKernelInc, uOffset;
	//���ں˵�ַ-���ں˵�ַ���õ����ƫ��
	uNewKernelInc = (ULONG)pNewImage - OldImageBase;

	//���ں˵�ssdtָ��������ƫ�ƣ��õ����ں˵�ssdtָ��
	pNewSSDT = (ServiceDescriptorTableEntry_t *)((ULONG)&KeServiceDescriptorTable + uNewKernelInc);

	if (!MmIsAddressValid(pNewSSDT))
	{
		KdPrint(("pNewSSDT is unaviable!"));
		return;
	}
	//����������һ����ֵ����˲��������ƫ��
	pNewSSDT->NumberOfServices = KeServiceDescriptorTable.NumberOfServices;
	//������Ժ�����ַ
	uOffset = (ULONG)KeServiceDescriptorTable.ServiceTableBase - OldImageBase;
	//�õ��µ�ssdt�������ַ
	pNewSSDT->ServiceTableBase = (unsigned int*)((ULONG)pNewImage + uOffset);
	if (!MmIsAddressValid(pNewSSDT->ServiceTableBase))
	{
		KdPrint(("pNewSSDT->ServiceTableBase: %X", pNewSSDT->ServiceTableBase));
		return;
	}

	//���α���
	for (uIndex = 0; uIndex < pNewSSDT->NumberOfServices; uIndex++)
	{  //�µĺ�����ַ�ټ�����Լ��ص�ַ���õ����ڵ�ssdt������ַ
		pNewSSDT->ServiceTableBase[uIndex] = pNewSSDT->ServiceTableBase[uIndex] - ImageBase + OldImageBase;
		//DbgPrint("%d->%08x\n",uIndex,pNewSSDT->ServiceTableBase[uIndex]);  //��ӡSSDT�����ź͵�ַ
	}

	//
	//����SSDT��Ϣ
	//
	SSDT = (PSSDTInformation)ExAllocatePool(NonPagedPool, sizeof(SSDTInformation)*pNewSSDT->NumberOfServices);
	if (SSDT == NULL)
	{
		DbgPrint("�����ڴ�ʧ��\n");
		return;
	}
	else
	{
		IsGetSSDT = TRUE;
	}
	for (uIndex = 0; uIndex < pNewSSDT->NumberOfServices; uIndex++)
	{
		SSDT[uIndex].index = uIndex;  //���
		SSDT[uIndex].OriginalAddress = pNewSSDT->ServiceTableBase[uIndex];  //ԭʼ��ַ
		SSDT[uIndex].CurrentAddress = KeServiceDescriptorTable.ServiceTableBase[uIndex];
	}
	SSDTNumber = pNewSSDT->NumberOfServices;  //�ж�����
}

BOOLEAN LoadKernel()
{
	NTSTATUS				status;
	UNICODE_STRING			uFileName;
	HANDLE					hFile;
	OBJECT_ATTRIBUTES		ObjAttr;
	IO_STATUS_BLOCK			IoStatusBlock;
	LARGE_INTEGER			FileOffset;
	ULONG					retsize;
	PVOID					lpVirtualPointer;
	ULONG					uLoop;
	ULONG					SectionVirtualAddress, SectionSize;
	PIMAGE_DOS_HEADER		ImageDosHeader;
	PIMAGE_NT_HEADERS		ImageNtHeader;
	PIMAGE_SECTION_HEADER	lpImageSectionHeader;

	InitializeObjectAttributes(&ObjAttr, 
		&uFileName, 
		OBJ_CASE_INSENSITIVE, 
		NULL, 
		NULL);
	RtlInitUnicodeString(&uFileName, NtosVersionName[NtosVersion]);
	//���ļ�
	status = ZwCreateFile(
		&hFile, 
		FILE_ALL_ACCESS, 
		&ObjAttr, 
		&IoStatusBlock, 
		0, 
		FILE_ATTRIBUTE_NORMAL, 
		FILE_SHARE_READ, 
		FILE_OPEN, 
		FILE_NON_DIRECTORY_FILE, 
		NULL, 
		0);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("CreateFile Failed!\n"));
		return FALSE;
	}

	//��ȡDOSͷ
	FileOffset.QuadPart = 0;
	ImageDosHeader = (PIMAGE_DOS_HEADER)ExAllocatePool(NonPagedPool, sizeof(IMAGE_DOS_HEADER));  //�ǵ��ͷ�
	status = ZwReadFile(hFile, 
		NULL, 
		NULL, 
		NULL, 
		&IoStatusBlock, 
		ImageDosHeader, 
		sizeof(IMAGE_DOS_HEADER), 
		&FileOffset, 
		0);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("Read ImageDosHeader Failed!"));
		ZwClose(hFile);
		return FALSE;
	}

	//��ȡNTͷ
	ImageNtHeader = (PIMAGE_NT_HEADERS)ExAllocatePool(NonPagedPool, sizeof(IMAGE_NT_HEADERS));  //�ǵ��ͷ�
	FileOffset.QuadPart = ImageDosHeader->e_lfanew;
	status = ZwReadFile(hFile, 
		NULL, 
		NULL, 
		NULL, 
		&IoStatusBlock, 
		ImageNtHeader, 
		sizeof(IMAGE_NT_HEADERS), 
		&FileOffset, 
		0);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("Read ImageNtHeaders Failed!"));
		ZwClose(hFile);
		return FALSE;
	}
	ImageBase = ImageNtHeader->OptionalHeader.ImageBase;
	//��ȡ����
	lpImageSectionHeader = (PIMAGE_SECTION_HEADER)ExAllocatePool(NonPagedPool, sizeof(IMAGE_SECTION_HEADER)*ImageNtHeader->FileHeader.NumberOfSections);
	FileOffset.QuadPart += sizeof(IMAGE_NT_HEADERS);
	status = ZwReadFile(hFile, 
		NULL, 
		NULL, 
		NULL, 
		&IoStatusBlock, 
		lpImageSectionHeader, 
		sizeof(IMAGE_SECTION_HEADER)*ImageNtHeader->FileHeader.NumberOfSections, 
		&FileOffset, 
		0);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("Read ImageSectionHeader Failed!"));
		ExFreePool(lpImageSectionHeader);
		ZwClose(hFile);
		return FALSE;
	}

	//COPY���ݵ��ڴ�
	lpVirtualPointer = ExAllocatePool(NonPagedPool, 
		ImageNtHeader->OptionalHeader.SizeOfImage);
	if (lpVirtualPointer == 0)
	{
		KdPrint(("lpVirtualPointer Alloc space Failed!"));
		ZwClose(hFile);
		return FALSE;
	}
	memset(lpVirtualPointer, 0, ImageNtHeader->OptionalHeader.SizeOfImage);
	//COPY DOSͷ
	RtlCopyMemory(lpVirtualPointer, 
		ImageDosHeader, 
		sizeof(IMAGE_DOS_HEADER));

	//COPY NTͷ
	RtlCopyMemory((PVOID)((ULONG)lpVirtualPointer + ImageDosHeader->e_lfanew), 
		ImageNtHeader, 
		sizeof(IMAGE_NT_HEADERS));
	//COPY ����
	RtlCopyMemory((PVOID)((ULONG)lpVirtualPointer + ImageDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS)), 
		lpImageSectionHeader, 
		sizeof(IMAGE_SECTION_HEADER)*ImageNtHeader->FileHeader.NumberOfSections);
	//����COPY ����������
	for (uLoop = 0; uLoop < ImageNtHeader->FileHeader.NumberOfSections; uLoop++)
	{
		SectionVirtualAddress = lpImageSectionHeader[uLoop].VirtualAddress;//��Ӧ�������ƫ��
		if (lpImageSectionHeader[uLoop].Misc.VirtualSize > lpImageSectionHeader[uLoop].SizeOfRawData)
			SectionSize = lpImageSectionHeader[uLoop].Misc.VirtualSize;//ȡ����ռ�ÿռ�
		else
			SectionSize = lpImageSectionHeader[uLoop].SizeOfRawData;
		FileOffset.QuadPart = lpImageSectionHeader[uLoop].PointerToRawData;//��Ӧ���εĳ�ʼ��ַ
		status = ZwReadFile(hFile, 
			NULL, 
			NULL, 
			NULL, 
			&IoStatusBlock, 
			(PVOID)((ULONG)lpVirtualPointer + SectionVirtualAddress), 
			SectionSize, 
			&FileOffset, 
			0);
		if (!NT_SUCCESS(status))
		{
			KdPrint(("SectionData Read Failed!"));
			ExFreePool(lpImageSectionHeader);
			ExFreePool(lpVirtualPointer);
			ZwClose(hFile);
			return FALSE;
		}
	}

	SetNewSSDT(lpVirtualPointer);

	ExFreePool(lpImageSectionHeader);//�ͷ������ڴ�ռ�
	ExFreePool(ImageNtHeader);
	ZwClose(hFile);//�رվ��
	return TRUE;
}

// ��ȡkernelģ�����Ϣ
NTSTATUS GetKernelModuleInfo()
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PSYSTEM_MODULE_INFO_LIST pSysModInfoList = NULL;
	ULONG ulLength = 0;

	status = ZwQuerySystemInformation(SystemModuleInformation, pSysModInfoList, ulLength, &ulLength);
	if (status != STATUS_INFO_LENGTH_MISMATCH)
	{
		return STATUS_UNSUCCESSFUL;
	}

	pSysModInfoList = (PSYSTEM_MODULE_INFO_LIST)ExAllocatePool(NonPagedPool, ulLength);
	if (NULL == pSysModInfoList)
	{
		return STATUS_UNSUCCESSFUL;
	}

	status = ZwQuerySystemInformation(SystemModuleInformation, pSysModInfoList, ulLength, &ulLength);
	if (!NT_SUCCESS(status))
	{
		ExFreePool(pSysModInfoList);
		return STATUS_UNSUCCESSFUL;
	}

	OldImageBase = (ULONG)pSysModInfoList->smi[0].Base;  //�õ���ǰ�ں˵Ļ�ַ

	if (strstr(pSysModInfoList->smi[0].ImageName, "ntoskrnl.exe"))
	{
		NtosVersion = 0;
	}
	if (strstr(pSysModInfoList->smi[0].ImageName, "ntkrnlpa.exe"))
	{
		NtosVersion = 1;
	}
	if (strstr(pSysModInfoList->smi[0].ImageName, "ntkrnlmp.exe"))
	{
		NtosVersion = 2;
	}
	if (strstr(pSysModInfoList->smi[0].ImageName, "ntkrpamp.exe"))
	{
		NtosVersion = 3;
	}
	ExFreePool(pSysModInfoList);

	return STATUS_SUCCESS;
}

BOOLEAN GetSSDTName()
{


	if (KeGetCurrentIrql() > PASSIVE_LEVEL)
	{
		return STATUS_UNSUCCESSFUL;
	}
	//����NTDLL·��
	UNICODE_STRING uniFileName;
	RtlInitUnicodeString(&uniFileName, L"\\SystemRoot\\system32\\ntdll.dll");

	//��ʼ�����ļ�������
	OBJECT_ATTRIBUTES objectAttributes;
	InitializeObjectAttributes(&objectAttributes, &uniFileName,
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

	//�����ļ�
	Status = IoCreateFile(&FileHandle, FILE_READ_ATTRIBUTES | SYNCHRONIZE, &objectAttributes,
		&ioStatus, 0, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT,
		NULL, 0, CreateFileTypeNone, NULL, IO_NO_PARAMETER_CHECKING);
	if (!NT_SUCCESS(Status))
	{
		DbgPrint("IoCreateFile failed��status:0x%08x\n", Status);
		return FALSE;
	}
	//��ȡ�ļ���Ϣ

	Status = ZwQueryInformationFile(FileHandle, &ioStatus, &FileInformation,
		sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
	if (!NT_SUCCESS(Status))
	{
		DbgPrint("ZwQueryInformationFile failed��status:0x%08x\n", Status);
		ZwClose(FileHandle);
		return FALSE;
	}
	//�ж��ļ���С�Ƿ����
	if (FileInformation.EndOfFile.HighPart != 0)
	{
		DbgPrint("File Size Too High");
		ZwClose(FileHandle);
		return FALSE;
	}
	//ȡ�ļ���С
	ULONG uFileSize = FileInformation.EndOfFile.LowPart;
	//�����ڴ�
	PVOID pBuffer = ExAllocatePoolWithTag(PagedPool, uFileSize, (ULONG)"NTDLL");
	if (pBuffer == NULL)
	{
		DbgPrint("ExAllocatePoolWithTag() == NULL");
		ZwClose(FileHandle);
		return FALSE;
	}
	//��ͷ��ʼ��ȡ�ļ�
	LARGE_INTEGER byteOffset;
	byteOffset.LowPart = 0;
	byteOffset.HighPart = 0;
	Status = ZwReadFile(FileHandle, NULL, NULL, NULL, &ioStatus, pBuffer, uFileSize, &byteOffset, NULL);
	if (!NT_SUCCESS(Status))
	{
		DbgPrint("ZwReadFile failed��status:0x%08x\n", Status);
		ZwClose(FileHandle);
		return FALSE;
	}
	//ȡ��������
	PIMAGE_DOS_HEADER		pDosHeader;
	PIMAGE_NT_HEADERS		pNtHeaders;
	PIMAGE_SECTION_HEADER	pSectionHeader;
	ULONG					FileOffset;
	PIMAGE_EXPORT_DIRECTORY pExportDirectory;
	//DLL�ڴ�����ת��DOSͷ�ṹ
	pDosHeader = (PIMAGE_DOS_HEADER)pBuffer;
	//ȡ��PEͷ�ṹ
	pNtHeaders = (PIMAGE_NT_HEADERS)((ULONG)pBuffer + pDosHeader->e_lfanew);
	//�ж�PEͷ��������Ƿ�Ϊ��
	if (pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
	{
		DbgPrint("VirtualAddress == 0");
		return FALSE;
	}
	//ȡ��������ƫ��
	FileOffset = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

	//ȡ����ͷ�ṹ
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pNtHeaders + sizeof(IMAGE_NT_HEADERS));
	PIMAGE_SECTION_HEADER pOldSectionHeader = pSectionHeader;
	//�����ڽṹ���е�ַ����
	for (WORD Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++)
	{
		if (pSectionHeader->VirtualAddress <= FileOffset &&
			FileOffset <= pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)
		{
			FileOffset = FileOffset - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
		}
	}
	//�������ַ
	pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((ULONG)pBuffer + FileOffset);
	//ȡ������������ַ
	PULONG AddressOfFunctions;
	FileOffset = pExportDirectory->AddressOfFunctions;
	//�����ڽṹ���е�ַ����
	pSectionHeader = pOldSectionHeader;
	for (WORD Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++)
	{
		if (pSectionHeader->VirtualAddress <= FileOffset &&
			FileOffset <= pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)
		{
			FileOffset = FileOffset - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
		}
	}
	AddressOfFunctions = (PULONG)((ULONG)pBuffer + FileOffset);

	//ȡ��������������
	PUSHORT AddressOfNameOrdinals;
	FileOffset = pExportDirectory->AddressOfNameOrdinals;
	//�����ڽṹ���е�ַ����
	pSectionHeader = pOldSectionHeader;
	for (WORD Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++)
	{
		if (pSectionHeader->VirtualAddress <= FileOffset &&
			FileOffset <= pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)
		{
			FileOffset = FileOffset - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
		}
	}
	AddressOfNameOrdinals = (PUSHORT)((ULONG)pBuffer + FileOffset);
	//ȡ�������������
	PULONG AddressOfNames;
	FileOffset = pExportDirectory->AddressOfNames;
	//�����ڽṹ���е�ַ����
	pSectionHeader = pOldSectionHeader;
	for (WORD Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++)
	{
		if (pSectionHeader->VirtualAddress <= FileOffset &&
			FileOffset <= pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)
		{
			FileOffset = FileOffset - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
		}
	}
	AddressOfNames = (PULONG)((ULONG)pBuffer + FileOffset);
	//����������
	ULONG uNameOffset;
	ULONG uOffset;
	LPSTR FunName;
	PVOID pFuncAddr;
	ULONG uServerIndex;
	ULONG uAddressOfNames;
	for (ULONG uIndex = 0; uIndex < pExportDirectory->NumberOfNames; uIndex++, AddressOfNames++, AddressOfNameOrdinals++)
	{
		uAddressOfNames = *AddressOfNames;
		pSectionHeader = pOldSectionHeader;
		for (WORD Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++)
		{
			if (pSectionHeader->VirtualAddress <= uAddressOfNames &&
				uAddressOfNames <= pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)
			{
				uOffset = uAddressOfNames - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
			}
		}
		FunName = (LPSTR)((ULONG)pBuffer + uOffset);

		if (FunName[0] == 'Z' && FunName[1] == 'w')
		{
			pSectionHeader = pOldSectionHeader;
			uOffset = (ULONG)AddressOfFunctions[*AddressOfNameOrdinals];
			for (WORD Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++)
			{
				if (pSectionHeader->VirtualAddress <= uOffset &&
					uOffset <= pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)
				{
					uNameOffset = uOffset - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
				}
			}
			pFuncAddr = (PVOID)((ULONG)pBuffer + uNameOffset);
			uServerIndex = *(PULONG)((ULONG)pFuncAddr + 1);
			FunName[0] = 'N';
			FunName[1] = 't';
			//KdPrint(("���к�Ϊ��%d,������Ϊ: %s\n", uServerIndex, FunName));
			RtlCopyMemory(SSDT[uServerIndex].FunctionName, FunName, sizeof(char) * 15);  //���溯����
			SSDT[uServerIndex].KernelMouduleBase = OldImageBase;  //�����ں�ģ���ַ
			RtlCopyMemory(SSDT[uServerIndex].KernelMouduleName, NtosVersionNameA[NtosVersion], sizeof(char) * 63);  //�����ں�ģ����

		}

	}
	ExFreePoolWithTag(pBuffer, (ULONG)"NTDLL");
	ZwClose(FileHandle);
	return TRUE;
}

