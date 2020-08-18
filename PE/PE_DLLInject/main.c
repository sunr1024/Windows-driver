#include<stdio.h>
#include<stdlib.h>
#include<windows.h>

#define size_surplus_sizeofheader 0x50
#define test 1

BOOL MemoryToFile(PVOID pMemBuffer, DWORD size, LPSTR lpszFile);
DWORD ToLoaderPE(LPSTR file_path, PVOID* pFileBuffer);
DWORD CopyFileBufferToImageBuffer(PVOID pFileBuffer, PVOID* pImageBuffer);
DWORD CopyImageBufferToNewFileBuffer(PVOID pImageBuffer, PVOID* pNewFileBuffer);
DWORD FoaToImageOffset(PVOID pBuffer, DWORD dwFoa);
DWORD RvaToFileOffset(PVOID pBuffer, DWORD dwRva);
DWORD GetSctionEmptySpace(PVOID pFileBuffer, DWORD SectionOrdinal);
DWORD Alignment(DWORD alignment_value, DWORD addend, DWORD address);
DWORD DLLInject(PVOID pFileBuffer, PVOID* pNewFileBuffer, char* dllname, char* dllfunction);
VOID LogPEHeaderInfo(PVOID pFileBuffer);
VOID LogImportTable(PVOID pFileBuffer);

char file_path[] = "d:\\ipmsg2007\\ipmsg2007.exe";
char dllname[] = "InjectDll.dll";
char dllfunction[] = "ExportFunction";
char write_dllinject_file_path[] = "D:\\Lib\\cp_XX.exe";

//����PE�ļ���С
DWORD ToLoaderPE(LPSTR file_path, PVOID* pFileBuffer)
{
	FILE *pFile = NULL;
	DWORD FileSize = 0;
	PVOID pFileBufferTemp = NULL;

	pFile = fopen(file_path, "rb");

	if (!pFile)
	{
		printf("(ToLoaderPE)Can't open file!\n");
		return 0;
	}

	fseek(pFile, 0, SEEK_END);
	FileSize = ftell(pFile);
	printf("FileBuffer: %#x\n", FileSize);
	fseek(pFile, 0, SEEK_SET);
	pFileBufferTemp = malloc(FileSize);

	if (!pFileBufferTemp)
	{
		printf("(ToLoaderPE)Allocate dynamic memory failed!\n");
		fclose(pFile);
		return 0;
	}

	DWORD n = fread(pFileBufferTemp, FileSize, 1, pFile);

	if (!n)
	{
		printf("(ToLoaderPE)Read file failed!\n");
		free(pFileBufferTemp);
		fclose(pFile);
		return 0;
	}
	*pFileBuffer = pFileBufferTemp;
	pFileBufferTemp = NULL;
	fclose(pFile);
	return FileSize;
}

BOOL MemoryToFile(PVOID pMemBuffer, DWORD size, LPSTR lpszFile)
{
	FILE *fp;
	fp = fopen(lpszFile, "wb");
	if (fp != NULL)
	{
		fwrite(pMemBuffer, size, 1, fp);
	}
	fclose(fp);
	printf("Store file success!\n");
	return 1;
}

DWORD RvaToFileOffset(PVOID pBuffer, DWORD dwRva)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;

	if (!pBuffer)
	{
		printf("(RvaToFileOffset)Can't open file!\n");
		return 0;
	}

	if (*((PWORD)pBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("(RvaToFileOffset)No MZ flag, not exe file!\n");
		return 0;
	}

	pDosHeader = (PIMAGE_DOS_HEADER)pBuffer;
	if (*((PDWORD)((DWORD)pBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("(RvaToFileOffset)Not a valid PE flag!\n");
		return 0;
	}

	//printf("ImageOffset: %#x\n", dwRva);
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pBuffer + pDosHeader->e_lfanew);
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 4); // �������ǿ������ת��
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	PIMAGE_SECTION_HEADER pSectionTemp = pSectionHeader;

	if (dwRva <= pOptionHeader->SizeOfHeaders)
		return (DWORD)dwRva;
	else
	{
		for (int n = 0; n < pPEHeader->NumberOfSections; n++, pSectionTemp++)
		{	//�ж� :   �ļ�����+�ļ�ƫ��>file_panyi>�ļ�ƫ��  (�������ļ����ĸ�����)
			if ((dwRva >= pSectionTemp->VirtualAddress) && (dwRva < pSectionTemp->VirtualAddress + pSectionTemp->Misc.VirtualSize))
			{
				return dwRva - pSectionTemp->VirtualAddress + pSectionTemp->PointerToRawData;
			}
		}
	}
	printf("RvaToFoa failed��\n");
	return 0;
}

DWORD FoaToImageOffset(PVOID pBuffer, DWORD dwFoa)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;

	if (!pBuffer)
	{
		printf("(FoaToImageOffset)Can't open file!\n");
		return 0;
	}

	if (*((PWORD)pBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("(FoaToImageOffset)No MZ flag, not exe file!\n");
		return 0;
	}

	pDosHeader = (PIMAGE_DOS_HEADER)pBuffer;
	if (*((PDWORD)((DWORD)pBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("(FoaToImageOffset)Not a valid PE flag!\n");
		return 0;
	}
	printf("FileOffset: %#x\n", dwFoa);

	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pBuffer + pDosHeader->e_lfanew);
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 4); // �������ǿ������ת��
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	PIMAGE_SECTION_HEADER pSectionTemp = pSectionHeader;

	if (dwFoa <= pOptionHeader->SizeOfHeaders)
		return (DWORD)dwFoa;
	else
	{
		for (int n = 0; n < pPEHeader->NumberOfSections; n++, pSectionTemp++)
		{	//�ж� :   �ļ�����+�ļ�ƫ��>file_panyi>�ļ�ƫ��  (�������ļ����ĸ�����)
			if ((dwFoa >= pSectionTemp->PointerToRawData) && (dwFoa < pSectionTemp->PointerToRawData + pSectionTemp->SizeOfRawData))
			{
				return dwFoa - pSectionTemp->PointerToRawData + pSectionTemp->VirtualAddress;
			}
		}
	}
	printf("FoaToRva failed��\n");
	return 0;
}

DWORD Alignment(DWORD alignment_value, DWORD addend, DWORD address)
{
	int n = 0;
	if (addend / alignment_value)
	{
		if (addend%alignment_value)
		{
			n = addend / alignment_value + 1;
		}
		else
		{
			n = addend / alignment_value;
		}
	}
	else
	{
		if (addend)
			n = 1;
		else
			n = 0;
	}
	address += n * alignment_value;
	return address;
}

DWORD GetSctionEmptySpace(PVOID pFileBuffer, DWORD SectionOrdinal)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;

	if (!pFileBuffer)
	{
		printf("(GetSctionEmptySpace)Can't open file!\n");
		return 0;
	}

	if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("(GetSctionEmptySpace)No MZ flag, not exe file!\n");
		return 0;
	}

	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if (*((PDWORD)((DWORD)pFileBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("(GetSctionEmptySpace)Not a valid PE flag!\n");
		return 0;
	}

	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 4); // �������ǿ������ת��
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	if (SectionOrdinal > pPEHeader->NumberOfSections)
	{
		printf("(GetSctionEmptySpace)There are only %#x sections ,no %#x th.\n", pPEHeader->NumberOfSections, SectionOrdinal);
		return 0;
	}

	for (DWORD n = 0; n < SectionOrdinal - 1; n++)
	{
		pSectionHeader++;
	}

	DWORD EmptySpace = pSectionHeader->SizeOfRawData - pSectionHeader->Misc.VirtualSize;

	return EmptySpace;
}

DWORD CopyFileBufferToImageBuffer(PVOID pFileBuffer, PVOID* pImageBuffer)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;

	PVOID pImageTemp = NULL;

	if (!pFileBuffer)
	{
		printf("(CopyFileBufferToImageBuffer)Can't open file!\n");
		return 0;
	}

	if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("(CopyFileBufferToImageBuffer)No MZ flag, not exe file!\n");
		return 0;
	}

	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;

	if (*((LPDWORD)((DWORD)pFileBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("(CopyFileBufferToImageBuffer)Not a valid PE flag!\n");
		return 0;
	}

	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	pImageTemp = malloc(pOptionHeader->SizeOfImage);

	if (!pImageTemp)
	{
		printf("(CopyFileBufferToImageBuffer)Allocate dynamic memory failed!\n");
		free(pImageTemp);
		return 0;
	}

	memset(pImageTemp, 0, pOptionHeader->SizeOfImage);
	memcpy(pImageTemp, pDosHeader, pOptionHeader->SizeOfHeaders);

	PIMAGE_SECTION_HEADER pSectionHeaderTemp = pSectionHeader;

	for (int n = 0; n < pPEHeader->NumberOfSections; n++, pSectionHeaderTemp++)
	{
		memcpy((PVOID)((DWORD)pImageTemp + pSectionHeaderTemp->VirtualAddress), (PVOID)((DWORD)pFileBuffer + pSectionHeaderTemp->PointerToRawData), pSectionHeaderTemp->SizeOfRawData);
		printf("VirtualAddress%d: %#10x         PointerToRawData%d: %#10x\n", n, (DWORD)pImageTemp + pSectionHeader->VirtualAddress, n, (DWORD)pFileBuffer + pSectionHeader->PointerToRawData);
	}
	*pImageBuffer = pImageTemp;
	pImageTemp = NULL;
	return pOptionHeader->SizeOfImage;
}

DWORD CopyImageBufferToNewFileBuffer(PVOID pImageBuffer, PVOID* pNewFileBuffer)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;

	LPVOID pTempNewbuffer = NULL;

	if (!pImageBuffer)
	{
		printf("(CopyImageBufferToNewBuffer)Can't open file!\n");
		return 0;
	}

	if (*((PWORD)pImageBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("(CopyImageBufferToNewBuffer)No MZ flag, not exe file!\n");
		return 0;
	}

	pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
	if (*((PDWORD)((DWORD)pImageBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("(CopyImageBufferToNewBuffer)Not a valid PE flag!\n");
		return 0;
	}

	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pImageBuffer + pDosHeader->e_lfanew);
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 4); // �������ǿ������ת��
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	//��ȡnew_buffer�Ĵ�С
	int new_buffer_size = pOptionHeader->SizeOfHeaders;
	for (DWORD i = 0; i < pPEHeader->NumberOfSections; i++)
	{
		new_buffer_size += pSectionHeader[i].SizeOfRawData;  // pSectionHeader[i]��һ�ּӷ�
	}
	// �����ڴ棨newbuffer��
	pTempNewbuffer = malloc(new_buffer_size);
	if (!pTempNewbuffer)
	{
		printf("(CopyImageBufferToNewBuffer)Allocate dynamic memory failed!\n");
		return 0;
	}
	memset(pTempNewbuffer, 0, new_buffer_size);
	memcpy(pTempNewbuffer, pDosHeader, pOptionHeader->SizeOfHeaders);
	// ѭ����������
	PIMAGE_SECTION_HEADER pTempSectionHeader = pSectionHeader;
	for (DWORD j = 0; j < pPEHeader->NumberOfSections; j++, pTempSectionHeader++)
	{	//PointerToRawData�������ļ��е�ƫ��,VirtualAddress�������ڴ��е�ƫ�Ƶ�ַ,SizeOfRawData�����ļ��ж����ĳߴ�
		memcpy((PDWORD)((DWORD)pTempNewbuffer + pTempSectionHeader->PointerToRawData), (PDWORD)((DWORD)pImageBuffer + pTempSectionHeader->VirtualAddress), pTempSectionHeader->SizeOfRawData);
	}
	//��������
	*pNewFileBuffer = pTempNewbuffer; //�ݴ�����ݴ����������ͷ�
	pTempNewbuffer = NULL;
	return new_buffer_size;  // ���ؼ���õ��ķ����ڴ�Ĵ�С
}

VOID LogPEHeaderInfo(PVOID pFileBuffer)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;

	if (!pFileBuffer)
	{
		printf("(LogPEHeaderInfo)Can't open file!\n");
		return;
	}

	//�ж��Ƿ�����Ч��MZ��־	
	if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("(LogPEHeaderInfo)No MZ flag, not exe file!\n");
		free(pFileBuffer);
		return;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	//��ӡDOCͷ	
	printf("\n********************DOSͷ********************\n");
	printf("MZ flag��%#x\n", pDosHeader->e_magic);
	printf("PE offset��%#x\n", pDosHeader->e_lfanew);
	//�ж��Ƿ�����Ч��PE��־	
	if (*((PDWORD)((DWORD)pFileBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("(LogPEHeaderInfo)Not a valid PE flag!\n");
		free(pFileBuffer);
		return;
	}
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
	//��ӡNTͷ	
	printf("********************NTͷ********************\n");
	printf("NT��%#x\n", pNTHeader->Signature);
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);

	//int NumberOfSections = pPEHeader->NumberOfSections;
	//int SizeOfOptionalHeader = pPEHeader->SizeOfOptionalHeader;

	printf("********************PEͷ********************\n");
	printf("PE��%#x\n", pPEHeader->Machine);
	printf("Section number��%#x\n", pPEHeader->NumberOfSections);
	printf("SizeOfOptionalHeader��%#x\n", pPEHeader->SizeOfOptionalHeader);
	//��ѡPEͷ	
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	printf("********************OPTIOIN_PEͷ********************\n");
	printf("OPTION_PE��%#x\n", pOptionHeader->Magic);

	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	for (int n = 0; n < pPEHeader->NumberOfSections; n++)
	{
		printf("********************SECTION %d********************\n", n + 1);
		char name[9] = { 0 };
		memcpy(name, pSectionHeader->Name, 8);
		printf("Section Name: %s\n", name);
		printf("VirtualAddress: %#x\n", pSectionHeader->VirtualAddress);
		printf("SizeOfRawData: %#x\n", pSectionHeader->SizeOfRawData);
		printf("PointerToRawData: %#x\n", pSectionHeader->PointerToRawData);
		printf("Characteristics: %#x\n", pSectionHeader->Characteristics);
		pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pSectionHeader + IMAGE_SIZEOF_SECTION_HEADER);
	}
}

VOID LogImportTable(PVOID pFileBuffer)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
	PIMAGE_DATA_DIRECTORY pDataDirectory_ImportTable = NULL;
	PIMAGE_IMPORT_DESCRIPTOR pImportTable = NULL;
	PIMAGE_IMPORT_BY_NAME  pImportByName = NULL;
	PIMAGE_THUNK_DATA pOriginalFirstThunk = NULL;
	PIMAGE_THUNK_DATA pFirstThunk = NULL;

	if (!pFileBuffer)
	{
		printf("(LogImportTable)Can't open file!\n");
		return 0;
	}

	if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("(LogImportTable)No MZ flag, not exe file!\n");
		return 0;
	}

	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if (*((PDWORD)((DWORD)pFileBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("(LogImportTable)Not a valid PE flag!\n");
		return 0;
	}

	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 4); // �������ǿ������ת��
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	pDataDirectory = (PIMAGE_DATA_DIRECTORY)pOptionHeader->DataDirectory;
	pDataDirectory_ImportTable = &pDataDirectory[1];

	if (!pDataDirectory_ImportTable->VirtualAddress)
	{
		printf("(LogImportTable)This program has no import table.\n");
		return 0;
	}

	printf("Import Table Rva: %#x\n", pDataDirectory_ImportTable->VirtualAddress);
	DWORD Foa_ImportTable = RvaToFileOffset(pFileBuffer, pDataDirectory_ImportTable->VirtualAddress);
	printf("Import Table Foa: %#x\n", Foa_ImportTable);
	pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pFileBuffer + Foa_ImportTable);

	//����dllģ��
	while (pImportTable->Name != 0)
	{
		//��ӡdllģ����
		DWORD Foa_DllName = RvaToFileOffset(pFileBuffer, pImportTable->Name);
		PDWORD Foa_pDllName = (PDWORD)((DWORD)pFileBuffer + Foa_DllName);
		printf("%s\n", Foa_pDllName);
		//��ӡOriginalFirstThunk
		DWORD Foa_OrginalFirstThunkAddr = RvaToFileOffset(pFileBuffer, pImportTable->OriginalFirstThunk);
		PDWORD Foa_pOrginalFirstThunkAddr = (PDWORD)((DWORD)pFileBuffer + Foa_OrginalFirstThunkAddr);
		printf("-------------------Foa_OrginalFirstThunkAddr:%#-10x -----------------------\n", Foa_OrginalFirstThunkAddr);
		pOriginalFirstThunk = (PIMAGE_THUNK_DATA)Foa_pOrginalFirstThunkAddr;
		//while (strcmp(pOriginalFirstThunk,"0"))
		while (*(PDWORD)pOriginalFirstThunk)
		{
			DWORD value = *(PDWORD)pOriginalFirstThunk;
			DWORD judge = (value & IMAGE_ORDINAL_FLAG32) >> 31;
			//���λΪ1������ŷ�ʽ���룻���λΪ0���Ժ�������ʽ����
			if (judge)
			{
				//�������
				value -= IMAGE_ORDINAL_FLAG32;
				printf("Import Ordinal  :%#-4x\n", value);
			}
			else
			{
				//��������
				DWORD Foa_ImportByNameAddr = RvaToFileOffset(pFileBuffer, value);
				PDWORD Foa_pImportByNameAddr = (PDWORD)((DWORD)pFileBuffer + Foa_ImportByNameAddr);
				pImportByName = (PIMAGE_IMPORT_BY_NAME)Foa_pImportByNameAddr;
				printf("Import Hint\\Name:%#-4x ,%s\n", pImportByName->Hint, pImportByName->Name);
			}
			pOriginalFirstThunk++;
		}
		//��ӡFirstThunk
		DWORD Foa_FirstThunkAddr = RvaToFileOffset(pFileBuffer, pImportTable->FirstThunk);
		PDWORD Foa_pFirstThunkAddr = (PDWORD)((DWORD)pFileBuffer + Foa_FirstThunkAddr);
		printf("-------------------Foa_FirstThunkAddr:%#-17x -----------------------\n", Foa_FirstThunkAddr);
		pFirstThunk = (PIMAGE_THUNK_DATA)Foa_pFirstThunkAddr;
		while (*(PDWORD)pFirstThunk)
		{
			DWORD value = *(PDWORD)pFirstThunk;
			DWORD judge = (value & IMAGE_ORDINAL_FLAG32) >> 31;
			//���λΪ1������ŷ�ʽ���룻���λΪ0���Ժ�������ʽ����
			if (judge)
			{
				//�������
				value -= IMAGE_ORDINAL_FLAG32;
				printf("Import Ordinal  :%#-4x\n", value);
			}
			else
			{
				//��������
				DWORD Foa_ImportByNameAddr = RvaToFileOffset(pFileBuffer, value);
				PDWORD Foa_pImportByNameAddr = (PDWORD)((DWORD)pFileBuffer + Foa_ImportByNameAddr);
				pImportByName = (PIMAGE_IMPORT_BY_NAME)Foa_pImportByNameAddr;
				printf("Import Hint\Name:%#-4x ,%s\n", pImportByName->Hint, pImportByName->Name);
			}
			pFirstThunk++;
		}
		printf("\n");
		pImportTable++;
	}
}

DWORD DLLInject(PVOID pFileBuffer, PVOID* pNewFileBuffer, char* dllname, char* dllfunction)
{
	PVOID pAddSectionTemp = NULL;
	//����.exe��PE�ṹ
	DWORD ret_loc2 = ToLoaderPE(file_path, &pFileBuffer);
	
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_SECTION_HEADER pNewSection = NULL;
	PIMAGE_SECTION_HEADER pNewSectionHeader = NULL;
	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
	PIMAGE_DATA_DIRECTORY pDataDirectory_ImportTable = NULL;
	PIMAGE_IMPORT_DESCRIPTOR pImportTable = NULL;
	PIMAGE_IMPORT_DESCRIPTOR pNewImportTable = NULL;
	PIMAGE_IMPORT_BY_NAME  pImportByName = NULL;
	PIMAGE_THUNK_DATA pOriginalFirstThunk = NULL;
	PIMAGE_THUNK_DATA pFirstThunk = NULL;

	if (!pFileBuffer)
	{
		printf("(DLLInject_ToLoaderPE)Can't open file!\n");
		return 0;
	}

	if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)  // IMAGE_DOS_SIGNATURE��4�ֽڣ���pFileBufferǿ������ת��Ϊ4�ֽ�ָ�����ͣ�PWORD��
	{
		printf("(DLLInject_ToLoaderPE)No MZ flag, not exe file!\n");
		return 0;
	}

	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if (*((PDWORD)((DWORD)pFileBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("(DLLInject_ToLoaderPE)Not a valid PE flag!\n");
		return 0;
	}
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	//�жϿռ乻����
	if ((pOptionHeader->SizeOfHeaders - ((DWORD)pSectionHeader - (DWORD)pFileBuffer + pPEHeader->NumberOfSections * 40)) < size_surplus_sizeofheader)
	{
		printf("Insufficient.\n");
		return 0;
	}
	//�¼ӽڱ�
	pNewSection = (PIMAGE_SECTION_HEADER)(pSectionHeader + pPEHeader->NumberOfSections);
	//�޸��½�����
	memcpy(pNewSection->Name, ".addimp", 8);
	PIMAGE_SECTION_HEADER pLastSectionHeader = (PIMAGE_SECTION_HEADER)(pSectionHeader + (pPEHeader->NumberOfSections - 1));
	
	DWORD max = pLastSectionHeader->Misc.VirtualSize > pLastSectionHeader->SizeOfRawData ? pLastSectionHeader->Misc.VirtualSize : pLastSectionHeader->SizeOfRawData;

	pNewSection->VirtualAddress = pLastSectionHeader->VirtualAddress + max;
	pNewSection->Misc.VirtualSize = 0x1000;
	pNewSection->PointerToRawData = pLastSectionHeader->PointerToRawData + max;
	pNewSection->SizeOfRawData = 0x1000;
	pNewSection->Characteristics = 0xE0000060;
	//��ӽں���հ���40
	memset(pNewSection + 1, 0, 40);
	//�޸Ŀ�ѡͷ����׼ͷ��Ϣ
	pPEHeader->NumberOfSections += 1;
	pOptionHeader->SizeOfImage += 0x1000;
	DWORD AddSecTotal = pOptionHeader->SizeOfImage;
	pAddSectionTemp = malloc(AddSecTotal);
	//��ʼ���ڴ�
	memset(pAddSectionTemp, 0, AddSecTotal);
	memcpy(pAddSectionTemp, pFileBuffer, AddSecTotal);
	
	if (!pAddSectionTemp)
	{
		printf("(DLLInject)Can't open file!\n");
		return 0;
	}

	if (*((PWORD)pAddSectionTemp) != IMAGE_DOS_SIGNATURE)
	{
		printf("(DLLInject)No MZ flag, not exe file!\n");
		return 0;
	}

	pDosHeader = (PIMAGE_DOS_HEADER)pAddSectionTemp;
	if (*((PDWORD)((DWORD)pAddSectionTemp + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("(DLLInject)Not a valid PE flag!\n");
		return 0;
	}

	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pAddSectionTemp + pDosHeader->e_lfanew);
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 4); // �������ǿ������ת��
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	pNewSectionHeader = &pSectionHeader[pPEHeader->NumberOfSections - 1];
	pDataDirectory = (PIMAGE_DATA_DIRECTORY)pOptionHeader->DataDirectory;
	pDataDirectory_ImportTable = &pDataDirectory[1];

	if (!pDataDirectory_ImportTable->VirtualAddress)
	{
		printf("(DLLInject)This program has no import table.\n");
		return 0;
	}

	printf("Import Table Rva: %#x\n", pDataDirectory_ImportTable->VirtualAddress);
	DWORD Foa_ImportTable = RvaToFileOffset(pAddSectionTemp, pDataDirectory_ImportTable->VirtualAddress);
	printf("Import Table Foa: %#x\n", Foa_ImportTable);
	pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pAddSectionTemp + Foa_ImportTable);

	DWORD Rva_NewSectionAddr = pNewSectionHeader->PointerToRawData;
	DWORD Foa_NewSectionAddr = RvaToFileOffset(pAddSectionTemp, Rva_NewSectionAddr);
	PDWORD Foa_pNewSectionAddr = (PDWORD)((DWORD)pAddSectionTemp + Foa_NewSectionAddr);
	//�ƶ������
	memcpy((PVOID)Foa_pNewSectionAddr, (PVOID)pImportTable, pDataDirectory_ImportTable->Size);

	//�޸�Ŀ¼��
	pDataDirectory_ImportTable->VirtualAddress = Rva_NewSectionAddr;

	//�˻�һ�������Ĵ�С����Ϊ���һ�������ȫΪ0
	pNewImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)Foa_pNewSectionAddr + pDataDirectory_ImportTable->Size - sizeof(IMAGE_IMPORT_DESCRIPTOR));

	PIMAGE_THUNK_DATA pNewINT = (PIMAGE_THUNK_DATA)((DWORD)pNewImportTable + sizeof(IMAGE_IMPORT_DESCRIPTOR) * 2);//pNewImport->OriginalFirstThunkָ���INT��*2������һ�������ṹ��С�Ŀռ�ȫ0��ʾ������Ѿ�����
	PIMAGE_THUNK_DATA pNewIAT = (PIMAGE_THUNK_DATA)((DWORD)pNewINT + sizeof(IMAGE_THUNK_DATA) * 2);	//pNewImport->FirstThunkָ���IAT�� *2������һ��IMAGE_THUNK_DATA��С�Ŀռ�ȫ0��ʾpINT�Ѿ�����
	DWORD Rva_NewINTAddr = FoaToImageOffset(pAddSectionTemp, (DWORD)pNewINT - (DWORD)pAddSectionTemp);
	DWORD Rva_NewIATAddr = FoaToImageOffset(pAddSectionTemp, (DWORD)pNewIAT - (DWORD)pAddSectionTemp);


	//����dll����
	PDWORD pDLLName = (PDWORD)((DWORD)pNewIAT + sizeof(PIMAGE_THUNK_DATA) * 2);
	DWORD DLLName_Size = strlen(dllname) + 1;
	memcpy(pDLLName, dllname, DLLName_Size);

	pNewImportTable->Name = FoaToImageOffset(pAddSectionTemp, (DWORD)pDLLName - (DWORD)pAddSectionTemp);

	PIMAGE_IMPORT_BY_NAME pNewImportByName = (PVOID)((DWORD)pDLLName + DLLName_Size);
	DWORD Rva_NewImportByNameAddr = FoaToImageOffset(pAddSectionTemp, (DWORD)pNewImportByName - (DWORD)pAddSectionTemp);

	//���ƺ�������
	PDWORD pDLLFunName = (PDWORD)((DWORD)pNewImportByName + 2);
	pNewImportByName->Hint = 0;
	DWORD DLLFunName_Size = strlen(dllfunction) + 1;
	memcpy(pDLLFunName, dllfunction, DLLFunName_Size);

	pNewImportTable->OriginalFirstThunk = Rva_NewINTAddr;
	printf("pNewImport->OriginalFirstThunk:%#X\n", pNewImportTable->OriginalFirstThunk);

	pNewImportTable->FirstThunk = Rva_NewIATAddr;
	printf("pNewImport->FirstThunk:%#X\n", pNewImportTable->FirstThunk);
	pNewINT->u1.AddressOfData = Rva_NewImportByNameAddr;
	pNewIAT->u1.AddressOfData = Rva_NewImportByNameAddr;

	DWORD ret_loc4 = MemoryToFile(pAddSectionTemp, AddSecTotal, write_dllinject_file_path);
	if (!ret_loc4)
	{
		printf("(DLLInject)Store memory failed.\n");
		return 0;
	}

	*pNewFileBuffer = pAddSectionTemp;
	return AddSecTotal;
}

VOID operate()
{
	PVOID pFileBuffer = NULL;
	PVOID pNewFileBuffer = NULL;
	PVOID pImageBuffer = NULL;

	DWORD ret6 = DLLInject(pFileBuffer, &pNewFileBuffer, dllname, dllfunction);
	printf("DLLInject: %#x\n", ret6);
	free(pFileBuffer);
	free(pNewFileBuffer);
	free(pImageBuffer);
}

int main()
{
	operate();
	getchar();
	return 0;
}