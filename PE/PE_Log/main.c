#include<stdio.h>
#include<stdlib.h>
#include<windows.h>

#define test 1

DWORD ToLoaderPE(LPSTR file_path, PVOID* pFileBuffer);
BOOL MemoryToFile(PVOID pMemBuffer, DWORD size, LPSTR lpszFile);
DWORD FoaToImageOffset(PVOID pBuffer, DWORD dwFoa);
DWORD RvaToFileOffset(PVOID pBuffer, DWORD dwRva);
DWORD GetSctionEmptySpace(PVOID pFileBuffer, DWORD SectionOrdinal);
DWORD Alignment(DWORD alignment_value, DWORD addend, DWORD address);
VOID LogPEHeaderInfo(PVOID pFileBuffer);
VOID LogExportTable(PVOID pFileBuffer);
VOID LogBaseRelocationTable(PVOID pFileBuffer);
VOID LogImportTable(PVOID pFileBuffer);
VOID LogBoundImportTable(PVOID pFileBuffer);

char file_path[] = "c:\\users\\desktop\\dll1test.dll";

char write_file_path[] = "D:\\Lib\\cp_XX.exe";
char write_adddata_file_path[] = "D:\\Lib\\cp_adddata_XX.exe";
char write_addsec_file_path[] = "D:\\Lib\\cp_addsec_XX.exe";
char write_enlargersec_file_path[] = "D:\\Lib\\cp_enlargersec_XX.exe";
char write_mergesec_file_path[] = "D:\\Lib\\cp_mergesec_XX.exe";

//返回PE文件大小
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
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 4); // 这里必须强制类型转换
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	PIMAGE_SECTION_HEADER pSectionTemp = pSectionHeader;

	if (dwRva <= pOptionHeader->SizeOfHeaders)
		return (DWORD)dwRva;
	else
	{
		for (int n = 0; n < pPEHeader->NumberOfSections; n++, pSectionTemp++)
		{	//判断 :   文件对齐+文件偏移>file_panyi>文件偏移  (即是在文件的哪个节中)
			if ((dwRva >= pSectionTemp->VirtualAddress) && (dwRva < pSectionTemp->VirtualAddress + pSectionTemp->Misc.VirtualSize))
			{
				return dwRva - pSectionTemp->VirtualAddress + pSectionTemp->PointerToRawData;
			}
		}
	}
	printf("RvaToFoa failed！\n");
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
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 4); // 这里必须强制类型转换
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	PIMAGE_SECTION_HEADER pSectionTemp = pSectionHeader;

	if (dwFoa <= pOptionHeader->SizeOfHeaders)
		return (DWORD)dwFoa;
	else
	{
		for (int n = 0; n < pPEHeader->NumberOfSections; n++, pSectionTemp++)
		{	//判断 :   文件对齐+文件偏移>file_panyi>文件偏移  (即是在文件的哪个节中)
			if ((dwFoa >= pSectionTemp->PointerToRawData) && (dwFoa < pSectionTemp->PointerToRawData + pSectionTemp->SizeOfRawData))
			{
				return dwFoa - pSectionTemp->PointerToRawData + pSectionTemp->VirtualAddress;
			}
		}
	}
	printf("FoaToRva failed！\n");
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
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 4); // 这里必须强制类型转换
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

	//判断是否是有效的MZ标志	
	if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("(LogPEHeaderInfo)No MZ flag, not exe file!\n");
		free(pFileBuffer);
		return;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	//打印DOC头	
	printf("\n********************DOS头********************\n");
	printf("MZ flag：%#x\n", pDosHeader->e_magic);
	printf("PE offset：%#x\n", pDosHeader->e_lfanew);
	//判断是否是有效的PE标志	
	if (*((PDWORD)((DWORD)pFileBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("(LogPEHeaderInfo)Not a valid PE flag!\n");
		free(pFileBuffer);
		return;
	}
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
	//打印NT头	
	printf("********************NT头********************\n");
	printf("NT：%#x\n", pNTHeader->Signature);
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);

	//int NumberOfSections = pPEHeader->NumberOfSections;
	//int SizeOfOptionalHeader = pPEHeader->SizeOfOptionalHeader;

	printf("********************PE头********************\n");
	printf("PE：%#x\n", pPEHeader->Machine);
	printf("Section number：%#x\n", pPEHeader->NumberOfSections);
	printf("SizeOfOptionalHeader：%#x\n", pPEHeader->SizeOfOptionalHeader);
	//可选PE头	
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	printf("********************OPTIOIN_PE头********************\n");
	printf("OPTION_PE：%#x\n", pOptionHeader->Magic);

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

VOID LogExportTable(PVOID pFileBuffer)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;

	if (!pFileBuffer)
	{
		printf("(LogExportTable)Can't open file!\n");
		return 0;
	}

	if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("(LogExportTable)No MZ flag, not exe file!\n");
		return 0;
	}

	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if (*((PDWORD)((DWORD)pFileBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("(LogExportTable)Not a valid PE flag!\n");
		return 0;
	}

	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 4); // 这里必须强制类型转换
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	pDataDirectory = (PIMAGE_DATA_DIRECTORY)pOptionHeader->DataDirectory;

	if (!pDataDirectory->VirtualAddress)
	{
		printf("(LogExportTable)This program has no export table.\n");
		return 0;
	}

	printf("Export Table Rva: %#x\n", pDataDirectory->VirtualAddress);

	DWORD Foa_ExportTable = RvaToFileOffset(pFileBuffer, pDataDirectory->VirtualAddress);

	printf("Export Table Foa: %#x\n", Foa_ExportTable);

	pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pFileBuffer + Foa_ExportTable);

	printf("Characteristics: %#x\n", pExportDirectory->Characteristics);
	printf("TimeDateStamp: %#x\n", pExportDirectory->TimeDateStamp);
	printf("MajorVersion: %#x\n", pExportDirectory->MajorVersion);
	printf("MinorVersion: %#x\n", pExportDirectory->MinorVersion);
	printf("Name: %s\n", (PVOID)((DWORD)pFileBuffer+RvaToFileOffset(pFileBuffer, pExportDirectory->Name)));
	printf("Base: %#x\n", pExportDirectory->Base);
	printf("NumberOfFunctions: %#x\n", pExportDirectory->NumberOfFunctions);
	printf("NumberOfNames: %#x\n", pExportDirectory->NumberOfNames);
	printf("AddressOfFunctions: %#x\n", pExportDirectory->AddressOfFunctions);
	printf("AddressOfNames: %#x\n", pExportDirectory->AddressOfNames);
	printf("AddressOfNameOrdinals: %#x\n", pExportDirectory->AddressOfNameOrdinals);
}

VOID LogBaseRelocationTable(PVOID pFileBuffer)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
	PIMAGE_BASE_RELOCATION pRelocationTable = NULL;

	if (!pFileBuffer)
	{
		printf("(LogBaseRelocationTable)Can't open file!\n");
		return 0;
	}

	if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("(LogBaseRelocationTable)No MZ flag, not exe file!\n");
		return 0;
	}

	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if (*((PDWORD)((DWORD)pFileBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("(LogBaseRelocationTable)Not a valid PE flag!\n");
		return 0;
	}

	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 4); // 这里必须强制类型转换
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	pDataDirectory = (PIMAGE_DATA_DIRECTORY)pOptionHeader->DataDirectory;

	PIMAGE_DATA_DIRECTORY pDataDirectory_RelocTable = &pDataDirectory[5];

	if (!pDataDirectory_RelocTable->VirtualAddress)
	{
		printf("This program has no relocation table.\n");
		return 0;
	}

	DWORD Foa_RelocationTable = RvaToFileOffset(pFileBuffer, pDataDirectory_RelocTable->VirtualAddress);

	if (!test)
	{
		printf("Relocation Table Rva: %#x\n", pDataDirectory_RelocTable->VirtualAddress);
		printf("Relocation Table Foa: %#x\n", Foa_RelocationTable);
		printf("pFileBuffer: %#x\n", (DWORD)pFileBuffer);
		printf("Relocation Table in this moment: %#x\n", (DWORD)pFileBuffer + Foa_RelocationTable);
	}

	pRelocationTable = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pFileBuffer + Foa_RelocationTable);
	printf("pRelocationTable: %#x\n", (DWORD)pRelocationTable);

	for (DWORD n = 0; pRelocationTable->VirtualAddress != IMAGE_REL_BASED_ABSOLUTE; n++)
	{
		printf(".....................RelocationTable %#5xth.................................\n", n + 1);
		DWORD arrNumber = (pRelocationTable->SizeOfBlock - 8) / 2;

		printf("TypeOffset Number: %#x\n", arrNumber);

		PWORD pTypeOffset = (PWORD)((PDWORD)pRelocationTable + 2);

		for (DWORD i = 0; i < arrNumber; i++)
		{
			printf("pTypeOffset: %#-10x", (WORD)pTypeOffset);
			WORD TypeOffset = *pTypeOffset;

			if (!test)
			{
				printf("TypeOffset(011) = %#x\n", TypeOffset);
			}
			BYTE attribute = (TypeOffset & 0b11000000000000) >> 12;

			TypeOffset = (TypeOffset & 0b111111111111);
			if (!test)
			{
				printf("TypeOffset(000) = %#x\n", TypeOffset);
			}
			printf("Attribute: %-5x", attribute);
			DWORD Offset = pRelocationTable->VirtualAddress + (DWORD)TypeOffset;
			printf("Rva_BaseRelocation: %#-10x", Offset);
			printf("Foa_BaseRelocation: %#-10x\n", RvaToFileOffset(pFileBuffer, Offset));
			pTypeOffset++;
		}
		pRelocationTable = (PDWORD)((DWORD)pRelocationTable + pRelocationTable->SizeOfBlock);
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
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 4); // 这里必须强制类型转换
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

	//遍历dll模块
	while (pImportTable->Name != 0)
	{
		//打印dll模块名
		DWORD Foa_DllName = RvaToFileOffset(pFileBuffer, pImportTable->Name);
		PDWORD Foa_pDllName = (PDWORD)((DWORD)pFileBuffer + Foa_DllName);
		printf("%s\n", Foa_pDllName);
		//打印OriginalFirstThunk
		DWORD Foa_OrginalFirstThunkAddr = RvaToFileOffset(pFileBuffer, pImportTable->OriginalFirstThunk);
		PDWORD Foa_pOrginalFirstThunkAddr = (PDWORD)((DWORD)pFileBuffer + Foa_OrginalFirstThunkAddr);
		printf("-------------------Foa_OrginalFirstThunkAddr:%#-10x -----------------------\n", Foa_OrginalFirstThunkAddr);
		pOriginalFirstThunk = (PIMAGE_THUNK_DATA)Foa_pOrginalFirstThunkAddr;
		
		while (*(PDWORD)pOriginalFirstThunk)
		{
			DWORD value = *(PDWORD)pOriginalFirstThunk;
			DWORD judge = (value & IMAGE_ORDINAL_FLAG32) >> 31;
			//最高位为1，以序号方式输入；最高位为0，以函数名方式输入
			if (judge)
			{
				//输入序号
				value -= IMAGE_ORDINAL_FLAG32;
				printf("Import Ordinal  :%#-4x\n", value);
			}
			else
			{
				//输入名字
				DWORD Foa_ImportByNameAddr = RvaToFileOffset(pFileBuffer, value);
				PDWORD Foa_pImportByNameAddr = (PDWORD)((DWORD)pFileBuffer + Foa_ImportByNameAddr);
				pImportByName = (PIMAGE_IMPORT_BY_NAME)Foa_pImportByNameAddr;
				printf("Import Hint\\Name:%#-4x ,%s\n", pImportByName->Hint, pImportByName->Name);
			}
			pOriginalFirstThunk++;
		}
		//打印FirstThunk
		DWORD Foa_FirstThunkAddr = RvaToFileOffset(pFileBuffer, pImportTable->FirstThunk);
		PDWORD Foa_pFirstThunkAddr = (PDWORD)((DWORD)pFileBuffer + Foa_FirstThunkAddr);
		printf("-------------------Foa_FirstThunkAddr:%#-17x -----------------------\n", Foa_FirstThunkAddr);
		pFirstThunk = (PIMAGE_THUNK_DATA)Foa_pFirstThunkAddr;
		while (*(PDWORD)pFirstThunk)
		{
			DWORD value = *(PDWORD)pFirstThunk;
			DWORD judge = (value & IMAGE_ORDINAL_FLAG32) >> 31;
			//最高位为1，以序号方式输入；最高位为0，以函数名方式输入
			if (judge)
			{
				//输入序号
				value -= IMAGE_ORDINAL_FLAG32;
				printf("Import Ordinal  :%#-4x\n", value);
			}
			else
			{
				//输入名字
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

VOID LogBoundImportTable(PVOID pFileBuffer)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
	PIMAGE_DATA_DIRECTORY pDataDirectory_BoundImportTable = NULL;
	PIMAGE_BOUND_IMPORT_DESCRIPTOR pBoundImportTable = NULL;

	if (!pFileBuffer)
	{
		printf("(LogBoundImportTable)Can't open file!\n");
		return 0;
	}

	if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("(LogBoundImportTable)No MZ flag, not exe file!\n");
		return 0;
	}

	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if (*((PDWORD)((DWORD)pFileBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("(LogBoundImportTable)Not a valid PE flag!\n");
		return 0;
	}

	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 4); // 这里必须强制类型转换
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	pDataDirectory = (PIMAGE_DATA_DIRECTORY)pOptionHeader->DataDirectory;
	pDataDirectory_BoundImportTable = pDataDirectory + 11;

	if (!pDataDirectory_BoundImportTable->VirtualAddress)
	{
		printf("(LogBoundImportTable)This program has no bound import table.\n");
		return 0;
	}

	printf("Bound Import Table Rva: %#x\n", pDataDirectory_BoundImportTable->VirtualAddress);
	DWORD Foa_ImportTable = RvaToFileOffset(pFileBuffer, pDataDirectory_BoundImportTable->VirtualAddress);
	printf("Bound Import Table Foa: %#x\n", Foa_ImportTable);
	pBoundImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pFileBuffer + Foa_ImportTable);

	DWORD BoundImportTableBase = (DWORD)pBoundImportTable;

	while (*(PDWORD)pBoundImportTable)
	{
		PDWORD pOffsetModuleName = (PDWORD)(BoundImportTableBase + pBoundImportTable->OffsetModuleName);
		printf("Module Name :%s\n", pOffsetModuleName);
		pBoundImportTable++;
	}
}

VOID operate()
{
	PVOID pFileBuffer = NULL;
	PVOID pNewFileBuffer = NULL;
	PVOID pImageBuffer = NULL;

	DWORD ret1 = ToLoaderPE(file_path, &pFileBuffer);  // &pFileBuffer(void**类型) 传递地址对其值可以进行修改
	printf("exe->filebuffer  返回值为计算所得文件大小：%#x\n", ret1);

	LogPEHeaderInfo(pFileBuffer);
	LogExportTable(pFileBuffer);
	LogBaseRelocationTable(pFileBuffer);
	LogImportTable(pFileBuffer);
	LogBoundImportTable(pFileBuffer);

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