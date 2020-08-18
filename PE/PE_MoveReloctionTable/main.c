#include<stdio.h>
#include<stdlib.h>
#include<windows.h>

#define test 1
#define size_surplus_sizeofheader 0x50

DWORD ToLoaderPE(LPSTR file_path, PVOID* pFileBuffer);
BOOL MemoryToFile(PVOID pMemBuffer, DWORD size, LPSTR lpszFile);
DWORD FoaToImageOffset(PVOID pBuffer, DWORD dwFoa);
DWORD RvaToFileOffset(PVOID pBuffer, DWORD dwRva);
DWORD GetSctionEmptySpace(PVOID pFileBuffer, DWORD SectionOrdinal);
DWORD Alignment(DWORD alignment_value, DWORD addend, DWORD address);
DWORD SizeOfBaseRelocationTable(PVOID pFileBuffer);
DWORD MoveBaseRelocationTable(PVOID pFileBuffer, DWORD FileBuffer, PVOID* pFileBuffer_ExportTable);
VOID LogBaseRelocationTable(PVOID pFileBuffer);

char file_path[] = "c:\\users\\desktop\\dll1test.dll";

char write_movreloctable_file_path[] = "D:\\Lib\\dll1test.dll";

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


DWORD SizeOfBaseRelocationTable(PVOID pFileBuffer)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
	PIMAGE_BASE_RELOCATION pRelocationTable = NULL;
	DWORD SizeOfBaseRelocationTableSectionTotal = 0;

	if (!pFileBuffer)
	{
		printf("(SizeOfBaseRelocationTable)Can't open file!\n");
		return 0;
	}

	if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("(SizeOfBaseRelocationTable))No MZ flag, not exe file!\n");
		return 0;
	}

	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if (*((PDWORD)((DWORD)pFileBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("(SizeOfBaseRelocationTable)Not a valid PE flag!\n");
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

	pRelocationTable = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pFileBuffer + Foa_RelocationTable);

	for (DWORD n = 0; pRelocationTable->VirtualAddress != IMAGE_REL_BASED_ABSOLUTE; n++)
	{
		SizeOfBaseRelocationTableSectionTotal += pRelocationTable->SizeOfBlock;
		pRelocationTable = (PDWORD)((DWORD)pRelocationTable + pRelocationTable->SizeOfBlock);
	}

	SizeOfBaseRelocationTableSectionTotal = Alignment(pOptionHeader->SectionAlignment, SizeOfBaseRelocationTableSectionTotal, 0);

	return SizeOfBaseRelocationTableSectionTotal;
}


DWORD MoveBaseRelocationTable(PVOID pFileBuffer, DWORD FileBuffer, PVOID* pFileBuffer_ExportTable)
{
	//未加载pMoveExportTableTemp，所以用pFileBuffer得到pOptionHeaderFileBuffer->SectionAlignment
	PIMAGE_DOS_HEADER pDosHeaderFileBuffer = NULL;
	PIMAGE_NT_HEADERS pNTHeaderFileBuffer = NULL;
	PIMAGE_FILE_HEADER pPEHeaderFileBuffer = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeaderFileBuffer = NULL;
	pDosHeaderFileBuffer = (PIMAGE_DOS_HEADER)pFileBuffer;
	pNTHeaderFileBuffer = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeaderFileBuffer->e_lfanew);
	pPEHeaderFileBuffer = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeaderFileBuffer) + 4);
	pOptionHeaderFileBuffer = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeaderFileBuffer + IMAGE_SIZEOF_FILE_HEADER);

	PVOID pMoveBaseRelocationTableTemp = NULL;
	DWORD SizeBaseRelocationTableSection = SizeOfBaseRelocationTable(pFileBuffer);
	size_t AddSecTotal = FileBuffer + SizeBaseRelocationTableSection;

	if (!test)
	{
		printf("SizeBaseRelocationTableSection: %#x\n", SizeBaseRelocationTableSection);
		printf("pFileBuffer: %#x\n", FileBuffer);
		printf("pOptionHeaderFileBuffer->SizeOfImage: %#x\n", pOptionHeaderFileBuffer->SizeOfImage);
		printf("AddSecTotal: %#x\n", AddSecTotal);
		printf("NTHeader->OptionalHeader.SizeOfImage + SizeOfSection: %#x\n", pOptionHeaderFileBuffer->SizeOfImage + SizeBaseRelocationTableSection);
	}

	//内存对齐
	AddSecTotal = Alignment(pOptionHeaderFileBuffer->SectionAlignment, AddSecTotal, 0);

	if (!test)
	{
		printf("pFileBuffer: %#x\n", FileBuffer);
		printf("pFileBufferAddSecTotal: %#x\n", AddSecTotal);
	}

	pMoveBaseRelocationTableTemp = malloc(AddSecTotal);

	if (!pMoveBaseRelocationTableTemp)
	{
		printf("(MoveBaseRelocationTable)Allocate dynamic memory failed!\n");
		return 0;
	}

	memset(pMoveBaseRelocationTableTemp, 0, AddSecTotal);
	memcpy(pMoveBaseRelocationTableTemp, pFileBuffer, FileBuffer);

	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
	PIMAGE_BASE_RELOCATION pRelocationTable = NULL;

	if (!pMoveBaseRelocationTableTemp)
	{
		printf("(MoveBaseRelocationTable)Can't open file!\n");
		return;
	}

	if (*((PWORD)pMoveBaseRelocationTableTemp) != IMAGE_DOS_SIGNATURE)
	{
		printf("(MoveBaseRelocationTable))No MZ flag, not exe file!\n");
		free(pMoveBaseRelocationTableTemp);
		return;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pMoveBaseRelocationTableTemp;
	
	if (*((PDWORD)((DWORD)pMoveBaseRelocationTableTemp + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("(MoveBaseRelocationTable)Not a valid PE flag!\n");
		free(pMoveBaseRelocationTableTemp);
		return;
	}
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pMoveBaseRelocationTableTemp + pDosHeader->e_lfanew);
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	pDataDirectory = (PIMAGE_DATA_DIRECTORY)pOptionHeader->DataDirectory;
	PIMAGE_DATA_DIRECTORY pDataDirectory_RelocTable = &pDataDirectory[5];

	PIMAGE_SECTION_HEADER pSectionHeaderTemp = pSectionHeader;

	for (DWORD i = 0; i < pPEHeader->NumberOfSections; i++, pSectionHeaderTemp++)
	{
		//
	}

	//加节
	if (size_surplus_sizeofheader <= (pOptionHeader->SizeOfHeaders - ((DWORD)(pSectionHeaderTemp - pMoveBaseRelocationTableTemp))))
	{
		//printf("Enough.\n");
		//得到最后一个节的信息
		pSectionHeaderTemp--;
		PIMAGE_SECTION_HEADER pLastSectionHeader = pSectionHeaderTemp;

		//填充节	
		//改节数目
		pPEHeader->NumberOfSections = pPEHeader->NumberOfSections + 1;
		//填充节表
		pSectionHeaderTemp++;
		memcpy(pSectionHeaderTemp, pSectionHeader, IMAGE_SIZEOF_SECTION_HEADER);
		memcpy(pSectionHeaderTemp, ".movRel", 8);

		pSectionHeaderTemp->VirtualAddress = pLastSectionHeader->VirtualAddress + pLastSectionHeader->Misc.VirtualSize;
		pSectionHeaderTemp->SizeOfRawData = SizeBaseRelocationTableSection;
		pSectionHeaderTemp->PointerToRawData = pLastSectionHeader->PointerToRawData + pLastSectionHeader->SizeOfRawData;
		pSectionHeaderTemp->Misc.VirtualSize = SizeBaseRelocationTableSection;
		pOptionHeader->SizeOfImage = pOptionHeaderFileBuffer->SizeOfImage + SizeBaseRelocationTableSection;

		pSectionHeaderTemp->VirtualAddress = Alignment(pOptionHeaderFileBuffer->SectionAlignment, pSectionHeaderTemp->VirtualAddress, 0);
		pSectionHeaderTemp->VirtualAddress = Alignment(pOptionHeaderFileBuffer->FileAlignment, pSectionHeaderTemp->PointerToRawData, 0);
	}
	else
	{
		free(pMoveBaseRelocationTableTemp);
		printf("Insufficient.\n");
	}

	if (!pDataDirectory_RelocTable->VirtualAddress)
	{
		printf("This program has no relocation table.\n");
		return 0;
	}

	printf("Relocation Table Rva: %#x\n", pDataDirectory_RelocTable->VirtualAddress);
	DWORD Foa_RelocationTable = RvaToFileOffset(pMoveBaseRelocationTableTemp, pDataDirectory_RelocTable->VirtualAddress);
	printf("Relocation Table Foa: %#x\n", Foa_RelocationTable);
	pRelocationTable = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pMoveBaseRelocationTableTemp + Foa_RelocationTable);
	PVOID pAddInsSction = (PDWORD)((DWORD)pMoveBaseRelocationTableTemp + pSectionHeaderTemp->PointerToRawData);

	memcpy(pAddInsSction, pRelocationTable, pDataDirectory_RelocTable->Size);

	DWORD NewpRelocationTable = pAddInsSction;
	PIMAGE_BASE_RELOCATION pNewpRelocationTable = (PIMAGE_BASE_RELOCATION)pAddInsSction;

	if (!test)
	{
		printf("The starting address of the new section：%#x\n", ((DWORD)pMoveBaseRelocationTableTemp + pSectionHeaderTemp->PointerToRawData));
	}

	//测试功能：修改imagebase
	DWORD ImageBaseOrg = pOptionHeader->ImageBase;
	pOptionHeader->ImageBase += 0x10000000;
	DWORD ImageBaseNew = pOptionHeader->ImageBase;

	for (DWORD n = 0; pNewpRelocationTable->VirtualAddress != IMAGE_REL_BASED_ABSOLUTE; n++)
	{
		printf(".....................RelocationTable %#5xth.................................\n", n + 1);
		DWORD arrNumber = (pNewpRelocationTable->SizeOfBlock - 8) / 2;
		printf("TypeOffset Number: %#x\n", arrNumber);
		PDWORD pTypeOffsetOrg = ((PDWORD)pNewpRelocationTable + 2);
		PWORD pTypeOffset = (PWORD)pTypeOffsetOrg;
		for (DWORD i = 0; i < arrNumber; i++)
		{
			//printf("pTypeOffset: %#-10x", (WORD)pTypeOffset);
			WORD TypeOffset = *pTypeOffset;
			TypeOffset = (TypeOffset & 0b111111111111);
			DWORD OffsetOrg = pNewpRelocationTable->VirtualAddress + (DWORD)TypeOffset;
			//printf("Rva_BaseRelocation: %#-10x", OffsetOrg);
			DWORD Foa_OffsetOrg = RvaToFileOffset(pMoveBaseRelocationTableTemp, OffsetOrg);
			PDWORD pFoa_Offset = (PDWORD)((DWORD)pMoveBaseRelocationTableTemp + Foa_OffsetOrg);
			printf("改基址前Foa_BaseRelocation: %#-10x   ", *pFoa_Offset);
			*pFoa_Offset = *pFoa_Offset - ImageBaseOrg + ImageBaseNew;
			printf("改基址后Foa_BaseRelocation: %#-10x\n", *pFoa_Offset);
			pTypeOffset++;
		}
		pNewpRelocationTable = (PDWORD)((DWORD)pNewpRelocationTable + pNewpRelocationTable->SizeOfBlock);
	}

	//修改数据目录表信息
	pDataDirectory_RelocTable->VirtualAddress = FoaToImageOffset(pMoveBaseRelocationTableTemp, NewpRelocationTable - (DWORD)pMoveBaseRelocationTableTemp);

	size_t ret_loc6 = MemoryToFile(pMoveBaseRelocationTableTemp, AddSecTotal, write_movreloctable_file_path);
	if (!ret_loc6)
	{
		printf("(MoveRelocationTable)store memory failed.\n");
		return 0;
	}

	*pFileBuffer_ExportTable = pMoveBaseRelocationTableTemp; //暂存的数据传给参数后释放
	free(pMoveBaseRelocationTableTemp);
	pMoveBaseRelocationTableTemp = NULL;

	return AddSecTotal;
}

VOID operate()
{
	PVOID pFileBuffer = NULL;
	PVOID pNewFileBuffer = NULL;
	PVOID pImageBuffer = NULL;

	DWORD ret1 = ToLoaderPE(file_path, &pFileBuffer);  // &pFileBuffer(void**类型) 传递地址对其值可以进行修改
	printf("exe->filebuffer  返回值为计算所得文件大小：%#x\n", ret1);


	DWORD ret13 = MoveBaseRelocationTable(pFileBuffer, ret1, &pNewFileBuffer);
	printf("SizeOfRelocationTableSection: %#x\n", ret13);

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