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
DWORD MoveExportTable(PVOID pFileBuffer, DWORD FileBuffer, PVOID* pFileBuffer_ExportTable);
DWORD SizeOfExportTableSection(PVOID pFileBuffer);
VOID LogExportTable(PVOID pFileBuffer);


char file_path[] = "c:\\users\\desktop\\dll1test.dll";

char write_movexportable_file_path[] = "D:\\Lib\\dll1test.dll";

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
	printf("Name: %s\n", (PVOID)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, pExportDirectory->Name)));
	printf("Base: %#x\n", pExportDirectory->Base);
	printf("NumberOfFunctions: %#x\n", pExportDirectory->NumberOfFunctions);
	printf("NumberOfNames: %#x\n", pExportDirectory->NumberOfNames);
	printf("AddressOfFunctions: %#x\n", pExportDirectory->AddressOfFunctions);
	printf("AddressOfNames: %#x\n", pExportDirectory->AddressOfNames);
	printf("AddressOfNameOrdinals: %#x\n", pExportDirectory->AddressOfNameOrdinals);
}

DWORD SizeOfExportTableSection(PVOID pFileBuffer)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;
	DWORD SizeOfExportTableSectionTotal = 0;

	if (!pFileBuffer)
	{
		printf("(SizeOfExportTableSection)Can't open file!\n");
		return 0;
	}

	if (*((PWORD)(pFileBuffer)) != IMAGE_DOS_SIGNATURE)
	{
		printf("(SizeOfExportTableSection)No MZ flag, not exe file!\n");
		return 0;
	}

	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if (*((PDWORD)((DWORD)pFileBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("(SizeOfExportTableSection)Not a valid PE flag!\n");
		return 0;
	}

	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 4); // 这里必须强制类型转换
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	pDataDirectory = (PIMAGE_DATA_DIRECTORY)pOptionHeader->DataDirectory;

	if (!pDataDirectory->VirtualAddress)
	{
		printf("This program has no export table.\n");
		return 0;
	}

	DWORD Foa_ExportTable = RvaToFileOffset(pFileBuffer, pDataDirectory->VirtualAddress);

	if (!test)
	{
		printf("Export Table Rva: %#x\n", pDataDirectory->VirtualAddress);
		printf("Export Table Foa: %#x\n", Foa_ExportTable);
	}

	pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pFileBuffer + Foa_ExportTable);


	//size输出表
	SizeOfExportTableSectionTotal += 40;
	//size AddressOfFunctions
	SizeOfExportTableSectionTotal += (4 * pExportDirectory->NumberOfFunctions);
	//size AddressOfNames
	SizeOfExportTableSectionTotal += (4 * pExportDirectory->NumberOfNames);
	//size AddressOfNameOrdinals
	SizeOfExportTableSectionTotal += (2 * pExportDirectory->NumberOfNames);

	//size Function Name string in AddressOfNames
	DWORD Foa_AddressOfNames = RvaToFileOffset(pFileBuffer, pExportDirectory->AddressOfNames);

	if (!test)
	{
		DWORD test1 = Foa_AddressOfNames + (DWORD)pFileBuffer;
		printf("AddressOfNames in this moment: %#x\n", test1);
		printf("Foa__AddressOfNames: %#x\n", Foa_AddressOfNames);
	}

	DWORD namestringSizeTotal = 0;
	for (DWORD i = 0; i < pExportDirectory->NumberOfNames; i++)
	{
		DWORD nameOffset = *(PDWORD)((DWORD)pFileBuffer + (DWORD)((LPDWORD)Foa_AddressOfNames + i));
		LPSTR nameAddr = (LPSTR)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, nameOffset));
		//strlen得到每个函数名的长度，strlen不包含"\0",因此+1
		DWORD namestringSize = strlen(nameAddr) + 1;
		namestringSizeTotal += namestringSize;
	}
	SizeOfExportTableSectionTotal += namestringSizeTotal;

	printf("SizeOfExportTableSectionTotal: %#x\n", SizeOfExportTableSectionTotal);

	SizeOfExportTableSectionTotal = Alignment(pOptionHeader->SectionAlignment, SizeOfExportTableSectionTotal, 0);

	return SizeOfExportTableSectionTotal;
}

DWORD MoveExportTable(PVOID pFileBuffer, DWORD FileBuffer, PVOID* pFileBuffer_ExportTable)
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

	LPVOID pMoveExportTableTemp = NULL;
	DWORD SizeExportTableSection = SizeOfExportTableSection(pFileBuffer);
	size_t AddSecTotal = FileBuffer + SizeExportTableSection;

	if (!test)
	{
		printf("SizeExportTableSection: %#x\n", SizeExportTableSection);
		printf("pFileBuffer: %#x\n", FileBuffer);
		printf("pOptionHeaderFileBuffer->SizeOfImage: %#x\n", pOptionHeaderFileBuffer->SizeOfImage);
		printf("pFileBufferAddSecTotal: %#x\n", AddSecTotal);
		printf("NTHeader->OptionalHeader.SizeOfImage + SizeOfSection: %#x\n", pOptionHeaderFileBuffer->SizeOfImage + SizeExportTableSection);
	}

	//内存对齐
	AddSecTotal = Alignment(pOptionHeaderFileBuffer->SectionAlignment, AddSecTotal, 0);

	if (!test)
	{
		printf("pFileBuffer: %#x\n", FileBuffer);
		printf("pFileBufferAddSecTotal: %#x\n", AddSecTotal);
	}

	pMoveExportTableTemp = malloc(AddSecTotal);

	if (!pMoveExportTableTemp)
	{
		printf("(MoveExportTable)Allocate dynamic memory failed!\n");
		return 0;
	}

	memset(pMoveExportTableTemp, 0, AddSecTotal);
	memcpy(pMoveExportTableTemp, pFileBuffer, FileBuffer);

	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;

	if (!pMoveExportTableTemp)
	{
		printf("(MoveExportTable)Can't open file!\n");
		return;
	}

	if (*((PWORD)pMoveExportTableTemp) != IMAGE_DOS_SIGNATURE)
	{
		printf("(MoveExportTable)No MZ flag, not exe file!\n");
		free(pMoveExportTableTemp);
		return;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pMoveExportTableTemp;
	
	if (*((PDWORD)((DWORD)pMoveExportTableTemp + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("(MoveExportTable)Not a valid PE flag!\n");
		free(pMoveExportTableTemp);
		return;
	}
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pMoveExportTableTemp + pDosHeader->e_lfanew);
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	pDataDirectory = (PIMAGE_DATA_DIRECTORY)pOptionHeader->DataDirectory;

	PIMAGE_SECTION_HEADER pSectionHeaderTemp = pSectionHeader;

	for (DWORD i = 0; i < pPEHeader->NumberOfSections; i++, pSectionHeaderTemp++)
	{
		//
	}

	//加节
	if (size_surplus_sizeofheader <= (pOptionHeader->SizeOfHeaders - ((DWORD)(pSectionHeaderTemp - pMoveExportTableTemp))))
	{
		//得到最后一个节的信息
		pSectionHeaderTemp--;
		PIMAGE_SECTION_HEADER pLastSectionHeader = pSectionHeaderTemp;

		//填充节	
		//memset(((PBYTE)(DWORD)pMoveExportTableTemp + ret_loc3), 0, SizeOfExportTableSection(&pFileBuffer));
		//改节数目
		pPEHeader->NumberOfSections = pPEHeader->NumberOfSections + 1;
		//填充节表
		pSectionHeaderTemp++;
		memcpy(pSectionHeaderTemp, pSectionHeader, IMAGE_SIZEOF_SECTION_HEADER);
		memcpy(pSectionHeaderTemp, ".movExp", 8);

		pSectionHeaderTemp->VirtualAddress = pLastSectionHeader->VirtualAddress + pLastSectionHeader->Misc.VirtualSize;
		pSectionHeaderTemp->SizeOfRawData = SizeExportTableSection;
		pSectionHeaderTemp->PointerToRawData = pLastSectionHeader->PointerToRawData + pLastSectionHeader->SizeOfRawData;
		pSectionHeaderTemp->Misc.VirtualSize = SizeExportTableSection;
		pOptionHeader->SizeOfImage = pOptionHeaderFileBuffer->SizeOfImage + SizeExportTableSection;

		pSectionHeaderTemp->VirtualAddress = Alignment(pOptionHeaderFileBuffer->SectionAlignment, pSectionHeaderTemp->VirtualAddress, 0);
		pSectionHeaderTemp->PointerToRawData = Alignment(pOptionHeaderFileBuffer->FileAlignment, pSectionHeaderTemp->PointerToRawData, 0);
	}
	else
	{
		free(pMoveExportTableTemp);
		printf("Insufficient.\n");
	}

	if (!pDataDirectory->VirtualAddress)
	{
		printf("This program has no export table.\n");
		return 0;
	}

	printf("Export Table Rva: %#x\n", pDataDirectory->VirtualAddress);

	DWORD Foa_ExportTable = RvaToFileOffset(pMoveExportTableTemp, pDataDirectory->VirtualAddress);
	printf("Export Table Foa: %#x\n", Foa_ExportTable);

	pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pMoveExportTableTemp + Foa_ExportTable);
	PVOID pAddInsSction = (PDWORD)((DWORD)pMoveExportTableTemp + pSectionHeaderTemp->PointerToRawData);

	if (!test)
	{
		printf("The starting address of the new section：%#x\n", ((DWORD)pMoveExportTableTemp + pSectionHeaderTemp->PointerToRawData));
	}
	PDWORD pAddressOfFunctions = (PDWORD)((DWORD)pMoveExportTableTemp + RvaToFileOffset(pMoveExportTableTemp, pExportDirectory->AddressOfFunctions));

	printf("AddressOfFunctions: %#x\n", pExportDirectory->AddressOfFunctions);
	DWORD NewAddressOfFunctions = (DWORD)pAddInsSction;
	memcpy(pAddInsSction, pAddressOfFunctions, 4 * pExportDirectory->NumberOfFunctions);
	pAddInsSction = (PWORD)((DWORD)pAddInsSction + 4 * pExportDirectory->NumberOfFunctions);
	PDWORD pAddressOfNameOrdinals = (PDWORD)((DWORD)pMoveExportTableTemp + RvaToFileOffset(pMoveExportTableTemp, pExportDirectory->AddressOfNameOrdinals));
	DWORD NewAddressOfNameOrdinals = (DWORD)pAddInsSction;
	memcpy(pAddInsSction, pAddressOfNameOrdinals, 2 * pExportDirectory->NumberOfNames);
	pAddInsSction = (PDWORD)((DWORD)pAddInsSction + 2 * pExportDirectory->NumberOfNames);

	PDWORD pAddressOfNames = (PDWORD)((DWORD)pMoveExportTableTemp + RvaToFileOffset(pMoveExportTableTemp, pExportDirectory->AddressOfNames));
	PDWORD pAddressOfNamesOrg = pAddressOfNames;
	if (!test)
	{
		printf("pAddressOfNamesOrg: %#x\n", *pAddressOfNamesOrg);
		printf("%#x\n", *pAddressOfNamesOrg);
	}

	DWORD NewAddressOfNames = (DWORD)pAddInsSction;
	memcpy(pAddInsSction, pAddressOfNames, 4 * pExportDirectory->NumberOfNames);
	pAddInsSction = (PDWORD)((DWORD)pAddInsSction + 4 * pExportDirectory->NumberOfNames);

	for (DWORD n = 0; n < pExportDirectory->NumberOfNames; n++)
	{
		PVOID pAddressNameString = *pAddressOfNames;
		DWORD nameSize = strlen((PVOID)((DWORD)pMoveExportTableTemp + RvaToFileOffset(pMoveExportTableTemp, pAddressNameString)));

		*pAddressOfNames = RvaToFileOffset(pMoveExportTableTemp, pAddressNameString);

		if (!test)
		{
			printf("pAddressNameString: %#x\n", (DWORD)pAddressNameString);
			printf("&pAddressOfNames: %#x\n", &pAddressOfNames);
			printf("pAddressOfNames: %#x\n", pAddressOfNames);
			printf("*pAddressOfNames: %#x\n", *pAddressOfNames);
		}

		memcpy(pAddInsSction, (PVOID)((DWORD)pMoveExportTableTemp + RvaToFileOffset(pMoveExportTableTemp, pAddressNameString)), nameSize);
		*(PDWORD)NewAddressOfNames = FoaToImageOffset(pMoveExportTableTemp, (DWORD)pAddInsSction - (DWORD)pMoveExportTableTemp);

		printf("pAddInsSction: %#x\n", (DWORD)pAddInsSction);

		pAddInsSction = (PDWORD)((DWORD)pAddInsSction + nameSize);

		memcpy(pAddInsSction, "\0", 1);
		pAddInsSction = (PDWORD)((DWORD)pAddInsSction + 1);
		pAddressOfNames++;
		((PDWORD)NewAddressOfNames)++;
	}
	DWORD NewExportDirectory = (DWORD)pAddInsSction;
	memcpy(pAddInsSction, pExportDirectory, 0x28);
	PIMAGE_EXPORT_DIRECTORY pAddInsSctionTemp = (PIMAGE_EXPORT_DIRECTORY)pAddInsSction;

	//修改导出表信息
	if (!test)
	{
		printf("pMoveExportTableTemp: %#x\n", (DWORD)pMoveExportTableTemp);
		printf("pSectionHeaderTemp->PointerToRawData: %#x\n", pSectionHeaderTemp->PointerToRawData);
		printf("pSectionHeaderTemp->VirtualAddress: %#x\n", pSectionHeaderTemp->VirtualAddress);
	}
	pAddInsSctionTemp->AddressOfFunctions = FoaToImageOffset(pMoveExportTableTemp, NewAddressOfFunctions - (DWORD)pMoveExportTableTemp);
	pAddInsSctionTemp->AddressOfNames = FoaToImageOffset(pMoveExportTableTemp, NewAddressOfNames - (DWORD)pMoveExportTableTemp);
	pAddInsSctionTemp->AddressOfNameOrdinals = FoaToImageOffset(pMoveExportTableTemp, NewAddressOfNameOrdinals - (DWORD)pMoveExportTableTemp);

	//修改数据目录表信息
	pDataDirectory->VirtualAddress = FoaToImageOffset(pMoveExportTableTemp, NewExportDirectory - (DWORD)pMoveExportTableTemp);

	size_t ret_loc5 = MemoryToFile(pMoveExportTableTemp, AddSecTotal, write_movexportable_file_path);
	if (!ret_loc5)
	{
		printf("(MoveExportTable)Store memory failed.\n");
		return 0;
	}

	*pFileBuffer_ExportTable = pMoveExportTableTemp; //暂存的数据传给参数后释放
	free(pMoveExportTableTemp);
	pMoveExportTableTemp = NULL;

	return AddSecTotal;
}

VOID operate()
{
	PVOID pFileBuffer = NULL;
	PVOID pNewFileBuffer = NULL;
	PVOID pImageBuffer = NULL;

	DWORD ret1 = ToLoaderPE(file_path, &pFileBuffer);  // &pFileBuffer(void**类型) 传递地址对其值可以进行修改
	printf("exe->filebuffer  返回值为计算所得文件大小：%#x\n", ret1);

	DWORD ret11 = MoveExportTable(pFileBuffer, ret1, &pNewFileBuffer);
	printf("SizeOfExportTableSection: %#x\n", ret11);

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