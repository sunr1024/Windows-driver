#include<stdio.h>
#include<stdlib.h>
#include<windows.h>

#define test 1
#define ordianl 3

DWORD ToLoaderPE(LPSTR file_path, PVOID* pFileBuffer);
BOOL MemoryToFile(PVOID pMemBuffer, DWORD size, LPSTR lpszFile);
DWORD FoaToImageOffset(PVOID pBuffer, DWORD dwFoa);
DWORD RvaToFileOffset(PVOID pBuffer, DWORD dwRva);
DWORD GetSctionEmptySpace(PVOID pFileBuffer, DWORD SectionOrdinal);
DWORD Alignment(DWORD alignment_value, DWORD addend, DWORD address);
DWORD GetFunctionAddrByName(PVOID pFileBuffer, LPSTR fun_name);
DWORD GetFunctionAddrByOrdinals(PVOID pFileBuffer, DWORD fun_ordinal);
VOID LogExportTable(PVOID pFileBuffer);


char file_path[] = "c:\\usersdesktop\\dll1test.dll";
char fun_name[] = "Mul";
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

DWORD GetFunctionAddrByOrdinals(PVOID pFileBuffer, DWORD fun_ordinal)
{
	printf("Function Ordinal: %#x\n", fun_ordinal);
	// 初始化PE头部结构体
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;

	// 判断pImageBuffer是否有效
	if (!pFileBuffer)
	{
		printf("(GetFunctionAddrByOrdinals)Can't open file!\n");
		return 0;
	}
	//判断是不是exe文件
	if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("(GetFunctionAddrByOrdinals)No MZ flag, not exe file!\n");
		return 0;
	}
	// 强制结构体类型转换
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if (*((PDWORD)((DWORD)pFileBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("(GetFunctionAddrByOrdinals)Not a valid PE flag!\n");
		return 0;
	}

	// 强制结构体类型转换
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

	printf("Export Table Rva: %#x\n", pDataDirectory->VirtualAddress);

	DWORD Foa_ExportTable = RvaToFileOffset(pFileBuffer, pDataDirectory->VirtualAddress);

	printf("Export Table Foa: %#x\n", Foa_ExportTable);

	pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pFileBuffer + Foa_ExportTable);

	if (!test)
	{
		printf("Characteristics: %#x\n", pExportDirectory->Characteristics);
		printf("TimeDateStamp:%#x\n", pExportDirectory->TimeDateStamp);
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

	DWORD Sequence = fun_ordinal - pExportDirectory->Base;
	DWORD Foa_AddressOfFunctions = RvaToFileOffset(pFileBuffer, pExportDirectory->AddressOfFunctions);

	if (!test)
	{
		DWORD test1 = Foa_AddressOfFunctions + (DWORD)pFileBuffer;
		printf("AddressOfFunctions in this moment: %#x\n", test1);
		printf("Foa_AddressOfFunctions: %#x\n", Foa_AddressOfFunctions);
	}

	PDWORD pFoa_AddressOfFunctions = (PBYTE)(Foa_AddressOfFunctions + (DWORD)pFileBuffer);

	for (DWORD n = 0; n < Sequence; n++)
	{
		pFoa_AddressOfFunctions++;
	}
	//DWORD Foa_AddrFun = RvaToFileOffset(pFileBuffer, *pFoa_AddressOfFunctions);

	return *pFoa_AddressOfFunctions;
}

DWORD GetFunctionAddrByName(PVOID pFileBuffer, LPSTR fun_name)
{
	printf("Function Name: %s\n", fun_name);
	// 初始化PE头部结构体
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;

	// 判断pImageBuffer是否有效
	if (!pFileBuffer)
	{
		printf("(GetFunctionAddrByName)Can't open file!\n");
		return 0;
	}
	//判断是不是exe文件
	if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("(GetFunctionAddrByName)No MZ flag, not exe file!\n");
		return 0;
	}
	// 强制结构体类型转换
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if (*((PDWORD)((DWORD)pFileBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("(GetFunctionAddrByName)Not a valid PE flag!\n");
		return 0;
	}

	// 强制结构体类型转换
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 4); // 这里必须强制类型转换
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	pDataDirectory = (PIMAGE_DATA_DIRECTORY)pOptionHeader->DataDirectory;

	if (!pDataDirectory->VirtualAddress)
	{
		printf("(GetFunctionAddrByName)This program has no export table.\n");
		return 0;
	}

	printf("(GetFunctionAddrByName)Export Table Rva: %#x\n", pDataDirectory->VirtualAddress);
	DWORD Foa_ExportTable = RvaToFileOffset(pFileBuffer, pDataDirectory->VirtualAddress);
	printf("(GetFunctionAddrByName)Export Table Foa: %#x\n", Foa_ExportTable);
	pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pFileBuffer + Foa_ExportTable);

	if (!test)
	{
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

	DWORD Foa_AddressOfNames = RvaToFileOffset(pFileBuffer, pExportDirectory->AddressOfNames);
	DWORD Foa_AddressOfNameOrdinals = RvaToFileOffset(pFileBuffer, pExportDirectory->AddressOfNameOrdinals);
	DWORD Foa_AddressOfFunctions = RvaToFileOffset(pFileBuffer, pExportDirectory->AddressOfFunctions);

	if (!test)
	{
		DWORD test1 = Foa_AddressOfNames + (DWORD)pFileBuffer;
		printf("AddressOfNames in this moment: %#x\n", test1);
		printf("Foa__AddressOfNames: %#x\n", Foa_AddressOfNames);
	}

	//1.循环从名字表中找与目标函数名相同的；如有有返回该名字在表中的索引
	DWORD ordIndex = -1;
	for (DWORD i = 0; i < pExportDirectory->NumberOfNames; i++)
	{
		DWORD nameOffset = *(PDWORD)((DWORD)pFileBuffer + (DWORD)((LPDWORD)Foa_AddressOfNames + i));
		LPSTR nameAddr = (LPSTR)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, nameOffset));
		if (!strcmp(nameAddr, fun_name))
		{
			ordIndex = i;
			break;
		}
	}
	if (ordIndex == -1)
	{
		printf("(GetFunctionAddrByName)The export table does not have this function name.\n");
		return 0;
	}

	//2.用获得的索引从序号表中找函数的序号
	WORD ord = *(PWORD)((DWORD)pFileBuffer + (DWORD)((LPWORD)Foa_AddressOfNameOrdinals + ordIndex));

	if (!test)
	{
		DWORD test1 = Foa_AddressOfNameOrdinals + (DWORD)pFileBuffer;
		printf("AddressOfNameOrdinals in this moment: %#x\n", test1);
		printf("Foa__AddressOfNameOrdinals: %#x\n", Foa_AddressOfNameOrdinals);
		printf("ordInex in AddressOfNames: %#x\n", ordIndex);
		printf("ordInex in AddressOfNameOrdinals: %#x\n", ord);
	}

	//3.以序号表中查出来的序号为索引从函数地址表中找函数地址
	DWORD addr = *(PDWORD)((DWORD)pFileBuffer + (DWORD)((LPDWORD)Foa_AddressOfFunctions + ord));
	//DWORD Foa_AddrFun = RvaToFileOffset(pFileBuffer, addr);

	return addr;
}

VOID operate()
{
	PVOID pFileBuffer = NULL;
	PVOID pNewFileBuffer = NULL;
	PVOID pImageBuffer = NULL;

	DWORD ret1 = ToLoaderPE(file_path, &pFileBuffer);  // &pFileBuffer(void**类型) 传递地址对其值可以进行修改
	printf("exe->filebuffer  返回值为计算所得文件大小：%#x\n", ret1);

	LogExportTable(pFileBuffer);

	DWORD ret9 = GetFunctionAddrByOrdinals(pFileBuffer, ordianl);
	printf("GetFunctionAddr is %#x\n", ret9);
	DWORD ret10 = GetFunctionAddrByName(pFileBuffer, fun_name);
	printf("GetFunctionAddr is %#x\n", ret10);

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