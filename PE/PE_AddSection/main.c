#include<stdio.h>
#include<stdlib.h>
#include<windows.h>

#define test 1
#define size_surplus_sizeofheader 0x50

DWORD ToLoaderPE(LPSTR file_path, PVOID* pFileBuffer);
BOOL MemoryToFile(PVOID pMemBuffer, DWORD size, LPSTR lpszFile);
DWORD GetSctionEmptySpace(PVOID pFileBuffer, DWORD SectionOrdinal);
DWORD Alignment(DWORD alignment_value, DWORD addend, DWORD address);
DWORD TestAddSection(LPSTR file_path, PVOID* pFileBuffer, PVOID* pAddSectionBuffer);

char file_path[] = "c:\\users\\desktop\\ipmsg2007.exe";
char write_addsec_file_path[] = "D:\\Lib\\cp_addsec_XX.exe";

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

DWORD TestAddSection(LPSTR file_path, PVOID* pFileBuffer, PVOID* pAddSectionBuffer)
{
	PVOID pAddSectionTemp = NULL;
	//加载.exe的PE结构
	DWORD ret_loc2 = ToLoaderPE(file_path, pFileBuffer);
	DWORD AddSecTotal = ret_loc2 + 0x1000;

	pAddSectionTemp = malloc(AddSecTotal);

	if (!pAddSectionTemp)
	{
		printf("(TestAddSection)Allocate dynamic memory failed!\n");
		return 0;
	}

	memset(pAddSectionTemp, 0, AddSecTotal);
	memcpy(pAddSectionTemp, *pFileBuffer, ret_loc2);

	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;

	if (!pAddSectionTemp)
	{
		printf("(TestAddSection)Can't open file!\n");
		return;
	}

	if (*((PWORD)pAddSectionTemp) != IMAGE_DOS_SIGNATURE)
	{
		printf("(TestAddSection)No MZ flag, not exe file!\n");
		free(pAddSectionTemp);
		return;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pAddSectionTemp;

	if (*((PDWORD)((DWORD)pAddSectionTemp + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("(TestAddSection)Not a valid PE flag!\n");
		free(pAddSectionTemp);
		return;
	}
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pAddSectionTemp + pDosHeader->e_lfanew);
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	//新加的区块只能加在最后一个区块后面
	PIMAGE_SECTION_HEADER pSectionHeaderTemp = pSectionHeader;
	for (DWORD i = 0; i < pPEHeader->NumberOfSections; i++, pSectionHeaderTemp++)
	{
		//
	}

	//判断SizeOFHeader能否放下多余两个节区（一个新增节区，一个全0节区代表区块结束）
	//分三种情况：1.节表后直接可以放下两个节区 2.节表后放不下，但是dos头后pe前可放下 3.前两种情况都不行，需扩大最后一个节把代码填进去
	//就讨论第一种情况吧...
	if (size_surplus_sizeofheader <= (pOptionHeader->SizeOfHeaders - ((DWORD)(pSectionHeaderTemp - pAddSectionTemp))))
	{
		printf("Enough.\n");
		//得到最后一个节的信息
		pSectionHeaderTemp--;
		//填充节
		DWORD ret_loc3 = Alignment(pOptionHeader->SectionAlignment, (DWORD)pSectionHeaderTemp->Misc.VirtualSize, (DWORD)pSectionHeaderTemp->PointerToRawData);
		memset(((PBYTE)(DWORD)pAddSectionTemp + ret_loc3), 0, 0x1000);
		//改节数目
		pPEHeader->NumberOfSections = pPEHeader->NumberOfSections + 1;
		//填充节表
		pSectionHeaderTemp++;
		memcpy(pSectionHeaderTemp, pSectionHeader, IMAGE_SIZEOF_SECTION_HEADER);
		memcpy(pSectionHeaderTemp, ".addsec", 8);

		pSectionHeaderTemp->VirtualAddress = ret_loc3;
		pSectionHeaderTemp->SizeOfRawData = 0x1000;
		pSectionHeaderTemp->PointerToRawData = ret_loc3;
		pSectionHeaderTemp->Misc.VirtualSize = 0x1000;
		pOptionHeader->SizeOfImage = AddSecTotal;

		//后面再添IMAGE_SIZEOF_SECTION_HEADER个0
		pSectionHeaderTemp++;
		memset(pSectionHeaderTemp, 0, IMAGE_SIZEOF_SECTION_HEADER);
	}
	else
	{
		free(pAddSectionTemp);
		printf("Insufficient.\n");
	}

	size_t ret_loc4 = MemoryToFile(pAddSectionTemp, AddSecTotal, write_addsec_file_path);
	if (!ret_loc4)
	{
		printf("(TestAddSection)Store memory failed.\n");
		return 0;
	}

	*pAddSectionBuffer = pAddSectionTemp; //暂存的数据传给参数后释放
	
	//主函数free了
	//free(pAddSectionTemp);
	pAddSectionTemp = NULL;

	return AddSecTotal;
}

VOID operate()
{
	PVOID pFileBuffer = NULL;
	PVOID pNewFileBuffer = NULL;
	PVOID pImageBuffer = NULL;
	
	DWORD ret5 = TestAddSection(file_path, &pFileBuffer, &pNewFileBuffer);
	printf("TestAddSection Buffer: %#x\n", ret5);

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