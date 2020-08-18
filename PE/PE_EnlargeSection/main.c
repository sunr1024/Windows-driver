#include<stdio.h>
#include<stdlib.h>
#include<windows.h>
 
#define test 1

DWORD ToLoaderPE(LPSTR file_path, PVOID* pFileBuffer);
BOOL MemoryToFile(PVOID pMemBuffer, DWORD size, LPSTR lpszFile);
DWORD Alignment(DWORD alignment_value, DWORD addend, DWORD address);
DWORD TestEnlargeSection(PVOID* pFileBuffer, PVOID* pEnlargerSection);

char file_path[] = "c:\\users\\desktop\\ipmsg2007.exe";
char write_enlargersec_file_path[] = "D:\\Lib\\cp_enlargersec_XX.exe";

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

DWORD TestEnlargeSection(PVOID* pFileBuffer, PVOID* pEnlargerSection)
{
	LPVOID pEnlargerSectionTemp = NULL;
	//加载.exe的PE结构
	DWORD ret_loc2 = ToLoaderPE(file_path, pFileBuffer);
	DWORD EnlargerSecTotal = ret_loc2 + 0x1000;

	pEnlargerSectionTemp = malloc(EnlargerSecTotal);

	if (!pEnlargerSectionTemp)
	{
		printf("(TestEnlargeSection)Allocate dynamic memory failed!\n");
		return 0;
	}

	memset(pEnlargerSectionTemp, 0, EnlargerSecTotal);
	memcpy(pEnlargerSectionTemp, *pFileBuffer, ret_loc2);

	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;

	if (!pEnlargerSectionTemp)
	{
		printf("(TestEnlargeSection)Can't open file!\n");
		return;
	}

	//判断是否是有效的MZ标志	
	if (*((PWORD)pEnlargerSectionTemp) != IMAGE_DOS_SIGNATURE)
	{
		printf("(TestEnlargeSection)No MZ flag, not exe file!\n");
		free(pEnlargerSectionTemp);
		return;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pEnlargerSectionTemp;

	//判断是否是有效的PE标志	
	if (*((PDWORD)((DWORD)pEnlargerSectionTemp + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("(TestEnlargeSection)Not a valid PE flag!\n");
		free(pEnlargerSectionTemp);
		return;
	}
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pEnlargerSectionTemp + pDosHeader->e_lfanew);
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	//遍历到最后一个节表
	PIMAGE_SECTION_HEADER pSectionHeaderTemp = pSectionHeader;
	for (DWORD i = 0; i < pPEHeader->NumberOfSections; i++, pSectionHeaderTemp++)
	{
		//
	}

	DWORD max = (pSectionHeaderTemp->SizeOfRawData > pSectionHeaderTemp->Misc.VirtualSize ? pSectionHeaderTemp->SizeOfRawData : pSectionHeaderTemp->Misc.VirtualSize);
	pSectionHeaderTemp->SizeOfRawData = max + 0x1000;
	pSectionHeaderTemp->Misc.VirtualSize = max + 0x1000;

	pOptionHeader->SizeOfImage = Alignment(pOptionHeader->SectionAlignment, pSectionHeaderTemp->Misc.VirtualSize, pOptionHeader->SizeOfImage);

	size_t ret_loc4 = MemoryToFile(pEnlargerSectionTemp, pOptionHeader->SizeOfImage, write_enlargersec_file_path);
	if (!ret_loc4)
	{
		printf("(TestEnlargeSection)store memory failed.\n");
		return 0;
	}

	*pEnlargerSection = pEnlargerSectionTemp; //暂存的数据传给参数后释放
	//free(pEnlargerSectionTemp);
	pEnlargerSectionTemp = NULL;

	return EnlargerSecTotal;
}

VOID operate()
{
	PVOID pFileBuffer = NULL;
	PVOID pNewFileBuffer = NULL;
	PVOID pImageBuffer = NULL;
	
	DWORD ret7 = TestEnlargeSection(&pFileBuffer, &pNewFileBuffer);
	printf("TestEnlargeSection Buffer: %#x\n", ret7);

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