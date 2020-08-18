#include<stdio.h>
#include<stdlib.h>
#include<windows.h>

#define test 1

DWORD ToLoaderPE(LPSTR file_path, PVOID* pFileBuffer);
DWORD FoaToImageOffset(PVOID pBuffer, DWORD dwFoa);
DWORD RvaToFileOffset(PVOID pBuffer, DWORD dwRva);

char file_path[] = "c:\\users\\desktop\\notepad.exe";
char write_file_path[] = "D:\\Lib\\cp_XX.exe";

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

	printf("ImageOffset: %#x\n", dwRva);
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

VOID operate()
{
	LPVOID pFileBuffer = NULL;
	LPVOID pNewFileBuffer = NULL;
	LPVOID pImageBuffer = NULL;
	size_t pRVA = 0x0003123;
	size_t pFOA = 0x00020450;

	DWORD ret1 = ToLoaderPE(file_path, &pFileBuffer);  // &pFileBuffer(void**类型) 传递地址对其值可以进行修改
	printf("exe->filebuffer  返回值为计算所得文件大小：%#x\n", ret1);
	
	DWORD ret_FOA1 = RvaToFileOffset(pFileBuffer, pRVA);
	printf("内存偏移%#x 转换为文件中的偏移: %#x\n", pRVA, ret_FOA1);
	DWORD ret_RVA1 = FoaToImageOffset(pFileBuffer, pFOA);
	printf("文件偏移%#x 转换为内存中的偏移: %#x\n", pFOA, ret_RVA1);

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