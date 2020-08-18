#include<stdio.h>
#include<stdlib.h>
#include<windows.h>

#define size_shellcode 0x12
#define size_surplus_sizeofheader 0x50
#define messagebox_addr 0x75CA2030  
#define test 1

DWORD ToLoaderPE(LPSTR file_path, PVOID* pFileBuffer);
DWORD CopyFileBufferToImageBuffer(PVOID pFileBuffer, PVOID* pImageBuffer);
DWORD CopyImageBufferToNewFileBuffer(PVOID pImageBuffer, PVOID* pNewFileBuffer);
BOOL MemoryToFile(PVOID pMemBuffer, DWORD size, LPSTR lpszFile);
DWORD FoaToImageOffset(PVOID pBuffer, DWORD dwFoa);
DWORD RvaToFileOffset(PVOID pBuffer, DWORD dwRva);
DWORD TestAddCodeInDataSec(PVOID pImageBuffer, PVOID* pNewFileBuffer, DWORD FileSize);
DWORD GetSctionEmptySpace(PVOID pFileBuffer, DWORD SectionOrdinal);

char file_path[] = "c:\\userst\\desktop\\ipmsg2007.exe";
char write_file_path[] = "D:\\Lib\\cp_XX.exe";
char write_adddata_file_path[] = "D:\\Lib\\cp_adddata_XX.exe";

BYTE shellcode[] = {
	0x6A,00,0x6A,00,0x6A,00,0x6A,00,
	0XE8,00,00,00,00,
	0XE9,00,00,00,00
};

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
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 4); // 这里必须强制类型转换
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	//获取new_buffer的大小
	int new_buffer_size = pOptionHeader->SizeOfHeaders;
	for (DWORD i = 0; i < pPEHeader->NumberOfSections; i++)
	{
		new_buffer_size += pSectionHeader[i].SizeOfRawData;  // pSectionHeader[i]另一种加法
	}
	// 分配内存（newbuffer）
	pTempNewbuffer = malloc(new_buffer_size);
	if (!pTempNewbuffer)
	{
		printf("(CopyImageBufferToNewBuffer)Allocate dynamic memory failed!\n");
		return 0;
	}
	memset(pTempNewbuffer, 0, new_buffer_size);
	memcpy(pTempNewbuffer, pDosHeader, pOptionHeader->SizeOfHeaders);
	// 循环拷贝节区
	PIMAGE_SECTION_HEADER pTempSectionHeader = pSectionHeader;
	for (DWORD j = 0; j < pPEHeader->NumberOfSections; j++, pTempSectionHeader++)
	{	//PointerToRawData节区在文件中的偏移,VirtualAddress节区在内存中的偏移地址,SizeOfRawData节在文件中对齐后的尺寸
		memcpy((PDWORD)((DWORD)pTempNewbuffer + pTempSectionHeader->PointerToRawData), (PDWORD)((DWORD)pImageBuffer + pTempSectionHeader->VirtualAddress), pTempSectionHeader->SizeOfRawData);
	}
	//返回数据
	*pNewFileBuffer = pTempNewbuffer; //暂存的数据传给参数后释放
	pTempNewbuffer = NULL;
	return new_buffer_size;  // 返回计算得到的分配内存的大小
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

DWORD TestAddCodeInDataSec(PVOID pBuffer, PVOID* pNewFileBuffer, DWORD FileSize)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;

	if (!pBuffer)
	{
		printf("(TestAddCodeInDataSec)Can't open file!\n");
		return 0;
	}

	if (*((PWORD)pBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("(TestAddCodeInDataSec)No MZ flag, not exe file!\n");
		return 0;
	}
	
	pDosHeader = (PIMAGE_DOS_HEADER)pBuffer;
	if (*((PDWORD)((DWORD)pBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("(TestAddCodeInDataSec)Not a valid PE flag!\n");
		return 0;
	}
	
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pBuffer + pDosHeader->e_lfanew);
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 4); // 这里必须强制类型转换
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	//判断.text节区空余位置能否放下shellcode
	if (size_shellcode > GetSctionEmptySpace(pBuffer, 1))
	{
		printf("(TestAddCodeInDataSec)Data section sapce not enough to store shellcode!\n");
		free(pBuffer);
		return 0;
	}

	printf("(TestAddCodeInDataSec)pSectionHeader->PointerToRawData: %#x  pSectionHeader->Misc.VirtualSize: %#x\n", pSectionHeader->PointerToRawData, pSectionHeader->Misc.VirtualSize);
	printf("(TestAddCodeInDataSec)pImageBuffer: %#x\n", pBuffer);

	//填充代码
	PBYTE CodeAddLoc = (PBYTE)((DWORD)pBuffer + pSectionHeader->VirtualAddress + pSectionHeader->Misc.VirtualSize);
	printf("(TestAddCodeInDataSec)pSectionHeader->VirtualAddress: %#x\n", pSectionHeader->VirtualAddress);
	printf("(TestAddCodeInDataSec)CodeAddLoc: %#x\n", CodeAddLoc);
	memcpy(CodeAddLoc, shellcode, size_shellcode);

	//修改E8跳转地址
	//硬编码  真正要跳转的地址 = E8这条指令的下一行地址 + X
	DWORD callAddr = (messagebox_addr - (pOptionHeader->ImageBase + ((DWORD)(CodeAddLoc + 0xD) - (DWORD)pBuffer)));
	*(PDWORD)(CodeAddLoc + 0x09) = callAddr;
	//修改E9跳转地址
	DWORD jmpAddr = (pOptionHeader->AddressOfEntryPoint - ((DWORD)(CodeAddLoc + size_shellcode) - (DWORD)pBuffer));
	*(PDWORD)(CodeAddLoc + 0x0E) = jmpAddr;

	pOptionHeader->AddressOfEntryPoint = (DWORD)CodeAddLoc - (DWORD)pBuffer;

	DWORD size = CopyImageBufferToNewFileBuffer(pBuffer, pNewFileBuffer);

	if (size = 0 || !pNewFileBuffer)
	{
		printf("imagebuffer->newfilebuffer failed\n");
		free(pBuffer);
		free(pNewFileBuffer);
	}
	// 存盘
	DWORD ret_loc1 = MemoryToFile(*pNewFileBuffer, FileSize, write_adddata_file_path);
	if (!ret_loc1)
	{
		printf("(TestAddCodeInDataSec)Store memory failed.\n");
		return 0;
	}
	return 1;	
}

VOID operate()
{
	PVOID pFileBuffer = NULL;
	PVOID pNewFileBuffer = NULL;
	PVOID pImageBuffer = NULL;
	//DWORD pRVA = 0x0003123;
	//DWORD pFOA = 0x00020450;

	DWORD ret1 = ToLoaderPE(file_path, &pFileBuffer);  // &pFileBuffer(void**类型) 传递地址对其值可以进行修改
	printf("exe->filebuffer  返回值为计算所得文件大小：%#x\n", ret1);

	DWORD ret2 = CopyFileBufferToImageBuffer(pFileBuffer, &pImageBuffer);
	printf("filebuffer -> imagebuffer返回值为计算所得文件大小：%#x\n", ret2);
	//DWORD ret3 = CopyImageBufferToNewFileBuffer(pImageBuffer, &pNewFileBuffer);
	//printf("imagebuffer -> newfilebuffer返回值为计算所得文件大小：%#x\n", ret3);
	
	DWORD ret4 = TestAddCodeInDataSec(pFileBuffer, &pNewFileBuffer, ret1);
	printf("AddCodeInDataSec：%#x\n", ret4);

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