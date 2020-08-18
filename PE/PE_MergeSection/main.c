#include<stdio.h>
#include<stdlib.h>
#include<windows.h>

#define test 1

DWORD ToLoaderPE(LPSTR file_path, PVOID* pFileBuffer);
BOOL MemoryToFile(PVOID pMemBuffer, DWORD size, LPSTR lpszFile);
DWORD FoaToImageOffset(PVOID pBuffer, DWORD dwFoa);
DWORD RvaToFileOffset(PVOID pBuffer, DWORD dwRva);
DWORD Alignment(DWORD alignment_value, DWORD addend, DWORD address);
DWORD TestMergeSection(PVOID* pFileBuffer, PVOID* pEnlargerSection);

char file_path[] = "c:\\users\\desktop\\ipmsg2007.exe";
char write_file_path[] = "D:\\Lib\\cp_XX.exe";
char write_mergesec_file_path[] = "D:\\Lib\\cp_mergesec_XX.exe";

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

	printf("ImageOffset: %#x\n", dwRva);
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

DWORD TestMergeSection(PVOID* pImageBuffer, PVOID* pEnlargerSection)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PVOID pMergeSectionTemp = NULL;

	if (!*pImageBuffer)
	{
		printf("(TestMergeSection)Can't open file!\n");
		return;
	}

	if (*((PWORD)*pImageBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("(TestMergeSection)No MZ flag, not exe file!\n");
		free(*pImageBuffer);
		return;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)*pImageBuffer;

	if (*((PDWORD)((DWORD)*pImageBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("(TestMergeSection)Not a valid PE flag!\n");
		free(*pImageBuffer);
		return;
	}
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)*pImageBuffer + pDosHeader->e_lfanew);
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	PIMAGE_SECTION_HEADER pSectionHeaderTemp = pSectionHeader;

	DWORD NewSecCharacteristics = 0;
	pOptionHeader->SizeOfHeaders = Alignment(pOptionHeader->SectionAlignment, pOptionHeader->SizeOfHeaders, 0);

	//PIMAGE_SECTION_HEADER pLastSectionHeader = pSectionHeader + pPEHeader->NumberOfSections - 1;
	PIMAGE_SECTION_HEADER pLastSectionHeader = &pSectionHeader [pPEHeader->NumberOfSections - 1];

	DWORD max = (pLastSectionHeader->SizeOfRawData > pLastSectionHeader->Misc.VirtualSize ? pLastSectionHeader->SizeOfRawData : pLastSectionHeader->Misc.VirtualSize);
	if (!test)
	{
		printf("pLastSectionHeader->SizeOfRawData: %#x\n", pLastSectionHeader->SizeOfRawData);
		printf("pLastSectionHeader->Misc.VirtualSize: %#x\n", pLastSectionHeader->Misc.VirtualSize);
		printf("max: %#x\n", max);
	}
	
	DWORD NewSecBuffer = (pLastSectionHeader->VirtualAddress + max - pOptionHeader->SizeOfHeaders);

	//���������һ���ڱ�
	for (DWORD i = 0; i < pPEHeader->NumberOfSections; i++, pSectionHeaderTemp++)
	{
		//printf("pSectionHeaderTemp->Characteristics: %#x\n", pSectionHeaderTemp->Characteristics);
		NewSecCharacteristics |= pSectionHeaderTemp->Characteristics;
		if (i > 0)
		{
			memset(&pSectionHeader[i], 0, IMAGE_SIZEOF_SECTION_HEADER);
		}
	}

	pSectionHeader->Characteristics = NewSecCharacteristics;
	pSectionHeader->SizeOfRawData = NewSecBuffer;
	pSectionHeader->Misc.VirtualSize = NewSecBuffer;
	pPEHeader->NumberOfSections = 0x01;

	if (!test)
	{
		printf("pSectionHeader->Characteristics : %#x\n", pSectionHeader->Characteristics);
		printf("pSectionHeader->SizeOfRawData: %#x\n", pSectionHeader->SizeOfRawData);
		printf("pSectionHeader->Misc.VirtualSize: %#x\n", pSectionHeader->Misc.VirtualSize);
	}
	
	pMergeSectionTemp = malloc(pOptionHeader->SizeOfImage);

	if (!pMergeSectionTemp)
	{
		printf("(TestMergeSection)Allocate dynamic memory failed!\n");
		return 0;
	}

	memset(pMergeSectionTemp, 0, pOptionHeader->SizeOfImage);
	memcpy(pMergeSectionTemp, *pImageBuffer, pOptionHeader->SizeOfHeaders);
	memcpy((PDWORD)((DWORD)pMergeSectionTemp + pSectionHeader->PointerToRawData), (PDWORD)((DWORD)*pImageBuffer + pSectionHeader->VirtualAddress), pSectionHeader->SizeOfRawData);

	DWORD ret_loc4 = MemoryToFile(pMergeSectionTemp, pOptionHeader->SizeOfImage, write_mergesec_file_path);
	if (!ret_loc4)
	{
		printf("(TestMergeSection)Store file failed.\n");
		return 0;
	}

	*pEnlargerSection = pMergeSectionTemp; //�ݴ�����ݴ����������ͷ�
	//free(pMergeSectionTemp);
	pMergeSectionTemp = NULL;

	return pOptionHeader->SizeOfImage;
}


VOID operate()
{
	/*˼·
	1.�����������ļ����ڴ棬�����н����ڴ��п���һ����
	2.�����ڵ�Misc.VirtualSize��SizeOfRawData=SizeOfImage-pSectionHeader->VirtualAddress
	3.��׼peͷ�еĽ�����Ҫ��Ϊ1
	4.�ϲ���ڵ����Ե������нڵ����Լ�����
	5.ֱ�ӿ��������ļ�
	*/
	PVOID pFileBuffer = NULL;
	PVOID pNewFileBuffer = NULL;
	PVOID pImageBuffer = NULL;

	DWORD ret1 = ToLoaderPE(file_path, &pFileBuffer);  // &pFileBuffer(void**����) ���ݵ�ַ����ֵ���Խ����޸�
	printf("exe->filebuffer  ����ֵΪ���������ļ���С��%#x\n", ret1);

	DWORD ret2 = CopyFileBufferToImageBuffer(pFileBuffer, &pImageBuffer);
	printf("filebuffer -> imagebuffer����ֵΪ���������ļ���С��%#x\n", ret2);
	
	DWORD ret8 = TestMergeSection(&pImageBuffer, &pNewFileBuffer);
	printf("TestMergeSection Buffer: %#x\n", ret8);

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