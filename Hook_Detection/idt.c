#include <ntifs.h>
#include"idthead.h"
#include"framehead.h"
#include <ntddk.h>
#define MAKE_LONG(a,b) ((a) + (b<<16))
ULONG uAddr[256] = { 0 };


VOID IDTAgain()
{
	int n = 0;
	IDT_INFO stcIDT1 = { 0 };
	PIDTENTRY pIdtEntry1 = NULL;
	ULONG uAddr1[256] = { 0 };
	// IDT table
	__asm sidt stcIDT1;
	// IDT array
	pIdtEntry1 = (PIDTENTRY)MAKE_LONG(stcIDT1.uLowIdtBase, stcIDT1.uHighIdtBase);
	KdPrint(("-------------IDT----------------\n"));
	FileWriteExA("-------------IDT----------------\r\n");
	KdPrint(("IDT Addr: 0x%p\n", pIdtEntry1));
	FileWriteExA("IDT Addr: 0x");
	FileWriteInt(pIdtEntry1, 16);
	FileWriteExA("\r\n");
	for (ULONG i = 0; i < 0x100; ++i)
	{
		
		uAddr1[i] = MAKE_LONG(pIdtEntry1[i].uOffsetLow, pIdtEntry1[i].uOffsetHigh);
			
		if (uAddr1[i] != uAddr[i])
		{
			KdPrint(("IRP HOOK!\n"));
			FileWriteExA("IRP HOOK!\r\n");
			KdPrint(("Interrupted number: %d\n", i));
			FileWriteExA("Interrupted number: ");
			FileWriteInt(i, 10);
			FileWriteExA("\r\n");
			KdPrint(("Current  Addr: 0x%p\n", uAddr1[i]));
			FileWriteExA("Current  Addr: 0x");
			FileWriteInt(uAddr1[i], 16);
			FileWriteExA("\r\n");
			KdPrint(("Original Addr: 0x%p\n", uAddr[i]));
			FileWriteExA("Original  Addr: 0x");
			FileWriteInt(uAddr[i], 16);
			FileWriteExA("\r\n");
			KdPrint(("selector: %d\n", pIdtEntry1[i].uSelector));
			FileWriteExA("selector: ");
			FileWriteInt(pIdtEntry1[i].uSelector, 10);
			FileWriteExA("\r\n");
			KdPrint(("GataType: %d\n", pIdtEntry1[i].GateType));
			FileWriteExA("GataType: ");
			FileWriteInt(pIdtEntry1[i].GateType, 10);
			FileWriteExA("\r\n");
			KdPrint(("DPL: %d\n", pIdtEntry1[i].DPL));
			FileWriteExA("DPL: ");
			FileWriteInt(pIdtEntry1[i].DPL, 10);
			FileWriteExA("\r\n");
			n++;
		}
	}
	if (!n)
	{
		KdPrint(("NO IRP HOOK.\n"));
		FileWriteExA("NO IRP HOOK.\r\n");
	}
		

}

VOID IDTOrg()
{
	IDT_INFO stcIDT = { 0 };
	PIDTENTRY pIdtEntry = NULL;
	PIDTENTRY pIdtEntry2 = NULL;

	// IDT table
	__asm sidt stcIDT;
	// IDT array
	pIdtEntry = (PIDTENTRY)MAKE_LONG(stcIDT.uLowIdtBase, stcIDT.uHighIdtBase);
	for (ULONG i = 0; i < 0x100; ++i)
	{
		uAddr[i] = MAKE_LONG(pIdtEntry[i].uOffsetLow, pIdtEntry[i].uOffsetHigh);
	}
}


