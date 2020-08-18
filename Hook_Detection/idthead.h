#pragma once
#ifndef __idthead_h__
#define __idthead_h__



#include <ntifs.h>
#include <ntddk.h>
#define MAKE_LONG(a,b) ((a) + (b<<16))

typedef struct _IDT_INFO {
	UINT16 uIdtLimit;   // IDT��Χ
	UINT16 uLowIdtBase;   // IDT�ͻ�ַ
	UINT16 uHighIdtBase;   // IDT�߻�ַ
}IDT_INFO, *PIDT_INFO;
//0x8 bytes (sizeof)
typedef struct _IDTENTRY
{
	// USHORT == UINT16
	USHORT uOffsetLow;       //0x0���͵�ַƫ��
	USHORT uSelector;     //0x2����ѡ����
	//USHORT uAccess;      //0x4
	UINT8 uReserved;     // ����
	UINT8 GateType : 4;     // �ж�����
	UINT8 StorageSegment : 1;   // Ϊ0�����ж���
	UINT8 DPL : 2;      // ��Ȩ��
	UINT8 Present : 1;      // ��δʹ���жϿ���Ϊ0
	USHORT uOffsetHigh; //0x6   // �ߵ�ַƫ��
}IDTENTRY, *PIDTENTRY;

typedef VOID(*CUSTOM_TIMER_ROUTINE)();

VOID TimerThread(PVOID context);
BOOLEAN CreateTimer(LONG MilliSecond, CUSTOM_TIMER_ROUTINE routine);
VOID DestroyTimer();
VOID TimerFunc();
VOID IDTOrg();
VOID IDTAgain();


#endif // !1