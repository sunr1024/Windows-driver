#pragma once
#ifndef __idthead_h__
#define __idthead_h__



#include <ntifs.h>
#include <ntddk.h>
#define MAKE_LONG(a,b) ((a) + (b<<16))

typedef struct _IDT_INFO {
	UINT16 uIdtLimit;   // IDT范围
	UINT16 uLowIdtBase;   // IDT低基址
	UINT16 uHighIdtBase;   // IDT高基址
}IDT_INFO, *PIDT_INFO;
//0x8 bytes (sizeof)
typedef struct _IDTENTRY
{
	// USHORT == UINT16
	USHORT uOffsetLow;       //0x0，低地址偏移
	USHORT uSelector;     //0x2，段选择器
	//USHORT uAccess;      //0x4
	UINT8 uReserved;     // 保留
	UINT8 GateType : 4;     // 中断类型
	UINT8 StorageSegment : 1;   // 为0则是中断门
	UINT8 DPL : 2;      // 特权级
	UINT8 Present : 1;      // 如未使用中断可置为0
	USHORT uOffsetHigh; //0x6   // 高地址偏移
}IDTENTRY, *PIDTENTRY;

typedef VOID(*CUSTOM_TIMER_ROUTINE)();

VOID TimerThread(PVOID context);
BOOLEAN CreateTimer(LONG MilliSecond, CUSTOM_TIMER_ROUTINE routine);
VOID DestroyTimer();
VOID TimerFunc();
VOID IDTOrg();
VOID IDTAgain();


#endif // !1