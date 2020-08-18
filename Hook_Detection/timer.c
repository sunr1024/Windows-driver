#include <ntifs.h>
#include"idthead.h"
#include"ssdthead.h"
#include <ntddk.h>
#include"framehead.h"

extern g_FileHandle;


VOID LocalTime()
{
	LARGE_INTEGER current_system_time;
	KeQuerySystemTime(&current_system_time);

	LARGE_INTEGER current_loacl_time;
	ExSystemTimeToLocalTime(&current_system_time, &current_loacl_time);

	TIME_FIELDS current_time_info;

	RtlTimeToTimeFields(&current_loacl_time, &current_time_info);

	KdPrint(("%d/%d/%d-%d:%d:%d\n", current_time_info.Year, current_time_info.Month, current_time_info.Day, current_time_info.Hour, current_time_info.Minute, current_time_info.Second));
	FileWriteInt(current_time_info.Year, 10);
	FileWriteExA("/");
	FileWriteInt(current_time_info.Month, 10);
	FileWriteExA("/");
	FileWriteInt(current_time_info.Day, 10);
	FileWriteExA("-");
	FileWriteInt(current_time_info.Hour, 10);
	FileWriteExA(":");
	FileWriteInt(current_time_info.Minute, 10);
	FileWriteExA(":");
	FileWriteInt(current_time_info.Second, 10);
	FileWriteExA("\r\n");
}

typedef struct {
	LARGE_INTEGER Interval;                      // 间隔的时间
	CUSTOM_TIMER_ROUTINE Routine;                // 定时调用的函数指针
	PVOID Thread;                                // 线程句柄
	KEVENT Exit;                                 // 退出通知
}CUSTOM_TIMER, *PCUSTOM_TIMER;

PCUSTOM_TIMER g_Timer = NULL;

// 全局定时器

// 执行定时器线程
VOID TimerThread(PVOID context) 
{
	UNREFERENCED_PARAMETER(context);
	// 等待间隔时间的通知，无通知则循环。没有用KeDelayExecutionThread
	// 因为调用KeDelayExecutionThread，每次卸载时都有间隔时间内的卡顿
	// 而等待系列函数只要获得通知会立即返回，这也是我在用户模式常用的方法
	while (STATUS_SUCCESS != KeWaitForSingleObject(
		&g_Timer->Exit, Executive, KernelMode, FALSE, &g_Timer->Interval)) {
		g_Timer->Routine();
	}
	//KdPrint(("安全退出\n"));
	// 似乎不用调用PsTerminateSystemThread (STATUS_SUCCESS)也退出了
}
// 创建定时器
BOOLEAN CreateTimer(LONG MilliSecond, CUSTOM_TIMER_ROUTINE routine) 
{
	//KdPrint(("创建\n"));
	
	BOOLEAN bOK = TRUE;
	NTSTATUS status = STATUS_SUCCESS;
	HANDLE hThread = NULL;
	g_Timer = (PCUSTOM_TIMER)ExAllocatePool(NonPagedPool, sizeof(CUSTOM_TIMER));
	if (NULL == g_Timer) 
	{
		bOK = FALSE;
		goto RETURN;
	}
	g_Timer->Interval.QuadPart = -10000 * MilliSecond;
	g_Timer->Routine = routine;
	KeInitializeEvent(&g_Timer->Exit, NotificationEvent, FALSE);
	status = PsCreateSystemThread(
		&hThread,
		0,
		NULL,
		NULL,
		NULL,
		TimerThread,
		NULL
	);
	if (!NT_SUCCESS(status)) 
	{
		bOK = FALSE;
		goto RETURN;
	}
	status = ObReferenceObjectByHandle(
		hThread,
		EVENT_ALL_ACCESS,
		NULL,
		KernelMode,
		&g_Timer->Thread,
		NULL
	);
	if (!NT_SUCCESS(status)) 
	{
		bOK = FALSE;
		goto RETURN;
	}
RETURN:
	if (!bOK && NULL != g_Timer) 
	{
		ExFreePool(g_Timer);
		g_Timer = NULL;
	}
	if (NULL != hThread)
		ZwClose(hThread);
	return bOK;
}
// 销毁定时器
VOID DestroyTimer() {
	//KdPrint(("销毁\n"));

	if (NULL != g_Timer) 
	{
		KeSetEvent(&g_Timer->Exit, IO_NO_INCREMENT, FALSE);
		KeWaitForSingleObject(g_Timer->Thread, Executive, KernelMode, FALSE, NULL);
		ObDereferenceObject(g_Timer->Thread);
		ExFreePool(g_Timer);
		g_Timer = NULL;
	}
}
// 定时器例程实现
VOID TimerFunc() {
	// 简单的打印计数
	static int count = 0;
	FileCreate();
	
	KdPrint(("********************************\n"));

	FileWriteExA("********************************\r\n");
	

	KdPrint(("%dth DETECTION:\n", ++count));
	FileWriteInt(count, 10);
	FileWriteExA("th DETECTION:\r\n");
	
	LocalTime();
	KdPrint(("********************************\n"));
	FileWriteExA("********************************\r\n");

	SSDTdet();

	IRPdet();
	
	IDTAgain();

	FileClose();
}
