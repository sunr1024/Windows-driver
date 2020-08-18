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
	LARGE_INTEGER Interval;                      // �����ʱ��
	CUSTOM_TIMER_ROUTINE Routine;                // ��ʱ���õĺ���ָ��
	PVOID Thread;                                // �߳̾��
	KEVENT Exit;                                 // �˳�֪ͨ
}CUSTOM_TIMER, *PCUSTOM_TIMER;

PCUSTOM_TIMER g_Timer = NULL;

// ȫ�ֶ�ʱ��

// ִ�ж�ʱ���߳�
VOID TimerThread(PVOID context) 
{
	UNREFERENCED_PARAMETER(context);
	// �ȴ����ʱ���֪ͨ����֪ͨ��ѭ����û����KeDelayExecutionThread
	// ��Ϊ����KeDelayExecutionThread��ÿ��ж��ʱ���м��ʱ���ڵĿ���
	// ���ȴ�ϵ�к���ֻҪ���֪ͨ���������أ���Ҳ�������û�ģʽ���õķ���
	while (STATUS_SUCCESS != KeWaitForSingleObject(
		&g_Timer->Exit, Executive, KernelMode, FALSE, &g_Timer->Interval)) {
		g_Timer->Routine();
	}
	//KdPrint(("��ȫ�˳�\n"));
	// �ƺ����õ���PsTerminateSystemThread (STATUS_SUCCESS)Ҳ�˳���
}
// ������ʱ��
BOOLEAN CreateTimer(LONG MilliSecond, CUSTOM_TIMER_ROUTINE routine) 
{
	//KdPrint(("����\n"));
	
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
// ���ٶ�ʱ��
VOID DestroyTimer() {
	//KdPrint(("����\n"));

	if (NULL != g_Timer) 
	{
		KeSetEvent(&g_Timer->Exit, IO_NO_INCREMENT, FALSE);
		KeWaitForSingleObject(g_Timer->Thread, Executive, KernelMode, FALSE, NULL);
		ObDereferenceObject(g_Timer->Thread);
		ExFreePool(g_Timer);
		g_Timer = NULL;
	}
}
// ��ʱ������ʵ��
VOID TimerFunc() {
	// �򵥵Ĵ�ӡ����
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
