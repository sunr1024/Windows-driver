#include"ntddk.h"
VOID SSDTdet();
VOID IRPdet();

VOID LocalTime();

NTSTATUS FileClose();
NTSTATUS FileWriteExA(char *);
NTSTATUS FileWriteExW(wchar_t *);
NTSTATUS FileWriteInt(ULONG, int);
NTSTATUS FileCreate();

