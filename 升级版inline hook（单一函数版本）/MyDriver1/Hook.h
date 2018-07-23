#pragma once
#ifndef HOOK_H
#define HOOK_H
#include <ntifs.h>
#include <ntddk.h>

#define sfExAllocate(size) ExAllocatePoolWithTag(NonPagedPool,size,'ytz')
#define sfExFree(p) {if(p != NULL){ExFreePoolWithTag(p,'ytz');p = NULL;}}

typedef NTSTATUS(__fastcall*PSLOOKUPPROCESSBYPROCESSID)(__in HANDLE ProcessId, __deref_out PEPROCESS *Process);
typedef NTSTATUS(__fastcall *NTCREATEFILE)(
	_Out_ PHANDLE FileHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_In_opt_ PLARGE_INTEGER AllocationSize,
	_In_ ULONG FileAttributes,
	_In_ ULONG ShareAccess,
	_In_ ULONG CreateDisposition,
	_In_ ULONG CreateOptions,
	_In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
	_In_ ULONG EaLength
	);

extern UCHAR *PsGetProcessImageFileName(PEPROCESS Process);

extern unsigned __int64 __readcr0(void);			//读取cr0的值

extern void __writecr0(unsigned __int64 Data);		//写入cr0

extern void __debugbreak();							//断点，类似int 3

VOID PageProtectOff();

VOID PageProtectOn();

NTSTATUS __fastcall MyPsLookupProcessByProcessId(__in HANDLE ProcessId, __deref_out PEPROCESS *Process);
NTSTATUS __fastcall MyNtCreateFile(
	_Out_ PHANDLE FileHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_In_opt_ PLARGE_INTEGER AllocationSize,
	_In_ ULONG FileAttributes,
	_In_ ULONG ShareAccess,
	_In_ ULONG CreateDisposition,
	_In_ ULONG CreateOptions,
	_In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
	_In_ ULONG EaLength
);

ULONG_PTR GetFuncAddress(PWSTR FuncName);			//根据函数名字获取函数地址（必须是ntoskrnl导出的）

VOID StartHook();

VOID StopHook();

/*用来担当HOOK过程中的IRQL变化使用的*/
KIRQL Irql;
/*这个JmpCode很好理解就是FF 25跳转过去*/
UCHAR JmpCode[] = { '\xFF', '\x25', '\x00', '\x00', '\x00', '\x00', '\x90', '\x90', '\x90', '\x90', '\x90', '\x90', '\x90', '\x90'};
/*这个OldCode就是原本顶上的N个字节，用来恢复使用的*/
UCHAR *OldCode;
/*这个变量则是用来在HOOK的函数中调用原函数使用的*/
UCHAR *OldFunc;
#endif