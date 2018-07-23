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

extern unsigned __int64 __readcr0(void);			//��ȡcr0��ֵ

extern void __writecr0(unsigned __int64 Data);		//д��cr0

extern void __debugbreak();							//�ϵ㣬����int 3

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

ULONG_PTR GetFuncAddress(PWSTR FuncName);			//���ݺ������ֻ�ȡ������ַ��������ntoskrnl�����ģ�

VOID StartHook();

VOID StopHook();

/*��������HOOK�����е�IRQL�仯ʹ�õ�*/
KIRQL Irql;
/*���JmpCode�ܺ�������FF 25��ת��ȥ*/
UCHAR JmpCode[] = { '\xFF', '\x25', '\x00', '\x00', '\x00', '\x00', '\x90', '\x90', '\x90', '\x90', '\x90', '\x90', '\x90', '\x90'};
/*���OldCode����ԭ�����ϵ�N���ֽڣ������ָ�ʹ�õ�*/
UCHAR *OldCode;
/*�����������������HOOK�ĺ����е���ԭ����ʹ�õ�*/
UCHAR *OldFunc;
#endif