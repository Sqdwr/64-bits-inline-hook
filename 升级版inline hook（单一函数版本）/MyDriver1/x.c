#include "Hook.h"
#include "LDE.h"

VOID PageProtectOff()
{
	ULONG_PTR cr0;
	//__disable();										//�����ж�
	Irql = KeRaiseIrqlToDpcLevel();						//������DpcLevelȻ�󱣴�ԭ����IRQL
	cr0 = __readcr0();									//��ȡcr0
	cr0 &= 0xfffffffffffeffff;							//��ҳд�뱣��λ��������
	__writecr0(cr0);									//д��cr0
}

VOID PageProtectOn()
{
	ULONG_PTR cr0;
	cr0 = __readcr0();									//��ȡcr0
	cr0 |= 0x10000;										//��ԭҳ����λ
	__writecr0(cr0);									//д��cr0
														//__enable();										//��������ж�����
	KeLowerIrql(Irql);									//����IRQL�������ֵ
}

ULONG_PTR GetFuncAddress(PWSTR FuncName)
{
	UNICODE_STRING uFunctionName;
	RtlInitUnicodeString(&uFunctionName, FuncName);
	return (ULONG_PTR)MmGetSystemRoutineAddress(&uFunctionName);
}

NTSTATUS __fastcall MyPsLookupProcessByProcessId(__in HANDLE ProcessId, __deref_out PEPROCESS *Process)
{
	NTSTATUS RetStatus;

	RetStatus = ((PSLOOKUPPROCESSBYPROCESSID)(OldFunc))(ProcessId, Process);
	if (NT_SUCCESS(RetStatus) && strstr((CHAR*)PsGetProcessImageFileName(*Process), "calc"))
	{
		KdPrint(("������ͨ��PID��ȡ��������EPROCESS\n"));
		*Process = NULL;
		return STATUS_ACCESS_DENIED;
	}

	return RetStatus;
}

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
)
{
	KdPrint(("���˴����ļ���\n"));
	return ((NTCREATEFILE)(OldFunc))(
		FileHandle,
		DesiredAccess,
		ObjectAttributes,
		IoStatusBlock,
		AllocationSize,
		FileAttributes,
		ShareAccess,
		CreateDisposition,
		CreateOptions,
		EaBuffer,
		EaLength);
}


//��һ����������ҪHOOK�ĺ��������֣��ڶ����������ṩ�Ĺ��˵ĺ�����Address
VOID StartHook(PWSTR OldFuncName, ULONG_PTR NewFuncAddress)
{
	LDE_DISASM LDE_Disasm = NULL;					//��ʼ�����������
	ULONG_PTR OldFuncAddress = 0;					//��ȡ��ҪHOOK�ĺ����ĵ�ַ
	ULONG_PTR TempAddress = 0;						//��Ϊһ����ʱ������������
	ULONG_PTR AsmSize = 0;							//��ȡָ��ĳ���

	OldCode = NULL;
	OldFunc = NULL;

	OldFuncAddress = GetFuncAddress(OldFuncName);
	if (OldFuncAddress == 0)
	{
		KdPrint(("��ȡ%wsʧ�ܣ�\n", OldFuncName));
		return;
	}
	
	LDE_Disasm = LDE_Init();
	if (LDE_Disasm == NULL)
	{
		KdPrint(("��ʼ��LDE���������ʧ�ܣ�\n"));
		return;
	}

	TempAddress = OldFuncAddress;
	while (TempAddress - OldFuncAddress < 14)
	{
		AsmSize = LDE_Disasm((PVOID)TempAddress, 64);
		TempAddress += AsmSize;
	}
	AsmSize = TempAddress - OldFuncAddress;
	sfExFree((PVOID)LDE_Disasm);

	OldCode = (UCHAR*)sfExAllocate(AsmSize);
	if (OldCode == NULL)
	{
		KdPrint(("�����ڴ�ʧ�ܣ�\n"));
		return;
	}
	RtlCopyMemory((PVOID)OldCode, (PVOID)OldFuncAddress, AsmSize);

	*(ULONG_PTR*)(JmpCode + 6) = (ULONG_PTR)NewFuncAddress;
	PageProtectOff();
	RtlCopyMemory((PVOID)OldFuncAddress, (PVOID)JmpCode, sizeof(JmpCode));				//����ת������ԭ������
	PageProtectOn();

	OldFunc = (UCHAR*)sfExAllocate(AsmSize + sizeof(JmpCode));
	if (OldFunc == NULL)
	{
		KdPrint(("�����ڴ�ʧ�ܣ�\n"));
		return;
	}
	RtlCopyMemory((PVOID)OldFunc, (PVOID)OldCode, AsmSize);
	RtlCopyMemory((PVOID)(OldFunc + AsmSize), JmpCode, sizeof(JmpCode));
	*(ULONG_PTR*)(OldFunc + AsmSize + 6) = (ULONG_PTR)(OldFuncAddress + AsmSize);

	*(ULONG_PTR*)JmpCode = AsmSize;														
	*(ULONG_PTR*)(JmpCode + 8) = (ULONG_PTR)OldFuncAddress;								//����JmpCode�Ѿ�û�������ˣ�����һ��JmpCode����OldCode�Ĵ�С��֮ǰ�����ĵ�ַ������ж��HOOKʹ��
}

VOID StopHook()
{
	ULONG_PTR OldFuncAddress;
	ULONG_PTR OldCodeSize;	
	OldCodeSize = *(ULONG_PTR*)JmpCode;
	OldFuncAddress = *(ULONG_PTR*)(JmpCode + 8);										

	PageProtectOff();
	RtlCopyMemory((PVOID)OldFuncAddress, (PVOID)OldCode, OldCodeSize);					//��ԭ������ָ��
	PageProtectOn();

	sfExFree(OldCode);
	sfExFree(OldFunc);
}

VOID Unload(PDRIVER_OBJECT DriverObject)
{
	StopHook();
	KdPrint(("Unload Success!\n"));
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegString)
{
	KdPrint(("Entry Driver!\n"));

	StartHook(L"NtCreateFile", (ULONG_PTR)MyNtCreateFile);
	//StartHook(L"PsLookupProcessByProcessId",(ULONG_PTR)MyPsLookupProcessByProcessId);
	DriverObject->DriverUnload = Unload;
	return STATUS_SUCCESS;
}