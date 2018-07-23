#include "Hook.h"
#include "LDE.h"

VOID PageProtectOff()
{
	ULONG_PTR cr0;
	//__disable();										//屏蔽中断
	Irql = KeRaiseIrqlToDpcLevel();						//提升到DpcLevel然后保存原本的IRQL
	cr0 = __readcr0();									//读取cr0
	cr0 &= 0xfffffffffffeffff;							//对页写入保护位进行清零
	__writecr0(cr0);									//写入cr0
}

VOID PageProtectOn()
{
	ULONG_PTR cr0;
	cr0 = __readcr0();									//读取cr0
	cr0 |= 0x10000;										//还原页保护位
	__writecr0(cr0);									//写入cr0
														//__enable();										//允许接收中断请求
	KeLowerIrql(Irql);									//减低IRQL回最初的值
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
		KdPrint(("不允许通过PID获取计算器的EPROCESS\n"));
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
	KdPrint(("有人打开了文件！\n"));
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


//第一个参数是想要HOOK的函数的名字，第二个函数是提供的过滤的函数的Address
VOID StartHook(PWSTR OldFuncName, ULONG_PTR NewFuncAddress)
{
	LDE_DISASM LDE_Disasm = NULL;					//初始化反汇编引擎
	ULONG_PTR OldFuncAddress = 0;					//获取想要HOOK的函数的地址
	ULONG_PTR TempAddress = 0;						//作为一个临时变量用来缓冲
	ULONG_PTR AsmSize = 0;							//获取指令的长度

	OldCode = NULL;
	OldFunc = NULL;

	OldFuncAddress = GetFuncAddress(OldFuncName);
	if (OldFuncAddress == 0)
	{
		KdPrint(("获取%ws失败！\n", OldFuncName));
		return;
	}
	
	LDE_Disasm = LDE_Init();
	if (LDE_Disasm == NULL)
	{
		KdPrint(("初始化LDE反汇编引擎失败！\n"));
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
		KdPrint(("分配内存失败！\n"));
		return;
	}
	RtlCopyMemory((PVOID)OldCode, (PVOID)OldFuncAddress, AsmSize);

	*(ULONG_PTR*)(JmpCode + 6) = (ULONG_PTR)NewFuncAddress;
	PageProtectOff();
	RtlCopyMemory((PVOID)OldFuncAddress, (PVOID)JmpCode, sizeof(JmpCode));				//把跳转拷贝到原函数上
	PageProtectOn();

	OldFunc = (UCHAR*)sfExAllocate(AsmSize + sizeof(JmpCode));
	if (OldFunc == NULL)
	{
		KdPrint(("分配内存失败！\n"));
		return;
	}
	RtlCopyMemory((PVOID)OldFunc, (PVOID)OldCode, AsmSize);
	RtlCopyMemory((PVOID)(OldFunc + AsmSize), JmpCode, sizeof(JmpCode));
	*(ULONG_PTR*)(OldFunc + AsmSize + 6) = (ULONG_PTR)(OldFuncAddress + AsmSize);

	*(ULONG_PTR*)JmpCode = AsmSize;														
	*(ULONG_PTR*)(JmpCode + 8) = (ULONG_PTR)OldFuncAddress;								//这里JmpCode已经没有作用了，利用一下JmpCode保存OldCode的大小和之前函数的地址，用来卸载HOOK使用
}

VOID StopHook()
{
	ULONG_PTR OldFuncAddress;
	ULONG_PTR OldCodeSize;	
	OldCodeSize = *(ULONG_PTR*)JmpCode;
	OldFuncAddress = *(ULONG_PTR*)(JmpCode + 8);										

	PageProtectOff();
	RtlCopyMemory((PVOID)OldFuncAddress, (PVOID)OldCode, OldCodeSize);					//还原函数的指令
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