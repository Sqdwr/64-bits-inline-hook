#include "Hook.h"

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

VOID StartHook()
{
	ULONG_PTR PsLookupAddress;

	PsLookupAddress = GetFuncAddress(L"PsLookupProcessByProcessId");
	
	OldFunc = (UCHAR*)sfExAllocate(sizeof(OldCode) + sizeof(JmpOld));					//先分配内存出来，如果分配失败也没必须要继续了，因为这是跳转回来的函数

	if (OldFunc == NULL)
	{
		KdPrint(("分配内存失败！\n"));
		return;
	}

	*(ULONG_PTR*)(JmpOld + 6) = PsLookupAddress + 15;									//跳转回原函数上15个字节处

	*(ULONG_PTR*)(NewCode + 6) = (ULONG_PTR)MyPsLookupProcessByProcessId;				//跳转地址指向我们自己的函数

	RtlCopyMemory((PVOID)OldCode, (PVOID)PsLookupAddress, sizeof(OldCode));				//拷贝原本函数最上面的15个字节保存起来

	PageProtectOff();

	RtlCopyMemory((PVOID)PsLookupAddress, (PVOID)NewCode, sizeof(NewCode));				//把跳转拷贝到原函数上

	PageProtectOn();

	RtlCopyMemory((PVOID)OldFunc, (PVOID)OldCode, sizeof(OldCode));						//拷贝原本的十五个字节出来

	RtlCopyMemory((PVOID)(OldFunc + sizeof(OldCode)), (PVOID)JmpOld, sizeof(JmpOld));	//拷贝跳转回原函数第十五个字节处的指令进来
}

VOID StopHook()
{
	ULONG_PTR PsLookupAddress;

	PsLookupAddress = GetFuncAddress(L"PsLookupProcessByProcessId");

	PageProtectOff();

	RtlCopyMemory((PVOID)PsLookupAddress, (PVOID)OldCode, sizeof(OldCode));				//还原函数的指令

	PageProtectOn();

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
	StartHook();
	DriverObject->DriverUnload = Unload;
	return STATUS_SUCCESS;
}