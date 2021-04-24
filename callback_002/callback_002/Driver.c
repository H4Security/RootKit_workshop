
#include <Ntifs.h>
#include <ntddk.h>
#include <wdm.h>

#define DEVICE_NAME_PROCESS				L"\\Device\\CallBacks"
#define SYMBOLINK_NAME_PROCESS			L"\\??\\CallBacks"


DRIVER_INITIALIZE  DriverEntry;


void sCreateProcessNotifyRoutineEx(PEPROCESS process, HANDLE pid, PPS_CREATE_NOTIFY_INFO createInfo)
{
	KdPrint(("\n[+] sCreateProcessNotifyRoutineEx\n\n"));
	UNREFERENCED_PARAMETER(process);
	UNREFERENCED_PARAMETER(pid);
	
	if (createInfo != NULL)
	{
		KdPrint(("[+] Process Command line------->%wZ\n", createInfo->CommandLine->Buffer));
		if (wcscmp(createInfo->CommandLine->Buffer,L"notepad") == 0)
		{
			DbgPrint("[!] Access to %wZ was denied!\n\n", "Notepad");
			createInfo->CreationStatus = STATUS_ACCESS_DENIED;
		}
		DbgPrint("CreateProcessNotifyRoutine2:ParentId=%d\n parentProcessName=%wZ\n ", pid, createInfo->ImageFileName);
	}
	//PUNICODE_STRING  processName = NULL ;
	//SeLocateProcessImageName(process, &processName);
	
}


VOID CallBackDriverUnload(IN PDRIVER_OBJECT pDriverObject)
{
	UNICODE_STRING strSymbolLinkName;

	DbgPrint("In DriverUnload !");

	RtlInitUnicodeString(&strSymbolLinkName, SYMBOLINK_NAME_PROCESS);
	IoDeleteSymbolicLink(&strSymbolLinkName);
	IoDeleteDevice(pDriverObject->DeviceObject);


	
	PsSetCreateProcessNotifyRoutineEx(sCreateProcessNotifyRoutineEx, TRUE);

	DbgPrint("Out CallBackDriverUnload !");
}


NTSTATUS MajorFunctions(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	PIO_STACK_LOCATION stackLocation = NULL;
	stackLocation = IoGetCurrentIrpStackLocation(Irp);

	switch (stackLocation->MajorFunction)
	{
	case IRP_MJ_CREATE:
		DbgPrint("Handle to symbolink link %wZ opened", SYMBOLINK_NAME_PROCESS);
		break;
	case IRP_MJ_CLOSE:
		DbgPrint("Handle to symbolink link %wZ closed", SYMBOLINK_NAME_PROCESS);
		break;
	default:
		break;
	}

	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}


NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT  DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
{

	//ULONG i;
	NTSTATUS status;
	UNICODE_STRING strDeviceName;
	UNICODE_STRING strSymbolLinkName;
	PDEVICE_OBJECT pDeviceObject;
	
	
	pDeviceObject = NULL;

	KdPrint(("\nregister: %ws\n\n", RegistryPath->Buffer));

	RtlInitUnicodeString(&strDeviceName, DEVICE_NAME_PROCESS);
	RtlInitUnicodeString(&strSymbolLinkName, SYMBOLINK_NAME_PROCESS);

	
	// routines that will execute once a handle to our device's symbolik link is opened/closed
	DriverObject->MajorFunction[IRP_MJ_CREATE] = MajorFunctions;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = MajorFunctions;

	DriverObject->DriverUnload = CallBackDriverUnload;

	status = IoCreateDevice(DriverObject, 0, &strDeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &pDeviceObject);

	if (!NT_SUCCESS(status))
	{
		KdPrint(("Create Device Failed!\n"));
		return status;
	}
	if (!pDeviceObject)
	{
		KdPrint(("Create Device Failed pDeviceObject!\n"));
		return STATUS_UNEXPECTED_IO_ERROR;
	}

	KdPrint(("DriverEntry===->\n"));
	status = IoCreateSymbolicLink(&strSymbolLinkName, &strDeviceName);
	if (!NT_SUCCESS(status)) {
		KdPrint(("[-] CallBack Driver: Failed to create symbolic link (0x%08X)\n", status));
		IoDeleteDevice(pDeviceObject);
		return status;
	}
	
	NTSTATUS pn = STATUS_SUCCESS;
	/*pn = PsSetCreateProcessNotifyRoutine((PCREATE_PROCESS_NOTIFY_ROUTINE)CreateProcessNotify, FALSE);
	if (pn != STATUS_SUCCESS)
		KdPrint(("[+] CallBack Driver:PsSetCreateProcessNotifyRoutine Successful!!!!"));
	else
		KdPrint(("[-] CallBack Driver:Failed PsSetCreateProcessNotifyRoutine!!!!!"));
		*/
	pn = STATUS_SUCCESS;
	pn = PsSetCreateProcessNotifyRoutineEx((PCREATE_PROCESS_NOTIFY_ROUTINE_EX )sCreateProcessNotifyRoutineEx, FALSE);
	if (pn != STATUS_SUCCESS)
		KdPrint(("[+] CallBack Driver:PsSetCreateProcessNotifyRoutineEx Successful!!!!"));
	else
		KdPrint(("[-] CallBack Driver:Failed PsSetCreateProcessNotifyRoutineEx!!!!!"));

	return STATUS_SUCCESS;
}


