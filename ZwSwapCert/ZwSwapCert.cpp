#include "RawDriver.hpp"
#include "ZwSwapCert.hpp"

// this function was taken from Kernel-Force-Delete...
// https://github.com/DragonQuestHero/Kernel-Force-Delete/blob/master/Kernel_Force_Delete/Kernel_Force_Delete.cc#L3
// (i cleaned it up a little and put it in here)
NTSTATUS Utils::SwapDriver(PUNICODE_STRING DriverPath, PVOID DriverBuffer, SIZE_T BufferSize)
{
	HANDLE FileHandle;
	NTSTATUS Status;
	IO_STATUS_BLOCK IOBlock;
	PDEVICE_OBJECT DeviceObject = nullptr;
	PFILE_OBJECT FileObject = nullptr;
	OBJECT_ATTRIBUTES FileAttributes;

	RtlZeroMemory(&IOBlock, sizeof IOBlock);
	InitializeObjectAttributes(&FileAttributes,
		DriverPath,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL);

	if ((Status = IoCreateFileSpecifyDeviceObjectHint(
		&FileHandle,
		SYNCHRONIZE | FILE_WRITE_ATTRIBUTES | FILE_READ_ATTRIBUTES | FILE_READ_DATA,
		&FileAttributes,
		&IOBlock,
		NULL,
		NULL,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		FILE_OPEN,
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		NULL,
		CreateFileTypeNone,
		NULL,
		IO_IGNORE_SHARE_ACCESS_CHECK,
		DeviceObject)) != STATUS_SUCCESS)
			return Status;


	if ((Status = ObReferenceObjectByHandle(
		FileHandle, NULL, NULL, NULL, (PVOID*)&FileObject, NULL)) != STATUS_SUCCESS)
		return Status;

	// Make the driver file object section object null and then try 
	// and delete the file on disk...
	FileObject->SectionObjectPointer->ImageSectionObject = 0;
	FileObject->DeleteAccess = 1;
	if ((Status = ZwDeleteFile(&FileAttributes)) != STATUS_SUCCESS)
		return Status;

	ObDereferenceObject(FileObject);
	if ((Status = ZwClose(FileHandle)) != STATUS_SUCCESS)
		return Status;

	RtlZeroMemory(&IOBlock, sizeof IOBlock);
	InitializeObjectAttributes(&FileAttributes, DriverPath,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL, NULL);

	// Create a new file where the driver was on disk
	// instead we are going to write a valid driver to disk...
	// (by valid i mean signed by MS...)
	if ((Status = ZwCreateFile(
		&FileHandle,
		GENERIC_WRITE,
		&FileAttributes,
		&IOBlock,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		NULL,
		FILE_OVERWRITE_IF,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		NULL
	)) != STATUS_SUCCESS)
		return Status;

	// Write the driver buffer to disk...
	if ((Status = ZwWriteFile(
		FileHandle,
		NULL,
		NULL,
		NULL,
		&IOBlock,
		DriverBuffer,
		BufferSize,
		NULL,
		NULL
	)) != STATUS_SUCCESS)
		return Status;

	return ZwClose(FileHandle);
}

PVOID Utils::MapDriver(UINT64 ModuleBase, UINT64 DriverBuffer)
{
	// copy pe header...
	PIMAGE_DOS_HEADER dosHeaders = (IMAGE_DOS_HEADER*)DriverBuffer;
	PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)(DriverBuffer + dosHeaders->e_lfanew);

	// disable write protect bit in cr0...
	{
		auto cr0 = __readcr0();
		cr0 &= 0xfffffffffffeffff;
		__writecr0(cr0);
		_disable();
	}

	// PE headers are not writeable (readonly i assume? so we disable WP bit)...
	memcpy((PVOID)ModuleBase, (PVOID)DriverBuffer, ntHeaders->OptionalHeader.SizeOfHeaders);

	// enable write protect bit in cr0...
	{
		auto cr0 = __readcr0();
		cr0 |= 0x10000;
		_enable();
		__writecr0(cr0);
	}

	PIMAGE_SECTION_HEADER sections = 
		(PIMAGE_SECTION_HEADER)((UINT8*)&ntHeaders->OptionalHeader +
			ntHeaders->FileHeader.SizeOfOptionalHeader);

	// map sections...
	for (UINT32 i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i)
	{
		PIMAGE_SECTION_HEADER section = &sections[i];
		memcpy((PVOID)(ModuleBase + section->VirtualAddress), 
			(PVOID)(DriverBuffer + section->PointerToRawData), section->SizeOfRawData);
	}

	// return entry point...
	return (PVOID)(ModuleBase + ntHeaders->OptionalHeader.AddressOfEntryPoint);
}

NTSTATUS ScDriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNICODE_STRING DriverPath;
	NTSTATUS Result;

	// get the path to the current driver on disk...
	if ((Result = IoQueryFullDriverPath(DriverObject, &DriverPath)) != STATUS_SUCCESS)
		return Result;

	// replace file on disk with the MS driver...
	if ((Result = Utils::SwapDriver(&DriverPath, RawDriver, MS_DRIVER_FILE_SIZE)) != STATUS_SUCCESS)
		return Result;

	// allocate a temp buffer, copy the MS driver into the buffer
	// and then map the driver from the buffer into the first section
	// of this driver + overwrite this drivers PE headers...
	PVOID DriverTempBuffer = 
		ExAllocatePool(NonPagedPool, sizeof RawDriver);

	memcpy(DriverTempBuffer, RawDriver, sizeof RawDriver);
	PDRIVER_INITIALIZE SignedDriverEntry = (PDRIVER_INITIALIZE) 
		Utils::MapDriver((UINT64)DriverObject->DriverStart, (UINT64)DriverTempBuffer);

	// change driver size and entry point to the mapped MS driver...
	ExFreePool(DriverTempBuffer);
	DriverObject->DriverSize = sizeof RawDriver;
	DriverObject->DriverInit = SignedDriverEntry;
	return drv_entry(DriverObject, RegistryPath);
}