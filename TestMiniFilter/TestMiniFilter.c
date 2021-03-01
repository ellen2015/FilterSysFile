/*++

Module Name:

    TestMiniFilter.c

Abstract:

    This is the main module of the TestMiniFilter miniFilter driver.

Environment:

    Kernel mode

--*/

#include <fltKernel.h>
#include <ntstrsafe.h>
#include <dontuse.h>

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")


PFLT_FILTER gFilterHandle;
ULONG_PTR OperationStatusCtx = 1;

#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002

ULONG gTraceFlags = 0;


#define PT_DBG_PRINT( _dbgLevel, _string )          \
    (FlagOn(gTraceFlags,(_dbgLevel)) ?              \
        DbgPrint _string :                          \
        ((int)0))

/*************************************************************************
    Prototypes
*************************************************************************/

EXTERN_C_START

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    );

NTSTATUS
TestMiniFilterInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    );

VOID
TestMiniFilterInstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

VOID
TestMiniFilterInstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

NTSTATUS
TestMiniFilterUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    );

NTSTATUS
TestMiniFilterInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
TestMiniFilterPreOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

VOID
TestMiniFilterOperationStatusCallback (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
    _In_ NTSTATUS OperationStatus,
    _In_ PVOID RequesterContext
    );

FLT_POSTOP_CALLBACK_STATUS
TestMiniFilterPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
TestMiniFilterPreOperationNoPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

BOOLEAN
TestMiniFilterDoRequestOperationStatus(
    _In_ PFLT_CALLBACK_DATA Data
    );


// 自己需要实现的函数
// 拷贝需要过滤的文件（驱动文件）
NTSTATUS
FltCopyFile(
	PCFLT_RELATED_OBJECTS FltObjects,
	PFLT_FILE_NAME_INFORMATION NameInfo);

// 过滤函数
FLT_PREOP_CALLBACK_STATUS
SYSFilterPreSection(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID* CompletionContext);



EXTERN_C_END

//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, TestMiniFilterUnload)
#pragma alloc_text(PAGE, TestMiniFilterInstanceQueryTeardown)
#pragma alloc_text(PAGE, TestMiniFilterInstanceSetup)
#pragma alloc_text(PAGE, TestMiniFilterInstanceTeardownStart)
#pragma alloc_text(PAGE, TestMiniFilterInstanceTeardownComplete)
#pragma alloc_text(PAGE, SYSFilterPreSection)
#endif

//
//  operation registration
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {

	// 过滤部分
	{ IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,
	  0,
	  SYSFilterPreSection,
	  NULL },

	// 其他框架函数，需要过滤的话  放在外面即可
#if 0 // TODO - List all of the requests to filter.
    { IRP_MJ_CREATE,
      0,
      TestMiniFilterPreOperation,
      TestMiniFilterPostOperation },

    { IRP_MJ_CREATE_NAMED_PIPE,
      0,
      TestMiniFilterPreOperation,
      TestMiniFilterPostOperation },

    { IRP_MJ_CLOSE,
      0,
      TestMiniFilterPreOperation,
      TestMiniFilterPostOperation },

    { IRP_MJ_READ,
      0,
      TestMiniFilterPreOperation,
      TestMiniFilterPostOperation },

    { IRP_MJ_WRITE,
      0,
      TestMiniFilterPreOperation,
      TestMiniFilterPostOperation },

    { IRP_MJ_QUERY_INFORMATION,
      0,
      TestMiniFilterPreOperation,
      TestMiniFilterPostOperation },

    { IRP_MJ_SET_INFORMATION,
      0,
      TestMiniFilterPreOperation,
      TestMiniFilterPostOperation },

    { IRP_MJ_QUERY_EA,
      0,
      TestMiniFilterPreOperation,
      TestMiniFilterPostOperation },

    { IRP_MJ_SET_EA,
      0,
      TestMiniFilterPreOperation,
      TestMiniFilterPostOperation },

    { IRP_MJ_FLUSH_BUFFERS,
      0,
      TestMiniFilterPreOperation,
      TestMiniFilterPostOperation },

    { IRP_MJ_QUERY_VOLUME_INFORMATION,
      0,
      TestMiniFilterPreOperation,
      TestMiniFilterPostOperation },

    { IRP_MJ_SET_VOLUME_INFORMATION,
      0,
      TestMiniFilterPreOperation,
      TestMiniFilterPostOperation },

    { IRP_MJ_DIRECTORY_CONTROL,
      0,
      TestMiniFilterPreOperation,
      TestMiniFilterPostOperation },

    { IRP_MJ_FILE_SYSTEM_CONTROL,
      0,
      TestMiniFilterPreOperation,
      TestMiniFilterPostOperation },

    { IRP_MJ_DEVICE_CONTROL,
      0,
      TestMiniFilterPreOperation,
      TestMiniFilterPostOperation },

    { IRP_MJ_INTERNAL_DEVICE_CONTROL,
      0,
      TestMiniFilterPreOperation,
      TestMiniFilterPostOperation },

    { IRP_MJ_SHUTDOWN,
      0,
      TestMiniFilterPreOperationNoPostOperation,
      NULL },                               //post operations not supported

    { IRP_MJ_LOCK_CONTROL,
      0,
      TestMiniFilterPreOperation,
      TestMiniFilterPostOperation },

    { IRP_MJ_CLEANUP,
      0,
      TestMiniFilterPreOperation,
      TestMiniFilterPostOperation },

    { IRP_MJ_CREATE_MAILSLOT,
      0,
      TestMiniFilterPreOperation,
      TestMiniFilterPostOperation },

    { IRP_MJ_QUERY_SECURITY,
      0,
      TestMiniFilterPreOperation,
      TestMiniFilterPostOperation },

    { IRP_MJ_SET_SECURITY,
      0,
      TestMiniFilterPreOperation,
      TestMiniFilterPostOperation },

    { IRP_MJ_QUERY_QUOTA,
      0,
      TestMiniFilterPreOperation,
      TestMiniFilterPostOperation },

    { IRP_MJ_SET_QUOTA,
      0,
      TestMiniFilterPreOperation,
      TestMiniFilterPostOperation },

    { IRP_MJ_PNP,
      0,
      TestMiniFilterPreOperation,
      TestMiniFilterPostOperation },

    

    { IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION,
      0,
      TestMiniFilterPreOperation,
      TestMiniFilterPostOperation },

    { IRP_MJ_ACQUIRE_FOR_MOD_WRITE,
      0,
      TestMiniFilterPreOperation,
      TestMiniFilterPostOperation },

    { IRP_MJ_RELEASE_FOR_MOD_WRITE,
      0,
      TestMiniFilterPreOperation,
      TestMiniFilterPostOperation },

    { IRP_MJ_ACQUIRE_FOR_CC_FLUSH,
      0,
      TestMiniFilterPreOperation,
      TestMiniFilterPostOperation },

    { IRP_MJ_RELEASE_FOR_CC_FLUSH,
      0,
      TestMiniFilterPreOperation,
      TestMiniFilterPostOperation },

    { IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE,
      0,
      TestMiniFilterPreOperation,
      TestMiniFilterPostOperation },

    { IRP_MJ_NETWORK_QUERY_OPEN,
      0,
      TestMiniFilterPreOperation,
      TestMiniFilterPostOperation },

    { IRP_MJ_MDL_READ,
      0,
      TestMiniFilterPreOperation,
      TestMiniFilterPostOperation },

    { IRP_MJ_MDL_READ_COMPLETE,
      0,
      TestMiniFilterPreOperation,
      TestMiniFilterPostOperation },

    { IRP_MJ_PREPARE_MDL_WRITE,
      0,
      TestMiniFilterPreOperation,
      TestMiniFilterPostOperation },

    { IRP_MJ_MDL_WRITE_COMPLETE,
      0,
      TestMiniFilterPreOperation,
      TestMiniFilterPostOperation },

    { IRP_MJ_VOLUME_MOUNT,
      0,
      TestMiniFilterPreOperation,
      TestMiniFilterPostOperation },

    { IRP_MJ_VOLUME_DISMOUNT,
      0,
      TestMiniFilterPreOperation,
      TestMiniFilterPostOperation },

#endif // TODO

    { IRP_MJ_OPERATION_END }
};

//
//  This defines what we want to filter with FltMgr
//

CONST FLT_REGISTRATION FilterRegistration = {

    sizeof( FLT_REGISTRATION ),         //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags

    NULL,                               //  Context
    Callbacks,                          //  Operation callbacks

    TestMiniFilterUnload,                           //  MiniFilterUnload

    TestMiniFilterInstanceSetup,                    //  InstanceSetup
    TestMiniFilterInstanceQueryTeardown,            //  InstanceQueryTeardown
    TestMiniFilterInstanceTeardownStart,            //  InstanceTeardownStart
    TestMiniFilterInstanceTeardownComplete,         //  InstanceTeardownComplete

    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent

};



NTSTATUS
TestMiniFilterInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    )
/*++

Routine Description:

    This routine is called whenever a new instance is created on a volume. This
    gives us a chance to decide if we need to attach to this volume or not.

    If this routine is not defined in the registration structure, automatic
    instances are always created.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Flags describing the reason for this attach request.

Return Value:

    STATUS_SUCCESS - attach
    STATUS_FLT_DO_NOT_ATTACH - do not attach

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );
    UNREFERENCED_PARAMETER( VolumeDeviceType );
    UNREFERENCED_PARAMETER( VolumeFilesystemType );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("TestMiniFilter!TestMiniFilterInstanceSetup: Entered\n") );

    return STATUS_SUCCESS;
}


NTSTATUS
TestMiniFilterInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This is called when an instance is being manually deleted by a
    call to FltDetachVolume or FilterDetach thereby giving us a
    chance to fail that detach request.

    If this routine is not defined in the registration structure, explicit
    detach requests via FltDetachVolume or FilterDetach will always be
    failed.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Indicating where this detach request came from.

Return Value:

    Returns the status of this operation.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("TestMiniFilter!TestMiniFilterInstanceQueryTeardown: Entered\n") );

    return STATUS_SUCCESS;
}


VOID
TestMiniFilterInstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This routine is called at the start of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is being deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("TestMiniFilter!TestMiniFilterInstanceTeardownStart: Entered\n") );
}


VOID
TestMiniFilterInstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This routine is called at the end of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is being deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("TestMiniFilter!TestMiniFilterInstanceTeardownComplete: Entered\n") );
}


/*************************************************************************
    MiniFilter initialization and unload routines.
*************************************************************************/

NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
/*++

Routine Description:

    This is the initialization routine for this miniFilter driver.  This
    registers with FltMgr and initializes all global data structures.

Arguments:

    DriverObject - Pointer to driver object created by the system to
        represent this driver.

    RegistryPath - Unicode string identifying where the parameters for this
        driver are located in the registry.

Return Value:

    Routine can return non success error codes.

--*/
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER( RegistryPath );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("TestMiniFilter!DriverEntry: Entered\n") );

    //
    //  Register with FltMgr to tell it our callback routines
    //

    status = FltRegisterFilter( DriverObject,
                                &FilterRegistration,
                                &gFilterHandle );

    FLT_ASSERT( NT_SUCCESS( status ) );

    if (NT_SUCCESS( status )) {

        //
        //  Start filtering i/o
        //

        status = FltStartFiltering( gFilterHandle );

        if (!NT_SUCCESS( status )) {

            FltUnregisterFilter( gFilterHandle );
        }
    }

    return status;
}

NTSTATUS
TestMiniFilterUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
/*++

Routine Description:

    This is the unload routine for this miniFilter driver. This is called
    when the minifilter is about to be unloaded. We can fail this unload
    request if this is not a mandatory unload indicated by the Flags
    parameter.

Arguments:

    Flags - Indicating if this is a mandatory unload.

Return Value:

    Returns STATUS_SUCCESS.

--*/
{
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("TestMiniFilter!TestMiniFilterUnload: Entered\n") );

    FltUnregisterFilter( gFilterHandle );

    return STATUS_SUCCESS;
}


/*************************************************************************
    MiniFilter callback routines.
*************************************************************************/
FLT_PREOP_CALLBACK_STATUS
TestMiniFilterPreOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
/*++

Routine Description:

    This routine is a pre-operation dispatch routine for this miniFilter.

    This is non-pageable because it could be called on the paging path

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The context for the completion routine for this
        operation.

Return Value:

    The return value is the status of the operation.

--*/
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("TestMiniFilter!TestMiniFilterPreOperation: Entered\n") );

    //
    //  See if this is an operation we would like the operation status
    //  for.  If so request it.
    //
    //  NOTE: most filters do NOT need to do this.  You only need to make
    //        this call if, for example, you need to know if the oplock was
    //        actually granted.
    //

    if (TestMiniFilterDoRequestOperationStatus( Data )) {

        status = FltRequestOperationStatusCallback( Data,
                                                    TestMiniFilterOperationStatusCallback,
                                                    (PVOID)(++OperationStatusCtx) );
        if (!NT_SUCCESS(status)) {

            PT_DBG_PRINT( PTDBG_TRACE_OPERATION_STATUS,
                          ("TestMiniFilter!TestMiniFilterPreOperation: FltRequestOperationStatusCallback Failed, status=%08x\n",
                           status) );
        }
    }

    // This template code does not do anything with the callbackData, but
    // rather returns FLT_PREOP_SUCCESS_WITH_CALLBACK.
    // This passes the request down to the next miniFilter in the chain.

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS
SYSFilterPreSection(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID* CompletionContext)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	KIRQL irql = KeGetCurrentIrql();
	PFLT_FILE_NAME_INFORMATION fileNameInformation = NULL;

	if (irql > APC_LEVEL)
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	// 过滤拷贝加载的驱动文件
	if (Data->Iopb->Parameters.AcquireForSectionSynchronization.PageProtection == PAGE_EXECUTE)
	{
		if ((HANDLE)4 == PsGetCurrentProcessId())
		{
			// 获取过滤对象的名字信息
			status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &fileNameInformation);
			if (!NT_SUCCESS(status))
			{
				return FLT_PREOP_SUCCESS_NO_CALLBACK;
			}

			// 解析
			status = FltParseFileNameInformation(fileNameInformation);
			if (!NT_SUCCESS(status))
			{
				return FLT_PREOP_SUCCESS_NO_CALLBACK;
			}

			// 干活了。。。
			status = FltCopyFile(FltObjects, fileNameInformation);

			FltReleaseFileNameInformation(fileNameInformation);
		}
	}



	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

VOID
TestMiniFilterOperationStatusCallback (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
    _In_ NTSTATUS OperationStatus,
    _In_ PVOID RequesterContext
    )
/*++

Routine Description:

    This routine is called when the given operation returns from the call
    to IoCallDriver.  This is useful for operations where STATUS_PENDING
    means the operation was successfully queued.  This is useful for OpLocks
    and directory change notification operations.

    This callback is called in the context of the originating thread and will
    never be called at DPC level.  The file object has been correctly
    referenced so that you can access it.  It will be automatically
    dereferenced upon return.

    This is non-pageable because it could be called on the paging path

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    RequesterContext - The context for the completion routine for this
        operation.

    OperationStatus -

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("TestMiniFilter!TestMiniFilterOperationStatusCallback: Entered\n") );

    PT_DBG_PRINT( PTDBG_TRACE_OPERATION_STATUS,
                  ("TestMiniFilter!TestMiniFilterOperationStatusCallback: Status=%08x ctx=%p IrpMj=%02x.%02x \"%s\"\n",
                   OperationStatus,
                   RequesterContext,
                   ParameterSnapshot->MajorFunction,
                   ParameterSnapshot->MinorFunction,
                   FltGetIrpName(ParameterSnapshot->MajorFunction)) );
}


FLT_POSTOP_CALLBACK_STATUS
TestMiniFilterPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
/*++

Routine Description:

    This routine is the post-operation completion routine for this
    miniFilter.

    This is non-pageable because it may be called at DPC level.

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The completion context set in the pre-operation routine.

    Flags - Denotes whether the completion is successful or is being drained.

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER( Data );
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );
    UNREFERENCED_PARAMETER( Flags );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("TestMiniFilter!TestMiniFilterPostOperation: Entered\n") );

    return FLT_POSTOP_FINISHED_PROCESSING;
}

#ifndef MAX_PATH
#define MAX_PATH (260)
#endif

#ifndef COPY_FILE_ALLOC_TAG
#define COPY_FILE_ALLOC_TAG 'STFC'
#endif


NTSTATUS
FltCopyFile(
	PCFLT_RELATED_OBJECTS FltObjects,
	PFLT_FILE_NAME_INFORMATION NameInfo)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	PVOID pBuffer = NULL;
	PWCHAR pwBuffer = NULL;
	ULONG uBytes = 0;
	LARGE_INTEGER offset = { 0 };


	ULONG uLength = 0;
	// 文件标准信息
	FILE_STANDARD_INFORMATION fileStandardInformation = { 0 };
	// 获取过滤文件的基本信息
	status = FltQueryInformationFile(FltObjects->Instance,
		FltObjects->FileObject,
		&fileStandardInformation,
		sizeof(FILE_STANDARD_INFORMATION),
		FileStandardInformation,
		NULL);

	if (!NT_SUCCESS(status))
	{
		return status;
	}
	// 获取文件的长度
	uLength = fileStandardInformation.AllocationSize.LowPart;
	// 申请文件大小的内存，用于保存文件数据
	pBuffer = FltAllocatePoolAlignedWithTag(FltObjects->Instance, NonPagedPoolCacheAligned, uLength, COPY_FILE_ALLOC_TAG);
	if (!pBuffer)
	{
		return STATUS_UNSUCCESSFUL;
	}

	offset.QuadPart = uBytes = 0;

	// 读取过滤文件的数据
	status = FltReadFile(FltObjects->Instance,
		FltObjects->FileObject,
		&offset,
		uLength,
		pBuffer,
		FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET | FLTFL_IO_OPERATION_NON_CACHED,
		&uBytes,
		NULL,
		NULL);

	if (NT_SUCCESS(status) && (uBytes == fileStandardInformation.EndOfFile.LowPart))
	{
		// 拼接一个copy的文件路径名
		
		WCHAR buffer[MAX_PATH] = { 0 };
		UNICODE_STRING ustrFileName = { 0 };
		RtlInitEmptyUnicodeString(&ustrFileName, buffer, MAX_PATH);
		// 保存在每个卷的根目录下
		RtlCopyUnicodeString(&ustrFileName, &NameInfo->Volume);
		// 设置拷贝文件的前缀
		RtlUnicodeStringCatString(&ustrFileName, L"\\CopyFile_");
		// 最终拷贝的文件名称
		RtlUnicodeStringCat(&ustrFileName, &NameInfo->FinalComponent);

		if (NameInfo->Stream.Length &&
			NameInfo->FinalComponent.Length > NameInfo->Stream.Length)
		{
			ULONG uTempLength = NameInfo->FinalComponent.Length - NameInfo->Stream.Length;
			if (NameInfo->FinalComponent.Buffer[uTempLength / 2] == L':')
			{
				ustrFileName.Length -= NameInfo->Stream.Length;
			}
		}

		BOOLEAN bReturn = FALSE;
		OBJECT_ATTRIBUTES oa;
		IO_STATUS_BLOCK ioBlock;
		HANDLE hFile = NULL;
		PFILE_OBJECT pFileObject = NULL;
		InitializeObjectAttributes(&oa, &ustrFileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

		// 创建一个copy文件
		status = FltCreateFile(FltObjects->Filter,
			FltObjects->Instance,
			&hFile,
			GENERIC_READ | GENERIC_WRITE,
			&oa,
			&ioBlock,
			0,
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_DELETE | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			FILE_OPEN_IF,
			FILE_SYNCHRONOUS_IO_NONALERT,
			NULL, 0, 0);
		if (!NT_SUCCESS(status))
		{
			FltClose(hFile);
			ObDereferenceObject(pFileObject);
			if (pBuffer)
			{
				FltFreePoolAlignedWithTag(FltObjects->Instance, pBuffer, COPY_FILE_ALLOC_TAG);
			}
			return status;
		}

		// 获取文件对象
		status = ObReferenceObjectByHandle(hFile, FILE_ALL_ACCESS, NULL, KernelMode, (PVOID*)&pFileObject, NULL);
		if (!NT_SUCCESS(status))
		{		
			FltClose(hFile);
			ObDereferenceObject(pFileObject);
			if (pBuffer)
			{
				FltFreePoolAlignedWithTag(FltObjects->Instance, pBuffer, COPY_FILE_ALLOC_TAG);
			}
			return status;
		}

		ULONG uWriteBytes = 0;
		LARGE_INTEGER writeOffset = { 0 };
		// 写文件
		status = FltWriteFile(FltObjects->Instance,
			pFileObject,
			&writeOffset,
			uBytes,
			pBuffer,
			FILE_NO_INTERMEDIATE_BUFFERING,
			&uWriteBytes,
			NULL,
			NULL);

		if (!NT_SUCCESS(status) || (uBytes != uWriteBytes))
		{
			FILE_DISPOSITION_INFORMATION fileDispositionInformation = { 0 };
			fileDispositionInformation.DeleteFile = TRUE;
			FltSetInformationFile(FltObjects->Instance,
				pFileObject,
				&fileDispositionInformation,
				sizeof(FILE_DISPOSITION_INFORMATION),
				FileDispositionInformation);
			
			FltClose(hFile);
			ObDereferenceObject(pFileObject);
			status = STATUS_UNSUCCESSFUL;
		}
	
		FltClose(hFile);
		ObDereferenceObject(pFileObject);
	}

	// 释放申请的内存空间
	if (pBuffer)
	{
		FltFreePoolAlignedWithTag(FltObjects->Instance, pBuffer, COPY_FILE_ALLOC_TAG);
	}


	return status;
}


FLT_PREOP_CALLBACK_STATUS
TestMiniFilterPreOperationNoPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
/*++

Routine Description:

    This routine is a pre-operation dispatch routine for this miniFilter.

    This is non-pageable because it could be called on the paging path

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The context for the completion routine for this
        operation.

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER( Data );
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("TestMiniFilter!TestMiniFilterPreOperationNoPostOperation: Entered\n") );

    // This template code does not do anything with the callbackData, but
    // rather returns FLT_PREOP_SUCCESS_NO_CALLBACK.
    // This passes the request down to the next miniFilter in the chain.

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


BOOLEAN
TestMiniFilterDoRequestOperationStatus(
    _In_ PFLT_CALLBACK_DATA Data
    )
/*++

Routine Description:

    This identifies those operations we want the operation status for.  These
    are typically operations that return STATUS_PENDING as a normal completion
    status.

Arguments:

Return Value:

    TRUE - If we want the operation status
    FALSE - If we don't

--*/
{
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;

    //
    //  return boolean state based on which operations we are interested in
    //

    return (BOOLEAN)

            //
            //  Check for oplock operations
            //

             (((iopb->MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL) &&
               ((iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_FILTER_OPLOCK)  ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_BATCH_OPLOCK)   ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_1) ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_2)))

              ||

              //
              //    Check for directy change notification
              //

              ((iopb->MajorFunction == IRP_MJ_DIRECTORY_CONTROL) &&
               (iopb->MinorFunction == IRP_MN_NOTIFY_CHANGE_DIRECTORY))
             );
}
