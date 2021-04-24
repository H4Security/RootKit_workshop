/*++

Module Name:

    FsFilter1HideFile.c

Abstract:

    This is the main module of the FsFilter1_HideFile miniFilter driver.

Environment:

    Kernel mode

--*/

#include <fltKernel.h>
#include <dontuse.h>

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")


PFLT_FILTER gFilterHandle;
ULONG_PTR OperationStatusCtx = 1;
PWCHAR          g_Pattern = NULL;
#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002

ULONG gTraceFlags = 1;

BOOLEAN ProcessFileFullDirectoryInformation(PFLT_CALLBACK_DATA Data);
BOOLEAN ProcessFileIdBothDirectoryInformation(PFLT_CALLBACK_DATA Data);
BOOLEAN ProcessFileBothDirectoryInformation(PFLT_CALLBACK_DATA Data);

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
FsFilter1HideFileUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    );


FLT_POSTOP_CALLBACK_STATUS
FsFilter1HideFilePostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    );



EXTERN_C_END


//
//  operation registration
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_DIRECTORY_CONTROL,
      0,
      NULL,
      FsFilter1HideFilePostOperation },
    /*{ IRP_MJ_CREATE,
      0,
      FsFilter1HideFilePreOperation,
      NULL },*/

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

    FsFilter1HideFileUnload,                           //  MiniFilterUnload

    NULL,                    //  InstanceSetup
    NULL,            //  InstanceQueryTeardown
    NULL,            //  InstanceTeardownStart
    NULL,         //  InstanceTeardownComplete

    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent

};




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
                  ("FsFilter1HideFile!DriverEntry: Entered\n") );

    //
    //  Register with FltMgr to tell it our callback routines
    //

    status = FltRegisterFilter( DriverObject,
                                &FilterRegistration,
                                &gFilterHandle );
    g_Pattern = L"Hideme.txt";
    FLT_ASSERT( NT_SUCCESS( status ) );
    if (!NT_SUCCESS(status)) 
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FsFilter1HideFile FltRegisterFilter() FAIL %08x=", status));
   
    if (NT_SUCCESS( status )) {

        //
        //  Start filtering i/o
        //
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FsFilter1HideFile FltRegisterFilter() "));
        status = FltStartFiltering( gFilterHandle );

        if (!NT_SUCCESS( status )) {
            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FsFilter1HideFile FltRegisterFilter() FAIL %08x=",status));
            FltUnregisterFilter( gFilterHandle );
        }
    }

    return status;
}

NTSTATUS
FsFilter1HideFileUnload (
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
                  ("FsFilter1HideFile!FsFilter1HideFileUnload: Entered\n") );

    FltUnregisterFilter( gFilterHandle );

    return STATUS_SUCCESS;
}



FLT_POSTOP_CALLBACK_STATUS
FsFilter1HideFilePostOperation (
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
    //UNREFERENCED_PARAMETER( Data );
    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("FsFilter1HideFile!FsFilter1HideFilePostOperation: Entered\n"));
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );
    UNREFERENCED_PARAMETER( Flags );
    PFLT_IO_PARAMETER_BLOCK     Iopb = Data->Iopb;

    

    // If a volume detach is in progress then exit (FLTFL_POST_OPERATION_DRAINING)
    if (Flags & FLTFL_POST_OPERATION_DRAINING) {
        goto Fail;
    }
    // If the operation is not successful then exit
    if (!NT_SUCCESS(Data->IoStatus.Status)) {
        goto Fail;
    }
    // Retrieve the buffer where the data is available
   // If the buffer is invalid (NULL) then exit
    if (Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer == NULL) {
        goto Fail;
    }

    // Retrieve the length of data in the buffer, if the length is 0 then exit
    if (Iopb->Parameters.DirectoryControl.QueryDirectory.Length == 0) {
        goto Fail;
    }

    DbgPrint("PID [%x] QueryDirectory [Length=%u FileIndex=%x FileName=%wZ] OperationFlags=%08x\n",
        FltGetRequestorProcessId(Data),
        Iopb->Parameters.DirectoryControl.QueryDirectory.Length,
        Iopb->Parameters.DirectoryControl.QueryDirectory.FileIndex,
        Iopb->Parameters.DirectoryControl.QueryDirectory.FileName,
        Data->Iopb->OperationFlags);

    if (Iopb->Parameters.DirectoryControl.QueryDirectory.FileInformationClass ==
        FileFullDirectoryInformation) {
        ProcessFileFullDirectoryInformation(Data);
    }
    else if (Iopb->Parameters.DirectoryControl.QueryDirectory.FileInformationClass ==
        FileIdBothDirectoryInformation)
    {
        DbgPrint("FileIdBothDirectoryInformation\n");
        ProcessFileIdBothDirectoryInformation(Data);
    }
    else if (Iopb->Parameters.DirectoryControl.QueryDirectory.FileInformationClass == FileBothDirectoryInformation)
    {
        DbgPrint("FileBothDirectoryInformation\n");
        ProcessFileBothDirectoryInformation(Data);
    }
Fail:
    return FLT_POSTOP_FINISHED_PROCESSING;
}

BOOLEAN
ProcessFileFullDirectoryInformation(
    PFLT_CALLBACK_DATA Data)
{
    BOOLEAN Found = FALSE;
    PUCHAR Buffer = (PUCHAR)Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer;
    ULONG Length = Data->Iopb->Parameters.DirectoryControl.QueryDirectory.Length;
    PFILE_FULL_DIR_INFORMATION Current = (PFILE_FULL_DIR_INFORMATION)Buffer;
    PFILE_FULL_DIR_INFORMATION Previous = NULL;
    BOOLEAN EmptySetReturned = FALSE; // set if the only entry is being removed i.e. empty buffer returned

    while (!Found) {
        // cache the next entry offset in case the Current entry is overwritten
        ULONG NextEntryOffset = Current->NextEntryOffset;

        DbgPrint("ENTRY @ %u Index=%u Name=%.*ls Length=%u NextEntryOffset=%u Current=%p Previous=%p\n",
            ((PUCHAR)Current - Buffer),
            Current->FileIndex,
            Current->FileNameLength / 2,
            Current->FileName,
            Current->FileNameLength,
            Current->NextEntryOffset,
            Current,
            Previous);

        // check if the current directory entry contains the filename of interest
        if (_wcsnicmp(Current->FileName, g_Pattern, Current->FileNameLength / sizeof(WCHAR)) == 0) {
            Found = TRUE;
            DbgPrint("PATTERN %ls FOUND @ %u\n",
                g_Pattern,
                ((PUCHAR)Current - Buffer));
        }

        if (Found) {
            // is this the first entry
            if (!Previous) {
                // if this the only entry and is being removed, a special error code has to be returned
                if (NextEntryOffset == 0) {
                    RtlZeroMemory(Buffer, FIELD_OFFSET(FILE_FULL_DIR_INFORMATION, FileName) + Current->FileNameLength);
                    EmptySetReturned = TRUE;
                }
                else {
                    // move over the rest of the buffer to the beginning
                    RtlMoveMemory(Buffer, ((PUCHAR)Current) + NextEntryOffset, Length - NextEntryOffset);
                    // zero out the remaining space in the buffer
                    RtlZeroMemory(Buffer + (Length - NextEntryOffset), NextEntryOffset);
                }
            }
            else {
                // is this the last entry
                if (NextEntryOffset == 0) {
                    // make the previous entry the last entry
                    Previous->NextEntryOffset = 0;
                    // zero out the last entry which needs to be removed
                    RtlZeroMemory(Current, FIELD_OFFSET(FILE_FULL_DIR_INFORMATION, FileName) + Current->FileNameLength);
                }
                else {
                    // entry is somewhere in the middle
                    Previous->NextEntryOffset += NextEntryOffset;
                    RtlZeroMemory(Current, NextEntryOffset);
                }
            }
        }

        // if this is the last entry, then exit out
        if (NextEntryOffset == 0) {
            break;
        }

        // save the current entry as previous for the next iteration
        Previous = Current;

        // forward to the next entry
        Current = (PFILE_FULL_DIR_INFORMATION)(((PUCHAR)Current) + NextEntryOffset);
    }

    if (EmptySetReturned) {
        DbgPrint(("Status = STATUS_NO_SUCH_FILE\n"));
        Data->IoStatus.Status = STATUS_NO_SUCH_FILE;
    }

    return Found;
} // ProcessFileFullDirectoryInformation()


BOOLEAN ProcessFileIdBothDirectoryInformation(PFLT_CALLBACK_DATA Data)
{
    BOOLEAN Found = FALSE;
    PUCHAR Buffer = (PUCHAR)Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer;
    ULONG Length = Data->Iopb->Parameters.DirectoryControl.QueryDirectory.Length;
    PFILE_ID_BOTH_DIR_INFORMATION Current = (PFILE_ID_BOTH_DIR_INFORMATION)Buffer;
    PFILE_ID_BOTH_DIR_INFORMATION Previous = NULL;
    BOOLEAN EmptySetReturned = FALSE; // set if the only entry is being removed i.e. empty buffer returned

    while (!Found) {
        // cache the next entry offset in case the Current entry is overwritten
        ULONG NextEntryOffset = Current->NextEntryOffset;

        DbgPrint("ENTRY @ %u Index=%u Name=%.*ls Length=%u NextEntryOffset=%u Current=%p Previous=%p\n",
            ((PUCHAR)Current - Buffer),
            Current->FileIndex,
            Current->FileNameLength / 2,
            Current->FileName,
            Current->FileNameLength,
            Current->NextEntryOffset,
            Current,
            Previous);

        // check if the current directory entry contains the filename of interest
        if (_wcsnicmp(Current->FileName, g_Pattern, Current->FileNameLength / sizeof(WCHAR)) == 0) {
            Found = TRUE;
            DbgPrint("PATTERN %ls FOUND @ %u\n",
                g_Pattern,
                ((PUCHAR)Current - Buffer));
        }

        if (Found) {
        
            if (!Previous) {
                // if this the only entry and is being removed, a special error code has to be returned
                if (NextEntryOffset == 0) {
                    RtlZeroMemory(Buffer, FIELD_OFFSET(FILE_ID_BOTH_DIR_INFORMATION, FileName) + Current->FileNameLength);
                    EmptySetReturned = TRUE;
                }
                else {
                    // move over the rest of the buffer to the beginning
                    RtlMoveMemory(Buffer, ((PUCHAR)Current) + NextEntryOffset, Length - NextEntryOffset);
                    // zero out the remaining space in the buffer
                    RtlZeroMemory(Buffer + (Length - NextEntryOffset), NextEntryOffset);
                }
            }
            else {
                // is this the last entry
                if (NextEntryOffset == 0) {
                    // make the previous entry the last entry
                    Previous->NextEntryOffset = 0;
                    // zero out the last entry which needs to be removed
                    RtlZeroMemory(Current, FIELD_OFFSET(FILE_ID_BOTH_DIR_INFORMATION, FileName) + Current->FileNameLength);
                }
                else {
                    // entry is somewhere in the middle
                    Previous->NextEntryOffset += NextEntryOffset;
                    RtlZeroMemory(Current, NextEntryOffset);
                }
            }
        }

        // if this is the last entry, then exit out
        if (NextEntryOffset == 0) {
            break;
        }

        // save the current entry as previous for the next iteration
        Previous = Current;

        // forward to the next entry
        Current = (PFILE_ID_BOTH_DIR_INFORMATION)(((PUCHAR)Current) + NextEntryOffset);
    }

    if (EmptySetReturned) {
        DbgPrint("Status = STATUS_NO_MORE_ENTRIES\n");
        Data->IoStatus.Status = STATUS_NO_MORE_ENTRIES;
    }

    return Found;

}
BOOLEAN ProcessFileBothDirectoryInformation(PFLT_CALLBACK_DATA Data)
{
    BOOLEAN Found = FALSE;
    PUCHAR Buffer = (PUCHAR)Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer;
    ULONG Length = Data->Iopb->Parameters.DirectoryControl.QueryDirectory.Length;
    PFILE_BOTH_DIR_INFORMATION Current = (PFILE_BOTH_DIR_INFORMATION)Buffer;
    PFILE_BOTH_DIR_INFORMATION Previous = NULL;
    BOOLEAN EmptySetReturned = FALSE; // set if the only entry is being removed i.e. empty buffer returned

    while (!Found) {
        // cache the next entry offset in case the Current entry is overwritten
        ULONG NextEntryOffset = Current->NextEntryOffset;

        DbgPrint("ENTRY @ %u Index=%u Name=%.*ls Length=%u NextEntryOffset=%u Current=%p Previous=%p\n",
            ((PUCHAR)Current - Buffer),
            Current->FileIndex,
            Current->FileNameLength / 2,
            Current->FileName,
            Current->FileNameLength,
            Current->NextEntryOffset,
            Current,
            Previous);

        // check if the current directory entry contains the filename of interest
        if (_wcsnicmp(Current->FileName, g_Pattern, Current->FileNameLength / sizeof(WCHAR)) == 0) {
            Found = TRUE;
            DbgPrint("PATTERN %ls FOUND @ %u\n",
                g_Pattern,
                ((PUCHAR)Current - Buffer));
        }

        if (Found) {
            
            if (!Previous) {
                // if this the only entry and is being removed, a special error code has to be returned
                if (NextEntryOffset == 0) {
                    RtlZeroMemory(Buffer, FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION, FileName) + Current->FileNameLength);
                    EmptySetReturned = TRUE;
                }
                else {
                    // move over the rest of the buffer to the beginning
                    RtlMoveMemory(Buffer, ((PUCHAR)Current) + NextEntryOffset, Length - NextEntryOffset);
                    // zero out the remaining space in the buffer
                    RtlZeroMemory(Buffer + (Length - NextEntryOffset), NextEntryOffset);
                }
            }
            else {
                // is this the last entry
                if (NextEntryOffset == 0) {
                    // make the previous entry the last entry
                    Previous->NextEntryOffset = 0;
                    // zero out the last entry which needs to be removed
                    RtlZeroMemory(Current, FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION, FileName) + Current->FileNameLength);
                }
                else {
                    // entry is somewhere in the middle
                    Previous->NextEntryOffset += NextEntryOffset;
                    RtlZeroMemory(Current, NextEntryOffset);
                }
            }
        }

        // if this is the last entry, then exit out
        if (NextEntryOffset == 0) {
            break;
        }

        // save the current entry as previous for the next iteration
        Previous = Current;

        // forward to the next entry
        Current = (PFILE_BOTH_DIR_INFORMATION)(((PUCHAR)Current) + NextEntryOffset);
    }

    if (EmptySetReturned) {
        DbgPrint("Status = STATUS_NO_MORE_ENTRIES\n");
        Data->IoStatus.Status = STATUS_NO_MORE_ENTRIES;
    }

    return Found;

}