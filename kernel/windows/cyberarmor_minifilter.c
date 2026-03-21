/*
 * CyberArmor Protect - Windows Minifilter Driver
 * File system minifilter with process monitoring for AI security.
 *
 * Monitors:
 * - File create/write operations by AI processes
 * - AI tool process launches
 * - Sensitive file access patterns
 *
 * Build with WDK: msbuild cyberarmor_minifilter.vcxproj
 */

#include "cyberarmor_minifilter.h"

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

/* Global data */
CYBERARMOR_GLOBAL_DATA Globals = { 0 };

/* Known AI process names */
static const WCHAR *AIProcessList[] = {
    L"ChatGPT.exe", L"Copilot.exe", L"claude.exe",
    L"ollama.exe", L"lm-studio.exe", L"Cursor.exe",
    L"windsurf.exe", L"Code.exe",
    L"text-generation-webui.exe", L"llamacpp.exe",
    NULL
};

/* Built-in sensitive path fragments */
static const WCHAR *BuiltinSensitiveFragments[] = {
    L"\\.ssh\\",
    L"\\.aws\\",
    L"\\.kube\\",
    L"\\appdata\\roaming\\gnupg\\",
    L"\\windows\\system32\\config\\",
    L"\\programdata\\microsoft\\crypto\\",
    NULL
};

/* Operation registration */
CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE, 0, CyberArmorPreCreate, CyberArmorPostCreate },
    { IRP_MJ_WRITE, 0, CyberArmorPreWrite, NULL },
    { IRP_MJ_OPERATION_END }
};

/* Filter registration */
CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,                          /* Flags */
    NULL,                       /* Context registration */
    Callbacks,                  /* Operation callbacks */
    CyberArmorUnload,           /* FilterUnloadCallback */
    CyberArmorInstanceSetup,    /* InstanceSetupCallback */
    NULL,                       /* InstanceQueryTeardownCallback */
    NULL, NULL, NULL, NULL      /* Other callbacks */
};

static USHORT CyberArmorBoundedWcsLen(_In_reads_(MaxChars) PCWSTR Text, _In_ USHORT MaxChars)
{
    USHORT i;

    for (i = 0; i < MaxChars; ++i) {
        if (Text[i] == L'\0') {
            break;
        }
    }

    return i;
}

static VOID CyberArmorCopyUnicodeToBuffer(
    _Out_writes_(DestChars) PWCHAR Dest,
    _In_ USHORT DestChars,
    _In_opt_ PCUNICODE_STRING Source)
{
    USHORT copyChars;

    if (Dest == NULL || DestChars == 0) {
        return;
    }

    Dest[0] = L'\0';

    if (Source == NULL || Source->Buffer == NULL || Source->Length == 0) {
        return;
    }

    copyChars = (USHORT)(Source->Length / sizeof(WCHAR));
    if (copyChars >= DestChars) {
        copyChars = DestChars - 1;
    }

    if (copyChars > 0) {
        RtlCopyMemory(Dest, Source->Buffer, copyChars * sizeof(WCHAR));
    }
    Dest[copyChars] = L'\0';
}

static UNICODE_STRING CyberArmorBasename(_In_ PCUNICODE_STRING FullPath)
{
    UNICODE_STRING fileName = { 0 };
    USHORT i;

    if (FullPath == NULL || FullPath->Buffer == NULL || FullPath->Length == 0) {
        return fileName;
    }

    fileName = *FullPath;

    for (i = (USHORT)(FullPath->Length / sizeof(WCHAR)); i > 0; --i) {
        if (FullPath->Buffer[i - 1] == L'\\' || FullPath->Buffer[i - 1] == L'/') {
            fileName.Buffer = &FullPath->Buffer[i];
            fileName.Length = (USHORT)(FullPath->Length - (i * sizeof(WCHAR)));
            fileName.MaximumLength = fileName.Length;
            break;
        }
    }

    return fileName;
}

static BOOLEAN CyberArmorContainsInsensitive(_In_ PCUNICODE_STRING Haystack, _In_ PCUNICODE_STRING Needle)
{
    USHORT hChars;
    USHORT nChars;
    USHORT i;
    USHORT j;

    if (Haystack == NULL || Needle == NULL ||
        Haystack->Buffer == NULL || Needle->Buffer == NULL ||
        Haystack->Length == 0 || Needle->Length == 0) {
        return FALSE;
    }

    hChars = (USHORT)(Haystack->Length / sizeof(WCHAR));
    nChars = (USHORT)(Needle->Length / sizeof(WCHAR));

    if (nChars > hChars) {
        return FALSE;
    }

    for (i = 0; i <= (USHORT)(hChars - nChars); ++i) {
        BOOLEAN match = TRUE;
        for (j = 0; j < nChars; ++j) {
            WCHAR a = RtlUpcaseUnicodeChar(Haystack->Buffer[i + j]);
            WCHAR b = RtlUpcaseUnicodeChar(Needle->Buffer[j]);
            if (a != b) {
                match = FALSE;
                break;
            }
        }
        if (match) {
            return TRUE;
        }
    }

    return FALSE;
}

static NTSTATUS CyberArmorAddSensitivePath(_In_ PCUNICODE_STRING Path)
{
    NTSTATUS status = STATUS_SUCCESS;

    if (Path == NULL || Path->Buffer == NULL || Path->Length == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    ExAcquireResourceExclusiveLite(&Globals.Lock, TRUE);

    if (Globals.SensitivePathCount >= CYBERARMOR_MAX_SENSITIVE) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    for (ULONG i = 0; i < Globals.SensitivePathCount; ++i) {
        if (RtlEqualUnicodeString(&Globals.SensitivePaths[i], Path, TRUE)) {
            status = STATUS_OBJECT_NAME_COLLISION;
            goto Exit;
        }
    }

    {
        ULONG index = Globals.SensitivePathCount;
        UNICODE_STRING *dst = &Globals.SensitivePaths[index];
        USHORT pathChars;

        pathChars = (USHORT)(Path->Length / sizeof(WCHAR));
        if (pathChars >= CYBERARMOR_MAX_PATH) {
            status = STATUS_NAME_TOO_LONG;
            goto Exit;
        }

        RtlZeroMemory(Globals.SensitivePathStorage[index], sizeof(Globals.SensitivePathStorage[index]));
        RtlCopyMemory(
            Globals.SensitivePathStorage[index],
            Path->Buffer,
            pathChars * sizeof(WCHAR));
        Globals.SensitivePathStorage[index][pathChars] = L'\0';

        dst->Buffer = Globals.SensitivePathStorage[index];
        dst->Length = (USHORT)(pathChars * sizeof(WCHAR));
        dst->MaximumLength = CYBERARMOR_MAX_PATH * sizeof(WCHAR);
        Globals.SensitivePathCount++;
    }

Exit:
    ExReleaseResourceLite(&Globals.Lock);
    return status;
}

static NTSTATUS CyberArmorRemoveSensitivePath(_In_ PCUNICODE_STRING Path)
{
    NTSTATUS status = STATUS_NOT_FOUND;

    if (Path == NULL || Path->Buffer == NULL || Path->Length == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    ExAcquireResourceExclusiveLite(&Globals.Lock, TRUE);

    for (ULONG i = 0; i < Globals.SensitivePathCount; ++i) {
        if (RtlEqualUnicodeString(&Globals.SensitivePaths[i], Path, TRUE)) {
            ULONG last = Globals.SensitivePathCount - 1;

            if (i != last) {
                RtlZeroMemory(Globals.SensitivePathStorage[i], sizeof(Globals.SensitivePathStorage[i]));
                RtlCopyMemory(Globals.SensitivePathStorage[i],
                    Globals.SensitivePathStorage[last],
                    sizeof(Globals.SensitivePathStorage[i]));

                Globals.SensitivePaths[i].Buffer = Globals.SensitivePathStorage[i];
                Globals.SensitivePaths[i].Length = Globals.SensitivePaths[last].Length;
                Globals.SensitivePaths[i].MaximumLength = CYBERARMOR_MAX_PATH * sizeof(WCHAR);
            }

            RtlZeroMemory(Globals.SensitivePathStorage[last], sizeof(Globals.SensitivePathStorage[last]));
            RtlZeroMemory(&Globals.SensitivePaths[last], sizeof(Globals.SensitivePaths[last]));
            Globals.SensitivePathCount = last;
            status = STATUS_SUCCESS;
            break;
        }
    }

    ExReleaseResourceLite(&Globals.Lock);
    return status;
}

static NTSTATUS CyberArmorAddTargetIp(_In_ ULONG IpAddress)
{
    NTSTATUS status = STATUS_SUCCESS;

    if (IpAddress == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    ExAcquireResourceExclusiveLite(&Globals.Lock, TRUE);

    if (Globals.TargetIPCount >= CYBERARMOR_MAX_TARGET_IPS) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    for (ULONG i = 0; i < Globals.TargetIPCount; ++i) {
        if (Globals.TargetIPs[i] == IpAddress) {
            status = STATUS_OBJECT_NAME_COLLISION;
            goto Exit;
        }
    }

    Globals.TargetIPs[Globals.TargetIPCount++] = IpAddress;

Exit:
    ExReleaseResourceLite(&Globals.Lock);
    return status;
}

static NTSTATUS CyberArmorRemoveTargetIp(_In_ ULONG IpAddress)
{
    NTSTATUS status = STATUS_NOT_FOUND;

    ExAcquireResourceExclusiveLite(&Globals.Lock, TRUE);

    for (ULONG i = 0; i < Globals.TargetIPCount; ++i) {
        if (Globals.TargetIPs[i] == IpAddress) {
            ULONG last = Globals.TargetIPCount - 1;
            Globals.TargetIPs[i] = Globals.TargetIPs[last];
            Globals.TargetIPs[last] = 0;
            Globals.TargetIPCount = last;
            status = STATUS_SUCCESS;
            break;
        }
    }

    ExReleaseResourceLite(&Globals.Lock);
    return status;
}

static VOID CyberArmorInitDefaults(VOID)
{
    Globals.AIProcessCount = 0;
    Globals.SensitivePathCount = 0;
    Globals.TargetIPCount = 0;

    for (ULONG i = 0; AIProcessList[i] != NULL && i < CYBERARMOR_MAX_AI_PROCESSES; ++i) {
        RtlInitUnicodeString(&Globals.AIProcessNames[i], AIProcessList[i]);
        Globals.AIProcessCount++;
    }
}

/* ============================================
 * Driver Entry / Unload
 * ============================================ */

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    PSECURITY_DESCRIPTOR sd = NULL;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING portName;

    UNREFERENCED_PARAMETER(RegistryPath);

    status = ExInitializeResourceLite(&Globals.Lock);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    Globals.GlobalMode = ActionMonitor;
    CyberArmorInitDefaults();

    status = FltRegisterFilter(DriverObject, &FilterRegistration, &Globals.FilterHandle);
    if (!NT_SUCCESS(status)) {
        ExDeleteResourceLite(&Globals.Lock);
        return status;
    }

    RtlInitUnicodeString(&portName, CYBERARMOR_PORT_NAME);

    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (NT_SUCCESS(status)) {
        InitializeObjectAttributes(&oa, &portName,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, sd);

        status = FltCreateCommunicationPort(
            Globals.FilterHandle,
            &Globals.ServerPort,
            &oa,
            NULL,
            CyberArmorPortConnect,
            CyberArmorPortDisconnect,
            CyberArmorPortMessage,
            1 /* MaxConnections */);

        FltFreeSecurityDescriptor(sd);
    }

    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(Globals.FilterHandle);
        ExDeleteResourceLite(&Globals.Lock);
        return status;
    }

    status = PsSetCreateProcessNotifyRoutineEx(CyberArmorProcessNotify, FALSE);
    if (!NT_SUCCESS(status)) {
        KdPrint(("CyberArmor: Process notify registration failed: 0x%x\n", status));
    }

    status = FltStartFiltering(Globals.FilterHandle);
    if (!NT_SUCCESS(status)) {
        PsSetCreateProcessNotifyRoutineEx(CyberArmorProcessNotify, TRUE);
        FltCloseCommunicationPort(Globals.ServerPort);
        FltUnregisterFilter(Globals.FilterHandle);
        ExDeleteResourceLite(&Globals.Lock);
        return status;
    }

    KdPrint(("CyberArmor: Minifilter driver loaded successfully\n"));
    return STATUS_SUCCESS;
}

NTSTATUS CyberArmorUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);

    PsSetCreateProcessNotifyRoutineEx(CyberArmorProcessNotify, TRUE);

    if (Globals.ServerPort != NULL) {
        FltCloseCommunicationPort(Globals.ServerPort);
        Globals.ServerPort = NULL;
    }

    if (Globals.FilterHandle != NULL) {
        FltUnregisterFilter(Globals.FilterHandle);
        Globals.FilterHandle = NULL;
    }

    ExDeleteResourceLite(&Globals.Lock);

    KdPrint(("CyberArmor: Minifilter driver unloaded. Stats: files=%lld blocked=%lld procs=%lld\n",
        Globals.Stats.FilesMonitored, Globals.Stats.FilesBlocked, Globals.Stats.ProcessesMonitored));

    return STATUS_SUCCESS;
}

NTSTATUS CyberArmorInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);

    if (VolumeFilesystemType != FLT_FSTYPE_NTFS &&
        VolumeFilesystemType != FLT_FSTYPE_REFS) {
        return STATUS_FLT_DO_NOT_ATTACH;
    }

    return STATUS_SUCCESS;
}

/* ============================================
 * Minifilter Callbacks
 * ============================================ */

FLT_PREOP_CALLBACK_STATUS CyberArmorPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status;
    PUNICODE_STRING processImage = NULL;
    BOOLEAN isAIProcess = FALSE;
    BOOLEAN isSensitive;
    CYBERARMOR_ACTION mode;

    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;

    if (Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltGetFileNameInformation(Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo);
    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    FltParseFileNameInformation(nameInfo);

    status = SeLocateProcessImageName(PsGetCurrentProcess(), &processImage);
    if (NT_SUCCESS(status) && processImage != NULL) {
        isAIProcess = CyberArmorIsAIProcess(processImage);
    }

    isSensitive = CyberArmorIsSensitivePath(&nameInfo->Name);

    ExAcquireResourceSharedLite(&Globals.Lock, TRUE);
    mode = Globals.GlobalMode;
    ExReleaseResourceLite(&Globals.Lock);

    if (isAIProcess || isSensitive) {
        CYBERARMOR_EVENT event = { 0 };

        InterlockedIncrement64(&Globals.Stats.FilesMonitored);

        event.EventType = EventFileCreate;
        event.Severity = isSensitive ? SeverityHigh : SeverityMedium;
        event.Action = mode;
        KeQuerySystemTimePrecise(&event.Timestamp);
        event.ProcessId = HandleToUlong(PsGetCurrentProcessId());
        event.ThreadId = HandleToUlong(PsGetCurrentThreadId());

        if (processImage != NULL) {
            UNICODE_STRING imageNameOnly = CyberArmorBasename(processImage);
            CyberArmorCopyUnicodeToBuffer(event.ProcessName, CYBERARMOR_MAX_PROCESS_NAME, &imageNameOnly);
        }

        CyberArmorCopyUnicodeToBuffer(event.Data.FileCreate.FilePath, CYBERARMOR_MAX_PATH, &nameInfo->Name);
        event.Data.FileCreate.DesiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
        event.Data.FileCreate.CreateDisposition =
            (Data->Iopb->Parameters.Create.Options >> 24) & 0xFF;
        event.Data.FileCreate.IsDirectory =
            (BOOLEAN)((Data->Iopb->Parameters.Create.Options & FILE_DIRECTORY_FILE) != 0);

        CyberArmorSendEvent(&event);

        if (mode == ActionBlock && isAIProcess && isSensitive) {
            InterlockedIncrement64(&Globals.Stats.FilesBlocked);
            FltReleaseFileNameInformation(nameInfo);
            if (processImage != NULL) {
                ExFreePool(processImage);
            }
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }
    }

    FltReleaseFileNameInformation(nameInfo);
    if (processImage != NULL) {
        ExFreePool(processImage);
    }

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS CyberArmorPostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS CyberArmorPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status;
    ULONG writeLength;

    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;

    if (Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    writeLength = Data->Iopb->Parameters.Write.Length;
    if (writeLength < 4096) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltGetFileNameInformation(Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo);
    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    FltParseFileNameInformation(nameInfo);

    {
        CYBERARMOR_EVENT event = { 0 };
        PUNICODE_STRING processImage = NULL;

        event.EventType = EventFileWrite;
        event.Severity = SeverityMedium;
        ExAcquireResourceSharedLite(&Globals.Lock, TRUE);
        event.Action = Globals.GlobalMode;
        ExReleaseResourceLite(&Globals.Lock);
        KeQuerySystemTimePrecise(&event.Timestamp);
        event.ProcessId = HandleToUlong(PsGetCurrentProcessId());
        event.ThreadId = HandleToUlong(PsGetCurrentThreadId());
        event.Data.FileWrite.WriteLength = writeLength;

        CyberArmorCopyUnicodeToBuffer(event.Data.FileWrite.FilePath, CYBERARMOR_MAX_PATH, &nameInfo->Name);

        if (NT_SUCCESS(SeLocateProcessImageName(PsGetCurrentProcess(), &processImage)) && processImage != NULL) {
            UNICODE_STRING imageNameOnly = CyberArmorBasename(processImage);
            CyberArmorCopyUnicodeToBuffer(event.ProcessName, CYBERARMOR_MAX_PROCESS_NAME, &imageNameOnly);
            ExFreePool(processImage);
        }

        CyberArmorSendEvent(&event);
    }

    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

/* ============================================
 * Process Notification Callback
 * ============================================ */

VOID CyberArmorProcessNotify(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNREFERENCED_PARAMETER(Process);

    if (CreateInfo == NULL || CreateInfo->ImageFileName == NULL) {
        return;
    }

    if (CyberArmorIsAIProcess(CreateInfo->ImageFileName)) {
        CYBERARMOR_EVENT event = { 0 };

        InterlockedIncrement64(&Globals.Stats.ProcessesMonitored);

        event.EventType = EventProcessCreate;
        event.Severity = SeverityMedium;
        ExAcquireResourceSharedLite(&Globals.Lock, TRUE);
        event.Action = Globals.GlobalMode;
        ExReleaseResourceLite(&Globals.Lock);
        KeQuerySystemTimePrecise(&event.Timestamp);
        event.ProcessId = HandleToUlong(ProcessId);
        event.ThreadId = 0;
        event.Data.ProcessCreate.ChildProcessId = HandleToUlong(ProcessId);

        {
            UNICODE_STRING imageNameOnly = CyberArmorBasename(CreateInfo->ImageFileName);
            CyberArmorCopyUnicodeToBuffer(event.ProcessName, CYBERARMOR_MAX_PROCESS_NAME, &imageNameOnly);
        }
        CyberArmorCopyUnicodeToBuffer(event.Data.ProcessCreate.ImageFileName, CYBERARMOR_MAX_PATH,
            CreateInfo->ImageFileName);

        if (CreateInfo->CommandLine != NULL) {
            CyberArmorCopyUnicodeToBuffer(event.Data.ProcessCreate.CommandLine, CYBERARMOR_MAX_PATH,
                CreateInfo->CommandLine);
        }

        CyberArmorSendEvent(&event);

        KdPrint(("CyberArmor: AI process launched: PID=%lu Image=%wZ\n",
            HandleToUlong(ProcessId), CreateInfo->ImageFileName));
    }
}

/* ============================================
 * Communication Port
 * ============================================ */

NTSTATUS CyberArmorPortConnect(
    _In_ PFLT_PORT ClientPort,
    _In_ PVOID ServerPortCookie,
    _In_ PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_ PVOID *ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);

    ExAcquireResourceExclusiveLite(&Globals.Lock, TRUE);
    Globals.ClientPort = ClientPort;
    Globals.UserProcess = PsGetCurrentProcess();
    Globals.Connected = TRUE;
    ExReleaseResourceLite(&Globals.Lock);

    *ConnectionCookie = NULL;
    KdPrint(("CyberArmor: Usermode service connected\n"));
    return STATUS_SUCCESS;
}

VOID CyberArmorPortDisconnect(_In_opt_ PVOID ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);

    ExAcquireResourceExclusiveLite(&Globals.Lock, TRUE);
    FltCloseClientPort(Globals.FilterHandle, &Globals.ClientPort);
    Globals.Connected = FALSE;
    Globals.UserProcess = NULL;
    ExReleaseResourceLite(&Globals.Lock);

    KdPrint(("CyberArmor: Usermode service disconnected\n"));
}

NTSTATUS CyberArmorPortMessage(
    _In_ PVOID ConnectionCookie,
    _In_ PVOID InputBuffer,
    _In_ ULONG InputBufferSize,
    _Out_ PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength)
{
    NTSTATUS status = STATUS_SUCCESS;
    PCYBERARMOR_COMMAND_MESSAGE cmd;

    UNREFERENCED_PARAMETER(ConnectionCookie);

    if (ReturnOutputBufferLength != NULL) {
        *ReturnOutputBufferLength = 0;
    }

    if (InputBuffer == NULL || InputBufferSize < sizeof(CYBERARMOR_COMMAND)) {
        return STATUS_INVALID_PARAMETER;
    }

    cmd = (PCYBERARMOR_COMMAND_MESSAGE)InputBuffer;

    switch (cmd->Command) {
    case CommandSetMode:
        if (InputBufferSize < sizeof(CYBERARMOR_COMMAND_MESSAGE)) {
            return STATUS_INVALID_PARAMETER;
        }
        if (cmd->Payload.Mode != ActionMonitor && cmd->Payload.Mode != ActionBlock) {
            return STATUS_INVALID_PARAMETER;
        }

        ExAcquireResourceExclusiveLite(&Globals.Lock, TRUE);
        Globals.GlobalMode = cmd->Payload.Mode;
        ExReleaseResourceLite(&Globals.Lock);

        KdPrint(("CyberArmor: Mode set to %s\n",
            cmd->Payload.Mode == ActionBlock ? "ENFORCE" : "MONITOR"));
        break;

    case CommandAddTargetIP:
        if (InputBufferSize < sizeof(CYBERARMOR_COMMAND_MESSAGE)) {
            return STATUS_INVALID_PARAMETER;
        }
        status = CyberArmorAddTargetIp(cmd->Payload.IPAddress);
        break;

    case CommandRemoveTargetIP:
        if (InputBufferSize < sizeof(CYBERARMOR_COMMAND_MESSAGE)) {
            return STATUS_INVALID_PARAMETER;
        }
        status = CyberArmorRemoveTargetIp(cmd->Payload.IPAddress);
        break;

    case CommandAddSensitivePath:
    case CommandRemoveSensitivePath:
        if (InputBufferSize < sizeof(CYBERARMOR_COMMAND_MESSAGE)) {
            return STATUS_INVALID_PARAMETER;
        }
        {
            USHORT pathLen = CyberArmorBoundedWcsLen(cmd->Payload.Path, CYBERARMOR_MAX_PATH);
            UNICODE_STRING path;

            if (pathLen == 0 || pathLen == CYBERARMOR_MAX_PATH) {
                return STATUS_INVALID_PARAMETER;
            }

            path.Buffer = (PWSTR)cmd->Payload.Path;
            path.Length = (USHORT)(pathLen * sizeof(WCHAR));
            path.MaximumLength = path.Length;

            if (cmd->Command == CommandAddSensitivePath) {
                status = CyberArmorAddSensitivePath(&path);
            } else {
                status = CyberArmorRemoveSensitivePath(&path);
            }
        }
        break;

    case CommandGetStats:
        if (OutputBuffer == NULL || OutputBufferSize < sizeof(CYBERARMOR_STATS) ||
            ReturnOutputBufferLength == NULL) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        ExAcquireResourceSharedLite(&Globals.Lock, TRUE);
        RtlCopyMemory(OutputBuffer, &Globals.Stats, sizeof(CYBERARMOR_STATS));
        ExReleaseResourceLite(&Globals.Lock);

        *ReturnOutputBufferLength = sizeof(CYBERARMOR_STATS);
        break;

    default:
        return STATUS_INVALID_PARAMETER;
    }

    return status;
}

/* ============================================
 * Helper Functions
 * ============================================ */

NTSTATUS CyberArmorSendEvent(_In_ PCYBERARMOR_EVENT Event)
{
    NTSTATUS status;
    PFLT_PORT clientPort;
    LARGE_INTEGER timeout;
    ULONG replyLength = 0;

    if (Event == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    ExAcquireResourceSharedLite(&Globals.Lock, TRUE);
    clientPort = Globals.ClientPort;
    ExReleaseResourceLite(&Globals.Lock);

    if (clientPort == NULL) {
        InterlockedIncrement64(&Globals.Stats.EventsDropped);
        return STATUS_PORT_DISCONNECTED;
    }

    timeout.QuadPart = -10000000; /* 1 second timeout */

    status = FltSendMessage(
        Globals.FilterHandle,
        &clientPort,
        (PVOID)Event,
        sizeof(CYBERARMOR_EVENT),
        NULL,
        &replyLength,
        &timeout);

    if (NT_SUCCESS(status)) {
        InterlockedIncrement64(&Globals.Stats.EventsSent);
    } else {
        InterlockedIncrement64(&Globals.Stats.EventsDropped);
    }

    return status;
}

BOOLEAN CyberArmorIsAIProcess(_In_ PCUNICODE_STRING ProcessName)
{
    UNICODE_STRING fileName;

    if (ProcessName == NULL || ProcessName->Buffer == NULL || ProcessName->Length == 0) {
        return FALSE;
    }

    fileName = CyberArmorBasename(ProcessName);

    ExAcquireResourceSharedLite(&Globals.Lock, TRUE);
    for (ULONG i = 0; i < Globals.AIProcessCount; ++i) {
        if (RtlCompareUnicodeString(&fileName, &Globals.AIProcessNames[i], TRUE) == 0) {
            ExReleaseResourceLite(&Globals.Lock);
            return TRUE;
        }
    }
    ExReleaseResourceLite(&Globals.Lock);

    return FALSE;
}

BOOLEAN CyberArmorIsSensitivePath(_In_ PCUNICODE_STRING FilePath)
{
    UNICODE_STRING fragment;

    if (FilePath == NULL || FilePath->Buffer == NULL || FilePath->Length == 0) {
        return FALSE;
    }

    ExAcquireResourceSharedLite(&Globals.Lock, TRUE);
    for (ULONG i = 0; i < Globals.SensitivePathCount; ++i) {
        if (RtlPrefixUnicodeString(&Globals.SensitivePaths[i], FilePath, TRUE)) {
            ExReleaseResourceLite(&Globals.Lock);
            return TRUE;
        }
    }
    ExReleaseResourceLite(&Globals.Lock);

    for (ULONG i = 0; BuiltinSensitiveFragments[i] != NULL; ++i) {
        RtlInitUnicodeString(&fragment, BuiltinSensitiveFragments[i]);
        if (CyberArmorContainsInsensitive(FilePath, &fragment)) {
            return TRUE;
        }
    }

    return FALSE;
}

BOOLEAN CyberArmorIsTargetIP(_In_ ULONG IPAddress)
{
    BOOLEAN found = FALSE;

    ExAcquireResourceSharedLite(&Globals.Lock, TRUE);
    for (ULONG i = 0; i < Globals.TargetIPCount; ++i) {
        if (Globals.TargetIPs[i] == IPAddress) {
            found = TRUE;
            break;
        }
    }
    ExReleaseResourceLite(&Globals.Lock);

    return found;
}
