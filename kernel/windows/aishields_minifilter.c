/*
 * AIShields Protect - Windows Minifilter Driver
 * File system minifilter with process monitoring for AI security.
 *
 * Monitors:
 * - File create/write operations by AI processes
 * - AI tool process launches
 * - Sensitive file access patterns
 *
 * Build with WDK: msbuild aishields_minifilter.vcxproj
 */

#include "aishields_minifilter.h"

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

/* Global data */
AISHIELDS_GLOBAL_DATA Globals = { 0 };

/* Known AI process names */
static const WCHAR* AIProcessList[] = {
    L"ChatGPT.exe", L"Copilot.exe", L"claude.exe",
    L"ollama.exe", L"lm-studio.exe", L"Cursor.exe",
    L"windsurf.exe", L"Code.exe",
    L"text-generation-webui.exe", L"llamacpp.exe",
    NULL
};

/* Operation registration */
CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE,  0, AIShieldsPreCreate,  AIShieldsPostCreate },
    { IRP_MJ_WRITE,   0, AIShieldsPreWrite,   NULL },
    { IRP_MJ_OPERATION_END }
};

/* Filter registration */
CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,                          /* Flags */
    NULL,                       /* Context registration */
    Callbacks,                  /* Operation callbacks */
    AIShieldsUnload,            /* FilterUnloadCallback */
    AIShieldsInstanceSetup,     /* InstanceSetupCallback */
    NULL,                       /* InstanceQueryTeardownCallback */
    NULL, NULL, NULL, NULL      /* Other callbacks */
};

/* ============================================
 * Driver Entry / Unload
 * ============================================ */

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    PSECURITY_DESCRIPTOR sd = NULL;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING portName;

    UNREFERENCED_PARAMETER(RegistryPath);

    ExInitializeResourceLite(&Globals.Lock);
    Globals.GlobalMode = ActionMonitor;

    /* Initialize AI process names */
    Globals.AIProcessCount = 0;
    for (ULONG i = 0; AIProcessList[i] != NULL && i < 64; i++) {
        RtlInitUnicodeString(&Globals.AIProcessNames[i], AIProcessList[i]);
        Globals.AIProcessCount++;
    }

    /* Register minifilter */
    status = FltRegisterFilter(DriverObject, &FilterRegistration, &Globals.FilterHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* Create communication port */
    RtlInitUnicodeString(&portName, AISHIELDS_PORT_NAME);

    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (NT_SUCCESS(status)) {
        InitializeObjectAttributes(&oa, &portName,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, sd);

        status = FltCreateCommunicationPort(
            Globals.FilterHandle,
            &Globals.ServerPort,
            &oa,
            NULL,
            AIShieldsPortConnect,
            AIShieldsPortDisconnect,
            AIShieldsPortMessage,
            1  /* MaxConnections */
        );

        FltFreeSecurityDescriptor(sd);
    }

    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(Globals.FilterHandle);
        return status;
    }

    /* Register process creation callback */
    status = PsSetCreateProcessNotifyRoutineEx(AIShieldsProcessNotify, FALSE);
    if (!NT_SUCCESS(status)) {
        /* Non-fatal: continue without process monitoring */
        KdPrint(("AIShields: Process notify registration failed: 0x%x\n", status));
    }

    /* Start filtering */
    status = FltStartFiltering(Globals.FilterHandle);
    if (!NT_SUCCESS(status)) {
        PsSetCreateProcessNotifyRoutineEx(AIShieldsProcessNotify, TRUE);
        FltCloseCommunicationPort(Globals.ServerPort);
        FltUnregisterFilter(Globals.FilterHandle);
        return status;
    }

    KdPrint(("AIShields: Minifilter driver loaded successfully\n"));
    return STATUS_SUCCESS;
}

NTSTATUS AIShieldsUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);

    PsSetCreateProcessNotifyRoutineEx(AIShieldsProcessNotify, TRUE);

    if (Globals.ServerPort) {
        FltCloseCommunicationPort(Globals.ServerPort);
    }

    if (Globals.FilterHandle) {
        FltUnregisterFilter(Globals.FilterHandle);
    }

    ExDeleteResourceLite(&Globals.Lock);

    KdPrint(("AIShields: Minifilter driver unloaded. Stats: files=%lld blocked=%lld procs=%lld\n",
        Globals.Stats.FilesMonitored, Globals.Stats.FilesBlocked, Globals.Stats.ProcessesMonitored));

    return STATUS_SUCCESS;
}

NTSTATUS AIShieldsInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);

    /* Only attach to NTFS and ReFS volumes */
    if (VolumeFilesystemType != FLT_FSTYPE_NTFS &&
        VolumeFilesystemType != FLT_FSTYPE_REFS) {
        return STATUS_FLT_DO_NOT_ATTACH;
    }

    return STATUS_SUCCESS;
}

/* ============================================
 * Minifilter Callbacks
 * ============================================ */

FLT_PREOP_CALLBACK_STATUS AIShieldsPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status;
    PEPROCESS process;
    UNICODE_STRING processName;
    BOOLEAN isAIProcess;

    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;

    /* Skip kernel-mode operations */
    if (Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* Get file name */
    status = FltGetFileNameInformation(Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    FltParseFileNameInformation(nameInfo);

    /* Check if the calling process is an AI tool */
    process = PsGetCurrentProcess();
    /* Get process image name - simplified */
    DECLARE_UNICODE_STRING_SIZE(procNameBuf, AISHIELDS_MAX_PROCESS_NAME);
    status = SeLocateProcessImageName(process, &processName);
    isAIProcess = FALSE;
    if (NT_SUCCESS(status)) {
        isAIProcess = AIShieldsIsAIProcess(&processName);
    }

    /* Check if path is sensitive */
    BOOLEAN isSensitive = AIShieldsIsSensitivePath(&nameInfo->Name);

    if (isAIProcess || isSensitive) {
        InterlockedIncrement64(&Globals.Stats.FilesMonitored);

        /* Build and send event */
        AISHIELDS_EVENT event = { 0 };
        event.EventType = EventFileCreate;
        event.Severity = isSensitive ? SeverityHigh : SeverityMedium;
        event.Action = Globals.GlobalMode;
        KeQuerySystemTimePrecise(&event.Timestamp);
        event.ProcessId = HandleToUlong(PsGetCurrentProcessId());
        event.ThreadId = HandleToUlong(PsGetCurrentThreadId());

        RtlCopyMemory(event.FileCreate.FilePath, nameInfo->Name.Buffer,
            min(nameInfo->Name.Length, sizeof(event.FileCreate.FilePath) - sizeof(WCHAR)));
        event.FileCreate.DesiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
        event.FileCreate.CreateDisposition =
            (Data->Iopb->Parameters.Create.Options >> 24) & 0xFF;

        AIShieldsSendEvent(&event);

        /* Block in enforce mode if sensitive path accessed by AI */
        if (Globals.GlobalMode == ActionBlock && isAIProcess && isSensitive) {
            InterlockedIncrement64(&Globals.Stats.FilesBlocked);
            FltReleaseFileNameInformation(nameInfo);
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }
    }

    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS AIShieldsPostCreate(
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

FLT_PREOP_CALLBACK_STATUS AIShieldsPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;

    if (Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* Only interested in large writes (potential data exfiltration) */
    ULONG writeLength = Data->Iopb->Parameters.Write.Length;
    if (writeLength < 4096) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltGetFileNameInformation(Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    FltParseFileNameInformation(nameInfo);

    AISHIELDS_EVENT event = { 0 };
    event.EventType = EventFileWrite;
    event.Severity = SeverityMedium;
    event.Action = ActionMonitor;
    KeQuerySystemTimePrecise(&event.Timestamp);
    event.ProcessId = HandleToUlong(PsGetCurrentProcessId());
    event.ThreadId = HandleToUlong(PsGetCurrentThreadId());
    event.FileWrite.WriteLength = writeLength;

    RtlCopyMemory(event.FileWrite.FilePath, nameInfo->Name.Buffer,
        min(nameInfo->Name.Length, sizeof(event.FileWrite.FilePath) - sizeof(WCHAR)));

    AIShieldsSendEvent(&event);

    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

/* ============================================
 * Process Notification Callback
 * ============================================ */

VOID AIShieldsProcessNotify(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNREFERENCED_PARAMETER(Process);

    if (CreateInfo) {
        /* Process creation */
        if (CreateInfo->ImageFileName) {
            BOOLEAN isAI = AIShieldsIsAIProcess(CreateInfo->ImageFileName);

            if (isAI) {
                InterlockedIncrement64(&Globals.Stats.ProcessesMonitored);

                AISHIELDS_EVENT event = { 0 };
                event.EventType = EventProcessCreate;
                event.Severity = SeverityMedium;
                event.Action = Globals.GlobalMode;
                KeQuerySystemTimePrecise(&event.Timestamp);
                event.ProcessId = HandleToUlong(ProcessId);
                event.ProcessCreate.ChildProcessId = HandleToUlong(ProcessId);

                RtlCopyMemory(event.ProcessCreate.ImageFileName,
                    CreateInfo->ImageFileName->Buffer,
                    min(CreateInfo->ImageFileName->Length,
                        sizeof(event.ProcessCreate.ImageFileName) - sizeof(WCHAR)));

                if (CreateInfo->CommandLine) {
                    RtlCopyMemory(event.ProcessCreate.CommandLine,
                        CreateInfo->CommandLine->Buffer,
                        min(CreateInfo->CommandLine->Length,
                            sizeof(event.ProcessCreate.CommandLine) - sizeof(WCHAR)));
                }

                AIShieldsSendEvent(&event);

                KdPrint(("AIShields: AI process launched: PID=%lu Image=%wZ\n",
                    HandleToUlong(ProcessId), CreateInfo->ImageFileName));
            }
        }
    }
}

/* ============================================
 * Communication Port
 * ============================================ */

NTSTATUS AIShieldsPortConnect(
    _In_ PFLT_PORT ClientPort,
    _In_ PVOID ServerPortCookie,
    _In_ PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_ PVOID *ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);

    Globals.ClientPort = ClientPort;
    Globals.UserProcess = PsGetCurrentProcess();
    Globals.Connected = TRUE;
    *ConnectionCookie = NULL;

    KdPrint(("AIShields: Usermode service connected\n"));
    return STATUS_SUCCESS;
}

VOID AIShieldsPortDisconnect(_In_opt_ PVOID ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);

    FltCloseClientPort(Globals.FilterHandle, &Globals.ClientPort);
    Globals.Connected = FALSE;
    Globals.UserProcess = NULL;

    KdPrint(("AIShields: Usermode service disconnected\n"));
}

NTSTATUS AIShieldsPortMessage(
    _In_ PVOID ConnectionCookie,
    _In_ PVOID InputBuffer,
    _In_ ULONG InputBufferSize,
    _Out_ PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);

    PAISHIELDS_COMMAND_MESSAGE cmd = (PAISHIELDS_COMMAND_MESSAGE)InputBuffer;

    if (InputBufferSize < sizeof(AISHIELDS_COMMAND)) {
        return STATUS_INVALID_PARAMETER;
    }

    switch (cmd->Command) {
    case CommandSetMode:
        Globals.GlobalMode = cmd->Mode;
        KdPrint(("AIShields: Mode set to %s\n",
            cmd->Mode == ActionBlock ? "ENFORCE" : "MONITOR"));
        break;

    case CommandGetStats:
        if (OutputBuffer && OutputBufferSize >= sizeof(AISHIELDS_STATS)) {
            RtlCopyMemory(OutputBuffer, &Globals.Stats, sizeof(AISHIELDS_STATS));
            *ReturnOutputBufferLength = sizeof(AISHIELDS_STATS);
        }
        break;

    default:
        return STATUS_INVALID_PARAMETER;
    }

    return STATUS_SUCCESS;
}

/* ============================================
 * Helper Functions
 * ============================================ */

NTSTATUS AIShieldsSendEvent(_In_ PAISHIELDS_EVENT Event)
{
    if (!Globals.Connected || !Globals.ClientPort) {
        InterlockedIncrement64(&Globals.Stats.EventsDropped);
        return STATUS_PORT_DISCONNECTED;
    }

    LARGE_INTEGER timeout;
    timeout.QuadPart = -10000000; /* 1 second timeout */

    ULONG replyLength = 0;
    NTSTATUS status = FltSendMessage(
        Globals.FilterHandle,
        &Globals.ClientPort,
        Event,
        sizeof(AISHIELDS_EVENT),
        NULL,
        &replyLength,
        &timeout
    );

    if (NT_SUCCESS(status)) {
        InterlockedIncrement64(&Globals.Stats.EventsSent);
    } else {
        InterlockedIncrement64(&Globals.Stats.EventsDropped);
    }

    return status;
}

BOOLEAN AIShieldsIsAIProcess(_In_ PUNICODE_STRING ProcessName)
{
    /* Extract just the filename from the full path */
    UNICODE_STRING fileName = *ProcessName;
    for (USHORT i = ProcessName->Length / sizeof(WCHAR); i > 0; i--) {
        if (ProcessName->Buffer[i - 1] == L'\\') {
            fileName.Buffer = &ProcessName->Buffer[i];
            fileName.Length = ProcessName->Length - (i * sizeof(WCHAR));
            fileName.MaximumLength = fileName.Length;
            break;
        }
    }

    for (ULONG i = 0; i < Globals.AIProcessCount; i++) {
        if (RtlCompareUnicodeString(&fileName, &Globals.AIProcessNames[i], TRUE) == 0) {
            return TRUE;
        }
    }

    return FALSE;
}

BOOLEAN AIShieldsIsSensitivePath(_In_ PUNICODE_STRING FilePath)
{
    for (ULONG i = 0; i < Globals.SensitivePathCount; i++) {
        if (RtlPrefixUnicodeString(&Globals.SensitivePaths[i], FilePath, TRUE)) {
            return TRUE;
        }
    }

    /* Built-in sensitive path checks */
    static const WCHAR* BuiltinSensitive[] = {
        L"\\Users\\",    /* Check for .ssh, .aws, etc. below */
        L"\\Windows\\System32\\config\\",
        L"\\ProgramData\\Microsoft\\Crypto\\",
        NULL
    };

    for (ULONG i = 0; BuiltinSensitive[i]; i++) {
        UNICODE_STRING pattern;
        RtlInitUnicodeString(&pattern, BuiltinSensitive[i]);
        if (FsRtlIsNameInExpression(&pattern, FilePath, TRUE, NULL)) {
            return TRUE;
        }
    }

    return FALSE;
}

BOOLEAN AIShieldsIsTargetIP(_In_ ULONG IPAddress)
{
    for (ULONG i = 0; i < Globals.TargetIPCount; i++) {
        if (Globals.TargetIPs[i] == IPAddress) {
            return TRUE;
        }
    }
    return FALSE;
}
