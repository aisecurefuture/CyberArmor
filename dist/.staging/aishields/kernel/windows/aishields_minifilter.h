/*
 * AIShields Protect - Windows Minifilter Driver Header
 * File system minifilter + WFP network filter for AI security monitoring.
 *
 * Build: WDK (Windows Driver Kit) required
 * Target: Windows 10 1903+ / Windows Server 2019+
 */

#pragma once

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include <ntstrsafe.h>
#include <wdm.h>

#define AISHIELDS_FILTER_NAME       L"AIShieldsProtect"
#define AISHIELDS_PORT_NAME         L"\\AIShieldsPort"
#define AISHIELDS_ALTITUDE          L"370100"
#define AISHIELDS_MAX_PATH          520
#define AISHIELDS_MAX_PROCESS_NAME  260
#define AISHIELDS_MAX_EVENTS        4096
#define AISHIELDS_POOL_TAG          'ShIA'

/* Event types sent to usermode */
typedef enum _AISHIELDS_EVENT_TYPE {
    EventFileCreate = 1,
    EventFileWrite  = 2,
    EventFileDelete = 3,
    EventProcessCreate = 4,
    EventProcessTerminate = 5,
    EventNetworkConnect = 6,
} AISHIELDS_EVENT_TYPE;

/* Severity levels */
typedef enum _AISHIELDS_SEVERITY {
    SeverityInfo     = 0,
    SeverityLow      = 1,
    SeverityMedium   = 2,
    SeverityHigh     = 3,
    SeverityCritical = 4,
} AISHIELDS_SEVERITY;

/* Action to take */
typedef enum _AISHIELDS_ACTION {
    ActionMonitor = 0,      /* Log only */
    ActionBlock   = 1,      /* Deny the operation */
} AISHIELDS_ACTION;

/* Event structure sent to usermode service */
typedef struct _AISHIELDS_EVENT {
    AISHIELDS_EVENT_TYPE EventType;
    AISHIELDS_SEVERITY   Severity;
    AISHIELDS_ACTION     Action;
    LARGE_INTEGER        Timestamp;
    ULONG                ProcessId;
    ULONG                ThreadId;
    WCHAR                ProcessName[AISHIELDS_MAX_PROCESS_NAME];
    union {
        struct {
            WCHAR    FilePath[AISHIELDS_MAX_PATH];
            ULONG    DesiredAccess;
            ULONG    CreateDisposition;
            BOOLEAN  IsDirectory;
        } FileCreate;
        struct {
            WCHAR    FilePath[AISHIELDS_MAX_PATH];
            ULONG    WriteLength;
        } FileWrite;
        struct {
            WCHAR    FilePath[AISHIELDS_MAX_PATH];
        } FileDelete;
        struct {
            ULONG    ChildProcessId;
            WCHAR    ImageFileName[AISHIELDS_MAX_PATH];
            WCHAR    CommandLine[AISHIELDS_MAX_PATH];
        } ProcessCreate;
        struct {
            ULONG    ExitCode;
        } ProcessTerminate;
        struct {
            ULONG    RemoteAddress;     /* IPv4 in network byte order */
            USHORT   RemotePort;
            USHORT   LocalPort;
            USHORT   Protocol;          /* IPPROTO_TCP or IPPROTO_UDP */
        } NetworkConnect;
    };
} AISHIELDS_EVENT, *PAISHIELDS_EVENT;

/* Command from usermode to kernel */
typedef enum _AISHIELDS_COMMAND {
    CommandSetMode = 1,         /* Set monitor/enforce mode */
    CommandAddTargetIP = 2,     /* Add IP to monitoring list */
    CommandRemoveTargetIP = 3,  /* Remove IP from list */
    CommandAddSensitivePath = 4,/* Add sensitive file path */
    CommandGetStats = 5,        /* Get statistics */
} AISHIELDS_COMMAND;

typedef struct _AISHIELDS_COMMAND_MESSAGE {
    AISHIELDS_COMMAND Command;
    union {
        AISHIELDS_ACTION Mode;
        ULONG            IPAddress;
        WCHAR            Path[AISHIELDS_MAX_PATH];
    };
} AISHIELDS_COMMAND_MESSAGE, *PAISHIELDS_COMMAND_MESSAGE;

/* Statistics */
typedef struct _AISHIELDS_STATS {
    LONG64 FilesMonitored;
    LONG64 FilesBlocked;
    LONG64 ProcessesMonitored;
    LONG64 NetworkConnectionsMonitored;
    LONG64 EventsSent;
    LONG64 EventsDropped;
} AISHIELDS_STATS, *PAISHIELDS_STATS;

/* Global filter data */
typedef struct _AISHIELDS_GLOBAL_DATA {
    PFLT_FILTER         FilterHandle;
    PFLT_PORT           ServerPort;
    PFLT_PORT           ClientPort;
    PEPROCESS           UserProcess;
    AISHIELDS_ACTION    GlobalMode;
    AISHIELDS_STATS     Stats;
    BOOLEAN             Connected;

    /* Monitored AI process names */
    UNICODE_STRING      AIProcessNames[64];
    ULONG               AIProcessCount;

    /* Sensitive file paths */
    UNICODE_STRING      SensitivePaths[128];
    ULONG               SensitivePathCount;

    /* Target IP addresses */
    ULONG               TargetIPs[64];
    ULONG               TargetIPCount;

    /* Synchronization */
    ERESOURCE           Lock;
} AISHIELDS_GLOBAL_DATA, *PAISHIELDS_GLOBAL_DATA;

/* Function prototypes */

/* Driver lifecycle */
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath);
NTSTATUS AIShieldsUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);
NTSTATUS AIShieldsInstanceSetup(_In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags, _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType);

/* Minifilter callbacks */
FLT_PREOP_CALLBACK_STATUS AIShieldsPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);
FLT_POSTOP_CALLBACK_STATUS AIShieldsPostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext, _In_ FLT_POST_OPERATION_FLAGS Flags);
FLT_PREOP_CALLBACK_STATUS AIShieldsPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);

/* Communication port */
NTSTATUS AIShieldsPortConnect(_In_ PFLT_PORT ClientPort, _In_ PVOID ServerPortCookie,
    _In_ PVOID ConnectionContext, _In_ ULONG SizeOfContext, _Outptr_ PVOID *ConnectionCookie);
VOID AIShieldsPortDisconnect(_In_opt_ PVOID ConnectionCookie);
NTSTATUS AIShieldsPortMessage(_In_ PVOID ConnectionCookie, _In_ PVOID InputBuffer,
    _In_ ULONG InputBufferSize, _Out_ PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize, _Out_ PULONG ReturnOutputBufferLength);

/* Process notifications */
VOID AIShieldsProcessNotify(_Inout_ PEPROCESS Process, _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo);

/* Event helpers */
NTSTATUS AIShieldsSendEvent(_In_ PAISHIELDS_EVENT Event);
BOOLEAN AIShieldsIsAIProcess(_In_ PUNICODE_STRING ProcessName);
BOOLEAN AIShieldsIsSensitivePath(_In_ PUNICODE_STRING FilePath);
BOOLEAN AIShieldsIsTargetIP(_In_ ULONG IPAddress);
