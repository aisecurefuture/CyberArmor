/*
 * CyberArmor Protect - Windows Minifilter Driver Header
 * File system minifilter baseline with process telemetry and policy enforcement.
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

#define CYBERARMOR_FILTER_NAME       L"CyberArmorProtect"
#define CYBERARMOR_PORT_NAME         L"\\CyberArmorPort"
#define CYBERARMOR_ALTITUDE          L"370100"
#define CYBERARMOR_MAX_PATH          520
#define CYBERARMOR_MAX_PROCESS_NAME  260
#define CYBERARMOR_MAX_EVENTS        4096
#define CYBERARMOR_MAX_AI_PROCESSES  64
#define CYBERARMOR_MAX_SENSITIVE     128
#define CYBERARMOR_MAX_TARGET_IPS    64
#define CYBERARMOR_POOL_TAG          'CbAR'

/* Event types sent to usermode */
typedef enum _CYBERARMOR_EVENT_TYPE {
    EventFileCreate = 1,
    EventFileWrite  = 2,
    EventFileDelete = 3,
    EventProcessCreate = 4,
    EventProcessTerminate = 5,
    EventNetworkConnect = 6,
} CYBERARMOR_EVENT_TYPE;

/* Severity levels */
typedef enum _CYBERARMOR_SEVERITY {
    SeverityInfo     = 0,
    SeverityLow      = 1,
    SeverityMedium   = 2,
    SeverityHigh     = 3,
    SeverityCritical = 4,
} CYBERARMOR_SEVERITY;

/* Action to take */
typedef enum _CYBERARMOR_ACTION {
    ActionMonitor = 0,      /* Log only */
    ActionBlock   = 1,      /* Deny the operation */
} CYBERARMOR_ACTION;

/* Event structure sent to usermode service */
typedef struct _CYBERARMOR_EVENT {
    CYBERARMOR_EVENT_TYPE EventType;
    CYBERARMOR_SEVERITY   Severity;
    CYBERARMOR_ACTION     Action;
    LARGE_INTEGER         Timestamp;
    ULONG                 ProcessId;
    ULONG                 ThreadId;
    WCHAR                 ProcessName[CYBERARMOR_MAX_PROCESS_NAME];
    union {
        struct {
            WCHAR    FilePath[CYBERARMOR_MAX_PATH];
            ULONG    DesiredAccess;
            ULONG    CreateDisposition;
            BOOLEAN  IsDirectory;
        } FileCreate;
        struct {
            WCHAR    FilePath[CYBERARMOR_MAX_PATH];
            ULONG    WriteLength;
        } FileWrite;
        struct {
            WCHAR    FilePath[CYBERARMOR_MAX_PATH];
        } FileDelete;
        struct {
            ULONG    ChildProcessId;
            WCHAR    ImageFileName[CYBERARMOR_MAX_PATH];
            WCHAR    CommandLine[CYBERARMOR_MAX_PATH];
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
    } Data;
} CYBERARMOR_EVENT, *PCYBERARMOR_EVENT;

/* Command from usermode to kernel */
typedef enum _CYBERARMOR_COMMAND {
    CommandSetMode = 1,         /* Set monitor/enforce mode */
    CommandAddTargetIP = 2,     /* Add IP to monitoring list */
    CommandRemoveTargetIP = 3,  /* Remove IP from list */
    CommandAddSensitivePath = 4,/* Add sensitive file path */
    CommandRemoveSensitivePath = 5,
    CommandGetStats = 6,        /* Get statistics */
} CYBERARMOR_COMMAND;

typedef struct _CYBERARMOR_COMMAND_MESSAGE {
    CYBERARMOR_COMMAND Command;
    union {
        CYBERARMOR_ACTION Mode;
        ULONG             IPAddress;
        WCHAR             Path[CYBERARMOR_MAX_PATH];
    } Payload;
} CYBERARMOR_COMMAND_MESSAGE, *PCYBERARMOR_COMMAND_MESSAGE;

/* Statistics */
typedef struct _CYBERARMOR_STATS {
    LONG64 FilesMonitored;
    LONG64 FilesBlocked;
    LONG64 ProcessesMonitored;
    LONG64 NetworkConnectionsMonitored;
    LONG64 EventsSent;
    LONG64 EventsDropped;
} CYBERARMOR_STATS, *PCYBERARMOR_STATS;

/* Global filter data */
typedef struct _CYBERARMOR_GLOBAL_DATA {
    PFLT_FILTER          FilterHandle;
    PFLT_PORT            ServerPort;
    PFLT_PORT            ClientPort;
    PEPROCESS            UserProcess;
    CYBERARMOR_ACTION    GlobalMode;
    CYBERARMOR_STATS     Stats;
    BOOLEAN              Connected;

    /* Monitored AI process names */
    UNICODE_STRING       AIProcessNames[CYBERARMOR_MAX_AI_PROCESSES];
    ULONG                AIProcessCount;

    /* Sensitive file paths */
    UNICODE_STRING       SensitivePaths[CYBERARMOR_MAX_SENSITIVE];
    WCHAR                SensitivePathStorage[CYBERARMOR_MAX_SENSITIVE][CYBERARMOR_MAX_PATH];
    ULONG                SensitivePathCount;

    /* Target IP addresses */
    ULONG                TargetIPs[CYBERARMOR_MAX_TARGET_IPS];
    ULONG                TargetIPCount;

    /* Synchronization */
    ERESOURCE            Lock;
} CYBERARMOR_GLOBAL_DATA, *PCYBERARMOR_GLOBAL_DATA;

/* Driver lifecycle */
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath);
NTSTATUS CyberArmorUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);
NTSTATUS CyberArmorInstanceSetup(_In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags, _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType);

/* Minifilter callbacks */
FLT_PREOP_CALLBACK_STATUS CyberArmorPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);
FLT_POSTOP_CALLBACK_STATUS CyberArmorPostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext, _In_ FLT_POST_OPERATION_FLAGS Flags);
FLT_PREOP_CALLBACK_STATUS CyberArmorPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);

/* Communication port */
NTSTATUS CyberArmorPortConnect(_In_ PFLT_PORT ClientPort, _In_ PVOID ServerPortCookie,
    _In_ PVOID ConnectionContext, _In_ ULONG SizeOfContext, _Outptr_ PVOID *ConnectionCookie);
VOID CyberArmorPortDisconnect(_In_opt_ PVOID ConnectionCookie);
NTSTATUS CyberArmorPortMessage(_In_ PVOID ConnectionCookie, _In_ PVOID InputBuffer,
    _In_ ULONG InputBufferSize, _Out_ PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize, _Out_ PULONG ReturnOutputBufferLength);

/* Process notifications */
VOID CyberArmorProcessNotify(_Inout_ PEPROCESS Process, _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo);

/* Event helpers */
NTSTATUS CyberArmorSendEvent(_In_ PCYBERARMOR_EVENT Event);
BOOLEAN CyberArmorIsAIProcess(_In_ PCUNICODE_STRING ProcessName);
BOOLEAN CyberArmorIsSensitivePath(_In_ PCUNICODE_STRING FilePath);
BOOLEAN CyberArmorIsTargetIP(_In_ ULONG IPAddress);
