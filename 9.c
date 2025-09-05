#include <ntifs.h>
#include <ntstrsafe.h>
#include <ntddk.h>

// 保护常量定义
#define MAX_PROTECTED_PIDS 64
#define MAX_PROCESS_NAME_LEN 256
#define MAX_PROTECTED_NAMES 16

// 进程保护信息结构
typedef struct _PROTECTED_PROCESS_INFO {
    ULONG Pid;
    WCHAR ProcessName[MAX_PROCESS_NAME_LEN];
    LARGE_INTEGER ProtectionTime;
    BOOLEAN IsActive;
} PROTECTED_PROCESS_INFO, * PPROTECTED_PROCESS_INFO;

// 进程名称保护结构
typedef struct _PROCESS_NAME_PROTECTION {
    WCHAR ProcessName[MAX_PROCESS_NAME_LEN];
    BOOLEAN IsActive;
    BOOLEAN ExactMatch;  // TRUE=精确匹配, FALSE=模糊匹配
} PROCESS_NAME_PROTECTION, * PPROCESS_NAME_PROTECTION;

// 全局变量
volatile BOOLEAN g_ProtectionEnabled = TRUE;
volatile BOOLEAN g_AutoProtectChildren = TRUE;
volatile ULONG g_AllowCallerPid = 0;

// 特权调用者PID列表（硬编码方式）
static const ULONG g_PrivilegedPids[] = {
    4,      // SYSTEM进程
    0,      // 结束标记
};
static const ULONG g_PrivilegedPidsCount = sizeof(g_PrivilegedPids) / sizeof(g_PrivilegedPids[0]) - 1;

// 受保护的进程列表
static PROTECTED_PROCESS_INFO g_ProtectedProcesses[MAX_PROTECTED_PIDS];
static PROCESS_NAME_PROTECTION g_ProtectedNames[MAX_PROTECTED_NAMES];
static KSPIN_LOCK g_ProtectedListLock;
static KSPIN_LOCK g_ProtectedNamesLock;

// 进程访问权限掩码
#define PROCESS_TERMINATE 1
#ifndef PROCESS_CREATE_THREAD
#define PROCESS_CREATE_THREAD 0x0002
#endif
#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION 0x0008
#endif
#ifndef PROCESS_VM_WRITE
#define PROCESS_VM_WRITE 0x0020
#endif
#ifndef PROCESS_SUSPEND_RESUME
#define PROCESS_SUSPEND_RESUME 0x0800
#endif
#ifndef PROCESS_SET_QUOTA
#define PROCESS_SET_QUOTA 0x0100
#endif
#ifndef PROCESS_SET_INFORMATION
#define PROCESS_SET_INFORMATION 0x0200
#endif

#define PROTECT_ACCESS_MASK (PROCESS_TERMINATE | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_SUSPEND_RESUME | PROCESS_SET_QUOTA | PROCESS_SET_INFORMATION)

// 线程保护权限掩码
#ifndef THREAD_TERMINATE
#define THREAD_TERMINATE 0x0001
#endif
#ifndef THREAD_SUSPEND_RESUME
#define THREAD_SUSPEND_RESUME 0x0002
#endif
#ifndef THREAD_SET_CONTEXT
#define THREAD_SET_CONTEXT 0x0010
#endif
#ifndef THREAD_IMPERSONATE
#define THREAD_IMPERSONATE 0x0100
#endif
#ifndef THREAD_DIRECT_IMPERSONATION
#define THREAD_DIRECT_IMPERSONATION 0x0200
#endif
#ifndef THREAD_SET_LIMITED_INFORMATION
#define THREAD_SET_LIMITED_INFORMATION 0x0400
#endif

#define THREAD_PROTECT_MASK (THREAD_TERMINATE | THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT | THREAD_IMPERSONATE | THREAD_DIRECT_IMPERSONATION | THREAD_SET_LIMITED_INFORMATION)

// 设备名称
#define SAOGANG_DEVICE_NAME L"\\Device\\saogang"
#define SAOGANG_SYMLINK_NAME L"\\DosDevices\\saogang"

// IOCTL 代码
#define IOCTL_SAOGANG_ENABLE_PROTECTION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SAOGANG_DISABLE_PROTECTION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SAOGANG_ADD_PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SAOGANG_REMOVE_PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SAOGANG_ADD_NAME CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SAOGANG_REMOVE_NAME CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SAOGANG_SET_ALLOWPID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SAOGANG_GET_STATUS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SAOGANG_SET_AUTOCHILD CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)

// 状态结构
typedef struct _SAOGANG_STATUS {
    BOOLEAN ProtectionEnabled;
    BOOLEAN AutoProtectChildren;
    ULONG ProtectedPidCount;
    ULONG ProtectedNameCount;
    ULONG AllowCallerPid;
} SAOGANG_STATUS, * PSAOGANG_STATUS;

// 添加名称结构
typedef struct _ADD_NAME_REQUEST {
    WCHAR ProcessName[MAX_PROCESS_NAME_LEN];
    BOOLEAN ExactMatch;
} ADD_NAME_REQUEST, * PADD_NAME_REQUEST;

// 全局句柄
PVOID g_RegHandle = NULL;
PDEVICE_OBJECT g_DeviceObject = NULL;

// 函数声明
void DriverUnload(PDRIVER_OBJECT pDriverObject);
OB_PREOP_CALLBACK_STATUS OnPreOpenProcess(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION Info);
OB_PREOP_CALLBACK_STATUS OnPreOpenThread(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION Info);
VOID OnProcessNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo);
NTSTATUS DeviceCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS DeviceIoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);

// 内部函数
static BOOLEAN IsPidProtected(ULONG pid);
static BOOLEAN IsProcessNameProtected(PWCHAR processName);
static VOID AddProtectedPid(ULONG pid, PWCHAR processName);
static VOID RemoveProtectedPid(ULONG pid);
static VOID AddProtectedName(PWCHAR processName, BOOLEAN exactMatch);
static VOID RemoveProtectedName(PWCHAR processName);
static BOOLEAN GetProcessNameByPid(ULONG pid, PWCHAR processName, SIZE_T nameSize);
static BOOLEAN ValidateCallerAccess(PIRP Irp);
static VOID LogEvent(PWCHAR message, NTSTATUS status);
static VOID CleanupExpiredProtections();
static BOOLEAN AddPrivilegedPid(ULONG pid);
static BOOLEAN RemovePrivilegedPid(ULONG pid);
static BOOLEAN IsPrivilegedPid(ULONG pid);

// 前向声明
DRIVER_DISPATCH DeviceCreateClose;
DRIVER_DISPATCH DeviceIoControl;

// 权限验证函数
static BOOLEAN ValidateCallerAccess(PIRP Irp)
{
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);

    // 权限验证 - 检查是否为允许的PID
    ULONG callerPid = HandleToULong(PsGetCurrentProcessId());

    // 1. 检查是否为特权PID列表中的进程
    for (ULONG i = 0; i < g_PrivilegedPidsCount; i++) {
        if (callerPid == g_PrivilegedPids[i]) {
            return TRUE;
        }
    }

    // 2. 检查是否为动态设置的允许调用者PID
    if (g_AllowCallerPid != 0 && callerPid == g_AllowCallerPid) {
        return TRUE;
    }

    // 检查调用者是否有足够的权限（简化版本）
    if (irpSp->Parameters.Create.SecurityContext &&
        irpSp->Parameters.Create.SecurityContext->AccessState) {
        PACCESS_STATE accessState = irpSp->Parameters.Create.SecurityContext->AccessState;

        // 如果调用者有足够的访问权限，则允许
        if (accessState->PreviouslyGrantedAccess & (FILE_GENERIC_READ | FILE_GENERIC_WRITE)) {
            return TRUE;
        }
    }

	// 默认允许（简化版本），如果想使用这个功能在上面的g_PrivilegedPid中添加允许的PID，这里改为false
    return TRUE;
}

// 检查PID是否受保护
static BOOLEAN IsPidProtected(ULONG pid)
{
    if (pid == 0 || !g_ProtectionEnabled)
        return FALSE;

    // 检查是否为允许的调用者
    ULONG currentPid = HandleToULong(PsGetCurrentProcessId());
    if (currentPid == 4 || (g_AllowCallerPid != 0 && currentPid == g_AllowCallerPid))
        return FALSE;

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_ProtectedListLock, &oldIrql);

    BOOLEAN found = FALSE;
    for (int i = 0; i < MAX_PROTECTED_PIDS; ++i) {
        if (g_ProtectedProcesses[i].IsActive && g_ProtectedProcesses[i].Pid == pid) {
            found = TRUE;
            break;
        }
    }

    KeReleaseSpinLock(&g_ProtectedListLock, oldIrql);
    return found;
}

// 检查进程名称是否受保护
static BOOLEAN IsProcessNameProtected(PWCHAR processName)
{
    if (!processName || !g_ProtectionEnabled)
        return FALSE;

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_ProtectedNamesLock, &oldIrql);

    BOOLEAN found = FALSE;
    for (int i = 0; i < MAX_PROTECTED_NAMES; ++i) {
        if (g_ProtectedNames[i].IsActive) {
            if (g_ProtectedNames[i].ExactMatch) {
                if (RtlCompareMemory(processName, g_ProtectedNames[i].ProcessName,
                    wcslen(processName) * sizeof(WCHAR)) == wcslen(processName) * sizeof(WCHAR)) {
                    found = TRUE;
                    break;
                }
            }
            else {
                // 模糊匹配
                if (wcsstr(processName, g_ProtectedNames[i].ProcessName) != NULL) {
                    found = TRUE;
                    break;
                }
            }
        }
    }

    KeReleaseSpinLock(&g_ProtectedNamesLock, oldIrql);
    return found;
}

// 添加受保护的进程PID
static VOID AddProtectedPid(ULONG pid, PWCHAR processName)
{
    if (pid == 0)
        return;

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_ProtectedListLock, &oldIrql);

    // 查找空闲位置或更新现有项
    for (int i = 0; i < MAX_PROTECTED_PIDS; ++i) {
        if (!g_ProtectedProcesses[i].IsActive || g_ProtectedProcesses[i].Pid == pid) {
            g_ProtectedProcesses[i].Pid = pid;
            g_ProtectedProcesses[i].IsActive = TRUE;
            KeQuerySystemTime(&g_ProtectedProcesses[i].ProtectionTime);

            if (processName) {
                RtlZeroMemory(g_ProtectedProcesses[i].ProcessName, MAX_PROCESS_NAME_LEN);
                SIZE_T copySize = wcslen(processName) * sizeof(WCHAR);
                if (copySize > MAX_PROCESS_NAME_LEN - sizeof(WCHAR)) {
                    copySize = MAX_PROCESS_NAME_LEN - sizeof(WCHAR);
                }
                RtlCopyMemory(g_ProtectedProcesses[i].ProcessName, processName, copySize);
            }
            break;
        }
    }

    KeReleaseSpinLock(&g_ProtectedListLock, oldIrql);

    LogEvent(L"Added protected PID", STATUS_SUCCESS);
}

// 移除受保护的进程PID
static VOID RemoveProtectedPid(ULONG pid)
{
    if (pid == 0)
        return;

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_ProtectedListLock, &oldIrql);

    for (int i = 0; i < MAX_PROTECTED_PIDS; ++i) {
        if (g_ProtectedProcesses[i].IsActive && g_ProtectedProcesses[i].Pid == pid) {
            g_ProtectedProcesses[i].IsActive = FALSE;
            g_ProtectedProcesses[i].Pid = 0;
            RtlZeroMemory(g_ProtectedProcesses[i].ProcessName, MAX_PROCESS_NAME_LEN);
            break;
        }
    }

    KeReleaseSpinLock(&g_ProtectedListLock, oldIrql);

    LogEvent(L"Removed protected PID", STATUS_SUCCESS);
}

// 添加受保护的进程名称
static VOID AddProtectedName(PWCHAR processName, BOOLEAN exactMatch)
{
    if (!processName)
        return;

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_ProtectedNamesLock, &oldIrql);

    for (int i = 0; i < MAX_PROTECTED_NAMES; ++i) {
        if (!g_ProtectedNames[i].IsActive) {
            g_ProtectedNames[i].IsActive = TRUE;
            g_ProtectedNames[i].ExactMatch = exactMatch;
            RtlZeroMemory(g_ProtectedNames[i].ProcessName, MAX_PROCESS_NAME_LEN);
            SIZE_T copySize = wcslen(processName) * sizeof(WCHAR);
            if (copySize > MAX_PROCESS_NAME_LEN - sizeof(WCHAR)) {
                copySize = MAX_PROCESS_NAME_LEN - sizeof(WCHAR);
            }
            RtlCopyMemory(g_ProtectedNames[i].ProcessName, processName, copySize);
            break;
        }
    }

    KeReleaseSpinLock(&g_ProtectedNamesLock, oldIrql);
}

// 移除受保护的进程名称
static VOID RemoveProtectedName(PWCHAR processName)
{
    if (!processName)
        return;

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_ProtectedNamesLock, &oldIrql);

    for (int i = 0; i < MAX_PROTECTED_NAMES; ++i) {
        if (g_ProtectedNames[i].IsActive &&
            RtlCompareMemory(processName, g_ProtectedNames[i].ProcessName,
                wcslen(processName) * sizeof(WCHAR)) == wcslen(processName) * sizeof(WCHAR)) {
            g_ProtectedNames[i].IsActive = FALSE;
            RtlZeroMemory(g_ProtectedNames[i].ProcessName, MAX_PROCESS_NAME_LEN);
            break;
        }
    }

    KeReleaseSpinLock(&g_ProtectedNamesLock, oldIrql);
}

// 根据PID获取进程名称
static BOOLEAN GetProcessNameByPid(ULONG pid, PWCHAR processName, SIZE_T nameSize)
{
    PEPROCESS process;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &process);
    if (!NT_SUCCESS(status))
        return FALSE;

    // 简化版本 - 直接返回进程名，不实际获取
    // 注意：SeLocateProcessImageName在某些WDK版本中可能不存在
    // 这里使用一个简化的方法

    // 设置默认名称
    wcscpy_s(processName, nameSize / sizeof(WCHAR), L"unknown.exe");

    ObDereferenceObject(process);

    // 在实际应用中，这里需要使用其他方法来获取进程名
    // 比如通过进程通知回调来记录进程名

    return TRUE;
}

// 清理过期的保护
static VOID CleanupExpiredProtections()
{
    LARGE_INTEGER currentTime;
    KeQuerySystemTime(&currentTime);

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_ProtectedListLock, &oldIrql);

    for (int i = 0; i < MAX_PROTECTED_PIDS; ++i) {
        if (g_ProtectedProcesses[i].IsActive) {
            // 检查进程是否仍然存在
            PEPROCESS process;
            if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)g_ProtectedProcesses[i].Pid, &process))) {
                g_ProtectedProcesses[i].IsActive = FALSE;
                g_ProtectedProcesses[i].Pid = 0;
                RtlZeroMemory(g_ProtectedProcesses[i].ProcessName, MAX_PROCESS_NAME_LEN);
            }
            else {
                ObDereferenceObject(process);
            }
        }
    }

    KeReleaseSpinLock(&g_ProtectedListLock, oldIrql);
}

// 日志记录函数
static VOID LogEvent(PWCHAR message, NTSTATUS status)
{
    UNICODE_STRING logMessage;
    RtlInitUnicodeString(&logMessage, message);

    KdPrint(("[SAOGANG] %wZ - Status: 0x%08X\n", &logMessage, status));
}

// 进程打开前回调
OB_PREOP_CALLBACK_STATUS OnPreOpenProcess(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION Info)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    if (Info->KernelHandle || !g_ProtectionEnabled)
        return OB_PREOP_SUCCESS;

    PEPROCESS process = (PEPROCESS)Info->Object;
    ULONG pid = HandleToULong(PsGetProcessId(process));

    // 检查PID保护
    if (IsPidProtected(pid)) {
        if (Info->Operation == OB_OPERATION_HANDLE_CREATE) {
            Info->Parameters->CreateHandleInformation.DesiredAccess &= ~PROTECT_ACCESS_MASK;
        }
        else if (Info->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
            Info->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROTECT_ACCESS_MASK;
        }
        return OB_PREOP_SUCCESS;
    }

    // 检查进程名称保护
    WCHAR processName[MAX_PROCESS_NAME_LEN];
    if (GetProcessNameByPid(pid, processName, MAX_PROCESS_NAME_LEN)) {
        if (IsProcessNameProtected(processName)) {
            // 自动添加到PID保护列表
            AddProtectedPid(pid, processName);

            if (Info->Operation == OB_OPERATION_HANDLE_CREATE) {
                Info->Parameters->CreateHandleInformation.DesiredAccess &= ~PROTECT_ACCESS_MASK;
            }
            else if (Info->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
                Info->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROTECT_ACCESS_MASK;
            }
        }
    }

    return OB_PREOP_SUCCESS;
}

// 线程打开前回调
OB_PREOP_CALLBACK_STATUS OnPreOpenThread(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION Info)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    if (Info->KernelHandle || !g_ProtectionEnabled)
        return OB_PREOP_SUCCESS;

    PETHREAD thread = (PETHREAD)Info->Object;
    PEPROCESS ownerProcess = IoThreadToProcess(thread);
    if (!ownerProcess)
        return OB_PREOP_SUCCESS;

    ULONG ownerPid = HandleToULong(PsGetProcessId(ownerProcess));
    if (IsPidProtected(ownerPid)) {
        if (Info->Operation == OB_OPERATION_HANDLE_CREATE) {
            Info->Parameters->CreateHandleInformation.DesiredAccess &= ~THREAD_PROTECT_MASK;
        }
        else if (Info->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
            Info->Parameters->DuplicateHandleInformation.DesiredAccess &= ~THREAD_PROTECT_MASK;
        }
    }

    return OB_PREOP_SUCCESS;
}

// 进程通知回调
VOID OnProcessNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNREFERENCED_PARAMETER(Process);

    if (!CreateInfo || !g_AutoProtectChildren)
        return; // 进程退出

    ULONG parentPid = HandleToULong(CreateInfo->CreatingThreadId.UniqueProcess);
    ULONG childPid = HandleToULong(ProcessId);

    // 如果父进程受保护，自动保护子进程
    if (IsPidProtected(parentPid)) {
        WCHAR childProcessName[MAX_PROCESS_NAME_LEN];
        if (GetProcessNameByPid(childPid, childProcessName, MAX_PROCESS_NAME_LEN)) {
            AddProtectedPid(childPid, childProcessName);
        }
    }
}

// 设备创建/关闭处理
NTSTATUS DeviceCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    // 验证调用者权限
    if (!ValidateCallerAccess(Irp)) {
        Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_ACCESS_DENIED;
    }

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// 设备IO控制处理
NTSTATUS DeviceIoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    // 验证调用者权限
    if (!ValidateCallerAccess(Irp)) {
        Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_ACCESS_DENIED;
    }

    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR information = 0;

    __try {
        switch (irpSp->Parameters.DeviceIoControl.IoControlCode) {
        case IOCTL_SAOGANG_ENABLE_PROTECTION:
            g_ProtectionEnabled = TRUE;
            status = STATUS_SUCCESS;
            LogEvent(L"Protection enabled", STATUS_SUCCESS);
            break;

        case IOCTL_SAOGANG_DISABLE_PROTECTION:
            g_ProtectionEnabled = FALSE;
            status = STATUS_SUCCESS;
            LogEvent(L"Protection disabled", STATUS_SUCCESS);
            break;

        case IOCTL_SAOGANG_ADD_PID:
            if (irpSp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(ULONG)) {
                ULONG newPid = *(ULONG*)Irp->AssociatedIrp.SystemBuffer;
                WCHAR processName[MAX_PROCESS_NAME_LEN];
                GetProcessNameByPid(newPid, processName, MAX_PROCESS_NAME_LEN);
                AddProtectedPid(newPid, processName);
                status = STATUS_SUCCESS;
            }
            else {
                status = STATUS_BUFFER_TOO_SMALL;
            }
            break;

        case IOCTL_SAOGANG_REMOVE_PID:
            if (irpSp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(ULONG)) {
                ULONG remPid = *(ULONG*)Irp->AssociatedIrp.SystemBuffer;
                RemoveProtectedPid(remPid);
                status = STATUS_SUCCESS;
            }
            else {
                status = STATUS_BUFFER_TOO_SMALL;
            }
            break;

        case IOCTL_SAOGANG_ADD_NAME:
            if (irpSp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(ADD_NAME_REQUEST)) {
                PADD_NAME_REQUEST request = (PADD_NAME_REQUEST)Irp->AssociatedIrp.SystemBuffer;
                AddProtectedName(request->ProcessName, request->ExactMatch);
                status = STATUS_SUCCESS;
            }
            else {
                status = STATUS_BUFFER_TOO_SMALL;
            }
            break;

        case IOCTL_SAOGANG_REMOVE_NAME:
            if (irpSp->Parameters.DeviceIoControl.InputBufferLength >= MAX_PROCESS_NAME_LEN) {
                PWCHAR processName = (PWCHAR)Irp->AssociatedIrp.SystemBuffer;
                RemoveProtectedName(processName);
                status = STATUS_SUCCESS;
            }
            else {
                status = STATUS_BUFFER_TOO_SMALL;
            }
            break;

        case IOCTL_SAOGANG_SET_ALLOWPID:
            if (irpSp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(ULONG)) {
                ULONG allowPid = *(ULONG*)Irp->AssociatedIrp.SystemBuffer;
                InterlockedExchange((volatile LONG*)&g_AllowCallerPid, (LONG)allowPid);
                status = STATUS_SUCCESS;
            }
            else {
                status = STATUS_BUFFER_TOO_SMALL;
            }
            break;

        case IOCTL_SAOGANG_GET_STATUS:
            if (irpSp->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(SAOGANG_STATUS)) {
                PSAOGANG_STATUS statusInfo = (PSAOGANG_STATUS)Irp->AssociatedIrp.SystemBuffer;
                statusInfo->ProtectionEnabled = g_ProtectionEnabled;
                statusInfo->AutoProtectChildren = g_AutoProtectChildren;
                statusInfo->AllowCallerPid = g_AllowCallerPid;

                // 统计受保护的PID和名称数量
                KIRQL oldIrql;
                KeAcquireSpinLock(&g_ProtectedListLock, &oldIrql);
                ULONG pidCount = 0;
                for (int i = 0; i < MAX_PROTECTED_PIDS; ++i) {
                    if (g_ProtectedProcesses[i].IsActive) pidCount++;
                }
                KeReleaseSpinLock(&g_ProtectedListLock, oldIrql);

                KeAcquireSpinLock(&g_ProtectedNamesLock, &oldIrql);
                ULONG nameCount = 0;
                for (int i = 0; i < MAX_PROTECTED_NAMES; ++i) {
                    if (g_ProtectedNames[i].IsActive) nameCount++;
                }
                KeReleaseSpinLock(&g_ProtectedNamesLock, oldIrql);

                statusInfo->ProtectedPidCount = pidCount;
                statusInfo->ProtectedNameCount = nameCount;

                information = sizeof(SAOGANG_STATUS);
                status = STATUS_SUCCESS;
            }
            else {
                status = STATUS_BUFFER_TOO_SMALL;
            }
            break;

        case IOCTL_SAOGANG_SET_AUTOCHILD:
            if (irpSp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(ULONG)) {
                ULONG flag = *(ULONG*)Irp->AssociatedIrp.SystemBuffer;
                g_AutoProtectChildren = (flag ? TRUE : FALSE);
                status = STATUS_SUCCESS;
            }
            else {
                status = STATUS_BUFFER_TOO_SMALL;
            }
            break;

        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = STATUS_UNSUCCESSFUL;
        LogEvent(L"Exception in DeviceIoControl", status);
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

// 驱动入口点
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath)
{
    UNREFERENCED_PARAMETER(pRegPath);

    NTSTATUS status;

    // 初始化受保护列表锁
    KeInitializeSpinLock(&g_ProtectedListLock);
    KeInitializeSpinLock(&g_ProtectedNamesLock);

    // 初始化受保护列表
    RtlZeroMemory(g_ProtectedProcesses, sizeof(g_ProtectedProcesses));
    RtlZeroMemory(g_ProtectedNames, sizeof(g_ProtectedNames));

    // 创建设备和符号链接
    UNICODE_STRING deviceName = RTL_CONSTANT_STRING(SAOGANG_DEVICE_NAME);
    UNICODE_STRING symLinkName = RTL_CONSTANT_STRING(SAOGANG_SYMLINK_NAME);

    status = IoCreateDevice(pDriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN, FALSE, &g_DeviceObject);
    if (!NT_SUCCESS(status)) {
        LogEvent(L"IoCreateDevice failed", status);
        return status;
    }

    g_DeviceObject->Flags |= DO_BUFFERED_IO;

    status = IoCreateSymbolicLink(&symLinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        LogEvent(L"IoCreateSymbolicLink failed", status);
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    // 设置分发函数
    pDriverObject->MajorFunction[IRP_MJ_CREATE] = DeviceCreateClose;
    pDriverObject->MajorFunction[IRP_MJ_CLOSE] = DeviceCreateClose;
    pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceIoControl;

    // 注册回调
    OB_OPERATION_REGISTRATION operations[] = {
        {
            PsProcessType,
            OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE,
            OnPreOpenProcess, NULL
        },
        {
            PsThreadType,
            OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE,
            OnPreOpenThread, NULL
        }
    };

    OB_CALLBACK_REGISTRATION reg = {
        OB_FLT_REGISTRATION_VERSION,
        2,
        RTL_CONSTANT_STRING(L"SAOGANG_12345.6171"),
        NULL,
        operations
    };

    status = ObRegisterCallbacks(&reg, &g_RegHandle);
    if (!NT_SUCCESS(status)) {
        LogEvent(L"Failed to register callbacks", status);
        IoDeleteSymbolicLink(&symLinkName);
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    // 注册进程通知
    status = PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, FALSE);
    if (!NT_SUCCESS(status)) {
        LogEvent(L"PsSetCreateProcessNotifyRoutineEx failed", status);
        ObUnRegisterCallbacks(g_RegHandle);
        IoDeleteSymbolicLink(&symLinkName);
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    // 设置卸载函数
    pDriverObject->DriverUnload = DriverUnload;

    LogEvent(L"Driver loaded successfully", STATUS_SUCCESS);
    return STATUS_SUCCESS;
}

// 驱动卸载函数
void DriverUnload(PDRIVER_OBJECT pDriverObject)
{
    UNREFERENCED_PARAMETER(pDriverObject);

    // 注销回调
    if (g_RegHandle) {
        ObUnRegisterCallbacks(g_RegHandle);
        g_RegHandle = NULL;
    }

    // 注销进程通知
    PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, TRUE);

    // 删除符号链接和设备
    UNICODE_STRING symLinkName = RTL_CONSTANT_STRING(SAOGANG_SYMLINK_NAME);
    IoDeleteSymbolicLink(&symLinkName);

    if (g_DeviceObject) {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
    }

    LogEvent(L"Driver unloaded successfully", STATUS_SUCCESS);
}

// 特权PID管理函数
static BOOLEAN IsPrivilegedPid(ULONG pid)
{
    // 检查硬编码的特权PID列表
    for (ULONG i = 0; i < g_PrivilegedPidsCount; i++) {
        if (pid == g_PrivilegedPids[i]) {
            return TRUE;
        }
    }
    
    // 检查动态设置的允许调用者PID
    if (g_AllowCallerPid != 0 && pid == g_AllowCallerPid) {
        return TRUE;
    }
    
    return FALSE;
}

static BOOLEAN AddPrivilegedPid(ULONG pid)
{
    if (pid == 0) return FALSE;
    
    // 如果PID已经在特权列表中，返回成功
    if (IsPrivilegedPid(pid)) {
        return TRUE;
    }
    
    // 设置动态允许的调用者PID
    InterlockedExchange((volatile LONG*)&g_AllowCallerPid, (LONG)pid);
    LogEvent(L"Added privileged PID", STATUS_SUCCESS);
    return TRUE;
}

static BOOLEAN RemovePrivilegedPid(ULONG pid)
{
    if (pid == 0) return FALSE;
    
    // 只能移除动态设置的PID，不能移除硬编码的
    if (g_AllowCallerPid == pid) {
        InterlockedExchange((volatile LONG*)&g_AllowCallerPid, 0);
        LogEvent(L"Removed privileged PID", STATUS_SUCCESS);
        return TRUE;
    }
    
    return FALSE;
}
