# NO-TskKILL
一个简单的进程与线程保护的驱动；通过拦截进程 / 线程的打开操作、限制关键访问权限，防止受保护的进程被恶意终止、修改内存或操控线程，同时支持通过用户态程序动态配置保护规则。
这是一个基于 Windows 内核模式驱动（Kernel-Mode Driver） 的代码，核心功能是 进程与线程保护 —— 通过拦截进程 / 线程的打开操作、限制关键访问权限，防止受保护的进程被恶意终止、修改内存或操控线程，同时支持通过用户态程序动态配置保护规则。以下从核心功能、技术原理、代码结构、风险与局限性四个维度展开讲解：
一、核心功能定位
该驱动本质是一个 轻量级进程保护工具，目标是防止特定进程被非法篡改或终止，典型应用场景包括：保护安全软件（如杀毒软件）、防止关键服务被恶意关闭等。其核心保护能力可归纳为 5 类：

保护维度	具体能力
进程权限拦截	限制对受保护进程的关键操作（终止、创建线程、修改内存、暂停 / 恢复等）
线程权限拦截	限制对受保护进程所属线程的关键操作（终止、暂停 / 恢复、设置上下文等）
多规则保护	支持两种保护规则：按 PID（进程 ID） 保护、按 进程名（精确 / 模糊匹配） 保护
子进程自动保护	若父进程受保护，其创建的子进程会自动加入保护列表
动态配置	支持用户态程序通过 IOCTL 指令开启 / 关闭保护、添加 / 移除保护对象、查询状态
二、核心技术原理
驱动基于 Windows 内核提供的 回调机制 和 设备模型 实现保护逻辑，关键技术点如下：
1. 进程 / 线程拦截：Object Manager 回调（ObRegisterCallbacks）
Windows 内核的 对象管理器（Object Manager） 负责管理所有内核对象（如进程、线程、文件等）。当用户态程序尝试打开一个进程 / 线程（如调用 OpenProcess/OpenThread）时，内核会触发预操作回调（Pre-Operation Callback），该驱动正是通过注册此回调实现拦截：

注册回调：在 DriverEntry（驱动入口）中，通过 ObRegisterCallbacks 注册两个回调函数：
OnPreOpenProcess：拦截 进程打开 / 复制句柄 操作；
OnPreOpenThread：拦截 线程打开 / 复制句柄 操作。
权限过滤：回调中会检查目标进程是否受保护（按 PID 或进程名），若受保护则 清除关键访问权限（如 PROCESS_TERMINATE 终止权限、THREAD_SUSPEND_RESUME 线程暂停权限），使调用者无法执行恶意操作。
2. 子进程自动保护：进程创建通知（PsSetCreateProcessNotifyRoutineEx）
通过 PsSetCreateProcessNotifyRoutineEx 注册进程创建通知回调 OnProcessNotify，当有新进程创建时：

检查新进程的 父进程 PID 是否在保护列表中；
若父进程受保护，自动将新进程（子进程）加入 PID 保护列表，实现 “父子联动保护”。
3. 用户态交互：设备模型与 IOCTL 通信
内核驱动无法直接与用户态程序交互，需通过 设备对象（Device Object） 和 符号链接（Symbolic Link） 提供接口：

创建设备：在 DriverEntry 中通过 IoCreateDevice 创建设备 \\Device\\saogang，用于内核态与用户态的数据传输；
创建符号链接：通过 IoCreateSymbolicLink 创建用户态可见的符号链接 \\DosDevices\\saogang（用户态程序可通过 \\.\saogang 访问）；
IOCTL 指令：定义 9 类 IOCTL 指令（如 IOCTL_SAOGANG_ADD_PID 添加保护 PID、IOCTL_SAOGANG_GET_STATUS 查询保护状态），用户态程序通过 DeviceIoControl 发送指令，驱动在 DeviceIoControl 函数中解析并执行。
4. 并发安全：自旋锁（KSPIN_LOCK）
内核态多线程并发访问共享数据（如保护列表）时，需避免竞争条件（Race Condition）。该驱动使用 KSPIN_LOCK 保护两个核心共享资源：

g_ProtectedListLock：保护 PID 保护列表 g_ProtectedProcesses；
g_ProtectedNamesLock：保护进程名保护列表 g_ProtectedNames；
操作逻辑：访问列表前通过 KeAcquireSpinLock 加锁（提升 IRQL 避免中断），操作后通过 KeReleaseSpinLock 解锁。
三、代码结构拆解
代码按 “驱动生命周期 + 功能模块” 划分，结构清晰，核心模块如下：
1. 常量与数据结构定义（头部）
定义保护规则、数据存储、通信协议相关的常量和结构：

保护常量：MAX_PROTECTED_PIDS（最大保护 PID 数量，64）、MAX_PROTECTED_NAMES（最大保护进程名数量，16）、PROTECT_ACCESS_MASK（进程保护权限掩码）、THREAD_PROTECT_MASK（线程保护权限掩码）；
核心结构：
_PROTECTED_PROCESS_INFO：存储单个受保护 PID 的信息（PID、进程名、保护时间、是否激活）；
_PROCESS_NAME_PROTECTION：存储单个受保护进程名的信息（进程名、是否激活、是否精确匹配）；
_SAOGANG_STATUS：返回给用户态的保护状态（是否开启保护、子进程自动保护开关、保护对象数量等）；
_ADD_NAME_REQUEST：用户态添加进程名保护的请求结构（进程名 + 匹配模式）。
2. 全局变量
存储保护状态、保护列表、内核对象句柄：

g_ProtectionEnabled：全局保护开关（TRUE = 开启）；
g_AutoProtectChildren：子进程自动保护开关；
g_AllowCallerPid：允许操作驱动的 “特权 PID”（动态配置）；
g_ProtectedProcesses：PID 保护列表（数组）；
g_ProtectedNames：进程名保护列表（数组）；
g_RegHandle：Ob 回调注册句柄；
g_DeviceObject：设备对象指针。
3. 核心功能函数（内部函数）
实现保护规则的核心逻辑：

权限验证：ValidateCallerAccess：检查调用者（用户态程序）是否为 “特权 PID”（硬编码的 SYSTEM 进程 PID=4 或动态配置的 g_AllowCallerPid）；
保护检查：IsPidProtected（检查 PID 是否在保护列表）、IsProcessNameProtected（检查进程名是否匹配保护规则）；
列表操作：AddProtectedPid/RemoveProtectedPid（添加 / 移除 PID 保护）、AddProtectedName/RemoveProtectedName（添加 / 移除进程名保护）；
辅助函数：GetProcessNameByPid（根据 PID 获取进程名，注：代码中为简化版本，实际需调用 SeLocateProcessImageName 等接口）、LogEvent（打印调试日志，通过 KdPrint 输出到调试器）。
4. 驱动生命周期函数
DriverEntry：驱动入口函数，完成初始化工作：
初始化自旋锁和保护列表；
创建设备对象和符号链接；
注册 Ob 回调（进程 / 线程拦截）和进程创建通知；
设置驱动卸载函数和 IRP 分发函数（处理 CREATE/CLOSE/DEVICE_CONTROL 请求）；
DriverUnload：驱动卸载函数，释放资源：
注销 Ob 回调和进程创建通知；
删除符号链接和设备对象；
打印卸载日志。
5. IRP 分发函数
处理用户态程序发送的请求：

DeviceCreateClose：处理用户态的 “打开 / 关闭设备” 请求（如 CreateFile/CloseHandle），核心是调用 ValidateCallerAccess 验证权限；
DeviceIoControl：处理用户态的 IOCTL 指令，解析指令类型并调用对应功能（如开启保护、添加 PID 等），支持异常捕获（__try/__except）避免驱动崩溃。
四、风险与局限性
该驱动为 “基础保护实现”，存在明显的安全风险和功能局限性，不适用于生产环境：
权限验证漏洞：ValidateCallerAccess 函数中 默认返回 TRUE（代码注释：“默认允许，想限制需修改为 false”）
