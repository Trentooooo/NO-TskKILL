#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <tlhelp32.h>

// IOCTL definitions (consistent with driver)
#define IOCTL_SAOGANG_ENABLE_PROTECTION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SAOGANG_DISABLE_PROTECTION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SAOGANG_ADD_PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SAOGANG_REMOVE_PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SAOGANG_ADD_NAME CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SAOGANG_REMOVE_NAME CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SAOGANG_SET_ALLOWPID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SAOGANG_GET_STATUS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SAOGANG_SET_AUTOCHILD CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Structure definitions
typedef struct _SAOGANG_STATUS {
    BOOLEAN ProtectionEnabled;
    BOOLEAN AutoProtectChildren;
    ULONG ProtectedPidCount;
    ULONG ProtectedNameCount;
    ULONG AllowCallerPid;
} SAOGANG_STATUS, * PSAOGANG_STATUS;

typedef struct _ADD_NAME_REQUEST {
    WCHAR ProcessName[256];
    BOOLEAN ExactMatch;
} ADD_NAME_REQUEST, * PADD_NAME_REQUEST;

class SaogangClient {
private:
    HANDLE hDevice;

public:
    SaogangClient() : hDevice(INVALID_HANDLE_VALUE) {}

    ~SaogangClient() {
        if (hDevice != INVALID_HANDLE_VALUE) {
            CloseHandle(hDevice);
        }
    }

    bool Connect() {
        std::wcout << L"Attempting to connect to driver..." << std::endl;
        
        hDevice = CreateFile(
            L"\\\\.\\saogang",
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            0,
            NULL
        );

        if (hDevice == INVALID_HANDLE_VALUE) {
            DWORD error = GetLastError();
            std::wcout << L"Failed to connect to driver, error code: " << error << std::endl;
            
            // Provide detailed error information
            switch (error) {
                case ERROR_FILE_NOT_FOUND:
                    std::wcout << L"Error: Driver device not found. Please ensure:" << std::endl;
                    std::wcout << L"1. Driver is properly compiled" << std::endl;
                    std::wcout << L"2. Driver is installed (using saogang.inf)" << std::endl;
                    std::wcout << L"3. Driver service is started" << std::endl;
                    break;
                case ERROR_ACCESS_DENIED:
                    std::wcout << L"Error: Access denied. Please run this program as administrator." << std::endl;
                    break;
                case ERROR_INVALID_HANDLE:
                    std::wcout << L"Error: Invalid device handle." << std::endl;
                    break;
                default:
                    std::wcout << L"Unknown error, please check driver status." << std::endl;
                    break;
            }
            
            std::wcout << L"\nDriver installation steps:" << std::endl;
            std::wcout << L"1. Compile saogang project to generate saogang.sys" << std::endl;
            std::wcout << L"2. Run as admin: pnputil /add-driver saogang.inf /install" << std::endl;
            std::wcout << L"3. Start service: sc start saogang" << std::endl;
            
            return false;
        }

        std::wcout << L"Successfully connected to driver!" << std::endl;
        return true;
    }

    bool EnableProtection() {
        DWORD bytesReturned;
        BOOL result = DeviceIoControl(
            hDevice,
            IOCTL_SAOGANG_ENABLE_PROTECTION,
            NULL, 0,
            NULL, 0,
            &bytesReturned,
            NULL
        );
        
        if (!result) {
            DWORD error = GetLastError();
            std::wcout << L"EnableProtection failed with error code: " << error << std::endl;
            
            switch (error) {
                case ERROR_INVALID_FUNCTION:
                    std::wcout << L"Error: Invalid function - IOCTL not supported by driver" << std::endl;
                    break;
                case ERROR_INVALID_PARAMETER:
                    std::wcout << L"Error: Invalid parameter" << std::endl;
                    break;
                case ERROR_NOT_SUPPORTED:
                    std::wcout << L"Error: Operation not supported" << std::endl;
                    break;
                case ERROR_ACCESS_DENIED:
                    std::wcout << L"Error: Access denied - insufficient privileges" << std::endl;
                    break;
                default:
                    std::wcout << L"Unknown error occurred" << std::endl;
                    break;
            }
        }
        
        return result != 0;
    }

    bool DisableProtection() {
        DWORD bytesReturned;
        BOOL result = DeviceIoControl(
            hDevice,
            IOCTL_SAOGANG_DISABLE_PROTECTION,
            NULL, 0,
            NULL, 0,
            &bytesReturned,
            NULL
        );
        
        if (!result) {
            DWORD error = GetLastError();
            std::wcout << L"DisableProtection failed with error code: " << error << std::endl;
        }
        
        return result != 0;
    }

    bool AddProtectedPid(DWORD pid) {
        DWORD bytesReturned;
        return DeviceIoControl(
            hDevice,
            IOCTL_SAOGANG_ADD_PID,
            &pid, sizeof(pid),
            NULL, 0,
            &bytesReturned,
            NULL
        );
    }

    bool RemoveProtectedPid(DWORD pid) {
        DWORD bytesReturned;
        return DeviceIoControl(
            hDevice,
            IOCTL_SAOGANG_REMOVE_PID,
            &pid, sizeof(pid),
            NULL, 0,
            &bytesReturned,
            NULL
        );
    }

    bool AddProtectedName(const std::wstring& processName, bool exactMatch = false) {
        ADD_NAME_REQUEST request;
        ZeroMemory(&request, sizeof(request));
        wcscpy_s(request.ProcessName, processName.c_str());
        request.ExactMatch = exactMatch;

        DWORD bytesReturned;
        return DeviceIoControl(
            hDevice,
            IOCTL_SAOGANG_ADD_NAME,
            &request, sizeof(request),
            NULL, 0,
            &bytesReturned,
            NULL
        );
    }

    bool RemoveProtectedName(const std::wstring& processName) {
        DWORD bytesReturned;
        // Fix compilation warning: convert size_t to DWORD
        DWORD dataSize = static_cast<DWORD>(processName.length() * sizeof(WCHAR));
        return DeviceIoControl(
            hDevice,
            IOCTL_SAOGANG_REMOVE_NAME,
            (PVOID)processName.c_str(), dataSize,
            NULL, 0,
            &bytesReturned,
            NULL
        );
    }

    bool SetAllowCallerPid(DWORD pid) {
        DWORD bytesReturned;
        return DeviceIoControl(
            hDevice,
            IOCTL_SAOGANG_SET_ALLOWPID,
            &pid, sizeof(pid),
            NULL, 0,
            &bytesReturned,
            NULL
        );
    }

    bool GetStatus(SAOGANG_STATUS& status) {
        DWORD bytesReturned;
        return DeviceIoControl(
            hDevice,
            IOCTL_SAOGANG_GET_STATUS,
            NULL, 0,
            &status, sizeof(status),
            &bytesReturned,
            NULL
        );
    }

    bool SetAutoProtectChildren(bool enable) {
        DWORD flag = enable ? 1 : 0;
        DWORD bytesReturned;
        return DeviceIoControl(
            hDevice,
            IOCTL_SAOGANG_SET_AUTOCHILD,
            &flag, sizeof(flag),
            NULL, 0,
            &bytesReturned,
            NULL
        );
    }

    // Get process list
    std::vector<std::pair<DWORD, std::wstring>> GetProcessList() {
        std::vector<std::pair<DWORD, std::wstring>> processes;

        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            return processes;
        }

        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);

        if (Process32FirstW(hSnapshot, &pe32)) {
            do {
                processes.push_back(std::make_pair(pe32.th32ProcessID, std::wstring(pe32.szExeFile)));
            } while (Process32NextW(hSnapshot, &pe32));
        }

        CloseHandle(hSnapshot);
        return processes;
    }

    // Find PID by process name
    std::vector<DWORD> FindProcessesByName(const std::wstring& processName) {
        std::vector<DWORD> pids;
        auto processes = GetProcessList();

        for (const auto& proc : processes) {
            if (proc.second.find(processName) != std::wstring::npos) {
                pids.push_back(proc.first);
            }
        }

        return pids;
    }
};

void PrintMenu() {
    std::wcout << L"\n=== SAOGANG Process Protection Client ===" << std::endl;
    std::wcout << L"1. Enable Protection" << std::endl;
    std::wcout << L"2. Disable Protection" << std::endl;
    std::wcout << L"3. Add Protected PID" << std::endl;
    std::wcout << L"4. Remove Protected PID" << std::endl;
    std::wcout << L"5. Add Protected Process Name" << std::endl;
    std::wcout << L"6. Remove Protected Process Name" << std::endl;
    std::wcout << L"7. Set Allowed Caller PID" << std::endl;
    std::wcout << L"8. Get Status Information" << std::endl;
    std::wcout << L"9. Set Auto-Protect Children" << std::endl;
    std::wcout << L"10. Show Process List" << std::endl;
    std::wcout << L"11. Find Process by Name" << std::endl;
    std::wcout << L"0. Exit" << std::endl;
    std::wcout << L"Please select operation: ";
}

int main() {
    // Set console output page to support English
    SetConsoleOutputCP(CP_UTF8);

    SaogangClient client;

    if (!client.Connect()) {
        std::wcout << L"Connection failed, program exiting..." << std::endl;
        std::cin.get();
        return 1;
    }

    int choice;
    std::wstring input;

    while (true) {
        PrintMenu();
        std::wcin >> choice;

        switch (choice) {
        case 1:
            if (client.EnableProtection()) {
                std::wcout << L"Protection enabled" << std::endl;
            }
            else {
                std::wcout << L"Failed to enable protection" << std::endl;
            }
            break;

        case 2:
            if (client.DisableProtection()) {
                std::wcout << L"Protection disabled" << std::endl;
            }
            else {
                std::wcout << L"Failed to disable protection" << std::endl;
            }
            break;

        case 3: {
            DWORD pid;
            std::wcout << L"Please enter PID to protect: ";
            std::wcin >> pid;
            if (client.AddProtectedPid(pid)) {
                std::wcout << L"PID " << pid << L" added to protection list" << std::endl;
            }
            else {
                std::wcout << L"Failed to add PID" << std::endl;
            }
            break;
        }

        case 4: {
            DWORD pid;
            std::wcout << L"Please enter PID to remove: ";
            std::wcin >> pid;
            if (client.RemoveProtectedPid(pid)) {
                std::wcout << L"PID " << pid << L" removed from protection list" << std::endl;
            }
            else {
                std::wcout << L"Failed to remove PID" << std::endl;
            }
            break;
        }

        case 5: {
            std::wstring processName;
            bool exactMatch;
            std::wcout << L"Please enter process name: ";
            std::wcin >> processName;
            std::wcout << L"Exact match? (1=yes, 0=no): ";
            std::wcin >> exactMatch;

            if (client.AddProtectedName(processName, exactMatch)) {
                std::wcout << L"Process name " << processName << L" added to protection list" << std::endl;
            }
            else {
                std::wcout << L"Failed to add process name" << std::endl;
            }
            break;
        }

        case 6: {
            std::wstring processName;
            std::wcout << L"Please enter process name to remove: ";
            std::wcin >> processName;
            if (client.RemoveProtectedName(processName)) {
                std::wcout << L"Process name " << processName << L" removed from protection list" << std::endl;
            }
            else {
                std::wcout << L"Failed to remove process name" << std::endl;
            }
            break;
        }

        case 7: {
            DWORD pid;
            std::wcout << L"Please enter allowed caller PID: ";
            std::wcin >> pid;
            if (client.SetAllowCallerPid(pid)) {
                std::wcout << L"Allowed caller PID set to " << pid << std::endl;
            }
            else {
                std::wcout << L"Failed to set allowed caller PID" << std::endl;
            }
            break;
        }

        case 8: {
            SAOGANG_STATUS status;
            if (client.GetStatus(status)) {
                std::wcout << L"\n=== Status Information ===" << std::endl;
                std::wcout << L"Protection Status: " << (status.ProtectionEnabled ? L"Enabled" : L"Disabled") << std::endl;
                std::wcout << L"Auto-Protect Children: " << (status.AutoProtectChildren ? L"Enabled" : L"Disabled") << std::endl;
                std::wcout << L"Protected PID Count: " << status.ProtectedPidCount << std::endl;
                std::wcout << L"Protected Process Name Count: " << status.ProtectedNameCount << std::endl;
                std::wcout << L"Allowed Caller PID: " << status.AllowCallerPid << std::endl;
            }
            else {
                std::wcout << L"Failed to get status" << std::endl;
            }
            break;
        }

        case 9: {
            bool enable;
            std::wcout << L"Enable auto-protect children? (1=yes, 0=no): ";
            std::wcin >> enable;
            if (client.SetAutoProtectChildren(enable)) {
                std::wcout << L"Auto-protect children " << (enable ? L"enabled" : L"disabled") << std::endl;
            }
            else {
                std::wcout << L"Failed to set auto-protect children" << std::endl;
            }
            break;
        }

        case 10: {
            auto processes = client.GetProcessList();
            std::wcout << L"\n=== Process List ===" << std::endl;
            std::wcout << L"PID\tProcess Name" << std::endl;
            std::wcout << L"---\t------------" << std::endl;

            for (const auto& proc : processes) {
                std::wcout << proc.first << L"\t" << proc.second << std::endl;
            }
            std::wcout << L"Total " << processes.size() << L" processes" << std::endl;
            break;
        }

        case 11: {
            std::wstring processName;
            std::wcout << L"Please enter process name to search: ";
            std::wcin >> processName;

            auto pids = client.FindProcessesByName(processName);
            if (pids.empty()) {
                std::wcout << L"No processes found with name '" << processName << L"'" << std::endl;
            }
            else {
                std::wcout << L"Found the following processes:" << std::endl;
                for (DWORD pid : pids) {
                    std::wcout << L"PID: " << pid << std::endl;
                }
            }
            break;
        }

        case 0:
            std::wcout << L"Exiting program" << std::endl;
            return 0;

        default:
            std::wcout << L"Invalid choice, please try again" << std::endl;
            break;
        }

        std::wcout << L"\nPress Enter to continue...";
        std::wcin.ignore();
        std::wcin.get();
    }

    return 0;
}
