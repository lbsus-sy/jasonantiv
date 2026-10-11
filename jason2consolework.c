#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <stdio.h>
#include <aclapi.h>
#include <shlwapi.h>
#include <wchar.h>
#include <stdbool.h>
#include <restartmanager.h>
#include <shlobj.h>

#define SystemExtendedHandleInformation 0x40
#ifndef DOMAIN_ALIAS_ADMINS
#define DOMAIN_ALIAS_ADMINS (0x00000220L)
#endif

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "rstrtmgr.lib")

// --------------------------------------------------------------------------
// NT API 數據結構與函數指標定義
// --------------------------------------------------------------------------
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif

#ifndef NTAPI
#define NTAPI __stdcall
#endif

typedef NTSTATUS(NTAPI* pfnNtSetInformationProcess)(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength
);

typedef NTSTATUS(NTAPI* pfnNtSuspendProcess)(HANDLE ProcessHandle);

typedef NTSTATUS(NTAPI* pfnNtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS(NTAPI* pfnNtDuplicateObject)(
    HANDLE SourceProcessHandle,
    HANDLE SourceHandle,
    HANDLE TargetProcessHandle,
    PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes,
    ULONG Options
);

typedef struct {
    DWORD pid;
    wchar_t exeName[MAX_PATH];
    wchar_t fullPath[MAX_PATH];
    HANDLE hProcess;
} TARGET_PROCESS;

// 註冊表/結構日誌記錄輔助結構
typedef struct {
    wchar_t name[256];
    wchar_t targetPath[MAX_PATH];
} EXPLICIT_DELETE_INFO;

// 全域保存 SYSTEM Primary Token，供 CreateProcessWithTokenW 使用
static HANDLE g_hSystemPrimaryToken = NULL;

// 系統關鍵進程白名單檢查
static bool IsCriticalSystemProcess(_In_opt_ LPCWSTR szExeName) {
    if (!szExeName || *szExeName == L'\0') return true;

    LPCWSTR whitelist[] = {
        L"explorer.exe", L"winlogon.exe", L"lsass.exe", L"csrss.exe",
        L"services.exe", L"smss.exe", L"svchost.exe", L"taskmgr.exe",
        L"userinit.exe", L"wininit.exe", L"spoolsv.exe"
    };
    for (size_t i = 0; i < sizeof(whitelist) / sizeof(whitelist[0]); i++) {
        if (_wcsicmp(szExeName, whitelist[i]) == 0) return true;
    }
    return false;
}

// 精準目標比對工具
static bool IsTargetMatch(LPCWSTR szPathOrText, LPCWSTR szTargetName, LPCWSTR szTargetPath) {
    if (!szPathOrText || *szPathOrText == L'\0') return false;

    wchar_t cleanPath[MAX_PATH] = { 0 };
    LPCWSTR pStart = szPathOrText;

    while (*pStart == L'\"' || *pStart == L' ' || *pStart == L'\t') {
        pStart++;
    }
    wcscpy_s(cleanPath, MAX_PATH, pStart);

    for (int i = 0; cleanPath[i] != L'\0'; i++) {
        if (cleanPath[i] == L'\"' || cleanPath[i] == L',' || cleanPath[i] == L'\r' || cleanPath[i] == L'\n') {
            cleanPath[i] = L'\0';
            break;
        }
    }

    if (szTargetPath && *szTargetPath != L'\0') {
        wchar_t cleanTarget[MAX_PATH] = { 0 };
        LPCWSTR pTargetStart = szTargetPath;
        while (*pTargetStart == L'\"' || *pTargetStart == L' ') pTargetStart++;
        wcscpy_s(cleanTarget, MAX_PATH, pTargetStart);

        for (int i = 0; cleanTarget[i] != L'\0'; i++) {
            if (cleanTarget[i] == L'\"') { cleanTarget[i] = L'\0'; break; }
        }

        if (_wcsicmp(cleanPath, cleanTarget) == 0) return true;
    }

    if (szTargetName && *szTargetName != L'\0') {
        LPCWSTR szFileName = PathFindFileNameW(cleanPath);

        wchar_t cleanName[MAX_PATH] = { 0 };
        wcscpy_s(cleanName, MAX_PATH, szFileName);

        for (int i = 0; cleanName[i] != L'\0'; i++) {
            if (cleanName[i] == L'\"' || cleanName[i] == L' ' || cleanName[i] == L'\t') {
                cleanName[i] = L'\0';
                break;
            }
        }

        if (_wcsicmp(cleanName, szTargetName) == 0) {
            return true;
        }
    }
    return false;
}

// 判斷是否為真實登入使用者的 SID 註冊表項
static bool IsValidUserSidKey(_In_ LPCWSTR szSubKey) {
    if (szSubKey[0] == L'\0') return false;
    if (_wcsicmp(szSubKey, L".DEFAULT") == 0) return false;
    if (wcsstr(szSubKey, L"_Classes") != NULL) return false;

    if (_wcsicmp(szSubKey, L"S-1-5-18") == 0 ||
        _wcsicmp(szSubKey, L"S-1-5-19") == 0 ||
        _wcsicmp(szSubKey, L"S-1-5-20") == 0) {
        return false;
    }

    return (wcsncmp(szSubKey, L"S-1-5-", 6) == 0);
}

// --------------------------------------------------------------------------
// 1. 權限提升與 SYSTEM 令牌竊取 & 跨進程命令執行（帶輸出日誌捕獲）
// --------------------------------------------------------------------------
bool EnableAllPrivileges() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) return false;

    LPCWSTR privileges[] = {
        L"SeDebugPrivilege", L"SeTakeOwnershipPrivilege", L"SeRestorePrivilege",
        L"SeBackupPrivilege", L"SeLoadDriverPrivilege", L"SeImpersonatePrivilege",
        L"SeAssignPrimaryTokenPrivilege", L"SeIncreaseQuotaPrivilege"
    };

    bool allSuccess = true;
    size_t privCount = sizeof(privileges) / sizeof(privileges[0]);
    for (size_t i = 0; i < privCount; i++) {
        TOKEN_PRIVILEGES tp;
        LUID luid;
        if (LookupPrivilegeValueW(NULL, privileges[i], &luid)) {
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL) ||
                GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
                allSuccess = false;
            }
        }
    }
    CloseHandle(hToken);
    return allSuccess;
}

bool ImpersonateSystemToken() {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return false;

    LPCWSTR targetProcesses[] = { L"spoolsv.exe", L"services.exe" };
    size_t targetCount = sizeof(targetProcesses) / sizeof(targetProcesses[0]);

    PROCESSENTRY32W pe = { sizeof(pe) };
    bool success = false;

    if (Process32FirstW(hSnap, &pe)) {
        do {
            for (size_t i = 0; i < targetCount; i++) {
                if (_wcsicmp(pe.szExeFile, targetProcesses[i]) == 0) {
                    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe.th32ProcessID);
                    if (!hProcess) continue;

                    HANDLE hToken = NULL, hDupToken = NULL, hPrimaryToken = NULL;
                    if (OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &hToken)) {
                        if (DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenImpersonation, &hDupToken)) {
                            if (SetThreadToken(NULL, hDupToken)) {
                                wprintf(L"[+] Successfully impersonated NT AUTHORITY\\SYSTEM thread token via %s (PID: %lu).\n", pe.szExeFile, pe.th32ProcessID);
                                success = true;
                            }
                            CloseHandle(hDupToken);
                        }
                        if (DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hPrimaryToken)) {
                            g_hSystemPrimaryToken = hPrimaryToken;
                            wprintf(L"[+] Acquired SYSTEM Primary Process Token for child process execution.\n");
                        }
                        CloseHandle(hToken);
                    }
                    CloseHandle(hProcess);

                    if (success) break;
                }
            }
            if (success) break;
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);

    if (!success) {
        wprintf(L"[-] Failed to impersonate SYSTEM token from candidate processes.\n");
    }

    return success;
}

void ExecuteCommandAsSystem(LPCWSTR szCmd) {
    if (!szCmd || wcslen(szCmd) == 0) return;

    wchar_t cmdBuffer[4096];
    wcscpy_s(cmdBuffer, 4096, szCmd);

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    bool launched = false;

    if (g_hSystemPrimaryToken) {
        if (CreateProcessAsUserW(g_hSystemPrimaryToken, NULL, cmdBuffer, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
            launched = true;
        }
        else if (CreateProcessWithTokenW(g_hSystemPrimaryToken, LOGON_WITH_PROFILE, NULL, cmdBuffer, 0, NULL, NULL, &si, &pi)) {
            launched = true;
        }
    }

    if (launched) {
        WaitForSingleObject(pi.hProcess, 15000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return;
    }

    _wsystem(szCmd);
}

// 執行 SYSTEM 子進程指令，並將隱藏的標準輸出捕捉打印到當前控制台
void ExecuteCommandAsSystemWithVisibleLog(LPCWSTR szCmd) {
    wchar_t tempPath[MAX_PATH] = { 0 };
    GetTempPathW(MAX_PATH, tempPath);

    wchar_t logFile[MAX_PATH] = { 0 };
    swprintf_s(logFile, MAX_PATH, L"%sterminator_out.log", tempPath);
    DeleteFileW(logFile);

    // 使用 CMD /S /C 語法正確包裹帶有引號和重定向的命令
    wchar_t fullCmd[4096] = { 0 };
    swprintf_s(fullCmd, 4096, L"cmd.exe /S /C \"%s > \"%s\" 2>&1\"", szCmd, logFile);

    ExecuteCommandAsSystem(fullCmd);

    HANDLE hFile = CreateFileW(logFile, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD fileSize = GetFileSize(hFile, NULL);
        if (fileSize > 0 && fileSize < 1048576) {
            char* buffer = (char*)malloc(fileSize + 1);
            if (buffer) {
                DWORD readBytes = 0;
                if (ReadFile(hFile, buffer, fileSize, &readBytes, NULL)) {
                    buffer[readBytes] = '\0';
                    printf("%s", buffer);
                }
                free(buffer);
            }
        }
        CloseHandle(hFile);
    }
    DeleteFileW(logFile);
}

// --------------------------------------------------------------------------
// 2. 解除 Winlogon / 全系統進程 Handle 鎖定核心
// --------------------------------------------------------------------------
void UnlockFileWithRestartManager(LPCWSTR szFilePath) {
    wprintf(L"[*] Querying Restart Manager for locked file: %s\n", szFilePath);
    DWORD dwSession = 0;
    WCHAR strSessionKey[CCH_RM_SESSION_KEY] = { 0 };

    if (RmStartSession(&dwSession, 0, strSessionKey) == ERROR_SUCCESS) {
        LPCWSTR files[] = { szFilePath };
        if (RmRegisterResources(dwSession, 1, files, 0, NULL, 0, NULL) == ERROR_SUCCESS) {
            UINT pnProcInfoNeeded = 0;
            UINT pnProcInfo = 0;
            DWORD dwReason = 0;

            RmGetList(dwSession, &pnProcInfoNeeded, &pnProcInfo, NULL, &dwReason);
            if (pnProcInfoNeeded > 0) {
                RM_PROCESS_INFO* pProcInfo = (RM_PROCESS_INFO*)malloc(pnProcInfoNeeded * sizeof(RM_PROCESS_INFO));
                pnProcInfo = pnProcInfoNeeded;
                if (pProcInfo && RmGetList(dwSession, &pnProcInfoNeeded, &pnProcInfo, pProcInfo, &dwReason) == ERROR_SUCCESS) {
                    for (UINT i = 0; i < pnProcInfo; i++) {
                        wprintf(L"[!] RM: File currently held by Process: %s (PID: %lu)\n",
                                pProcInfo[i].strAppName, pProcInfo[i].Process.dwProcessId);
                    }
                }
                if (pProcInfo) free(pProcInfo);
            }
        }
        RmEndSession(dwSession);
    }
}

bool ForceCloseFileHandles(LPCWSTR szTargetFilePath) {
    if (!szTargetFilePath || wcslen(szTargetFilePath) == 0) return false;
    wprintf(L"[*] Force closing system-wide file handles for: %s\n", szTargetFilePath);

    HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtDll) return false;

    pfnNtQuerySystemInformation NtQuerySystemInformation = (pfnNtQuerySystemInformation)GetProcAddress(hNtDll, "NtQuerySystemInformation");
    pfnNtDuplicateObject NtDuplicateObject = (pfnNtDuplicateObject)GetProcAddress(hNtDll, "NtDuplicateObject");

    if (!NtQuerySystemInformation || !NtDuplicateObject) return false;

    ULONG size = 0x10000;
    PSYSTEM_HANDLE_INFORMATION_EX info = (PSYSTEM_HANDLE_INFORMATION_EX)malloc(size);
    if (!info) return false;

    NTSTATUS status;
    while ((status = NtQuerySystemInformation(SystemExtendedHandleInformation, info, size, &size)) == 0xC0000004L) {
        free(info);
        size += 0x10000;
        info = (PSYSTEM_HANDLE_INFORMATION_EX)malloc(size);
        if (!info) return false;
    }

    if (status != 0) {
        free(info);
        return false;
    }

    bool closedAny = false;
    DWORD currentPid = GetCurrentProcessId();

    for (ULONG_PTR i = 0; i < info->NumberOfHandles; i++) {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX entry = info->Handles[i];
        if (entry.UniqueProcessId == currentPid) continue;

        HANDLE hProc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, (DWORD)entry.UniqueProcessId);
        if (!hProc) continue;

        HANDLE hDup = NULL;
        if (NtDuplicateObject(hProc, (HANDLE)entry.HandleValue, GetCurrentProcess(), &hDup, 0, 0, DUPLICATE_SAME_ACCESS) == 0) {
            if (GetFileType(hDup) == FILE_TYPE_DISK) {
                wchar_t handlePath[MAX_PATH] = { 0 };
                if (GetFinalPathNameByHandleW(hDup, handlePath, MAX_PATH, VOLUME_NAME_DOS) > 0) {
                    wchar_t* cleanPath = handlePath;
                    if (wcsncmp(cleanPath, L"\\\\?\\", 4) == 0) cleanPath += 4;

                    if (IsTargetMatch(cleanPath, szTargetFilePath, szTargetFilePath)) {
                        wprintf(L"[!] Closing locked handle in PID %I64u...\n", (unsigned long long)entry.UniqueProcessId);
                        NtDuplicateObject(hProc, (HANDLE)entry.HandleValue, NULL, NULL, 0, 0, DUPLICATE_CLOSE_SOURCE);
                        closedAny = true;
                    }
                }
            }
            CloseHandle(hDup);
        }
        CloseHandle(hProc);
    }

    free(info);
    return closedAny;
}

// --------------------------------------------------------------------------
// 3. 系統關鍵組件劫持修復 & 防護疫苗
// --------------------------------------------------------------------------
void ApplyIFEOBlockVaccine(LPCWSTR szExeName) {
    if (IsCriticalSystemProcess(szExeName)) {
        wprintf(L"[!] SAFETY GUARD: Refusing to apply IFEO vaccine to critical OS component: %s\n", szExeName ? szExeName : L"(null)");
        return;
    }

    wprintf(L"[*] Applying IFEO Block Vaccine for: %s\n", szExeName);
    wchar_t keyPath[512];
    swprintf_s(keyPath, 512, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\%s", szExeName);

    HKEY hKey;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        LPCWSTR blockCmd = L"cmd.exe /c exit";
        RegSetValueExW(hKey, L"Debugger", 0, REG_SZ, (const BYTE*)blockCmd, (wcslen(blockCmd) + 1) * sizeof(wchar_t));
        RegCloseKey(hKey);
        wprintf(L"[+] IFEO Execution Block active for %s.\n", szExeName);
    }
}

void RepairWinlogonHijack() {
    wprintf(L"[*] Auditing Winlogon Critical Keys...\n");
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
        wchar_t userinit[512] = { 0 };
        DWORD size = sizeof(userinit);
        RegQueryValueExW(hKey, L"Userinit", NULL, NULL, (LPBYTE)userinit, &size);
        if (!IsTargetMatch(userinit, L"userinit.exe", NULL) || wcslen(userinit) > 35) {
            wprintf(L"[!] Winlogon Userinit Hijack Detected: %s\n", userinit);
            LPCWSTR cleanUserinit = L"C:\\Windows\\system32\\userinit.exe,";
            RegSetValueExW(hKey, L"Userinit", 0, REG_SZ, (const BYTE*)cleanUserinit, (wcslen(cleanUserinit) + 1) * sizeof(wchar_t));
            wprintf(L"[+] Restored Userinit to default system path.\n");
        }

        wchar_t shell[512] = { 0 };
        size = sizeof(shell);
        RegQueryValueExW(hKey, L"Shell", NULL, NULL, (LPBYTE)shell, &size);
        if (_wcsicmp(shell, L"explorer.exe") != 0) {
            wprintf(L"[!] Winlogon Shell Hijack Detected: %s\n", shell);
            LPCWSTR cleanShell = L"explorer.exe";
            RegSetValueExW(hKey, L"Shell", 0, REG_SZ, (const BYTE*)cleanShell, (wcslen(cleanShell) + 1) * sizeof(wchar_t));
            wprintf(L"[+] Restored Shell to explorer.exe.\n");
        }
        RegCloseKey(hKey);
    }
}

void CleanGlobalDllInjection() {
    wprintf(L"[*] Auditing AppInit_DLLs Injection...\n");
    HKEY hKey;
    LPCWSTR appInitPaths[] = {
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
        L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows"
    };

    for (int i = 0; i < 2; i++) {
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, appInitPaths[i], 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
            DWORD disableVal = 0;
            RegSetValueExW(hKey, L"LoadAppInit_DLLs", 0, REG_DWORD, (const BYTE*)&disableVal, sizeof(DWORD));
            RegSetValueExW(hKey, L"AppInit_DLLs", 0, REG_SZ, (const BYTE*)L"", sizeof(wchar_t));
            RegCloseKey(hKey);
            wprintf(L"[+] Cleared AppInit_DLLs registry entries in: HKLM\\%s\n", appInitPaths[i]);
        }
    }
}

static void ScanAndCleanClsidKey(HKEY hCLSIDKey, LPCWSTR szTargetName, _In_opt_ LPCWSTR szUserSidForLog) {
    DWORD index = 0;
    wchar_t guidName[256];
    DWORD guidLen = 256;

    EXPLICIT_DELETE_INFO deleteQueue[200];
    int deleteCount = 0;

    while (RegEnumKeyExW(hCLSIDKey, index++, guidName, &guidLen, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
        LPCWSTR serverTypes[] = { L"InprocServer32", L"LocalServer32" };
        bool matched = false;
        wchar_t matchedPath[MAX_PATH] = { 0 };

        for (int s = 0; s < 2 && !matched; s++) {
            wchar_t subKeyPath[512];
            swprintf_s(subKeyPath, 512, L"%s\\%s", guidName, serverTypes[s]);

            HKEY hSubKey;
            if (RegOpenKeyExW(hCLSIDKey, subKeyPath, 0, KEY_READ, &hSubKey) == ERROR_SUCCESS) {
                wchar_t binaryPath[MAX_PATH] = { 0 };
                DWORD dataSize = sizeof(binaryPath);
                if (RegQueryValueExW(hSubKey, NULL, NULL, NULL, (LPBYTE)binaryPath, &dataSize) == ERROR_SUCCESS) {
                    if (IsTargetMatch(binaryPath, szTargetName, NULL)) {
                        matched = true;
                        wcscpy_s(matchedPath, MAX_PATH, binaryPath);
                    }
                }
                RegCloseKey(hSubKey);
            }
        }

        if (matched && deleteCount < 200) {
            wcscpy_s(deleteQueue[deleteCount].name, 256, guidName);
            wcscpy_s(deleteQueue[deleteCount].targetPath, MAX_PATH, matchedPath);
            deleteCount++;
        }
        guidLen = 256;
    }

    for (int i = 0; i < deleteCount; i++) {
        if (szUserSidForLog) {
            wprintf(L"[!] Deleted COM Hijack Key:\n    User SID : %s\n    CLSID    : %s\n    DLL Path : %s\n",
                    szUserSidForLog, deleteQueue[i].name, deleteQueue[i].targetPath);
        } else {
            wprintf(L"[!] Deleted HKLM COM Hijack Key:\n    CLSID    : %s\n    DLL Path : %s\n",
                    deleteQueue[i].name, deleteQueue[i].targetPath);
        }
        RegDeleteTreeW(hCLSIDKey, deleteQueue[i].name);
    }
}

void CleanCOMHijack(LPCWSTR szTargetName) {
    wprintf(L"[*] Auditing HKLM & HKU COM CLSID Hijacks...\n");

    HKEY hHKLMClsidKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Classes\\CLSID", 0, KEY_ALL_ACCESS, &hHKLMClsidKey) == ERROR_SUCCESS) {
        ScanAndCleanClsidKey(hHKLMClsidKey, szTargetName, NULL);
        RegCloseKey(hHKLMClsidKey);
    }

    DWORD index = 0;
    wchar_t sidName[256];
    DWORD sidLen = 256;

    while (RegEnumKeyExW(HKEY_USERS, index++, sidName, &sidLen, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
        if (IsValidUserSidKey(sidName)) {
            wchar_t userClsidPath[512];
            swprintf_s(userClsidPath, 512, L"%s\\Software\\Classes\\CLSID", sidName);

            HKEY hUserClsidKey;
            if (RegOpenKeyExW(HKEY_USERS, userClsidPath, 0, KEY_ALL_ACCESS, &hUserClsidKey) == ERROR_SUCCESS) {
                ScanAndCleanClsidKey(hUserClsidKey, szTargetName, sidName);
                RegCloseKey(hUserClsidKey);
            }
        }
        sidLen = 256;
    }
}

void CleanLsaAndSpoolerHijack(LPCWSTR szTargetName) {
    wprintf(L"[*] Auditing Print Monitors Hijack...\n");
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors", 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
        DWORD index = 0;
        wchar_t subKeyName[256];
        DWORD nameLen = 256;
        while (RegEnumKeyExW(hKey, index++, subKeyName, &nameLen, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            HKEY hSubKey;
            if (RegOpenKeyExW(hKey, subKeyName, 0, KEY_READ, &hSubKey) == ERROR_SUCCESS) {
                wchar_t driverPath[MAX_PATH] = { 0 };
                DWORD dSize = sizeof(driverPath);
                RegQueryValueExW(hSubKey, L"Driver", NULL, NULL, (LPBYTE)driverPath, &dSize);
                if (IsTargetMatch(driverPath, szTargetName, NULL)) {
                    RegCloseKey(hSubKey);
                    RegDeleteTreeW(hKey, subKeyName);
                    wprintf(L"[+] Deleted Malicious Print Monitor Key:\n    Monitor Name: %s\n    Driver Path : %s\n", subKeyName, driverPath);
                    break;
                }
                RegCloseKey(hSubKey);
            }
            nameLen = 256;
        }
        RegCloseKey(hKey);
    }
}

void CleanShellExtensionHijack(LPCWSTR szTargetName) {
    wprintf(L"[*] Auditing Explorer Shell Extensions...\n");
    LPCWSTR shellKeyPaths[] = {
        L"*\\shellex\\ContextMenuHandlers",
        L"Directory\\shellex\\ContextMenuHandlers",
        L"Folder\\shellex\\ContextMenuHandlers",
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellIconOverlayIdentifiers"
    };

    for (int i = 0; i < 4; i++) {
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_CLASSES_ROOT, shellKeyPaths[i], 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
            DWORD index = 0;
            wchar_t subKey[256];
            DWORD subKeyLen = 256;

            EXPLICIT_DELETE_INFO deleteQueue[100];
            int deleteCount = 0;

            while (RegEnumKeyExW(hKey, index++, subKey, &subKeyLen, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                bool isMatch = false;
                wchar_t dllPath[MAX_PATH] = { 0 };

                if (IsTargetMatch(subKey, szTargetName, NULL)) {
                    isMatch = true;
                    wcscpy_s(dllPath, MAX_PATH, subKey);
                } else {
                    HKEY hSubKey;
                    if (RegOpenKeyExW(hKey, subKey, 0, KEY_READ, &hSubKey) == ERROR_SUCCESS) {
                        wchar_t clsidVal[256] = { 0 };
                        DWORD valLen = sizeof(clsidVal);
                        if (RegQueryValueExW(hSubKey, NULL, NULL, NULL, (LPBYTE)clsidVal, &valLen) == ERROR_SUCCESS && clsidVal[0] == L'{') {
                            wchar_t clsidRegPath[512];
                            swprintf_s(clsidRegPath, 512, L"CLSID\\%s\\InprocServer32", clsidVal);
                            HKEY hClsidKey;
                            if (RegOpenKeyExW(HKEY_CLASSES_ROOT, clsidRegPath, 0, KEY_READ, &hClsidKey) == ERROR_SUCCESS) {
                                DWORD dllLen = sizeof(dllPath);
                                if (RegQueryValueExW(hClsidKey, NULL, NULL, NULL, (LPBYTE)dllPath, &dllLen) == ERROR_SUCCESS) {
                                    if (IsTargetMatch(dllPath, szTargetName, NULL)) {
                                        isMatch = true;
                                    }
                                }
                                RegCloseKey(hClsidKey);
                            }
                        }
                        RegCloseKey(hSubKey);
                    }
                }

                if (isMatch && deleteCount < 100) {
                    wcscpy_s(deleteQueue[deleteCount].name, 256, subKey);
                    wcscpy_s(deleteQueue[deleteCount].targetPath, MAX_PATH, dllPath);
                    deleteCount++;
                }
                subKeyLen = 256;
            }

            for (int k = 0; k < deleteCount; k++) {
                RegDeleteTreeW(hKey, deleteQueue[k].name);
                wprintf(L"[+] Deleted Shell Extension Hijack:\n    Location: HKCR\\%s\\%s\n    Target  : %s\n",
                        shellKeyPaths[i], deleteQueue[k].name, deleteQueue[k].targetPath);
            }

            RegCloseKey(hKey);
        }
    }
}

void CleanActiveSetup(LPCWSTR szTargetName) {
    wprintf(L"[*] Auditing Active Setup Installed Components...\n");
    HKEY hRoots[] = { HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER };
    LPCWSTR rootNames[] = { L"HKLM", L"HKCU" };

    for (int r = 0; r < 2; r++) {
        HKEY hKey;
        if (RegOpenKeyExW(hRoots[r], L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Active Setup\\Installed Components", 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
            DWORD index = 0;
            wchar_t subKeyName[256];
            DWORD nameLen = 256;
            EXPLICIT_DELETE_INFO deleteQueue[50];
            int deleteCount = 0;

            while (RegEnumKeyExW(hKey, index++, subKeyName, &nameLen, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                HKEY hSubKey;
                if (RegOpenKeyExW(hKey, subKeyName, 0, KEY_READ, &hSubKey) == ERROR_SUCCESS) {
                    wchar_t stubPath[MAX_PATH] = { 0 };
                    DWORD dSize = sizeof(stubPath);
                    if (RegQueryValueExW(hSubKey, L"StubPath", NULL, NULL, (LPBYTE)stubPath, &dSize) == ERROR_SUCCESS) {
                        if (IsTargetMatch(stubPath, szTargetName, NULL)) {
                            if (deleteCount < 50) {
                                wcscpy_s(deleteQueue[deleteCount].name, 256, subKeyName);
                                wcscpy_s(deleteQueue[deleteCount].targetPath, MAX_PATH, stubPath);
                                deleteCount++;
                            }
                        }
                    }
                    RegCloseKey(hSubKey);
                }
                nameLen = 256;
            }

            for (int k = 0; k < deleteCount; k++) {
                RegDeleteTreeW(hKey, deleteQueue[k].name);
                wprintf(L"[+] Deleted Active Setup Hijack Entry:\n    Root    : %s\n    Component: %s\n    StubPath: %s\n",
                        rootNames[r], deleteQueue[k].name, deleteQueue[k].targetPath);
            }
            RegCloseKey(hKey);
        }
    }
}

void CleanUserInitLogonScript(LPCWSTR szTargetName) {
    wprintf(L"[*] Auditing UserInitMprLogonScript Environment Variable...\n");

    DWORD index = 0;
    wchar_t sidName[256];
    DWORD sidLen = 256;

    while (RegEnumKeyExW(HKEY_USERS, index++, sidName, &sidLen, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
        if (IsValidUserSidKey(sidName)) {
            wchar_t envKeyPath[512];
            swprintf_s(envKeyPath, 512, L"%s\\Environment", sidName);

            HKEY hKey;
            if (RegOpenKeyExW(HKEY_USERS, envKeyPath, 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
                wchar_t val[MAX_PATH] = { 0 };
                DWORD valSize = sizeof(val);
                if (RegQueryValueExW(hKey, L"UserInitMprLogonScript", NULL, NULL, (LPBYTE)val, &valSize) == ERROR_SUCCESS) {
                    if (IsTargetMatch(val, szTargetName, NULL)) {
                        RegDeleteValueW(hKey, L"UserInitMprLogonScript");
                        wprintf(L"[+] Removed UserInitMprLogonScript Hijack:\n    User SID    : %s\n    Script Path : %s\n", sidName, val);
                    }
                }
                RegCloseKey(hKey);
            }
        }
        sidLen = 256;
    }
}

void CleanLsaAuthPackages(LPCWSTR szTargetName) {
    wprintf(L"[*] Auditing LSA Authentication Packages...\n");
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa", 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
        wchar_t buf[2048] = { 0 };
        DWORD size = sizeof(buf);
        if (RegQueryValueExW(hKey, L"Authentication Packages", NULL, NULL, (LPBYTE)buf, &size) == ERROR_SUCCESS) {
            if (IsTargetMatch(buf, szTargetName, NULL)) {
                wprintf(L"[!] Found malicious LSA Auth Package entry (%s), resetting to default...\n", szTargetName);
                LPCWSTR defaultLsa = L"msv1_0\0";
                RegSetValueExW(hKey, L"Authentication Packages", 0, REG_MULTI_SZ, (const BYTE*)defaultLsa, 16);
                wprintf(L"[+] Restored LSA Authentication Packages to 'msv1_0'.\n");
            }
        }
        RegCloseKey(hKey);
    }
}

void CleanCredentialProviders(LPCWSTR szTargetName) {
    wprintf(L"[*] Auditing Credential Providers...\n");
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers", 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
        DWORD index = 0;
        wchar_t subKey[256];
        DWORD subKeyLen = 256;
        EXPLICIT_DELETE_INFO deleteQueue[50];
        int deleteCount = 0;

        while (RegEnumKeyExW(hKey, index++, subKey, &subKeyLen, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            HKEY hSubKey;
            if (RegOpenKeyExW(hKey, subKey, 0, KEY_READ, &hSubKey) == ERROR_SUCCESS) {
                wchar_t dllPath[MAX_PATH] = { 0 };
                DWORD dSize = sizeof(dllPath);
                if (RegQueryValueExW(hSubKey, NULL, NULL, NULL, (LPBYTE)dllPath, &dSize) == ERROR_SUCCESS) {
                    if (IsTargetMatch(dllPath, szTargetName, NULL)) {
                        if (deleteCount < 50) {
                            wcscpy_s(deleteQueue[deleteCount].name, 256, subKey);
                            wcscpy_s(deleteQueue[deleteCount].targetPath, MAX_PATH, dllPath);
                            deleteCount++;
                        }
                    }
                }
                RegCloseKey(hSubKey);
            }
            subKeyLen = 256;
        }

        for (int k = 0; k < deleteCount; k++) {
            RegDeleteTreeW(hKey, deleteQueue[k].name);
            wprintf(L"[+] Deleted Malicious Credential Provider:\n    CLSID    : %s\n    DLL Path : %s\n",
                    deleteQueue[k].name, deleteQueue[k].targetPath);
        }
        RegCloseKey(hKey);
    }
}

// --------------------------------------------------------------------------
// 4. 進程控制與遠程 DLL 卸載
// --------------------------------------------------------------------------
bool SuspendProcess(HANDLE hProcess) {
    HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtDll) return false;
    pfnNtSuspendProcess NtSuspendProcess = (pfnNtSuspendProcess)GetProcAddress(hNtDll, "NtSuspendProcess");
    return (NtSuspendProcess && NtSuspendProcess(hProcess) == 0);
}

bool StripCriticalStatus(HANDLE hProcess) {
    HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtDll) return false;
    pfnNtSetInformationProcess NtSetInformationProcess = (pfnNtSetInformationProcess)GetProcAddress(hNtDll, "NtSetInformationProcess");
    if (!NtSetInformationProcess) return false;

    ULONG isCritical = 0;
    return (NtSetInformationProcess(hProcess, 29, &isCritical, sizeof(ULONG)) == 0);
}

bool UnloadRemoteDll(DWORD dwProcessId, LPCWSTR szDllNameOrPath) {
    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD,
        FALSE,
        dwProcessId
    );
    if (!hProcess) return false;

    BOOL isCleanerWow64 = FALSE;
    BOOL isTargetWow64 = FALSE;
    IsWow64Process(GetCurrentProcess(), &isCleanerWow64);
    IsWow64Process(hProcess, &isTargetWow64);

#if defined(_WIN64)
    if (isTargetWow64) {
        CloseHandle(hProcess);
        return false;
    }
#else
    if (!isTargetWow64) {
        CloseHandle(hProcess);
        return false;
    }
#endif

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, dwProcessId);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        CloseHandle(hProcess);
        return false;
    }

    MODULEENTRY32W me = { sizeof(me) };
    bool unloaded = false;

    if (Module32FirstW(hSnapshot, &me)) {
        do {
            if (IsTargetMatch(me.szModule, szDllNameOrPath, szDllNameOrPath) || IsTargetMatch(me.szExePath, szDllNameOrPath, szDllNameOrPath)) {
                wprintf(L"[+] Found injected DLL in PID %lu:\n    DLL Name: %s\n    Full Path: %s\n    Base Addr: 0x%p\n",
                        dwProcessId, me.szModule, me.szExePath, me.hModule);

                LPTHREAD_START_ROUTINE pfnFreeLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "FreeLibrary");
                if (pfnFreeLibrary) {
                    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pfnFreeLibrary, (LPVOID)me.hModule, 0, NULL);
                    if (hThread) {
                        WaitForSingleObject(hThread, 5000);
                        CloseHandle(hThread);
                        wprintf(L"    [+] Successfully executed FreeLibrary remote thread on PID %lu.\n", dwProcessId);
                        unloaded = true;
                    }
                }
            }
        } while (Module32NextW(hSnapshot, &me));
    }

    CloseHandle(hSnapshot);
    CloseHandle(hProcess);
    return unloaded;
}

int ScanTargetProcessTree(LPCWSTR szTargetTarget, TARGET_PROCESS* outList, int maxCapacity, wchar_t* outMainPath) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe = { sizeof(pe) };
    int count = 0;
    DWORD matchedPids[200] = { 0 };
    int matchedPidCount = 0;

    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, szTargetTarget) == 0) {
                if (matchedPidCount < 200) {
                    matchedPids[matchedPidCount++] = pe.th32ProcessID;
                }
            }
        } while (Process32NextW(hSnapshot, &pe));

        if (matchedPidCount > 0 && Process32FirstW(hSnapshot, &pe)) {
            do {
                bool isTreeRelated = false;
                for (int i = 0; i < matchedPidCount; i++) {
                    if (pe.th32ProcessID == matchedPids[i] || pe.th32ParentProcessID == matchedPids[i]) {
                        isTreeRelated = true;
                        break;
                    }
                }

                if (isTreeRelated && count < maxCapacity) {
                    HANDLE hProc = OpenProcess(
                        PROCESS_TERMINATE | PROCESS_SUSPEND_RESUME | PROCESS_SET_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION,
                        FALSE,
                        pe.th32ProcessID
                    );
                    if (hProc) {
                        outList[count].pid = pe.th32ProcessID;
                        wcscpy_s(outList[count].exeName, MAX_PATH, pe.szExeFile);
                        outList[count].hProcess = hProc;

                        DWORD pathSize = MAX_PATH;
                        if (QueryFullProcessImageNameW(hProc, 0, outList[count].fullPath, &pathSize)) {
                            if (outMainPath && wcslen(outMainPath) == 0 && _wcsicmp(pe.szExeFile, szTargetTarget) == 0) {
                                wcscpy_s(outMainPath, MAX_PATH, outList[count].fullPath);
                            }
                        }
                        count++;
                    }
                }
            } while (Process32NextW(hSnapshot, &pe));
        }
    }

    CloseHandle(hSnapshot);
    return count;
}

// --------------------------------------------------------------------------
// 5. 檔案解鎖、NTFS 數據流、疫苗與截斷
// --------------------------------------------------------------------------
void CleanNTFSStreams(LPCWSTR szHostFilePath) {
    if (!szHostFilePath || wcslen(szHostFilePath) == 0) return;
    wprintf(L"[*] Scanning NTFS Alternate Data Streams (ADS) for: %s\n", szHostFilePath);
    WIN32_FIND_STREAM_DATA findStreamData;
    HANDLE hFind = FindFirstStreamW(szHostFilePath, FindStreamInfoStandard, &findStreamData, 0);

    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (_wcsicmp(findStreamData.cStreamName, L"::$DATA") != 0) {
                wchar_t fullStreamPath[MAX_PATH * 2];
                swprintf_s(fullStreamPath, MAX_PATH * 2, L"%s%s", szHostFilePath, findStreamData.cStreamName);
                wprintf(L"[!] Found Hidden ADS Stream: %s\n", fullStreamPath);

                HANDLE hStream = CreateFileW(fullStreamPath, GENERIC_WRITE, 0, NULL, TRUNCATE_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
                if (hStream != INVALID_HANDLE_VALUE) CloseHandle(hStream);
                DeleteFileW(fullStreamPath);
                wprintf(L"[+] Deleted ADS Stream: %s\n", fullStreamPath);
            }
        } while (FindNextStreamW(hFind, &findStreamData));
        FindClose(hFind);
    }
}

bool VaccinateAndTruncateFile(LPCWSTR szFilePath) {
    if (!szFilePath || wcslen(szFilePath) == 0) return false;
    wprintf(L"[*] Target File Operation: %s\n", szFilePath);

    UnlockFileWithRestartManager(szFilePath);
    ForceCloseFileHandles(szFilePath);
    CleanNTFSStreams(szFilePath);
    SetFileAttributesW(szFilePath, FILE_ATTRIBUTE_NORMAL);

    HANDLE hFile = CreateFileW(szFilePath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               NULL, TRUNCATE_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        wprintf(L"[+] Truncated target binary to 0 bytes: %s\n", szFilePath);
        CloseHandle(hFile);
    } else {
        wprintf(L"[!] File truncation failed (Err: %lu). Retrying zero-fill overwrite...\n", GetLastError());
        HANDLE hFileWrite = CreateFileW(szFilePath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFileWrite != INVALID_HANDLE_VALUE) {
            DWORD written = 0;
            BYTE dummy[512] = { 0 };
            WriteFile(hFileWrite, dummy, 512, &written, NULL);
            SetEndOfFile(hFileWrite);
            CloseHandle(hFileWrite);
            wprintf(L"[+] Overwritten and truncated binary to zero bytes.\n");
        }
    }

    if (DeleteFileW(szFilePath)) {
        wprintf(L"[+] Binary file successfully DELETED from disk: %s\n", szFilePath);
        return true;
    }

    wprintf(L"[!] Direct file deletion failed. Scheduled MoveFileEx reboot deletion & applying execution DENY ACL...\n");
    MoveFileExW(szFilePath, NULL, MOVEFILE_DELAY_UNTIL_REBOOT);

    PSID pEveryoneSid = NULL;
    SID_IDENTIFIER_AUTHORITY WorldAuth = SECURITY_WORLD_SID_AUTHORITY;
    if (AllocateAndInitializeSid(&WorldAuth, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &pEveryoneSid)) {
        EXPLICIT_ACCESSW ea;
        ZeroMemory(&ea, sizeof(EXPLICIT_ACCESSW));
        ea.grfAccessPermissions = FILE_EXECUTE | FILE_TRAVERSE;
        ea.grfAccessMode = DENY_ACCESS;
        ea.grfInheritance = NO_INHERITANCE;
        ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
        ea.Trustee.ptstrName = (LPWSTR)pEveryoneSid;

        PACL pNewDacl = NULL;
        if (SetEntriesInAclW(1, &ea, NULL, &pNewDacl) == ERROR_SUCCESS) {
            SetNamedSecurityInfoW((LPWSTR)szFilePath, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, pNewDacl, NULL);
            wprintf(L"[+] Applied DENY_EXECUTE ACL vaccine on path: %s\n", szFilePath);
        }
        if (pNewDacl) LocalFree(pNewDacl);
        FreeSid(pEveryoneSid);
    }

    return false;
}

// --------------------------------------------------------------------------
// 6. 全方位持久化清理
// --------------------------------------------------------------------------
void CleanServices(LPCWSTR szTargetPath, LPCWSTR szTargetName) {
    wprintf(L"[*] Scanning Services & ServiceDLLs...\n");
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) return;

    DWORD bytesNeeded = 0, servicesReturned = 0, resumeHandle = 0;
    EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, NULL, 0, &bytesNeeded, &servicesReturned, &resumeHandle, NULL);
    if (bytesNeeded == 0) { CloseServiceHandle(hSCM); return; }

    bytesNeeded += 4096;
    BYTE* buffer = (BYTE*)malloc(bytesNeeded);
    if (buffer && EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, buffer, bytesNeeded, &bytesNeeded, &servicesReturned, &resumeHandle, NULL)) {
        ENUM_SERVICE_STATUS_PROCESSW* services = (ENUM_SERVICE_STATUS_PROCESSW*)buffer;
        for (DWORD i = 0; i < servicesReturned; i++) {
            SC_HANDLE hService = OpenServiceW(hSCM, services[i].lpServiceName, SERVICE_QUERY_CONFIG | SERVICE_STOP | DELETE);
            if (hService) {
                DWORD cfgNeeded = 0;
                QueryServiceConfigW(hService, NULL, 0, &cfgNeeded);
                if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                    QUERY_SERVICE_CONFIGW* pCfg = (QUERY_SERVICE_CONFIGW*)malloc(cfgNeeded);
                    if (pCfg && QueryServiceConfigW(hService, pCfg, cfgNeeded, &cfgNeeded)) {
                        bool isMatch = false;
                        wchar_t matchedBinPath[MAX_PATH] = { 0 };

                        if (pCfg->lpBinaryPathName) {
                            if (IsTargetMatch(pCfg->lpBinaryPathName, szTargetName, szTargetPath)) {
                                isMatch = true;
                                wcscpy_s(matchedBinPath, MAX_PATH, pCfg->lpBinaryPathName);
                            }
                        }

                        if (!isMatch) {
                            wchar_t svcParamPath[512];
                            swprintf_s(svcParamPath, 512, L"SYSTEM\\CurrentControlSet\\Services\\%s\\Parameters", services[i].lpServiceName);
                            HKEY hSvcKey;
                            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, svcParamPath, 0, KEY_READ, &hSvcKey) == ERROR_SUCCESS) {
                                wchar_t serviceDll[MAX_PATH] = { 0 };
                                DWORD sSize = sizeof(serviceDll);
                                if (RegQueryValueExW(hSvcKey, L"ServiceDll", NULL, NULL, (LPBYTE)serviceDll, &sSize) == ERROR_SUCCESS) {
                                    if (IsTargetMatch(serviceDll, szTargetName, szTargetPath)) {
                                        isMatch = true;
                                        wcscpy_s(matchedBinPath, MAX_PATH, serviceDll);
                                    }
                                }
                                RegCloseKey(hSvcKey);
                            }
                        }

                        if (isMatch) {
                            wprintf(L"[+] Found Malicious Service:\n    Service Name: '%s'\n    Binary Path : '%s'\n",
                                    services[i].lpServiceName, matchedBinPath);
                            SERVICE_STATUS status;
                            ControlService(hService, SERVICE_CONTROL_STOP, &status);
                            if (DeleteService(hService)) {
                                wprintf(L"    [+] Service successfully DELETED.\n");
                            } else {
                                wprintf(L"    [!] Failed to delete service (Err: %lu).\n", GetLastError());
                            }
                        }
                    }
                    if (pCfg) free(pCfg);
                }
                CloseServiceHandle(hService);
            }
        }
    }
    if (buffer) free(buffer);
    CloseServiceHandle(hSCM);
}

void CleanTasks(LPCWSTR szTargetPath, LPCWSTR szTargetExe) {
    wprintf(L"[*] Scanning Scheduled Tasks for matching execution paths...\n");

    wchar_t rawSearchTerm[MAX_PATH] = { 0 };
    if (szTargetExe && wcslen(szTargetExe) > 0) {
        wcscpy_s(rawSearchTerm, MAX_PATH, szTargetExe);
    } else if (szTargetPath && wcslen(szTargetPath) > 0) {
        wcscpy_s(rawSearchTerm, MAX_PATH, szTargetPath);
    }

    if (wcslen(rawSearchTerm) == 0) {
        wprintf(L"[-] No valid search term for scheduled task scan.\n");
        return;
    }

    wchar_t escapedTerm[MAX_PATH * 2] = { 0 };
    int j = 0;
    for (int i = 0; rawSearchTerm[i] != L'\0' && j < (MAX_PATH * 2 - 2); i++) {
        if (rawSearchTerm[i] == L'\'') {
            escapedTerm[j++] = L'\'';
            escapedTerm[j++] = L'\'';
        } else if (rawSearchTerm[i] == L'\"') {
            continue;
        } else {
            escapedTerm[j++] = rawSearchTerm[i];
        }
    }
    escapedTerm[j] = L'\0';

    wchar_t psCommand[2048] = { 0 };
    swprintf_s(psCommand, 2048,
        L"powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "
        L"Get-ScheduledTask ^| Where-Object { $_.Actions ^| Where-Object { $_.Execute -like '*%s*' -or $_.Arguments -like '*%s*' } } ^| ForEach-Object { Write-Host '[+] Deleted Scheduled Task:' $_.TaskName; Unregister-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath -Confirm:$false }",
        rawSearchTerm, rawSearchTerm);

    // 通過日誌重定向將隱藏的 PowerShell 刪除歷史直接列印到主控制台
    ExecuteCommandAsSystemWithVisibleLog(psCommand);
}

void CleanRegistry(LPCWSTR szTargetPath, LPCWSTR szTargetName) {
    wprintf(L"[*] Scanning Registry Auto-Start & IFEO Keys...\n");

    LPCWSTR hklmKeys[] = {
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"
    };

    for (int k = 0; k < 4; k++) {
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, hklmKeys[k], 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
            DWORD index = 0, nameLen = 16384, dataLen = 16384, type = 0;
            wchar_t valName[16384];
            BYTE valData[16384];
            EXPLICIT_DELETE_INFO deleteQueue[100];
            int deleteCount = 0;

            while (RegEnumValueW(hKey, index++, valName, &nameLen, NULL, &type, valData, &dataLen) == ERROR_SUCCESS) {
                if (dataLen < sizeof(valData)) { valData[dataLen] = 0; valData[dataLen + 1] = 0; }
                wchar_t* pData = (wchar_t*)valData;
                if ((type == REG_SZ || type == REG_EXPAND_SZ) && deleteCount < 100) {
                    if (IsTargetMatch(pData, szTargetName, szTargetPath) || IsTargetMatch(valName, szTargetName, NULL)) {
                        wcscpy_s(deleteQueue[deleteCount].name, 256, valName);
                        wcscpy_s(deleteQueue[deleteCount].targetPath, MAX_PATH, pData);
                        deleteCount++;
                    }
                }
                nameLen = 16384; dataLen = 16384;
            }

            for (int i = 0; i < deleteCount; i++) {
                wprintf(L"[+] Deleted HKLM Registry Auto-Start Value:\n");
                wprintf(L"    Reg Key    : HKLM\\%s\n", hklmKeys[k]);
                wprintf(L"    Value Name : %s\n", deleteQueue[i].name);
                wprintf(L"    Target Path: %s\n", deleteQueue[i].targetPath);
                RegDeleteValueW(hKey, deleteQueue[i].name);
            }
            RegCloseKey(hKey);
        }
    }

    LPCWSTR hkcuSubPaths[] = {
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
    };

    DWORD enumIndex = 0;
    wchar_t sidName[256];
    DWORD sidLen = 256;

    while (RegEnumKeyExW(HKEY_USERS, enumIndex++, sidName, &sidLen, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
        if (IsValidUserSidKey(sidName)) {
            for (int k = 0; k < 2; k++) {
                wchar_t userRunPath[512];
                swprintf_s(userRunPath, 512, L"%s\\%s", sidName, hkcuSubPaths[k]);

                HKEY hKey;
                if (RegOpenKeyExW(HKEY_USERS, userRunPath, 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
                    DWORD valIndex = 0, nameLen = 16384, dataLen = 16384, type = 0;
                    wchar_t valName[16384];
                    BYTE valData[16384];
                    EXPLICIT_DELETE_INFO deleteQueue[100];
                    int deleteCount = 0;

                    while (RegEnumValueW(hKey, valIndex++, valName, &nameLen, NULL, &type, valData, &dataLen) == ERROR_SUCCESS) {
                        if (dataLen < sizeof(valData)) { valData[dataLen] = 0; valData[dataLen + 1] = 0; }
                        wchar_t* pData = (wchar_t*)valData;
                        if ((type == REG_SZ || type == REG_EXPAND_SZ) && deleteCount < 100) {
                            if (IsTargetMatch(pData, szTargetName, szTargetPath) || IsTargetMatch(valName, szTargetName, NULL)) {
                                wcscpy_s(deleteQueue[deleteCount].name, 256, valName);
                                wcscpy_s(deleteQueue[deleteCount].targetPath, MAX_PATH, pData);
                                deleteCount++;
                            }
                        }
                        nameLen = 16384; dataLen = 16384;
                    }

                    for (int i = 0; i < deleteCount; i++) {
                        wprintf(L"[+] Deleted User Registry Auto-Start Value:\n");
                        wprintf(L"    User SID   : %s\n", sidName);
                        wprintf(L"    Reg Key    : HKU\\%s\\%s\n", sidName, hkcuSubPaths[k]);
                        wprintf(L"    Value Name : %s\n", deleteQueue[i].name);
                        wprintf(L"    Target Path: %s\n", deleteQueue[i].targetPath);
                        RegDeleteValueW(hKey, deleteQueue[i].name);
                    }
                    RegCloseKey(hKey);
                }
            }
        }
        sidLen = 256;
    }
}

void CleanWMIPersistence(LPCWSTR szTargetPath, LPCWSTR szTargetName) {
    wprintf(L"[*] Scanning WMI Event Subscriptions...\n");
    LPCWSTR term = (szTargetName && wcslen(szTargetName) > 0) ? szTargetName : szTargetPath;
    if (!term || wcslen(term) == 0) return;

    wchar_t psCmd[2048];
    swprintf_s(psCmd, 2048,
            L"powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "
            L"\"Get-WmiObject -Namespace root\\subscription -Class __EventConsumer ^| Where-Object { $_.CommandLine -like '*%s*' -or $_.ScriptText -like '*%s*' } ^| ForEach-Object { $n = $_.Name; Get-WmiObject -Namespace root\\subscription -Class __FilterToConsumerBinding ^| Where-Object { $_.Consumer -like ('*' + $n + '*') } ^| Remove-WmiObject; Get-WmiObject -Namespace root\\subscription -Class __EventFilter ^| Where-Object { $_.Name -eq $n } ^| Remove-WmiObject; $_ ^| Remove-WmiObject; Write-Host '[+] Deleted WMI Persistence:' $n }\"",
            term, term);

    ExecuteCommandAsSystemWithVisibleLog(psCmd);
}

static bool IsShortcutTargetMatch(LPCWSTR szLnkPath, LPCWSTR szTargetName) {
    bool match = false;
    HRESULT hr = CoInitialize(NULL);
    IShellLinkW* psl = NULL;

    if (SUCCEEDED(CoCreateInstance(&CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, &IID_IShellLinkW, (LPVOID*)&psl))) {
        IPersistFile* ppf = NULL;
        if (SUCCEEDED(psl->lpVtbl->QueryInterface(psl, &IID_IPersistFile, (LPVOID*)&ppf))) {
            if (SUCCEEDED(ppf->lpVtbl->Load(ppf, szLnkPath, STGM_READ))) {
                wchar_t targetPath[MAX_PATH] = { 0 };
                if (SUCCEEDED(psl->lpVtbl->GetPath(psl, targetPath, MAX_PATH, NULL, SLGP_UNCPRIORITY))) {
                    if (IsTargetMatch(targetPath, szTargetName, NULL)) {
                        match = true;
                    }
                }
            }
            ppf->lpVtbl->Release(ppf);
        }
        psl->lpVtbl->Release(psl);
    }
    if (SUCCEEDED(hr)) CoUninitialize();
    return match;
}

void CleanStartupFolderAndLnk(LPCWSTR szTargetName) {
    wprintf(L"[*] Scanning Startup Folders & LNK Shortcuts...\n");

    LPCWSTR envPaths[] = {
        L"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
        L"%PROGRAMDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
    };

    for (int i = 0; i < 2; i++) {
        wchar_t startupPath[MAX_PATH];
        if (ExpandEnvironmentStringsW(envPaths[i], startupPath, MAX_PATH) == 0) continue;

        wchar_t searchPattern[MAX_PATH];
        swprintf_s(searchPattern, MAX_PATH, L"%s\\*", startupPath);

        WIN32_FIND_DATAW ffd;
        HANDLE hFind = FindFirstFileW(searchPattern, &ffd);
        if (hFind == INVALID_HANDLE_VALUE) continue;

        do {
            if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;

            wchar_t fullPath[MAX_PATH];
            swprintf_s(fullPath, MAX_PATH, L"%s\\%s", startupPath, ffd.cFileName);
            bool shouldDelete = false;

            if (IsTargetMatch(ffd.cFileName, szTargetName, NULL)) {
                shouldDelete = true;
            } else {
                size_t len = wcslen(ffd.cFileName);
                if (len > 4 && _wcsicmp(ffd.cFileName + len - 4, L".lnk") == 0) {
                    wchar_t baseName[MAX_PATH] = { 0 };
                    wcsncpy_s(baseName, MAX_PATH, ffd.cFileName, len - 4);

                    if (IsTargetMatch(baseName, szTargetName, NULL)) {
                        shouldDelete = true;
                    } else if (IsShortcutTargetMatch(fullPath, szTargetName)) {
                        shouldDelete = true;
                    }
                }
            }

            if (shouldDelete) {
                if (DeleteFileW(fullPath)) {
                    wprintf(L"[+] Deleted Startup Item / Shortcut:\n    Path: %s\n", fullPath);
                } else {
                    wprintf(L"[!] Failed to delete Startup Item (Err: %lu):\n    Path: %s\n", GetLastError(), fullPath);
                }
            }
        } while (FindNextFileW(hFind, &ffd));

        FindClose(hFind);
    }
}

// --------------------------------------------------------------------------
// 7. 主控工作流程
// --------------------------------------------------------------------------
int wmain(int argc, wchar_t* argv[]) {
    wprintf(L"====================================================================\n");
    wprintf(L"       JASON ULTIMATE MALWARE TERMINATOR & CLEANER (v6.2 - LOGGED)  \n");
    wprintf(L"====================================================================\n\n");

    if (argc < 3) {
        wprintf(L"Usage:\n");
        wprintf(L"  Kill EXE Process Tree : %s --kill-exe <malware.exe>\n", argv[0]);
        wprintf(L"  Unload Injected DLL   : %s --kill-dll <malware.dll>\n", argv[0]);
        return 1;
    }

    LPCWSTR mode = argv[1];
    LPCWSTR targetName = argv[2];
    wchar_t mainBinaryPath[MAX_PATH] = { 0 };

    wprintf(L"[PHASE 0] ELEVATING SECURITY CONTEXT\n");
    wprintf(L"--------------------------------------------------------------------\n");
    if (EnableAllPrivileges()) {
        wprintf(L"[+] Successfully acquired SeDebugPrivilege & SeTakeOwnershipPrivilege.\n");
    }
    ImpersonateSystemToken();

    wprintf(L"\n[PHASE 1] APPLYING VACCINE & REPAIRING SYSTEM COMPONENT HIJACKS\n");
    wprintf(L"--------------------------------------------------------------------\n");
    ApplyIFEOBlockVaccine(targetName);
    RepairWinlogonHijack();
    CleanGlobalDllInjection();
    CleanCOMHijack(targetName);
    CleanLsaAndSpoolerHijack(targetName);
    CleanShellExtensionHijack(targetName);
    CleanActiveSetup(targetName);
    CleanUserInitLogonScript(targetName);
    CleanLsaAuthPackages(targetName);
    CleanCredentialProviders(targetName);

    if (_wcsicmp(mode, L"--kill-dll") == 0) {
        wprintf(L"\n[PHASE 2] UNLOADING INJECTED DLL FROM ALL PROCESSES\n");
        wprintf(L"--------------------------------------------------------------------\n");
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe = { sizeof(pe) };
            if (Process32FirstW(hSnap, &pe)) {
                do {
                    UnloadRemoteDll(pe.th32ProcessID, targetName);
                } while (Process32NextW(hSnap, &pe));
            }
            CloseHandle(hSnap);
        }

        wprintf(L"\n[PHASE 3] DISK VACCINATION & TRUNCATION\n");
        wprintf(L"--------------------------------------------------------------------\n");
        VaccinateAndTruncateFile(targetName);
    }
    else {
        TARGET_PROCESS procList[100];
        int procCount = ScanTargetProcessTree(targetName, procList, 100, mainBinaryPath);

        wprintf(L"\n[PHASE 2] FREEZING ALL TREE PROCESSES (NtSuspendProcess)\n");
        wprintf(L"--------------------------------------------------------------------\n");
        if (procCount == 0) {
            wprintf(L"[*] No active processes found matching '%s'.\n", targetName);
        } else {
            for (int i = 0; i < procCount; i++) {
                if (SuspendProcess(procList[i].hProcess)) {
                    wprintf(L"[+] FROZEN Process '%s' [PID: %lu] (Path: %s)\n",
                            procList[i].exeName, procList[i].pid, procList[i].fullPath);
                }
            }
        }

        wprintf(L"\n[PHASE 3] STRIPPING CRITICAL FLAGS & TERMINATING PROCESSES\n");
        wprintf(L"--------------------------------------------------------------------\n");
        for (int i = 0; i < procCount; i++) {
            StripCriticalStatus(procList[i].hProcess);
            if (TerminateProcess(procList[i].hProcess, 0)) {
                wprintf(L"[+] Process '%s' [PID: %lu] terminated cleanly.\n", procList[i].exeName, procList[i].pid);
            }
            CloseHandle(procList[i].hProcess);
        }

        wprintf(L"\n[PHASE 4] FORCE CLOSING SYSTEM HANDLES, DISK VACCINATION & TRUNCATION\n");
        wprintf(L"--------------------------------------------------------------------\n");
        if (wcslen(mainBinaryPath) > 0) {
            VaccinateAndTruncateFile(mainBinaryPath);
        } else {
            VaccinateAndTruncateFile(targetName);
        }
    }

    wprintf(L"\n[PHASE 5] FULL SYSTEM PERSISTENCE CLEANUP\n");
    wprintf(L"--------------------------------------------------------------------\n");
    LPCWSTR pathPtr = (wcslen(mainBinaryPath) > 0) ? mainBinaryPath : NULL;
    CleanServices(pathPtr, targetName);
    CleanTasks(pathPtr, targetName);
    CleanRegistry(pathPtr, targetName);
    CleanWMIPersistence(pathPtr, targetName);
    CleanStartupFolderAndLnk(targetName);

    if (g_hSystemPrimaryToken) {
        CloseHandle(g_hSystemPrimaryToken);
    }

    wprintf(L"\n====================================================================\n");
    wprintf(L"[+] ALL TERMINATION AND CLEANUP WORKFLOWS COMPLETED.\n");
    wprintf(L"====================================================================\n");

    return 0;
}