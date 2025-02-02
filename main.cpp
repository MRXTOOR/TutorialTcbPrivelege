#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <ntsecapi.h>
BOOL CheckPrivilege(
    HANDLE hToken,          
    LPCTSTR lpszPrivilege   
) {
    PRIVILEGE_SET privs;
    LUID luid;
    BOOL bResult = FALSE;

    if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid)) {
        printf("LookupPrivilegeValue error: %u\n", GetLastError());
        return FALSE;
    }

    privs.PrivilegeCount = 1;
    privs.Control = PRIVILEGE_SET_ALL_NECESSARY;
    privs.Privilege[0].Luid = luid;
    privs.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!PrivilegeCheck(hToken, &privs, &bResult)) {
        printf("PrivilegeCheck error: %u\n", GetLastError());
        return FALSE;
    }

    return bResult;
}

BOOL SetPrivilege(
    HANDLE hToken,          
    LPCTSTR lpszPrivilege,  
    BOOL bEnablePrivilege  
) {
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValue(
        NULL,            
        lpszPrivilege,   
        &luid)) {       
        printf("LookupPrivilegeValue error: %u\n", GetLastError());
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = (bEnablePrivilege) ? SE_PRIVILEGE_ENABLED : 0;

   
    if (!AdjustTokenPrivileges(
        hToken,
        FALSE,
        &tp,
        sizeof(TOKEN_PRIVILEGES),
        (PTOKEN_PRIVILEGES)NULL,
        (PDWORD)NULL)) {
        printf("AdjustTokenPrivileges error: %u\n", GetLastError());
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        printf("The token does not have the specified privilege. \n");
        return FALSE;
    }

    return TRUE;
}

HANDLE GetSystemProcessToken() {
    HANDLE hToken = NULL;
    HANDLE hProcess = NULL;
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("CreateToolhelp32Snapshot error: %u\n", GetLastError());
        return NULL;
    }

    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, L"winlogon.exe") == 0) {
                hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);
                if (hProcess) {
                    if (OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
                        CloseHandle(hProcess);
                        break;
                    }
                    CloseHandle(hProcess);
                }
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return hToken;
}

int main() {
    HANDLE hToken;

    hToken = GetSystemProcessToken();
    if (hToken == NULL) {
        printf("Failed to get system process token.\n");
        return 1;
    }

    if (!ImpersonateLoggedOnUser(hToken)) {
        printf("ImpersonateLoggedOnUser error: %u\n", GetLastError());
        CloseHandle(hToken);
        return 1;
    }

    if (CheckPrivilege(hToken, SE_TCB_NAME)) {
        printf("SeTcbPrivilege is already enabled.\n");
    }
    else {
        if (SetPrivilege(hToken, SE_TCB_NAME, TRUE)) {
            printf("SeTcbPrivilege is now enabled.\n");
        }
        else {
            printf("Failed to enable SeTcbPrivilege.\n");
        }
    }
    
    RevertToSelf();
    CloseHandle(hToken);
    system("pause");
    return 0;
}