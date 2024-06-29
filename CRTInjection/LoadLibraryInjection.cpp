#include <iostream>
#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>

using namespace std;

// sets up our ioctls
#define HXD_DISABLE_CALLBACKS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define HXD_ENABLE_CALLBACKS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS)

// stores old callback values
typedef struct _CALLBACK_OPERATIONS
{
	DWORD64 PreOperation;
	DWORD64 PostOperation;
} CALLBACK_OPERATIONS, *PCALLBACK_OPERATIONS;

// returns a valid process handle
HANDLE GetProcessHandle(DWORD ProcessId)
{
	// opens the driver
	HANDLE driver = CreateFile("\\\\.\\HxDriver", NULL, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	// validates the handle
	if (driver != INVALID_HANDLE_VALUE)
	{
		// stores our returned bytes
		DWORD returnedBytes = 0;
		// stores our output
		CALLBACK_OPERATIONS buffer;
		// sends command to the driver to disable callbacks
		if (DeviceIoControl(driver, HXD_DISABLE_CALLBACKS, &buffer, sizeof(CALLBACK_OPERATIONS), &buffer, sizeof(CALLBACK_OPERATIONS), &returnedBytes, NULL) != NULL)
		{
			// grabs a handle to the process
			HANDLE ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, false, ProcessId);
			// sends command to the driver to enable callbacks
			if (DeviceIoControl(driver, HXD_ENABLE_CALLBACKS, &buffer, sizeof(CALLBACK_OPERATIONS), &buffer, sizeof(CALLBACK_OPERATIONS), &returnedBytes, NULL) != NULL)
			{
				// returns the process handle
				return ProcessHandle;
			}
		}
	}
	// else we return null
	return NULL;
}

// returns a valid thread handle
HANDLE GetThreadHandle(DWORD ThreadId)
{
	// opens the driver
	HANDLE driver = CreateFile("\\\\.\\HxDriver", NULL, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	// validates the handle
	if (driver != INVALID_HANDLE_VALUE)
	{
		// stores our returned bytes
		DWORD returnedBytes = 0;
		// stores our output
		CALLBACK_OPERATIONS buffer;
		// sends command to the driver to disable callbacks
		if (DeviceIoControl(driver, HXD_DISABLE_CALLBACKS, &buffer, sizeof(CALLBACK_OPERATIONS), &buffer, sizeof(CALLBACK_OPERATIONS), &returnedBytes, NULL) != NULL)
		{
			// grabs a handle to the thread
			HANDLE ThreadHandle = OpenThread(THREAD_ALL_ACCESS, false, ThreadId);
			// sends command to the driver to enable callbacks
			if (DeviceIoControl(driver, HXD_ENABLE_CALLBACKS, &buffer, sizeof(CALLBACK_OPERATIONS), &buffer, sizeof(CALLBACK_OPERATIONS), &returnedBytes, NULL) != NULL)
			{
				// returns the game handle
				return ThreadHandle;
			}
		}
	}
	// else we return null
	return NULL;
}

// returns the process id of the game
DWORD GetProcessPid(string processName)
{
	// stores information about our process
	PROCESSENTRY32 procInfo;
	// initalizes our procInfo structure
	procInfo.dwSize = sizeof(PROCESSENTRY32);
	// takes a snapshot of all current system processes
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	// checks the handle
	if (snapshot != INVALID_HANDLE_VALUE)
		// iterates through all processes
		while (Process32Next(snapshot, &procInfo))
			// checks the process executable name
			if (!processName.compare(procInfo.szExeFile))
				// returns the process id
				return procInfo.th32ProcessID;
	// else we return null
	return NULL;
}

// returns an arbitrary thread id of the process
DWORD GetProcessThread(DWORD ProcessId)
{
	// stores information about our thread
	THREADENTRY32 threadInfo;
	// initalizes our threadInfo structure
	threadInfo.dwSize = sizeof(THREADENTRY32);
	// takes a snapshot of all current system threads
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
	// checks the handle
	if (snapshot != INVALID_HANDLE_VALUE)
		// iterates through all threads
		while (Thread32Next(snapshot, &threadInfo))
			// checks the process id
			if (threadInfo.th32OwnerProcessID == ProcessId)
				// returns the thread id
				return threadInfo.th32ThreadID;
	// else we return null
	return NULL;
}

// hijacks a thread within the process
BOOLEAN HijackThread(HANDLE ProcessHandle, HANDLE ThreadHandle, PVOID LoadLibraryAddress, PVOID DllPathAddress)
{
	// stores the shell code
	byte ShellCode[] = { 0x48, 0xB8, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
		0x50, 0x53, 0x51, 0x52, 0x57, 0x56, 0x54, 0x55, 0x41, 0x50,
		0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x41, 0x54, 0x41, 0x55,
		0x41, 0x56, 0x41, 0x57, 0x48, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
		0xBB, 0xBB, 0xBB, 0xBB, 0x48, 0xB9, 0xCC, 0xCC, 0xCC, 0xCC,
		0xCC, 0xCC, 0xCC, 0xCC, 0x83, 0xEC, 0x08, 0xFF, 0xD3, 0x83,
		0xC4, 0x08, 0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C,
		0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5D, 0x5C,
		0x5E, 0x5F, 0x5A, 0x59, 0x5B, 0xC3 };
	// allocates executable memory for the shellcode
	LPVOID ShellCodeAddress = VirtualAllocEx(ProcessHandle, NULL, sizeof(ShellCode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	// validates address
	if (ShellCodeAddress)
	{
		// suspends the thread
		if (SuspendThread(ThreadHandle) != -1)
		{
			// notifies user
			// cout << "Suspended thread: 0x" << hex << ThreadHandle << endl;
			// stores our thread context
			CONTEXT ctx;
			// we want the full context
			ctx.ContextFlags = CONTEXT_FULL;
			// gets the thread context
			if (GetThreadContext(ThreadHandle, &ctx))
			{
				// writes the old eip to the shell code
				*(DWORD64*)&ShellCode[2] = (DWORD64)ctx.Rip;
				// writes the address of load library
				*(DWORD64*)&ShellCode[36] = (DWORD64)LoadLibraryAddress;
				// writes the addrs of the dll string
				*(DWORD64*)&ShellCode[46] = (DWORD64)DllPathAddress;
				// writes shellcode to the buffer
				if (WriteProcessMemory(ProcessHandle, ShellCodeAddress, ShellCode, sizeof(ShellCode), NULL))
				{
					// notifies user
					// cout << "Shell code written to: 0x" << hex << ShellCodeAddress << endl;
					// sets the instruction pointer to point to the shell code
					ctx.Rip = (DWORD64)ShellCodeAddress;
					// applies the thread context
					if (SetThreadContext(ThreadHandle, &ctx))
					{
						// resumes the thread
						if (ResumeThread(ThreadHandle) != -1)
						{
							// notifies user
							// cout << "Resumed thread: 0x" << hex << ThreadHandle << endl;
							// returns true
							return TRUE;
						}
					}
				}
			}
		}
	}
	// returns false
	return FALSE;
}

// injects a dll into the given process
BOOLEAN InjectDll(HANDLE ProcessHandle, HANDLE ThreadHandle, LPCSTR DllPath)
{
	// allocates memory for the dll path in the target process
	LPVOID DllPathAddress = VirtualAllocEx(ProcessHandle, 0, strlen(DllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
	// validates the address
	if (DllPathAddress)
	{
		// writes the path to the process
		if (WriteProcessMemory(ProcessHandle, DllPathAddress, (LPVOID)DllPath, strlen(DllPath) + 1, 0))
		{
			// notifies user
			// cout << "Dll path written to: 0x" << hex << DllPathAddress << endl;
			// creates a thread that calls load library with our dll path
			if (HijackThread(ProcessHandle, ThreadHandle, GetProcAddress(GetModuleHandleA("Kernel32.dll"), "LoadLibraryA"), DllPathAddress))
			{
				// sleeps to allow injection
				// Sleep(1000);
				// frees the memory that we allocated
				// if (VirtualFreeEx(ProcessHandle, DllPathAddress, strlen(DllPath) + 1, MEM_RELEASE))
				// {
				// returns true
				return TRUE;
				// }
			}
		}
	}
	// returns false
	return FALSE;
}

// the main entry of our injector
INT main()
{
	// gets the process id of our game
	DWORD ProcessId = GetProcessPid("Miscreated.exe");
	// if the process id is valid
	if (ProcessId)
	{
		// gets a handle to the process
		HANDLE ProcessHandle = GetProcessHandle(ProcessId);
		// validates the process handle
		if (ProcessHandle)
		{
			// gets a thread from the process
			DWORD ThreadId = GetProcessThread(ProcessId);
			// if the thread id is valid
			if (ThreadId)
			{
				// gets the thread handle
				HANDLE ThreadHandle = GetThreadHandle(ThreadId);
				// validates the thread handle
				if (ThreadHandle)
				{
					// stores the current directory
					CHAR CurrentDirectory[MAX_PATH];
					// gets the current directory
					GetCurrentDirectory(MAX_PATH, CurrentDirectory);
					// appends to the directory
					strcat_s(CurrentDirectory, "\\Irondick.dll");
					// injects our dll
					if (InjectDll(ProcessHandle, ThreadHandle, CurrentDirectory))
					{
						// notifies the user
						cout << "Successfully Injected." << endl;
					}
					else
					{
						// notifies the user
						cout << "Injection failed." << endl;
					}
				}
				// else we notify the user of the failure
				else cout << "Could not obtain a thread handle." << endl;
			}
			// else we notify the user of the failure
			else cout << "Thread not found." << endl;
		}
		// else we notify the user of the failure
		else cout << "Could not obtain a game handle." << endl;
	}
	// else we notify the user of the failure
	else cout << "Process not found." << endl;
	// waits to close
	cin.get();
	// returns to the kernel
	return 0;
}