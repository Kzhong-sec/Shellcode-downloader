#include <windows.h>
#include <ntstatus.h>
#include "crypto_.h"

typedef NTSTATUS(NTAPI* fnSystemFunction032) (USTRING* Data, USTRING* Key);

PVOID Rc4Decrypt(USTRING* uData, USTRING* uKey) {
	HMODULE advapi = LoadLibraryA("Advapi32");
	fnSystemFunction032 rc4Crypt = (fnSystemFunction032)GetProcAddress(advapi, "SystemFunction032");
	if (rc4Crypt(uData, uKey) != STATUS_SUCCESS)
		return 0;
	else 
		return uData->Buffer;
}