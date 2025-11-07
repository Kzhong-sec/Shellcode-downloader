#pragma once

#include <windows.h>

typedef struct {
	SIZE_T Length;
	SIZE_T MaximumLength;
	PVOID Buffer;
} USTRING;



PVOID Rc4Decrypt(USTRING* uData, USTRING* uKey);