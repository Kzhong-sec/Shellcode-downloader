    format binary
    use32
    include 'win32a.inc'





    push ebp
    mov ebp, esp
    sub esp, 100
    mov eax, [fs:30h]; eax = PEB base
    mov eax, dword [eax + 0x0c] ; eax = ptr PEB_LDR_DATA
    add eax, 0x0c ;eax = ptr PEB_LDR_DATA.InLoadOrderModuleList
NEXT_FLINK:
    mov eax, dword [eax] ; eax = InLoadOrdeModuleList->Flink; {ptr32 _LIST_ENTRY}
    mov ebx, dword [eax + 0x030] ; ebx = BaseDllName{_UNICODE_STRING}->Buffer
    xor edx, edx ;edx = null byte
    xor ecx, ecx ;ecx = counter
STR_CMP_LOOP_START:
    cmp dx, word [ebx + ecx]
    pushf
    add ecx, 2
    popf
    jnz STR_CMP_LOOP_START
    cmp ecx, 26
    jnz NEXT_FLINK
    ; Found kernel32 dll, in the LDR_DATA_TABLE_ENTRY. EAX still is the LDR
kern32 equ 4
    mov eax, dword [eax + 0x18] ; eax = Kernel32 module base.
    mov dword [ebp - kern32], eax
    call LoadLibStr
    db 'LoadLibraryA', 0
LoadLibStr:
    ;LoadLib Str is on the stack
    push eax
    call ResolveExport
loadlib equ 12
    mov dword [ebp - loadlib], eax

    call exitProcessStr
    db 'ExitProcess', 0
exitProcessStr:
    push dword [ebp - kern32]
    call ResolveExport
exitProcess equ 28
    mov dword [ebp - exitProcess], eax


    call getProcAddrStr
    db 'GetProcAddress', 0
getProcAddrStr:
    push dword [ebp - kern32]
    call ResolveExport
GetProc equ 16
    mov dword [ebp - GetProc], eax
    call user32str
    db 'user32.dll', 0
user32str:
    call dword [ebp - loadlib]
user32 equ 20
    mov dword [ebp - user32], eax
    call messageBoxStr
    db 'MessageBoxA', 0
messageBoxStr:
    push dword [ebp - user32]
    call dword [ebp - GetProc]
messageBox equ 24
    mov dword [ebp - messageBox], eax
    call uh_ohStr
    db 'uh oh', 0
uh_ohStr:
    pop edx ; 'uh oh!'
    call hackedStr
    db 'hacked!', 0
hackedStr:
    pop ecx ; "hacked!"

    push MB_OK
    push edx ; uh oh
    push ecx ;hacked
    push HWND_DESKTOP
    call dword [ebp - messageBox]
    push 1
    call dword [ebp - exitProcess]







module_ea equ 8
proc_str equ 12
ResolveExport:
    push ebp
    mov ebp, esp
    push ebx
    push esi

    mov eax, dword [ebp + module_ea]
    mov ebx, dword [eax + 0x3c] ; ebx = elfanew value, offset to _IMAGE_NT_HEADER
    mov ebx, [eax + ebx + 0x78] ; ebx = export table base
    add ebx, eax ; ebx = export table absolute address
    mov ecx, [ebx + 0x18] ; ecx = Number of names
    mov esi, [ebx + 0x20] ; esi = address of names
    add esi, eax  ; esi = absolute address of names
NEXT_EXPORT:
    dec ecx ; decreasing the index into the name table
    mov edx, [esi + ecx * 4] ; edx = address of current export name
    add edx, eax ; edx = absolute address of export name
    push eax ; saving local vars on stack that will get clobbered
    push ecx
    push dword [ebp + proc_str]
    push edx
    call StrCmp
    test eax, eax
    pop ecx
    pop eax
    jz NEXT_EXPORT

    ; String Matched
    mov esi, dword [ebx + 0x24] ; esi = ordinal address, ebx = absolute addr of export table
    add esi, eax ; esi = absolute address of ord export table
    movzx edx, word [esi + ecx*2] ; edx = value from index in ord table
    mov esi, dword [ebx + 0x1c] ; esi = function address, ebx = absolute addr of export table
    add esi, eax ; esi = absolute address of function addresses
    mov edx, dword [esi+edx*4] ; using the index from ord table to index into address table
    add eax, edx ; eax = absolute address of func
   
    pop esi
    pop ebx
    mov esp, ebp
    pop ebp
    retn 8


src equ 8
dst equ 12
StrCmp:
    push ebp
    mov ebp, esp
    push ebx
    push esi
    xor ecx, ecx
    dec ecx
loop_start:
    inc ecx
    mov esi, dword [ebp + 8]
    mov edx, dword [ebp + 12]
    mov al, byte [esi + ecx]
    test al, al
    jz StringMatched
    cmp al, byte [edx + ecx]
    jz loop_start
    ; string did not match before null term found
    xor eax, eax
    jmp NoMatch
StringMatched:
    mov eax, 1
NoMatch:
    pop esi
    pop ebx
    mov esp, ebp
    pop ebp
    retn 8


