		.386
		.model flat, stdcall
		option casemap :none

include		windows.inc
include		user32.inc
include		kernel32.inc

includelib	kernel32.lib
includelib	user32.lib

CTXT macro Text:VARARG
	local	szText
.const
	szText	db	Text,0
.code
	exitm <offset szText>
endm

_PPModule32First		typedef proto :dword,:dword

_lpModule32First	typedef 	ptr _PPModule32First

HookData struct 4
	idx			dw		0
	attr		db		0
	fname		dd		0
	oldaddr		dd		0
	newaddr		dd		0
	bytes		db		11 dup (0)
	args		db		0
HookData ends

.data

_Module32First	_lpModule32First		?
hkernel32		dd						?
lpIT			dd						?
lpHookCount		dd						0
lpOldMemAttr	dd						?
lpHook			HookData				200 dup(<>)

.code

HookProcStart equ this byte
	
	pop eax
	mov cl, sizeof HookData
	mul cl
	lea edi, [lpHook + eax]
	assume edi: ptr HookData
	
;还原指令
	push edi
	lea esi, [edi].bytes
	mov edi, [edi].oldaddr
	mov ecx, sizeof HookData.bytes
	rep movsb
	pop edi
	
;处理
	mov eax, [edi].fname
	push edi
	invoke MessageBoxA, NULL, CTXT('是否拦截'), eax, MB_YESNO
	pop edi
	.if eax == IDYES
		movzx eax, [edi].args
		shl eax, 2
		mov word ptr [HookProcYes-2], ax
		jmp @YES
	.else
		jmp @NO
	.endif
	
@YES:
	xor eax, eax
	retn 4
HookProcYes equ this byte

@NO:
;处理桟
	movzx ecx, [edi].args
	inc ecx
	mov ebx, ecx
	shl ebx, 2
	inc ecx
	mov edx, [esp]
	push edi
	mov esi, esp
	lea edi, [esi - 4]
	rep movsd
	mov [esp], offset HookProcRet
	lea eax, [esp + ebx]
	mov dword ptr [eax], edx
	sub esp, 4
	pop edi	
	
;调会原处
	mov eax, [edi].oldaddr
	push eax
	ret
;调用完成
HookProcRet equ this byte
	ret

HookProcEnd equ this byte

FindHook proc @name

	lea esi, lpHook
	assume esi: ptr HookData
	mov ecx, [lpHookCount]
	.while ecx
		mov ebx, [esi].fname
		push ecx
		push esi
		invoke lstrcmp, ebx, @name
		.if !eax
			.break
		.endif
		pop esi
		pop ecx
		dec ecx
		add esi, sizeof HookData
	.endw
	.if !ecx
		mov esi, 0FFFFFFFFh
	.endif
	mov eax, esi
	ret

FindHook endp

Hook proc @name, @args

	invoke	FindHook, @name
	.if eax == 0FFFFFFFFh
		invoke MessageBoxA, NULL, CTXT('not find hook function'), NULL, MB_OK
	.else
		mov esi, eax
		assume esi: ptr HookData
		.if [esi].attr == 1
			invoke MessageBoxA, NULL, CTXT('already hooked'), NULL, MB_OK
		.else
			mov [esi].attr, 1
			mov al, byte ptr [@args]
			mov [esi].args, al
			mov edi, [esi].oldaddr
			invoke	VirtualProtect, edi, 10h, PAGE_EXECUTE_READWRITE, offset lpOldMemAttr
			mov al, 068h
			stosb
			movzx eax, [esi].idx
			stosd
			mov al, 068h
			stosb
			lea eax, HookProcStart
			stosd	
			mov al, 0c3h
			stosb
		.endif
	.endif
	ret

Hook endp

UnHook proc @name

	invoke	FindHook, @name
	.if eax == 0FFFFFFFFh
		invoke MessageBoxA, NULL, CTXT('not find unhook function'), NULL, MB_OK
	.else
		mov esi, eax
		assume esi: ptr HookData
		.if [esi].attr == 0
			invoke MessageBoxA, NULL, CTXT('not hooked'), NULL, MB_OK
		.else
			mov [esi].attr, 0
			mov edi, [esi].oldaddr
			push edi
			lea esi, [esi].bytes
			mov ecx, sizeof HookData.bytes
			rep movsb
			pop edi
			invoke	VirtualProtect, edi, 10h, PAGE_EXECUTE_READ, offset lpOldMemAttr
		.endif		
	.endif
	ret
	
UnHook endp

findFunc proc _baseAddr
	
	mov esi,_baseAddr
	assume esi:ptr IMAGE_DOS_HEADER
	add esi,[esi].e_lfanew
	assume esi:ptr IMAGE_NT_HEADERS
	mov eax, dword ptr [_baseAddr]
	mov lpIT, eax
	mov esi,[esi].OptionalHeader.DataDirectory[8].VirtualAddress
	add esi,_baseAddr
	push esi
	assume esi:ptr IMAGE_IMPORT_DESCRIPTOR
	.while [esi].OriginalFirstThunk || [esi].TimeDateStamp || [esi].ForwarderChain ||\
		 [esi].Name1  || [esi].FirstThunk
		mov edi, [esi].FirstThunk
		.if lpIT > edi
			mov lpIT,edi
		.endif
		add esi,sizeof IMAGE_IMPORT_DESCRIPTOR
	.endw
	pop esi
	.while [esi].OriginalFirstThunk || [esi].TimeDateStamp || [esi].ForwarderChain ||\
		 [esi].Name1  || [esi].FirstThunk
		
		push esi
		mov edi, [esi].FirstThunk
		add edi, _baseAddr	
		mov esi, [esi].OriginalFirstThunk
		add esi, _baseAddr
		.while dword ptr [edi]
			mov eax, dword ptr [esi]
			add eax, _baseAddr
			assume eax: ptr IMAGE_IMPORT_BY_NAME
			push esi
			push edi
			lea ebx,[eax].Name1
			mov edx, dword ptr [edi]
			mov eax, edi
			sub eax, lpIT
			sub eax, _baseAddr
			shr eax,2
			.if eax > lpHookCount
				mov lpHookCount, eax
			.endif
			push ebx
			mov ebx,eax
			mov cl, sizeof HookData
			mul cl
			mov [lpHook.idx + eax], bx
			mov [lpHook.attr + eax], 0
			pop ebx
			mov [lpHook.fname + eax], ebx
			mov [lpHook.oldaddr + eax], edx
			mov [lpHook.newaddr + eax], 0
			mov esi, edx
			lea edi, [lpHook.bytes + eax]
			mov ecx, sizeof lpHook.bytes
			rep movsb
			pop edi
			pop esi
			add edi, 4
			add esi, 4
		.endw
		pop esi
		add esi,sizeof IMAGE_IMPORT_DESCRIPTOR
	.endw
	ret
	
findFunc endp

_getBaseAddr proc
	local	@stModule: MODULEENTRY32
	local	@hSnapShot: HANDLE 
	
	invoke	RtlZeroMemory,addr @stModule,sizeof @stModule
	mov	@stModule.dwSize,sizeof @stModule	
	invoke	CreateToolhelp32Snapshot,TH32CS_SNAPMODULE,0
	mov @hSnapShot,eax
	invoke	_Module32First,@hSnapShot,addr @stModule
	invoke	findFunc, @stModule.modBaseAddr
	invoke	VirtualProtect, offset HookProcYes-2, 2, PAGE_EXECUTE_READWRITE, offset lpOldMemAttr
	invoke	Hook, CTXT('GetStockObject'), 1
	invoke	UnHook, CTXT('GetStockObject')
	ret
	
_getBaseAddr endp
	
start:
	invoke	GetModuleHandle,CTXT('KERNEL32.DLL')
	mov		hkernel32,eax
	invoke	GetProcAddress,hkernel32,CTXT('Module32First')
	mov		_Module32First,eax
	call	_getBaseAddr
	invoke	GetModuleHandle, CTXT('hook.dll')
	invoke	FreeLibrary, eax
	ret

end start