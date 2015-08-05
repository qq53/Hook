		.386
		.model flat, stdcall
		option casemap :none

include		windows.inc
include		user32.inc
include		kernel32.inc
include		msvcrt.inc

includelib	kernel32.lib
includelib	user32.lib
includelib	msvcrt.lib

_PProcess32First		typedef proto :dword,:dword
_PProcess32Next			typedef proto :dword,:dword
_ProtoLoadLibrary		typedef	proto :dword
_ProtoGetProcAddress	typedef	proto :dword,:dword

_lpProcess32First	typedef 	ptr _PProcess32First
_lpProcess32Next	typedef 	ptr _PProcess32Next
_lpLoadLibrary		typedef		ptr _ProtoLoadLibrary
_lpGetProcAddress	typedef		ptr _ProtoGetProcAddress

CTXT macro Text:VARARG
	local	szText
.const
	szText	db	Text,0
.code
	exitm <offset szText>
endm

reverseArgs	macro	arglist:VARARG
	local	txt,count
    
	txt	TEXTEQU	<>
	count	= 0
	for	i,<arglist>
        count	= count + 1
        txt	TEXTEQU @CatStr(i,<!,>,<%txt>)
	endm
	if	count GT 0
        txt	SUBSTR  txt,1,@SizeStr(%txt)-1
	endif
	exitm txt
endm

_invoke	 macro	_Proc,args:VARARG
	local	count
	
	count	= 0
	% for i,< reverseArgs( args ) >
		count=count + 1
		push i
	endm
	call dword ptr _Proc
endm

.code

REMOTE_THREAD_START equ this byte
_GetKrnlAddress	proc

		assume fs:nothing
		mov esi,fs:[30h]
		mov esi,[esi+0ch]
		mov esi,[esi+1ch]
_find:
		mov eax,[esi+08h]
		mov ebx,[esi+20h]
		mov bl,byte ptr [ebx+12*2]
		mov esi,[esi]
		cmp bl,0
		jnz _find
		
		ret

_GetKrnlAddress	endp	

_GetApiAddr	proc	_hModule,_lpsz
	local @ret
	local @dwLen

		mov @ret,0
		mov edi,_lpsz
		mov ecx,-1
		xor al,al
		cld
		repnz scasb
		mov ecx,edi
		sub ecx,_lpsz
		mov @dwLen,ecx
		
		mov esi,_hModule
		add esi,[esi+3ch]
		assume esi:ptr IMAGE_NT_HEADERS
		mov esi,[esi].OptionalHeader.DataDirectory[0].VirtualAddress
		add esi,_hModule
		assume esi:ptr IMAGE_EXPORT_DIRECTORY
		
		mov ebx,[esi].AddressOfNames
		add ebx,_hModule
		xor edx,edx
		.while edx < [esi].NumberOfNames
			push esi
			mov edi,[ebx]
			add edi,_hModule
			mov esi,_lpsz
			mov ecx,@dwLen
			repz cmpsb
			.if ZERO?
				pop esi
				jmp @F
			.endif
			pop esi
			add ebx,4
			inc edx
		.endw
		jmp _ret
@@:  	
		sub ebx,[esi].AddressOfNames
		sub ebx,_hModule
		shr ebx,1
		add ebx,[esi].AddressOfNameOrdinals
		add ebx,_hModule
		movzx eax,word ptr [ebx]
		shl eax,2
		add eax,[esi].AddressOfFunctions
		add eax,_hModule
   
		mov eax,[eax]
		add eax,_hModule
		mov @ret,eax
_ret:
		assume esi:nothing
		mov eax,@ret
		ret
		
_GetApiAddr endp

_RemoteThread	proc	lParam

		call @F
@@:
		pop ebx
		sub ebx,offset @B
		
		push ebx
		invoke _GetKrnlAddress
		pop ebx
		mov [ebx+offset lpKrnlBase],eax
		
		lea eax,[ebx+offset szGetProcAddr]	
		mov edi,[ebx+offset lpKrnlBase]
		push ebx
		invoke	_GetApiAddr,edi,eax
		pop ebx
		mov [ebx+offset _GetProcAddress],eax
	
		mov edi,[ebx+offset lpKrnlBase]
		lea eax,[ebx+offset szLoadlib]
		mov edx,[ebx+offset _GetProcAddress]
		push ebx
		_invoke edx,edi,eax
		pop ebx
		mov [ebx+offset _Loadlibrary],eax

	;从这开始可以干任何事^_^
		mov eax,[ebx+offset _Loadlibrary]
		lea ecx,[ebx+offset szDllPath]		
		push ebx
		_invoke eax, ecx
		pop ebx
				
		ret
	
_RemoteThread	endp

szGetProcAddr	db	'GetProcAddress',0
szLoadlib		db	'LoadLibraryA',0
szDllPath		db	128 dup (0)

_GetProcAddress	_lpGetProcAddress	?
_Loadlibrary	_lpLoadLibrary	?

lpKrnlBase		dd		?

REMOTE_THREAD_END equ this byte
REMOTE_THREAD_SIZE=offset REMOTE_THREAD_END - offset REMOTE_THREAD_START

	.data
hkernel32		dd		?
szCmd			db		128 dup (0)
hProcHandle 	dd		?
hThread		 	dd		?
lpRemote		dd		?
dwtmp			dd		?

_Process32First	_lpProcess32First		?
_Process32Next	_lpProcess32Next		?
	
	.code
	
_GetProcessList	proc
	local	@stProcess:PROCESSENTRY32
	local	@hSnapShot
	local	@dwCount
	local	@szBuffer[30]: byte
	
		invoke	RtlZeroMemory,addr @stProcess,sizeof @stProcess
		mov	@stProcess.dwSize,sizeof @stProcess	
		invoke	CreateToolhelp32Snapshot,TH32CS_SNAPPROCESS,0
		mov	@hSnapShot,eax
		
		invoke	_Process32First,@hSnapShot,addr @stProcess
		mov @dwCount, 0				
		.while	eax
			invoke	wsprintf,addr @szBuffer, CTXT('%04d %s',0ah,0dh), @stProcess.th32ProcessID, addr @stProcess.szExeFile
			invoke	crt_printf, addr @szBuffer	
			inc @dwCount
			invoke	_Process32Next,@hSnapShot,addr @stProcess
		.endw
		invoke	CloseHandle,@hSnapShot
		ret
		
_GetProcessList	endp

_atoi proc _szStr
	mov edi,_szStr
	xor ebx,ebx
	movzx eax,byte ptr [edi+3]
	sub al,'0'
	add ebx,eax
	movzx eax,byte ptr [edi+2]
	sub al,'0'
	imul eax,eax,10
	add ebx,eax
	movzx eax,byte ptr [edi+1]
	sub al,'0'
	imul eax,eax,100	
	add ebx,eax
	movzx eax,byte ptr [edi]
	sub al,'0'
	imul eax,eax,1000
	add ebx,eax
	mov eax,ebx
	ret
_atoi endp
	
start:
		invoke	VirtualProtect,	offset szDllPath, 128, PAGE_READWRITE, offset dwtmp
		invoke	GetCommandLine
		inc eax
		invoke	lstrcpy, offset szDllPath, eax
		invoke	lstrlen, offset szDllPath
		lea edi,[offset szDllPath + eax]
		mov al, '\'
		std
		repnz scasb
		add edi, 2
		cld
		invoke	lstrcpy, edi, CTXT('hook.dll')
		invoke	VirtualProtect,	offset szDllPath, 128, dwtmp, NULL
		invoke	GetModuleHandle,CTXT('KERNEL32.DLL')
		mov		hkernel32,eax
		invoke	GetProcAddress,hkernel32,CTXT('Process32First')
		mov		_Process32First,eax
		invoke	GetProcAddress,hkernel32,CTXT('Process32Next')
		mov		_Process32Next,eax
		.while 1
			invoke	crt_gets, offset szCmd
			cmp byte ptr [szCmd], 'l'
			sete al
			.if al
				call	_GetProcessList
			.endif
			cmp byte ptr [szCmd], 'q'
			sete al
			.if al
				invoke	CloseHandle, hkernel32
				invoke	ExitProcess, NULL
			.endif	
			cmp byte ptr [szCmd], 'h'
			sete al
			.if al
				invoke	crt_printf, offset szCmd + 2
				invoke	_atoi, offset szCmd + 2
				invoke	OpenProcess,PROCESS_ALL_ACCESS,FALSE, eax
				.if eax
					mov hProcHandle, eax
					invoke	crt_printf, CTXT(0ah,0dh,'open success',0ah,0dh)
					
					invoke	VirtualAllocEx,hProcHandle,NULL,\
						REMOTE_THREAD_SIZE,MEM_COMMIT,\
						PAGE_EXECUTE_READWRITE
					.if eax
						mov lpRemote,eax
						invoke	crt_printf, CTXT('alloc success',0ah,0dh)
						invoke	WriteProcessMemory,hProcHandle,lpRemote,\
										offset REMOTE_THREAD_START,\
										REMOTE_THREAD_SIZE,addr dwtmp
						.if eax
							invoke	crt_printf, CTXT('write success',0ah,0dh)
						.endif
						mov eax,lpRemote
						add eax,offset _RemoteThread - offset REMOTE_THREAD_START
						invoke	CreateRemoteThread,hProcHandle,NULL,0,eax,NULL,0,NULL
						mov hThread, eax
						.if eax
							invoke	crt_printf, CTXT('create remote thread success',0ah,0dh)
							invoke	WaitForSingleObject, hThread, INFINITE
							invoke	CloseHandle, hThread
							
						.elseif 
							invoke	GetLastError 
							invoke	wsprintf, offset szCmd, CTXT('Error code: %d',0ah,0dh), eax
							invoke	crt_printf, offset szCmd
						.endif
						invoke VirtualFreeEx, hProcHandle, lpRemote, REMOTE_THREAD_SIZE, MEM_RELEASE
					.endif

					invoke	CloseHandle, hProcHandle
				.endif
			.endif				
		.endw
		
end start