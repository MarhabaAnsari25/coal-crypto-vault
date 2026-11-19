; ============================================================
; crypto_logic.inc
; Modular 32-bit MASM cryptographic procedures
; Conventions: Kip Irvine Irvine32.inc (STDCALL / Irvine32)
; NO 16-bit DOS interrupts (INT 21h)
;
; Register contract (caller sets before each CALL):
;   ESI = address of data buffer
;   EDI = address of key  buffer
;   EBX = key length  (bytes, must be > 0)
;   ECX = data length (bytes)
;
; Registers preserved across each procedure:
;   ESI, EDI, EBX, ECX, EDX (saved/restored via stack)
;   EAX is the return value for ComputeChecksum only.
; ============================================================

; ------------------------------------------------------------
; EncryptBuffer
; Algorithm per byte:
;   1. XOR byte with key[keyIndex mod keyLen]   (rolling key)
;   2. ROL  AL, 3                               (bit rotation)
;   3. keyIndex++ (wraps via modulo next loop)
;
; IN : ESI = data buffer address
;      EDI = key  buffer address
;      EBX = key length
;      ECX = data length
; OUT: buffer at ESI modified in place
; ------------------------------------------------------------
EncryptBuffer PROC
    pushad                          ; save all general-purpose registers

    xor     edx, edx                ; edx = key index (0-based)

    test    ecx, ecx                ; guard: nothing to do if length == 0
    jz      EncryptDone

EncryptLoop:
    mov     al, [esi]               ; al = current data byte

    ; --- rolling XOR with key byte ---
    push    ebx                     ; save key length
    push    edx                     ; save key index
    ; compute key[edx mod ebx] without div (use xor trick via loop index)
    ; We already maintain edx as a simple counter; wrap it manually below.
    mov     bl, [edi + edx]         ; bl = key[keyIndex]
    xor     al, bl                  ; apply XOR
    pop     edx
    pop     ebx

    ; --- bit rotation ---
    rol     al, 3                   ; rotate left 3 bits

    mov     [esi], al               ; write encrypted byte back

    ; --- advance pointers / indices ---
    inc     esi                     ; next data byte
    inc     edx                     ; next key index

    ; wrap key index: if edx == ebx then edx = 0
    cmp     edx, ebx
    jb      EncryptNoWrap
    xor     edx, edx                ; reset key index to 0
EncryptNoWrap:

    dec     ecx
    jnz     EncryptLoop

EncryptDone:
    popad                           ; restore all general-purpose registers
    ret
EncryptBuffer ENDP


; ------------------------------------------------------------
; DecryptBuffer
; Exact inverse of EncryptBuffer:
;   1. ROR  AL, 3                               (undo rotation first)
;   2. XOR byte with key[keyIndex mod keyLen]   (undo rolling XOR)
;   3. keyIndex++
;
; IN : ESI = data buffer address
;      EDI = key  buffer address
;      EBX = key length
;      ECX = data length
; OUT: buffer at ESI restored in place
; ------------------------------------------------------------
DecryptBuffer PROC
    pushad                          ; save all general-purpose registers

    xor     edx, edx                ; edx = key index (0-based)

    test    ecx, ecx
    jz      DecryptDone

DecryptLoop:
    mov     al, [esi]               ; al = current (encrypted) data byte

    ; --- undo bit rotation FIRST ---
    ror     al, 3                   ; rotate right 3 bits (inverse of ROL 3)

    ; --- undo rolling XOR ---
    push    ebx
    push    edx
    mov     bl, [edi + edx]         ; bl = key[keyIndex]
    xor     al, bl                  ; XOR is its own inverse
    pop     edx
    pop     ebx

    mov     [esi], al               ; write decrypted byte back

    ; --- advance pointers / indices ---
    inc     esi
    inc     edx

    cmp     edx, ebx
    jb      DecryptNoWrap
    xor     edx, edx
DecryptNoWrap:

    dec     ecx
    jnz     DecryptLoop

DecryptDone:
    popad
    ret
DecryptBuffer ENDP


; ------------------------------------------------------------
; ComputeChecksum
; Computes a 32-bit rolling XOR checksum over [ESI .. ESI+ECX).
;
; Algorithm:
;   checksum = 0
;   for each byte b in buffer:
;       checksum = ROL(checksum, 1) XOR ZeroExtend(b)
;
; The ROL-before-XOR gives positional sensitivity (a simple
; byte-by-byte XOR would miss byte-order transpositions).
;
; IN : ESI = data buffer address
;      ECX = data length (bytes)
; OUT: EAX = 32-bit checksum
;      All other caller-saved registers unchanged.
; ------------------------------------------------------------
ComputeChecksum PROC
    push    esi                     ; preserve ESI (caller may need it)
    push    ecx                     ; preserve ECX
    push    ebx                     ; preserve EBX (used as temp)

    xor     eax, eax                ; eax = running checksum = 0

    test    ecx, ecx
    jz      ChecksumDone

ChecksumLoop:
    rol     eax, 1                  ; rotate checksum left by 1 before mixing

    movzx   ebx, BYTE PTR [esi]     ; zero-extend current byte into ebx
    xor     eax, ebx                ; fold byte into checksum

    inc     esi
    dec     ecx
    jnz     ChecksumLoop

ChecksumDone:
    pop     ebx
    pop     ecx
    pop     esi
    ; EAX holds the final checksum -- do NOT pop/restore it
    ret
ComputeChecksum ENDP
