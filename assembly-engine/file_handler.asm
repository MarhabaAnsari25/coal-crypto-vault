; ============================================================
; file_handler.asm
; Non-interactive 32-bit MASM file processing driver.
;
; Execution flow:
;   1. Read key.txt  -> line 1 = mode ('E' or 'D'), line 2 = key
;   2. Read input.txt into inputBuf (up to 5000 bytes)
;   3. Call EncryptBuffer / DecryptBuffer (from crypto_logic.inc)
;   4. Call ComputeChecksum
;   5. Write processed bytes to output.txt
;   6. Write hex dump + checksum to meta.txt
;
; Dependencies: Irvine32.inc, crypto_logic.inc
; Assemble  :  ml /c /coff file_handler.asm
; Link      :  link /subsystem:console /entry:main file_handler.obj Irvine32.lib kernel32.lib user32.lib
; ============================================================

INCLUDE c:\Users\840 G6\.vscode\extensions\istareatscreens.masm-runner-1.0.0\native\irvine\Irvine32.inc


; ---- constants ------------------------------------------------
BUFFER_SIZE     EQU 5000
KEY_MAX         EQU 256
KEYTXT_SIZE     EQU 512          ; enough for mode line + key line
HEX_CHARS_SIZE  EQU (BUFFER_SIZE * 3) + 64   ; "XX " per byte + header

; ---- .data ----------------------------------------------------
.data
    ; File names
    keyFileName     BYTE "key.txt",    0
    inputFileName   BYTE "input.txt",  0
    outputFileName  BYTE "output.txt", 0
    metaFileName    BYTE "meta.txt",   0

    ; Hex digit lookup table
    hexTable        BYTE "0123456789ABCDEF"

    ; meta.txt section headers (plain BYTE strings, no CRLF appended yet)
    hdrHex          BYTE "=== Processed Bytes (Hex) ===", 13, 10, 0
    hdrChk          BYTE "=== Checksum (32-bit) ===",    13, 10, 0
    newLine         BYTE 13, 10, 0

    ; Error / status messages written to meta.txt on failure
    errKeyOpen      BYTE "ERROR: cannot open key.txt",    13, 10, 0
    errInputOpen    BYTE "ERROR: cannot open input.txt",  13, 10, 0
    errOutputOpen   BYTE "ERROR: cannot create output.txt", 13, 10, 0
    errMetaOpen     BYTE "ERROR: cannot create meta.txt", 13, 10, 0

; ---- .data? ---------------------------------------------------
.data?
    ; Raw key.txt content
    keyFileBuf      BYTE KEYTXT_SIZE dup(?)

    ; Parsed fields
    modeChar        BYTE ?          ; 'E' or 'D' (uppercased)
    keyBuf          BYTE KEY_MAX dup(?)
    keyLen          DWORD ?

    ; Input data
    inputBuf        BYTE BUFFER_SIZE dup(?)
    bytesRead       DWORD ?

    ; Checksum result
    checksum        DWORD ?

    ; Hex output staging buffer  (3 chars per byte + newlines)
    hexBuf          BYTE HEX_CHARS_SIZE dup(?)
    hexBufLen       DWORD ?

    ; Checksum hex string "XXXXXXXX" + CRLF  (8 nibbles + 2 + nul)
    chkHexStr       BYTE 12 dup(?)

    ; Reusable file handle
    fileHandle      DWORD ?

; ---- .code ----------------------------------------------------
.code
INCLUDE crypto_logic.inc
; ============================================================
; Utility: WriteStringToFile
; Writes a nul-terminated string to an already-open file.
; IN  : EAX = file handle
;       ESI = address of nul-terminated string
; OUT : nothing (preserves EAX)
; ============================================================
WriteStringToFile PROC
    push    eax
    push    ecx
    push    esi

    ; measure string length
    push    esi
    xor     ecx, ecx
@@lenLoop:
    cmp     BYTE PTR [esi], 0
    je      @@lenDone
    inc     ecx
    inc     esi
    jmp     @@lenLoop
@@lenDone:
    pop     esi

    ; write ecx bytes from esi to file (handle in [esp+12] after pushes)
    push    ecx                     ; byteCount
    push    esi                     ; buffer address
    mov     eax, [esp + 8 + 4]     ; reload original EAX (handle) from stack slot
    push    eax                     ; fileHandle
    call    WriteToFile             ; Irvine32: WriteToFile(handle, buffer, count)

    pop     esi
    pop     ecx
    pop     eax
    ret
WriteStringToFile ENDP

; ============================================================
; Utility: DwordToHex
; Converts a 32-bit value into an 8-char uppercase hex string.
; IN  : EAX = value to convert
;       EDI = destination buffer (at least 8 bytes; NOT nul-terminated)
; OUT : EDI advanced by 8
; ============================================================
DwordToHex PROC
    push    eax
    push    ebx
    push    ecx

    mov     ecx, 8          ; 8 nibbles
    rol     eax, 4          ; start with the most-significant nibble
@@dHexLoop:
    rol     eax, 4
    mov     bl, al
    and     bl, 0Fh
    movzx   ebx, bl
    mov     bl, hexTable[ebx]
    mov     [edi], bl
    inc     edi
    dec     ecx
    jnz     @@dHexLoop

    pop     ecx
    pop     ebx
    pop     eax
    ret
DwordToHex ENDP

; ============================================================
; Utility: ByteToHex
; Converts a single byte into two uppercase hex characters.
; IN  : AL  = byte to convert
;       EDI = destination (2 bytes written, EDI NOT advanced here)
; OUT : [EDI]   = high nibble char
;       [EDI+1] = low  nibble char
; ============================================================
ByteToHex PROC
    push    eax
    push    ebx

    ; high nibble
    mov     bl, al
    shr     bl, 4
    movzx   ebx, bl
    mov     bl, hexTable[ebx]
    mov     [edi], bl

    ; low nibble
    mov     bl, al
    and     bl, 0Fh
    movzx   ebx, bl
    mov     bl, hexTable[ebx]
    mov     [edi+1], bl

    pop     ebx
    pop     eax
    ret
ByteToHex ENDP

; ============================================================
; Utility: ParseKeyFile
; Parses keyFileBuf filled from key.txt.
;   Line 1: single char  mode  ('E'/'e' or 'D'/'d')
;   Line 2: key string (up to KEY_MAX-1 chars, terminated by CR/LF/EOF)
;
; Writes results into modeChar, keyBuf, keyLen.
; IN  : ECX = number of bytes actually read into keyFileBuf
; ============================================================
ParseKeyFile PROC
    push    esi
    push    edi
    push    eax
    push    ecx
    push    ebx

    lea     esi, keyFileBuf
    lea     edi, keyBuf

    ; ---- read mode char (first non-whitespace byte) ----
    ; skip leading whitespace
@@skipWS:
    cmp     ecx, 0
    je      @@parseEnd
    mov     al, [esi]
    cmp     al, ' '
    je      @@wsAdv
    cmp     al, 9           ; TAB
    je      @@wsAdv
    cmp     al, 13          ; CR
    je      @@wsAdv
    cmp     al, 10          ; LF
    je      @@wsAdv
    jmp     @@gotMode
@@wsAdv:
    inc     esi
    dec     ecx
    jmp     @@skipWS

@@gotMode:
    mov     al, [esi]
    ; uppercase
    cmp     al, 'a'
    jb      @@storeMode
    cmp     al, 'z'
    ja      @@storeMode
    sub     al, 20h         ; to uppercase
@@storeMode:
    mov     modeChar, al
    inc     esi
    dec     ecx

    ; skip to end of line 1
@@skipLine1:
    cmp     ecx, 0
    je      @@parseEnd
    mov     al, [esi]
    inc     esi
    dec     ecx
    cmp     al, 10          ; LF ends line
    jne     @@skipLine1

    ; ---- read key (line 2) ----
    xor     ebx, ebx        ; ebx = key byte count
@@keyLoop:
    cmp     ecx, 0
    je      @@keyDone
    cmp     ebx, KEY_MAX - 1
    jae     @@keyDone
    mov     al, [esi]
    cmp     al, 13
    je      @@keyDone
    cmp     al, 10
    je      @@keyDone
    mov     [edi], al
    inc     edi
    inc     esi
    inc     ebx
    dec     ecx
    jmp     @@keyLoop
@@keyDone:
    mov     keyLen, ebx

@@parseEnd:
    pop     ebx
    pop     ecx
    pop     eax
    pop     edi
    pop     esi
    ret
ParseKeyFile ENDP

; ============================================================
; main
; ============================================================
main PROC
    ; ---- 1. Open and read key.txt --------------------------------
    lea     eax, keyFileName
    call    OpenInputFile           ; Irvine32: EAX = handle (INVALID_HANDLE_VALUE on fail)
    cmp     eax, INVALID_HANDLE_VALUE
    je      @@fatalKeyOpen
    mov     fileHandle, eax

    push    KEYTXT_SIZE
    lea     eax, keyFileBuf
    push    eax
    push    fileHandle
    call    ReadFromFile            ; Irvine32: EAX = bytes read
    mov     ecx, eax                ; ecx = bytes read (used by ParseKeyFile)

    push    fileHandle
    call    CloseFile

    call    ParseKeyFile            ; fills modeChar, keyBuf, keyLen

    ; ---- 2. Open and read input.txt ------------------------------
    lea     eax, inputFileName
    call    OpenInputFile
    cmp     eax, INVALID_HANDLE_VALUE
    je      @@fatalInputOpen
    mov     fileHandle, eax

    push    BUFFER_SIZE
    lea     eax, inputBuf
    push    eax
    push    fileHandle
    call    ReadFromFile
    mov     bytesRead, eax

    push    fileHandle
    call    CloseFile

    ; ---- 3. Call crypto routine based on mode -------------------
    ; Register contract for crypto_logic.inc:
    ;   ESI = data buffer
    ;   EDI = key buffer
    ;   EBX = key length
    ;   ECX = data length
    lea     esi, inputBuf
    lea     edi, keyBuf
    mov     ebx, keyLen
    mov     ecx, bytesRead

    ; guard: if keyLen == 0, skip crypto (no key available)
    test    ebx, ebx
    jz      @@skipCrypto

    cmp     modeChar, 'E'
    je      @@doEncrypt
    cmp     modeChar, 'D'
    je      @@doDecrypt
    ; unknown mode: fall through to checksum without transform
    jmp     @@skipCrypto

@@doEncrypt:
    call    EncryptBuffer
    jmp     @@skipCrypto

@@doDecrypt:
    call    DecryptBuffer

@@skipCrypto:

    ; ---- 4. Compute checksum ------------------------------------
    lea     esi, inputBuf
    mov     ecx, bytesRead
    call    ComputeChecksum         ; returns EAX = checksum
    mov     checksum, eax

    ; ---- 5. Write output.txt ------------------------------------
    lea     eax, outputFileName
    call    CreateOutputFile        ; Irvine32: EAX = handle
    cmp     eax, INVALID_HANDLE_VALUE
    je      @@fatalOutputOpen
    mov     fileHandle, eax

    push    bytesRead
    lea     eax, inputBuf
    push    eax
    push    fileHandle
    call    WriteToFile

    push    fileHandle
    call    CloseFile

    ; ---- 6. Build hex dump string into hexBuf -------------------
    lea     edi, hexBuf
    lea     esi, inputBuf
    mov     ecx, bytesRead
    xor     ebx, ebx                ; byte counter for line wrapping (16 per line)
    mov     hexBufLen, 0

    test    ecx, ecx
    jz      @@hexDone

@@hexLoop:
    ; convert byte to two hex chars
    mov     al, [esi]
    call    ByteToHex               ; writes [EDI], [EDI+1]
    add     edi, 2

    ; add space separator
    mov     BYTE PTR [edi], ' '
    inc     edi

    inc     esi
    inc     ebx

    ; every 16 bytes insert CRLF
    cmp     ebx, 16
    jne     @@noLineBreak
    mov     BYTE PTR [edi],   13
    mov     BYTE PTR [edi+1], 10
    add     edi, 2
    xor     ebx, ebx
@@noLineBreak:

    dec     ecx
    jnz     @@hexLoop

    ; final CRLF (if last line wasn't exactly 16 bytes)
    test    ebx, ebx
    jz      @@hexDone
    mov     BYTE PTR [edi],   13
    mov     BYTE PTR [edi+1], 10
    add     edi, 2

@@hexDone:
    ; nul-terminate and record length
    mov     BYTE PTR [edi], 0
    lea     eax, hexBuf
    sub     edi, eax
    mov     hexBufLen, edi

    ; ---- Build checksum hex string in chkHexStr -----------------
    ; format: "XXXXXXXX\r\n\0"
    lea     edi, chkHexStr
    mov     eax, checksum
    call    DwordToHex              ; writes 8 chars, advances EDI by 8
    mov     BYTE PTR [edi],   13
    mov     BYTE PTR [edi+1], 10
    mov     BYTE PTR [edi+2], 0

    ; ---- 7. Write meta.txt --------------------------------------
    lea     eax, metaFileName
    call    CreateOutputFile
    cmp     eax, INVALID_HANDLE_VALUE
    je      @@fatalMetaOpen
    mov     fileHandle, eax

    ; --- section header: hex ---
    lea     esi, hdrHex
    push    fileHandle
    pop     eax
    call    WriteStringToFile

    ; --- hex body ---
    push    hexBufLen
    lea     eax, hexBuf
    push    eax
    push    fileHandle
    call    WriteToFile

    ; --- blank line ---
    lea     esi, newLine
    push    fileHandle
    pop     eax
    call    WriteStringToFile

    ; --- section header: checksum ---
    lea     esi, hdrChk
    push    fileHandle
    pop     eax
    call    WriteStringToFile

    ; --- checksum value ---
    lea     esi, chkHexStr
    push    fileHandle
    pop     eax
    call    WriteStringToFile

    push    fileHandle
    call    CloseFile

    ; ---- done ---------------------------------------------------
    jmp     @@exit

; ---- error paths -----------------------------------------------
@@fatalKeyOpen:
    ; Write error note to stderr via WriteConsole or simply exit with code 1
    invoke  ExitProcess, 1

@@fatalInputOpen:
    invoke  ExitProcess, 2

@@fatalOutputOpen:
    invoke  ExitProcess, 3

@@fatalMetaOpen:
    invoke  ExitProcess, 4

@@exit:
    invoke  ExitProcess, 0

main ENDP
END main
