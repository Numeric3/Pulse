;#INDEX# =======================================================================================================================
; Title .........: tls.au3 - non-blocking Schannel/SSPI transport (layer 2 of the WebSocket UDF)
; AutoIt Version : 3.3.16.1
; Language ......: English
; Description ...: TLS record layer built on secur32.dll/crypt32.dll with no third-party DLL:
;                  client and server contexts, encryption/decryption of records, peer certificate
;                  chain validation and a name check that cannot be bypassed. The three layers split
;                  the work: wsk.au3 = TCP, tls.au3 = TLS records, wsp.au3 = WebSocket frames.
; Remarks .......: Windows 8 and later, proven 32 and 64 bit. Every rule quoted below comes from a
;                  measurement on this machine (spike4 probes, probe_srvcred, spike8), never from a
;                  macro or from documentation prose; the reference is kept next to the code that
;                  depends on it.
;                  A normal program does not include this file: it includes WebSocket.au3,
;                  which pulls the four layers in dependency order and decides nothing itself;
;                  going through one layer directly is a caller's choice, never a need.
; Copyright ....: Copyright (c) 2026 Numeric1
; Licence .......: MIT
; Author ........: Numeric1
; https .........:
;===============================================================================================================================
;
;#COMMENTS#=====================================================================================================================
; Verified facts this layer depends on
;
; R1  A SecHandle is "ptr;ptr": 8 bytes x86, 16 bytes x64. Declaring it "dword;dword" in x64 is
;     TRUNCATED by 8 bytes by Windows, which then writes into the heap; the process dies later with
;     exit code 127 and no message (proven: same probe, same machine, P4 alone = death, P4 skipped =
;     rc 0).
; R2  SCHANNEL_CRED.dwVersion must be 3, 4 or 5 (of the 9 values tried, 0..8). Below that,
;     AcquireCredentialsHandle returns SEC_E_UNKNOWN_CREDENTIALS 0x8009030D and it is NOT a
;     certificate or flag problem.
; R3  dwFlags changes nothing at acquisition time: all 5 combinations tried pass once dwVersion>=3.
;     They only matter during the handshake (manual validation or not).
; R4  No network is needed to produce a ClientHello: InitializeSecurityContext with no input byte
;     already returns SEC_I_CONTINUE_NEEDED with 171 bytes including the SNI. The ABI is therefore
;     verifiable before any socket exists.
; R5  ISC_REQ_ALLOCATE_MEMORY (0x100) is honoured by Schannel (measured mode 1); a caller-supplied
;     buffer (mode 0) works too. This layer allocates itself: no forgotten FreeContextBuffer is
;     possible.
; R6  QueryContextAttributes on a FRESH context returns SEC_E_INVALID_HANDLE 0x80090301, and so does
;     a second FreeCredentialsHandle. Both codes are the expected signature of a teardown done
;     twice, not of a bug.
; R7  EnumSecurityPackagesW is NOT exported by secur32.dll nor sspicli.dll here (@error identical to
;     an invented function name). The token size therefore comes from QuerySecurityPackageInfoW:
;     cbMaxToken = 24576.
; R8  SSPI codes are NAMED by the system message table (FormatMessageW), because no SDK header
;     exists on this machine. An unknown code is returned with its Windows text, never with an
;     invented name.
;
; DS1..DS7 (server half, probe_srvcred 15/15 and spike8 21/21 on both bitnesses): the export is
; "AcceptSecurityContext" WITHOUT the W suffix; fCredentialUse 0 and 4 are refused while 1 (INBOUND),
; 2 and 3 succeed, and ASC does NOT check the direction; the server credential is built from a PKCS#12
; loaded IN MEMORY (PFXImportCertStore, temporary store, nothing installed in the Windows stores) and
; paCred is an array of PCCERT_CONTEXT; one acquired INBOUND credential serves every slot and is
; never freed by _Tls_Close; the first flight always belongs to the peer; _Tls_Pump @error 2 is not an
; error; and on this machine a Schannel server negotiates TLS 1.2 with OpenSSL even when the client
; offers 1.3.
;
; V1..V10 (chain validation, probe_cert/probe_dec): the peer certificate leaves
; QueryContextAttributesW through attribute 83 (decimal - the SDK writes 0x53) as a pointer to a
; CERT_CONTEXT that must be released with CertFreeCertificateContext and never with
; FreeContextBuffer (wrong allocator: segfault in x86, silent exit 127 in x64); hCertStore holds the
; whole chain the server sent and must be handed to CertGetCertificateChain as AdditionalStore;
; cbSize is NOT validated (16 accepted although the real struct is 32/36); the host-dependent
; policy is id 4 (55 is a hex number copied as decimal); SSL_EXTRA_CERT_CHAIN_POLICY_PARA takes the
; server name as a POINTER, writing the text inline segfaults crypt32; dwAuthType = 2 is the only
; value that performs a useful name check; verdicts 0x800B0109 (untrusted root) and 0x800B010F (name
; mismatch) are reported with the Windows text.
;
; DD1..DD5 (records): DecryptMessage must receive ONE DATA buffer holding the WHOLE record including
; the 5-byte header; Windows rewrites the descriptor and puts the clear text in the buffer of type
; DATA (offset 13 = 5 header + 8 GCM salt), never at index 0; a partial record returns
; SEC_E_INCOMPLETE_MESSAGE 0x80090318; header+payload split returns SEC_E_INVALID_TOKEN; two records
; in one DATA return SEC_E_DECRYPT_FAILURE 0x80090330.
;
; ALPN is a CLOSED door on this machine (probe_alpn, 3 doors x 120 ids, ClientHello unchanged), so the
; subprotocol is negotiated in the HTTP header only - see _Tls_SetAlpn.
;
; Proofs to replay after any change in this file (both bitnesses): spike4, probe_srvcred, spike8,
; spike5 (wss client), spike9 (wss server), spike10 (multiple inbound), and the layer 3 seam.
;
; CONTENTS
;   Naming ......... _Tls_HexD, _Tls_SecName, _Tls_SecText, _Tls_SecDesc, _Tls_StateName,
;                    _Tls_SetErr, _Tls_FatalErr, _Tls_HrTxt, _Tls_HrDesc
;   Buffers ........ _Tls_WriteAt, _Tls_ConsumeRaw, _Tls_AppendRaw, _Tls_PushTx, _Tls_SetBuf,
;                    _Tls_GetCb, _Tls_GetType, _Tls_GetPtr, _Tls_PokeD, _Tls_PokeP, _Tls_ZerosHex
;   Life cycle ..... _Tls_Startup, _Tls_Cleanup, _Tls_PkgInfo, _Tls_AcqCred, _Tls_AlpnBlob,
;                    _Tls_SetAlpn
;   Client ......... _Tls_Connect
;   Server ......... _Tls_SrvPrepare, _Tls_SrvRelease, _Tls_Accept, _Tls_IsInbound
;   Slots .......... _Tls_InitSlot, _Tls_Available, _Tls_PendingTx, _Tls_State, _Tls_Info
;   Handshake ...... _Tls_RecLen, _Tls_TraceRecords, _Tls_CompletePrefix, _Tls_HandshakeLeg,
;                    _Tls_QuerySizes, _Tls_StreamSizes, _Tls_ConnInfo
;   Validation ..... _Tls_CertContextPtr, _Tls_FreePeerCert, _Tls_PeerCert, _Tls_ChainParaSize,
;                    _Tls_CryptStructs, _Tls_BuildChain, _Tls_PolicySsl, _Tls_VerifyChain,
;                    _Tls_VerifyError
;   Records ........ _Tls_FlushTx, _Tls_PullRaw, _Tls_EncryptPush, _Tls_Send, _Tls_DecryptStep,
;                    _Tls_Pump, _Tls_Read, _Tls_ApplyShutdown, _Tls_Close
;===============================================================================================================================

#include-once
#include "wsk.au3"

; -----------------------------------------------------------------------------
; SSPI constants (values measured in spike4, see probe_tls1.au3)
; -----------------------------------------------------------------------------
Global $g_sTlsPkg = "Microsoft Unified Security Protocol Provider"
Global Const $g_sTlsSpecHandle = "ptr;ptr"
Global Const $g_sTlsSpecDesc = "dword;dword;ptr"
Global Const $g_sTlsSpecBuf4 = "dword;dword;ptr;dword;dword;ptr;dword;dword;ptr;dword;dword;ptr"
Global Const $g_sTlsSpecCred = _
        "dword;dword;ptr;ptr;dword;ptr;dword;ptr;dword;dword;dword;dword;dword;dword"

Global Const $Tls_SchCredVersion = 4            ; R2 : 3..5 acceptes
Global Const $Tls_SecPkgCredOutbound = 2
; DS2 (measure probe_srvcred, sweep 0..4): 1 = INBOUND, 3 = both, 0 and 4 return
; SEC_E_UNKNOWN_CREDENTIALS. ASC does NOT check the direction.
Global Const $Tls_SecPkgCredInbound = 1
Global Const $Tls_SecurityNativeDrep = 16
Global Const $Tls_SchCredManualCredValidation = 0x00000008
Global Const $Tls_SchCredNoDefaultCreds = 0x00000010
Global Const $Tls_SchUseStrongCrypto = 0x00400000

Global Const $Tls_SecBufferEmpty = 0
Global Const $Tls_SecBufferData = 1
Global Const $Tls_SecBufferToken = 2
Global Const $Tls_SecBufferExtra = 5
Global Const $Tls_SecBufferStreamTrailer = 6
Global Const $Tls_SecBufferStreamHeader = 7
Global Const $Tls_SecBufferAlert = 17
Global Const $Tls_SecBufferApplicationProtocols = 18

Global Const $Tls_SecPkgAttrStreamSizes = 4
; ALPN: **no id works on this machine, measured 2026-11-14 (probe_alpn, alpn_a.txt +
; alpn_cred_0.txt + alpn_ctxc_0.txt)**. The three doors are closed and the constant stays at 0 so no
; code can rely on it:
;   SetContextAttributes before the first leg (zero context): 0x80090301 for all 120 ids;
;   SetContextAttributes after the first leg (live context): 113 ids at 0x80090302, 4 at 0x8009035D,
;     2 at 0x80090304, 1 at 0x80090321 (id 16, and neither cbBuffer=2 nor cbBuffer=1024 changes it);
;     NO SEC_E_OK at all;
;   SetCredentialsAttributesW: 119 times 0x80090302 and a SEGFAULT at id=2.
; A second leg without input does not regenerate the ClientHello either: len2=len1=171 bytes,
; identical bytes, SEC_E_INCOMPLETE_MESSAGE. The constant 31 inherited from the documentation was
; therefore a second "55". NAMED limitation of the product, with no consequence: RFC 6455 negotiates
; the subprotocol in the HTTP header Sec-WebSocket-Protocol, not in a TLS extension.
Global Const $Tls_SecPkgAttrApplicationProtocol = 0
; MEASURE probe_cert 2026-11-14 (x86): 55 returns SEC_E_UNSUPPORTED_FUNCTION, it is 83 that returns
; the peer's CERT_CONTEXT POINTER. The written documentation numbers it 0x53: 0x53 = 83 IN DECIMAL.
; Same mistake for CONNECTION_INFO 0x5A = 90.
Global Const $Tls_SecPkgAttrRemoteCertContext = 83
Global Const $Tls_SecPkgAttrConnectionInfo = 90

; -----------------------------------------------------------------------------
; Chain validation (crypt32): ids and codes MEASURED, see the _Tls_VerifyChain section below. No
; invented name: the texts come from FormatMessageW on this machine.
; -----------------------------------------------------------------------------
Global Const $Tls_PolicySslId = 4  ; V4: the only id whose verdict depends on the name
Global Const $Tls_AuthTypeServer = 2  ; V5: the only dwAuthType that checks the name
; V8: 0x100 on the fdwChecks side, 0x10 on the dwFlags side. Same measured effect, one OR the other.
Global Const $Tls_SslFdIgnoreUntrustedRoot = 0x100
Global Const $Tls_PolicyFlagIgnoreUntrustedRoot = 0x10
Global Const $Tls_CertEUntrustedRoot = 0x800B0109
Global Const $Tls_CertECnNoMatch = 0x800B010F
Global Const $Tls_CertEInvalidUsage = 0x800B0110
Global Const $Tls_CertEExpired = 0x800B0101

Global Const $Tls_SecEOk = 0
Global Const $Tls_SecIContinueNeeded = 0x00090312
Global Const $Tls_SecICompleteNeeded = 0x00090313
Global Const $Tls_SecICompleteAndContinue = 0x00090314
Global Const $Tls_SecIRenegotiate = 0x00090561
Global Const $Tls_SecEIncompleteMessage = 0x80090318  ; measure probe_dec D5
Global Const $Tls_SecEInvalidHandle = 0x80090301
Global Const $Tls_SecIContextExpired = 0x00091092

Global Const $Tls_IscReqReplayDetect = 0x00000004
Global Const $Tls_IscReqSequenceDetect = 0x00000008
Global Const $Tls_IscReqConfidentiality = 0x00000010
Global Const $Tls_IscReqAllocateMemory = 0x00000100

; The two SCHANNEL_CRED fields that really matter (1-based positions).
Global Const $Tls_CredFieldVersion = 1
Global Const $Tls_CredFieldFlags = 13

; Slot states
Global Const $Tls_ST_FREE = 0
Global Const $Tls_ST_HANDSHAKE = 1
Global Const $Tls_ST_OPEN = 2
Global Const $Tls_ST_CLOSING = 3
Global Const $Tls_ST_DEAD = 4
Global Const $Tls_ST_PEER_CLOSED = 5

Global Const $g_iTlsSlots = 8
Global Const $g_iTlsRxSize = 65536 + 32768
Global Const $g_iTlsClearSize = 262144
Global Const $g_iTlsReadCapDefault = 32768

; ALPN (measure probe_alpn.au3, see _Tls_SetAlpn). Empty list = nothing is emitted, so the behaviour
; inherited from spike4 stays exact.
Global $g_sTlsAlpn = ""
Global $g_iTlsAlpnAttr = 0
Global $g_iTlsAlpnMode = 1 ; 1 = SetContextAttributes, 2 = SetCredentialsAttributes
Global $g_sTlsAlpnInfo = ""

Global $g_aTls_State[$g_iTlsSlots]
Global $g_aTls_Sock[$g_iTlsSlots]
Global $g_aTls_Sni[$g_iTlsSlots]
Global $g_aTls_Cred[$g_iTlsSlots] ; structs SecHandle
Global $g_aTls_Ctx[$g_iTlsSlots]
Global $g_aTls_HaveCtx[$g_iTlsSlots]
Global $g_aTls_Bufs[$g_iTlsSlots] ; 4 contiguous SecBuffer entries
Global $g_aTls_Desc[$g_iTlsSlots]
Global $g_aTls_Out[$g_iTlsSlots]  ; byte[] recipient of tokens and encrypted records
Global $g_aTls_Raw[$g_iTlsSlots]  ; network bytes not consumed yet
Global $g_aTls_RawLen[$g_iTlsSlots]
Global $g_aTls_TxPend[$g_iTlsSlots] ; bytes still pending on the wire (tokens + records)
Global $g_aTls_Clear[$g_iTlsSlots]  ; decrypted clear bytes, not taken yet
Global $g_aTls_ClearLen[$g_iTlsSlots]
Global $g_aTls_Hdr[$g_iTlsSlots]
Global $g_aTls_Trailer[$g_iTlsSlots]
Global $g_aTls_MaxMsg[$g_iTlsSlots]
Global $g_aTls_Err[$g_iTlsSlots]  ; last named diagnostic line
Global $g_aTls_BytesIn[$g_iTlsSlots]
Global $g_aTls_BytesOut[$g_iTlsSlots]
Global $g_aTls_Records[$g_iTlsSlots]
Global $g_aTls_Incomplete[$g_iTlsSlots]
Global $g_aTls_HandshakeMs[$g_iTlsSlots]  ; FINISHED duration (0 = not yet)
Global $g_aTls_HsTimer[$g_iTlsSlots]  ; TimerInit of the handshake in progress
Global $g_aTls_RxTrace[$g_iTlsSlots]  ; successive network read sizes
Global $g_aTls_ReadCap[$g_iTlsSlots]  ; network read ceiling per slot
Global $g_aTls_Alert[$g_iTlsSlots]       ; derniere alerte recue : level/description
Global $g_aTls_Inbound[$g_iTlsSlots]  ; 1 = this slot IS the server (AcceptSecurityContext)
Global $g_aTls_OwnCred[$g_iTlsSlots]  ; 0 = the credential is shared, do not free it
Global $g_iTlsMaxToken = 24576  ; R7: returned by QuerySecurityPackageInfoW
Global $g_sTlsPkgInfo = ""
Global $g_sTlsFatalErr = ""  ; last error with no slot possible (start-up)

; Server credential shared by every inbound slot (measure probe_srvcred).
Global $g_tTlsSrvCredH = 0  ; SecHandle of the acquired INBOUND credential
Global $g_tTlsSrvCred = 0  ; SCHANNEL_CRED that must stay alive
Global $g_tTlsSrvArr = 0  ; array of PCCERT_CONTEXT
Global $g_hTlsSrvStore = 0  ; in-memory HCERTSTORE built from the PFX
Global $g_pTlsSrvCert = 0  ; CERT_CONTEXT of the server certificate
Global $g_sTlsSrvInfo = ""

;#FUNCTION#=====================================================================================================================
; Name ..........: _Tls_HexD
; Description ...: Render a value as an unsigned 32-bit hexadecimal SSPI code.
; Syntax ........: _Tls_HexD($i)
; Parameters ....: $i                    - value to mask, may arrive signed from a "dword" read
; Return values .: Success - String "0xXXXXXXXX".
; Author ........: Numeric1
; Remarks .......: Measure: a DWORD read in AutoIt comes back unsigned while the SDK literal is signed, so both must be put in the same space before any comparison.
; Related .......: _Tls_SecName
;===============================================================================================================================
Func _Tls_HexD($i)
    Return "0x" & Hex(BitAND($i, 0xFFFFFFFF), 8)
EndFunc   ;==>_Tls_HexD

;#FUNCTION#=====================================================================================================================
; Name ..........: _Tls_SecName
; Description ...: Known SSPI name of a status code, from the measured table of this layer.
; Syntax ........: _Tls_SecName($iCode)
; Parameters ....: $iCode                - status code returned by a secur32.dll call
; Return values .: Success - Name such as "SEC_I_CONTINUE_NEEDED", "?" when the code is not in the table.
; Author ........: Numeric1
; Remarks .......: Rule R8: the name only covers codes this project actually measured; the Windows text comes from _Tls_SecText.
; Related .......: _Tls_SecText, _Tls_SecDesc
;===============================================================================================================================
; R8: the NAME comes from Windows, not from my memory.
Func _Tls_SecName($iCode)
    Switch BitAND($iCode, 0xFFFFFFFF)
        Case $Tls_SecEOk
            Return "SEC_E_OK"
        Case $Tls_SecIContinueNeeded
            Return "SEC_I_CONTINUE_NEEDED"
        Case $Tls_SecICompleteNeeded
            Return "SEC_I_COMPLETE_NEEDED"
        Case $Tls_SecICompleteAndContinue
            Return "SEC_I_COMPLETE_AND_CONTINUE"
        Case $Tls_SecIRenegotiate
            Return "SEC_I_RENEGOTIATE"
        Case $Tls_SecEIncompleteMessage
            Return "SEC_E_INCOMPLETE_MESSAGE"
        Case $Tls_SecEInvalidHandle
            Return "SEC_E_INVALID_HANDLE"
        Case $Tls_SecIContextExpired
            Return "SEC_I_CONTEXT_EXPIRED"
        Case Else
            Return "?"
    EndSwitch
EndFunc   ;==>_Tls_SecName

;#FUNCTION#=====================================================================================================================
; Name ..........: _Tls_SecText
; Description ...: Windows text of an SSPI status code, asked through FormatMessageW.
; Syntax ........: _Tls_SecText($iCode)
; Parameters ....: $iCode                - status code to look up
; Return values .: Success - Stripped text, "" when Windows has nothing for this code.
; Author ........: Numeric1
; Remarks .......: No SDK header exists on the build machine, so the wording is always Windows' own, never a remembered string.
; Related .......: _Tls_SecName
;===============================================================================================================================
Func _Tls_SecText($iCode)
    Local $t = DllStructCreate("wchar[512]")
    Local $a = DllCall("kernel32.dll", "dword", "FormatMessageW", _
            "dword", 0x1000 + 0x200, "ptr", 0, "dword", BitAND($iCode, 0xFFFFFFFF), _
            "dword", 0, "ptr", DllStructGetPtr($t), "dword", 512, "ptr", 0)
    If @error Or $a[0] = 0 Then Return ""
    Return StringStripWS(DllStructGetData($t, 1), 3)
EndFunc   ;==>_Tls_SecText

;#FUNCTION#=====================================================================================================================
; Name ..........: _Tls_SecDesc
; Description ...: One complete diagnostic for a status code: value, known name, Windows text.
; Syntax ........: _Tls_SecDesc($iCode)
; Parameters ....: $iCode                - status code to describe
; Return values .: Success - String such as "0x80090301 SEC_E_INVALID_HANDLE [the handle is invalid]".
; Author ........: Numeric1
; Related .......: _Tls_SecName, _Tls_SecText
;===============================================================================================================================
; One complete diagnostic line: value, known name, Windows text.
Func _Tls_SecDesc($iCode)
    Local $s = _Tls_HexD($iCode) & " " & _Tls_SecName($iCode)
    Local $t = _Tls_SecText($iCode)
    If $s = "?" Or $t <> "" Then $s &= " [" & $t & "]"
    Return $s
EndFunc   ;==>_Tls_SecDesc

;#FUNCTION#=====================================================================================================================
; Name ..........: _Tls_StateName
; Description ...: English name of a layer 2 slot state.
; Syntax ........: _Tls_StateName($i)
; Parameters ....: $i                    - one of $Tls_ST_FREE, $Tls_ST_HANDSHAKE, $Tls_ST_OPEN, $Tls_ST_CLOSING, $Tls_ST_DEAD, $Tls_ST_PEER_CLOSED
; Return values .: Success - "free", "handshake", "open", "closing", "dead", "closed_by_peer" or "?N".
; Author ........: Numeric1
; Related .......: _Tls_State, _Tls_Info
;===============================================================================================================================
Func _Tls_StateName($i)
    Switch $i
        Case $Tls_ST_FREE
            Return "free"
        Case $Tls_ST_HANDSHAKE
            Return "handshake"
        Case $Tls_ST_OPEN
            Return "open"
        Case $Tls_ST_CLOSING
            Return "closing"
        Case $Tls_ST_DEAD
            Return "dead"
        Case $Tls_ST_PEER_CLOSED
            Return "closed_by_peer"
        Case Else
            Return "?" & $i
    EndSwitch
EndFunc   ;==>_Tls_StateName

;#FUNCTION#=====================================================================================================================
; Name ..........: _Tls_SetErr
; Description ...: Store the last diagnostic line of a slot, or in the global fallback before any slot exists.
; Syntax ........: _Tls_SetErr($iIdx, $s)
; Parameters ....: $iIdx                 - slot index, or -1 / an out-of-range value for a start-up error
;                  $s                    - diagnostic line
; Return values .: Success - 1.
;                  Failure - 0 = index out of table, the text then goes to $g_sTlsFatalErr.
; Author ........: Numeric1
; Remarks .......: An error can arrive before any slot (WSAStartup, QuerySecurityPackageInfoW, shared credential); without a global landing place its text was thrown away and the caller only saw a step number.
; Related .......: _Tls_FatalErr, _Tls_Info
;===============================================================================================================================
Func _Tls_SetErr($iIdx, $s)
    If $iIdx >= 0 And $iIdx < $g_iTlsSlots Then
        $g_aTls_Err[$iIdx] = $s
    Else
        ; An error sometimes arrives BEFORE any slot (WSAStartup, QuerySecurityPackageInfo,
        ; shared credential): without a global landing place its text was thrown away and the
        ; caller only saw a step number.
        $g_sTlsFatalErr = $s
    EndIf
EndFunc   ;==>_Tls_SetErr

;#FUNCTION#=====================================================================================================================
; Name ..........: _Tls_FatalErr
; Description ...: Diagnostic text stored when no slot existed yet.
; Syntax ........: _Tls_FatalErr() :None
; Return values .: Success - String, "" when nothing was recorded.
; Author ........: Numeric1
; Remarks .......: Written by _Tls_SetErr(-1, ...), read by the caller after a failing _Tls_Startup or _Tls_SrvPrepare.
; Related .......: _Tls_SetErr
;===============================================================================================================================
Func _Tls_FatalErr()
    Return $g_sTlsFatalErr
EndFunc   ;==>_Tls_FatalErr

;#FUNCTION#=====================================================================================================================
; Name ..........: _Tls_WriteAt
; Description ...: Copy a binary block at an absolute address using an overlay struct.
; Syntax ........: _Tls_WriteAt($p, $b)
; Parameters ....: $p                    - destination address
;                  $b                    - bytes to write
; Return values .: Success - Number of bytes written.
;                  Failure - @error 1 = unusable address, 2 = the write itself failed.
; Author ........: Numeric1
; Remarks .......: Measure probe_raw (x86 AND x64): DllStructSetData with a start index writes ONLY the first byte and drops the rest, so the overlay is the only path that writes n bytes.
; Related .......: _Tls_PokeD, _Tls_AppendRaw
;===============================================================================================================================
; Write $b at offset $p. NO DllStructSetData with a start index: measured (probe_raw, x86 AND x64) -
; DllStructSetData($t,1,Binary("0x998877"),5) writes ONLY the first byte 0x99 and DROPS 8877. The
; overlay (a struct created ON the target pointer) is the only path that writes the n bytes.
Func _Tls_WriteAt($p, $b)
    Local $n = BinaryLen($b)
    If $n = 0 Then Return 1
    Local $t = DllStructCreate("byte[" & $n & "]", $p)
    If @error Then Return SetError(1, 0, 0)
    DllStructSetData($t, 1, $b)
    If @error Then Return SetError(2, 0, 0)
    Return $n
EndFunc   ;==>_Tls_WriteAt

;#FUNCTION#=====================================================================================================================
; Name ..........: _Tls_ConsumeRaw
; Description ...: Shift the input queue of a slot by the bytes already handed to Schannel.
; Syntax ........: _Tls_ConsumeRaw($iIdx, $n)
; Parameters ....: $iIdx                 - slot index
;                  $n                    - bytes consumed at the head of Raw
; Return values .: Success - No meaningful return value.
; Author ........: Numeric1
; Related .......: _Tls_AppendRaw, _Tls_HandshakeLeg
;===============================================================================================================================
; Shift the input queue by the $n consumed bytes.
Func _Tls_ConsumeRaw($iIdx, $n)
    Local $cur = $g_aTls_RawLen[$iIdx]
    If $n <= 0 Or $n >= $cur Then
        If $n > 0 Then $g_aTls_RawLen[$iIdx] = 0
        Return
    EndIf
    Local $tRaw = $g_aTls_Raw[$iIdx]
    Local $b = BinaryMid(DllStructGetData($tRaw, 1), $n + 1, $cur - $n)
    DllStructSetData($tRaw, 1, $b)
    $g_aTls_RawLen[$iIdx] = $cur - $n
EndFunc   ;==>_Tls_ConsumeRaw

;#FUNCTION#=====================================================================================================================
; Name ..........: _Tls_AppendRaw
; Description ...: Append bytes read from the network at the tail of Raw.
; Syntax ........: _Tls_AppendRaw($iIdx, $b)
; Parameters ....: $iIdx                 - slot index
;                  $b                    - bytes coming from the socket
; Return values .: Success - Number of bytes added.
;                  Failure - @error 1 = Raw full (decrypt before reading more), 2 = the write failed.
; Author ........: Numeric1
; Related .......: _Tls_PullRaw, _Tls_CompletePrefix
;===============================================================================================================================
Func _Tls_AppendRaw($iIdx, $b)
    Local $iLen = $g_aTls_RawLen[$iIdx]
    Local $n = BinaryLen($b)
    If $n = 0 Then Return 0
    If $iLen + $n > $g_iTlsRxSize Then Return SetError(1, 0, 0)  ; buffer full
    Local $w = _Tls_WriteAt(DllStructGetPtr($g_aTls_Raw[$iIdx]) + $iLen, $b)
    If @error Then Return SetError(2, 0, 0)
    $g_aTls_RxTrace[$iIdx] &= "/" & $n
    $g_aTls_RawLen[$iIdx] = $iLen + $n
    Return $n
EndFunc   ;==>_Tls_AppendRaw

;#FUNCTION#=====================================================================================================================
; Name ..........: _Tls_PushTx
; Description ...: Queue encrypted bytes waiting for the wire.
; Syntax ........: _Tls_PushTx($iIdx, $b)
; Parameters ....: $iIdx                 - slot index
;                  $b                    - encrypted bytes (record plus header)
; Return values .: Success - Number of bytes queued.
;                  Failure - 0 = empty input.
; Author ........: Numeric1
; Related .......: _Tls_FlushTx, _Tls_PendingTx
;===============================================================================================================================
Func _Tls_PushTx($iIdx, $b)
    If BinaryLen($b) = 0 Then Return 0
    $g_aTls_TxPend[$iIdx] &= $b
    Return BinaryLen($b)
EndFunc   ;==>_Tls_PushTx

;#FUNCTION#=====================================================================================================================
; Name ..........: _Tls_SetBuf
; Description ...: Fill one SecBuffer of the descriptor owned by a slot.
; Syntax ........: _Tls_SetBuf($iIdx, $i, $iCb, $iType, $pPtr)
; Parameters ....: $iIdx                 - slot index
;                  $i                    - buffer slot, 0..3 (SEC_INTEGER_64_BUFFER_SIZE descriptors are 4)
;                  $iCb                  - byte count
;                  $iType                - SecBuffer type ($Tls_SecBufferToken, $Tls_SecBufferData, ...)
;                  $pPtr                 - address of the data, or 0 to let Schannel allocate
; Return values .: Success - No meaningful return value.
; Author ........: Numeric1
; Related .......: _Tls_GetCb, _Tls_GetType, _Tls_GetPtr
;===============================================================================================================================
; Fill a descriptor of 4 SecBuffer from an array of (cb,type,ptr).
Func _Tls_SetBuf($iIdx, $i, $iCb, $iType, $pPtr)
    Local $t = $g_aTls_Bufs[$iIdx]
    DllStructSetData($t, $i * 3 + 1, $iCb)
    DllStructSetData($t, $i * 3 + 2, $iType)
    DllStructSetData($t, $i * 3 + 3, $pPtr)
EndFunc   ;==>_Tls_SetBuf

;#FUNCTION#=====================================================================================================================
; Name ..........: _Tls_GetCb
; Description ...: Byte count of buffer $i as rewritten by Schannel.
; Syntax ........: _Tls_GetCb($iIdx, $i)
; Parameters ....: $iIdx                 - slot index
;                  $i                    - buffer slot, 0..3
; Return values .: Success - DWORD value (unsigned).
; Author ........: Numeric1
; Remarks .......: Measure DD1: DecryptMessage rewrites the descriptor, so the counts must be read back after the call, never assumed.
; Related .......: _Tls_SetBuf
;===============================================================================================================================
Func _Tls_GetCb($iIdx, $i)
    Return DllStructGetData($g_aTls_Bufs[$iIdx], $i * 3 + 1)
EndFunc   ;==>_Tls_GetCb

;#FUNCTION#=====================================================================================================================
; Name ..........: _Tls_GetType
; Description ...: SecBuffer type of buffer $i as rewritten by Schannel.
; Syntax ........: _Tls_GetType($iIdx, $i)
; Parameters ....: $iIdx                 - slot index
;                  $i                    - buffer slot, 0..3
; Return values .: Success - DWORD value (unsigned).
; Author ........: Numeric1
; Remarks .......: Look for the buffer of TYPE DATA, never index 0 (DD1).
; Related .......: _Tls_SetBuf
;===============================================================================================================================
Func _Tls_GetType($iIdx, $i)
    Return DllStructGetData($g_aTls_Bufs[$iIdx], $i * 3 + 2)
EndFunc   ;==>_Tls_GetType

;#FUNCTION#=====================================================================================================================
; Name ..........: _Tls_GetPtr
; Description ...: Address of buffer $i as rewritten by Schannel.
; Syntax ........: _Tls_GetPtr($iIdx, $i)
; Parameters ....: $iIdx                 - slot index
;                  $i                    - buffer slot, 0..3
; Return values .: Success - DWORD/pointer value.
; Author ........: Numeric1
; Related .......: _Tls_SetBuf
;===============================================================================================================================
Func _Tls_GetPtr($iIdx, $i)
    Return DllStructGetData($g_aTls_Bufs[$iIdx], $i * 3 + 3)
EndFunc   ;==>_Tls_GetPtr

;#FUNCTION#=====================================================================================================================
; Name ..........: _Tls_Startup
; Description ...: Start layer 2: WSAStartup plus the token size and capabilities returned by the security package.
; Syntax ........: _Tls_Startup() :None
; Return values .: Success - 1.
;                  Failure - @error 1 = Winsock start-up failed, 2 = QuerySecurityPackageInfoW failed (@extended and _Tls_FatalErr carry the text).
; Author ........: Numeric1
; Remarks .......: Rule R7: EnumSecurityPackagesW is not exported by secur32.dll nor sspicli.dll on this machine, so cbMaxToken comes from QuerySecurityPackageInfoW (measured 24576). The SECURITY_PACKAGE_INFO32/64 read step is 20 in x86 and 32 in x64.
; Related .......: _Tls_PkgInfo, _Wsk_Startup
;===============================================================================================================================
; =============================================================================
; Start-up: WSAStartup plus the token size returned by the package (R7).
; =============================================================================
Func _Tls_Startup()
    Local $r = _Wsk_Startup()
    If @error Then Return SetError(1, 0, 0)
    Local $tInfo = DllStructCreate("ptr")
    Local $a = DllCall("secur32.dll", "dword", "QuerySecurityPackageInfoW", _
            "wstr", $g_sTlsPkg, "ptr", DllStructGetPtr($tInfo))
    Local $e = @error
    If $e Or $a[0] <> 0 Then
        _Tls_SetErr(-1, "QuerySecurityPackageInfoW " & (@error ? "DllCall err " & $e : _Tls_SecDesc($a[0])))
        Return SetError(2, 0, 0)
    EndIf
    Local $p = DllStructGetData($tInfo, 1)
    Local $iStep = 0
    If @AutoItX64 Then
        $iStep = 32
    Else
        $iStep = 20
    EndIf
    Local $tRec = DllStructCreate("dword;word;word;dword;ptr;ptr", $p)
    Local $pName = DllStructGetData($tRec, 5)
    Local $tName = DllStructCreate("wchar[64]", $pName)
    $g_iTlsMaxToken = DllStructGetData($tRec, 4)
    $g_sTlsPkgInfo = "caps=" & _Tls_HexD(DllStructGetData($tRec, 1)) & _
            " wVersion=" & DllStructGetData($tRec, 2) & _
            " wRPCID=" & DllStructGetData($tRec, 3) & _
            " cbMaxToken=" & $g_iTlsMaxToken & _
            " step=" & $iStep & " name=[" & DllStructGetData($tName, 1) & "]"
    Local $f = DllCall("secur32.dll", "dword", "FreeContextBuffer", "ptr", $p)
    If @error Or $f[0] <> 0 Then $g_sTlsPkgInfo &= " freeInfo=" & (@error ? "err" : _Tls_SecDesc($f[0]))
    Return 1
EndFunc   ;==>_Tls_Startup

;#FUNCTION#=====================================================================================================================
; Name ..........: _Tls_Cleanup
; Description ...: Close every open slot and release Winsock.
; Syntax ........: _Tls_Cleanup() :None
; Return values .: Success - No meaningful return value.
; Author ........: Numeric1
; Related .......: _Tls_Close, _Wsk_Cleanup
;===============================================================================================================================
Func _Tls_Cleanup()
    For $i = 0 To $g_iTlsSlots - 1
        If $g_aTls_State[$i] <> $Tls_ST_FREE Then _Tls_Close($i)
    Next
    _Wsk_Cleanup()
EndFunc   ;==>_Tls_Cleanup

;#FUNCTION#=====================================================================================================================
; Name ..........: _Tls_PkgInfo
; Description ...: One-line description of the security package as Windows returned it.
; Syntax ........: _Tls_PkgInfo() :None
; Return values .: Success - String with caps, wVersion, wRPCID, cbMaxToken, struct step and package name.
; Author ........: Numeric1
; Related .......: _Tls_Startup
;===============================================================================================================================
Func _Tls_PkgInfo()
    Return $g_sTlsPkgInfo
EndFunc   ;==>_Tls_PkgInfo

;#FUNCTION#=====================================================================================================================
; Name ..........: _Tls_AcqCred
; Description ...: Acquire the client credential for a slot.
; Syntax ........: _Tls_AcqCred($iIdx, $fManual)
; Parameters ....: $iIdx                 - slot index that will own the credential
;                  $fManual              - True = SCH_CRED_MANUAL_CRED_VALIDATION, the stack does not validate the chain and layer 2 does it with CertGetCertificateChain
; Return values .: Success - 1, @extended = the dwFlags actually passed.
;                  Failure - @error 1 = DllCall failure, 2 = SSPI refusal (@extended = the raw status code).
; Author ........: Numeric1
; Remarks .......: Rules R2/R3: SCHANNEL_CRED.dwVersion must be 3, 4 or 5 or AcquireCredentialsHandle returns SEC_E_UNKNOWN_CREDENTIALS 0x8009030D; the dwFlags combinations tested all succeed once dwVersion is correct.
; Related .......: _Tls_Connect, _Tls_InitSlot
;===============================================================================================================================
; =============================================================================
; Acquisition of the client credential. $fManual = 1 -> the stack does NOT validate the chain (it is
; validated by the calling layer, see CertGetCertificateChain).
; =============================================================================
Func _Tls_AcqCred($iIdx, $fManual)
    Local $iFlags = BitOR($Tls_SchUseStrongCrypto, $Tls_SchCredNoDefaultCreds)
    If $fManual Then $iFlags = BitOR($iFlags, $Tls_SchCredManualCredValidation)
    Local $tCred = DllStructCreate($g_sTlsSpecCred)
    DllStructSetData($tCred, $Tls_CredFieldVersion, $Tls_SchCredVersion)
    DllStructSetData($tCred, $Tls_CredFieldFlags, $iFlags)
    Local $tH = DllStructCreate($g_sTlsSpecHandle)
    Local $tExp = DllStructCreate("dword;dword")
    Local $a = DllCall("secur32.dll", "dword", "AcquireCredentialsHandleW", _
            "ptr", 0, "wstr", $g_sTlsPkg, "dword", $Tls_SecPkgCredOutbound, "ptr", 0, _
            "ptr", DllStructGetPtr($tCred), "ptr", 0, "ptr", 0, _
            "ptr", DllStructGetPtr($tH), "ptr", DllStructGetPtr($tExp))
    If @error Then
        _Tls_SetErr($iIdx, "AcquireCredentialsHandle DllCall err " & @error)
        Return SetError(1, 0, 0)
    EndIf
    If $a[0] <> $Tls_SecEOk Then
        _Tls_SetErr($iIdx, "AcquireCredentialsHandle " & _Tls_SecDesc($a[0]))
        Return SetError(2, $a[0], 0)
    EndIf
    $g_aTls_Cred[$iIdx] = $tH
    $g_aTls_Ctx[$iIdx] = DllStructCreate($g_sTlsSpecHandle)
    $g_aTls_HaveCtx[$iIdx] = 0
    Return SetError(0, $iFlags, 1)
EndFunc   ;==>_Tls_AcqCred

;#FUNCTION#=====================================================================================================================
; Name ..........: _Tls_AlpnBlob
; Description ...: Build the ALPN ProtocolNameList blob (RFC 7301) wrapped in a native DWORD.
; Syntax ........: _Tls_AlpnBlob($sList)
; Parameters ....: $sList                - comma-separated ids, e.g. "chat,http/1.1"
; Return values .: Success - The DllStruct holding the blob.
;                  Failure - @error 1 = one id longer than 255 bytes, 2 = empty list, 3 or 4 = struct write failure.
; Author ........: Numeric1
; Related .......: _Tls_SetAlpn
;===============================================================================================================================
; ALPN blob: {DWORD what follows}{WORD total length}{BYTE n ; n ASCII}*
; That is exactly the wire ProtocolNameList (RFC 7301) wrapped in a native DWORD. $sList =
; "chat,http/1.1". Returns the DllStruct, 0 + @error otherwise.
Func _Tls_AlpnBlob($sList)
    Local $a = StringSplit($sList, ",")
    Local $b = Binary("0x")
    For $i = 1 To $a[0]
        Local $s = StringStripWS($a[$i], 8)
        If $s = "" Then ContinueLoop
        Local $n = StringLen($s)
        If $n > 255 Then Return SetError(1, $n, 0)
        $b &= Binary("0x" & Hex($n, 2)) & StringToBinary($s, 1)
    Next
    Local $tot = BinaryLen($b)
    If $tot = 0 Then Return SetError(2, 0, 0)
    Local $t = DllStructCreate("dword;word;byte[" & $tot & "]")
    If @error Then Return SetError(3, 0, 0)
    DllStructSetData($t, 1, $tot + 2)
    DllStructSetData($t, 2, $tot)
    DllStructSetData($t, 3, $b)
    If @error Then Return SetError(4, 0, 0)
    Return $t
EndFunc   ;==>_Tls_AlpnBlob

;#FUNCTION#=====================================================================================================================
; Name ..........: _Tls_SetAlpn
; Description ...: Emit an ALPN extension on a slot before the first handshake leg.
; Syntax ........: _Tls_SetAlpn($iIdx, $iAttr, $sList[, $iMode])
; Parameters ....: $iIdx                 - slot index
;                  $iAttr                - attribute id to try
;                  $sList                - comma-separated protocol ids
;                  $iMode                - [optional] 1 = SetContextAttributesW, 2 = SetCredentialsAttributesW
; Return values .: Success - 1.
;                  Failure - @error 1 = refused list (@extended = _Tls_AlpnBlob code), 2 = SetContextAttributesW missing, 3 = SSPI refusal (@extended = status code).
; Author ........: Numeric1
; Remarks .......: MEASURED CLOSED DOOR (probe_alpn, 2026-11-14): mode 1 returns 0x80090301 for all 120 ids on the zero context, mode 2 returns 0x80090302 for 119 ids and segfaults at id 2; after the first leg 113 ids give 0x80090302. No id ever returns SEC_E_OK on this machine. RFC 6455 negotiates the subprotocol in the HTTP header anyway, so this failure is harmless and is only logged.
; Related .......: _Tls_AlpnBlob, _Tls_Connect
;===============================================================================================================================
; Emit ALPN on a context NOT INITIALISED YET (the handle is zero: the first ISC leg creates it). Call
; it between AcquireCredentialsHandle and the first InitializeSecurityContext, otherwise the
; ClientHello is already gone without the extension. @error 1 = refused list, 2 = missing export,
; 3 = SSPI refusal (reason in @extended).
;
; MODE is a measurement, not an aesthetic choice (probe_alpn, 2026-11-14):
;   1 = SetContextAttributesW on the zero context -> **0x80090301 SEC_E_INVALID_HANDLE for all 120
;       ids tried**, in x86. The context does not exist before the first leg, so this door is closed
;       here.
;   2 = SetCredentialsAttributesW on the freshly acquired credential.
Func _Tls_SetAlpn($iIdx, $iAttr, $sList, $iMode = 1)
    Local $t = _Tls_AlpnBlob($sList)
    If @error Then Return SetError(1, @error, 0)
    Local $a
    If $iMode = 2 Then
        $a = DllCall("secur32.dll", "dword", "SetCredentialsAttributesW", _
                "ptr", DllStructGetPtr($g_aTls_Cred[$iIdx]), "dword", $iAttr, _
                "ptr", DllStructGetPtr($t), "dword", DllStructGetSize($t))
    Else
        $a = DllCall("secur32.dll", "dword", "SetContextAttributesW", _
                "ptr", DllStructGetPtr($g_aTls_Ctx[$iIdx]), "dword", $iAttr, _
                "ptr", DllStructGetPtr($t), "dword", DllStructGetSize($t))
    EndIf
    If @error Then Return SetError(2, 0, 0)
    Local $rc = BitAND($a[0], 0xFFFFFFFF)
    If $rc <> 0 Then Return SetError(3, $rc, 0)
    Return DllStructGetSize($t)
EndFunc   ;==>_Tls_SetAlpn

;#FUNCTION#=====================================================================================================================
; Name ..........: _Tls_Connect
; Description ...: Open a non-blocking TCP socket and place the first handshake leg (the ClientHello is produced here).
; Syntax ........: _Tls_Connect($sAddr, $iPort, $sSni, $iTimeoutMs[, $fManual[, $hReady]])
; Parameters ....: $sAddr                - peer address, IPv4 or IPv6 text form
;                  $iPort                - peer TCP port
;                  $sSni                 - host name sent as SNI and used later for the certificate policy
;                  $iTimeoutMs           - poll budget for the connect finish, in milliseconds
;                  $fManual              - [optional] True = manual chain validation for this credential
;                  $hReady               - [optional] socket already connected by the caller, -1 = let layer 2 connect
; Return values .: Success - Slot index >= 0.
;                  Failure - @error 1 = no free slot, 2 = socket creation, 3 = FIONBIO, 4 = connect (@extended = step), 5 = connect finish, 6 = credential acquisition, 7 = first leg (@extended = inner step).
; Author ........: Numeric1
; Remarks .......: Rule R4: no network is needed to produce a ClientHello, InitializeSecurityContext with no input byte already returns SEC_I_CONTINUE_NEEDED. Measure C2/C3: "localhost" returns "::1" before "127.0.0.1", so layer 4 walks the GetAddrInfoW list itself and passes the winning socket through $hReady.
; Related .......: _Tls_HandshakeLeg, _Tls_Pump, _Wsk_ConnectAddr
;===============================================================================================================================
; =============================================================================
; Connection: non-blocking TCP then the first handshake leg (the ClientHello is produced here,
; before the socket is even readable).
;
; $hReady: an ALREADY CONNECTED socket supplied by the caller. Measure C2/C3 (spike6\probe_conn.au3,
; 9/9 on both bitnesses): "localhost" returns "::1" BEFORE "127.0.0.1", so layer 4 has to walk the
; list GetAddrInfoW returned and settle on the address that works; it cannot delegate connect() to a
; name. With $hReady, layer 2 no longer touches the socket and layer 4 alone decides which address
; was kept.
; =============================================================================
Func _Tls_Connect($sAddr, $iPort, $sSni, $iTimeoutMs, $fManual = True, $hReady = -1)
    Local $iIdx = -1
    For $i = 0 To $g_iTlsSlots - 1
        If $g_aTls_State[$i] = $Tls_ST_FREE Then
            $iIdx = $i
            ExitLoop
        EndIf
    Next
    If $iIdx < 0 Then Return SetError(1, 0, -1)

    Local $h = $hReady
    If $hReady < 0 Then
        $h = _Wsk_Socket()
        If @error Then
            _Tls_SetErr($iIdx, "socket " & @error)
            Return SetError(2, 0, -1)
        EndIf
        _Wsk_NonBlocking($h, True)
        If @error Then
            _Wsk_Close($h)
            _Tls_SetErr($iIdx, "FIONBIO " & @error)
            Return SetError(3, 0, -1)
        EndIf
        _Wsk_Connect($h, $sAddr, $iPort)
        Local $eC = @error
        Local $xC = @extended
        If $eC > 3 Then ; 0 = connecte illico, 3 = EINPROGRESS a finir ; au-dessus, echec
            _Wsk_Close($h)
            _Tls_SetErr($iIdx, "connect step " & $eC & " " & _Wsk_ErrorName($xC))
            Return SetError(4, $eC, -1)
        EndIf
        Local $f = _Wsk_ConnectFinish($h, $iTimeoutMs)
        If @error Then
            Local $x = @extended
            _Wsk_Close($h)
            _Tls_SetErr($iIdx, "connectFinish err " & @error & " " & _Wsk_ErrorName($x))
            Return SetError(5, @error, -1)
        EndIf
    EndIf

    Local $r = _Tls_AcqCred($iIdx, $fManual)
    If @error Then
        If $hReady < 0 Then _Wsk_Close($h)
        Return SetError(6, @error, -1)
    EndIf

    ; ALPN: mandatory here, the context already exists (zero) and the first leg has not been
    ; placed yet. A failure does not stop the handshake: it is logged in $g_sTlsAlpnInfo and
    ; returned in @extended by the caller.
    If $g_sTlsAlpn <> "" And $g_iTlsAlpnAttr > 0 Then
        Local $iAlpn = _Tls_SetAlpn($iIdx, $g_iTlsAlpnAttr, $g_sTlsAlpn, $g_iTlsAlpnMode)
        If @error Then
            $g_sTlsAlpnInfo = "set echoue mode=" & $g_iTlsAlpnMode & " attr=" & $g_iTlsAlpnAttr & _
                    " err=" & @error & " " & _Tls_SecDesc(@extended)
        Else
            $g_sTlsAlpnInfo = "set ok mode=" & $g_iTlsAlpnMode & " attr=" & $g_iTlsAlpnAttr & _
                    " cb=" & $iAlpn & " liste=[" & $g_sTlsAlpn & "]"
        EndIf
    EndIf

    $g_aTls_Sock[$iIdx] = $h
    $g_aTls_Sni[$iIdx] = $sSni
    _Tls_InitSlot($iIdx)
    $g_aTls_Inbound[$iIdx] = 0
    $g_aTls_OwnCred[$iIdx] = 1

    ; First leg, with no received byte: that is R4, measured.
    Local $iStep = _Tls_HandshakeLeg($iIdx)
    If @error Then
        _Tls_SetErr($iIdx, "leg1 " & $iStep)
        _Tls_Close($iIdx)
        Return SetError(7, $iStep, -1)
    EndIf
    Return SetError(0, 0, $iIdx)
EndFunc   ;==>_Tls_Connect

;#FUNCTION#=====================================================================================================================
; Name ..........: _Tls_InitSlot
; Description ...: Reset a slot completely: state, handles, queues, buffers and counters.
; Syntax ........: _Tls_InitSlot($iIdx)
; Parameters ....: $iIdx                 - slot index
; Return values .: Success - 1.
;                  Failure - @error 1 = index out of table.
; Author ........: Numeric1
; Remarks .......: Called by the client AND by the server: any divergence between the two would be a state bug invisible until the stress test.
; Related .......: _Tls_Connect, _Tls_Accept
;===============================================================================================================================
; Complete reset of a slot. Called by the client AND by the server: any divergence between the two
; would be a state bug invisible until the stress test.
Func _Tls_InitSlot($iIdx)
    $g_aTls_Raw[$iIdx] = DllStructCreate("byte[" & $g_iTlsRxSize & "]")
    $g_aTls_Out[$iIdx] = DllStructCreate("byte[" & ($g_iTlsMaxToken + $g_iTlsRxSize + 1024) & "]")
    $g_aTls_Bufs[$iIdx] = DllStructCreate($g_sTlsSpecBuf4)
    $g_aTls_Desc[$iIdx] = DllStructCreate($g_sTlsSpecDesc)
    DllStructSetData($g_aTls_Desc[$iIdx], 1, 0) ; ulVersion = 0
    DllStructSetData($g_aTls_Desc[$iIdx], 2, 4)
    DllStructSetData($g_aTls_Desc[$iIdx], 3, DllStructGetPtr($g_aTls_Bufs[$iIdx]))
    $g_aTls_Ctx[$iIdx] = DllStructCreate($g_sTlsSpecHandle)
    $g_aTls_HaveCtx[$iIdx] = 0
    $g_aTls_RawLen[$iIdx] = 0
    $g_aTls_TxPend[$iIdx] = Binary("0x")
    $g_aTls_Clear[$iIdx] = Binary("0x")
    $g_aTls_ClearLen[$iIdx] = 0
    $g_aTls_BytesIn[$iIdx] = 0
    $g_aTls_RxTrace[$iIdx] = ""
    $g_aTls_ReadCap[$iIdx] = $g_iTlsReadCapDefault
    $g_aTls_Alert[$iIdx] = ""
    $g_aTls_BytesOut[$iIdx] = 0
    $g_aTls_Records[$iIdx] = 0
    $g_aTls_Incomplete[$iIdx] = 0
    $g_aTls_Err[$iIdx] = ""
    $g_aTls_State[$iIdx] = $Tls_ST_HANDSHAKE
    $g_aTls_HandshakeMs[$iIdx] = 0
    $g_aTls_HsTimer[$iIdx] = TimerInit()
EndFunc   ;==>_Tls_InitSlot

;#FUNCTION#=====================================================================================================================
; Name ..........: _Tls_SrvPrepare
; Description ...: Build the shared INBOUND credential from a PKCS#12 file loaded in memory.
; Syntax ........: _Tls_SrvPrepare($sPfxPath, $sPass)
; Parameters ....: $sPfxPath             - path to the .pfx / .p12 file
;                  $sPass                - password of that file
; Return values .: Success - 1 (already prepared, @error 0 too).
;                  Failure - @error 1 = PFX unreadable, 2 = read failed (@extended = FileRead error), 3 = DllCall failure on PFXImportCertStore, 4 = import refused (@extended = GetLastError), 5 = DllCall failure on CertEnumCertificatesInStore, 6 = no certificate in the store, 7 = DllCall failure on AcquireCredentialsHandle, 8 = SSPI refusal (@extended = status code).
; Author ........: Numeric1
; Remarks .......: Rules DS2/DS3: fCredentialUse 0 and 4 are refused (SEC_E_UNKNOWN_CREDENTIALS), the value is 1 by contract because AcceptSecurityContext does not check the direction; paCred is an ARRAY of PCCERT_CONTEXT with cCreds=1. Nothing is installed in the Windows certificate stores.
; Related .......: _Tls_Accept, _Tls_SrvRelease
;===============================================================================================================================
; =============================================================================
; SERVER HALF (measure probe_srvcred.au3, 15/15 on both bitnesses).
; Rules kept by the measurement, not by the documentation:
;   DS1  the export is called "AcceptSecurityContext", WITHOUT the W suffix (the PE table of
;        secur32.dll does not know "AcceptSecurityContextW": @error 3, the same code as an invented
;        name).
;   DS2  fCredentialUse: 0 and 4 are REFUSED (SEC_E_UNKNOWN_CREDENTIALS 0x8009030E); 1 = INBOUND,
;        2 = OUTBOUND, 3 = both, and all three return SEC_E_OK at acquisition. CAREFUL: ASC does NOT
;        check the direction (an outbound credential succeeds there too) -> the correct value is 1
;        by contract, not because Windows would force it.
;   DS3  the server credential is built from a PKCS#12 loaded IN MEMORY (PFXImportCertStore,
;        temporary store, nothing installed in the Windows stores). paCred is an ARRAY of
;        PCCERT_CONTEXT: cCreds=1 and field 3 = pointer to that array.
;   DS4  one acquired INBOUND credential serves ALL slots: it is copied byte for byte into the
;        slot's SecHandle and never freed by _Tls_Close ($g_aTls_OwnCred = 0). Otherwise closing one
;        connection would free the other connections' credential.
;   DS5  the first flight always belongs to the peer: a server calling ASC with no received byte
;        returns SEC_E_INCOMPLETE_MESSAGE, so _Tls_Accept places no leg (unlike the client, rule R4).
;   DS6  (measure spike8 on a real socket) @error 2 of _Tls_Pump is NOT an error: expired poll or
;        EWOULDBLOCK, the peer's second flight has not arrived yet. A server treating 2 as fatal
;        kills the python peer's handshake on the first turn without data. Only 3 (and 4 on the
;        read side) are endings.
;   DS7  (measure spike8) on this machine (Windows 10 10.0.19045), a Schannel server NEGOTIATES
;        TLS 1.2 with OpenSSL even when the client offers 1.3; the Schannel client, on its side,
;        gets 1.3. The server half therefore never exercised TLS 1.3 records here - that is a
;        measured limitation, not a code choice.
; =============================================================================
Func _Tls_SrvPrepare($sPfxPath, $sPass)
    If $g_tTlsSrvCredH <> 0 Then Return SetError(0, 0, 1) ; already prepared, idempotent
    Local $h = FileOpen($sPfxPath, 16)
    If $h = -1 Then Return SetError(1, 0, 0)
    Local $b = FileRead($h)
    Local $e1 = @error
    FileClose($h)
    If $e1 Or BinaryLen($b) = 0 Then Return SetError(2, $e1, 0)

    Local $tData = DllStructCreate("byte[" & BinaryLen($b) & "]")
    DllStructSetData($tData, 1, $b)
    Local $tBlob = DllStructCreate("dword;ptr")
    DllStructSetData($tBlob, 1, BinaryLen($b))
    DllStructSetData($tBlob, 2, DllStructGetPtr($tData))
    Local $a = DllCall("crypt32.dll", "handle", "PFXImportCertStore", _
            "ptr", DllStructGetPtr($tBlob), "wstr", $sPass, "dword", 0)
    If @error Then Return SetError(3, @error, 0)
    If $a[0] = 0 Then
        Local $g = DllCall("kernel32.dll", "dword", "GetLastError")
        Return SetError(4, $g[0], 0)
    EndIf
    $g_hTlsSrvStore = $a[0]

    Local $e = DllCall("crypt32.dll", "ptr", "CertEnumCertificatesInStore", "handle", $g_hTlsSrvStore, "ptr", 0)
    If @error Then Return SetError(5, @error, 0)
    If $e[0] = 0 Then Return SetError(6, 0, 0)
    $g_pTlsSrvCert = $e[0]

    $g_tTlsSrvArr = DllStructCreate("ptr[1]")
    DllStructSetData($g_tTlsSrvArr, 1, $g_pTlsSrvCert)
    $g_tTlsSrvCred = DllStructCreate($g_sTlsSpecCred)
    DllStructSetData($g_tTlsSrvCred, $Tls_CredFieldVersion, $Tls_SchCredVersion)
    DllStructSetData($g_tTlsSrvCred, 2, 1) ; cCreds
    DllStructSetData($g_tTlsSrvCred, 3, DllStructGetPtr($g_tTlsSrvArr)) ; paCred
    DllStructSetData($g_tTlsSrvCred, $Tls_CredFieldFlags, 0)

    Local $tH = DllStructCreate($g_sTlsSpecHandle)
    Local $tExp = DllStructCreate("dword;dword")
    Local $c = DllCall("secur32.dll", "dword", "AcquireCredentialsHandleW", _
            "ptr", 0, "wstr", $g_sTlsPkg, "dword", $Tls_SecPkgCredInbound, "ptr", 0, _
            "ptr", DllStructGetPtr($g_tTlsSrvCred), "ptr", 0, "ptr", 0, _
            "ptr", DllStructGetPtr($tH), "ptr", DllStructGetPtr($tExp))
    If @error Then Return SetError(7, @error, 0)
    If $c[0] <> 0 Then Return SetError(8, $c[0], 0)
    $g_tTlsSrvCredH = $tH
    $g_sTlsSrvInfo = "pfx=" & BinaryLen($b) & " o cert=" & $g_pTlsSrvCert & _
            " credStruct=" & DllStructGetSize($g_tTlsSrvCred) & " use=" & $Tls_SecPkgCredInbound
    Return SetError(0, 0, 1)
EndFunc   ;==>_Tls_SrvPrepare

;#FUNCTION#=====================================================================================================================
; Name ..........: _Tls_SrvRelease
; Description ...: Free the shared INBOUND credential and its temporary certificate store.
; Syntax ........: _Tls_SrvRelease() :None
; Return values .: Success - No meaningful return value.
; Author ........: Numeric1
; Remarks .......: Rule DS4: one acquired INBOUND credential serves all slots, so it is released here and never by _Tls_Close.
; Related .......: _Tls_SrvPrepare
;===============================================================================================================================
Func _Tls_SrvRelease()
    If $g_tTlsSrvCredH <> 0 Then
        DllCall("secur32.dll", "dword", "FreeCredentialsHandle", "ptr", DllStructGetPtr($g_tTlsSrvCredH))
        $g_tTlsSrvCredH = 0
    EndIf
    If $g_hTlsSrvStore <> 0 Then
        DllCall("crypt32.dll", "bool", "CertCloseStore", "handle", $g_hTlsSrvStore, "dword", 0)
        $g_hTlsSrvStore = 0
        $g_pTlsSrvCert = 0
    EndIf
EndFunc   ;==>_Tls_SrvRelease

;#FUNCTION#=====================================================================================================================
; Name ..........: _Tls_Accept
; Description ...: Put an already accepted socket into server-handshake state.
; Syntax ........: _Tls_Accept($hSock)
; Parameters ....: $hSock                - socket already returned by accept(), usually through _Wsk_*
; Return values .: Success - Slot index >= 0.
;                  Failure - @error 1 = no free slot, 2 = the server credential was never prepared.
; Author ........: Numeric1
; Remarks .......: Rule DS5: the first flight always belongs to the peer, so no leg is placed here (a server calling AcceptSecurityContext with no received byte returns SEC_E_INCOMPLETE_MESSAGE). Rule DS4: the shared credential handle is copied byte for byte into the slot and $g_aTls_OwnCred stays 0.
; Related .......: _Tls_SrvPrepare, _Tls_HandshakeLeg, _Tls_IsInbound
;===============================================================================================================================
; Take an ALREADY ACCEPTED socket (accept() done by the caller, usually through _Wsk_*) and put it in
; server-handshake state. Returns the slot index.
Func _Tls_Accept($hSock)
    Local $iIdx = -1
    For $i = 0 To $g_iTlsSlots - 1
        If $g_aTls_State[$i] = $Tls_ST_FREE Then
            $iIdx = $i
            ExitLoop
        EndIf
    Next
    If $iIdx < 0 Then Return SetError(1, 0, -1)
    If $g_tTlsSrvCredH = 0 Then
        _Tls_SetErr($iIdx, "server credential not prepared (_Tls_SrvPrepare)")
        Return SetError(2, 0, -1)
    EndIf

    ; Byte-for-byte copy of the shared handle (DS4): the size is the struct's, so identical in x86
    ; (8 bytes) and x64 (16 bytes).
    _Tls_InitSlot($iIdx)
    Local $n = DllStructGetSize($g_tTlsSrvCredH)
    $g_aTls_Cred[$iIdx] = DllStructCreate($g_sTlsSpecHandle)
    Local $tSrc = DllStructCreate("byte[" & $n & "]", DllStructGetPtr($g_tTlsSrvCredH))
    Local $tDst = DllStructCreate("byte[" & $n & "]", DllStructGetPtr($g_aTls_Cred[$iIdx]))
    DllStructSetData($tDst, 1, DllStructGetData($tSrc, 1))
    $g_aTls_Sock[$iIdx] = $hSock
    $g_aTls_Sni[$iIdx] = ""
    $g_aTls_Inbound[$iIdx] = 1
    $g_aTls_OwnCred[$iIdx] = 0
    ; DS5: no leg is placed here, the peer speaks first.
    Return SetError(0, 0, $iIdx)
EndFunc   ;==>_Tls_Accept

;#FUNCTION#=====================================================================================================================
; Name ..........: _Tls_IsInbound
; Description ...: Tell whether a slot is driven by AcceptSecurityContext (server) or InitializeSecurityContext (client).
; Syntax ........: _Tls_IsInbound($iIdx)
; Parameters ....: $iIdx                 - slot index
; Return values .: Success - 1 = server half, 0 = client half or index out of table.
; Author ........: Numeric1
; Related .......: _Tls_Accept, _Tls_HandshakeLeg
;===============================================================================================================================
Func _Tls_IsInbound($iIdx)
    If $iIdx < 0 Or $iIdx >= $g_iTlsSlots Then Return 0
    Return $g_aTls_Inbound[$iIdx]
EndFunc   ;==>_Tls_IsInbound

;#FUNCTION#=====================================================================================================================
; Name ..........: _Tls_RecLen
; Description ...: Total length of the first TLS record at an address (5-byte header plus length field).
; Syntax ........: _Tls_RecLen($p, $n)
; Parameters ....: $p                    - address of the record
;                  $n                    - bytes available at that address
; Return values .: Success - Total size in bytes.
;                  Failure - 0 = the 5 header bytes are not there yet.
; Author ........: Numeric1
; Related .......: _Tls_CompletePrefix, _Tls_TraceRecords
;===============================================================================================================================
; TOTAL length of the first TLS record at $p (5-byte header + length field). Returns 0 when the 5
; bytes are not there yet.
Func _Tls_RecLen($p, $n)
    If $n < 5 Then Return 0
    Local $t = DllStructCreate("byte;byte;byte;byte;byte", $p)
    If @error Then Return 0
    Return 5 + BitShift(DllStructGetData($t, 4), -8) + DllStructGetData($t, 5)
EndFunc   ;==>_Tls_RecLen

;#FUNCTION#=====================================================================================================================
; Name ..........: _Tls_TraceRecords
; Description ...: Describe the TLS record skeleton present in Raw: type, version, length, truncation.
; Syntax ........: _Tls_TraceRecords($iIdx)
; Parameters ....: $iIdx                 - slot index
; Return values .: Success - String with at most 6 records, "" when Raw is empty.
; Author ........: Numeric1
; Remarks .......: Diagnostic only. With a public 8 Ko chain the Certificate record spreads over several reads, and this line is what proves whether the record was whole when it was submitted.
; Related .......: _Tls_CompletePrefix, _Tls_HandshakeLeg
;===============================================================================================================================
; Describe the TLS record skeleton present in Raw: type, version, length, and whether the last record
; is TRUNCATED. One line per record, 6 at most.
Func _Tls_TraceRecords($iIdx)
    Local $n = $g_aTls_RawLen[$iIdx]
    If $n = 0 Then Return "raw empty"
    Local $t = $g_aTls_Raw[$iIdx]
    Local $s = "raw[" & $n & "]="
    Local $i = 1, $k = 0
    While $i + 4 <= $n And $k < 6
        Local $h = DllStructCreate("byte;byte;byte;byte;byte", DllStructGetPtr($t) + $i - 1)
        Local $ty = DllStructGetData($h, 1)
        Local $vm = DllStructGetData($h, 2)
        Local $vn = DllStructGetData($h, 3)
        Local $lg = BitShift(DllStructGetData($h, 4), -8) + DllStructGetData($h, 5)
        $k += 1
        $s &= " {0x" & Hex($ty, 2) & "/" & Hex($vm, 2) & Hex($vn, 2) & "/" & $lg & "}"
        If $i + 4 + $lg > $n Then
            $s &= " TRUNCATED_expected=" & ($i + 4 + $lg - 1) & " have=" & $n
            ExitLoop
        EndIf
        $i += 5 + $lg
    WEnd
    If $i <= $n And $k < 6 Then $s &= " left=" & ($n - $i + 1)
    Return $s
EndFunc   ;==>_Tls_TraceRecords

;#FUNCTION#=====================================================================================================================
; Name ..........: _Tls_CompletePrefix
; Description ...: Count how many bytes at the head of Raw form complete TLS records.
; Syntax ........: _Tls_CompletePrefix($iIdx)
; Parameters ....: $iIdx                 - slot index
; Return values .: Success - Byte count (0 = nothing complete yet).
;                  Failure - 1 = the header itself is inconsistent, the stream is no longer aligned.
; Author ........: Numeric1
; Remarks .......: Measured 2026-11-14 on a public site: feeding Schannel a truncated record returns SEC_E_INVALID_TOKEN, not SEC_E_INCOMPLETE_MESSAGE - the context dies, not the read. So nothing is submitted until the record in progress is whole.
; Related .......: _Tls_HandshakeLeg, _Tls_RecLen
;===============================================================================================================================
; How many bytes at the head of Raw form COMPLETE TLS records?
; Rule measured on 2026-11-14 on a public site: as long as the record in progress is not whole, ISC
; must receive NOTHING. The local server had hidden this case (its whole second flight fit in one
; 1412-byte read); with a public 8 Ko chain the Certificate record spreads over several reads, and
; feeding a truncated record returns SEC_E_INVALID_TOKEN, not SEC_E_INCOMPLETE_MESSAGE: the context
; dies, not the read.
; Returns -1 when the header itself is inconsistent (the stream is no longer aligned).
Func _Tls_CompletePrefix($iIdx)
    Local $n = $g_aTls_RawLen[$iIdx]
    Local $p = DllStructGetPtr($g_aTls_Raw[$iIdx])
    Local $i = 0
    While $i + 5 <= $n
        Local $lg = _Tls_RecLen($p + $i, $n - $i)
        If $lg < 5 Or $lg > $g_iTlsRxSize Then Return -1
        If $i + $lg > $n Then ExitLoop
        $i += $lg
    WEnd
    Return $i
EndFunc   ;==>_Tls_CompletePrefix

;#FUNCTION#=====================================================================================================================
; Name ..........: _Tls_HandshakeLeg
; Description ...: Feed one handshake leg to Schannel with the complete records held in Raw.
; Syntax ........: _Tls_HandshakeLeg($iIdx)
; Parameters ....: $iIdx                 - slot index
; Return values .: Success - 1 with @error 0 = still in progress, 2 with @error 0 = context negotiated.
;                  Failure - @error 3 = error (@extended = raw SSPI code).
; Author ........: Numeric1
; Remarks .......: Rule R5: the output descriptor uses caller-allocated buffers, so no FreeContextBuffer can be forgotten. Rule DS6: on the server side SEC_I_COMPLETE_NEEDED is handled with CompleteAuthToken, a branch never exercised on this machine (AcceptSecurityContext returns CONTINUE_NEEDED then OK).
; Related .......: _Tls_Connect, _Tls_Pump, _Tls_CompletePrefix
;===============================================================================================================================
; One handshake leg: feed ISC with what is in Raw.
; Returns 1 with @error 0 = still in progress, 2 = context negotiated, 3 = error, @extended = the raw
; SSPI code.
Func _Tls_HandshakeLeg($iIdx)
    Local $iRawLen = $g_aTls_RawLen[$iIdx]
    ; Taken BEFORE ISC: afterwards Raw is shifted and the trace shows nothing any more.
    Local $sTrace0 = _Tls_TraceRecords($iIdx)
    Local $iComplete = ($iRawLen > 0 ? _Tls_CompletePrefix($iIdx) : 0)
    If $iComplete < 0 Then
        _Tls_SetErr($iIdx, "raw NOT aligned on a record: " & $sTrace0)
        Return SetError(3, 0, 0)
    EndIf
    If $iRawLen > 0 And $iComplete = 0 Then
        ; Not a whole record yet: wait for the next read, without calling ISC (a call with 0
        ; input bytes would restart a ClientHello).
        Return SetError(0, 0, 1)
    EndIf
    ; DS5: on the server side no flight is placed without a byte from the peer.
    If $g_aTls_Inbound[$iIdx] And $iComplete = 0 Then Return SetError(0, 0, 1)
    Local $pIn = 0
    Local $tIn = 0
    If $iComplete > 0 Then
        _Tls_SetBuf($iIdx, 0, $iComplete, $Tls_SecBufferToken, DllStructGetPtr($g_aTls_Raw[$iIdx]))
        For $k = 1 To 3
            _Tls_SetBuf($iIdx, $k, 0, $Tls_SecBufferEmpty, 0)
        Next
        $pIn = DllStructGetPtr($g_aTls_Desc[$iIdx])
    EndIf

    ; Separate OUTPUT descriptor: Schannel writes the token there.
    Local $tOutBuf = DllStructCreate($g_sTlsSpecBuf4)
    Local $tOutDesc = DllStructCreate($g_sTlsSpecDesc)
    DllStructSetData($tOutDesc, 1, 0)
    DllStructSetData($tOutDesc, 2, 1)
    DllStructSetData($tOutDesc, 3, DllStructGetPtr($tOutBuf))
    DllStructSetData($tOutBuf, 1, 0)  ; cbBuffer = 0 -> allocated by Schannel (R5)
    DllStructSetData($tOutBuf, 2, $Tls_SecBufferToken)
    DllStructSetData($tOutBuf, 3, 0)

    Local $tAttr = DllStructCreate("dword")
    Local $pCtxIn = ($g_aTls_HaveCtx[$iIdx] ? DllStructGetPtr($g_aTls_Ctx[$iIdx]) : 0)
    Local $iReq = BitOR($Tls_IscReqReplayDetect, $Tls_IscReqSequenceDetect, _
            $Tls_IscReqConfidentiality, $Tls_IscReqAllocateMemory)

    Local $a, $sWho = "ISC"
    If $g_aTls_Inbound[$iIdx] Then
        ; DS1: the real export is "AcceptSecurityContext", no W. Same output shape as ISC, without
        ; the target name nor the package reserved fields.
        $sWho = "ASC"
        $a = DllCall("secur32.dll", "dword", "AcceptSecurityContext", _
                "ptr", DllStructGetPtr($g_aTls_Cred[$iIdx]), "ptr", $pCtxIn, _
                "ptr", $pIn, "dword", $iReq, "dword", $Tls_SecurityNativeDrep, _
                "ptr", DllStructGetPtr($g_aTls_Ctx[$iIdx]), "ptr", DllStructGetPtr($tOutDesc), _
                "ptr", DllStructGetPtr($tAttr), "ptr", 0)
    Else
        $a = DllCall("secur32.dll", "dword", "InitializeSecurityContextW", _
                "ptr", DllStructGetPtr($g_aTls_Cred[$iIdx]), "ptr", $pCtxIn, _
                "wstr", $g_aTls_Sni[$iIdx], "dword", $iReq, "dword", 0, _
                "dword", $Tls_SecurityNativeDrep, "ptr", $pIn, "dword", 0, _
                "ptr", DllStructGetPtr($g_aTls_Ctx[$iIdx]), "ptr", DllStructGetPtr($tOutDesc), _
                "ptr", DllStructGetPtr($tAttr), "ptr", 0)
    EndIf
    If @error Then Return SetError(3, 0, "DllCall err " & @error)
    Local $rc = $a[0]
    Local $pTok = DllStructGetData($tOutBuf, 3)
    Local $cbTok = DllStructGetData($tOutBuf, 1)
    Local $cbConsume = $iComplete
    Local $cbInReturned = -1  ; -1 = no input submitted
    If $iComplete > 0 Then
        ; Schannel reports in the INPUT buffer how many bytes were consumed.
        Local $cbIn = _Tls_GetCb($iIdx, 0)
        If $cbIn > 0 And $cbIn <= $iComplete Then $cbConsume = $cbIn
        $cbInReturned = $cbIn
    EndIf

    ; Server: if Schannel asks for COMPLETE_NEEDED, the token must be frozen by CompleteAuthToken
    ; BEFORE being read, then freed. Branch NOT EXERCISED on this machine (measure probe_srvcred: ASC
    ; returns SEC_I_CONTINUE_NEEDED then SEC_E_OK, never COMPLETE_NEEDED) - written so we do not loop
    ; if another peer triggers it.
    If $g_aTls_Inbound[$iIdx] Then
        Local $uRC = BitAND($rc, 0xFFFFFFFF)
        If $uRC = $Tls_SecICompleteNeeded Or $uRC = $Tls_SecICompleteAndContinue Then
            Local $ca = DllCall("secur32.dll", "dword", "CompleteAuthToken", _
                    "ptr", DllStructGetPtr($g_aTls_Ctx[$iIdx]), "ptr", DllStructGetPtr($tOutDesc))
            If @error Then
                _Tls_SetErr($iIdx, "CompleteAuthToken DllCall err " & @error)
            ElseIf $ca[0] <> 0 Then
                _Tls_SetErr($iIdx, "CompleteAuthToken " & _Tls_SecDesc($ca[0]))
            EndIf
        EndIf
    EndIf

    If $cbTok > 0 And $pTok <> 0 Then
        Local $tTok = DllStructCreate("byte[" & $cbTok & "]", $pTok)
        If @error Then
            _Tls_SetErr($iIdx, "token read " & @error)
        Else
            _Tls_PushTx($iIdx, DllStructGetData($tTok, 1))
        EndIf
        Local $fr = DllCall("secur32.dll", "dword", "FreeContextBuffer", "ptr", $pTok)
        If @error Or $fr[0] <> 0 Then _Tls_SetErr($iIdx, "freeToken " & (@error ? "err" : _Tls_SecDesc($fr[0])))
    EndIf

    If $cbConsume > 0 Then _Tls_ConsumeRaw($iIdx, $cbConsume)

    Switch BitAND($rc, 0xFFFFFFFF)
        Case $Tls_SecEOk
            $g_aTls_HandshakeMs[$iIdx] = TimerDiff($g_aTls_HsTimer[$iIdx])
            _Tls_QuerySizes($iIdx)
            Return SetError(0, $rc, 2)
        Case $Tls_SecIContinueNeeded, $Tls_SecICompleteNeeded, $Tls_SecICompleteAndContinue
            $g_aTls_HaveCtx[$iIdx] = 1
            Return SetError(0, $rc, 1)
        Case $Tls_SecEIncompleteMessage
            ; Cannot happen through our fault any more (only complete records are submitted): stay in
            ; progress and wait for the next read.
            $g_aTls_HaveCtx[$iIdx] = 1
            Return SetError(0, $rc, 1)
        Case Else
            _Tls_SetErr($iIdx, $sWho & " " & _Tls_SecDesc($rc) & " input=" & $iRawLen & _
                    " cbInputReturned=" & $cbInReturned & " output=" & $cbTok & _
                    " volees=" & $g_aTls_RxTrace[$iIdx] & " | " & $sTrace0)
            Return SetError(3, $rc, 0)
    EndSwitch
EndFunc   ;==>_Tls_HandshakeLeg

;#FUNCTION#=====================================================================================================================
; Name ..........: _Tls_QuerySizes
; Description ...: Ask Schannel for the real header, trailer and maximum message sizes of the context.
; Syntax ........: _Tls_QuerySizes($iIdx)
; Parameters ....: $iIdx                 - slot index
; Return values .: Success - 1.
;                  Failure - @error 1 = the call or the query failed.
; Author ........: Numeric1
; Remarks .......: Without these sizes EncryptMessage cannot dimension its buffers; they are measured per connection, not assumed.
; Related .......: _Tls_StreamSizes, _Tls_EncryptPush
;===============================================================================================================================
; QueryContextAttributes(STREAM_SIZES): the real header and trailer sizes, without which
; EncryptMessage cannot size its buffers.
Func _Tls_QuerySizes($iIdx)
    Local $t = DllStructCreate("dword;dword;dword;dword")
    Local $a = DllCall("secur32.dll", "dword", "QueryContextAttributesW", _
            "ptr", DllStructGetPtr($g_aTls_Ctx[$iIdx]), "dword", $Tls_SecPkgAttrStreamSizes, _
            "ptr", DllStructGetPtr($t))
    If @error Or $a[0] <> 0 Then
        _Tls_SetErr($iIdx, "QueryContextAttributes(stream) " & (@error ? "DllCall err " & @error : _Tls_SecDesc($a[0])))
        Return SetError(1, 0, 0)
    EndIf
    $g_aTls_Hdr[$iIdx] = DllStructGetData($t, 1)
    $g_aTls_Trailer[$iIdx] = DllStructGetData($t, 2)
    $g_aTls_MaxMsg[$iIdx] = DllStructGetData($t, 3)
    Return 1
EndFunc   ;==>_Tls_QuerySizes

;#FUNCTION#=====================================================================================================================
; Name ..........: _Tls_StreamSizes
; Description ...: One-line text of the stream sizes recorded for a slot.
; Syntax ........: _Tls_StreamSizes($iIdx)
; Parameters ....: $iIdx                 - slot index
; Return values .: Success - String "header=N trailer=N maxMessage=N".
; Author ........: Numeric1
; Related .......: _Tls_QuerySizes
;===============================================================================================================================
Func _Tls_StreamSizes($iIdx)
    Return "header=" & $g_aTls_Hdr[$iIdx] & " trailer=" & $g_aTls_Trailer[$iIdx] & _
            " maxMessage=" & $g_aTls_MaxMsg[$iIdx]
EndFunc   ;==>_Tls_StreamSizes

;#FUNCTION#=====================================================================================================================
; Name ..........: _Tls_ConnInfo
; Description ...: Return the negotiated connection info: protocol version, cipher, hash and key exchange.
; Syntax ........: _Tls_ConnInfo($iIdx)
; Parameters ....: $iIdx                 - slot index
; Return values .: Success - String "protocol=0x...(TLS1.2) cipher=0x... bitsCipher=... hash=0x... bitsHash=... keyEx=0x... bitsKeyEx=...".
;                  Failure - String starting with "connInfo " when the query failed.
; Author ........: Numeric1
; Remarks .......: Measure: the attribute id is 90 in DECIMAL (SCHANNEL_CONNECTION_INFO); the documentation number 0x5A is the same value written in hexadecimal. Rule DS7: a Schannel server on this machine negotiates TLS 1.2 with OpenSSL even when the client offers 1.3.
; Related .......: _Tls_Info
;===============================================================================================================================
Func _Tls_ConnInfo($iIdx)
    Local $t = DllStructCreate("dword;dword;dword;dword;dword;dword;dword")
    Local $a = DllCall("secur32.dll", "dword", "QueryContextAttributesW", _
            "ptr", DllStructGetPtr($g_aTls_Ctx[$iIdx]), "dword", $Tls_SecPkgAttrConnectionInfo, _
            "ptr", DllStructGetPtr($t))
    If @error Or $a[0] <> 0 Then Return "connInfo " & (@error ? "DllCall err " & @error : _Tls_SecDesc($a[0]))
    Local $p = DllStructGetData($t, 1)
    Local $sName = "?"
    Switch BitAND($p, 0xFFFFFFFF)
        Case 0x0080
            $sName = "TLS1.0"
        Case 0x0200
            $sName = "TLS1.1"
        Case 0x0800
            $sName = "TLS1.2"
        Case 0x2000
            $sName = "TLS1.3"
    EndSwitch
    Return "protocol=0x" & Hex($p, 8) & "(" & $sName & ") cipher=0x" & Hex(DllStructGetData($t, 2), 8) & _
            " bitsCipher=" & DllStructGetData($t, 3) & " hash=0x" & Hex(DllStructGetData($t, 4), 8) & _
            " bitsHash=" & DllStructGetData($t, 5) & " keyEx=0x" & Hex(DllStructGetData($t, 6), 8) & _
            " bitsKeyEx=" & DllStructGetData($t, 7)
EndFunc   ;==>_Tls_ConnInfo

;#FUNCTION#=====================================================================================================================
; Name ..........: _Tls_CertContextPtr
; Description ...: Read then release the peer CERT_CONTEXT pointer (diagnostic use, no leak kept).
; Syntax ........: _Tls_CertContextPtr($iIdx)
; Parameters ....: $iIdx                 - slot index
; Return values .: Success - Pointer, always returned even when it was just freed.
;                  Failure - @error 1 = DllCall failure, 2 = query failed (@extended = status code).
; Author ........: Numeric1
; Remarks .......: Rule V1b: that CERT_CONTEXT is a crypt32 object and must be released with CertFreeCertificateContext; FreeContextBuffer on it corrupts the heap and kills the process later (x86 segfault 139, x64 silent exit 127).
; Related .......: _Tls_PeerCert, _Tls_FreePeerCert
;===============================================================================================================================
Func _Tls_CertContextPtr($iIdx)
    Local $t = DllStructCreate("ptr")
    Local $a = DllCall("secur32.dll", "dword", "QueryContextAttributesW", _
            "ptr", DllStructGetPtr($g_aTls_Ctx[$iIdx]), "dword", $Tls_SecPkgAttrRemoteCertContext, _
            "ptr", DllStructGetPtr($t))
    If @error Then Return SetError(1, 0, 0)
    If $a[0] <> 0 Then Return SetError(2, $a[0], 0)
    Local $p = DllStructGetData($t, 1)
    ; V1b: that CERT_CONTEXT is a crypt32 object, it is released with CertFreeCertificateContext,
    ; not with FreeContextBuffer.
    _Tls_FreePeerCert($p)
    Return $p
EndFunc   ;==>_Tls_CertContextPtr

; =============================================================================
; CHAIN VALIDATION (layer 2). Every statement below is a MEASUREMENT of probe_cert.au3 of
; 2026-11-14, x86 first, x64 confirmed by phase v:
;   V1  The peer certificate leaves through QueryContextAttributesW(id 83) and returns a POINTER to
;       CERT_CONTEXT = {dword encoding; ptr DER; dword DER size; ptr CERT_INFO; ptr hCertStore}.
;       encoding = 1 (X509_ASN_ENCODING), the DER head read is 30 82 = SEQUENCE.
;   V1b MEASURED 2026-11-14: this block is a CRYPT32 OBJECT (it carries a crypt32 hCertStore) and is
;       released with CertFreeCertificateContext. Releasing it with FreeContextBuffer calls the WRONG
;       allocator: in x86 the heap survives one free and dies on the next (segfault 139 inside free),
;       in x64 the process dies INSIDE the call (exit 127, no message). Both failure modes were
;       observed, then made to disappear.
;   V2  hCertStore contains THE WHOLE chain the server returned (measure api.github.com: 3 leaves,
;       root USERTrust > Sectigo E36 > *.github.com). Passing it as AdditionalStore to
;       CertGetCertificateChain is what makes PUBLIC chains build; without it a local self-signed
;       chain does not ascend and a public chain is not completed.
;   V3  CertGetCertificateChain does NOT check cbSize: measure phase v x86, size 16 is accepted
;       although the real struct is 32 or 36. We use NO usage filter: the block is ZERO everywhere
;       and cbSize is the only field written, so the real position of the other fields no longer
;       matters (cUsage = 0 stops Windows from dereferencing rgpUsageIdentifier), and the 96-byte
;       allocation covers what Windows reads beyond our declaration.
;   V4  The policy that depends on the host name is id 4 (only its verdicts change between the right
;       name and "zzz.invalid"; id 5 = always OK, id 8 = 0x800B0110 whatever the name, id 9 = rc=0).
;   V5  SSL_EXTRA_CERT_CHAIN_POLICY_PARA = {cbSize, dwAuthType, fdwChecks, PWCHAR pwszServerName}:
;       the name is a POINTER, not an inline array. Measure: writing the name at offset 12 as text
;       makes crypt32 SEGFAULT (it dereferences that offset); a valid pointer to the name gives the
;       expected verdict. dwAuthType = 2 (AUTHTYPE_SERVER) is the only one that performs the useful
;       name check on a public chain.
;   V6  cbSize of SSL_EXTRA is NOT checked by Windows (16, 268, 1036 all accepted): we declare the
;       size AutoIt really computed.
;   V7  Measured verdicts, with their own words: 0x800B0109 = chain ending on an unapproved root,
;       0x800B010F = "the certificate CN does not match the passed value", 0x800B0110 = invalid
;       usage, 0x00000000 = accepted.
;   V8  Two switches tested SEPARATELY on the local self-signed chain:
;       fdwChecks = 0x100 -> right name 0x00000000, wrong name 0x800B010F
;       dwFlags   = 0x10  -> right name 0x00000000, wrong name 0x800B010F
;       Each one alone ignores the root WITHOUT removing the name check: that is the legitimate base
;       of a "self-signed certificate accepted here" option.
; =============================================================================

; The CERT_CHAIN_PARA cbSize Windows accepts (0 = not measured yet).
Global $g_iTlsChainParaCb = 0
Global $g_iTlsCryptStructs = 0
Global $g_tTlsChainPara, $g_tTlsPolicyPara, $g_tTlsPolicyStatus
Global $g_tTlsSslExtra, $g_tTlsSslName
; Two service globals: the question "is this size accepted?" must be asked under real conditions,
; with a real leaf and a real store, never with an invented pointer.
Global $g_pTlsChainSeed = 0
Global $g_hTlsChainStore = 0

;#FUNCTION#=====================================================================================================================
; Name ..........: _Tls_HrTxt
; Description ...: Windows text of an HRESULT, asking the system message table then the crypt32 module.
; Syntax ........: _Tls_HrTxt($iCode)
; Parameters ....: $iCode                - HRESULT to look up
; Return values .: Success - Stripped text, "" when Windows has nothing for this code.
; Author ........: Numeric1
; Related .......: _Tls_HrDesc, _Tls_SecText
;===============================================================================================================================
Func _Tls_HrTxt($iCode)
    Local $t = DllStructCreate("wchar[512]")
    Local $a = DllCall("kernel32.dll", "dword", "FormatMessageW", "dword", 0x1200, _
            "ptr", 0, "dword", BitAND($iCode, 0xFFFFFFFF), "dword", 0, _
            "ptr", DllStructGetPtr($t), "dword", 512, "ptr", 0)
    If Not @error And $a[0] > 0 Then Return StringStripWS(DllStructGetData($t, 1), 3)
    Local $h = DllCall("kernel32.dll", "ptr", "GetModuleHandleW", "wstr", "crypt32.dll")
    If @error Or $h[0] = 0 Then Return ""
    $a = DllCall("kernel32.dll", "dword", "FormatMessageW", "dword", 0x1204, _
            "ptr", $h[0], "dword", BitAND($iCode, 0xFFFFFFFF), "dword", 0, _
            "ptr", DllStructGetPtr($t), "dword", 512, "ptr", 0)
    If @error Or $a[0] = 0 Then Return ""
    Return StringStripWS(DllStructGetData($t, 1), 3)
EndFunc   ;==>_Tls_HrTxt

;#FUNCTION#=====================================================================================================================
; Name ..........: _Tls_HrDesc
; Description ...: Value plus Windows text of an HRESULT, for a diagnostic line.
; Syntax ........: _Tls_HrDesc($iCode)
; Parameters ....: $iCode                - HRESULT to describe
; Return values .: Success - String such as "0x800B010F [the certificate CN does not match...]".
; Author ........: Numeric1
; Related .......: _Tls_HrTxt
;===============================================================================================================================
Func _Tls_HrDesc($iCode)
    Local $i = BitAND($iCode, 0xFFFFFFFF)
    Local $s = "0x" & Hex($i, 8)
    Local $t = _Tls_HrTxt($i)
    If $t <> "" Then $s &= " [" & $t & "]"
    Return $s
EndFunc   ;==>_Tls_HrDesc

;#FUNCTION#=====================================================================================================================
; Name ..........: _Tls_PokeD
; Description ...: Write a DWORD at an absolute address through an overlay.
; Syntax ........: _Tls_PokeD($p, $v)
; Parameters ....: $p                    - destination address
;                  $v                    - value to write
; Return values .: Success - 1.
;                  Failure - @error 1 = null address, 2 = overlay refused.
; Author ........: Numeric1
; Remarks .......: Same measured reason as _Tls_WriteAt: the indexed DllStructSetData form writes one byte only.
; Related .......: _Tls_WriteAt, _Tls_PokeP
;===============================================================================================================================
; Write a dword / a pointer at an absolute address. The overlay (struct created ON the target) is the
; only safe path: DllStructSetData with a start index copies the first byte only (measure probe_raw,
; x86 and x64).
Func _Tls_PokeD($p, $v)
    If $p = 0 Then Return SetError(1, 0, 0)
    Local $t = DllStructCreate("dword", $p)
    If @error Then Return SetError(2, 0, 0)
    DllStructSetData($t, 1, $v)
    Return 1
EndFunc   ;==>_Tls_PokeD

;#FUNCTION#=====================================================================================================================
; Name ..........: _Tls_PokeP
; Description ...: Write a pointer-sized value at an absolute address through an overlay.
; Syntax ........: _Tls_PokeP($p, $v)
; Parameters ....: $p                    - destination address
;                  $v                    - pointer value to write
; Return values .: Success - 1.
;                  Failure - @error 1 = null address, 2 = overlay refused.
; Author ........: Numeric1
; Related .......: _Tls_PokeD
;===============================================================================================================================
Func _Tls_PokeP($p, $v)
    If $p = 0 Then Return SetError(1, 0, 0)
    Local $t = DllStructCreate("ptr", $p)
    If @error Then Return SetError(2, 0, 0)
    DllStructSetData($t, 1, $v)
    Return 1
EndFunc   ;==>_Tls_PokeP

;#FUNCTION#=====================================================================================================================
; Name ..........: _Tls_ZerosHex
; Description ...: Build a string of N null bytes in hexadecimal.
; Syntax ........: _Tls_ZerosHex($iN)
; Parameters ....: $iN                   - number of bytes
; Return values .: Success - 2N hexadecimal characters.
; Author ........: Numeric1
; Remarks .......: There is no StringRepeat in AutoIt 3.3.16 (measured with Au3Check: undefined function) and Hex(0,n) is capped at 16 digits, so the loop is the only path without an include.
; Related .......: _Tls_CryptStructs
;===============================================================================================================================
; A string of $iN null bytes in hexadecimal. There is NO StringRepeat in AutoIt 3.3.16 (measured with
; Au3Check: "StringRepeat(): undefined function"), and Hex(0,n) is capped at 16 digits: the loop is
; the only path without an include.
Func _Tls_ZerosHex($iN)
    Local $s = ""
    For $i = 1 To $iN
        $s &= "00"
    Next
    Return $s
EndFunc   ;==>_Tls_ZerosHex

;#FUNCTION#=====================================================================================================================
; Name ..........: _Tls_CryptStructs
; Description ...: Allocate the crypt32 parameter structures once and for all.
; Syntax ........: _Tls_CryptStructs() :None
; Return values .: Success - 1.
;                  Failure - @error 1 = allocation failed.
; Author ........: Numeric1
; Remarks .......: They MUST outlive the call: a destroyed Local leaves a dangling pointer that crypt32 writes into without warning. CERT_CHAIN_PARA is allocated 96 bytes because Windows reads beyond what is declared (rule V3).
; Related .......: _Tls_ChainParaSize, _Tls_BuildChain, _Tls_PolicySsl
;===============================================================================================================================
; Allocate the crypt32 parameter structures once and for all. They MUST outlive the call: a destroyed
; Local leaves a dangling pointer that crypt32 writes into without warning.
Func _Tls_CryptStructs()
    If $g_iTlsCryptStructs Then Return 1
    ; V3: 96-byte block entirely ZERO, so Windows can only read cUsageIdentifier = 0 or empty OIDs;
    ; cbSize will be the only field written.
    $g_tTlsChainPara = DllStructCreate("byte[96]")
    If @error Then Return SetError(1, 0, 0)
    DllStructSetData($g_tTlsChainPara, 1, Binary("0x" & _Tls_ZerosHex(96)))
    ; CERT_CHAIN_POLICY_PARA = {cbSize, dwFlags, pvExtraParameters}
    $g_tTlsPolicyPara = DllStructCreate("dword;dword;ptr")
    ; CERT_CHAIN_POLICY_STATUS = {cbSize, dwError, lChainIndex, lChainElementIndex, pvExtra}
    $g_tTlsPolicyStatus = DllStructCreate("dword;dword;dword;dword;ptr")
    ; V5: pwszServerName is a POINTER; 512 bytes of name in direct derivation.
    $g_tTlsSslExtra = DllStructCreate("dword;dword;dword;ptr")
    $g_tTlsSslName = DllStructCreate("wchar[512]")
    Return 1
EndFunc   ;==>_Tls_CryptStructs

;#FUNCTION#=====================================================================================================================
; Name ..........: _Tls_FreePeerCert
; Description ...: Release a peer CERT_CONTEXT through crypt32, the only safe deallocator here.
; Syntax ........: _Tls_FreePeerCert($p)
; Parameters ....: $p                    - CERT_CONTEXT pointer
; Return values .: Success - 1.
;                  Failure - @error 1 = CertFreeCertificateContext unavailable (null pointer returns 0 silently).
; Author ........: Numeric1
; Remarks .......: Rule V1b.
; Related .......: _Tls_PeerCert, _Tls_CertContextPtr
;===============================================================================================================================
; Return a peer CERT_CONTEXT. One path only is safe: crypt32 itself.
Func _Tls_FreePeerCert($p)
    If $p = 0 Then Return 0
    Local $a = DllCall("crypt32.dll", "none", "CertFreeCertificateContext", "ptr", $p)
    If @error Then Return SetError(1, 0, 0)
    Return 1
EndFunc   ;==>_Tls_FreePeerCert

;#FUNCTION#=====================================================================================================================
; Name ..........: _Tls_PeerCert
; Description ...: Read the peer certificate of an open context without releasing it.
; Syntax ........: _Tls_PeerCert($iIdx, $pCtx, $hStore, $cbDer)
; Parameters ....: $iIdx                 - slot index
;                  $pCtx                 - receives the CERT_CONTEXT pointer
;                  $hStore               - receives the HCERTSTORE that holds the whole chain sent by the peer
;                  $cbDer                - receives the DER byte count
; Return values .: Success - 1.
;                  Failure - @error 1 = slot not open (@extended = state), 2 = DllCall failure, 3 = query failed (@extended = status code), 4 = null pointer, 5 = CERT_INFO unreadable, 6 = unexpected encoding (@extended = encoding value).
; Author ........: Numeric1
; Remarks .......: Rule V1 (id 83 in DECIMAL, not 0x53) and V2: hStore contains every leaf the server sent, which is what lets CertGetCertificateChain build public chains. $pCtx and $hStore are valid only until the next call; the caller releases the block itself.
; Related .......: _Tls_CertContextPtr, _Tls_BuildChain
;===============================================================================================================================
; The peer's CERT_CONTEXT, WITHOUT freeing it: $pCtx and $hStore are valid only until the next call
; (1.1); the caller must release the block itself.
Func _Tls_PeerCert($iIdx, ByRef $pCtx, ByRef $hStore, ByRef $cbDer)
    $pCtx = 0
    $hStore = 0
    $cbDer = 0
    If $g_aTls_State[$iIdx] <> $Tls_ST_OPEN Then Return SetError(1, $g_aTls_State[$iIdx], 0)
    Local $t = DllStructCreate("ptr")
    Local $a = DllCall("secur32.dll", "dword", "QueryContextAttributesW", _
            "ptr", DllStructGetPtr($g_aTls_Ctx[$iIdx]), "dword", $Tls_SecPkgAttrRemoteCertContext, _
            "ptr", DllStructGetPtr($t))
    If @error Then Return SetError(2, 0, 0)
    If $a[0] <> 0 Then Return SetError(3, $a[0], 0)
    $pCtx = DllStructGetData($t, 1)
    If $pCtx = 0 Then Return SetError(4, 0, 0)
    Local $tC = DllStructCreate("dword;ptr;dword;ptr;ptr", $pCtx)
    If @error Then Return SetError(5, 0, 0)
    $cbDer = DllStructGetData($tC, 3)
    $hStore = DllStructGetData($tC, 5)
    If DllStructGetData($tC, 1) <> 1 Then Return SetError(6, DllStructGetData($tC, 1), 0)
    Return 1
EndFunc   ;==>_Tls_PeerCert

;#FUNCTION#=====================================================================================================================
; Name ..........: _Tls_ChainParaSize
; Description ...: Measure once the CERT_CHAIN_PARA cbSize that Windows accepts, then keep it.
; Syntax ........: _Tls_ChainParaSize() :None
; Return values .: Success - The accepted size.
;                  Failure - @error 1 = DllCall failure, 2 = no candidate accepted.
; Author ........: Numeric1
; Remarks .......: Measure phase v (x86): Windows accepts 16, less than the real struct, so cbSize is NOT checked (rule V6 as for SSL_EXTRA). What protects the process is the 96-byte zeroed allocation: Windows reads beyond what is declared but always inside our own bytes.
; Related .......: _Tls_CryptStructs, _Tls_BuildChain
;===============================================================================================================================
; V3: size of CERT_CHAIN_PARA that Windows accepts, measured once and kept. Candidates are tried
; FROM THE SMALLEST TO THE LARGEST. MEASURE phase v (x86): Windows accepts 16, that is LESS than the
; real struct (36 computed by AutoIt, 32 in the header): cbSize is therefore NOT checked here either,
; as with SSL_EXTRA (V6). The sweep therefore does not measure the real size, it proves one thing: the
; chain construction works with THIS block. What protects us is the 96-byte allocation zeroed
; entirely: Windows reads beyond what we declare, but always inside our own bytes.
Func _Tls_ChainParaSize()
    If $g_iTlsChainParaCb > 0 Then Return $g_iTlsChainParaCb
    _Tls_CryptStructs()
    Local $aCand = "16;24;28;32;36;40;48;56;64"
    Local $aS = StringSplit($aCand, ";")
    Local $pBase = DllStructGetPtr($g_tTlsChainPara)
    Local $tCh = DllStructCreate("ptr")
    For $i = 1 To $aS[0]
        Local $iSz = Int($aS[$i])
        If $iSz > 96 Then ContinueLoop  ; never declare more than what was allocated
        _Tls_PokeD($pBase, $iSz)
        DllStructSetData($tCh, 1, 0)
        Local $a = DllCall("crypt32.dll", "bool", "CertGetCertificateChain", _
                "ptr", 0, "ptr", $g_pTlsChainSeed, "ptr", 0, "ptr", $g_hTlsChainStore, _
                "ptr", $pBase, "dword", 0, "ptr", 0, "ptr", DllStructGetPtr($tCh))
        If @error Then Return SetError(1, 0, 0)
        Local $pChain = DllStructGetData($tCh, 1)
        If $a[0] <> 0 And $pChain <> 0 Then
            $g_iTlsChainParaCb = $iSz
            DllCall("crypt32.dll", "none", "CertFreeCertificateChain", "ptr", $pChain)
            Return $iSz
        EndIf
    Next
    Return SetError(2, 0, 0)
EndFunc   ;==>_Tls_ChainParaSize

;#FUNCTION#=====================================================================================================================
; Name ..........: _Tls_BuildChain
; Description ...: Build the Windows certificate chain from the peer CERT_CONTEXT.
; Syntax ........: _Tls_BuildChain($pCertCtx, $hStore, $pChain)
; Parameters ....: $pCertCtx             - peer CERT_CONTEXT pointer
;                  $hStore               - HCERTSTORE from the peer, passed as AdditionalStore
;                  $pChain               - receives the CERT_CHAIN_CONTEXT pointer
; Return values .: Success - 1, $pChain receives the CERT_CHAIN_CONTEXT pointer.
;                  Failure - @error 1 or 2 = the cbSize probe failed (code shifted by 1), 3 = DllCall failure, 4 = chain refused or pointer missing (@extended = returned rc).
; Author ........: Numeric1
; Remarks .......: Rule V2. A successful CertGetCertificateChain still leaves GetLastError 0x80092004: that is a leftover, not a verdict, so only the returned rc and the pointer are reported.
; Related .......: _Tls_PeerCert, _Tls_PolicySsl, _Tls_VerifyChain
;===============================================================================================================================
; Two service globals: _Tls_ChainParaSize needs a leaf/store pair so the question "is this size
; accepted?" is asked under real conditions, not with an invented pointer.
; Build the Windows chain from the peer's CERT_CONTEXT (V2).
; Returns the CERT_CHAIN pointer through ByRef; 0 and @error otherwise.
Func _Tls_BuildChain($pCertCtx, $hStore, ByRef $pChain)
    $pChain = 0
    _Tls_CryptStructs()
    $g_pTlsChainSeed = $pCertCtx
    $g_hTlsChainStore = $hStore
    Local $iSz = _Tls_ChainParaSize()
    If @error Then Return SetError(1 + @error, @extended, 0)
    Local $pBase = DllStructGetPtr($g_tTlsChainPara)
    _Tls_PokeD($pBase, $iSz)
    Local $tCh = DllStructCreate("ptr")
    Local $a = DllCall("crypt32.dll", "bool", "CertGetCertificateChain", _
            "ptr", 0, "ptr", $pCertCtx, "ptr", 0, "ptr", $hStore, _
            "ptr", $pBase, "dword", 0, "ptr", 0, "ptr", DllStructGetPtr($tCh))
    $g_pTlsChainSeed = 0
    $g_hTlsChainStore = 0
    If @error Then Return SetError(3, 0, 0)
    $pChain = DllStructGetData($tCh, 1)
    ; Measure x86 2026-11-14: after a SUCCESSFUL CertGetCertificateChain (rc=1), GetLastError is
    ; 0x80092004. That is a leftover, not a verdict: this layer only reports rc and the presence of
    ; the pointer, and the real reason comes from the policy step (V7).
    If $a[0] = 0 Or $pChain = 0 Then Return SetError(4, $a[0], 0)
    Return 1
EndFunc   ;==>_Tls_BuildChain

;#FUNCTION#=====================================================================================================================
; Name ..........: _Tls_PolicySsl
; Description ...: Ask the Windows SSL chain policy for its verdict on a built chain, for one host name.
; Syntax ........: _Tls_PolicySsl($pChain, $sHost, $fIgnoreUntrusted, $iIdxEl)
; Parameters ....: $pChain               - CERT_CHAIN_CONTEXT pointer
;                  $sHost                - name taken from the URL
;                  $fIgnoreUntrusted     - V8: tolerate an untrusted root
;                  $iIdxEl               - receives the index of the failing chain element, -1 when none
; Return values .: Success - 1 when Windows approves (dwError = 0).
;                  Failure - @error 1 = empty host name, 2 = host name longer than 510 characters, 3 = DllCall failure, 4 = policy call refused, 5 = Windows returned a verdict (@extended = HRESULT, always unsigned).
; Author ........: Numeric1
; Remarks .......: Rules V4/V5/V7: id 4 is the only policy whose verdict depends on the name; dwAuthType = 2 (AUTHTYPE_SERVER) and the name travels as a POINTER, writing it inline at offset 12 segfaults crypt32. Verdicts measured: 0x800B0109 untrusted root, 0x800B010F name mismatch, 0x800B0110 invalid usage.
; Related .......: _Tls_BuildChain, _Tls_VerifyChain
;===============================================================================================================================
; Verdict of the SSL policy on an already built chain.
; $sHost: the requested name (the one from the URL), $fIgnoreUntrusted: V8.
; Returns 1 when Windows approves (dwError = 0), 0 otherwise; @extended = the HRESULT of
; CERT_CHAIN_POLICY_STATUS, ALWAYS returned unsigned (measure: a "dword" read in AutoIt can come back
; negative, and 0x800B010F < 0 then compares with nothing).
Func _Tls_PolicySsl($pChain, $sHost, $fIgnoreUntrusted, ByRef $iIdxEl)
    _Tls_CryptStructs()
    $iIdxEl = -1
    If $sHost = "" Then Return SetError(1, 0, 0)
    If StringLen($sHost) > 510 Then Return SetError(2, 0, 0)
    ; V5/V6: structure sized by AutoIt, name in DERIVATION (pointer).
    DllStructSetData($g_tTlsSslName, 1, $sHost)
    DllStructSetData($g_tTlsSslExtra, 1, DllStructGetSize($g_tTlsSslExtra))
    DllStructSetData($g_tTlsSslExtra, 2, $Tls_AuthTypeServer)
    DllStructSetData($g_tTlsSslExtra, 3, ($fIgnoreUntrusted ? $Tls_SslFdIgnoreUntrustedRoot : 0))
    DllStructSetData($g_tTlsSslExtra, 4, DllStructGetPtr($g_tTlsSslName))
    DllStructSetData($g_tTlsPolicyPara, 1, DllStructGetSize($g_tTlsPolicyPara))
    DllStructSetData($g_tTlsPolicyPara, 2, 0)
    DllStructSetData($g_tTlsPolicyPara, 3, DllStructGetPtr($g_tTlsSslExtra))
    DllStructSetData($g_tTlsPolicyStatus, 1, DllStructGetSize($g_tTlsPolicyStatus))
    DllStructSetData($g_tTlsPolicyStatus, 2, 0)
    DllStructSetData($g_tTlsPolicyStatus, 3, 0xFFFFFFFF)
    DllStructSetData($g_tTlsPolicyStatus, 4, 0xFFFFFFFF)
    Local $a = DllCall("crypt32.dll", "bool", "CertVerifyCertificateChainPolicy", _
            "ptr", $Tls_PolicySslId, "ptr", $pChain, _
            "ptr", DllStructGetPtr($g_tTlsPolicyPara), _
            "ptr", DllStructGetPtr($g_tTlsPolicyStatus))
    If @error Then Return SetError(3, 0, 0)
    If $a[0] = 0 Then Return SetError(4, 0, 0)
    Local $dw = BitAND(DllStructGetData($g_tTlsPolicyStatus, 2), 0xFFFFFFFF)
    $iIdxEl = BitAND(DllStructGetData($g_tTlsPolicyStatus, 3), 0xFFFFFFFF)
    If $dw <> 0 Then Return SetError(5, $dw, 0)
    Return SetError(0, 0, 1)
EndFunc   ;==>_Tls_PolicySsl

;#FUNCTION#=====================================================================================================================
; Name ..........: _Tls_VerifyChain
; Description ...: Does Windows approve the certificate this peer just presented, for this host name?
; Syntax ........: _Tls_VerifyChain($iIdx, $sHost[, $fIgnoreUntrusted])
; Parameters ....: $iIdx                 - slot index
;                  $sHost                - expected name (the URL host, which is also the SNI)
;                  $fIgnoreUntrusted     - [optional] accept a chain ending on an unapproved root
; Return values .: Success - 1 = approved.
;                  Failure - 0 = refused, @extended = the Windows HRESULT; @error 1 = peer certificate unavailable, 2 = chain impossible, 3 = policy verdict (real refusal), 4 = host name empty or too long.
; Author ........: Numeric1
; Remarks .......: The single public call of the validation section. The full Windows text of the decision is kept for _Tls_VerifyError.
; Related .......: _Tls_PeerCert, _Tls_PolicySsl, _Tls_VerifyError
;===============================================================================================================================
; The single public call of this section: does Windows approve the certificate this peer just
; presented, FOR THIS HOST NAME?
;   1 = approved. 0 = refused, @extended = the Windows HRESULT, and the full text is in
;   _Tls_VerifyError($iIdx).
; @error : 1 = peer certificate unavailable, 2 = Windows chain impossible,
;          3 = policy verdict returned by Windows (real refusal),
;          4 = host name empty or too long for the parameter.
Func _Tls_VerifyChain($iIdx, $sHost, $fIgnoreUntrusted = False)
    Local $pCtx = 0, $hStore = 0, $cbDer = 0, $pChain = 0, $iEl = -1
    Local $rv = _Tls_PeerCert($iIdx, $pCtx, $hStore, $cbDer)
    Local $e = @error, $x = @extended
    If Not $rv Then
        ; 1 = state, 3 = SSPI code, 6 = encoding other than X509_ASN, the rest = DllCall
        _Tls_SetErr($iIdx, "peerCert " & _
                ($e = 1 ? "state=" & _Tls_StateName($x) : _
                ($e = 3 Or $e = 6 ? _Tls_SecDesc($x) : "dllcall/structure err " & $e)))
        Return SetError(1, $x, 0)
    EndIf
    $rv = _Tls_BuildChain($pCtx, $hStore, $pChain)
    $e = @error
    $x = @extended
    If Not $rv Then
        ; 2 = cbSize sweep failing in DllCall, 3 = NO size accepted, 4 = CertGetCertificateChain
        ; returned neither a chain nor success, 5 = DllCall
        _Tls_SetErr($iIdx, "chain cbSize=" & $g_iTlsChainParaCb & " " & _
                ($e = 4 ? "rc=" & $x : _
                ($e = 3 ? "no accepted CERT_CHAIN_PARA size" : "dllcall err " & $e)))
        _Tls_FreePeerCert($pCtx)
        Return SetError(2, $x, 0)
    EndIf
    $rv = _Tls_PolicySsl($pChain, $sHost, $fIgnoreUntrusted, $iEl)
    $e = @error
    $x = @extended
    DllCall("crypt32.dll", "none", "CertFreeCertificateChain", "ptr", $pChain)
    _Tls_FreePeerCert($pCtx)
    If Not $rv Then
        ; 1/2 = unusable name, 3/4 = the call itself, 5 = the Windows VERDICT
        _Tls_SetErr($iIdx, ($e = 5 ? "policy " : "policy call ") & "step " & $e & " host=" & $sHost & _
                ($e = 5 ? " " & _Tls_HrDesc($x) & " item=" & $iEl : "") & _
                " ignoreRoot=" & ($fIgnoreUntrusted ? 1 : 0))
        Return SetError($e = 1 Or $e = 2 ? 4 : 3, $x, 0)
    EndIf
    _Tls_SetErr($iIdx, "approved host=" & $sHost & " ignoreRoot=" & ($fIgnoreUntrusted ? 1 : 0) & _
            " cbSize=" & $g_iTlsChainParaCb)
    Return SetError(0, 0, 1)
EndFunc   ;==>_Tls_VerifyChain

;#FUNCTION#=====================================================================================================================
; Name ..........: _Tls_VerifyError
; Description ...: Text of the last validation decision, approval or refusal alike.
; Syntax ........: _Tls_VerifyError($iIdx)
; Parameters ....: $iIdx                 - slot index
; Return values .: Success - String such as "0x800B010F [the certificate CN ...]".
; Author ........: Numeric1
; Remarks .......: Written at BOTH exits on purpose: a diagnostic keeping the previous refusal's text would make a rejection look alive where there is none any more.
; Related .......: _Tls_VerifyChain
;===============================================================================================================================
; The text of the last decision, for the caller: "0x800B010F [the certificate CN ...]". It is
; written at BOTH exits (approval and refusal): a diagnostic keeping the previous refusal's text
; would make a rejection look alive where there is none any more.
Func _Tls_VerifyError($iIdx)
    Return $g_aTls_Err[$iIdx]
EndFunc   ;==>_Tls_VerifyError

;#FUNCTION#=====================================================================================================================
; Name ..........: _Tls_FlushTx
; Description ...: Push the queued encrypted bytes towards the network, partially when needed.
; Syntax ........: _Tls_FlushTx($iIdx, $iWaitMs)
; Parameters ....: $iIdx                 - slot index
;                  $iWaitMs              - poll budget for writability, in milliseconds
; Return values .: Success - Bytes written this call; the queue keeps the rest.
;                  Failure - @error 1 = WSASend failed (@extended = Winsock error), 2 = nothing to send, 3 = socket not writable now (@extended = error).
; Author ........: Numeric1
; Remarks .......: Real non-blocking behaviour: chunks are capped at 64 KiB per call and a short write is not an error.
; Related .......: _Tls_PushTx, _Tls_PendingTx, _Wsk_SendChunk
;===============================================================================================================================
; =============================================================================
; Write towards the network, partially when needed (real non-blocking).
; Returns the bytes pushed out of the queue; the queue keeps the rest.
; =============================================================================
Func _Tls_FlushTx($iIdx, $iWaitMs)
    Local $b = $g_aTls_TxPend[$iIdx]
    Local $n = BinaryLen($b)
    If $n = 0 Then Return 0
    Local $rv = _Wsk_Poll($g_aTls_Sock[$iIdx], $Wsk_POLLWRNORM, $iWaitMs)
    If @error = 3 Then Return SetError(2, 0, 0)  ; still nothing
    Local $s = BinaryMid($b, 1, ($n > 65536 ? 65536 : $n))
    Local $sent = _Wsk_SendChunk($g_aTls_Sock[$iIdx], $s)
    Local $e = @error
    Local $x = @extended
    If $e = 4 Then Return SetError(3, $x, 0) ; EWOULDBLOCK
    If $e Then
        _Tls_SetErr($iIdx, "WSASend err " & $e & " " & _Wsk_ErrorName($x))
        Return SetError(1, $e, 0)
    EndIf
    If $sent > 0 Then
        $g_aTls_TxPend[$iIdx] = BinaryMid($b, $sent + 1)
        $g_aTls_BytesOut[$iIdx] += $sent
    EndIf
    Return $sent
EndFunc   ;==>_Tls_FlushTx

;#FUNCTION#=====================================================================================================================
; Name ..........: _Tls_PullRaw
; Description ...: Read the network into Raw.
; Syntax ........: _Tls_PullRaw($iIdx, $iWaitMs)
; Parameters ....: $iIdx                 - slot index
;                  $iWaitMs              - poll budget for readability, in milliseconds
; Return values .: Success - Number of bytes added (0 possible).
;                  Failure - @error 1 = Raw full (decrypt before reading more), 2 = nothing arrived (expired poll or WSAEWOULDBLOCK), 3 = socket error (@extended = Winsock error), 4 = peer closed (FIN).
; Author ........: Numeric1
; Remarks .......: Rule DS6: @error 2 is NOT an error, a server that treats it as fatal kills the peer's handshake on the first turn without data.
; Related .......: _Tls_AppendRaw, _Tls_Pump
;===============================================================================================================================
; Read the network into Raw. Returns the number of bytes added.
Func _Tls_PullRaw($iIdx, $iWaitMs)
    Local $free = $g_iTlsRxSize - $g_aTls_RawLen[$iIdx]
    If $free <= 0 Then Return SetError(1, 0, 0)  ; full: decrypt before reading more
    Local $iCap = ($g_aTls_ReadCap[$iIdx] > 0 ? $g_aTls_ReadCap[$iIdx] : $g_iTlsReadCapDefault)
    If $iCap > $free Then $iCap = $free
    Local $rv = _Wsk_Poll($g_aTls_Sock[$iIdx], $Wsk_POLLRDNORM, $iWaitMs)
    Local $eP = @error
    If $eP = 3 Then Return SetError(2, 0, 0)
    If $eP Then Return SetError(3, $eP, 0)
    Local $got = _Wsk_Recv($g_aTls_Sock[$iIdx], $iCap)
    Local $e = @error
    Local $x = @extended
    If $e = 4 Then Return SetError(2, $x, 0) ; EWOULDBLOCK
    If $e = 6 Then Return SetError(4, 0, 0)  ; peer FIN
    If $e Then Return SetError(3, $e, 0)
    Local $n = BinaryLen($got)
    $g_aTls_BytesIn[$iIdx] += $n
    _Tls_AppendRaw($iIdx, $got)
    Return $n
EndFunc   ;==>_Tls_PullRaw

;#FUNCTION#=====================================================================================================================
; Name ..........: _Tls_EncryptPush
; Description ...: Encrypt one application block with EncryptMessage and queue the resulting record.
; Syntax ........: _Tls_EncryptPush($iIdx, $bData)
; Parameters ....: $iIdx                 - slot index
;                  $bData                - application bytes (one WebSocket frame at most maxMessage)
; Return values .: Success - Number of encrypted bytes queued.
;                  Failure - @error 1 = buffer setup failed, 2 = EncryptMessage refused (@extended = SSPI code), 3 = token read failed, 4 = size query needed (call _Tls_QuerySizes).
; Author ........: Numeric1
; Remarks .......: Rule DD2: with 16384 clear bytes the header is 13 and the trailer 16, 13+16384+16 = 16413 = exactly the record size on the wire.
; Related .......: _Tls_Send, _Tls_PushTx, _Tls_QuerySizes
;===============================================================================================================================
; =============================================================================
; Encrypt then queue a record. $bData = application data.
; =============================================================================
Func _Tls_EncryptPush($iIdx, $bData)
    Local $n = BinaryLen($bData)
    Local $iHdr = $g_aTls_Hdr[$iIdx]
    Local $iTr = $g_aTls_Trailer[$iIdx]
    Local $pOut = DllStructGetPtr($g_aTls_Out[$iIdx])
    Local $pHdr = $pOut
    Local $pData = $pOut + $iHdr
    Local $pTr = $pData + $n
    _Tls_SetBuf($iIdx, 0, $iHdr, $Tls_SecBufferStreamHeader, $pHdr)
    _Tls_SetBuf($iIdx, 1, $n, $Tls_SecBufferData, $pData)
    _Tls_SetBuf($iIdx, 2, $iTr, $Tls_SecBufferStreamTrailer, $pTr)
    _Tls_SetBuf($iIdx, 3, 0, $Tls_SecBufferEmpty, 0)
    DllStructSetData($g_aTls_Desc[$iIdx], 2, 4)
    DllStructSetData($g_aTls_Desc[$iIdx], 3, DllStructGetPtr($g_aTls_Bufs[$iIdx]))
    If $n > 0 Then
        Local $w = _Tls_WriteAt($pData, $bData)
        If @error Then Return SetError(4, 0, 0)
    EndIf

    Local $a = DllCall("secur32.dll", "dword", "EncryptMessage", _
            "ptr", DllStructGetPtr($g_aTls_Ctx[$iIdx]), "dword", 0, _
            "ptr", DllStructGetPtr($g_aTls_Desc[$iIdx]), "dword", 0)
    If @error Then Return SetError(1, 0, 0)
    If $a[0] <> 0 Then
        _Tls_SetErr($iIdx, "EncryptMessage " & _Tls_SecDesc($a[0]))
        Return SetError(2, $a[0], 0)
    EndIf
    ; Schannel reports in cbBuffer the buffers REALLY used.
    Local $useHdr = _Tls_GetCb($iIdx, 0)
    Local $useTr = _Tls_GetCb($iIdx, 2)
    Local $total = $useHdr + $n + $useTr
    Local $tAll = DllStructCreate("byte[" & $total & "]", $pOut)
    If @error Then Return SetError(3, 0, 0)
    _Tls_PushTx($iIdx, DllStructGetData($tAll, 1))
    $g_aTls_Records[$iIdx] += 1
    Return $total
EndFunc   ;==>_Tls_EncryptPush

;#FUNCTION#=====================================================================================================================
; Name ..........: _Tls_Send
; Description ...: Encrypt application data and queue it, cut into maxMessage chunks.
; Syntax ........: _Tls_Send($iIdx, $bData)
; Parameters ....: $iIdx                 - slot index
;                  $bData                - application bytes to protect
; Return values .: Success - Number of bytes accepted into the encrypted queue.
;                  Failure - @error 1 = slot not open (@extended = state), 2 = encryption failed (@extended = inner code, return value = bytes already queued).
; Author ........: Numeric1
; Remarks .......: Queuing is a promise about memory, never about the network: use _Tls_PendingTx and _Tls_FlushTx to know what is still on the way.
; Related .......: _Tls_EncryptPush, _Tls_PendingTx
;===============================================================================================================================
; Send application data: cut into maxMessage chunks.
Func _Tls_Send($iIdx, $bData)
    If $g_aTls_State[$iIdx] <> $Tls_ST_OPEN Then Return SetError(1, $g_aTls_State[$iIdx], 0)
    Local $iMax = $g_aTls_MaxMsg[$iIdx]
    If $iMax <= 0 Then $iMax = 16384
    Local $pos = 1
    Local $total = BinaryLen($bData)
    Local $sent = 0
    While $pos <= $total
        Local $chunk = BinaryMid($bData, $pos, $iMax)
        Local $r = _Tls_EncryptPush($iIdx, $chunk)
        If @error Then Return SetError(2, @extended, $sent)
        $sent += BinaryLen($chunk)
        $pos += BinaryLen($chunk)
    WEnd
    ; One immediate write attempted only: the rest waits for the pump.
    _Tls_FlushTx($iIdx, 0)
    Return SetError(0, 0, $sent)
EndFunc   ;==>_Tls_Send

;#FUNCTION#=====================================================================================================================
; Name ..........: _Tls_DecryptStep
; Description ...: Decrypt the complete records present in Raw into the clear queue.
; Syntax ........: _Tls_DecryptStep($iIdx)
; Parameters ....: $iIdx                 - slot index
; Return values .: Success - Number of records processed (0 = nothing complete yet).
;                  Failure - @error 3 = fatal error (@extended = SSPI code), 4 = the peer closed (@extended = SSPI code), 5 = clear queue full, backpressure (@extended = pending clear bytes).
; Author ........: Numeric1
; Remarks .......: Rules DD1-DD5: the only accepted input shape is ONE DATA buffer holding the WHOLE record including its 5-byte header; the clear text lands in the buffer of TYPE DATA, at offset 13, never at index 0; a partial record gives SEC_E_INCOMPLETE_MESSAGE 0x80090318 with a MISSING buffer naming the bytes still expected; two records in one submission give 0x80090330.
; Related .......: _Tls_Pump, _Tls_Read, _Tls_CompletePrefix
;===============================================================================================================================
; =============================================================================
; Decrypt the first record of Raw. Returns the number of records processed.
; @error 0 = ok, 4 = the peer closed, 3 = fatal error (@extended = SSPI code),
;            5 = clear queue full (backpressure).
;
; Measure probe_dec (x86, redone in x64) that decides EVERYTHING here:
;   DD1  A single DATA buffer holding the WHOLE record (5-byte header + payload) is the right input
;        shape. After the call Windows has REWRITTEN the descriptor: [0] type 7 (STREAM_HEADER)
;        cb=13 dp=0, [1] type 1 (DATA) cb=4 dp=13, [2] type 6 (TRAILER) cb=16. The clear text is
;        therefore placed at offset 13 (= 5 header + 8 GCM salt), and index 0 no longer holds the
;        clear text. Reading cb from buffer 0 returns 13 bytes of header+salt: that is the bug that
;        produced "received=170303001C..." instead of the 4 bytes. Hence: look for the buffer of TYPE
;        DATA, never index 0.
;   DD2  Record with 16384 bytes of clear text: DATA cb = 16384 at dp=13, TRAILER 16, and
;        13+16384+16 = 16413 = exactly the record size on the wire.
;   DD3  A partial record (5 bytes submitted) returns 0x80090318, Windows text "the message supplied
;        is incomplete" = SEC_E_INCOMPLETE_MESSAGE, and the buffers become type 4 (MISSING) cb=8 =
;        the missing bytes. 0x80090321 is ANOTHER code (measure probe_dec D5).
;   DD4  The header/payload SPLIT is NOT ACCEPTED: STREAM_HEADER(5) + DATA(payload) returns
;        SEC_E_INVALID_TOKEN 0x80090308 (measure probe_dec2 F2, x86). And DATA without header returns
;        INCOMPLETE with an incoherent MISSING (F3): the length field is read inside the payload. So
;        shape F1 is THE only one: one DATA = one complete record, header included.
;   DD5  TWO records in a single DATA return 0x80090330 (Windows text: "cannot decrypt the specified
;        data" = SEC_E_DECRYPT_FAILURE), measured probe_dec2 F5 over 2 x 4125 bytes. One
;        DecryptMessage = ONE record, never more; it is the skeleton (5 + length field) that decides
;        what we submit and what we consume.
; =============================================================================
Func _Tls_DecryptStep($iIdx)
    Local $iRawLen = $g_aTls_RawLen[$iIdx]
    If $iRawLen = 0 Then Return SetError(0, 0, 0)
    Local $pBase = DllStructGetPtr($g_aTls_Raw[$iIdx])
    Local $iRecLen = _Tls_RecLen($pBase, $iRawLen)
    ; what we submit: the complete record when it is all there, otherwise what arrived
    Local $nSub = ($iRecLen > 0 And $iRawLen >= $iRecLen ? $iRecLen : $iRawLen)
    Local $tH = DllStructCreate("byte", $pBase)
    Local $iType = DllStructGetData($tH, 1)

    _Tls_SetBuf($iIdx, 0, $nSub, $Tls_SecBufferData, $pBase)
    For $k = 1 To 3
        _Tls_SetBuf($iIdx, $k, 0, $Tls_SecBufferEmpty, 0)
    Next
    DllStructSetData($g_aTls_Desc[$iIdx], 2, 4)
    DllStructSetData($g_aTls_Desc[$iIdx], 3, DllStructGetPtr($g_aTls_Bufs[$iIdx]))

    Local $a = DllCall("secur32.dll", "dword", "DecryptMessage", _
            "ptr", DllStructGetPtr($g_aTls_Ctx[$iIdx]), _
            "ptr", DllStructGetPtr($g_aTls_Desc[$iIdx]), "dword", 0, "ptr", 0)
    If @error Then
        _Tls_SetErr($iIdx, "DecryptMessage DllCall err " & @error)
        Return SetError(3, 0, 0)
    EndIf
    Local $rc = BitAND($a[0], 0xFFFFFFFF)

    Switch $rc
        Case $Tls_SecEOk
            ; DD1: the clear text is in the buffer of TYPE DATA, wherever it sits.
            Local $pPlain = 0, $cbPlain = 0
            For $k = 0 To 3
                If BitAND(_Tls_GetType($iIdx, $k), 0x7FFFFFFF) = $Tls_SecBufferData Then
                    $cbPlain = _Tls_GetCb($iIdx, $k)
                    $pPlain = _Tls_GetPtr($iIdx, $k)
                    ExitLoop
                EndIf
            Next
            If $iType = 0x15 And $cbPlain >= 2 And $pPlain <> 0 Then
                ; an alert is NEVER application data: level/description
                Local $tA = DllStructCreate("byte;byte", $pPlain)
                If Not @error Then
                    $g_aTls_Alert[$iIdx] = DllStructGetData($tA, 1) & "/" & DllStructGetData($tA, 2)
                EndIf
            ElseIf $cbPlain > 0 Then
                If $pPlain = 0 Then Return SetError(3, 0, 0)
                If $g_aTls_ClearLen[$iIdx] + $cbPlain > $g_iTlsClearSize Then _
                        Return SetError(5, $cbPlain, 0) ; file claire pleine : backpressure
                Local $tP = DllStructCreate("byte[" & $cbPlain & "]", $pPlain)
                If @error Then Return SetError(3, 0, 0)
                $g_aTls_Clear[$iIdx] &= DllStructGetData($tP, 1)
                $g_aTls_ClearLen[$iIdx] += $cbPlain
            EndIf
            ; Consumption = TLS skeleton (5 + length field), not a sum of cb: DD2 shows the two
            ; agree, and the skeleton does not depend on what Windows decided to rewrite.
            If $iRecLen = 0 Then Return SetError(3, 0, 0)
            _Tls_ConsumeRaw($iIdx, $iRecLen)
            $g_aTls_Records[$iIdx] += 1
            ; 0x15 = TLS alert: the peer announces its closure (close_notify).
            If $iType = 0x15 Then Return SetError(4, $rc, 1)
            Return SetError(0, $rc, 1)
        Case $Tls_SecEIncompleteMessage
            $g_aTls_Incomplete[$iIdx] += 1
            Return SetError(0, $rc, 0)  ; no complete record yet
        Case $Tls_SecIContextExpired, $Tls_SecIRenegotiate
            _Tls_SetErr($iIdx, "DecryptMessage " & _Tls_SecDesc($rc))
            Return SetError(4, $rc, 0)
        Case Else
            _Tls_SetErr($iIdx, "DecryptMessage " & _Tls_SecDesc($rc))
            Return SetError(3, $rc, 0)
    EndSwitch
EndFunc   ;==>_Tls_DecryptStep

;#FUNCTION#=====================================================================================================================
; Name ..........: _Tls_Pump
; Description ...: Drive everything that moves on a slot: flush, read, handshake legs and decryption.
; Syntax ........: _Tls_Pump($iIdx[, $iWaitMs])
; Parameters ....: $iIdx                 - slot index
;                  $iWaitMs              - [optional] poll budget for this turn, in milliseconds
; Return values .: Success - 1 = progress this turn.
;                  Failure - @error 2 = nothing to do this turn (never fatal, rule DS6), 3 = slot dead or handshake failed (@extended = SSPI code), 4 = clear queue full.
; Author ........: Numeric1
; Remarks .......: One entry point so that a client and a server share the same state machine; the per-slot handshake duration is recorded on completion.
; Related .......: _Tls_HandshakeLeg, _Tls_FlushTx, _Tls_DecryptStep
;===============================================================================================================================
; =============================================================================
; The pump: one entry point for everything that moves on the slot.
; Returns 1 with @error 0 = progress, @error 2 = nothing to do this turn, @error 3 = slot
; dead/closed (@extended = SSPI code), @error 4 = clear queue full.
; =============================================================================
Func _Tls_Pump($iIdx, $iWaitMs = 50)
    If $iIdx < 0 Or $iIdx >= $g_iTlsSlots Then Return SetError(3, 0, 0)
    Local $st = $g_aTls_State[$iIdx]
    If $st = $Tls_ST_FREE Or $st = $Tls_ST_DEAD Or $st = $Tls_ST_PEER_CLOSED Then _
            Return SetError(3, 0, 0)

    If BinaryLen($g_aTls_TxPend[$iIdx]) > 0 Then
        Local $f = _Tls_FlushTx($iIdx, $iWaitMs)
        Local $eF = @error
        ; 2 = poll expired, 3 = EWOULDBLOCK: the queue waits for the next turn.
        If $eF <> 0 And $eF <> 2 And $eF <> 3 Then Return SetError(3, @extended, 0)
    EndIf

    If $st = $Tls_ST_HANDSHAKE Or $st = $Tls_ST_CLOSING Then
        Local $r = _Tls_PullRaw($iIdx, $iWaitMs)
        Local $e = @error
        If $e = 2 Then Return SetError(2, 0, 0)
        If $e = 4 Then
            $g_aTls_State[$iIdx] = $Tls_ST_PEER_CLOSED
            Return SetError(3, 0, 0)
        EndIf
        If $e Then Return SetError(3, $e, 0)
        Local $leg = _Tls_HandshakeLeg($iIdx)
        Local $eL = @error
        If $eL Then
            $g_aTls_State[$iIdx] = $Tls_ST_DEAD
            Return SetError(3, $leg, 0)
        EndIf
        If $leg = 2 Then
            $g_aTls_State[$iIdx] = $Tls_ST_OPEN
            Return SetError(0, 0, 1)
        EndIf
        Return SetError(0, 0, 1)
    EndIf

    ; OPEN: read then decrypt until exhaustion.
    Local $loop = 0
    While $loop < 8
        $loop += 1
        Local $rr = _Tls_PullRaw($iIdx, $loop = 1 ? $iWaitMs : 0)
        Local $e2 = @error
        If $e2 = 2 Then
            ; nothing new: still try to decrypt what is left
        ElseIf $e2 = 4 Then
            If $g_aTls_RawLen[$iIdx] = 0 Then
                $g_aTls_State[$iIdx] = $Tls_ST_PEER_CLOSED
                Return SetError(3, 0, 0)
            EndIf
        ElseIf $e2 Then
            Return SetError(3, $e2, 0)
        EndIf
        Local $d = _Tls_DecryptStep($iIdx)
        Local $e3 = @error
        If $e3 = 5 Then Return SetError(4, $d, 0)
        If $e3 = 4 Then
            $g_aTls_State[$iIdx] = $Tls_ST_PEER_CLOSED
            Return SetError(3, @extended, 0)
        EndIf
        If $e3 Then Return SetError(3, @extended, 0)
        If $e2 = 2 And $d = 0 Then ExitLoop
    WEnd
    Return SetError(0, 0, 1)
EndFunc   ;==>_Tls_Pump

;#FUNCTION#=====================================================================================================================
; Name ..........: _Tls_Available
; Description ...: How many decrypted bytes are waiting to be read.
; Syntax ........: _Tls_Available($iIdx)
; Parameters ....: $iIdx                 - slot index
; Return values .: Success - Byte count.
; Author ........: Numeric1
; Related .......: _Tls_Read, _Tls_Pump
;===============================================================================================================================
Func _Tls_Available($iIdx)
    Return $g_aTls_ClearLen[$iIdx]
EndFunc   ;==>_Tls_Available

;#FUNCTION#=====================================================================================================================
; Name ..........: _Tls_PendingTx
; Description ...: How many encrypted bytes still wait for the wire.
; Syntax ........: _Tls_PendingTx($iIdx)
; Parameters ....: $iIdx                 - slot index
; Return values .: Success - Byte count.
; Author ........: Numeric1
; Remarks .......: Layer 3 needs this to know when to stop its send pump: _Tls_Send queues, it promises nothing about the network.
; Related .......: _Tls_Send, _Tls_FlushTx
;===============================================================================================================================
; Encrypted bytes still waiting to be written on the wire. Layer 3 needs this to know when to stop
; its send pump: _Tls_Send queues, it promises nothing about the network.
Func _Tls_PendingTx($iIdx)
    If $iIdx < 0 Or $iIdx >= $g_iTlsSlots Then Return 0
    Return BinaryLen($g_aTls_TxPend[$iIdx])
EndFunc   ;==>_Tls_PendingTx

;#FUNCTION#=====================================================================================================================
; Name ..........: _Tls_Read
; Description ...: Take decrypted bytes out of the clear queue.
; Syntax ........: _Tls_Read($iIdx[, $n])
; Parameters ....: $iIdx                 - slot index
;                  $n                    - [optional] maximum bytes to take, -1 = everything available
; Return values .: Success - Binary; empty binary when nothing is available.
; Author ........: Numeric1
; Related .......: _Tls_Available, _Tls_DecryptStep
;===============================================================================================================================
Func _Tls_Read($iIdx, $n = -1)
    Local $have = $g_aTls_ClearLen[$iIdx]
    If $n < 0 Or $n > $have Then $n = $have
    If $n <= 0 Then Return Binary("0x")
    Local $b = BinaryMid($g_aTls_Clear[$iIdx], 1, $n)
    If $n >= $have Then
        $g_aTls_Clear[$iIdx] = Binary("0x")
        $g_aTls_ClearLen[$iIdx] = 0
    Else
        $g_aTls_Clear[$iIdx] = BinaryMid($g_aTls_Clear[$iIdx], $n + 1)
        $g_aTls_ClearLen[$iIdx] = $have - $n
    EndIf
    Return $b
EndFunc   ;==>_Tls_Read

;#FUNCTION#=====================================================================================================================
; Name ..........: _Tls_State
; Description ...: Current state constant of a slot.
; Syntax ........: _Tls_State($iIdx)
; Parameters ....: $iIdx                 - slot index
; Return values .: Success - One of the $Tls_ST_* values.
; Author ........: Numeric1
; Remarks .......: Layer 3 compares these values without including tls.au3, so the numbers are part of the contract between layers.
; Related .......: _Tls_StateName, _Tls_Pump
;===============================================================================================================================
Func _Tls_State($iIdx)
    Return $g_aTls_State[$iIdx]
EndFunc   ;==>_Tls_State

;#FUNCTION#=====================================================================================================================
; Name ..........: _Tls_Info
; Description ...: One-line diagnostic of a slot: state, queues, counters, records, handshake duration and last error.
; Syntax ........: _Tls_Info($iIdx)
; Parameters ....: $iIdx                 - slot index
; Return values .: Success - String.
; Author ........: Numeric1
; Related .......: _Tls_StateName, _Tls_SetErr
;===============================================================================================================================
Func _Tls_Info($iIdx)
    Return "state=" & _Tls_StateName($g_aTls_State[$iIdx]) & _
            " raw=" & $g_aTls_RawLen[$iIdx] & " clear=" & $g_aTls_ClearLen[$iIdx] & _
            " tx=" & BinaryLen($g_aTls_TxPend[$iIdx]) & _
            " read=" & $g_aTls_BytesIn[$iIdx] & " written=" & $g_aTls_BytesOut[$iIdx] & _
            " records=" & $g_aTls_Records[$iIdx] & " incomplete=" & $g_aTls_Incomplete[$iIdx] & _
            " handshake=" & Round($g_aTls_HandshakeMs[$iIdx]) & _
            " alert=[" & $g_aTls_Alert[$iIdx] & "] err=[" & $g_aTls_Err[$iIdx] & "]"
EndFunc   ;==>_Tls_Info

;#FUNCTION#=====================================================================================================================
; Name ..........: _Tls_ApplyShutdown
; Description ...: Ask Schannel for the close_notify alert and queue it for the wire.
; Syntax ........: _Tls_ApplyShutdown($iIdx, $iBufferType)
; Parameters ....: $iIdx                 - slot index
;                  $iBufferType          - SecBuffer type used for the SCHANNEL_SHUTDOWN control token
; Return values .: Success - Diagnostic string with the ApplyControlToken and leg result, @error 0.
;                  Failure - @error 1 = DllCall failure on ApplyControlToken, 2 = ApplyControlToken refused (@extended = status code), 3 = DllCall failure on the returning leg (ISC or ASC).
; Author ........: Numeric1
; Remarks .......: The BufferType of that control token is not published in the documentation available here, so it is SWEEPED and the value that produces a 0x15 record is the right one; nothing is assumed. Rule DS1: on the server half the returning leg is AcceptSecurityContext.
; Related .......: _Tls_Close, _Tls_PushTx
;===============================================================================================================================
; =============================================================================
; close_notify: the Schannel contract is ApplyControlToken(SCHANNEL_SHUTDOWN) then an ISC leg that
; RETURNS the alert token. The BufferType of that control token is not published by the
; documentation available here: it is therefore SWEEPED, and the value that produces a 0x17 record is
; the right one. Nothing is assumed.
; =============================================================================
Func _Tls_ApplyShutdown($iIdx, $iBufferType)
    Local $tSd = DllStructCreate("dword")
    DllStructSetData($tSd, 1, 1) ; SCHANNEL_SHUTDOWN_VERSION
    Local $tBuf = DllStructCreate($g_sTlsSpecBuf4)
    DllStructSetData($tBuf, 1, DllStructGetSize($tSd))
    DllStructSetData($tBuf, 2, $iBufferType)
    DllStructSetData($tBuf, 3, DllStructGetPtr($tSd))
    Local $tDesc = DllStructCreate($g_sTlsSpecDesc)
    DllStructSetData($tDesc, 1, 0)
    DllStructSetData($tDesc, 2, 1)
    DllStructSetData($tDesc, 3, DllStructGetPtr($tBuf))
    Local $a = DllCall("secur32.dll", "dword", "ApplyControlToken", _
            "ptr", DllStructGetPtr($g_aTls_Ctx[$iIdx]), "ptr", DllStructGetPtr($tDesc))
    If @error Then Return SetError(1, 0, "ApplyControlToken DllCall err " & @error)
    If $a[0] <> 0 Then Return SetError(2, $a[0], "ApplyControlToken " & _Tls_SecDesc($a[0]))

    Local $tOutBuf = DllStructCreate($g_sTlsSpecBuf4)
    Local $tOutDesc = DllStructCreate($g_sTlsSpecDesc)
    DllStructSetData($tOutDesc, 1, 0)
    DllStructSetData($tOutDesc, 2, 1)
    DllStructSetData($tOutDesc, 3, DllStructGetPtr($tOutBuf))
    DllStructSetData($tOutBuf, 1, 0)
    DllStructSetData($tOutBuf, 2, $Tls_SecBufferToken)
    DllStructSetData($tOutBuf, 3, 0)
    Local $tAttr = DllStructCreate("dword")
    Local $iReqSrv = BitOR($Tls_IscReqReplayDetect, $Tls_IscReqSequenceDetect, _
            $Tls_IscReqConfidentiality, $Tls_IscReqAllocateMemory)
    Local $b
    If $g_aTls_Inbound[$iIdx] Then
        ; Same contract on the server side: ApplyControlToken then the leg that RETURNS the alert,
        ; but through AcceptSecurityContext (DS1).
        $b = DllCall("secur32.dll", "dword", "AcceptSecurityContext", _
                "ptr", DllStructGetPtr($g_aTls_Cred[$iIdx]), "ptr", DllStructGetPtr($g_aTls_Ctx[$iIdx]), _
                "ptr", 0, "dword", $iReqSrv, "dword", $Tls_SecurityNativeDrep, _
                "ptr", DllStructGetPtr($g_aTls_Ctx[$iIdx]), "ptr", DllStructGetPtr($tOutDesc), _
                "ptr", DllStructGetPtr($tAttr), "ptr", 0)
        If @error Then Return SetError(3, 0, "ASC(shutdown) DllCall err " & @error)
    Else
        $b = DllCall("secur32.dll", "dword", "InitializeSecurityContextW", _
                "ptr", DllStructGetPtr($g_aTls_Cred[$iIdx]), "ptr", DllStructGetPtr($g_aTls_Ctx[$iIdx]), _
                "wstr", $g_aTls_Sni[$iIdx], "dword", $iReqSrv, "dword", 0, _
                "dword", $Tls_SecurityNativeDrep, "ptr", 0, "dword", 0, _
                "ptr", DllStructGetPtr($g_aTls_Ctx[$iIdx]), "ptr", DllStructGetPtr($tOutDesc), _
                "ptr", DllStructGetPtr($tAttr), "ptr", 0)
        If @error Then Return SetError(3, 0, "ISC(shutdown) DllCall err " & @error)
    EndIf
    Local $rc = $b[0]
    Local $cbTok = DllStructGetData($tOutBuf, 1)
    Local $pTok = DllStructGetData($tOutBuf, 3)
    Local $s = "apply=SEC_E_OK isc=" & _Tls_SecDesc($rc) & " cbTok=" & $cbTok
    If $cbTok > 0 And $pTok <> 0 Then
        Local $t = DllStructCreate("byte[" & ($cbTok < 16 ? $cbTok : 16) & "]", $pTok)
        If Not @error Then $s &= " premier16=" & Hex(DllStructGetData($t, 1))
        Local $tAll = DllStructCreate("byte[" & $cbTok & "]", $pTok)
        If Not @error Then _Tls_PushTx($iIdx, DllStructGetData($tAll, 1))
        DllCall("secur32.dll", "dword", "FreeContextBuffer", "ptr", $pTok)
    EndIf
    Return SetError(0, $rc, $s)
EndFunc   ;==>_Tls_ApplyShutdown

;#FUNCTION#=====================================================================================================================
; Name ..........: _Tls_Close
; Description ...: Tear a slot down completely: optional close_notify, security context, owned credential and counters.
; Syntax ........: _Tls_Close($iIdx[, $iNotifyType])
; Parameters ....: $iIdx                 - slot index
;                  $iNotifyType          - [optional] 0 = no close_notify, otherwise the control-token BufferType to sweep
; Return values .: Success - Trace string (1 when the slot was already free).
;                  Failure - @error 1 = index out of table.
; Author ........: Numeric1
; Remarks .......: Rule R6: a double DeleteSecurityContext or FreeCredentialsHandle returns SEC_E_INVALID_HANDLE, so that code here means a teardown done twice, not a bug. Rule DS4: a shared INBOUND credential ($g_aTls_OwnCred = 0) is never freed by this call.
; Related .......: _Tls_ApplyShutdown, _Tls_InitSlot
;===============================================================================================================================
; Complete teardown. $iNotifyType = 0 -> no close_notify (measurement in progress).
Func _Tls_Close($iIdx, $iNotifyType = 0)
    If $iIdx < 0 Or $iIdx >= $g_iTlsSlots Then Return SetError(1, 0, 0)
    Local $st = $g_aTls_State[$iIdx]
    If $st = $Tls_ST_FREE Then Return 1
    Local $sTrace = ""
    If $iNotifyType <> 0 And ($st = $Tls_ST_OPEN Or $st = $Tls_ST_CLOSING) Then
        Local $r = _Tls_ApplyShutdown($iIdx, $iNotifyType)
        Local $eN = @error
        $sTrace = $r
        If Not $eN Then
            $g_aTls_State[$iIdx] = $Tls_ST_CLOSING
            For $t = 1 To 20
                Local $f = _Tls_FlushTx($iIdx, 10)
                If @error Then ExitLoop
                If BinaryLen($g_aTls_TxPend[$iIdx]) = 0 Then ExitLoop
            Next
        EndIf
    EndIf

    If $g_aTls_HaveCtx[$iIdx] Or $st = $Tls_ST_OPEN Then
        Local $d = DllCall("secur32.dll", "dword", "DeleteSecurityContext", _
                "ptr", DllStructGetPtr($g_aTls_Ctx[$iIdx]))
        If @error Then
            _Tls_SetErr($iIdx, "DeleteSecurityContext DllCall err " & @error)
        ElseIf $d[0] <> 0 Then
            _Tls_SetErr($iIdx, "DeleteSecurityContext " & _Tls_SecDesc($d[0]))
        EndIf
    EndIf
    Local $tCred = $g_aTls_Cred[$iIdx]
    ; DS4: an inbound slot does NOT own its credential (copy of the shared handle). Freeing it here
    ; would break the server's other connections.
    If $tCred <> 0 And $g_aTls_OwnCred[$iIdx] <> 0 Then
        Local $fr = DllCall("secur32.dll", "dword", "FreeCredentialsHandle", "ptr", DllStructGetPtr($tCred))
        If @error Then
            _Tls_SetErr($iIdx, "FreeCredentialsHandle DllCall err " & @error)
        ElseIf $fr[0] <> 0 Then
            ; R6: a code returned here means "already torn down", not "broken".
            _Tls_SetErr($iIdx, "FreeCredentialsHandle " & _Tls_SecDesc($fr[0]))
        EndIf
    EndIf
    If $g_aTls_Sock[$iIdx] <> 0 Then _Wsk_Close($g_aTls_Sock[$iIdx])

    $g_aTls_State[$iIdx] = $Tls_ST_FREE
    $g_aTls_Sock[$iIdx] = 0
    $g_aTls_Sni[$iIdx] = ""
    $g_aTls_Cred[$iIdx] = 0
    $g_aTls_Ctx[$iIdx] = 0
    $g_aTls_HaveCtx[$iIdx] = 0
    $g_aTls_Bufs[$iIdx] = 0
    $g_aTls_Desc[$iIdx] = 0
    $g_aTls_Out[$iIdx] = 0
    $g_aTls_Raw[$iIdx] = 0
    $g_aTls_RawLen[$iIdx] = 0
    $g_aTls_TxPend[$iIdx] = Binary("0x")
    $g_aTls_Clear[$iIdx] = Binary("0x")
    $g_aTls_ClearLen[$iIdx] = 0
    $g_aTls_Hdr[$iIdx] = 0
    $g_aTls_Trailer[$iIdx] = 0
    $g_aTls_MaxMsg[$iIdx] = 0
    $g_aTls_Inbound[$iIdx] = 0
    $g_aTls_OwnCred[$iIdx] = 0
    Return SetError(0, 0, $sTrace)
EndFunc   ;==>_Tls_Close
