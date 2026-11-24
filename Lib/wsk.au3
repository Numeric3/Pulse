;#INDEX# =======================================================================================================================
; Title .........: wsk.au3 - non-blocking Winsock transport (layer 1 of the WebSocket UDF)
; AutoIt Version : 3.3.16.1
; Language ......: English
; Description ...: Raw ws2_32.dll wrappers with the correct return types and a poll-driven,
;                  never-blocking I/O model. This layer knows nothing about WebSocket, TLS or
;                  a GUI: it only places the Winsock calls that layer 2 (tls.au3) and layer 3
;                  (wsp.au3) need.
; Remarks .......: Windows 8 and later, tested 32 and 64 bit. Every constant, offset and
;                  error code in this file is MEASURED on a real machine, never copied from a
;                  macro. The measurement notes are kept as comments because re-deriving them
;                  costs a day.
;                  A normal program does not include this file: it includes WebSocket.au3,
;                  which pulls the four layers in dependency order and decides nothing itself;
;                  going through one layer directly is a caller's choice, never a need.
; Copyright ....: Copyright (c) 2026 Numeric1
; Licence .......: MIT
; Author ........: Numeric1
; https .........:
;===============================================================================================================================

;#COMMENTS#=====================================================================================================================
; Verified facts this layer depends on
;
; FIONBIO = 0x8004667E. Measured, not derived: the documentation does not publish the value and
; no SDK header exists on the build machine. 0x4004667E is REJECTED by ws2_32 (socketioctl
; returns -1 with 10045 WSAEOPNOTSUPP); 0x4004667F is accepted but has no effect (it is FIONREAD
; and is ignored by ioctlsocket); 0x8004667E is the only value after which WSARecv returns
; WSAEWOULDBLOCK. Identical on x86 and x64.
;
; ioctlsocket does not know SIOCINQ (0x6770006B): -1 with 10045. The only call that reports the
; number of bytes already waiting is WSAIoctl(FIONREAD) - see _Wsk_Inq.
;
; A SOCKET is a UINT_PTR, so "handle" is the correct DllCall type HERE. It is not correct for an
; API that returns a DWORD error code: on x64 only the low 32 bits of RAX are defined, so a
; declaration that reads 64 bits can turn a success into an error. Same lesson applies to
; WSASend/WSARecv, which are declared "dword*" for the byte counters below.
;
; WSAPoll rejects POLLERR / POLLHUP in the "events" field (they are revents only): the whole call
; fails with WSAEINVAL. Ask for WRITABLE/RDNORM only and read the revents back.
;
; connect() on a loopback socket returns WSAEWOULDBLOCK (not 0) once the socket is non-blocking;
; the result is finished with WSAPoll(WRITABLE) plus getsockopt(SO_ERROR), which is the only
; honest way to know whether "writable" meant "connected".
;
; DNS (measures N1-N8, spike6\probe_dns.au3, 10/10 on both bitnesses):
;   N1 ADDRINFOW = "int;int;int;int;dword;ptr;ptr;ptr" -> 32 bytes x86 / 48 bytes x64, and the
;      offsets computed from the pointer size agree with the linked list actually walked.
;   N2 GetAddrInfoW before WSAStartup returns 10093 (WSANOTINITIALISED): resolution belongs to
;      this layer and requires _Wsk_Startup.
;   N3 "localhost" service "80" yields TWO records and "::1" comes BEFORE "127.0.0.1". The order
;      comes from the stack, not from us, so a caller that tries one address only can fail on a
;      healthy machine - hence the list loop in layer 4.
;   N4 With empty hints, ai_socktype and ai_protocol return 0: never trust the returned type,
;      always request it.
;   N5 AF_INET = 2 and AF_INET6 = 23 confirmed from the sa_family of the returned sockaddr (and
;      the hints really do filter the family).
;   N6 ai_flags in the RESULT is unreliable: asking for AI_CANONNAME (2) returns 0 although
;      ai_canonname is filled; AI_NUMERICHOST (4) returns 4.
;   N7 11001 = "Host not found" (FormatMessageW) for a name absent from DNS.
;   N8 FreeAddrInfoW returns nothing: declare it "none".
;
; Structure sizes measured on this machine: x86 WSABUF 8, WSAPOLLFD 8, pointer 4; x64 WSABUF 16,
; WSAPOLLFD 16, pointer 8; sockaddr_in 16 on both. AutoIt adds the trailing padding itself, so an
; array of two WSAPOLLFD stays aligned.
;
; CONTENTS
;   Life cycle ....... _Wsk_Startup, _Wsk_Cleanup
;   Errors ........... _Wsk_LastError, _Wsk_ErrorName
;   Handles .......... _Wsk_IsInvalid, _Wsk_Socket, _Wsk_Close, _Wsk_Inq, _Wsk_NonBlocking
;   Addresses ........ _Wsk_InetAton, _Wsk_MakeSockAddr, _Wsk_PortOf
;   Server side ...... _Wsk_Bind, _Wsk_Listen, _Wsk_GetSockName, _Wsk_Accept, _Wsk_GetPeerName
;   Client side ...... _Wsk_Connect, _Wsk_ConnectFinish, _Wsk_ConnectAddr
;   Pump ............. _Wsk_PollStructSize, _Wsk_Poll, _Wsk_PollList
;   Data transfer .... _Wsk_WsaBuf, _Wsk_SendChunk, _Wsk_Recv
;   Socket options ... _Wsk_GetSoError
;   Name resolution .. _Wsk_Resolve, _Wsk_FreeAddrInfo, _Wsk_AiField, _Wsk_AiFamily,
;                      _Wsk_AiSockType, _Wsk_AiProto, _Wsk_AiAddrPtr, _Wsk_AiAddrLen,
;                      _Wsk_AiNext, _Wsk_AiCanonName, _Wsk_AiCount
;   Formatting ....... _Wsk_ByteAt, _Wsk_AddrText
;===============================================================================================================================

#include-once

Global Const $Wsk_DLL = "ws2_32.dll"

; --- address families and socket types ---
Global Const $Wsk_AF_INET = 2
Global Const $Wsk_SOCK_STREAM = 1
Global Const $Wsk_FIONBIO = 0x8004667E ; MEASURED, not the macro: the documentation does not publish it

; --- WSAPoll events ---
Global Const $Wsk_POLLERR = 0x0001
Global Const $Wsk_POLLHUP = 0x0002
Global Const $Wsk_POLLNVAL = 0x0004
Global Const $Wsk_POLLWRNORM = 0x0010 ; POLLOUT
Global Const $Wsk_POLLWRBAND = 0x0020
Global Const $Wsk_POLLRDNORM = 0x0100
Global Const $Wsk_POLLRDBAND = 0x0200
Global Const $Wsk_POLLIN = 0x0300
Global Const $Wsk_POLLPRI = 0x0400

; --- named Winsock errors (without names the caller cannot tell "invalid handle" from "cable out") ---
Global Const $Wsk_EINVAL = 10022
Global Const $Wsk_ECONNRESET = 10054
Global Const $Wsk_ENOTCONN = 10057
Global Const $Wsk_EWOULDBLOCK = 10035
Global Const $Wsk_EINPROGRESS = 10036
Global Const $Wsk_EALREADY = 10037
Global Const $Wsk_ECONNABORTED = 10053
Global Const $Wsk_ECONNREFUSED = 10061
Global Const $Wsk_ETIMEDOUT = 10060
Global Const $Wsk_EADDRINUSE = 10048
Global Const $Wsk_EADDRNOTAVAIL = 10049

; --- socket options (used by _Wsk_GetSoError) ---
Global Const $Wsk_SOL_SOCKET = 0xFFFF
Global Const $Wsk_SO_ERROR = 0x1007

; --- name resolution (values from measures N5-N7, offsets from measure N1) ---
Global Const $Wsk_AF_INET6 = 23 ; measure N5, read back from sa_family
Global Const $Wsk_AI_CANONNAME = 2 ; measure N6 (name filled, flag not echoed)
Global Const $Wsk_AI_NUMERICHOST = 4 ; measure N6/N7 (one record, no DNS)
Global Const $Wsk_ERR_UNKNOWN_NAME = 11001 ; measure N7

Global Const $g_iWskPtrSize = DllStructGetSize(DllStructCreate("ptr"))
Global Const $g_iWskOffAiFamily = 4
Global Const $g_iWskOffAiSockType = 8
Global Const $g_iWskOffAiProto = 12
Global Const $g_iWskOffAiAddrLen = 16
Global Const $g_iWskOffAiCanon = 16 + $g_iWskPtrSize
Global Const $g_iWskOffAiAddr = 16 + $g_iWskPtrSize * 2
Global Const $g_iWskOffAiNext = 16 + $g_iWskPtrSize * 3

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsk_LastError
; Description ...: Winsock error code of the last failed call on this thread.
; Syntax ........: _Wsk_LastError() :None
; Return values .: Success - error code
;                  Failure - 0 and sets @error to 1 (ws2_32.dll unavailable)
; Author ........: Numeric1
; Remarks .......: Read it immediately after the failing call: any later call may overwrite it.
; Related .......: _Wsk_ErrorName
;===============================================================================================================================
Func _Wsk_LastError()
    Local $aCall = DllCall($Wsk_DLL, "int", "WSAGetLastError")
    If @error Then Return SetError(1, 0, 0)
    Return $aCall[0]
EndFunc   ;==>_Wsk_LastError

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsk_ErrorName
; Description ...: Turns a Winsock error code into the C symbolic name.
; Syntax ........: _Wsk_ErrorName($iError)
; Parameters ....: $iError               - code returned by _Wsk_LastError or stored in @extended.
; Return values .: Success - Known code - "EWOULDBLOCK", "ECONNREFUSED", ... ; 0 - "OK"; unknown code - "WSA_" & the numeric code.
; Author ........: Numeric1
; Remarks .......: Pure AutoIt, no API call, so it is safe to use inside an error handler.
; Related .......: _Wsk_LastError
;===============================================================================================================================
Func _Wsk_ErrorName($iError)
    Switch $iError
        Case $Wsk_EWOULDBLOCK
            Return "EWOULDBLOCK"
        Case $Wsk_EINPROGRESS
            Return "EINPROGRESS"
        Case $Wsk_EALREADY
            Return "EALREADY"
        Case $Wsk_EINVAL
            Return "EINVAL"
        Case $Wsk_ECONNREFUSED
            Return "ECONNREFUSED"
        Case $Wsk_ECONNRESET
            Return "ECONNRESET"
        Case $Wsk_ECONNABORTED
            Return "ECONNABORTED"
        Case $Wsk_ENOTCONN
            Return "ENOTCONN"
        Case $Wsk_ETIMEDOUT
            Return "ETIMEDOUT"
        Case $Wsk_EADDRINUSE
            Return "EADDRINUSE"
        Case $Wsk_EADDRNOTAVAIL
            Return "EADDRNOTAVAIL"
        Case 0
            Return "OK"
    EndSwitch
    Return "WSA_" & $iError
EndFunc   ;==>_Wsk_ErrorName

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsk_Startup
; Description ...: Initialises Winsock 2.x for this process.
; Syntax ........: _Wsk_Startup([$iVersion])
; Parameters ....: $iVersion             - [optional] requested version as WSABUILDVERS, default 0x0202.
; Return values .: Success - 1 and @extended = the wVersion word the stack actually agreed to.
;                  Failure - 0 and sets @error to 1 (ws2_32.dll unavailable) or 2 (WSAStartup refused, WSA code in @extended).
; Author ........: Numeric1
; Remarks .......: Required before any other call of this layer, including name resolution (measure N2: GetAddrInfoW without it returns 10093).
; Related .......: _Wsk_Cleanup
;===============================================================================================================================
Func _Wsk_Startup($iVersion = 0x0202)
    Local $tData = DllStructCreate("byte[408]")
    Local $aCall = DllCall($Wsk_DLL, "int", "WSAStartup", "word", $iVersion, "ptr", DllStructGetPtr($tData))
    If @error Then Return SetError(1, 0, 0)
    If $aCall[0] <> 0 Then Return SetError(2, $aCall[0], 0)
    ; wVersion is the first word of WSADATA (little-endian)
    Local $iGot = DllStructGetData(DllStructCreate("word", DllStructGetPtr($tData)), 1)
    Return SetError(0, $iGot, 1)
EndFunc   ;==>_Wsk_Startup

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsk_Cleanup
; Description ...: Decrements the Winsock reference count of this process.
; Syntax ........: _Wsk_Cleanup() :None
; Return values .: Success - 0
;                  Failure - 1 and sets @error to 1 (ws2_32.dll unavailable)
; Author ........: Numeric1
; Remarks .......: Call it once when the last connection is gone, not between connections.
; Related .......: _Wsk_Startup
;===============================================================================================================================
Func _Wsk_Cleanup()
    Local $aCall = DllCall($Wsk_DLL, "int", "WSACleanup")
    If @error Then Return SetError(1, 0, 0)
    Return $aCall[0]
EndFunc   ;==>_Wsk_Cleanup

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsk_IsInvalid
; Description ...: Tells whether a socket handle is INVALID_SOCKET.
; Syntax ........: _Wsk_IsInvalid($hSocket)
; Parameters ....: $hSocket              - handle returned by _Wsk_Socket or _Wsk_Accept.
; Return values .: Success - 1 = invalid, 0 = usable.
; Author ........: Numeric1
; Remarks .......: INVALID_SOCKET is (SOCKET)(~0), which AutoIt renders zero-padded to the pointer size: 0xFFFFFFFF on x86, 0xFFFFFFFFFFFFFFFF on x64. Both are tested.
; Related .......: _Wsk_Socket, _Wsk_Accept
;===============================================================================================================================
Func _Wsk_IsInvalid($hSocket)
    Local $s = String($hSocket)
    If $s = "0xFFFFFFFF" Then Return 1
    If $s = "0xFFFFFFFFFFFFFFFF" Then Return 1
    Return 0
EndFunc   ;==>_Wsk_IsInvalid

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsk_Socket
; Description ...: Creates a stream socket through WSASocketW.
; Syntax ........: _Wsk_Socket([$iAddressFamily[, $iType]])
; Parameters ....: $iAddressFamily       - [optional] $Wsk_AF_INET (default) or $Wsk_AF_INET6.
;                  $iType                - [optional] $Wsk_SOCK_STREAM (default).
; Return values .: Success - socket handle.
;                  Failure - 1 and sets @error to 1 (ws2_32.dll unavailable, call error in @extended) or 2 (INVALID_SOCKET, WSA code in @extended).
; Author ........: Numeric1
; Remarks .......: "handle" is the correct type here because WSASocketW really returns a UINT_PTR, unlike the APIs that return a DWORD error code.
; Related .......: _Wsk_Close, _Wsk_IsInvalid
;===============================================================================================================================
Func _Wsk_Socket($iAddressFamily = $Wsk_AF_INET, $iType = $Wsk_SOCK_STREAM)
    Local $aCall = DllCall($Wsk_DLL, "handle", "WSASocketW", _
            "int", $iAddressFamily, "int", $iType, "int", 0, _
            "ptr", 0, "uint", 0, "dword", 0)
    If @error Then Return SetError(1, @error, -1)
    If _Wsk_IsInvalid($aCall[0]) Then Return SetError(2, _Wsk_LastError(), -1)
    Return $aCall[0]
EndFunc   ;==>_Wsk_Socket

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsk_Close
; Description ...: Closes a socket.
; Syntax ........: _Wsk_Close($hSocket)
; Parameters ....: $hSocket              - handle to close.
; Return values .: Success - 1.
;                  Failure - 0 and sets @error to 1 (ws2_32.dll unavailable) or 2 (closesocket returned -1, WSA code in @extended).
; Author ........: Numeric1
; Remarks .......: There is no TLS shutdown and no WebSocket close frame here: this drops TCP.
; Related .......: _Wsk_Socket
;===============================================================================================================================
Func _Wsk_Close($hSocket)
    Local $aCall = DllCall($Wsk_DLL, "int", "closesocket", "handle", $hSocket)
    If @error Then Return SetError(1, 0, 0)
    If $aCall[0] = -1 Then Return SetError(2, _Wsk_LastError(), 0)
    Return 1
EndFunc   ;==>_Wsk_Close

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsk_Inq
; Description ...: Number of bytes already sitting in the receive queue of the socket.
; Syntax ........: _Wsk_Inq($hSocket)
; Parameters ....: $hSocket              - connected or listening socket.
; Return values .: Success - byte count (0 = nothing waiting).
;                  Failure - 1 and sets @error to 1 (ws2_32.dll unavailable) or 2 (WSAIoctl refused, WSA code in @extended).
; Author ........: Numeric1
; Remarks .......: MEASURED (probe_inq): ioctlsocket does not know SIOCINQ (0x6770006B, -1 with 10045) and ignores FIONREAD, so WSAIoctl(FIONREAD) is the only path that reports a value.
; Related .......: _Wsk_Poll
;===============================================================================================================================
Func _Wsk_Inq($hSocket)
    Local $tArg = DllStructCreate("dword")
    Local $aCall = DllCall($Wsk_DLL, "int", "WSAIoctl", _
            "handle", $hSocket, "dword", 0x4004667F, "ptr", 0, "dword", 0, _
            "ptr", DllStructGetPtr($tArg), "dword", 4, "dword*", 0, "ptr", 0, "ptr", 0)
    If @error Then Return SetError(1, 0, -1)
    If $aCall[0] = -1 Then Return SetError(2, _Wsk_LastError(), -1)
    Return DllStructGetData($tArg, 1)
EndFunc   ;==>_Wsk_Inq

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsk_NonBlocking
; Description ...: Switches a socket between blocking and non-blocking mode.
; Syntax ........: _Wsk_NonBlocking($hSocket[, $fOn])
; Parameters ....: $hSocket              - socket handle.
;                  $fOn                  - [optional] True (default) = non-blocking, False = blocking.
; Return values .: Success - 1.
;                  Failure - 0 and sets @error to 1 (ws2_32.dll unavailable) or 2 (ioctlsocket refused, WSA code in @extended).
; Author ........: Numeric1
; Remarks .......: Uses $Wsk_FIONBIO = 0x8004667E, the only value measured to take effect.
; Related .......: _Wsk_Poll
;===============================================================================================================================
Func _Wsk_NonBlocking($hSocket, $fOn = True)
    Local $tArg = DllStructCreate("dword")
    DllStructSetData($tArg, 1, ($fOn ? 1 : 0))
    Local $aCall = DllCall($Wsk_DLL, "int", "ioctlsocket", _
            "handle", $hSocket, "long", $Wsk_FIONBIO, "ptr", DllStructGetPtr($tArg))
    If @error Then Return SetError(1, 0, 0)
    If $aCall[0] = -1 Then Return SetError(2, _Wsk_LastError(), 0)
    Return 1
EndFunc   ;==>_Wsk_NonBlocking

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsk_InetAton
; Description ...: Converts a dotted IPv4 string into the 32-bit network-order value.
; Syntax ........: _Wsk_InetAton($sAddress)
; Parameters ....: $sAddress             - dotted quad, e.g. "127.0.0.1".
; Return values .: Success - address in network order.
;                  Failure - 0 and sets @error to 1 (ws2_32.dll unavailable) or 2 (INADDR_NONE: the string is not an IPv4 literal).
; Author ........: Numeric1
; Remarks .......: No DNS here - use _Wsk_Resolve for a name, and note that an IPv6 literal is rejected by inet_addr as well.
; Related .......: _Wsk_MakeSockAddr, _Wsk_Resolve
;===============================================================================================================================
Func _Wsk_InetAton($sAddress)
    Local $aCall = DllCall($Wsk_DLL, "dword", "inet_addr", "str", $sAddress)
    If @error Then Return SetError(1, 0, 0)
    ; INADDR_NONE (0xFFFFFFFF) = rejected; the value is already in network order
    If $aCall[0] = 0xFFFFFFFF Then Return SetError(2, 0, 0)
    Return $aCall[0]
EndFunc   ;==>_Wsk_InetAton

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsk_MakeSockAddr
; Description ...: Builds a sockaddr_in structure from an IPv4 literal and a host-order port.
; Syntax ........: _Wsk_MakeSockAddr($sAddress, $iPort)
; Parameters ....: $sAddress             - dotted quad ("0.0.0.0" binds any interface).
;                  $iPort                - 0..65535; 0 lets Windows pick a free port.
; Return values .: Success - sockaddr_in DllStruct (16 bytes on both bitnesses).
;                  Failure - 0 and sets @error to 1 (htons unavailable) or 2 (address rejected, code from _Wsk_InetAton in @extended).
; Author ........: Numeric1
; Remarks .......: The port is stored in network order by htons, never by hand.
; Related .......: _Wsk_Bind, _Wsk_Connect, _Wsk_PortOf
;===============================================================================================================================
Func _Wsk_MakeSockAddr($sAddress, $iPort)
    Local $iAddr = _Wsk_InetAton($sAddress)
    If @error Then Return SetError(2, $iAddr, 0)
    Local $t = DllStructCreate("short;short;dword;byte[8]")
    DllStructSetData($t, 1, $Wsk_AF_INET)
    ; sin_port goes on the wire in network order: htons
    Local $aCall = DllCall($Wsk_DLL, "ushort", "htons", "ushort", $iPort)
    If @error Then Return SetError(1, 0, 0)
    DllStructSetData($t, 2, $aCall[0])
    DllStructSetData($t, 3, $iAddr)
    Return $t
EndFunc   ;==>_Wsk_MakeSockAddr

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsk_PortOf
; Description ...: Host-order port stored inside a sockaddr_in.
; Syntax ........: _Wsk_PortOf($tSockAddr)
; Parameters ....: $tSockAddr            - structure built by _Wsk_MakeSockAddr or returned by _Wsk_GetSockName.
; Return values .: Success - port number
;                  Failure - 0 and sets @error to 1 (ntohs unavailable)
; Author ........: Numeric1
; Remarks .......: This is how a server learns the port Windows chose after bind(port 0) - no invented port numbers anywhere in the UDF.
; Related .......: _Wsk_GetSockName
;===============================================================================================================================
Func _Wsk_PortOf($tSockAddr)
    Local $aCall = DllCall($Wsk_DLL, "ushort", "ntohs", "ushort", DllStructGetData($tSockAddr, 2))
    If @error Then Return SetError(1, 0, 0)
    Return $aCall[0]
EndFunc   ;==>_Wsk_PortOf

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsk_Bind
; Description ...: Associates a socket with a local address and port.
; Syntax ........: _Wsk_Bind($hSocket, $sAddress, $iPort)
; Parameters ....: $hSocket              - socket handle.
;                  $sAddress             - dotted quad, "0.0.0.0" for any interface.
;                  $iPort                - local port, 0 = let Windows choose.
; Return values .: Success - 1.
;                  Failure - 0 and sets @error to 1 (bad address), 2 (ws2_32.dll unavailable) or 3 (bind refused, WSA code in @extended).
; Author ........: Numeric1
; Remarks .......: After bind with port 0, read the real port back with _Wsk_GetSockName + _Wsk_PortOf.
; Related .......: _Wsk_Listen, _Wsk_GetSockName
;===============================================================================================================================
Func _Wsk_Bind($hSocket, $sAddress, $iPort)
    Local $tAddr = _Wsk_MakeSockAddr($sAddress, $iPort)
    If @error Then Return SetError(1, 0, 0)
    Local $iSize = DllStructGetSize($tAddr)
    Local $aCall = DllCall($Wsk_DLL, "int", "bind", _
            "handle", $hSocket, "ptr", DllStructGetPtr($tAddr), "int", $iSize)
    If @error Then Return SetError(2, 0, 0)
    If $aCall[0] = -1 Then Return SetError(3, _Wsk_LastError(), 0)
    Return 1
EndFunc   ;==>_Wsk_Bind

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsk_Listen
; Description ...: Marks a bound socket as a listening socket.
; Syntax ........: _Wsk_Listen($hSocket[, $iBacklog])
; Parameters ....: $hSocket              - bound socket handle.
;                  $iBacklog             - [optional] pending-connection queue, default 8.
; Return values .: Success - 1.
;                  Failure - 0 and sets @error to 1 (ws2_32.dll unavailable) or 2 (listen refused, WSA code in @extended).
; Author ........: Numeric1
; Remarks .......: The socket must be non-blocking before _Wsk_Accept is polled, see _Wsk_NonBlocking.
; Related .......: _Wsk_Accept
;===============================================================================================================================
Func _Wsk_Listen($hSocket, $iBacklog = 8)
    Local $aCall = DllCall($Wsk_DLL, "int", "listen", "handle", $hSocket, "int", $iBacklog)
    If @error Then Return SetError(1, 0, 0)
    If $aCall[0] = -1 Then Return SetError(2, _Wsk_LastError(), 0)
    Return 1
EndFunc   ;==>_Wsk_Listen

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsk_GetSockName
; Description ...: Returns the local address a socket is bound to.
; Syntax ........: _Wsk_GetSockName($hSocket)
; Parameters ....: $hSocket              - bound or connected socket handle.
; Return values .: Success - sockaddr_in structure.
;                  Failure - 0 and sets @error to 1 (ws2_32.dll unavailable) or 2 (getsockname refused, WSA code in @extended).
; Author ........: Numeric1
; Remarks .......: Pair it with _Wsk_PortOf to discover an ephemeral port.
; Related .......: _Wsk_Bind, _Wsk_PortOf
;===============================================================================================================================
Func _Wsk_GetSockName($hSocket)
    Local $tAddr = DllStructCreate("short;short;dword;byte[8]")
    Local $tLen = DllStructCreate("int")
    DllStructSetData($tLen, 1, DllStructGetSize($tAddr))
    Local $aCall = DllCall($Wsk_DLL, "int", "getsockname", _
            "handle", $hSocket, "ptr", DllStructGetPtr($tAddr), "ptr", DllStructGetPtr($tLen))
    If @error Then Return SetError(1, 0, 0)
    If $aCall[0] = -1 Then Return SetError(2, _Wsk_LastError(), 0)
    Return $tAddr
EndFunc   ;==>_Wsk_GetSockName

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsk_GetPeerName
; Description ...: Reads the remote address and port of an already connected socket.
; Syntax ........: _Wsk_GetPeerName($hSocket)
; Parameters ....: $hSocket              - connected socket handle (client side or accepted socket).
; Return values .: Success - sockaddr structure, 28 bytes so that IPv4 and IPv6 both fit.
;                  Failure - 0 and sets @error to 1 (ws2_32.dll unavailable) or 2 (getpeername refused, WSA code in @extended)
; Author ........: Numeric1
; Remarks .......: The structure is deliberately oversized: getpeername shrinks the length it writes to 16 for IPv4, and the extra bytes stay zero. Read it with _Wsk_AddrText plus _Wsk_PortOf, which only look at the first two fields, identical in sockaddr_in and sockaddr_in6. An accepted socket carries no URL, so this is the only identity a server can log.
; Related .......: _Wsk_GetSockName, _Wsk_Accept, _Wsk_AddrText, _Wsk_PortOf
;===============================================================================================================================
Func _Wsk_GetPeerName($hSocket)
    Local $tAddr = DllStructCreate("short;short;dword;byte[20]")
    Local $tLen = DllStructCreate("int")
    DllStructSetData($tLen, 1, DllStructGetSize($tAddr))
    Local $aCall = DllCall($Wsk_DLL, "int", "getpeername", _
            "handle", $hSocket, "ptr", DllStructGetPtr($tAddr), "ptr", DllStructGetPtr($tLen))
    If @error Then Return SetError(1, 0, 0)
    If $aCall[0] = -1 Then Return SetError(2, _Wsk_LastError(), 0)
    Return $tAddr
EndFunc   ;==>_Wsk_GetPeerName

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsk_Accept
; Description ...: Takes one pending connection off a listening socket.
; Syntax ........: _Wsk_Accept($hListen)
; Parameters ....: $hListen              - listening socket handle.
; Return values .: Success - new socket handle (already connected).
;                  Failure - 1 and sets @error to 1 (ws2_32.dll unavailable) or 2 (no pending connection or refused, WSA code in @extended).
; Author ........: Numeric1
; Remarks .......: On a non-blocking listener, @error 2 with @extended = 10035 simply means "nothing waiting yet"; poll the listener for POLLRDNORM first. The returned socket inherits the blocking mode, so set it explicitly.
; Related .......: _Wsk_Listen, _Wsk_NonBlocking
;===============================================================================================================================
Func _Wsk_Accept($hListen)
    Local $aCall = DllCall($Wsk_DLL, "handle", "accept", "handle", $hListen, "ptr", 0, "ptr", 0)
    If @error Then Return SetError(1, 0, -1)
    If _Wsk_IsInvalid($aCall[0]) Then Return SetError(2, _Wsk_LastError(), -1)
    Return $aCall[0]
EndFunc   ;==>_Wsk_Accept

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsk_Connect
; Description ...: Starts a connection to an IPv4 literal and a host-order port.
; Syntax ........: _Wsk_Connect($hSocket, $sAddress, $iPort)
; Parameters ....: $hSocket              - socket handle, non-blocking for the measured behaviour.
;                  $sAddress             - dotted quad.
;                  $iPort                - remote port.
; Return values .: Success - 1 (completed immediately, usual on loopback).
;                  Failure - 0 and sets @error to 1 (bad address), 2 (ws2_32.dll unavailable), 3 (in progress, finish it with _Wsk_ConnectFinish; WSA code in @extended) or 4 (refused now, WSA code in @extended).
; Author ........: Numeric1
; Remarks .......: MEASURED: a non-blocking connect on loopback returns WSAEWOULDBLOCK, not 0, so @error 3 is the normal path and not an error.
; Related .......: _Wsk_ConnectFinish, _Wsk_ConnectAddr
;===============================================================================================================================
Func _Wsk_Connect($hSocket, $sAddress, $iPort)
    Local $tAddr = _Wsk_MakeSockAddr($sAddress, $iPort)
    If @error Then Return SetError(1, 0, 0)
    Local $iSize = DllStructGetSize($tAddr)
    Local $aCall = DllCall($Wsk_DLL, "int", "connect", _
            "handle", $hSocket, "ptr", DllStructGetPtr($tAddr), "int", $iSize)
    If @error Then Return SetError(2, 0, 0)
    If $aCall[0] = 0 Then Return 1 ; completed now (loopback in general)
    Local $iErr = _Wsk_LastError()
    If $iErr = $Wsk_EWOULDBLOCK Or $iErr = $Wsk_EINPROGRESS Or $iErr = $Wsk_EALREADY Then _
            Return SetError(3, $iErr, 0) ; to be finished with _Wsk_Poll
    Return SetError(4, $iErr, 0)
EndFunc   ;==>_Wsk_Connect

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsk_PollStructSize
; Description ...: Size AutoIt gives to one WSAPOLLFD ("ptr;short;short").
; Syntax ........: _Wsk_PollStructSize() :None
; Return values .: Success - 8 on x86, 16 on x64 (both measured).
; Author ........: Numeric1
; Remarks .......: Reported so a caller can build an array of descriptors; AutoIt adds the trailing padding itself, so a two-element array stays aligned.
; Related .......: _Wsk_Poll
;===============================================================================================================================
Func _Wsk_PollStructSize()
    Local $t = DllStructCreate("ptr;short;short")
    Return DllStructGetSize($t)
EndFunc   ;==>_Wsk_PollStructSize

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsk_Poll
; Description ...: Waits up to $iTimeoutMs for one socket to become readable or writable.
; Syntax ........: _Wsk_Poll($hSocket, $iEvents, $iTimeoutMs)
; Parameters ....: $hSocket              - socket handle.
;                  $iEvents              - $Wsk_POLLWRNORM and/or $Wsk_POLLRDNORM. Never POLLERR/POLLHUP.
;                  $iTimeoutMs           - 0 = return at once, -1 = wait forever, N = wait up to N ms.
; Return values .: Success - revents bit mask.
;                  Failure - 0 and sets @error to 1 (ws2_32.dll unavailable), 2 (WSAPoll failed, WSA code in @extended) or 3 (timed out - not an error).
; Author ........: Numeric1
; Remarks .......: MEASURED: WSAPoll rejects POLLERR/POLLHUP in "events" (they are revents only). Throughput of this pump: 19 500-21 200 calls/s with timeout 0, but only ~90-106 calls/s with timeout 2 ms, because 2 ms is rounded up to the ~10 ms system timer - use timeout 0 and Sleep(1) in a busy loop when latency matters.
; Related .......: _Wsk_Inq
;===============================================================================================================================
Func _Wsk_Poll($hSocket, $iEvents, $iTimeoutMs)
    Local $tFd = DllStructCreate("ptr;short;short")
    DllStructSetData($tFd, 1, $hSocket)
    DllStructSetData($tFd, 2, $iEvents)
    DllStructSetData($tFd, 3, 0)
    Local $aCall = DllCall($Wsk_DLL, "int", "WSAPoll", _
            "ptr", DllStructGetPtr($tFd), "uint", 1, "int", $iTimeoutMs)
    If @error Then Return SetError(1, 0, 0)
    If $aCall[0] = -1 Then Return SetError(2, _Wsk_LastError(), 0)
    If $aCall[0] = 0 Then Return SetError(3, 0, 0) ; timed out, not an error
    Return BitAND(DllStructGetData($tFd, 3), 0xFFFF)
EndFunc   ;==>_Wsk_Poll

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsk_PollList
; Description ...: Waits up to $iTimeoutMs on several sockets at once and reports each revents mask.
; Syntax ........: _Wsk_PollList($ahSockets, $iEvents, $iTimeoutMs, ByRef $aRevents[, $iCount])
; Parameters ....: $ahSockets            - array of socket handles.
;                  $iEvents              - $Wsk_POLLWRNORM and/or $Wsk_POLLRDNORM. Never POLLERR/POLLHUP.
;                  $iTimeoutMs           - 0 = return at once, -1 = wait forever, N = wait up to N ms.
;                  $aRevents             - [out] array, one mask per socket, in the same order as $ahSockets.
;                  $iCount               - [optional] how many leading entries of $ahSockets to poll;
;                                          0 = the whole array.
; Return values .: Success - number of ready sockets (0 with @error 3 = nobody became ready in time).
;                  Failure - 0 and sets @error to 1 (ws2_32.dll unavailable), 2 (WSAPoll failed,
;                  @extended = Winsock code), 4 (the descriptor array is not the expected size, so the
;                  revents of a socket would overlap its neighbour).
; Author ........: Numeric1
; Remarks .......: One WSAPoll call over the whole array is what makes a set of sockets affordable: the
;                  single-socket function in a loop would multiply the wait by the number of candidates.
;                  The descriptor array is built as "ptr;short;short" repeated, and the size is checked
;                  against _Wsk_PollStructSize so an alignment change in AutoIt shows up as a named error
;                  instead of a silent misread of the neighbour's revents. Measured 2026-11-15
;                  (spike11\probe_pollist.au3, 9/9 on both bitnesses): the array layout is exactly
;                  n x the element size, and a caller that keeps a fixed-size array only pays for the
;                  $iCount entries it asked for.
; Related .......: _Wsk_Poll, _Wsk_PollStructSize
;===============================================================================================================================
Func _Wsk_PollList($ahSockets, $iEvents, $iTimeoutMs, ByRef $aRevents, $iCount = 0)
    Local $n = UBound($ahSockets)
    If $iCount > 0 And $iCount < $n Then $n = $iCount
    Dim $aRevents[$n]
    If $n = 0 Then Return SetError(3, 0, 0)
    Local $sFields = ""
    For $i = 1 To $n
        $sFields &= "ptr;short;short;"
    Next
    Local $tFd = DllStructCreate(StringTrimRight($sFields, 1))
    Local $iOne = _Wsk_PollStructSize()
    If DllStructGetSize($tFd) <> $n * $iOne Then Return SetError(4, DllStructGetSize($tFd), 0)
    For $i = 0 To $n - 1
        DllStructSetData($tFd, $i * 3 + 1, $ahSockets[$i])
        DllStructSetData($tFd, $i * 3 + 2, $iEvents)
        DllStructSetData($tFd, $i * 3 + 3, 0)
        $aRevents[$i] = 0
    Next
    Local $aCall = DllCall($Wsk_DLL, "int", "WSAPoll", _
            "ptr", DllStructGetPtr($tFd), "uint", $n, "int", $iTimeoutMs)
    If @error Then Return SetError(1, 0, 0)
    If $aCall[0] = -1 Then Return SetError(2, _Wsk_LastError(), 0)
    If $aCall[0] = 0 Then Return SetError(3, 0, 0) ; nobody ready, not an error
    Local $iReady = 0
    For $i = 0 To $n - 1
        $aRevents[$i] = BitAND(DllStructGetData($tFd, $i * 3 + 3), 0xFFFF)
        If $aRevents[$i] <> 0 Then $iReady += 1
    Next
    Return $iReady
EndFunc   ;==>_Wsk_PollList

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsk_WsaBuf
; Description ...: Builds a WSABUF (buffer length + pointer) for WSASend/WSARecv.
; Syntax ........: _Wsk_WsaBuf($ptrBuffer, $iLength)
; Parameters ....: $ptrBuffer            - pointer to the memory to send or receive into.
;                  $iLength              - bytes available at that pointer.
; Return values .: Success - WSABUF DllStruct - 8 bytes on x86, 16 bytes on x64.
; Author ........: Numeric1
; Remarks .......: Field order is "dword;ptr": length first. This is exactly the pair (address + length) that websocket.dll expects from layer 3, so no home-grown buffer object is needed anywhere above this layer.
; Related .......: _Wsk_SendChunk, _Wsk_Recv
;===============================================================================================================================
Func _Wsk_WsaBuf($ptrBuffer, $iLength)
    Local $t = DllStructCreate("dword;ptr")
    DllStructSetData($t, 1, $iLength)
    DllStructSetData($t, 2, $ptrBuffer)
    Return $t
EndFunc   ;==>_Wsk_WsaBuf

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsk_ConnectFinish
; Description ...: Completes a non-blocking connect started by _Wsk_Connect.
; Syntax ........: _Wsk_ConnectFinish($hSocket, $iTimeoutMs)
; Parameters ....: $hSocket              - socket whose connect returned @error 3.
;                  $iTimeoutMs           - how long to wait for writability.
; Return values .: Success - 1 with @error 0 (connected).
;                  Failure - 0 and sets @error to 2 (still not writable, revents in @extended), 3 (the stack reported a failure, WSA code in @extended) or 4 (getsockopt itself failed, WSA code in @extended).
; Author ........: Numeric1
; Remarks .......: WRITABLE alone proves nothing: the Windows stack parks ECONNREFUSED in SO_ERROR, so only getsockopt(SO_ERROR) = 0 means connected.
; Related .......: _Wsk_Connect, _Wsk_GetSoError
;===============================================================================================================================
Func _Wsk_ConnectFinish($hSocket, $iTimeoutMs)
    ; POLLERR and POLLHUP are revents: putting them in "events" makes WSAPoll fail with
    ; WSAEINVAL. Ask for WRITABLE only, and let getsockopt(SO_ERROR) say whether writable
    ; actually means connected.
    Local $rv = _Wsk_Poll($hSocket, $Wsk_POLLWRNORM, $iTimeoutMs)
    Local $ePoll = @error
    Local $xPoll = @extended
    If $ePoll = 3 Then Return SetError(2, 0, 0) ; timed out
    If $ePoll <> 0 Then Return SetError(3, $xPoll, 0)
    Local $iErr = _Wsk_GetSoError($hSocket)
    Local $eSo = @error
    Local $xSo = @extended
    If $eSo Then Return SetError(4, $xSo, 0)
    If $iErr <> 0 Then Return SetError(3, $iErr, 0)
    If BitAND($rv, $Wsk_POLLWRNORM) = 0 Then Return SetError(2, $rv, 0)
    Return 1
EndFunc   ;==>_Wsk_ConnectFinish

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsk_GetSoError
; Description ...: Reads SO_ERROR on a socket (the deferred error of the last operation).
; Syntax ........: _Wsk_GetSoError($hSocket)
; Parameters ....: $hSocket              - socket handle.
; Return values .: Success - error value, 0 = no deferred error.
;                  Failure - 1 and sets @error to 1 (ws2_32.dll unavailable) or 2 (getsockopt refused, WSA code in @extended).
; Author ........: Numeric1
; Remarks .......: The only honest test for "did the non-blocking connect succeed": poll says writing is possible, SO_ERROR says whether the connection exists.
; Related .......: _Wsk_ConnectFinish
;===============================================================================================================================
Func _Wsk_GetSoError($hSocket)
    Local $tVal = DllStructCreate("int")
    Local $tLen = DllStructCreate("int")
    DllStructSetData($tLen, 1, DllStructGetSize($tVal))
    Local $aCall = DllCall($Wsk_DLL, "int", "getsockopt", _
            "handle", $hSocket, "int", $Wsk_SOL_SOCKET, "int", $Wsk_SO_ERROR, _
            "ptr", DllStructGetPtr($tVal), "ptr", DllStructGetPtr($tLen))
    If @error Then Return SetError(1, 0, -1)
    If $aCall[0] = -1 Then Return SetError(2, _Wsk_LastError(), -1)
    Return SetError(0, 0, DllStructGetData($tVal, 1))
EndFunc   ;==>_Wsk_GetSoError

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsk_SendChunk
; Description ...: Sends one binary block with WSASend, without ever blocking.
; Syntax ........: _Wsk_SendChunk($hSocket, $bData)
; Parameters ....: $hSocket              - connected socket.
;                  $bData                - binary payload. Length always comes from BinaryLen.
; Return values .: Success - bytes accepted by the stack (may be less than $bData).
;                  Failure - 0 and sets @error to 1 ($bData not binary), 2 (buffer refused), 3 (ws2_32.dll unavailable), 4 (WSAEWOULDBLOCK, bytes already accepted in the return value) or 5 (hard error, WSA code in @extended).
; Author ........: Numeric1
; Remarks .......: The byte counter is $aCall[4], not $aCall[3] - [3] is dwBufferCount. Getting it wrong looks like "4 bytes sent as 1" and stalls the send queue.
; Related .......: _Wsk_Recv, _Wsk_WsaBuf
;===============================================================================================================================
Func _Wsk_SendChunk($hSocket, $bData)
    If Not IsBinary($bData) Then Return SetError(1, 0, 0)
    Local $iLen = BinaryLen($bData)
    If $iLen = 0 Then Return 0

    Local $tBuf = DllStructCreate("byte[" & $iLen & "]")
    If @error Then Return SetError(2, 0, 0)
    DllStructSetData($tBuf, 1, $bData)
    If @error Then Return SetError(2, 0, 0)

    Local $tWsa = _Wsk_WsaBuf(DllStructGetPtr($tBuf), $iLen)
    Local $iSent = 0, $iFlags = 0
    Local $aCall = DllCall($Wsk_DLL, "int", "WSASend", _
            "handle", $hSocket, "ptr", DllStructGetPtr($tWsa), "dword", 1, _
            "dword*", $iSent, "dword", 0, "ptr", 0, "ptr", 0)
    If @error Then Return SetError(3, 0, 0)
    If $aCall[0] = -1 Then
        Local $iErr = _Wsk_LastError()
        If $iErr = $Wsk_EWOULDBLOCK Then Return SetError(4, $iErr, $aCall[4])
        Return SetError(5, $iErr, 0)
    EndIf
    ; WSASend(s, bufs, count, &bytesSent, flags, overlapped, completion):
    ; [0] rc, [1] s, [2] bufs, [3] count, [4] bytesSent.
    Return $aCall[4]
EndFunc   ;==>_Wsk_SendChunk

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsk_AiField
; Description ...: Reads one field out of an ADDRINFOW item returned by GetAddrInfoW.
; Syntax ........: _Wsk_AiField($pItem, $iOff, $sType)
; Parameters ....: $pItem                - pointer to the ADDRINFOW item.
;                  $iOff                 - byte offset of the field (see the $g_iWskOff* constants).
;                  $sType                - DllStruct type of the field ("int", "dword", "ptr").
; Return values .: Success - field value
;                  Failure - 0 and sets @error to 1 (null item) or 2 (structure refused)
; Author ........: Numeric1
; Remarks .......: Offsets follow measure N1: the structure is "int;int;int;int;dword;ptr;ptr;ptr", 32 bytes on x86 and 48 on x64, with the pointer fields placed from the pointer size, never from a header.
; Related .......: _Wsk_AiFamily, _Wsk_AiAddrPtr, _Wsk_AiNext
;===============================================================================================================================
Func _Wsk_AiField($pItem, $iOff, $sType)
    If $pItem = 0 Then Return SetError(1, 0, 0)
    Local $t = DllStructCreate($sType, $pItem + $iOff)
    If @error Then Return SetError(2, 0, 0)
    Return DllStructGetData($t, 1)
EndFunc   ;==>_Wsk_AiField

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsk_AiFamily
; Description ...: ai_family of one address-record item.
; Syntax ........: _Wsk_AiFamily($pItem)
; Parameters ....: $pItem                - pointer to an ADDRINFOW item.
; Return values .: Success - $Wsk_AF_INET (2) or $Wsk_AF_INET6 (23), both confirmed by measure N5
;                  Failure - 0 and sets @error (see _Wsk_AiField)
; Author ........: Numeric1
; Remarks .......: With empty hints the stack may report 0 for socktype and protocol (N4) - the family is still filled.
; Related .......: _Wsk_AiField
;===============================================================================================================================
Func _Wsk_AiFamily($pItem)
    Local $v = _Wsk_AiField($pItem, $g_iWskOffAiFamily, "int")
    Return SetError(@error, 0, $v)
EndFunc   ;==>_Wsk_AiFamily

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsk_AiSockType
; Description ...: ai_socktype of one address-record item.
; Syntax ........: _Wsk_AiSockType($pItem)
; Parameters ....: $pItem                - pointer to an ADDRINFOW item.
; Return values .: Success - socket type, 0 when the hints were empty (measure N4)
;                  Failure - 0 and sets @error (see _Wsk_AiField)
; Author ........: Numeric1
; Remarks .......: Ask for it in the hints; never trust a 0 read from an unfiltered query.
; Related .......: _Wsk_Resolve
;===============================================================================================================================
Func _Wsk_AiSockType($pItem)
    Local $v = _Wsk_AiField($pItem, $g_iWskOffAiSockType, "int")
    Return SetError(@error, 0, $v)
EndFunc   ;==>_Wsk_AiSockType

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsk_AiProto
; Description ...: ai_protocol of one address-record item.
; Syntax ........: _Wsk_AiProto($pItem)
; Parameters ....: $pItem                - pointer to an ADDRINFOW item.
; Return values .: Success - protocol number, 0 when the hints were empty (measure N4)
;                  Failure - 0 and sets @error (see _Wsk_AiField)
; Author ........: Numeric1
; Remarks .......: 0 = IPPROTO_AUTO on this stack, which is exactly why the hints must be set when the caller cares.
; Related .......: _Wsk_Resolve
;===============================================================================================================================
Func _Wsk_AiProto($pItem)
    Local $v = _Wsk_AiField($pItem, $g_iWskOffAiProto, "int")
    Return SetError(@error, 0, $v)
EndFunc   ;==>_Wsk_AiProto

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsk_AiAddrPtr
; Description ...: Pointer to the sockaddr carried by an address record.
; Syntax ........: _Wsk_AiAddrPtr($pItem)
; Parameters ....: $pItem                - pointer to an ADDRINFOW item.
; Return values .: Success - pointer (pass it with _Wsk_AiAddrLen to _Wsk_ConnectAddr)
;                  Failure - 0 and sets @error (see _Wsk_AiField)
; Author ........: Numeric1
; Remarks .......: The sockaddr itself is owned by Winsock: do not free or rewrite it.
; Related .......: _Wsk_AiAddrLen, _Wsk_ConnectAddr
;===============================================================================================================================
Func _Wsk_AiAddrPtr($pItem)
    Local $v = _Wsk_AiField($pItem, $g_iWskOffAiAddr, "ptr")
    Return SetError(@error, 0, Number($v))
EndFunc   ;==>_Wsk_AiAddrPtr

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsk_AiAddrLen
; Description ...: ai_addrlen of the sockaddr inside an address record.
; Syntax ........: _Wsk_AiAddrLen($pItem)
; Parameters ....: $pItem                - pointer to an ADDRINFOW item.
; Return values .: Success - 16 for IPv4, 28 for IPv6 (measure N3)
;                  Failure - 0 and sets @error (see _Wsk_AiField)
; Author ........: Numeric1
; Remarks .......: This is the length connect() must receive - the one Windows announces, never the size of a structure we invented.
; Related .......: _Wsk_ConnectAddr
;===============================================================================================================================
Func _Wsk_AiAddrLen($pItem)
    Local $v = _Wsk_AiField($pItem, $g_iWskOffAiAddrLen, "dword")
    Return SetError(@error, 0, Number($v))
EndFunc   ;==>_Wsk_AiAddrLen

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsk_AiNext
; Description ...: Pointer to the next item of the address-record list.
; Syntax ........: _Wsk_AiNext($pItem)
; Parameters ....: $pItem                - pointer to an ADDRINFOW item.
; Return values .: Success - next pointer, 0 at the end of the list
;                  Failure - 0 and sets @error (see _Wsk_AiField)
; Author ........: Numeric1
; Remarks .......: The list order is the stack's (measure N3: "::1" before "127.0.0.1"), so walk the whole list rather than trusting its head.
; Related .......: _Wsk_AiCount
;===============================================================================================================================
Func _Wsk_AiNext($pItem)
    Local $v = _Wsk_AiField($pItem, $g_iWskOffAiNext, "ptr")
    Return SetError(@error, 0, Number($v))
EndFunc   ;==>_Wsk_AiNext

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsk_AiCanonName
; Description ...: Canonical name stored in an address record.
; Syntax ........: _Wsk_AiCanonName($pItem)
; Parameters ....: $pItem                - pointer to an ADDRINFOW item.
; Return values .: Success - Canonical name, or "" when ai_canonname is null or unreadable.
; Author ........: Numeric1
; Remarks .......: Measure N6: the record's ai_flags does NOT echo AI_CANONNAME even when the name is filled, so test the string, not the flag.
; Related .......: _Wsk_Resolve
;===============================================================================================================================
Func _Wsk_AiCanonName($pItem)
    Local $p = _Wsk_AiField($pItem, $g_iWskOffAiCanon, "ptr")
    If @error Or $p = 0 Then Return ""
    Local $t = DllStructCreate("wchar[256]", Number($p))
    If @error Then Return ""
    Return StringStripWS(DllStructGetData($t, 1), 3)
EndFunc   ;==>_Wsk_AiCanonName

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsk_AiCount
; Description ...: Counts the items of an address-record list.
; Syntax ........: _Wsk_AiCount($pHead)
; Parameters ....: $pHead                - pointer returned by _Wsk_Resolve.
; Return values .: Success - Number of records, capped at 32.
; Author ........: Numeric1
; Remarks .......: The cap is a guard: a list that loops back on itself must not freeze the caller.
; Related .......: _Wsk_AiNext
;===============================================================================================================================
Func _Wsk_AiCount($pHead)
    Local $p = $pHead, $iN = 0
    While $p <> 0 And $iN < 32
        $iN += 1
        $p = _Wsk_AiNext($p)
    WEnd
    Return $iN
EndFunc   ;==>_Wsk_AiCount

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsk_Resolve
; Description ...: Resolves a host name or a literal address into a list of connect-ready records.
; Syntax ........: _Wsk_Resolve($sHost, $sService[, $iFamily[, $iSockType[, $iFlags[, $fCanon]]]])
; Parameters ....: $sHost                - host name or literal address.
;                  $sService             - port as a decimal string ("443"). A service name ("https") depends on the Windows services database and is NOT measured, so it is not promised.
;                  $iFamily              - [optional] 0 = any, $Wsk_AF_INET or $Wsk_AF_INET6.
;                  $iSockType            - [optional] 0 = any, $Wsk_SOCK_STREAM.
;                  $iFlags               - [optional] raw ai_flags value.
;                  $fCanon               - [optional] True adds AI_CANONNAME to the hints.
; Return values .: Success - head pointer of the list (free it with _Wsk_FreeAddrInfo) and @extended = number of records.
;                  Failure - 0 and sets @error to 1 (empty argument), 2 (GetAddrInfoW unavailable, DllCall error in @extended) or 3 (resolution failed, Winsock code in @extended; 11001 = unknown host).
; Author ........: Numeric1
; Remarks .......: WSAStartup must have run first (measure N2). Loop over the whole list: on this machine "localhost" offers "::1" before "127.0.0.1", and connecting to the head alone fails with ECONNREFUSED against an IPv4-only server.
; Related .......: _Wsk_FreeAddrInfo, _Wsk_ConnectAddr
;===============================================================================================================================
Func _Wsk_Resolve($sHost, $sService, $iFamily = 0, $iSockType = 0, $iFlags = 0, $fCanon = False)
    If $sHost = "" Or $sService = "" Then Return SetError(1, 0, 0)

    Local $tHint = 0, $pHint = 0
    If $iFamily <> 0 Or $iSockType <> 0 Or $iFlags <> 0 Or $fCanon Then
        $tHint = DllStructCreate("int;int;int;int;dword;ptr;ptr;ptr")
        If @error Then Return SetError(2, 0, 0)
        Local $iFlags2 = $iFlags
        If $fCanon Then $iFlags2 = BitOR($iFlags2, $Wsk_AI_CANONNAME)
        If $iFlags2 <> 0 Then DllStructSetData($tHint, 1, $iFlags2)
        If $iFamily <> 0 Then DllStructSetData($tHint, 2, $iFamily)
        If $iSockType <> 0 Then DllStructSetData($tHint, 3, $iSockType)
        $pHint = DllStructGetPtr($tHint)
    EndIf

    Local $tOut = DllStructCreate("ptr")
    Local $aCall = DllCall($Wsk_DLL, "int", "GetAddrInfoW", _
            "wstr", $sHost, "wstr", $sService, "ptr", $pHint, "ptr", DllStructGetPtr($tOut))
    Local $eCall = @error
    If $eCall Then Return SetError(2, $eCall, 0)
    If $aCall[0] <> 0 Then Return SetError(3, $aCall[0], 0)

    Local $pHead = Number(DllStructGetData($tOut, 1))
    If $pHead = 0 Then Return SetError(3, 0, 0)
    Return SetError(0, _Wsk_AiCount($pHead), $pHead)
EndFunc   ;==>_Wsk_Resolve

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsk_FreeAddrInfo
; Description ...: Releases a list returned by _Wsk_Resolve.
; Syntax ........: _Wsk_FreeAddrInfo($pHead)
; Parameters ....: $pHead                - head pointer to free.
; Return values .: Success - 1 = freed, 0 = nothing freed (null pointer or FreeAddrInfoW unavailable).
; Author ........: Numeric1
; Remarks .......: Measure N8: FreeAddrInfoW returns no value, so the call is declared "none"; reading it as a status would be inventing an API contract.
; Related .......: _Wsk_Resolve
;===============================================================================================================================
Func _Wsk_FreeAddrInfo($pHead)
    If $pHead = 0 Then Return 0
    DllCall($Wsk_DLL, "none", "FreeAddrInfoW", "ptr", $pHead)
    Return (@error ? 0 : 1)
EndFunc   ;==>_Wsk_FreeAddrInfo

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsk_ByteAt
; Description ...: Reads a single byte of memory.
; Syntax ........: _Wsk_ByteAt($p, $iOff)
; Parameters ....: $p                    - base pointer.
;                  $iOff                 - byte offset from the base.
; Return values .: Success - Byte value 0..255.
; Author ........: Numeric1
; Remarks .......: Helper for _Wsk_AddrText only; the caller is responsible for the pointer staying alive.
; Related .......: _Wsk_AddrText
;===============================================================================================================================
Func _Wsk_ByteAt($p, $iOff)
    Local $t = DllStructCreate("byte", $p + $iOff)
    Return DllStructGetData($t, 1)
EndFunc   ;==>_Wsk_ByteAt

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsk_AddrText
; Description ...: Renders a sockaddr as human-readable text.
; Syntax ........: _Wsk_AddrText($pSockAddr)
; Parameters ....: $pSockAddr            - pointer to a sockaddr (IPv4 or IPv6).
; Return values .: Success - "1.2.3.4", "[0000:0001:...]" or "fam<n>" for an unknown family; "" for a null pointer.
; Author ........: Numeric1
; Remarks .......: Pure AutoIt, no extra API call, so it can be used inside an error message. IPv6 is printed in full, without :: compression: it is for logs, not for connecting.
; Related .......: _Wsk_Resolve
;===============================================================================================================================
Func _Wsk_AddrText($pSockAddr)
    If $pSockAddr = 0 Then Return ""
    Local $tFam = DllStructCreate("short", $pSockAddr)
    Local $iFam = DllStructGetData($tFam, 1)
    If $iFam = $Wsk_AF_INET Then
        Return _Wsk_ByteAt($pSockAddr, 4) & "." & _Wsk_ByteAt($pSockAddr, 5) & "." & _
                _Wsk_ByteAt($pSockAddr, 6) & "." & _Wsk_ByteAt($pSockAddr, 7)
    EndIf
    If $iFam = $Wsk_AF_INET6 Then
        Local $s = ""
        For $i = 0 To 7
            $s &= ($i = 0 ? "" : ":") & Hex(_Wsk_ByteAt($pSockAddr, 8 + $i * 2), 2) & _
                    Hex(_Wsk_ByteAt($pSockAddr, 9 + $i * 2), 2)
        Next
        Return "[" & $s & "]"
    EndIf
    Return "fam" & $iFam
EndFunc   ;==>_Wsk_AddrText

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsk_ConnectAddr
; Description ...: connect() on a sockaddr produced by GetAddrInfoW.
; Syntax ........: _Wsk_ConnectAddr($hSocket, $pSockAddr, $iLen)
; Parameters ....: $hSocket              - non-blocking socket handle.
;                  $pSockAddr            - pointer from _Wsk_AiAddrPtr.
;                  $iLen                 - length from _Wsk_AiAddrLen (16 IPv4 / 28 IPv6).
; Return values .: Success - 1 (connected immediately).
;                  Failure - 0 and sets @error to 1 (argument rejected, $iLen in @extended), 2 (ws2_32.dll unavailable, DllCall error in @extended), 3 (in progress, finish with _Wsk_ConnectFinish, WSA code in @extended) or 4 (refused, WSA code in @extended).
; Author ........: Numeric1
; Remarks .......: Same error contract as _Wsk_Connect, so layer 4 can walk an address list with one handler for both paths.
; Related .......: _Wsk_Resolve, _Wsk_ConnectFinish
;===============================================================================================================================
Func _Wsk_ConnectAddr($hSocket, $pSockAddr, $iLen)
    If $pSockAddr = 0 Or $iLen < 16 Then Return SetError(1, $iLen, 0)
    Local $aCall = DllCall($Wsk_DLL, "int", "connect", _
            "handle", $hSocket, "ptr", $pSockAddr, "int", $iLen)
    If @error Then Return SetError(2, @error, 0)
    If $aCall[0] = 0 Then Return 1
    Local $iErr = _Wsk_LastError()
    If $iErr = $Wsk_EWOULDBLOCK Or $iErr = $Wsk_EINPROGRESS Or $iErr = $Wsk_EALREADY Then _
            Return SetError(3, $iErr, 0)
    Return SetError(4, $iErr, 0)
EndFunc   ;==>_Wsk_ConnectAddr

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsk_Recv
; Description ...: Reads up to $iMax bytes from the socket without blocking.
; Syntax ........: _Wsk_Recv($hSocket, $iMax)
; Parameters ....: $hSocket              - connected socket.
;                  $iMax                 - buffer size to allocate for this read.
; Return values .: Success - binary data plus @extended = the WSASend/WSARecv flags, and: @error 0 = data, 4 = nothing yet (WSAEWOULDBLOCK, @extended = 10035), 6 = clean close by the peer (0 bytes readable).
;                  Failure - empty binary and @error 1 ($iMax < 1), 2 (buffer refused), 3 (ws2_32.dll unavailable) or 5 (hard error, WSA code in @extended).
; Author ........: Numeric1
; Remarks .......: Every length here comes from BinaryLen / the returned counter, never from StringLen: StringLen of a binary value returns the length of its hex TEXT, which is what corrupts every binary send in the pre-existing WinHTTP UDF.
; Related .......: _Wsk_SendChunk, _Wsk_Inq
;===============================================================================================================================
Func _Wsk_Recv($hSocket, $iMax)
    If $iMax < 1 Then Return SetError(1, 0, Binary("0x"))

    Local $tBuf = DllStructCreate("byte[" & $iMax & "]")
    If @error Then Return SetError(2, 0, Binary("0x"))

    Local $tWsa = _Wsk_WsaBuf(DllStructGetPtr($tBuf), $iMax)
    Local $iRead = 0, $iFlags = 0
    Local $aCall = DllCall($Wsk_DLL, "int", "WSARecv", _
            "handle", $hSocket, "ptr", DllStructGetPtr($tWsa), "dword", 1, _
            "dword*", $iRead, "dword*", $iFlags, "ptr", 0, "ptr", 0)
    If @error Then Return SetError(3, 0, Binary("0x"))
    If $aCall[0] = -1 Then
        Local $iErr = _Wsk_LastError()
        If $iErr = $Wsk_EWOULDBLOCK Then Return SetError(4, $iErr, Binary("0x"))
        Return SetError(5, $iErr, Binary("0x"))
    EndIf
    Local $iGot = $aCall[4]
    If $iGot = 0 Then Return SetError(6, 0, Binary("0x")) ; clean FIN from the peer
    Return SetError(0, $aCall[5], BinaryMid(DllStructGetData($tBuf, 1), 1, $iGot))
EndFunc   ;==>_Wsk_Recv
