;#INDEX# =======================================================================================================================
; Title .........: ws.au3 - caller API for ws:// and wss:// (layer 4 of the WebSocket UDF)
; AutoIt Version : 3.3.16.1
; Language ......: English
; Description ...: One entry point for both schemes and both sides: _WS_Connect opens, _WS_Send /
;                  _WS_Request write, _WS_Pump / _WS_Message read, _WS_Close shuts down; _WS_Listen
;                  plus _WS_Accept / _WS_UpgradeHead / _WS_UpgradeAnswer serve, so a caller can write
;                  a wss:// server without touching a system call either. Every operation is
;                  bounded by a budget in milliseconds and every failure comes back as a named
;                  step plus a real system code.
; Remarks .......: Windows 8 and later, tested 32 and 64 bit. This file makes NO system call of
;                  its own: it knows neither ws2_32, nor secur32, nor websocket.dll. It decides,
;                  it orders, and it names errors. Each decision is justified by a measurement
;                  made in layers 1-3 (see the verified-facts block below).
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
;   WALK THE WHOLE ADDRESS LIST (mandatory, not cosmetic) - measures C1/C2/C3
;   (spike6\probe_conn.au3, 9/9 on both bitnesses): "localhost" returns "::1" BEFORE
;   "127.0.0.1", and connect() on the first entry returns ECONNREFUSED (10061) against a perfectly
;   healthy server that only listens on IPv4. A _WS_Connect that tried one address would therefore
;   fail on a healthy machine.
;
;   THE REFUSED IPv6 ENTRY IS SLOW, NOT INSTANT - rule V29, measure spike11\probe_d16d.au3 (x86 and x64):
;   the walk over "localhost" costs 2036-2063 ms while the server side of the same connection takes
;   65 ms and a literal "127.0.0.1" costs 3 ms. The 2 s is the wait for [::1] to report ECONNREFUSED,
;   so a candidate tried one after the other makes every localhost open two seconds late. The walk is
;   therefore a RACE: the candidates are started 250 ms apart, all stay in flight, WSAPoll covers the
;   whole set in one call, and the first success wins while the losers are closed. Same measure after
;   the change: localhost 253 ms, 127.0.0.1 unchanged.
;
;   A REFUSED CANDIDATE MUST NEVER END THE RACE - measure spike11 D14: with the pacing above, a
;   [::1] that answers ECONNREFUSED leaves no candidate in flight before the next 250 ms slot has
;   opened, and a walk that then gives up reports step 3/10061 against a healthy IPv4 server whose
;   record was never tried. So the stagger paces the race ONLY while something is in flight: an
;   empty in-flight set releases the next candidate at once.
;
;   TLS BEFORE UPGRADE, AND LAYER 3 NEVER TOUCHES THE SOCKET - pattern V16 (spike5, 12/12 on both
;   bitnesses) plus the V11-V14 seam.
;
;   THE PEER CHAIN IS VERIFIED BEFORE THE UPGRADE - rules V1-V10 (SSPI attributes read in DECIMAL
;   4/83/90, the named rejections 0x800B0109 and 0x800B010F). A 101 received over a rejected
;   certificate proves nothing.
;
;   THE SUBPROTOCOL IS NEGOTIATED IN THE HTTP HEADER, NOT BY ALPN - ALPN is measured as a CLOSED
;   DOOR on this Schannel (3 doors x 120 ids, ClientHello unchanged), and V17/V18/V19 give the
;   emit/read behaviour on the client and the server side.
;
;   ONE SEND CALL ARMS NOTHING BY ITSELF - V21: the bytes leave only when the send queue is
;   served; _WS_Request serves that queue, _WS_Send does not. V24: the buffer of a send must
;   survive until INDICATE_SEND_COMPLETE, and it is layer 3 that holds it (ring of 64).
;
;   ONE PUMP TICK CAN DELIVER TWO MESSAGES - V22/V14: so this layer never returns "the last
;   value", it returns a queue (see _WS_Message).
;
;   TEARDOWN ORDER - V15: close frame, drain, absorb the peer's close, then layer 3, then layer 2.
;   The socket is filed on the layer 2 side for wss:// so that no close path can close it twice.
;
; The handle returned by _WS_Connect IS the layer 3 slot index. The tables below are stored at the
; same index, so two numbering systems never have to be reconciled.
;
; CONTENTS
;   Start-up ......... _WS_Startup, _WS_PrepareTls, _WS_Cleanup
;   URL .............. _WS_ParseUrl
;   Open / close ..... _WS_ConnectAddrList, _WS_Connect, _WS_CloseHandle, _WS_Close
;   Server ........... _WS_Listen, _WS_ListenPort, _WS_ListenInfo, _WS_CloseListener, _WS_Accept,
;                      _WS_UpgradeHead, _WS_UpgradeAnswer, _WS_Upgrade, _WS_PickSubprotocol,
;                      _WS_RequestHeader, _WS_Method, _WS_CloseRefused, _WS_CloseInfo, _WS_HeadValue
;   Sending .......... _WS_Send, _WS_SendBinary, _WS_Flush, _WS_Request
;   Receiving ........ _WS_Pump, _WS_Message, _WS_MessageText, _WS_WaitMessage, _WS_Call
;   Introspection .... _WS_StateName, _WS_TypeName, _WS_Encode, _WS_IsSecure, _WS_Host, _WS_Port, _WS_Path,
;                      _WS_Scheme, _WS_PeerAddress, _WS_SelectedSub, _WS_OfferedSub,
;                      _WS_LastWalk, _WS_ErrorText, _WS_Info, _WS_HResultText
;===============================================================================================================================

#include-once

#include "wsk.au3"
#include "tls.au3"
#include "wsp.au3"

Global Const $WS_PORT_WS = 80
Global Const $WS_PORT_WSS = 443
; Rule V29: how long the race waits before starting the next address candidate. 250 ms is the value
; the stack itself uses for the same problem; it is short enough to hide the 2 s refused-IPv6 measure
; and long enough not to flood a host that has many A records.
Global Const $WS_CONNECT_STAGGER_MS = 250

; --- per-handle tables (index = layer 3 slot) ---
Global $g_aWs_Tls[$g_iWspSlots] ; layer 2 slot, -1 = plain ws://
Global $g_aWs_Host[$g_iWspSlots]
Global $g_aWs_Port[$g_iWspSlots]
Global $g_aWs_Path[$g_iWspSlots]
Global $g_aWs_Scheme[$g_iWspSlots]
Global $g_aWs_Addr[$g_iWspSlots] ; text of the address actually USED (measure C3)
Global $g_aWs_Subs[$g_iWspSlots] ; list offered, comma separated
Global $g_aWs_Err[$g_iWspSlots] ; last named error of the handle
Global $g_aWs_OpenMs[$g_iWspSlots]
; An OPEN that failed before a handle existed stores nothing in the slot tables, so one global
; string is enough for it.
Global $g_sWs_LastOpenError = ""
; Journal of the LAST walk over the address list, success or failure. Without it, "connected on
; the second try" cannot be told back to the caller.
Global $g_sWs_LastWalk = ""
Global $g_fWsTlsReady = 0
; --- listener tables (a listener is NOT a layer 3 slot, so it has its own numbering) ---
Global Const $g_iWsListeners = 8
Global $g_aWsL_Sock[$g_iWsListeners] ; listening socket handle, 0 = free slot
Global $g_aWsL_Secure[$g_iWsListeners] ; 1 = wss://, the peer must speak TLS first
Global $g_aWsL_Port[$g_iWsListeners] ; port actually bound (measure: read back, never invented)
Global $g_aWsL_Addr[$g_iWsListeners]
Global $g_aWsL_Rx[$g_iWsListeners] ; buffer handed to _Wsp_Create per accepted connection
Global $g_aWsL_MaxMsg[$g_iWsListeners] ; receive cap armed per accepted connection
Global $g_aWsL_Err[$g_iWsListeners] ; last named error of the listener
Global $g_fWsSrvCred = 0 ; 1 = this layer acquired the shared INBOUND credential
; --- extras for accepted (inbound) connections, indexed like the handles above ---
Global $g_aWs_Inbound[$g_iWspSlots] ; 1 = the peer dialed us, so there is no URL to report
Global $g_aWs_Head[$g_iWspSlots] ; request head kept for _WS_RequestHeader (routing, Origin)
Global $g_aWs_SelSub[$g_iWspSlots] ; subprotocol WE selected, the server answer
Global $g_aWs_Listen[$g_iWspSlots] ; listener index that produced the handle, -1 = client

;#FUNCTION#=====================================================================================================================
; Name ..........: _WS_StateName
; Description ...: Turns a layer 3 state number into a readable word.
; Syntax ........: _WS_StateName($iState)
; Parameters ....: $iState               - value returned by _Wsp_State.
; Return values .: Success - "free", "create", "handshake", "open", "closed", otherwise "state<n>".
; Author ........: Numeric1
; Remarks .......: Logging helper: layer 3 speaks in numbers, the caller wants a word.
; Related .......: _WS_Info
;===============================================================================================================================
Func _WS_StateName($iState)
    Switch $iState
        Case $g_iWspFree
            Return "free"
        Case $g_iWspCreated
            Return "create"
        Case $g_iWspHandshake
            Return "handshake"
        Case $g_iWspOpen
            Return "open"
        Case $g_iWspClosed
            Return "closed"
    EndSwitch
    Return "state" & $iState
EndFunc   ;==>_WS_StateName
;#FUNCTION#=====================================================================================================================
; Name ..........: _WS_TypeName
; Description ...: Turns a frame type number into a readable word.
; Syntax ........: _WS_TypeName($iType)
; Parameters ....: $iType                - value returned in @extended by _WS_WaitMessage, _WS_Message or _WS_Call.
; Return values .: Success - UTF8_MESSAGE, UTF8_FRAGMENT, BINARY_MESSAGE, BINARY_FRAGMENT,
;                  CLOSE, PING_PONG, UNSOLICITED_PONG; otherwise the number in hex.
; Author ........: Numeric1
; Remarks .......: The same word layer 3 uses, reached without including wsp.au3: a server that
;                  logs what it received needs this, and a raw signed number in a journal is not
;                  a name. Rule V28: CLOSE only ever comes out of the pump that saw it, so this
;                  is the word that tells an echo script to stop echoing and tear down.
; Related .......: _WS_WaitMessage, _WS_Pump, _Wsp_TypeName
;===============================================================================================================================
Func _WS_TypeName($iType)
    Return _Wsp_TypeName($iType)
EndFunc   ;==>_WS_TypeName

;#FUNCTION#=====================================================================================================================
; Name ..........: _WS_Encode
; Description ...: Turns caller data into the bytes to put on the wire plus the frame type.
; Syntax ........: _WS_Encode($vData, ByRef $iType)
; Parameters ....: $vData                - string or binary.
;                  $iType                - [out] $Wsp_UTF8_MESSAGE for a string, $Wsp_BINARY_MESSAGE for binary.
; Return values .: Success - Binary payload.
; Author ........: Numeric1
; Remarks .......: A string is ALWAYS UTF-8 (layer 3 measure A8: the third-party server echoes the text byte for byte), never the local ANSI code page of the machine.
; Related .......: _WS_Send, _WS_Request
;===============================================================================================================================
Func _WS_Encode($vData, ByRef $iType)
    If IsBinary($vData) Then
        $iType = $Wsp_BINARY_MESSAGE
        Return $vData
    EndIf
    $iType = $Wsp_UTF8_MESSAGE
    Return StringToBinary(String($vData), 8)
EndFunc   ;==>_WS_Encode

;#FUNCTION#=====================================================================================================================
; Name ..........: _WS_Startup
; Description ...: Initialises Winsock and clears every handle table.
; Syntax ........: _WS_Startup() :None
; Return values .: Success - 1
;                  Failure - 0 and sets @error to 1 (WSAStartup refused, WSA code in @extended)
; Author ........: Numeric1
; Remarks .......: Call once per process, before _WS_Connect. TLS is NOT started here: a plain ws:// client owes nothing to secur32.dll.
; Related .......: _WS_PrepareTls, _WS_Cleanup
;===============================================================================================================================
Func _WS_Startup()
    _Wsk_Startup()
    If @error Then Return SetError(1, @extended, 0)
    For $i = 0 To $g_iWspSlots - 1
        $g_aWs_Tls[$i] = -1
        $g_aWs_Host[$i] = ""
        $g_aWs_Port[$i] = 0
        $g_aWs_Path[$i] = ""
        $g_aWs_Scheme[$i] = ""
        $g_aWs_Addr[$i] = ""
        $g_aWs_Subs[$i] = ""
        $g_aWs_Err[$i] = ""
        $g_aWs_OpenMs[$i] = 0
        $g_aWs_Inbound[$i] = 0
        $g_aWs_Head[$i] = ""
        $g_aWs_SelSub[$i] = ""
        $g_aWs_Listen[$i] = -1
    Next
    For $i = 0 To $g_iWsListeners - 1
        $g_aWsL_Sock[$i] = 0
        $g_aWsL_Secure[$i] = 0
        $g_aWsL_Port[$i] = 0
        $g_aWsL_Addr[$i] = ""
        $g_aWsL_Rx[$i] = 65536
        $g_aWsL_MaxMsg[$i] = 4194304
        $g_aWsL_Err[$i] = ""
    Next
    Return 1
EndFunc   ;==>_WS_Startup

;#FUNCTION#=====================================================================================================================
; Name ..........: _WS_PrepareTls
; Description ...: Starts the Schannel package the first time a wss:// connection is opened.
; Syntax ........: _WS_PrepareTls() :None
; Return values .: Success - 1.
;                  Failure - 0 and sets @error to 1 (Schannel package unavailable, SSPI code in @extended).
; Author ........: Numeric1
; Remarks .......: Idempotent (spike4 measure: QuerySecurityPackageInfoW can be re-read), and never called for ws://.
; Related .......: _WS_Connect, _Tls_Startup
;===============================================================================================================================
Func _WS_PrepareTls()
    If $g_fWsTlsReady = 1 Then Return 1
    _Tls_Startup()
    If @error Then Return SetError(1, @extended, 0)
    $g_fWsTlsReady = 1
    Return 1
EndFunc   ;==>_WS_PrepareTls

;#FUNCTION#=====================================================================================================================
; Name ..........: _WS_Cleanup
; Description ...: Closes every open handle and releases Schannel and Winsock.
; Syntax ........: _WS_Cleanup() :None
; Return values .: Success - 1 always.
; Author ........: Numeric1
; Remarks .......: Each open handle goes through the measured teardown order of _WS_Close with a 1200 ms budget, so a live peer still receives its close frame. Listeners close after the connections, and the shared INBOUND credential is released last (rule DS4).
; Related .......: _WS_Startup, _WS_Close
;===============================================================================================================================
Func _WS_Cleanup()
    For $i = 0 To $g_iWspSlots - 1
        If $g_aWsp_State[$i] = $g_iWspFree Then ContinueLoop
        If $g_aWs_Inbound[$i] And $g_aWsp_State[$i] <> $g_iWspOpen Then
            ; An accepted slot that never answered 101 has no protocol to close: dismantling it is
            ; the only honest teardown, and it is the path spike 10 uses for a failed funnel.
            _WS_CloseHandle($i)
        Else
            _WS_Close($i, 1000, "", 1200)
        EndIf
    Next
    For $i = 0 To $g_iWsListeners - 1
        If $g_aWsL_Sock[$i] <> 0 Then _WS_CloseListener($i)
    Next
    ; Rule DS4: one INBOUND credential serves every accepted connection, so it is released once,
    ; here, after all connections are gone - never by a per-connection close.
    If $g_fWsSrvCred = 1 Then
        _Tls_SrvRelease()
        $g_fWsSrvCred = 0
    EndIf
    If $g_fWsTlsReady = 1 Then _Tls_Cleanup()
    _Wsk_Cleanup()
    $g_fWsTlsReady = 0
    Return 1
EndFunc   ;==>_WS_Cleanup

;#FUNCTION#=====================================================================================================================
; Name ..........: _WS_ParseUrl
; Description ...: Splits a ws:// or wss:// URL into scheme, host, port and path.
; Syntax ........: _WS_ParseUrl($sUrl, ByRef $sScheme, ByRef $sHost, ByRef $iPort, ByRef $sPath)
; Parameters ....: $sUrl                 - "ws://host[:port]/path" or "wss://...".
;                  $sScheme              - [out] "ws" or "wss", lower-cased.
;                  $sHost                - [out] host name, IPv4 literal or IPv6 literal without brackets.
;                  $iPort                - [out] port; 0 in the URL becomes 80 (ws) or 443 (wss).
;                  $sPath                - [out] path and query; an empty path becomes "/" and the fragment is dropped because an upgrade request never carries it.
; Return values .: Success - 1 with @error 0.
;                  Failure - 0 and sets @error to the step: 1 = missing or unknown scheme (@extended = 1), 2 = empty
;                  host, 3 = invalid port (@extended = the value read), 4 = malformed authority.
; Author ........: Numeric1
; Remarks .......: This grammar is STATED, not measured - it is text, not an API. A "user:pass@" authority is rejected on purpose (named limitation: HTTP basic authorization is not part of layer 3).
; Related .......: _WS_Connect
;===============================================================================================================================
Func _WS_ParseUrl($sUrl, ByRef $sScheme, ByRef $sHost, ByRef $iPort, ByRef $sPath)
    $sScheme = ""
    $sHost = ""
    $iPort = 0
    $sPath = ""

    Local $iSep = StringInStr($sUrl, "://")
    If $iSep = 0 Then Return SetError(1, 1, 0)
    $sScheme = StringLower(StringLeft($sUrl, $iSep - 1))
    If $sScheme <> "ws" And $sScheme <> "wss" Then Return SetError(1, 1, 0)

    Local $sRest = StringMid($sUrl, $iSep + 3)
    Local $iSlash = StringInStr($sRest, "/")
    Local $sAuth = ""
    If $iSlash = 0 Then
        $sAuth = $sRest
        $sPath = "/"
    Else
        $sAuth = StringLeft($sRest, $iSlash - 1)
        $sPath = StringMid($sRest, $iSlash)
    EndIf

    ; The fragment is not part of the upgrade request.
    Local $iHash = StringInStr($sPath, "#")
    If $iHash > 0 Then $sPath = StringLeft($sPath, $iHash - 1)
    If $sPath = "" Then $sPath = "/"

    ; Authority: [v6]:port | name:port | name
    If StringInStr($sAuth, "@") > 0 Then Return SetError(4, 0, 0) ; not supported
    If StringLeft($sAuth, 1) = "[" Then
        Local $iBr = StringInStr($sAuth, "]")
        If $iBr = 0 Then Return SetError(4, 0, 0)
        $sHost = StringLeft($sAuth, $iBr - 1) ; without the brackets
        $sHost = StringTrimLeft($sHost, 1)
        Local $sApr = StringMid($sAuth, $iBr + 1)
        If StringLeft($sApr, 1) = ":" Then $sApr = StringTrimLeft($sApr, 1)
        If $sApr <> "" Then
            If Not StringIsInt($sApr) Then Return SetError(3, 0, 0)
            $iPort = Number($sApr)
        EndIf
    Else
        Local $iCol = StringInStr($sAuth, ":")
        If $iCol = 0 Then
            $sHost = $sAuth
        Else
            $sHost = StringLeft($sAuth, $iCol - 1)
            Local $sP = StringMid($sAuth, $iCol + 1)
            If Not StringIsInt($sP) Then Return SetError(3, 0, 0)
            $iPort = Number($sP)
        EndIf
    EndIf

    If $sHost = "" Then Return SetError(2, 0, 0)
    If $iPort = 0 Then $iPort = ($sScheme = "wss" ? $WS_PORT_WSS : $WS_PORT_WS)
    If $iPort < 1 Or $iPort > 65535 Then Return SetError(3, $iPort, 0)
    If StringInStr($sHost, "@") > 0 Then Return SetError(4, 0, 0) ; not supported
    ; EXPLICIT SetError: without it the @error of that last StringInStr (1 when the at-sign is
    ; absent, so ALWAYS on the success path) would leave the call as an invented error.
    Return SetError(0, 0, 1)
EndFunc   ;==>_WS_ParseUrl

;#FUNCTION#=====================================================================================================================
; Name ..........: _WS_ConnectAddrList
; Description ...: Resolves a host and races every address the stack returned; the first connect that succeeds wins.
; Syntax ........: _WS_ConnectAddrList($sHost, $iPort, $iBudgetMs, ByRef $hSocket, ByRef $sAddr[, ByRef $iFam[, ByRef $sLog]])
; Parameters ....: $sHost                - host name or literal address.
;                  $iPort                - remote port.
;                  $iBudgetMs            - TOTAL budget of the race, not of one attempt.
;                  $hSocket              - [out] connected socket, -1 on failure.
;                  $sAddr                - [out] text of the address that worked.
;                  $iFam                 - [out] address family of that address.
;                  $sLog                 - [out] one entry per candidate, for _WS_LastWalk.
; Return values .: Success - number of the record that won (1 = the first), @extended = records resolved.
;                  Failure - 0 and sets @error to 3 (nothing resolved, Winsock code in @extended) or
;                  4 (no address of the list answered, last Winsock code in @extended).
; Author ........: Numeric1
; Remarks .......: AI_NUMERICHOST is tried first (measure C5: one record in 0.3 ms without DNS) - not cosmetic, it keeps "127.0.0.1" off the resolver and makes open latency measurable. Rule V29: the candidates are started $WS_CONNECT_STAGGER_MS apart and stay in flight together, so a refused IPv6 entry no longer delays the healthy IPv4 one by the two seconds it takes to say so. The stagger only paces the race while something IS in flight: as soon as no candidate is pending the next one goes at once, because waiting a slot on an address that already answered is how a refused IPv6 made the walk give up before the IPv4 was ever tried (measure D14, step 3/10061). Every socket that did not win is closed here, the ADDRINFO block is freed only once the last candidate is decided, and the whole race is bounded by $iBudgetMs. Each record carries start= and end= stamps in $g_sWs_LastWalk, because the quantity V29 governs is the WALK window, not the open latency, which also contains the TLS handshake and the 101, that is the server's scheduling (measure probe_d16e: walk closed in 256 ms inside a connect leg of 1839 ms).
; Related .......: _Wsk_Resolve, _Wsk_PollList, _WS_Connect
;===============================================================================================================================
Func _WS_ConnectAddrList($sHost, $iPort, $iBudgetMs, ByRef $hSocket, ByRef $sAddr, ByRef $iFam, ByRef $sLog)
    $hSocket = -1
    $sAddr = ""
    $iFam = 0
    $sLog = ""

    Local $sService = String($iPort)
    ; AI_NUMERICHOST first (measure C5: 1 record, 0.3 ms, no DNS); this is not a cosmetic
    ; optimisation, it is what avoids a resolver call for "127.0.0.1" and keeps the open latency
    ; measurable.
    Local $pList = _Wsk_Resolve($sHost, $sService, 0, $Wsk_SOCK_STREAM, $Wsk_AI_NUMERICHOST)
    Local $eNum = @error
    If $eNum Then
        $pList = _Wsk_Resolve($sHost, $sService, 0, $Wsk_SOCK_STREAM, 0)
        If @error Then Return SetError(3, @extended, 0)
    EndIf
    Local $iN = @extended

    ; The records are copied out first: the race has to reach any of them at any moment, and the
    ; ADDRINFO block stays alive until the last candidate is decided, so it is freed after the loop.
    Local $iMax = $iN
    If $iMax > 16 Then $iMax = 16
    If $iMax < 1 Then
        _Wsk_FreeAddrInfo($pList)
        Return SetError(4, 0, 0)
    EndIf
    Local $apAddr[$iMax], $aiLen[$iMax], $aiFam[$iMax], $asTxt[$iMax]
    Local $ahSock[$iMax], $aiState[$iMax], $asRes[$iMax]
    Local $aiStart[$iMax], $aiEnd[$iMax]
    Local $p = $pList, $i = 0
    While $p <> 0 And $i < $iMax
        $apAddr[$i] = _Wsk_AiAddrPtr($p)
        $aiLen[$i] = _Wsk_AiAddrLen($p)
        $aiFam[$i] = _Wsk_AiFamily($p)
        $asTxt[$i] = _Wsk_AddrText($apAddr[$i])
        $ahSock[$i] = -1
        $aiState[$i] = 0 ; 0 = never started, 1 = in flight, 2 = decided and dead
        $asRes[$i] = ""
        $aiStart[$i] = -1
        $aiEnd[$i] = -1
        $i += 1
        $p = _Wsk_AiNext($p)
    WEnd

    Local $t0 = TimerInit(), $iStarted = 0, $iLastErr = 0, $iWin = -1
    Local $k, $eC, $xC, $iLive, $iWait, $rem, $iErr, $eSo, $j, $sNote = ""
    Local $aPoll[$iMax], $aMap[$iMax], $aRv[$iMax]
    Local $iLive0, $fSlot
    While $iWin < 0 And TimerDiff($t0) < $iBudgetMs
        ; How many candidates are in flight at this moment. Measured here: the first record of
        ; "localhost" is [::1], and it answers either late - then it is simply abandoned because
        ; the IPv4 won first - or refused. Refused was the fatal case: with the refused candidate
        ; closed nothing was in flight any more, the next stagger slot had not opened, and the
        ; walk gave up reporting the refusal while 127.0.0.1 had never been tried at all
        ; (spike11 D14, step 3/10061).
        $iLive0 = 0
        For $k = 0 To $iMax - 1
            If $aiState[$k] = 1 Then $iLive0 += 1
        Next

        ; --- one new candidate per stagger slot, the earlier ones stay in flight; but when
        ;     nothing is in flight the next candidate goes at once: the stagger is there to keep
        ;     several connects racing together, never to sit waiting on an address already dead.
        $fSlot = ($iLive0 = 0 Or TimerDiff($t0) >= $iStarted * $WS_CONNECT_STAGGER_MS)
        If $iStarted < $iMax And $fSlot Then
            $k = $iStarted
            $iStarted += 1
            $ahSock[$k] = _Wsk_Socket($aiFam[$k], $Wsk_SOCK_STREAM)
            $eC = @error
            If $eC Then
                $aiState[$k] = 2
                $asRes[$k] = "socket=" & $eC
                ContinueLoop
            EndIf
            _Wsk_NonBlocking($ahSock[$k])
            _Wsk_ConnectAddr($ahSock[$k], $apAddr[$k], $aiLen[$k])
            $eC = @error
            $xC = @extended
            $aiStart[$k] = Round(TimerDiff($t0))
            If $eC = 0 Then
                $iWin = $k
                $aiEnd[$k] = $aiStart[$k]
                $asRes[$k] = "CONNECTED"
            ElseIf $eC = 3 Then
                $aiState[$k] = 1
            Else
                $aiState[$k] = 2
                $aiEnd[$k] = $aiStart[$k]
                $iLastErr = $xC
                $asRes[$k] = _Wsk_ErrorName($xC)
                _Wsk_Close($ahSock[$k])
                $ahSock[$k] = -1
            EndIf
            ContinueLoop
        EndIf

        ; --- one WSAPoll over the whole in-flight set (rule V29) ---
        $iLive = 0
        For $k = 0 To $iMax - 1
            If $aiState[$k] <> 1 Then ContinueLoop
            $aPoll[$iLive] = $ahSock[$k]
            $aMap[$iLive] = $k
            $iLive += 1
        Next
        If $iLive = 0 Then ExitLoop ; every candidate started AND decided, nobody connected
        $iWait = $WS_CONNECT_STAGGER_MS
        If $iStarted >= $iMax Then $iWait = 50
        $rem = $iBudgetMs - TimerDiff($t0)
        If $rem < 0 Then $rem = 0
        If $iWait > $rem Then $iWait = $rem
        _Wsk_PollList($aPoll, $Wsk_POLLWRNORM, $iWait, $aRv, $iLive)
        Local $eR = @error
        Local $xR = @extended
        If $eR <> 0 And $eR <> 3 Then
            ; The poll itself refused: say which, instead of reporting "no address answered".
            $sNote = " poll refused " & $eR & "/" & $xR
            ExitLoop
        EndIf
        For $j = 0 To $iLive - 1
            If $aRv[$j] = 0 Then ContinueLoop
            $k = $aMap[$j]
            $iErr = _Wsk_GetSoError($ahSock[$k])
            $eSo = @error
            Local $iNow = Round(TimerDiff($t0))
            ; getsockopt(SO_ERROR) is what tells the truth, not the writability WSAPoll reports
            ; (layer 1 measure): a refused connect also makes the socket writable.
            If $eSo = 0 And $iErr = 0 Then
                $iWin = $k
                $aiEnd[$k] = $iNow
                $asRes[$k] = "CONNECTED"
                ExitLoop
            EndIf
            $aiState[$k] = 2
            $aiEnd[$k] = $iNow
            $iLastErr = ($iErr <> 0 ? $iErr : @extended)
            $asRes[$k] = _Wsk_ErrorName($iLastErr)
            _Wsk_Close($ahSock[$k])
            $ahSock[$k] = -1
        Next
    WEnd

    ; The losers of the race are closed here, so a won IPv4 never leaves a half-open IPv6 behind.
    ; The journal is then rebuilt in CANDIDATE ORDER, because "the second address won" only reads
    ; clearly when the entries are still in the order the resolver returned them. The two stamps
    ; are what makes the race itself measurable: the walk window is the quantity rule V29 governs,
    ; and the open latency of _WS_Connect also contains the TLS handshake and the 101, which is the
    ; SERVER's scheduling, not the address list (measure probe_d16e: connect leg 1839 ms with the
    ; whole walk closed in 256 ms).
    Local $iClosed = Round(TimerDiff($t0))
    For $k = 0 To $iMax - 1
        If $aiState[$k] = 1 And $k <> $iWin Then
            _Wsk_Close($ahSock[$k])
            $aiEnd[$k] = $iClosed
            $asRes[$k] = "abandoned"
        ElseIf $aiState[$k] = 0 And $asRes[$k] = "" Then
            $asRes[$k] = "not started"
        EndIf
        $sLog &= " #" & ($k + 1) & " " & $asTxt[$k]
        If $aiStart[$k] >= 0 Then $sLog &= " start=" & $aiStart[$k] & " end=" & $aiEnd[$k]
        $sLog &= " " & $asRes[$k]
    Next
    $sLog &= $sNote
    _Wsk_FreeAddrInfo($pList)
    If $iWin < 0 Then
        If $iLastErr = 0 Then $iLastErr = 10060 ; WSAETIMEDOUT: the budget closed the race, not a refusal
        Return SetError(4, $iLastErr, 0)
    EndIf
    $hSocket = $ahSock[$iWin]
    $sAddr = $asTxt[$iWin]
    $iFam = $aiFam[$iWin]
    Return SetError(0, $iN, $iWin + 1)
EndFunc   ;==>_WS_ConnectAddrList

;#FUNCTION#=====================================================================================================================
; Name ..........: _WS_Connect
; Description ...: Opens a WebSocket connection over ws:// or wss://, non-blocking, budgeted.
; Syntax ........: _WS_Connect($sUrl[, $iBudgetMs[, $sSubprotocols[, $iRx[, $iMaxMsg[, $fIgnoreRoot]]]]])
; Parameters ....: $sUrl                 - "ws://host[:port]/path" or "wss://...".
;                  $iBudgetMs            - [optional] total budget of the open (TCP + TLS + upgrade), default 15000 ms.
;                  $sSubprotocols        - [optional] comma-separated list to offer, or "" (measure V17: the COMPONENT emits the header, nothing is hand-built here).
;                  $iRx                  - [optional] armed receive buffer per message, default 65536 - the size layer 3 delivers in fragments (measure A4).
;                  $iMaxMsg              - [optional] largest reassembled message, default 4194304.
;                  $fIgnoreRoot          - [optional] True accepts a self-signed chain; it does NOT weaken the name check (measure V6).
; Return values .: Success - handle (the layer 3 slot index), @extended = number of addresses tried, and the
;                  receive action is already armed.
;                  Failure - -1 and sets @error to: 1 = invalid URL (@extended: 1 scheme, 2 host, 3 port, 4 form),
;                  2 = name could not be resolved (@extended = Winsock code, 11001 = unknown host), 3 = no address
;                  of the list answered (@extended = last Winsock code), 4 = layer 2 unavailable (DllCall or
;                  Schannel package), 5 = TLS handshake unfinished (@extended = layer 2 state), 6 = peer chain
;                  REJECTED (@extended = verdict HRESULT, text in _WS_ErrorText), 7 = no layer 3 slot or
;                  websocket.dll missing, 8 = upgrade request refused by the component (@extended = HRESULT),
;                  9 = the request could not be written (@extended = named layer 1/2 error), 10 = the 101 answer
;                  never arrived (@extended = bytes received), 11 = invalid answer (@extended = component
;                  HRESULT), 12 = arming the receive was refused (@extended).
; Author ........: Numeric1
; Remarks .......: Every step names itself, so a failure is testable: an unnumbered step without the system code cannot be asserted on. On any failure the socket, the TLS context and the component handle are released in the V15 order.
; Related .......: _WS_ParseUrl, _WS_ConnectAddrList, _WS_Close
;===============================================================================================================================
Func _WS_Connect($sUrl, $iBudgetMs = 15000, $sSubprotocols = "", $iRx = 65536, _
        $iMaxMsg = 4194304, $fIgnoreRoot = False)
    $g_sWs_LastOpenError = ""
    Local $sScheme, $sHost, $iPort, $sPath
    Local $v = _WS_ParseUrl($sUrl, $sScheme, $sHost, $iPort, $sPath)
    If @error Then
        $g_sWs_LastOpenError = "URL rejected step " & @extended & " [" & $sUrl & "]"
        Return SetError(1, @extended, -1)
    EndIf

    If $sScheme = "wss" Then
        _WS_PrepareTls()
        If @error Then
            $g_sWs_LastOpenError = "Schannel package unavailable"
            Return SetError(4, @extended, -1)
        EndIf
    EndIf

    Local $t0 = TimerInit()
    Local $hSock = -1, $sAddr = "", $iFam = 0, $sLog = ""
    _WS_ConnectAddrList($sHost, $iPort, $iBudgetMs, $hSock, $sAddr, $iFam, $sLog)
    Local $e = @error
    Local $x = @extended
    $g_sWs_LastWalk = $sLog
    If $e = 3 Then
        $g_sWs_LastOpenError = "cannot resolve [" & $sHost & "]: " & $x & " " & _Wsk_ErrorName($x)
        Return SetError(2, $x, -1)
    ElseIf $e <> 0 Then
        $g_sWs_LastOpenError = "no address reached for [" & $sHost & "] list=[" & $sLog & "]" & _
                " last=" & _Wsk_ErrorName($x)
        Return SetError(3, $x, -1)
    EndIf
    Local $iRemaining = $iBudgetMs - TimerDiff($t0)
    If $iRemaining < 1000 Then $iRemaining = 1000

    Local $iTls = -1
    If $sScheme = "wss" Then
        ; The socket is already connected and chosen, so layer 2 only has to put the legs of the
        ; handshake on it (pattern V16, $hReady of measure C3).
        $iTls = _Tls_Connect("", 0, $sHost, 0, True, $hSock)
        $e = @error
        If $iTls < 0 Then
            _Wsk_Close($hSock)
            $g_sWs_LastOpenError = "layer 2 unavailable step " & $e & " " & _Tls_SecDesc($e)
            Return SetError(4, $e, -1)
        EndIf
        Local $iState = _Tls_State($iTls)
        While $iState <> $Tls_ST_OPEN And TimerDiff($t0) < $iBudgetMs
            _Tls_Pump($iTls, 50)
            $e = @error
            If $e > 2 Then
                $g_sWs_LastOpenError = "TLS handshake failed step " & $e & " " & $g_aTls_Err[$iTls]
                _Tls_Close($iTls, 0)
                Return SetError(5, $e, -1)
            EndIf
            $iState = _Tls_State($iTls)
        WEnd
        If $iState <> $Tls_ST_OPEN Then
            $g_sWs_LastOpenError = "TLS handshake unfinished state=" & _Tls_StateName($iState)
            _Tls_Close($iTls, 0)
            Return SetError(5, $iState, -1)
        EndIf
        ; Upgrade only if the chain is acceptable: a 101 received over a rejected certificate
        ; proves nothing (rules V1-V10).
        Local $fOk = _Tls_VerifyChain($iTls, $sHost, $fIgnoreRoot)
        $e = @error
        Local $xChain = @extended
        If Not $fOk Then
            $g_sWs_LastOpenError = "chain rejected: " & _Tls_VerifyError($iTls)
            _Tls_Close($iTls, 0)
            ; @extended = the verdict HRESULT Windows returned (0x800B0109 = root not trusted,
            ; 0x800B010F = name mismatch). A numbered step without the code cannot be tested.
            Return SetError(6, $xChain, -1)
        EndIf
    EndIf

    Local $iIdx = _Wsp_Create(0, $iRx, 65536)
    Local $eCreate = @error
    If $iIdx < 0 Then
        If $iTls >= 0 Then _Tls_Close($iTls, 0)
        $g_sWs_LastOpenError = "no layer 3 slot or websocket.dll missing, step " & $eCreate
        Return SetError(7, $eCreate, -1)
    EndIf
    $g_aWs_Tls[$iIdx] = $iTls
    $g_aWs_Host[$iIdx] = $sHost
    $g_aWs_Port[$iIdx] = $iPort
    $g_aWs_Path[$iIdx] = $sPath
    $g_aWs_Scheme[$iIdx] = $sScheme
    $g_aWs_Addr[$iIdx] = $sAddr
    $g_aWs_Subs[$iIdx] = $sSubprotocols
    $g_aWs_Err[$iIdx] = ""

    If $sScheme = "wss" Then
        ; The seam: from here layer 3 no longer talks to the socket, it talks to layer 2
        ; (V11-V14). The socket is filed on the layer 2 side, not in $g_aWsp_Socket, so a
        ; _Wsp_Close can never close it twice.
        _Wsp_AttachTls($iIdx, $iTls)
        If @error Then
            $g_aWs_Err[$iIdx] = "AttachTls step " & @error
            _Wsp_Close($iIdx)
            _Tls_Close($iTls, 0)
            $g_aWs_Tls[$iIdx] = -1
            Return SetError(4, @error, -1)
        EndIf
    Else
        $g_aWsp_Socket[$iIdx] = $hSock
    EndIf

    Local $sReq = "", $aSups = 0
    If $sSubprotocols <> "" Then $aSups = StringSplit(StringStripWS($sSubprotocols, 8), ",", 2)
    Local $nT = _Wsp_BeginClient($iIdx, $sHost, $iPort, $sPath, $sReq, $aSups, _
            ($sScheme = "wss" ? $WS_PORT_WSS : $WS_PORT_WS))
    $e = @error
    If $e Then
        $g_aWs_Err[$iIdx] = "BeginClient step " & $e & " " & _Wsp_HexHResult(@extended)
        $g_sWs_LastOpenError = $g_aWs_Err[$iIdx]
        _WS_CloseHandle($iIdx)
        Return SetError(8, @extended, -1)
    EndIf

    _Wsp_NetWrite($iIdx, StringToBinary($sReq, 1), $iRemaining)
    $e = @error
    Local $xW = @extended
    If $e Then
        $g_aWs_Err[$iIdx] = "writing the request failed step " & $e & "/" & $xW
        $g_sWs_LastOpenError = $g_aWs_Err[$iIdx]
        _WS_CloseHandle($iIdx)
        Return SetError(9, $xW, -1)
    EndIf

    Local $sHead = _Wsp_ReadHead($iIdx, $iRemaining)
    $e = @error
    If $e Or $sHead = "" Then
        $g_aWs_Err[$iIdx] = "response head never arrived step " & $e
        $g_sWs_LastOpenError = $g_aWs_Err[$iIdx]
        _WS_CloseHandle($iIdx)
        Return SetError(10, @extended, -1)
    EndIf

    Local $tBlock = _Wsp_EndClient($iIdx, $sHead)
    $e = @error
    If $e Then
        $g_aWs_Err[$iIdx] = "response refused step " & $e & " " & _Wsp_HexHResult(@extended) & _
                " head=[" & StringRegExpReplace($sHead, "\R", " | ") & "]"
        $g_sWs_LastOpenError = $g_aWs_Err[$iIdx]
        _WS_CloseHandle($iIdx)
        Return SetError(11, @extended, -1)
    EndIf
    $g_aWsp_RspBlock[$iIdx] = $tBlock

    _Wsp_Receive($iIdx, $iMaxMsg)
    $e = @error
    If $e Then
        $g_aWs_Err[$iIdx] = "arming receive failed step " & $e
        $g_sWs_LastOpenError = $g_aWs_Err[$iIdx]
        _WS_CloseHandle($iIdx)
        Return SetError(12, @extended, -1)
    EndIf

    $g_aWs_OpenMs[$iIdx] = Round(TimerDiff($t0), 1)
    Return SetError(0, $nT, $iIdx)
EndFunc   ;==>_WS_Connect

;#FUNCTION#=====================================================================================================================
; Name ..........: _WS_CloseHandle
; Description ...: Releases a handle whose open failed halfway.
; Syntax ........: _WS_CloseHandle($iIdx)
; Parameters ....: $iIdx                 - handle to dismantle.
; Return values .: Success - 1 always.
; Author ........: Numeric1
; Remarks .......: The measured teardown order of V15 (layer 3 first, then layer 2) is what makes a double socket close impossible.
; Related .......: _WS_Connect, _WS_Close
;===============================================================================================================================
Func _WS_CloseHandle($iIdx)
    Local $iTls = $g_aWs_Tls[$iIdx]
    _Wsp_Close($iIdx)
    If $iTls >= 0 Then _Tls_Close($iTls, 0)
    $g_aWs_Tls[$iIdx] = -1
    $g_aWsp_Socket[$iIdx] = 0
    Return 1
EndFunc   ;==>_WS_CloseHandle

; =============================================================================
; SERVER SIDE. Three calls, in this order: _WS_Listen once, _WS_Accept whenever the
; listener is readable, _WS_Upgrade once per accepted handle.
;
; The funnel below is the one spike 10 measured at both bitnesses, with the SAME step
; order, because the order is what the measurement proved: TLS first, then the head
; read in the clear, then BeginServer/101/EndServer, then arming the receive. Skipping
; or reordering any of these legs is what made the earlier attempts lose the close
; code (rules V27/V28).
;
; ONE NAMED UNFAIRNESS, MEASURED AND NOT HIDDEN: _Wsp_ReadHead blocks while it waits
; for the request head, so during that window the other connections are not served.
; spike 10 counted it (teteBloqueeMaxMs) and it is the reason the budget is a parameter
; of _WS_Upgrade instead of an internal constant. Everything else in the loop is one
; slice per connection per turn.
; =============================================================================

;#FUNCTION#=====================================================================================================================
; Name ..........: _WS_Listen
; Description ...: Opens a listening socket, optionally with the TLS server credential.
; Syntax ........: _WS_Listen($iPort[, $sAddr[, $sPfxPath[, $sPass[, $iRx[, $iMaxMsg]]]]])
; Parameters ....: $iPort                - local port, 0 = let Windows choose (read it back with _WS_ListenPort).
;                  $sAddr                - [optional] local address, "127.0.0.1" by default, "0.0.0.0" for any interface.
;                  $sPfxPath             - [optional] PKCS#12 file with the certificate; empty = plain ws://, no TLS at all.
;                  $sPass                - [optional] password of the PKCS#12 file.
;                  $iRx                  - [optional] receive buffer handed to each accepted connection, 65536 by default.
;                  $iMaxMsg              - [optional] largest message accepted from a peer, 4194304 by default (the same cap IIS publishes as receiveBufferLimit).
; Return values .: Success - Listener index (>= 0), usable with _WS_Accept.
;                  Failure - -1 and sets @error to 1 (no free listener slot), 2 (socket refused, WSA code in @extended), 3 (non-blocking mode refused), 4 (bind refused, WSA code in @extended), 5 (listen refused, WSA code in @extended), 6 (the bound port could not be read back), 7 (Schannel package unavailable), 8 (server credential refused, SSPI code in @extended)
; Author ........: Numeric1
; Remarks .......: A ws:// listener is legal: spike 9 proved that such a listener answers a named refusal to a TLS client instead of hanging, which is the behaviour a mixed port expects. The credential is acquired ONCE for the process (rule DS4): every accepted connection shares it, so _WS_CloseListener never releases it.
; Related .......: _WS_Accept, _WS_Upgrade, _WS_CloseListener, _Tls_SrvPrepare
;===============================================================================================================================
Func _WS_Listen($iPort, $sAddr = "127.0.0.1", $sPfxPath = "", $sPass = "", $iRx = 65536, $iMaxMsg = 4194304)
    Local $iL = -1
    For $i = 0 To $g_iWsListeners - 1
        If $g_aWsL_Sock[$i] = 0 Then
            $iL = $i
            ExitLoop
        EndIf
    Next
    If $iL < 0 Then
        $g_sWs_LastOpenError = "no free listener slot (max " & $g_iWsListeners & ")"
        Return SetError(1, 0, -1)
    EndIf
    If $iPort < 0 Or $iPort > 65535 Then
        $g_sWs_LastOpenError = "port out of range: " & $iPort
        Return SetError(1, $iPort, -1)
    EndIf

    Local $fSecure = ($sPfxPath <> "")
    If $fSecure Then
        _WS_PrepareTls()
        If @error Then
            $g_sWs_LastOpenError = "Schannel package unavailable"
            Return SetError(7, @extended, -1)
        EndIf
        If Not _Tls_SrvPrepare($sPfxPath, $sPass) Then
            $g_sWs_LastOpenError = "server credential refused step " & @error & " " & _Tls_SecDesc(@extended)
            Return SetError(8, @extended, -1)
        EndIf
        $g_fWsSrvCred = 1
    EndIf

    Local $hS = _Wsk_Socket($Wsk_AF_INET)
    If @error Then
        $g_sWs_LastOpenError = "socket refused"
        Return SetError(2, @extended, -1)
    EndIf
    If Not _Wsk_NonBlocking($hS, True) Then
        _Wsk_Close($hS)
        $g_sWs_LastOpenError = "FIONBIO refused on the listener"
        Return SetError(3, @extended, -1)
    EndIf
    If Not _Wsk_Bind($hS, $sAddr, $iPort) Then
        Local $x = @extended
        _Wsk_Close($hS)
        $g_sWs_LastOpenError = "bind " & $sAddr & ":" & $iPort & " refused " & _Wsk_ErrorName($x)
        Return SetError(4, $x, -1)
    EndIf
    If Not _Wsk_Listen($hS, 8) Then
        Local $x = @extended
        _Wsk_Close($hS)
        $g_sWs_LastOpenError = "listen refused " & _Wsk_ErrorName($x)
        Return SetError(5, $x, -1)
    EndIf
    Local $tName = _Wsk_GetSockName($hS)
    Local $iReal = 0
    If @error Then
        _Wsk_Close($hS)
        $g_sWs_LastOpenError = "getsockname refused on the listener"
        Return SetError(6, @extended, -1)
    EndIf
    $iReal = _Wsk_PortOf($tName)
    If @error Or $iReal = 0 Then
        _Wsk_Close($hS)
        $g_sWs_LastOpenError = "the bound port never came back"
        Return SetError(6, 0, -1)
    EndIf

    $g_aWsL_Sock[$iL] = $hS
    $g_aWsL_Secure[$iL] = ($fSecure ? 1 : 0)
    $g_aWsL_Port[$iL] = $iReal
    $g_aWsL_Addr[$iL] = $sAddr
    $g_aWsL_Rx[$iL] = $iRx
    $g_aWsL_MaxMsg[$iL] = $iMaxMsg
    $g_aWsL_Err[$iL] = ""
    Return SetError(0, $iReal, $iL)
EndFunc   ;==>_WS_Listen

;#FUNCTION#=====================================================================================================================
; Name ..........: _WS_ListenPort
; Description ...: Port a listener is actually bound to.
; Syntax ........: _WS_ListenPort($hListener)
; Parameters ....: $hListener            - index returned by _WS_Listen.
; Return values .: Success - Port number read back from the socket. 0 for an invalid or closed listener.
; Author ........: Numeric1
; Remarks .......: Never a guessed number: bind(port 0) is resolved by _Wsk_GetSockName, so an ephemeral listener can be reported to a client.
; Related .......: _WS_Listen, _WS_ListenInfo
;===============================================================================================================================
Func _WS_ListenPort($hListener)
    If $hListener < 0 Or $hListener >= $g_iWsListeners Or $g_aWsL_Sock[$hListener] = 0 Then Return 0
    Return $g_aWsL_Port[$hListener]
EndFunc   ;==>_WS_ListenPort

;#FUNCTION#=====================================================================================================================
; Name ..........: _WS_ListenInfo
; Description ...: One line describing a listener and its last failure.
; Syntax ........: _WS_ListenInfo($hListener)
; Parameters ....: $hListener            - index returned by _WS_Listen.
; Return values .: Success - Text line, or "invalid listener" for an out-of-range index.
; Author ........: Numeric1
; Remarks .......: The secure flag is the only difference a caller can see between a ws:// and a wss:// listener, so it is printed.
; Related .......: _WS_Listen, _WS_ListenPort
;===============================================================================================================================
Func _WS_ListenInfo($hListener)
    If $hListener < 0 Or $hListener >= $g_iWsListeners Or $g_aWsL_Sock[$hListener] = 0 Then Return "invalid listener"
    Local $sTls = ($g_aWsL_Secure[$hListener] = 1 ? $g_sTlsSrvInfo : "no")
    Return "scheme=" & ($g_aWsL_Secure[$hListener] = 1 ? "wss" : "ws") & " addr=" & $g_aWsL_Addr[$hListener] & _
            " port=" & $g_aWsL_Port[$hListener] & " socket=" & $g_aWsL_Sock[$hListener] & _
            " rx=" & $g_aWsL_Rx[$hListener] & " maxMsg=" & $g_aWsL_MaxMsg[$hListener] & _
            " credential=[" & $sTls & "] err=[" & $g_aWsL_Err[$hListener] & "]"
EndFunc   ;==>_WS_ListenInfo

;#FUNCTION#=====================================================================================================================
; Name ..........: _WS_CloseListener
; Description ...: Stops accepting on a listener.
; Syntax ........: _WS_CloseListener($hListener)
; Parameters ....: $hListener            - index returned by _WS_Listen.
; Return values .: Success - 1
;                  Failure - 0 and sets @error to 1 (invalid listener)
; Author ........: Numeric1
; Remarks .......: The shared INBOUND credential is deliberately NOT released here: rule DS4 makes it serve every accepted connection, so releasing it on a closed listener would break the connections still open. _WS_Cleanup releases it last.
; Related .......: _WS_Listen, _WS_Cleanup
;===============================================================================================================================
Func _WS_CloseListener($hListener)
    If $hListener < 0 Or $hListener >= $g_iWsListeners Or $g_aWsL_Sock[$hListener] = 0 Then Return SetError(1, 0, 0)
    _Wsk_Close($g_aWsL_Sock[$hListener])
    $g_aWsL_Sock[$hListener] = 0
    $g_aWsL_Port[$hListener] = 0
    Return 1
EndFunc   ;==>_WS_CloseListener

;#FUNCTION#=====================================================================================================================
; Name ..........: _WS_Accept
; Description ...: Takes one pending connection off a listener and gives back a handle.
; Syntax ........: _WS_Accept($hListener)
; Parameters ....: $hListener            - index returned by _WS_Listen.
; Return values .: Success - Handle (the layer 3 slot index), to finish with _WS_Upgrade.
;                  Failure - -1 and sets @error to 1 (invalid listener), 2 (the listener is not readable yet - not an error, poll again), 3 (accept refused, WSA code in @extended), 4 (non-blocking mode refused on the new socket; the socket was closed), 5 (no free layer 2 slot, rule DS4), 6 (no free layer 3 slot or websocket.dll missing), 7 (the transport seam refused, @extended = step)
; Author ........: Numeric1
; Remarks .......: Nothing is read here: an accepted handle is only created (layer 2 handshake state for wss://, layer 3 slot for both). The peer speaks first (rule DS5), so _WS_Upgrade is the call that does the work and the caller decides when. One connection per call, so a burst of peers cannot starve the loop.
; Related .......: _WS_Listen, _WS_Upgrade, _WS_PeerAddress
;===============================================================================================================================
Func _WS_Accept($hListener)
    If $hListener < 0 Or $hListener >= $g_iWsListeners Or $g_aWsL_Sock[$hListener] = 0 Then Return SetError(1, 0, -1)
    Local $hL = $g_aWsL_Sock[$hListener]
    _Wsk_Poll($hL, $Wsk_POLLIN, 0)
    Local $e = @error
    If $e <> 0 Then Return SetError(2, $e, -1) ; 3 = timeout = nothing waiting
    Local $hC = _Wsk_Accept($hL)
    $e = @error
    If $e <> 0 Then
        $g_aWsL_Err[$hListener] = "accept step " & $e & " " & _Wsk_ErrorName(@extended)
        Return SetError(3, @extended, -1)
    EndIf
    If Not _Wsk_NonBlocking($hC, True) Then
        Local $x = @extended
        _Wsk_Close($hC)
        $g_aWsL_Err[$hListener] = "FIONBIO refused on the accepted socket"
        Return SetError(4, $x, -1)
    EndIf

    Local $sPeer = "", $iPeerPort = 0
    Local $tPeer = _Wsk_GetPeerName($hC)
    If Not @error Then
        $sPeer = _Wsk_AddrText(DllStructGetPtr($tPeer))
        $iPeerPort = _Wsk_PortOf($tPeer)
    EndIf

    Local $fSecure = ($g_aWsL_Secure[$hListener] = 1)
    Local $iTls = -1
    If $fSecure Then
        $iTls = _Tls_Accept($hC)
        If @error Then
            $g_aWsL_Err[$hListener] = "layer 2 refused the socket step " & @error
            _Wsk_Close($hC)
            Return SetError(5, @extended, -1)
        EndIf
    EndIf

    Local $iIdx = _Wsp_Create(1, $g_aWsL_Rx[$hListener], 65536)
    Local $eCreate = @error
    If $iIdx < 0 Then
        If $iTls >= 0 Then
            _Tls_Close($iTls, 0) ; the slot owns the socket, so this closes it once
        Else
            _Wsk_Close($hC)
        EndIf
        $g_aWsL_Err[$hListener] = "no layer 3 slot or websocket.dll missing, step " & $eCreate
        Return SetError(6, $eCreate, -1)
    EndIf

    $g_aWs_Tls[$iIdx] = $iTls
    $g_aWs_Host[$iIdx] = $sPeer
    $g_aWs_Port[$iIdx] = $iPeerPort
    $g_aWs_Path[$iIdx] = ""
    $g_aWs_Scheme[$iIdx] = ($fSecure ? "wss" : "ws")
    $g_aWs_Addr[$iIdx] = $sPeer
    $g_aWs_Subs[$iIdx] = ""
    $g_aWs_Err[$iIdx] = ""
    $g_aWs_OpenMs[$iIdx] = 0
    $g_aWs_Inbound[$iIdx] = 1
    $g_aWs_Head[$iIdx] = ""
    $g_aWs_SelSub[$iIdx] = ""
    $g_aWs_Listen[$iIdx] = $hListener

    If $fSecure Then
        _Wsp_AttachTls($iIdx, $iTls)
        If @error Then
            Local $x = @extended
            _WS_CloseHandle($iIdx)
            $g_aWs_Err[$iIdx] = "AttachTls step " & $x
            Return SetError(7, $x, -1)
        EndIf
    Else
        $g_aWsp_Socket[$iIdx] = $hC
    EndIf
    Return SetError(0, $iIdx, $iIdx)
EndFunc   ;==>_WS_Accept

;#FUNCTION#=====================================================================================================================
; Name ..........: _WS_HeadValue
; Description ...: Reads one header out of an HTTP head (internal, case-insensitive).
; Syntax ........: _WS_HeadValue($sHead, $sName)
; Parameters ....: $sHead                - head text, request line included.
;                  $sName                - header name without the colon.
; Return values .: Success - Value, already stripped of spaces.
;                  Failure - "" (name absent, or the head empty).
; Author ........: Numeric1
; Remarks .......: Scanning stops at the first blank line, so a body that follows a head is never mistaken for a header.
; Related .......: _WS_RequestHeader, _WS_PickSubprotocol
;===============================================================================================================================
Func _WS_HeadValue($sHead, $sName)
    If $sHead = "" Or $sName = "" Then Return ""
    Local $aL = StringSplit(StringStripCR($sHead), @LF)
    Local $sWant = StringLower($sName)
    For $i = 2 To $aL[0]
        If StringStripWS($aL[$i], 8) = "" Then ExitLoop
        Local $j = StringInStr($aL[$i], ":")
        If $j = 0 Then ContinueLoop
        If StringLower(StringStripWS(StringLeft($aL[$i], $j - 1), 8)) <> $sWant Then ContinueLoop
        Return StringStripWS(StringMid($aL[$i], $j + 1), 8)
    Next
    Return ""
EndFunc   ;==>_WS_HeadValue

;#FUNCTION#=====================================================================================================================
; Name ..........: _WS_PickSubprotocol
; Description ...: Selects the sub-protocol to answer, out of the list the peer offered.
; Syntax ........: _WS_PickSubprotocol($sRequestHead, $sPreferred)
; Parameters ....: $sRequestHead         - the request head read by _WS_Upgrade (or any HTTP head).
;                  $sPreferred           - comma-separated list in OUR order of preference; empty = offer nothing.
; Return values .: Success - The first preferred name the peer also offered, "" when there is no match.
; Author ........: Numeric1
; Remarks .......: RFC 6455 makes this the server's choice: answering with a protocol the peer did not offer is a protocol error the client must close on. Order matters, so this is preference, not intersection. spike 9 proved the third-party client accepts exactly the name returned here.
; Related .......: _WS_Upgrade, _WS_SelectedSub, _WS_RequestHeader
;===============================================================================================================================
Func _WS_PickSubprotocol($sRequestHead, $sPreferred)
    If $sPreferred = "" Then Return ""
    Local $sOffered = _WS_HeadValue($sRequestHead, "Sec-WebSocket-Protocol")
    If $sOffered = "" Then Return ""
    Local $aPref = StringSplit(StringStripWS($sPreferred, 8), ",", 2)
    Local $aOffer = StringSplit($sOffered, ",", 2)
    For $p = 0 To UBound($aPref) - 1
        Local $sPref = StringStripWS($aPref[$p], 8)
        If $sPref = "" Then ContinueLoop
        For $o = 0 To UBound($aOffer) - 1
            If StringStripWS($aOffer[$o], 8) = $sPref Then Return $sPref
        Next
    Next
    Return ""
EndFunc   ;==>_WS_PickSubprotocol

;#FUNCTION#=====================================================================================================================
; Name ..........: _WS_CloseInfo
; Description ...: Reports the close frame the peer sent, as layer 3 recorded it.
; Syntax ........: _WS_CloseInfo($h)
; Parameters ....: $h                    - handle returned by _WS_Connect or _WS_Accept.
; Return values .: Success - Text line; "" for an out-of-range handle.
; Author ........: Numeric1
; Remarks .......: A close frame is NEVER queued as a message (rule V28), so the only way to read its code and reason after the fact is this report. Layer 3 also answers the close by itself (rule DS6, $g_fWspAutoCloseReply), which is why a conformant peer always receives its own close back without the caller writing a line.
; Related .......: _WS_WaitMessage, _WS_Close, _Wsp_ReplyCloseIfNeeded
;===============================================================================================================================
Func _WS_CloseInfo($h)
    If $h < 0 Or $h >= $g_iWspSlots Then Return ""
    Return "code=" & $g_aWsp_CloseCode[$h] & " fromPeer=" & $g_aWsp_CloseFromPeer[$h] & _
            " weSent=" & $g_aWsp_CloseSent[$h] & " replyErr=" & $g_aWsp_CloseReplyErr[$h] & _
            " reason=[" & BinaryToString($g_aWsp_CloseReason[$h], 8) & "]"
EndFunc   ;==>_WS_CloseInfo

;#FUNCTION#=====================================================================================================================
; Name ..........: _WS_RequestHeader
; Description ...: Reads the stored request head of an accepted connection, or one header of it.
; Syntax ........: _WS_RequestHeader($h[, $sName])
; Parameters ....: $h                    - handle returned by _WS_Accept.
;                  $sName                - [optional] header name; empty = the whole head.
; Return values .: Success - Text, @extended = 1 when the name was found.
;                  Failure - "" and sets @error to 1 (not an accepted handle, or _WS_Upgrade has not read the head yet), 2 (the name is absent from the head)
; Author ........: Numeric1
; Remarks .......: This is how a server does routing and policy without inventing an HTTP layer: the path lands in _WS_Path, and Origin, User-Agent, Cookie or any custom header is readable here. The head is kept exactly as it arrived, so a value can be compared with what the peer really sent.
; Related .......: _WS_Upgrade, _WS_Path, _WS_PickSubprotocol
;===============================================================================================================================
Func _WS_RequestHeader($h, $sName = "")
    If $h < 0 Or $h >= $g_iWspSlots Or $g_aWs_Inbound[$h] = 0 Or $g_aWs_Head[$h] = "" Then Return SetError(1, 0, "")
    If $sName = "" Then Return SetError(0, 1, $g_aWs_Head[$h])
    Local $s = _WS_HeadValue($g_aWs_Head[$h], $sName)
    If $s = "" Then Return SetError(2, 0, "")
    Return SetError(0, 1, $s)
EndFunc   ;==>_WS_RequestHeader

;#FUNCTION#=====================================================================================================================
; Name ..........: _WS_Method
; Description ...: HTTP method the peer used for the upgrade request.
; Syntax ........: _WS_Method($h)
; Parameters ....: $h                    - handle returned by _WS_Accept.
; Return values .: Success - "GET" or whatever the peer really wrote. "" when the head is not stored yet.
; Author ........: Numeric1
; Remarks .......: RFC 6455 requires GET, so a server that never reads this field is not conformant; _WS_Upgrade uses it and answers 405 to anything else.
; Related .......: _WS_Upgrade, _WS_Path
;===============================================================================================================================
Func _WS_Method($h)
    If $h < 0 Or $h >= $g_iWspSlots Or $g_aWs_Head[$h] = "" Then Return ""
    Local $aL = StringSplit(StringStripCR($g_aWs_Head[$h]), @LF, 2)
    Local $a = StringSplit($aL[0], " ", 2)
    If UBound($a) < 1 Then Return ""
    Return $a[0]
EndFunc   ;==>_WS_Method

;#FUNCTION#=====================================================================================================================
; Name ..........: _WS_CloseRefused
; Description ...: Answers an HTTP error to an upgrade request and dismantles the connection.
; Syntax ........: _WS_CloseRefused($h[, $sStatus[, $iBudgetMs]])
; Parameters ....: $h                    - handle returned by _WS_Accept, still before _WS_Upgrade succeeded.
;                  $sStatus              - [optional] status line after "HTTP/1.1 ", default "400 Bad Request".
;                  $iBudgetMs            - [optional] budget for writing the answer, 3000 ms by default.
; Return values .: Success - 1
;                  Failure - 0 and sets @error to 1 (bad handle), 2 (the answer could not be written, @extended = named transport error)
; Author ........: Numeric1
; Remarks .......: A refusal is written on the same transport as the 101, so a wss:// peer receives it encrypted (spike 9 measured that path for the 101; the bytes here go through the identical call). No close frame is sent: a connection that never became a WebSocket has no close code to carry, and inventing one would be a protocol error.
; Related .......: _WS_Upgrade, _WS_CloseHandle
;===============================================================================================================================
Func _WS_CloseRefused($h, $sStatus = "400 Bad Request", $iBudgetMs = 3000)
    If $h < 0 Or $h >= $g_iWspSlots Or $g_aWs_Inbound[$h] = 0 Then Return SetError(1, 0, 0)
    Local $s = "HTTP/1.1 " & $sStatus & @CRLF & "Connection: close" & @CRLF & _
            "Content-Length: 0" & @CRLF & @CRLF
    _Wsp_NetWrite($h, StringToBinary($s, 1), $iBudgetMs)
    Local $e = @error, $x = @extended
    If $e Then
        _WS_CloseHandle($h)
        $g_aWs_Err[$h] = "refusal answer not written step " & $e & "/" & $x
        Return SetError(2, $x, 0)
    EndIf
    _WS_CloseHandle($h)
    Return 1
EndFunc   ;==>_WS_CloseRefused

;#FUNCTION#=====================================================================================================================
; Name ..........: _WS_UpgradeHead
; Description ...: Reads and checks the upgrade request of an accepted connection: TLS to open, head, method.
; Syntax ........: _WS_UpgradeHead($h[, $iBudgetMs])
; Parameters ....: $h                    - handle returned by _WS_Accept.
;                  $iBudgetMs            - [optional] 8000 ms for the TLS handshake plus the head read.
; Return values .: Success - 1, @extended = length of the stored request head.
;                  Failure - 0 and sets @error to 1 (bad handle, or not an accepted connection, or already open), 2 (TLS handshake failed, @extended = layer 2 step), 3 (TLS still unfinished when the budget ran out, @extended = layer 2 state), 4 (the request head never arrived, @extended = bytes received), 5 (method refused, not GET: the peer already received 405 and the handle is dismantled)
; Author ........: Numeric1
; Remarks .......: Split from _WS_UpgradeAnswer so that routing exists: between these two calls the server can read _WS_Path, _WS_Method and any _WS_RequestHeader and decide the policy of THAT route. Nothing is answered here except a non-GET request, which has no route to route.
; Related .......: _WS_Upgrade, _WS_UpgradeAnswer, _WS_Path, _WS_RequestHeader
;===============================================================================================================================
Func _WS_UpgradeHead($h, $iBudgetMs = 8000)
    If $h < 0 Or $h >= $g_iWspSlots Or $g_aWs_Inbound[$h] = 0 Then Return SetError(1, 0, 0)
    If $g_aWsp_State[$h] = $g_iWspOpen Then Return SetError(1, 0, 0) ; already upgraded
    Local $t0 = TimerInit()
    Local $iTls = $g_aWs_Tls[$h]

    If $iTls >= 0 And _Tls_State($iTls) <> $Tls_ST_OPEN Then
        Local $iState = _Tls_State($iTls)
        While $iState <> $Tls_ST_OPEN And TimerDiff($t0) < $iBudgetMs
            _Tls_Pump($iTls, 20)
            Local $e = @error
            If $e > 2 Then
                $g_aWs_Err[$h] = "TLS handshake failed step " & $e & " " & $g_aTls_Err[$iTls]
                Return SetError(2, $e, 0)
            EndIf
            $iState = _Tls_State($iTls)
        WEnd
        If $iState <> $Tls_ST_OPEN Then
            $g_aWs_Err[$h] = "TLS handshake unfinished state=" & _Tls_StateName($iState)
            Return SetError(3, $iState, 0)
        EndIf
    EndIf

    Local $iRem = $iBudgetMs - TimerDiff($t0)
    If $iRem < 250 Then $iRem = 250

    ; The one blocking leg of this server. spike 10 counted it as teteBloqueeMaxMs.
    Local $sHead = _Wsp_ReadHead($h, $iRem)
    Local $e = @error
    If $e Or $sHead = "" Then
        $g_aWs_Err[$h] = "request head never arrived step " & $e
        Return SetError(4, @extended, 0)
    EndIf
    $g_aWs_Head[$h] = $sHead

    ; The request line carries both the method and the path: RFC 6455 requires GET, and the path is
    ; the only routing information a bare WebSocket server has.
    Local $aL = StringSplit(StringStripCR($sHead), @LF, 2)
    Local $sMethod = "", $sPath = ""
    If UBound($aL) > 0 Then
        Local $aR = StringSplit($aL[0], " ", 2)
        If UBound($aR) >= 2 Then
            $sMethod = $aR[0]
            $sPath = $aR[1]
        EndIf
    EndIf
    $g_aWs_Path[$h] = $sPath
    If $sMethod <> "GET" Then
        _WS_CloseRefused($h, "405 Method Not Allowed", 3000)
        $g_aWs_Err[$h] = "method refused: [" & $sMethod & "]"
        Return SetError(5, 0, 0)
    EndIf

    Return SetError(0, StringLen($sHead), 1)
EndFunc   ;==>_WS_UpgradeHead

;#FUNCTION#=====================================================================================================================
; Name ..........: _WS_UpgradeAnswer
; Description ...: Answers an upgrade request the head of which was already read: Origin policy, sub-protocol, 101, armed receive.
; Syntax ........: _WS_UpgradeAnswer($h[, $sSubprotocols[, $sOriginAllow[, $iBudgetMs]]])
; Parameters ....: $h                    - handle already read by _WS_UpgradeHead.
;                  $sSubprotocols        - [optional] comma-separated list in our order of preference; the first name the peer also offered is selected.
;                  $sOriginAllow         - [optional] comma-separated origins to accept in the Origin header; "*" accepts any Origin including an absent one; empty = no Origin check at all.
;                  $iBudgetMs            - [optional] 5000 ms for writing the 101.
; Return values .: Success - 1, @extended = number of headers the component put in the 101.
;                  Failure - 0 and sets @error to 1 (bad handle, head never read, or already answered), 2 (Origin refused: the peer already received 403 and the handle is dismantled), 3 (the component refused the request headers, @extended = HRESULT), 4 (the 101 could not be written, @extended = named transport error), 5 (the component refused to end the handshake, @extended = HRESULT), 6 (arming the receive was refused, @extended)
; Author ........: Numeric1
; Remarks .......: Call it only after _WS_UpgradeHead returned 1: it works from the stored head, so a server that answered 403 or 405 never reaches this line. The 101 itself is written by the component through layer 3, so on wss:// it leaves encrypted exactly like the response spike 9 measured.
; Related .......: _WS_UpgradeHead, _WS_Upgrade, _WS_PickSubprotocol, _WS_CloseRefused
;===============================================================================================================================
Func _WS_UpgradeAnswer($h, $sSubprotocols = "", $sOriginAllow = "", $iBudgetMs = 5000)
    If $h < 0 Or $h >= $g_iWspSlots Or $g_aWs_Inbound[$h] = 0 Then Return SetError(1, 0, 0)
    If $g_aWs_Head[$h] = "" Then Return SetError(1, 0, 0) ; _WS_UpgradeHead never ran on this handle
    If $g_aWsp_State[$h] = $g_iWspOpen Then Return SetError(1, 0, 0) ; already answered
    Local $e, $x, $sHead = $g_aWs_Head[$h]
    Local $t0 = TimerInit()
    ; Origin policy, the cross-site WebSocket hijacking check. "*" means "do not check", so it also
    ; accepts a peer that sends no Origin at all (a non-browser client); a named list never does.
    If $sOriginAllow <> "" And $sOriginAllow <> "*" Then
        Local $sOrigin = _WS_HeadValue($sHead, "Origin")
        Local $fOk = False
        If $sOrigin <> "" Then
            Local $aA = StringSplit(StringStripWS($sOriginAllow, 8), ",", 2)
            For $i = 0 To UBound($aA) - 1
                Local $sOne = StringStripWS($aA[$i], 8)
                If $sOne <> "" And StringLower($sOne) = StringLower($sOrigin) Then
                    $fOk = True
                    ExitLoop
                EndIf
            Next
        EndIf
        If Not $fOk Then
            _WS_CloseRefused($h, "403 Forbidden", 3000)
            $g_aWs_Err[$h] = "Origin refused [" & $sOrigin & "] allow=[" & $sOriginAllow & "]"
            Return SetError(2, 0, 0)
        EndIf
    EndIf

    Local $sSel = _WS_PickSubprotocol($sHead, $sSubprotocols)
    Local $sResponse = ""
    _Wsp_BeginServer($h, $sHead, $sResponse, $sSel)
    $e = @error
    Local $x = @extended
    If $e Then
        $g_aWs_Err[$h] = "BeginServer refused step " & $e & " " & _Wsp_HexHResult($x)
        Return SetError(3, $x, 0)
    EndIf
    Local $iHeaders = $x

    _Wsp_NetWrite($h, StringToBinary($sResponse, 1), $iBudgetMs)
    $e = @error
    $x = @extended
    If $e Then
        $g_aWs_Err[$h] = "writing the 101 failed step " & $e & "/" & $x
        Return SetError(4, $x, 0)
    EndIf

    _Wsp_EndServer($h)
    $e = @error
    $x = @extended
    If $e Then
        $g_aWs_Err[$h] = "EndServer refused step " & $e & " " & _Wsp_HexHResult($x)
        Return SetError(5, $x, 0)
    EndIf

    Local $iL = $g_aWs_Listen[$h]
    _Wsp_Receive($h, ($iL >= 0 ? $g_aWsL_MaxMsg[$iL] : 4194304))
    $e = @error
    $x = @extended
    If $e Then
        $g_aWs_Err[$h] = "arming the receive failed step " & $e
        Return SetError(6, $x, 0)
    EndIf

    $g_aWs_Subs[$h] = $sSubprotocols
    $g_aWs_SelSub[$h] = $sSel
    $g_aWs_OpenMs[$h] = Round(TimerDiff($t0), 1)
    Return SetError(0, $iHeaders, 1)
EndFunc   ;==>_WS_UpgradeAnswer

;#FUNCTION#=====================================================================================================================
; Name ..........: _WS_Upgrade
; Description ...: Turns an accepted connection into an open WebSocket in one call: head, policy, 101, armed receive.
; Syntax ........: _WS_Upgrade($h[, $iBudgetMs[, $sSubprotocols[, $sOriginAllow]]])
; Parameters ....: $h                    - handle returned by _WS_Accept.
;                  $iBudgetMs            - [optional] 8000 ms by default for the whole funnel.
;                  $sSubprotocols        - [optional] comma-separated list in our order of preference.
;                  $sOriginAllow         - [optional] origins to accept; "*" = any, empty = no check.
; Return values .: Success - 1, @extended = number of headers the component put in the 101.
;                  Failure - 0 and sets @error to the code of the leg that failed: 1..5 come from _WS_UpgradeHead, 6..10 from _WS_UpgradeAnswer (see their contracts; the numbering is the published one of this call).
; Author ........: Numeric1
; Remarks .......: _WS_UpgradeHead followed by _WS_UpgradeAnswer with the same arguments. A server that routes on the path or on a header must call those two directly, because the decision has to be made between them; this wrapper is for the server that has one policy for every route.
; Related .......: _WS_UpgradeHead, _WS_UpgradeAnswer, _WS_Accept, _WS_Close
;===============================================================================================================================
Func _WS_Upgrade($h, $iBudgetMs = 8000, $sSubprotocols = "", $sOriginAllow = "")
    _WS_UpgradeHead($h, $iBudgetMs)
    Local $e = @error, $x = @extended
    If $e Then Return SetError($e, $x, 0)
    Local $v = _WS_UpgradeAnswer($h, $sSubprotocols, $sOriginAllow, 5000)
    $e = @error
    $x = @extended
    If $e = 0 Or $e = 1 Then Return SetError($e, $x, $v)
    Return SetError($e + 4, $x, 0)
EndFunc   ;==>_WS_Upgrade


;#FUNCTION#=====================================================================================================================
; Name ..........: _WS_Send
; Description ...: Arms a text or binary message on the wire without waiting for it to leave.
; Syntax ........: _WS_Send($h, $vData)
; Parameters ....: $h                    - handle returned by _WS_Connect or _WS_Accept.
;                  $vData                - string (sent as UTF-8) or binary (sent as a binary frame).
; Return values .: Success - 1, @extended = the send token (V24).
;                  Failure - 0 and sets @error to 1 (bad or free handle), 5 (send ring full) or 6 (arm queue full - 64 frames per connection).
; Author ........: Numeric1
; Remarks .......: This call only ARMS the frame: the bytes leave when the send queue is served, by _WS_Flush, _WS_Request, _WS_Pump or _WS_Close (measure V21). Several frames may be armed at once - the old rule "one armed send only" was measured FALSE (probe_sendq 2026-11-15: P2/P4/P5 wrote three frames in about 88 ms without a second WebSocketSend), and layer 3 queues the rest and re-arms on completion.
; Related .......: _WS_SendBinary, _WS_Flush, _WS_Request
;===============================================================================================================================
Func _WS_Send($h, $vData)
    If $h < 0 Or $h >= $g_iWspSlots Or $g_aWsp_State[$h] = $g_iWspFree Then Return SetError(1, 0, 0)
    Local $iType = 0
    Local $b = _WS_Encode($vData, $iType)
    Local $v = _Wsp_Send($h, $b, $iType)
    Return SetError(@error, @extended, $v)
EndFunc   ;==>_WS_Send

;#FUNCTION#=====================================================================================================================
; Name ..........: _WS_SendBinary
; Description ...: Arms a binary frame exactly as given, with no encoding step.
; Syntax ........: _WS_SendBinary($h, $bData)
; Parameters ....: $h                    - handle returned by _WS_Connect or _WS_Accept.
;                  $bData                - binary payload.
; Return values .: Success - 1, @extended = the send token
;                  Failure - 0 and sets @error to 1 (bad handle), 5 (ring full) or 6 (queue full)
; Author ........: Numeric1
; Remarks .......: Length always comes from BinaryLen. StringLen of a binary value returns the length of its hex TEXT, which is how every binary send of the pre-existing WinHTTP UDF got corrupted.
; Related .......: _WS_Send
;===============================================================================================================================
Func _WS_SendBinary($h, $bData)
    If $h < 0 Or $h >= $g_iWspSlots Or $g_aWsp_State[$h] = $g_iWspFree Then Return SetError(1, 0, 0)
    Local $v = _Wsp_Send($h, $bData, $Wsp_BINARY_MESSAGE)
    Return SetError(@error, @extended, $v)
EndFunc   ;==>_WS_SendBinary

;#FUNCTION#=====================================================================================================================
; Name ..........: _WS_Flush
; Description ...: Serves the send queue until it is empty or the budget is spent.
; Syntax ........: _WS_Flush($h[, $iBudgetMs])
; Parameters ....: $h                    - handle returned by _WS_Connect or _WS_Accept.
;                  $iBudgetMs            - [optional] 5000 ms by default.
; Return values .: Success - number of frames completed during the call, @error 0 = queue empty.
;                  Failure - sets @error to 1 (bad handle), 2 (the peer closed) or 3 (budget spent, frames still
;                  queued, count in @extended; arming failure, step in @extended).
; Author ........: Numeric1
; Remarks .......: Measure A6: "WebSocketSend returned S_OK" does not mean the frame went out; completion is late, so a flush needs at least one write AND an idle queue.
; Related .......: _WS_Send, _WS_Request
;===============================================================================================================================
Func _WS_Flush($h, $iBudgetMs = 5000)
    If $h < 0 Or $h >= $g_iWspSlots Then Return SetError(1, 0, 0)
    Local $v = _Wsp_FlushSend($h, $iBudgetMs)
    Return SetError(@error, @extended, $v)
EndFunc   ;==>_WS_Flush

;#FUNCTION#=====================================================================================================================
; Name ..........: _WS_Request
; Description ...: Arms a message and serves the send queue until the component confirms it.
; Syntax ........: _WS_Request($h, $vData[, $iTimeoutMs])
; Parameters ....: $h                    - handle returned by _WS_Connect or _WS_Accept.
;                  $vData                - string (UTF-8) or binary payload.
;                  $iTimeoutMs           - [optional] 8000 ms by default.
; Return values .: Success - 1 with @error 0 (frame out AND confirmed by the component), @extended = messages delivered while waiting.
;                  Failure - 0 and sets @error to 1 (bad handle or send refused, layer 3 code in @extended), 2 (named pump error in @extended) or 3 (BUDGET SPENT - the frame may still be in the queue, which is never reported as a silent success).
; Author ........: Numeric1
; Remarks .......: Use this when "sent" must mean "handed to the transport"; use _WS_Send when the pump loop will serve the queue anyway.
; Related .......: _WS_Send, _WS_Flush, _WS_Call
;===============================================================================================================================
Func _WS_Request($h, $vData, $iTimeoutMs = 8000)
    If $h < 0 Or $h >= $g_iWspSlots Or $g_aWsp_State[$h] = $g_iWspFree Then Return SetError(1, 0, 0)
    Local $iType = 0
    Local $b = _WS_Encode($vData, $iType)
    Local $v = _Wsp_Request($h, $b, $iTimeoutMs, $iType)
    Return SetError(@error, @extended, $v)
EndFunc   ;==>_WS_Request

;#FUNCTION#=====================================================================================================================
; Name ..........: _WS_Pump
; Description ...: Runs one pump tick: serves the receive queue, then the send queue.
; Syntax ........: _WS_Pump($h[, $iBudgetMs])
; Parameters ....: $h                    - handle returned by _WS_Connect or _WS_Accept.
;                  $iBudgetMs            - [optional] 50 ms by default.
; Return values .: Success - number of messages delivered during this tick.
;                  Failure - sets @error to 1 (peer closed the TCP connection, or bad handle), 2 (named error in @extended) or 3 (DELIVERY QUEUE FULL, lost messages in @extended).
; Author ........: Numeric1
; Remarks .......: QUEUE_ALL is never used while a receive is armed (measures S3/V21: the send queue starves). One tick can deliver more than one message (V22), which is why the return value is a count and the messages sit in a queue. A refused message is reported as a loss; it is never invented.
; Related .......: _WS_Message, _WS_WaitMessage
;===============================================================================================================================
Func _WS_Pump($h, $iBudgetMs = 50)
    If $h < 0 Or $h >= $g_iWspSlots Or $g_aWsp_State[$h] = $g_iWspFree Then Return SetError(1, 0, 0)
    Local $v = _Wsp_Pump($h, $iBudgetMs)
    Return SetError(@error, @extended, $v)
EndFunc   ;==>_WS_Pump

;#FUNCTION#=====================================================================================================================
; Name ..........: _WS_Message
; Description ...: Dequeues the oldest delivered message as binary.
; Syntax ........: _WS_Message($h)
; Parameters ....: $h                    - handle returned by _WS_Connect or _WS_Accept.
; Return values .: Success - binary payload, @extended = frame type ($Wsp_UTF8_MESSAGE or $Wsp_BINARY_MESSAGE)
;                  Failure - empty binary and sets @error to 1 (queue empty) or 2 (bad handle)
; Author ........: Numeric1
; Remarks .......: Reading the queue instead of "the last value" is what keeps two messages in one tick from overwriting each other (V22/V14).
; Related .......: _WS_MessageText, _WS_Pump
;===============================================================================================================================
Func _WS_Message($h)
    If $h < 0 Or $h >= $g_iWspSlots Then Return SetError(2, 0, Binary("0x"))
    Local $v = _Wsp_TakeMessage($h)
    Return SetError(@error, @extended, $v)
EndFunc   ;==>_WS_Message

;#FUNCTION#=====================================================================================================================
; Name ..........: _WS_MessageText
; Description ...: Dequeues the oldest message and decodes it as UTF-8 text.
; Syntax ........: _WS_MessageText($h)
; Parameters ....: $h                    - handle returned by _WS_Connect or _WS_Accept.
; Return values .: Success - text; a BINARY frame deliberately returns "" with @error 0
;                  Failure - "" and sets @error to 1 (queue empty) or 2 (bad handle)
; Author ........: Numeric1
; Remarks .......: Inventing a text reading of bytes that are not UTF-8 is exactly the false success rule R8 forbids. The type is always in @extended, so test it when the peer may mix frames.
; Related .......: _WS_Message
;===============================================================================================================================
Func _WS_MessageText($h)
    Local $b = _WS_Message($h)
    Local $e = @error, $t = @extended
    If $e Then Return SetError($e, $t, "")
    If $t = $Wsp_BINARY_MESSAGE Then Return SetError(0, $t, "")
    Return SetError(0, $t, BinaryToString($b, 8))
EndFunc   ;==>_WS_MessageText

;#FUNCTION#=====================================================================================================================
; Name ..........: _WS_WaitMessage
; Description ...: Waits for one complete message, reassembling fragments.
; Syntax ........: _WS_WaitMessage($h[, $iTimeoutMs])
; Parameters ....: $h                    - handle returned by _WS_Connect or _WS_Accept.
;                  $iTimeoutMs           - [optional] 5000 ms by default.
; Return values .: Success - binary payload, @extended = frame type.
;                  Failure - empty binary and sets @error to 1 (bad handle), 2 (timeout), 3 (the
;                  peer closed the WebSocket: @extended = close code, value = its reason) or 4
;                  (named pump error in @extended).
; Author ........: Numeric1
; Remarks .......: Measure A4: a large message arrives as ~65536-byte fragments plus a final message frame, and reassembly is our job - this function does it. It pumps, so it is the simple call for a script without its own loop.
; Related .......: _WS_Pump, _WS_Message, _WS_Call
;===============================================================================================================================
Func _WS_WaitMessage($h, $iTimeoutMs = 5000)
    If $h < 0 Or $h >= $g_iWspSlots Or $g_aWsp_State[$h] = $g_iWspFree Then Return SetError(1, 0, Binary("0x"))
    Local $v = _Wsp_WaitMessage($h, $iTimeoutMs)
    Return SetError(@error, @extended, $v)
EndFunc   ;==>_WS_WaitMessage

;#FUNCTION#=====================================================================================================================
; Name ..........: _WS_Call
; Description ...: One round trip: send, serve the send queue, wait for the answer.
; Syntax ........: _WS_Call($h, $vData[, $iTimeoutMs])
; Parameters ....: $h                    - handle returned by _WS_Connect or _WS_Accept.
;                  $vData                - request text (UTF-8) or binary.
;                  $iTimeoutMs           - [optional] 8000 ms, applied to both the send and the answer.
; Return values .: Success - answer as binary, @extended = frame type.
;                  Failure - empty binary and sets @error to 1 (send failed, reason in @extended) or to the
;                  @error of _WS_WaitMessage (2 = timeout, 3 = peer closed, 4 = pump error).
; Author ........: Numeric1
; Remarks .......: A send that spent its budget (@error 3 of _WS_Request) still lets us wait for the answer: the frame may well have left afterwards, so the round trip is not abandoned on a budget note alone.
; Related .......: _WS_Request, _WS_WaitMessage
;===============================================================================================================================
Func _WS_Call($h, $vData, $iTimeoutMs = 8000)
    _WS_Request($h, $vData, $iTimeoutMs)
    Local $eR = @error
    If $eR And $eR <> 3 Then Return SetError(1, $eR, Binary("0x"))
    Local $b = _WS_WaitMessage($h, $iTimeoutMs)
    Return SetError(@error, @extended, $b)
EndFunc   ;==>_WS_Call

;#FUNCTION#=====================================================================================================================
; Name ..........: _WS_Close
; Description ...: Closes a connection properly: close frame, drain, then release both layers.
; Syntax ........: _WS_Close($h[, $iStatus[, $sReason[, $iBudgetMs]]])
; Parameters ....: $h                    - handle returned by _WS_Connect or _WS_Accept.
;                  $iStatus              - [optional] RFC 6455 close code, default 1000 (normal).
;                  $sReason              - [optional] UTF-8 reason, at most 123 bytes.
;                  $iBudgetMs            - [optional] 2000 ms by default for the close frame plus the drain.
; Return values .: Success - 1.
;                  Failure - 0 and sets @error to 1 (bad handle) or to the @error of the close
;                  write, 4 meaning the frame was armed but never drained (the peer had already
;                  gone, reason in the layer 3 counters).
; Author ........: Numeric1
; Remarks .......: The order is the measured one (V15): send the close frame and drain the send queue, absorb the peer's own close so it is not counted as a read error, then layer 3, then layer 2. A free handle answers 1 without touching anything, so the call is safe to repeat.
; Related .......: _WS_CloseHandle, _WS_Cleanup
;===============================================================================================================================
Func _WS_Close($h, $iStatus = 1000, $sReason = "", $iBudgetMs = 2000)
    If $h < 0 Or $h >= $g_iWspSlots Then Return SetError(1, 0, 0)
    Local $fOpen = ($g_aWsp_State[$h] <> $g_iWspFree)
    If Not $fOpen Then Return 1
    _Wsp_SendClose($h, $iStatus, $sReason, $iBudgetMs)
    Local $eC = @error
    ; The peer usually answers with its own close frame: absorbing it keeps that frame from being
    ; counted as a read error.
    If $eC = 0 Or $eC = 4 Then _Wsp_WaitMessage($h, 500)
    Local $v = _WS_CloseHandle($h)
    Return SetError($eC, 0, $v)
EndFunc   ;==>_WS_Close

;#FUNCTION#=====================================================================================================================
; Name ..........: _WS_IsSecure
; Description ...: Tells whether the connection runs over TLS (wss://).
; Syntax ........: _WS_IsSecure($h)
; Parameters ....: $h                    - handle returned by _WS_Connect or _WS_Accept.
; Return values .: Success - 1 = wss://, 0 = ws:// or invalid handle.
; Author ........: Numeric1
; Remarks .......: True only when a layer 2 context owns the socket, which is the exact condition the plain-wss refusal test relies on.
; Related .......: _WS_Scheme
;===============================================================================================================================
Func _WS_IsSecure($h)
    Return ($h >= 0 And $h < $g_iWspSlots And $g_aWs_Tls[$h] >= 0)
EndFunc   ;==>_WS_IsSecure

;#FUNCTION#=====================================================================================================================
; Name ..........: _WS_Host
; Description ...: Host name the handle was opened to.
; Syntax ........: _WS_Host($h)
; Parameters ....: $h                    - handle returned by _WS_Connect or _WS_Accept.
; Return values .: Success - Host string, "" for an invalid handle.
; Author ........: Numeric1
; Remarks .......: As given in the URL, before resolution.
; Related .......: _WS_PeerAddress
;===============================================================================================================================
Func _WS_Host($h)
    If $h < 0 Or $h >= $g_iWspSlots Then Return ""
    Return $g_aWs_Host[$h]
EndFunc   ;==>_WS_Host

;#FUNCTION#=====================================================================================================================
; Name ..........: _WS_Port
; Description ...: Remote port of the connection.
; Syntax ........: _WS_Port($h)
; Parameters ....: $h                    - handle returned by _WS_Connect or _WS_Accept.
; Return values .: Success - Port number, 0 for an invalid handle.
; Author ........: Numeric1
; Remarks .......: Includes the implicit default: 80 for ws://, 443 for wss://.
; Related .......: _WS_Host
;===============================================================================================================================
Func _WS_Port($h)
    If $h < 0 Or $h >= $g_iWspSlots Then Return 0
    Return $g_aWs_Port[$h]
EndFunc   ;==>_WS_Port

;#FUNCTION#=====================================================================================================================
; Name ..........: _WS_Path
; Description ...: Path (and query) requested in the upgrade.
; Syntax ........: _WS_Path($h)
; Parameters ....: $h                    - handle returned by _WS_Connect or _WS_Accept.
; Return values .: Success - Path string, "" for an invalid handle.
; Author ........: Numeric1
; Remarks .......: The fragment has already been removed by _WS_ParseUrl.
; Related .......: _WS_ParseUrl
;===============================================================================================================================
Func _WS_Path($h)
    If $h < 0 Or $h >= $g_iWspSlots Then Return ""
    Return $g_aWs_Path[$h]
EndFunc   ;==>_WS_Path

;#FUNCTION#=====================================================================================================================
; Name ..........: _WS_Scheme
; Description ...: Scheme of the connection.
; Syntax ........: _WS_Scheme($h)
; Parameters ....: $h                    - handle returned by _WS_Connect or _WS_Accept.
; Return values .: Success - "ws", "wss", or "" for an invalid handle.
; Author ........: Numeric1
; Remarks .......: Pair it with _WS_IsSecure: both must agree, and the wss tests assert exactly that.
; Related .......: _WS_IsSecure
;===============================================================================================================================
Func _WS_Scheme($h)
    If $h < 0 Or $h >= $g_iWspSlots Then Return ""
    Return $g_aWs_Scheme[$h]
EndFunc   ;==>_WS_Scheme

;#FUNCTION#=====================================================================================================================
; Name ..........: _WS_PeerAddress
; Description ...: The address actually used, out of the ones the resolver returned.
; Syntax ........: _WS_PeerAddress($h)
; Parameters ....: $h                    - handle returned by _WS_Connect or _WS_Accept.
; Return values .: Success - Text address ("127.0.0.1", "[0000:...0001]"), "" for an invalid handle.
; Author ........: Numeric1
; Remarks .......: Without this field, a connection failure on an "IPv6 first" machine is unreadable (measure C3).
; Related .......: _WS_LastWalk
;===============================================================================================================================
Func _WS_PeerAddress($h)
    If $h < 0 Or $h >= $g_iWspSlots Then Return ""
    Return $g_aWs_Addr[$h]
EndFunc   ;==>_WS_PeerAddress

;#FUNCTION#=====================================================================================================================
; Name ..........: _WS_SelectedSub
; Description ...: Name of the sub-protocol in force on this connection.
; Syntax ........: _WS_SelectedSub($h)
; Parameters ....: $h                    - handle returned by _WS_Connect or _WS_Accept.
; Return values .: Success - sub-protocol name, @extended = its index in the offered list. On a server connection the name this server answered is returned with @extended = -1; "" with @error 0 and @extended = -1 means the peer selected none.
;                  Failure - "" and sets @error to 1 (invalid handle), 2 (nothing offered) or 3 (the index the component gave is outside our list).
; Author ........: Numeric1
; Remarks .......: V18: the component reports "nothing selected" as the index 0xFFFFFFFF, which layer 3 already turns into -1; an unselected connection is @error 0 with "".
; Related .......: _WS_OfferedSub
;===============================================================================================================================
Func _WS_SelectedSub($h)
    If $h < 0 Or $h >= $g_iWspSlots Then Return SetError(1, 0, "")
    If $g_aWs_Inbound[$h] = 1 Then Return SetError(0, -1, $g_aWs_SelSub[$h])
    Local $iSel = _Wsp_SelectedSub($h)
    If @error Or $iSel < 0 Then Return SetError(0, $iSel, "")
    If $g_aWs_Subs[$h] = "" Then Return SetError(2, $iSel, "")
    Local $a = StringSplit($g_aWs_Subs[$h], ",", 2)
    If $iSel >= UBound($a) Then Return SetError(3, $iSel, "")
    Return SetError(0, $iSel, StringStripWS($a[$iSel], 8))
EndFunc   ;==>_WS_SelectedSub

;#FUNCTION#=====================================================================================================================
; Name ..........: _WS_OfferedSub
; Description ...: The comma-separated sub-protocol list the handle offered.
; Syntax ........: _WS_OfferedSub($h)
; Parameters ....: $h                    - handle returned by _WS_Connect or _WS_Accept.
; Return values .: Success - Offered list, "" when nothing was offered or the handle is invalid.
; Author ........: Numeric1
; Remarks .......: Kept verbatim from the call so that the selected name can be resolved back to an index (V18).
; Related .......: _WS_SelectedSub
;===============================================================================================================================
Func _WS_OfferedSub($h)
    If $h < 0 Or $h >= $g_iWspSlots Then Return ""
    Return $g_aWs_Subs[$h]
EndFunc   ;==>_WS_OfferedSub

;#FUNCTION#=====================================================================================================================
; Name ..........: _WS_LastWalk
; Description ...: Journal of the last walk over the address list, success or failure.
; Syntax ........: _WS_LastWalk() :None
; Return values .: Success - Text such as " #1 [0000:...0001] ECONNREFUSED #2 127.0.0.1 CONNECTED".
; Author ........: Numeric1
; Remarks .......: Measures C1-C3: this is the only trace proving that the first address of the machine was not the usable one.
; Related .......: _WS_ConnectAddrList, _WS_PeerAddress
;===============================================================================================================================
Func _WS_LastWalk()
    Return $g_sWs_LastWalk
EndFunc   ;==>_WS_LastWalk

;#FUNCTION#=====================================================================================================================
; Name ..........: _WS_ErrorText
; Description ...: Human-readable detail of the last failure of a handle, or of the last open.
; Syntax ........: _WS_ErrorText($h)
; Parameters ....: $h                    - handle, or any negative value to read the open-time error.
; Return values .: Success - Message text; "" when nothing was recorded.
; Author ........: Numeric1
; Remarks .......: For a handle that reached layer 2, the TLS error of its layer 2 slot is used when the handle itself recorded nothing.
; Related .......: _WS_HResultText, _Tls_VerifyError
;===============================================================================================================================
Func _WS_ErrorText($h)
    If $h < 0 Or $h >= $g_iWspSlots Then Return $g_sWs_LastOpenError
    If $g_aWs_Err[$h] <> "" Then Return $g_aWs_Err[$h]
    If $g_aWs_Tls[$h] >= 0 Then Return $g_aTls_Err[$g_aWs_Tls[$h]]
    Return ""
EndFunc   ;==>_WS_ErrorText

;#FUNCTION#=====================================================================================================================
; Name ..........: _WS_Info
; Description ...: One line describing everything a handle knows about itself.
; Syntax ........: _WS_Info($h)
; Parameters ....: $h                    - handle returned by _WS_Connect or _WS_Accept.
; Return values .: Success - Text line, or "invalid handle" for an out-of-range handle.
; Author ........: Numeric1
; Remarks .......: The counters come from layers 1-3 (gates, zero reads, frames in flight): they are what separated faults V21-V24, so they are diagnostics, not decoration.
; Related .......: _Wsp_Counters, _Wsp_WireTrace, _Tls_Info
;===============================================================================================================================
Func _WS_Info($h)
    If $h < 0 Or $h >= $g_iWspSlots Then Return "invalid handle"
    Local $iTls = $g_aWs_Tls[$h]
    Local $sState = _WS_StateName($g_aWsp_State[$h])
    Local $sSub = _WS_SelectedSub($h)
    Local $sRole = ($g_aWs_Inbound[$h] = 1 ? "role=accepted listener=" & $g_aWs_Listen[$h] : "role=dialed")
    Return "url=" & $g_aWs_Scheme[$h] & "://" & $g_aWs_Host[$h] & ":" & $g_aWs_Port[$h] & $g_aWs_Path[$h] & _
            " " & $sRole & _
            " address=" & $g_aWs_Addr[$h] & " openMs=" & $g_aWs_OpenMs[$h] & _
            " layer3State=" & $sState & " deliveryQueue=" & _Wsp_QCount($h) & _
            " dropped=" & $g_aWspQDropped[$h] & " inFlight=" & $g_aWspTxCount[$h] & _
            " subprotocol=[" & $sSub & "]" & _
            " tls=[" & ($iTls >= 0 ? _Tls_Info($iTls) : "no") & "]" & _
            " counters=" & _Wsp_Counters($h) & " " & _Wsp_WireTrace($h)
EndFunc   ;==>_WS_Info

;#FUNCTION#=====================================================================================================================
; Name ..........: _WS_HResultText
; Description ...: Names an HRESULT the way Windows names it.
; Syntax ........: _WS_HResultText($iHr)
; Parameters ....: $iHr                  - HRESULT returned by a component call (usually in @extended).
; Return values .: Success - Message text from the system message table.
; Author ........: Numeric1
; Remarks .......: Rule R8 - never a remembered string built at compile time: an unnamed HRESULT that is guessed is an error invented.
; Related .......: _Wsp_HResultName
;===============================================================================================================================
Func _WS_HResultText($iHr)
    Return _Wsp_HResultName($iHr)
EndFunc   ;==>_WS_HResultText
