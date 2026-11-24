;#INDEX# =======================================================================================================================
; Title .........: wsp.au3 - websocket.dll protocol driver (layer 3 of the WebSocket UDF)
; AutoIt Version : 3.3.16.1
; Language ......: English
; Description ...: Drives the Windows "WebSocket Protocol Component" (websocket.dll) on top of a
;                  socket this layer never owns: raw Winsock for ws:// (layer 1) or Schannel for
;                  wss:// (layer 2). Framing, masking, fragmentation, UTF-8 validation, close
;                  handshake and subprotocol negotiation are done by the operating system; this
;                  file supplies the network bytes and pumps the action queues.
; Remarks .......: Windows 8 and later, proven 32 and 64 bit. Nothing here is guessed: every size,
;                  offset, code and contract rule below was MESURED on a real machine and the
;                  measurement is cited next to the code that depends on it, because re-deriving
;                  them costs days (see the spike/probe list in #COMMENTS#).
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
; websocket.dll does NOT validate the handle. WebSocketSend, WebSocketGetAction and
; WebSocketAbortHandle called with a bogus or NULL handle KILL the process (4 of 6 cases, identical
; on x86 and x64 - run_nullhandles.au3). No call leaves for the DLL except through _Wsp_Handle(),
; which rejects an out-of-table index.
;
; Structure sizes (probe P2, both bitnesses; AutoIt aligns exactly like C):
;   WEB_SOCKET_HEADER {PCHAR,ULONG,PCHAR,ULONG} = 16 x86 / 32 x64.
;   WEB_SOCKET_BUFFER is a union; CloseStatus {PBYTE,ULONG,USHORT} sets the stride, so it is
;   12 x86 (10 rounded to 4) / 16 x64, NOT 8. CloseStatus.usStatus sits at offset 8 x86 / 12 x64.
;   WEB_SOCKET_PROPERTY = 12 x86 / 24 x64. byte[N] receives no AutoIt padding (P2.6), which is what
;   makes the manual element offsets legitimate.
;
; Buffer sizes are NOT discoverable (P3.1): WebSocketGetGlobalProperty knows only
; KEEPALIVE_INTERVAL and SUPPORTED_VERSIONS, the other four return E_INVALIDARG 0x80070057. The
; caller therefore has to pass $iRx/$iTx to _Wsp_Create.
;
; The client handshake is only half done by the DLL (P4.1): it returns 4 headers
; (Sec-WebSocket-Key, Connection, Upgrade, Sec-WebSocket-Version) whether we supply 0 or 2, so the
; request line, Host and Path stay our responsibility. Subprotocols are the exception - the
; component itself emits the single "Sec-WebSocket-Protocol: a, b" header (V17), the selected
; subprotocol is returned as an INDEX into the offered array with 0xFFFFFFFF when the peer chooses
; nothing (V18), and a server selection is emitted in the 101 reply (V19).
;
; A buffer quoted to the DLL must stay ALIVE for the whole pump. WebSocketSend only ARMS the send -
; pbBuffer is read when SEND_TO_NETWORK is served - so reusing one variable lets AutoIt free the
; previous payload and the heap overwrites it (proof: two sends put 0x010000007572 on the wire
; instead of 0x7265746F7572, "retour"). Hence the per-slot tables, the 64-entry live send ring and
; the token kept as pvApplicationContext.
;
; GetAction returns two different contexts with one use each (probe_actionctx):
;   [7] pvApplicationContext = THE VALUE WE SUPPLIED - an application token only. Passing it to
;       CompleteAction is a SEGFAULT (rc 139).
;   [8] pvActionContext = allocated by the component, and this is what WebSocketCompleteAction
;       expects. Passing 0 survives but leaves the action open: every later GetAction returns
;       NO_ACTION and the send never finishes.
;
; Completing a receive with ZERO bytes is read by the component as "the peer closed" (spike3 A6),
; while a receive gate that refuses to ask starves messages already parsed inside the component
; (probe_sendq P7/P8 - measured 3.078 s and 6.26 s of latency). The fix keeps both truths: an action
; that cannot be filled stays OPEN instead of being completed with a lying 0, and GetAction may be
; asked at any time.
;
; WebSocketReceive takes 3 arguments (handle, buffer, context) - no buffer type on input; the type
; comes back from WebSocketGetAction. It hands out ONE fragment per call (A4/A8: 1 MiB = 4
; fragments of 65536 then a final MESSAGE; 204800 = 65522+65536+65536+8206), so the receive must be
; re-armed after every completion. The payload lives in the component's memory: the buffer we armed
; stays zero while the returned length is correct (A8), so we copy before CompleteAction, the only
; guaranteed lifetime.
;
; A protocol ping cannot be initiated here: WebSocketSend with WEB_SOCKET_PING_PONG_BUFFER returns
; E_INVALIDARG 0x80070057 and schedules nothing (probe_pingpoison P1b). The component answers peer
; pings by itself (proof A8: a third-party client got our pong although we never wrote one).
;
; The queues must be served separately. With QUEUE_ALL and an armed receive, GetAction keeps
; returning the receive action and SEND_TO_NETWORK never comes (A2/A4/S3) - emitting pumps
; QUEUE_SEND, receiving pumps QUEUE_RECEIVE. And "WebSocketSend returned S_OK" does not mean the
; frame left: only the flush sends it, so a close without a flush becomes a bare TCP FIN.
;
; One armed send at a time is OUR invariant, not a component limit (probe_sendq P2/P4/P5 retracted
; the old rule V26: three frames armed one by one leave in ~88 ms with no second WebSocketSend).
;
; The transport seam calls layer 2 by name through Call($variable), never Call("literal"): Au3Check
; resolves a literal statically and reports "undefined function" (6 errors) when tls.au3 is not
; included, which would defeat the point of the seam. @error 57005 = "function not found" is the
; only error a plain ws:// program can produce.
;
; Measured AutoIt behaviour relied upon: a DWORD read from a DllStruct is returned UNSIGNED
; (0x80000002 -> 2147483650) while the literal of the same name is SIGNED (-2147483646), so a direct
; comparison fails silently - _Wsp_TypeNorm normalises it (t_typecmp.au3, both bitnesses); and
; "Return OtherFunc()" returns the VALUE but resets @error/@extended to 0, so delegation must write
; SetError(@error, @extended, $v) explicitly (t_propagate.au3).
;
; Proofs to replay after any change in this file (both bitnesses): spike3 15/15 (ws:// client and
; server end to end), spike5 12/12 (wss:// client), spike7 15/15 (layer 4), spike8 21/21,
; spike9 30/30 (wss:// server), spike10 (peer-closed seam), probe_sendq, probe_actionctx.
;
; CONTENTS
;   Naming/format .. _Wsp_NowMs, _Wsp_LastErrorName, _Wsp_HexHResult, _Wsp_HResultName,
;                    _Wsp_TypeNorm, _Wsp_TypeName, _Wsp_ActionName
;   Slots .......... _Wsp_AllocSlot, _Wsp_Handle, _Wsp_Dll, _Wsp_Create, _Wsp_Close
;   Struct blocks .. _Wsp_SetHeader, _Wsp_GetHeaderPtr, _Wsp_SetBuffer, _Wsp_GetBufferPtr,
;                    _Wsp_ReadAnsi
;   Handshake ...... _Wsp_BeginClient, _Wsp_ParseResponse, _Wsp_EndClient, _Wsp_SelectedSub,
;                    _Wsp_BeginServer, _Wsp_EndServer
;   Transport seam . _Wsp_AttachTls, _Wsp_XptWrite, _Wsp_XptRead, _Wsp_XptWait, _Wsp_NetWrite,
;                    _Wsp_NoteRead, _Wsp_NetRead, _Wsp_QueueBytes, _Wsp_HasReadable
;   Delivery FIFO .. _Wsp_QCount, _Wsp_QReset, _Wsp_QPush, _Wsp_TakeMessage, _Wsp_Message
;   Send ring ...... _Wsp_TxKeep, _Wsp_TxDrop, _Wsp_TxReset, _Wsp_OqPush, _Wsp_ArmNext, _Wsp_OqCount
;   Pump ........... _Wsp_PumpInit, _Wsp_ClearOpenReceive, _Wsp_FillOpenReceive, _Wsp_PumpOnce,
;                    _Wsp_Complete, _Wsp_PumpUntil, _Wsp_FlushSend, _Wsp_ReplyCloseIfNeeded,
;                    _Wsp_Pump
;   Data ........... _Wsp_Receive, _Wsp_Send, _Wsp_SendText, _Wsp_SendClose, _Wsp_Ping
;   High level ..... _Wsp_ReadHead, _Wsp_Connect, _Wsp_Request, _Wsp_WaitMessage
;   Diagnostics .... _Wsp_WireTrace, _Wsp_Counters
;===============================================================================================================================

#include-once
#include "wsk.au3"

; ---------------------------------------------------------------- enums (header)
Global Const $Wsp_UTF8_MESSAGE = 0x80000000
Global Const $Wsp_UTF8_FRAGMENT = 0x80000001
Global Const $Wsp_BINARY_MESSAGE = 0x80000002
Global Const $Wsp_BINARY_FRAGMENT = 0x80000003
Global Const $Wsp_CLOSE_BUFFER = 0x80000004
Global Const $Wsp_PING_PONG_BUFFER = 0x80000005
Global Const $Wsp_UNSOLICITED_PONG = 0x80000006

Global Const $Wsp_NO_ACTION = 0
Global Const $Wsp_SEND_TO_NETWORK = 1
Global Const $Wsp_INDICATE_SEND_COMPLETE = 2
Global Const $Wsp_RECEIVE_FROM_NETWORK = 3
Global Const $Wsp_INDICATE_RECEIVE_COMPLETE = 4

Global Const $Wsp_QUEUE_SEND = 0x1
Global Const $Wsp_QUEUE_RECEIVE = 0x2
Global Const $Wsp_QUEUE_ALL = 0x3

Global Const $Wsp_PROP_RECEIVE_BUFFER_SIZE = 0
Global Const $Wsp_PROP_SEND_BUFFER_SIZE = 1
Global Const $Wsp_PROP_DISABLE_MASKING = 2
Global Const $Wsp_PROP_ALLOCATED_BUFFER = 3
Global Const $Wsp_PROP_DISABLE_UTF8_VERIFICATION = 4
Global Const $Wsp_PROP_KEEPALIVE_INTERVAL = 5
Global Const $Wsp_PROP_SUPPORTED_VERSIONS = 6

Global Const $Wsp_MAX_CLOSE_REASON = 123

; Measured sizes (probe P2). AutoIt aligns exactly like C - verified on both bitnesses.
Global Const $g_iWspPtr = (@AutoItX64 ? 8 : 4)
Global Const $g_iWspSzHeader = (@AutoItX64 ? 32 : 16) ; {PCHAR,ULONG,PCHAR,ULONG}
Global Const $g_iWspOffNameLen = $g_iWspPtr
Global Const $g_iWspOffValue = 2 * $g_iWspPtr
Global Const $g_iWspOffValueLen = 2 * $g_iWspPtr + 4 + (@AutoItX64 ? 4 : 0)
; WEB_SOCKET_BUFFER is a union; CloseStatus {PBYTE,ULONG,USHORT} sets the stride: 12 in x86
; (10 rounded up to 4), 16 in x64. Not 8. (measure P2.3)
Global Const $g_iWspSzBuffer = (@AutoItX64 ? 16 : 12)
Global Const $g_iWspOffBufPtr = 0
Global Const $g_iWspOffBufLen = $g_iWspPtr
Global Const $g_iWspOffBufStatus = $g_iWspPtr + 4 ; USHORT, membre CloseStatus
Global Const $g_iWspSzProperty = (@AutoItX64 ? 24 : 12)

; ------------------------------------------------------------------ etats
Global Const $g_iWspSlots = 8
Global Const $g_iWspFree = 0
Global Const $g_iWspCreated = 1
Global Const $g_iWspHandshake = 2
Global Const $g_iWspOpen = 3
Global Const $g_iWspClosed = 4

Global $g_aWsp_State[$g_iWspSlots]
Global $g_aWsp_Dll[$g_iWspSlots]
Global $g_aWsp_Handle[$g_iWspSlots]
Global $g_aWsp_Socket[$g_iWspSlots]
Global $g_aWsp_IsServer[$g_iWspSlots]
; A buffer quoted to the DLL must stay ALIVE for the whole pump, hence per-slot storage instead of
; a local variable.
Global $g_aWsp_RxStruct[$g_iWspSlots]  ; caller's WEB_SOCKET_BUFFER (armed receive)
Global $g_aWsp_RxData[$g_iWspSlots] ; byte[] recipient
Global $g_aWsp_TxStruct[$g_iWspSlots]
Global $g_aWsp_TxData[$g_iWspSlots]
Global $g_aWsp_Pending[$g_iWspSlots]  ; bytes already read from the network (after the 101)
Global $g_aWsp_MsgType[$g_iWspSlots]
Global $g_aWsp_MsgLen[$g_iWspSlots]
Global $g_aWsp_MsgCtx[$g_iWspSlots]
; Copy of the payload ASSEMBLED by the component. Measure A8: the buffer armed by WebSocketReceive
; stays zero while the returned length is correct, so GetAction points at the component's memory,
; not ours. Copy while CompleteAction has not been called yet - that is the only guaranteed
; lifetime.
Global $g_aWsp_MsgBin[$g_iWspSlots]
Global $g_aWsp_CloseCode[$g_iWspSlots]
; IsStruct() does not exist in 3.3.16.1: whether a caller buffer is armed is tracked by an explicit
; flag.
Global $g_aWsp_RxArmed[$g_iWspSlots]
Global $g_aWsp_RxSize[$g_iWspSlots]  ; size of the recipient currently allocated
Global $g_aWsp_ReArmErr[$g_iWspSlots]  ; @error of the last implicit re-arm
Global $g_aWsp_Pongs[$g_iWspSlots]  ; protocol pongs seen by WaitMessage
; Wire diagnostic: the last "short" (<= 64 bytes) network write of each slot, raw bytes. This is
; what tells us - when a peer reports a FIN instead of a close frame - whether the frame left or
; not. Deliberately limited to small writes: copying 1 MiB per pump turn for the pleasure of the
; log costs more than the frame itself.
Global $g_aWsp_LastSmallWrite[$g_iWspSlots]
; Read-side mirror: the last raw BYTES received by the socket. Without it, a peer that announces
; "FIN" where a frame was expected cannot be told apart from "the frame arrived and our stack never
; decoded it".
Global $g_aWsp_LastSmallRead[$g_iWspSlots]
; SLIDING window of the last 48 bytes read, whatever the read size. The short trace alone is not
; enough: when a close frame follows a 1 MiB message, the last "small" read can still be the tail of
; that 1 MiB, and we can no longer say whether the close bytes ever reached the socket.
Global $g_aWsp_TailRead[$g_iWspSlots]
; Description of the last writes requested by the component: "byteCount@first10". Tells apart "the
; close was its own send action" from "the close was glued at the end of the 1 MiB in one action".
Global $g_aWsp_LastWriteDesc[$g_iWspSlots]
Global $g_aWsp_PrevWriteDesc[$g_iWspSlots]
; TCP TOTALS PER SLOT. The only evidence that separates, when a peer announces a FIN instead of an
; expected frame, "the frame bytes were never put on the socket" (total = expected - frame size)
; from "they arrived and our pump never handed them over" (total = expected).
Global $g_aWsp_BytesRead[$g_iWspSlots]
Global $g_aWsp_BytesWritten[$g_iWspSlots]
; Close negotiation (RFC 6455 5.5.1): when the PEER closes first, our stack must answer with a close
; frame before releasing the socket. Without that answer the third party stays waiting and reports
; "no close frame received or sent" (measures A8/x64 and probe_pingclose C4).
Global $g_fWspAutoCloseReply = 1
Global $g_aWsp_CloseReason[$g_iWspSlots]  ; raw reason received from the peer (UTF-8)
Global $g_aWsp_CloseFromPeer[$g_iWspSlots]  ; 1 = the last close frame came from the peer
Global $g_aWsp_CloseSent[$g_iWspSlots]  ; 1 = we already sent our close frame
Global $g_aWsp_CloseReplyErr[$g_iWspSlots]  ; @error of the automatic answer (0 = delivered)
; Rule V28 corollary (measured spike 11): a close frame is never queued in the FIFO, so the pump
; that sees it is the only place the information exists. _Wsp_Pump answers the close by itself and
; then LOSES $iType - without this flag a caller that pumps first and reads afterwards never learns
; that the peer closed, and the connection looks alive forever.
Global $g_aWsp_PendingClose[$g_iWspSlots]  ; 1 = a pump already saw AND answered the peer close
Global $g_aWsp_Counters[$g_iWspSlots][6] ; pompes, sendIO, recvIO, sendDone, recvDone, maxTampons
; Probe A6: how many times a RECEIVE_FROM_NETWORK action was completed with ZERO bytes while no real
; FIN had been read (our budget expired). Completing a receive with 0 is the component's "peer
; closed" signal: if this counter grows during a plain idle, the stack is killing itself.
Global $g_aWsp_ZeroRecv[$g_iWspSlots]
; TWO measures, in opposite directions.
;
; MEASURE 1 (spike3 A6, x86): completing a receive with ZERO bytes although no real FIN had been read
; (our budget expired) is read as "the peer closed" by the component. The echo server logged "pair
; closed" with inq()=0 and recv()=WSAEWOULDBLOCK, so there was NO FIN on the socket. The answer then
; was a GATE: only ask for an action when a byte is there.
;
; MEASURE 2 (probe_sendq, x86, 2026-11-15): that gate starved the component. When the peer sends
; three frames at once, ONE RECEIVE_FROM_NETWORK action reads them all (server log: counters
; 45/3/1/3/3/2 = one receive action for three delivered messages). The next two messages therefore
; stay PARSED INSIDE THE COMPONENT, the socket can read nothing more, the gate shuts again and they
; only come out when the peer sends something else or closes: 3.078 s and 6.26 s of measured
; latency - which is what rule V26 had mistaken for a component limitation.
;
; THE FIX KEEPS BOTH TRUTHS: a receive action asked when no byte is available is NEVER completed
; with a lying 0, it stays OPEN (the component waits - probe_sendq P8: 10 bytes handed over 500 ms
; after the open, INDICATE_RECEIVE_COMPLETE delivers). And an action may be asked at any time since
; asking no longer lies (probe_sendq P7: an open receive action does not stop GetAction(QUEUE_SEND)
; from returning SEND_TO_NETWORK 1 ms later). $g_aWsp_ParserBusy is therefore 1 while a waiting
; action is open, and $g_aWsp_Gated counts the turns where that action waited without receiving.
Global $g_aWsp_ParserBusy[$g_iWspSlots]
Global $g_aWsp_Gated[$g_iWspSlots]
Global $g_aWsp_RxOpenCtx[$g_iWspSlots]  ; pvActionContext of the open action, 0 = none
Global $g_aWsp_RxOpenPtr[$g_iWspSlots]  ; where the component wants its bytes
Global $g_aWsp_RxOpenLen[$g_iWspSlots] ; combien il en reste place

; =============================================================================
; DELIVERY QUEUE (V22, measured twice: spike5 E7 and spike6 S4c).
;
; THE DEFECT THIS KILLS: $g_aWsp_MsgBin holds ONE value, while a single pump turn can deliver
; SEVERAL messages (measure S4c: two echoes delivered in the same turn, 6 bytes accumulated instead
; of 5+6=11; a caller doing "one pump line" therefore silently loses whole messages). A network UDF
; whose pieces depend on the pumping rhythm is unusable: layer 3 now holds a FIFO of COMPLETE
; messages, assembled here (fragments never reach the caller).
;
; Honest bound: 64 pending messages per slot. Beyond that the NEWEST is refused, counted in
; $g_aWsp_QDropped, and the pump signals it with @error 3: bounded memory plus a LOUD failure, never
; a silent loss.
; =============================================================================
Global Const $g_iWspQCap = 64
Global $g_aWspQBin[$g_iWspSlots][$g_iWspQCap]
Global $g_aWspQTyp[$g_iWspSlots][$g_iWspQCap]
Global $g_aWspQHead[$g_iWspSlots]  ; read cursor, ABSOLUTE counter
Global $g_aWspQTail[$g_iWspSlots]  ; write cursor, ABSOLUTE counter
Global $g_aWspQDropped[$g_iWspSlots]
Global $g_aWsp_QOverflow[$g_iWspSlots]  ; 1 = a delivery was REFUSED this turn
; Index of the subprotocol chosen by the peer (V18); -1 = none.
Global $g_aWsp_SelSub[$g_iWspSlots]
; Assembly in progress (fragments in flight, not yet delivered)
Global $g_aWspAsmBin[$g_iWspSlots]
Global $g_aWspAsmTyp[$g_iWspSlots]

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_QCount
; Description ...: Number of complete messages waiting in the delivery queue of a slot.
; Syntax ........: _Wsp_QCount($iIdx)
; Parameters ....: $iIdx                 - slot index (the handle used by every layer 3 call)
; Return values .: Success - Count (0 = empty).
;                  Failure - 0 for an index out of table.
; Author ........: Numeric1
; Related .......: _Wsp_TakeMessage, _Wsp_QPush
;===============================================================================================================================
Func _Wsp_QCount($iIdx)
    If $iIdx < 0 Or $iIdx >= $g_iWspSlots Then Return 0
    Return $g_aWspQTail[$iIdx] - $g_aWspQHead[$iIdx]
EndFunc   ;==>_Wsp_QCount

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_QReset
; Description ...: Empty the delivery queue, the fragment assembly and the send ring of a slot.
; Syntax ........: _Wsp_QReset($iIdx)
; Parameters ....: $iIdx                 - slot index
; Return values .: Success - 1.
;                  Failure - 0 = index out of table.
; Author ........: Numeric1
; Related .......: _Wsp_Create, _Wsp_TxReset
;===============================================================================================================================
Func _Wsp_QReset($iIdx)
    If $iIdx < 0 Or $iIdx >= $g_iWspSlots Then Return 0
    For $i = 0 To $g_iWspQCap - 1
        $g_aWspQBin[$iIdx][$i] = Binary("0x")
        $g_aWspQTyp[$iIdx][$i] = 0
    Next
    $g_aWspQHead[$iIdx] = 0
    $g_aWspQTail[$iIdx] = 0
    $g_aWspQDropped[$iIdx] = 0
    $g_aWspAsmBin[$iIdx] = Binary("0x")
    $g_aWspAsmTyp[$iIdx] = 0
    _Wsp_TxReset($iIdx)
    Return 1
EndFunc   ;==>_Wsp_QReset

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_QPush
; Description ...: Queue one delivery from the component, assembling fragments into a complete message.
; Syntax ........: _Wsp_QPush($iIdx, $bMsg, $iType)
; Parameters ....: $iIdx                 - slot index
;                  $bMsg                 - payload of this piece, already copied out of the component's memory
;                  $iType                - WEB_SOCKET_BUFFER_TYPE returned by WebSocketGetAction for this piece
; Return values .: Success - 1 = queued or fragment in progress, 2 = complete message queued.
;                  Failure - 0 = type never handed to the caller (close, ping, pong), 3 = queue full and delivery lost (counted in $g_aWspQDropped).
; Author ........: Numeric1
; Remarks .......: Non-application types never reach the queue; fragments are accumulated and only the assembled message is queued (measure S4c: one pump turn can deliver several messages).
; Related .......: _Wsp_TakeMessage, _Wsp_PumpOnce
;===============================================================================================================================
; Queue ONE delivery from the component. $iType = the WEB_SOCKET_BUFFER_TYPE returned by
; WebSocketGetAction for THIS piece. Non-application types (close, ping, pong) never go through the
; queue: they already have dedicated slots. Returns 1 = queued (or fragment in progress), 0 =
; NOTHING was handed to the caller, 2 = complete message queued, 3 = queue FULL, delivery lost.
Func _Wsp_QPush($iIdx, $bMsg, $iType)
    Switch $iType
        Case $Wsp_UTF8_FRAGMENT, $Wsp_BINARY_FRAGMENT
            If BinaryLen($g_aWspAsmBin[$iIdx]) = 0 Then _
                    $g_aWspAsmTyp[$iIdx] = ($iType = $Wsp_UTF8_FRAGMENT ? $Wsp_UTF8_MESSAGE : $Wsp_BINARY_MESSAGE)
            $g_aWspAsmBin[$iIdx] &= $bMsg
            Return 1
        Case $Wsp_UTF8_MESSAGE, $Wsp_BINARY_MESSAGE
            Local $bFull = $g_aWspAsmBin[$iIdx] & $bMsg
            ; The type of the assembled MESSAGE is that of the FIRST fragment; with no
            ; assembly in progress it is the type returned for this piece.
            Local $iFull = ($g_aWspAsmTyp[$iIdx] <> 0 ? $g_aWspAsmTyp[$iIdx] : $iType)
            $g_aWspAsmBin[$iIdx] = Binary("0x")
            $g_aWspAsmTyp[$iIdx] = 0
            If _Wsp_QCount($iIdx) >= $g_iWspQCap Then
                $g_aWspQDropped[$iIdx] += 1
                Return 3
            EndIf
            Local $c = $g_aWspQTail[$iIdx]
            $g_aWspQBin[$iIdx][Mod($c, $g_iWspQCap)] = $bFull
            $g_aWspQTyp[$iIdx][Mod($c, $g_iWspQCap)] = $iFull
            $g_aWspQTail[$iIdx] = $c + 1
            Return 2
        Case Else
            Return 0
    EndSwitch
EndFunc   ;==>_Wsp_QPush

; =============================================================================
; LIVE SEND RING (measured defect, spike6 S4c x86/x64):
; WebSocketSend only ARMS the send - the component reads pbBuffer when it serves SEND_TO_NETWORK. The
; previous call (which REUSED $g_aWsp_TxData) therefore made AutoIt FREE the previous message's
; buffer: AutoIt's allocator returns the block to the heap and the next 4 bytes get overwritten by
; the bookkeeping. PROOF (python peer, server log): two _Wsp_Send in a row put 0x010000007572 on the
; wire instead of 0x7265746F7572 ("retour") - the last 2 bytes survive, the first 4 are a heap DWORD.
; So: EVERY send keeps its own buffer until INDICATE_SEND_COMPLETE, indexed by a token handed over as
; pvApplicationContext (a value we supplied, measure probe_actionctx). 64 sends in flight per slot,
; beyond that a loud refusal.
; =============================================================================
Global Const $g_iWspTxCap = 64
Global $g_aWspTxBuf[$g_iWspSlots][$g_iWspTxCap]  ; peer's WEB_SOCKET_BUFFER (caller)
Global $g_aWspTxPay[$g_iWspSlots][$g_iWspTxCap] ; byte[] charge utile
Global $g_aWspTxTyp[$g_iWspSlots][$g_iWspTxCap]  ; buffer type to pass to WebSocketSend
Global $g_aWspTxTok[$g_iWspSlots][$g_iWspTxCap]  ; token stored in the slot
Global $g_aWspTxSeq[$g_iWspSlots]  ; absolute token counter
Global $g_aWspTxCount[$g_iWspSlots] ; emissions en vol

; =============================================================================
; ONE ARMED SEND AT A TIME (measured defect, spike7 N5 x86): three _Wsp_Send in a row with no pump
; between them, the component writes the FIRST two frames then DROPS THE THIRD for 6.2 s: server log,
; msg#4 at [84883565] (2nd frame) and msg#5 at [84889759] (the 3rd), to the millisecond when a NEW
; WebSocketSend was issued. All that time the QUEUE_SEND pump returned NO_ACTION and our own
; completions were consumed by the earlier frames: an idle queue therefore PROVES NOTHING, and the
; only "nothing in flight" counter was wrong.
; Layer 3 now owns its own queue of TOKENS: _Wsp_Send calls WebSocketSend only when nothing is armed,
; otherwise it parks the token. The next arming happens as soon as the completion of the frame in
; flight comes back (or, as a measured safety net A4, when the queue is idle while at least one
; action was served for that frame).
; =============================================================================
Global Const $g_iWspOqCap = 64
Global $g_aWspOqTok[$g_iWspSlots][$g_iWspOqCap]  ; tokens waiting to be armed
Global $g_aWspOqHead[$g_iWspSlots]
Global $g_aWspOqCount[$g_iWspSlots]
Global $g_aWspArmed[$g_iWspSlots]  ; token armed with the component, 0 = none
Global $g_aWsp_ArmErr[$g_iWspSlots]  ; re-arms refused from the pump

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_TxKeep
; Description ...: Reserve a send-ring slot for one frame so its buffer stays alive until INDICATE_SEND_COMPLETE.
; Syntax ........: _Wsp_TxKeep($iIdx, $tBuf, $tPay[, $iType])
; Parameters ....: $iIdx                 - slot index
;                  $tBuf                 - the caller's WEB_SOCKET_BUFFER struct
;                  $tPay                 - the byte[] payload it points at
;                  $iType                - [optional] buffer type to pass to WebSocketSend
; Return values .: Success - Token (> 0), the value later handed to the component as pvApplicationContext.
;                  Failure - 0 = ring full (64 sends in flight) or index out of table.
; Author ........: Numeric1
; Remarks .......: Required by measure S4c: WebSocketSend only arms the send, so reusing one buffer lets AutoIt free the previous payload and the heap overwrites it.
; Related .......: _Wsp_TxDrop, _Wsp_Send
;===============================================================================================================================
Func _Wsp_TxKeep($iIdx, $tBuf, $tPay, $iType = 0)
    If $iIdx < 0 Or $iIdx >= $g_iWspSlots Then Return 0
    If $g_aWspTxCount[$iIdx] >= $g_iWspTxCap Then Return 0
    $g_aWspTxSeq[$iIdx] += 1
    Local $iTok = $g_aWspTxSeq[$iIdx]
    Local $c = Mod($iTok, $g_iWspTxCap)
    $g_aWspTxBuf[$iIdx][$c] = $tBuf
    $g_aWspTxPay[$iIdx][$c] = $tPay
    $g_aWspTxTyp[$iIdx][$c] = $iType
    $g_aWspTxTok[$iIdx][$c] = $iTok
    $g_aWspTxCount[$iIdx] += 1
    Return $iTok
EndFunc   ;==>_Wsp_TxKeep

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_TxDrop
; Description ...: Release a send-ring slot once the component is done reading the buffer.
; Syntax ........: _Wsp_TxDrop($iIdx, $iTok)
; Parameters ....: $iIdx                 - slot index
;                  $iTok                 - token returned by _Wsp_TxKeep
; Return values .: Success - 1.
;                  Failure - 0 = index out of table, token already gone or not ours.
; Author ........: Numeric1
; Remarks .......: Also clears $g_aWspArmed when the released token was the armed one, otherwise the arming queue would keep believing a frame is in flight.
; Related .......: _Wsp_TxKeep, _Wsp_PumpOnce
;===============================================================================================================================
Func _Wsp_TxDrop($iIdx, $iTok)
    If $iIdx < 0 Or $iIdx >= $g_iWspSlots Or $iTok <= 0 Then Return 0
    Local $c = Mod($iTok, $g_iWspTxCap)
    If $g_aWspTxTok[$iIdx][$c] <> $iTok Then Return 0
    $g_aWspTxTok[$iIdx][$c] = 0
    $g_aWspTxBuf[$iIdx][$c] = 0
    $g_aWspTxPay[$iIdx][$c] = 0
    $g_aWspTxTyp[$iIdx][$c] = 0
    $g_aWspTxCount[$iIdx] -= 1
    ; The token that frees its ring slot is also the armed one: without this line the queue
    ; would still believe a send is in flight.
    If $g_aWspArmed[$iIdx] = $iTok Then $g_aWspArmed[$iIdx] = 0
    Return 1
EndFunc   ;==>_Wsp_TxDrop

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_TxReset
; Description ...: Clear the send ring and the arming queue of a slot.
; Syntax ........: _Wsp_TxReset($iIdx)
; Parameters ....: $iIdx                 - slot index
; Return values .: Success - 1.
;                  Failure - 0 = index out of table.
; Author ........: Numeric1
; Related .......: _Wsp_TxKeep, _Wsp_OqPush
;===============================================================================================================================
Func _Wsp_TxReset($iIdx)
    If $iIdx < 0 Or $iIdx >= $g_iWspSlots Then Return 0
    For $i = 0 To $g_iWspTxCap - 1
        $g_aWspTxBuf[$iIdx][$i] = 0
        $g_aWspTxPay[$iIdx][$i] = 0
        $g_aWspTxTyp[$iIdx][$i] = 0
        $g_aWspTxTok[$iIdx][$i] = 0
    Next
    For $i = 0 To $g_iWspOqCap - 1
        $g_aWspOqTok[$iIdx][$i] = 0
    Next
    $g_aWspOqHead[$iIdx] = 0
    $g_aWspOqCount[$iIdx] = 0
    $g_aWspArmed[$iIdx] = 0
    $g_aWsp_ArmErr[$iIdx] = 0
    $g_aWspTxSeq[$iIdx] = 0
    $g_aWspTxCount[$iIdx] = 0
    Return 1
EndFunc   ;==>_Wsp_TxReset

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_OqPush
; Description ...: Park a token in the arming queue (frame accepted by layer 3 but not yet handed to the component).
; Syntax ........: _Wsp_OqPush($iIdx, $iTok)
; Parameters ....: $iIdx                 - slot index
;                  $iTok                 - token to arm later
; Return values .: Success - 1, @extended = queue length after the push.
;                  Failure - 0, @error 1 = queue full (64 frames).
; Author ........: Numeric1
; Related .......: _Wsp_ArmNext, _Wsp_OqCount
;===============================================================================================================================
; Push a token into the arming queue. @error 1 = queue full.
Func _Wsp_OqPush($iIdx, $iTok)
    If $g_aWspOqCount[$iIdx] >= $g_iWspOqCap Then Return SetError(1, $g_aWspOqCount[$iIdx], 0)
    Local $c = Mod($g_aWspOqHead[$iIdx] + $g_aWspOqCount[$iIdx], $g_iWspOqCap)
    $g_aWspOqTok[$iIdx][$c] = $iTok
    $g_aWspOqCount[$iIdx] += 1
    Return SetError(0, $g_aWspOqCount[$iIdx], 1)
EndFunc   ;==>_Wsp_OqPush

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_ArmNext
; Description ...: Arm the oldest pending send with WebSocketSend when nothing is in flight.
; Syntax ........: _Wsp_ArmNext($iIdx)
; Parameters ....: $iIdx                 - slot index
; Return values .: Success - Armed token, @extended = remaining queue length. 0 with @error 0 = nothing to arm.
;                  Failure - @error 1 = dead slot, 2 = DllCall failure, 3 = component refusal (the token is returned to the ring in both cases).
; Author ........: Numeric1
; Remarks .......: One armed send at a time is our invariant (measure spike7 N5); it is what keeps a buffer alive until the component finished reading it.
; Related .......: _Wsp_OqPush, _Wsp_FlushSend
;===============================================================================================================================
; Arm the oldest pending send if NOTHING is in flight. Returns the armed token (0 = nothing to arm).
; @error 1 = dead slot, 2 = DllCall, 3 = component refusal (the token is returned to the ring in
; both cases).
Func _Wsp_ArmNext($iIdx)
    If $g_aWspArmed[$iIdx] <> 0 Then Return SetError(0, 0, 0)
    If $g_aWspOqCount[$iIdx] = 0 Then Return SetError(0, 0, 0)
    Local $c = Mod($g_aWspOqHead[$iIdx], $g_iWspOqCap)
    Local $iTok = $g_aWspOqTok[$iIdx][$c]
    $g_aWspOqTok[$iIdx][$c] = 0
    $g_aWspOqHead[$iIdx] += 1
    $g_aWspOqCount[$iIdx] -= 1
    If $iTok <= 0 Then Return SetError(0, 0, 0)

    Local $h = _Wsp_Handle($iIdx)
    If @error Then
        _Wsp_TxDrop($iIdx, $iTok)
        Return SetError(1, @error, 0)
    EndIf
    Local $iRing = Mod($iTok, $g_iWspTxCap)
    If $g_aWspTxTok[$iIdx][$iRing] <> $iTok Then Return SetError(0, 0, 0)  ; slot already freed
    Local $aCall = DllCall(_Wsp_Dll($iIdx), "int", "WebSocketSend", "ptr", $h, _
            "dword", $g_aWspTxTyp[$iIdx][$iRing], "ptr", DllStructGetPtr($g_aWspTxBuf[$iIdx][$iRing]), _
            "ptr", $iTok)
    Local $eCall = @error
    If $eCall Then
        _Wsp_TxDrop($iIdx, $iTok)
        Return SetError(2, $eCall, 0)
    EndIf
    If $aCall[0] < 0 Then
        _Wsp_TxDrop($iIdx, $iTok)
        Return SetError(3, $aCall[0], 0)
    EndIf
    $g_aWspArmed[$iIdx] = $iTok
    Return SetError(0, $g_aWspOqCount[$iIdx], $iTok)
EndFunc   ;==>_Wsp_ArmNext

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_OqCount
; Description ...: Number of frames layer 3 has not finished handing to the component.
; Syntax ........: _Wsp_OqCount($iIdx)
; Parameters ....: $iIdx                 - slot index
; Return values .: Success - Queued tokens plus the armed one (0 = send side idle).
;                  Failure - 0 for an index out of table.
; Author ........: Numeric1
; Related .......: _Wsp_FlushSend, _Wsp_ArmNext
;===============================================================================================================================
; Number of frames layer 3 has not been able to hand to the component yet.
Func _Wsp_OqCount($iIdx)
    If $iIdx < 0 Or $iIdx >= $g_iWspSlots Then Return 0
    Return $g_aWspOqCount[$iIdx] + ($g_aWspArmed[$iIdx] <> 0 ? 1 : 0)
EndFunc   ;==>_Wsp_OqCount

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_TakeMessage
; Description ...: Dequeue the oldest complete message of the delivery queue.
; Syntax ........: _Wsp_TakeMessage($iIdx)
; Parameters ....: $iIdx                 - slot index
; Return values .: Success - The binary payload, @extended = message type ($Wsp_UTF8_MESSAGE or $Wsp_BINARY_MESSAGE).
;                  Failure - Empty binary, @error 1 = queue empty, 2 = index out of table.
; Author ........: Numeric1
; Remarks .......: The slot is cleared on read, otherwise a 1 MiB payload would stay referenced until the queue wraps (64 MB per slot worst case).
; Related .......: _Wsp_QPush, _Wsp_Message, _Wsp_QCount
;===============================================================================================================================
; Dequeue the oldest message. Returns the BINARY, @extended = message TYPE ($Wsp_UTF8_MESSAGE or
; $Wsp_BINARY_MESSAGE), @error 1 = empty queue.
Func _Wsp_TakeMessage($iIdx)
    If $iIdx < 0 Or $iIdx >= $g_iWspSlots Then Return SetError(2, 0, Binary("0x"))
    If _Wsp_QCount($iIdx) = 0 Then Return SetError(1, 0, Binary("0x"))
    Local $c = $g_aWspQHead[$iIdx]
    Local $iSlot = Mod($c, $g_iWspQCap)
    Local $b = $g_aWspQBin[$iIdx][$iSlot]
    Local $t = $g_aWspQTyp[$iIdx][$iSlot]
    ; Clear the slot: otherwise the 1 MiB binary would stay stuck there until the queue wraps
    ; around, that is 64 MB per slot in the worst case.
    $g_aWspQBin[$iIdx][$iSlot] = Binary("0x")
    $g_aWspQTyp[$iIdx][$iSlot] = 0
    $g_aWspQHead[$iIdx] = $c + 1
    Return SetError(0, $t, $b)
EndFunc   ;==>_Wsp_TakeMessage

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_NowMs
; Description ...: Milliseconds in the local day - the only clock two AutoIt processes share.
; Syntax ........: _Wsp_NowMs() :None
; Return values .: Success - Milliseconds (float).
;                  Failure - 1 when GetLocalTime failed.
; Author ........: Numeric1
; Remarks .......: TimerInit/TimerDiff are per-process, so a random defect between a client and a server can only be settled with common timestamps.
; Related .......: _Wsp_WireTrace
;===============================================================================================================================
; Milliseconds in the local day: the ONLY way to align two AutoIt processes on the same clock
; (TimerInit is not shared). A random defect between a client and a server is only settled with
; common timestamps.
Func _Wsp_NowMs()
    Local $t = DllStructCreate("word;word;word;word;word;word;word;word")
    DllCall("kernel32.dll", "none", "GetLocalTime", "ptr", DllStructGetPtr($t))
    If @error Then Return -1
    Return DllStructGetData($t, 5) * 3600000 + DllStructGetData($t, 6) * 60000 + _
            DllStructGetData($t, 7) * 1000 + DllStructGetData($t, 8)
EndFunc   ;==>_Wsp_NowMs

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_LastErrorName
; Description ...: Name of a Winsock error code, delegated to layer 1.
; Syntax ........: _Wsp_LastErrorName($iErr)
; Parameters ....: $iErr                 - Winsock error code
; Return values .: Success - Error name.
; Author ........: Numeric1
; Related .......: _Wsk_ErrorName
;===============================================================================================================================
Func _Wsp_LastErrorName($iErr)
    Return _Wsk_ErrorName($iErr)
EndFunc   ;==>_Wsp_LastErrorName

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_HexHResult
; Description ...: Render an HRESULT as 0x........ whatever the sign AutoIt gave it.
; Syntax ........: _Wsp_HexHResult($i)
; Parameters ....: $i                    - HRESULT value
; Return values .: Success - Hexadecimal string.
; Author ........: Numeric1
; Related .......: _Wsp_HResultName, _Wsp_TypeNorm
;===============================================================================================================================
Func _Wsp_HexHResult($i)
    Local $t = DllStructCreate("int")
    DllStructSetData($t, 1, Int($i))
    Local $b = DllStructGetData(DllStructCreate("byte[4]", DllStructGetPtr($t)), 1)
    Local $r = BinaryMid($b, 4, 1) & BinaryMid($b, 3, 1) & BinaryMid($b, 2, 1) & BinaryMid($b, 1, 1)
    Return "0x" & StringTrimLeft($r, 2)
EndFunc   ;==>_Wsp_HexHResult

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_HResultName
; Description ...: Human name of an HRESULT (FORMAT_MESSAGE_FROM_SYSTEM | IGNORE_ERROR_STRING).
; Syntax ........: _Wsp_HResultName($iHResult)
; Parameters ....: $iHResult             - HRESULT value
; Return values .: Success - Message text, or "S_OK" for 0.
;                  Failure - "<unnamed>" when Windows has no string for the code.
; Author ........: Numeric1
; Remarks .......: A HRESULT without a name is an incomplete measurement - this is how 0x8000000E turned out to mean "the method was called at an unexpected time".
; Related .......: _Wsp_HexHResult
;===============================================================================================================================
; Human name of the error Windows returns (FORMAT_MESSAGE_FROM_SYSTEM | IGNORE_ERROR_STRING). A
; HRESULT without a name is an incomplete measurement: this is how 0x8000000E turned out to be
; "the method was called at an unexpected time", not a write failure.
Func _Wsp_HResultName($iHResult)
    If $iHResult = 0 Then Return "S_OK"
    Local $tBuf = DllStructCreate("wchar[512]")
    Local $aF = DllCall("kernel32.dll", "dword", "FormatMessageW", _
            "dword", 0x1000 + 0x200, "ptr", 0, "dword", Int($iHResult), "dword", 0, _
            "ptr", DllStructGetPtr($tBuf), "dword", 512, "ptr", 0)
    If @error Or $aF[0] = 0 Then Return "<unnamed>"
    Return StringStripWS(DllStructGetData($tBuf, 1), 3)
EndFunc   ;==>_Wsp_HResultName

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_TypeNorm
; Description ...: Bring a DWORD read from a DllStruct back into the signed space of the AutoIt literals.
; Syntax ........: _Wsp_TypeNorm($iValue)
; Parameters ....: $iValue               - raw DWORD value
; Return values .: Success - Signed value.
; Author ........: Numeric1
; Remarks .......: Measured (t_typecmp.au3, both bitnesses): 0x80000002 reads back as 2147483650 while $Wsp_BINARY_MESSAGE is -2147483646, so a direct comparison fails silently.
; Related .......: _Wsp_TypeName
;===============================================================================================================================
; MEASURED RULE (t_typecmp.au3, x86 AND x64): a DWORD read from a DllStruct is returned UNSIGNED
; (0x80000002 -> 2147483650) while the AutoIt literal of the same name is SIGNED (-> -2147483646).
; The two are never equal, so a direct comparison fails silently and no type is ever recognised.
; Every type comes from the component as a DWORD: bring it back into the literal space.
Func _Wsp_TypeNorm($iValue)
    If $iValue > 0x7FFFFFFF Then Return $iValue - 0x100000000
    Return $iValue
EndFunc   ;==>_Wsp_TypeNorm

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_TypeName
; Description ...: Readable name of a WEB_SOCKET_BUFFER_TYPE.
; Syntax ........: _Wsp_TypeName($iType)
; Parameters ....: $iType                - buffer type, already normalised by _Wsp_TypeNorm
; Return values .: Success - "UTF8_MESSAGE", "BINARY_MESSAGE", "CLOSE", ...
;                  Failure - The raw value in hex when the type is unknown.
; Author ........: Numeric1
; Related .......: _Wsp_TypeNorm, _Wsp_ActionName
;===============================================================================================================================
Func _Wsp_TypeName($iType)
    Switch _Wsp_TypeNorm($iType)
        Case $Wsp_UTF8_MESSAGE
            Return "UTF8_MESSAGE"
        Case $Wsp_UTF8_FRAGMENT
            Return "UTF8_FRAGMENT"
        Case $Wsp_BINARY_MESSAGE
            Return "BINARY_MESSAGE"
        Case $Wsp_BINARY_FRAGMENT
            Return "BINARY_FRAGMENT"
        Case $Wsp_CLOSE_BUFFER
            Return "CLOSE"
        Case $Wsp_PING_PONG_BUFFER
            Return "PING_PONG"
        Case $Wsp_UNSOLICITED_PONG
            Return "UNSOLICITED_PONG"
    EndSwitch
    Return Hex($iType, 8)
EndFunc   ;==>_Wsp_TypeName

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_ActionName
; Description ...: Readable name of a WEB_SOCKET_ACTION.
; Syntax ........: _Wsp_ActionName($iAction)
; Parameters ....: $iAction              - action code returned by WebSocketGetAction
; Return values .: Success - "NO_ACTION", "SEND_TO_NETWORK", "INDICATE_SEND_COMPLETE", "RECEIVE_FROM_NETWORK" or "INDICATE_RECEIVE_COMPLETE".
;                  Failure - "ACTION_n" for an unknown value.
; Author ........: Numeric1
; Related .......: _Wsp_TypeName, _Wsp_PumpOnce
;===============================================================================================================================
Func _Wsp_ActionName($iAction)
    Switch $iAction
        Case $Wsp_NO_ACTION
            Return "NO_ACTION"
        Case $Wsp_SEND_TO_NETWORK
            Return "SEND_TO_NETWORK"
        Case $Wsp_INDICATE_SEND_COMPLETE
            Return "INDICATE_SEND_COMPLETE"
        Case $Wsp_RECEIVE_FROM_NETWORK
            Return "RECEIVE_FROM_NETWORK"
        Case $Wsp_INDICATE_RECEIVE_COMPLETE
            Return "INDICATE_RECEIVE_COMPLETE"
    EndSwitch
    Return "ACTION_" & $iAction
EndFunc   ;==>_Wsp_ActionName

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_AllocSlot
; Description ...: Claim the first free slot of the layer 3 table.
; Syntax ........: _Wsp_AllocSlot() :None
; Return values .: Success - Slot index.
;                  Failure - 1, @error 1 = all 8 slots busy.
; Author ........: Numeric1
; Remarks .......: The ceiling is $g_iWspSlots; layer 2 has its own table with the same size.
; Related .......: _Wsp_Create, _Wsp_Handle
;===============================================================================================================================
; =============================================================================
; Slot management. RULE FROM THE MEASUREMENT: websocket.dll does NOT validate the handle.
; WebSocketSend/GetAction/AbortHandle with a bogus or NULL handle KILL the process (4 of 6 cases,
; x86 and x64 identical). No call therefore leaves for the DLL without going through _Wsp_Handle(),
; which refuses an out-of-table index.
; =============================================================================
Func _Wsp_AllocSlot()
    For $i = 0 To $g_iWspSlots - 1
        If $g_aWsp_State[$i] = $g_iWspFree Then Return $i
    Next
    Return SetError(1, 0, -1)
EndFunc   ;==>_Wsp_AllocSlot

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_Handle
; Description ...: Return the WEBSOCKET_HANDLE of a slot - the only way a handle reaches websocket.dll.
; Syntax ........: _Wsp_Handle($iIdx)
; Parameters ....: $iIdx                 - slot index
; Return values .: Success - Handle pointer, @extended 0.
;                  Failure - 0, @error 1 = index out of table, 2 = slot free, 3 = no handle yet.
; Author ........: Numeric1
; Remarks .......: Mandatory guard: websocket.dll does not validate the handle and a bogus or NULL one KILLS the process (measured, 4 of 6 cases, x86 and x64).
; Related .......: _Wsp_AllocSlot, _Wsp_Create
;===============================================================================================================================
Func _Wsp_Handle($iIdx)
    If $iIdx < 0 Or $iIdx >= $g_iWspSlots Then Return SetError(1, 0, 0)
    If $g_aWsp_State[$iIdx] = $g_iWspFree Then Return SetError(2, 0, 0)
    If String($g_aWsp_Handle[$iIdx]) = "" Then Return SetError(3, 0, 0)
    Return SetError(0, 0, $g_aWsp_Handle[$iIdx])
EndFunc   ;==>_Wsp_Handle

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_Dll
; Description ...: DllCall handle of websocket.dll used by a slot.
; Syntax ........: _Wsp_Dll($iIdx)
; Parameters ....: $iIdx                 - slot index
; Return values .: Success - Handle (-1 when the DLL could not be loaded).
;                  Failure - @error 1 = index out of table.
; Author ........: Numeric1
; Related .......: _Wsp_Handle
;===============================================================================================================================
Func _Wsp_Dll($iIdx)
    If $iIdx < 0 Or $iIdx >= $g_iWspSlots Then Return SetError(1, 0, -1)
    Return SetError(0, 0, $g_aWsp_Dll[$iIdx])
EndFunc   ;==>_Wsp_Dll

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_SetHeader
; Description ...: Write one WEB_SOCKET_HTTP_HEADER element of a shared byte[] block by member number.
; Syntax ........: _Wsp_SetHeader($tBlock, $iElem, $pName, $cName, $pValue, $cValue)
; Parameters ....: $tBlock               - byte[] block holding the header array
;                  $iElem                - element number in the array
;                  $pName                - pointer to the header name
;                  $cName                - name length in bytes
;                  $pValue               - pointer to the header value
;                  $cValue               - value length in bytes
; Return values .: Success - None - the struct is modified in place.
; Author ........: Numeric1
; Remarks .......: Separate members, never "ptr[N]": writing by member number is the only form the DLL accepts (spike6 S3b/S3c).
; Related .......: _Wsp_GetHeaderPtr, _Wsp_BeginClient
;===============================================================================================================================
; =============================================================================
; Arrays of structures built inside a single byte[] block: measure P2.6 confirms that byte[N]
; receives no AutoIt padding, so the manual offset is legitimate and the stride is exactly the C one.
; =============================================================================
Func _Wsp_SetHeader($tBlock, $iElem, $pName, $cName, $pValue, $cValue)
    Local $iBase = ($iElem - 1) * $g_iWspSzHeader
    Local $iAddr = DllStructGetPtr($tBlock) + $iBase
    Local $t = DllStructCreate("ptr;dword;ptr;dword", $iAddr)
    DllStructSetData($t, 1, $pName)
    DllStructSetData($t, 2, $cName)
    DllStructSetData($t, 3, $pValue)
    DllStructSetData($t, 4, $cValue)
EndFunc   ;==>_Wsp_SetHeader

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_GetHeaderPtr
; Description ...: Read one field of a WEB_SOCKET_HTTP_HEADER element out of a shared byte[] block.
; Syntax ........: _Wsp_GetHeaderPtr($tBlock, $iElem, $iField)
; Parameters ....: $tBlock               - byte[] block holding the header array
;                  $iElem                - element number
;                  $iField               - member number inside the element (1..4)
; Return values .: Success - Field value (pointer or length depending on $iField).
; Author ........: Numeric1
; Related .......: _Wsp_SetHeader
;===============================================================================================================================
Func _Wsp_GetHeaderPtr($tBlock, $iElem, $iField)
    Local $iAddr = DllStructGetPtr($tBlock) + ($iElem - 1) * $g_iWspSzHeader
    Local $t = DllStructCreate("ptr;dword;ptr;dword", $iAddr)
    Return DllStructGetData($t, $iField)
EndFunc   ;==>_Wsp_GetHeaderPtr

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_SetBuffer
; Description ...: Write one WEB_SOCKET_BUFFER union element of a shared byte[] block.
; Syntax ........: _Wsp_SetBuffer($tBlock, $iElem, $ptrData, $iLen[, $iStatus])
; Parameters ....: $tBlock               - byte[] block holding the buffer array
;                  $iElem                - element number
;                  $ptrData              - payload pointer (pbBuffer / CloseStatus.pbReason)
;                  $iLen                 - payload length in bytes
;                  $iStatus              - [optional] CloseStatus.usStatus, ignored for data buffers
; Return values .: Success - None - the struct is modified in place.
; Author ........: Numeric1
; Remarks .......: The stride is 12 bytes in x86 and 16 in x64 because CloseStatus {PBYTE,ULONG,USHORT} sets the union size (measure P2.3).
; Related .......: _Wsp_GetBufferPtr, _Wsp_Receive
;===============================================================================================================================
Func _Wsp_SetBuffer($tBlock, $iElem, $ptrData, $iLen, $iStatus = 0)
    Local $iAddr = DllStructGetPtr($tBlock) + ($iElem - 1) * $g_iWspSzBuffer
    Local $t = DllStructCreate("ptr;dword;ushort", $iAddr)
    DllStructSetData($t, 1, $ptrData)
    DllStructSetData($t, 2, $iLen)
    DllStructSetData($t, 3, $iStatus)
EndFunc   ;==>_Wsp_SetBuffer

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_GetBufferPtr
; Description ...: Read one field of a WEB_SOCKET_BUFFER element.
; Syntax ........: _Wsp_GetBufferPtr($tBlock, $iElem, $iField)
; Parameters ....: $tBlock               - byte[] block holding the buffer array
;                  $iElem                - element number
;                  $iField               - member number inside the element
; Return values .: Success - Field value.
; Author ........: Numeric1
; Related .......: _Wsp_SetBuffer
;===============================================================================================================================
Func _Wsp_GetBufferPtr($tBlock, $iElem, $iField)
    Local $iAddr = DllStructGetPtr($tBlock) + ($iElem - 1) * $g_iWspSzBuffer
    Local $t = DllStructCreate("ptr;dword;ushort", $iAddr)
    Return DllStructGetData($t, $iField)
EndFunc   ;==>_Wsp_GetBufferPtr

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_ReadAnsi
; Description ...: Read a length-delimited ASCII string out of memory owned by the component.
; Syntax ........: _Wsp_ReadAnsi($ptr, $iLen)
; Parameters ....: $ptr                  - pointer to the bytes
;                  $iLen                 - number of bytes
; Return values .: Success - The string.
;                  Failure - "" for a NULL pointer or a non-positive length.
; Author ........: Numeric1
; Remarks .......: Used on the header names and values the DLL filled; they are never NUL-terminated.
; Related .......: _Wsp_BeginClient, _Wsp_ParseResponse
;===============================================================================================================================
Func _Wsp_ReadAnsi($ptr, $iLen)
    If $ptr = 0 Or $iLen <= 0 Then Return ""
    Local $t = DllStructCreate("byte[" & $iLen & "]", $ptr)
    If @error Then Return ""
    Return BinaryToString(DllStructGetData($t, 1), 1)
EndFunc   ;==>_Wsp_ReadAnsi

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_Create
; Description ...: Create a websocket.dll handle for a slot and arm its buffer sizes.
; Syntax ........: _Wsp_Create($fServer, $iRx, $iTx)
; Parameters ....: $fServer              - 1 for the server side, 0 for the client side
;                  $iRx                  - receive buffer size to impose on the component
;                  $iTx                  - send buffer size to impose on the component
; Return values .: Success - Slot index (the handle used by every later call), @extended = the HRESULT.
;                  Failure - 1, @error 1 = no free slot, 2 = websocket.dll missing, 3 = WebSocketCreateHandle refused it (@extended = HRESULT).
; Author ........: Numeric1
; Remarks .......: The sizes are mandatory because they are not discoverable (measure P3.1: WebSocketGetGlobalProperty only knows KEEPALIVE_INTERVAL and SUPPORTED_VERSIONS).
; Related .......: _Wsp_Close, _Wsp_Handle
;===============================================================================================================================
; =============================================================================
; Opening a handle. $iRx/$iTx = imposed buffer sizes: mandatory, since they are NOT discoverable
; (measure P3.1: WebSocketGetGlobalProperty only knows KEEPALIVE_INTERVAL and SUPPORTED_VERSIONS,
; the other 4 return E_INVALIDARG 0x80070057).
; $fServer = 1 for the server side.
; =============================================================================
Func _Wsp_Create($fServer, $iRx, $iTx)
    Local $iIdx = _Wsp_AllocSlot()
    If @error Then Return SetError(1, 0, -1)

    Local $hDll = DllOpen("websocket.dll")
    If $hDll = -1 Then Return SetError(2, 0, -1)

    Local $tVals = DllStructCreate("dword;dword")
    DllStructSetData($tVals, 1, $iRx)
    DllStructSetData($tVals, 2, $iTx)
    Local $tProps = DllStructCreate("byte[" & (2 * $g_iWspSzProperty) & "]")
    Local $iP = DllStructGetPtr($tProps)
    Local $tP0 = DllStructCreate("dword;ptr;dword", $iP)
    DllStructSetData($tP0, 1, $Wsp_PROP_RECEIVE_BUFFER_SIZE)
    DllStructSetData($tP0, 2, DllStructGetPtr($tVals, 1))
    DllStructSetData($tP0, 3, 4)
    Local $tP1 = DllStructCreate("dword;ptr;dword", $iP + $g_iWspSzProperty)
    DllStructSetData($tP1, 1, $Wsp_PROP_SEND_BUFFER_SIZE)
    DllStructSetData($tP1, 2, DllStructGetPtr($tVals, 2))
    DllStructSetData($tP1, 3, 4)

    Local $tHnd = DllStructCreate("ptr")
    Local $sFn = ($fServer ? "WebSocketCreateServerHandle" : "WebSocketCreateClientHandle")
    Local $aCall = DllCall($hDll, "int", $sFn, "ptr", $iP, "dword", 2, "ptr", DllStructGetPtr($tHnd))
    Local $e = @error
    If $e Or $aCall[0] < 0 Then
        DllClose($hDll)
        Return SetError(3, ($e ? $e : $aCall[0]), -1)
    EndIf

    $g_aWsp_Dll[$iIdx] = $hDll
    $g_aWsp_Handle[$iIdx] = DllStructGetData($tHnd, 1)
    $g_aWsp_IsServer[$iIdx] = $fServer
    $g_aWsp_State[$iIdx] = $g_iWspCreated
    $g_aWsp_Pending[$iIdx] = Binary("0x")
    For $j = 0 To 5
        $g_aWsp_Counters[$iIdx][$j] = 0
    Next
    $g_aWsp_ZeroRecv[$iIdx] = 0
    $g_aWsp_Gated[$iIdx] = 0
    ; Rule V28 state travels with the slot, so it is cleared HERE as well as in _Wsp_Close: a slot
    ; that was taken away by an exception path keeps its close flag otherwise, and the next
    ; connection on that slot then reports its FIRST close as already answered.
    $g_aWsp_PendingClose[$iIdx] = 0
    _Wsp_ClearOpenReceive($iIdx)
    _Wsp_QReset($iIdx)
    Return SetError(0, $aCall[0], $iIdx)
EndFunc   ;==>_Wsp_Create

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_BeginClient
; Description ...: Client side step 1: build the upgrade request through WebSocketStartClientHandshake.
; Syntax ........: _Wsp_BeginClient($iIdx, $sHost, $iPort, $sPath, $sRequest[, $aSups[, $iPortDefault]])
; Parameters ....: $iIdx                 - slot index
;                  $sHost                - host as it must appear in the Host header
;                  $iPort                - port to write into Host (0 when the scheme default is implied)
;                  $sPath                - request target, for instance "/echo"
;                  $sRequest             - receives the complete request text to write on the socket
;                  $aSups                - [optional] array of offered subprotocol names (measure V17: the component emits the header)
;                  $iPortDefault         - [optional] default port of the scheme, 80 ws:// or 443 wss:// (RFC 6455 4.1: not written into Host)
; Return values .: Success - Number of headers the DLL returned, @extended = same value. $sRequest receives the bytes to write.
;                  Failure - 0, @error 1 = dead slot, 2 = DllCall failure, 3 = component refusal (@extended = HRESULT), 4 = empty header array.
; Author ........: Numeric1
; Remarks .......: The DLL returns Sec-WebSocket-Key, Connection, Upgrade and Sec-WebSocket-Version only - the request line and Host stay ours (measure P4.1).
; Related .......: _Wsp_EndClient, _WS_Connect
;===============================================================================================================================
; =============================================================================
; CLIENT side: build the upgrade request.
; The DLL returns Connection / Upgrade / Sec-WebSocket-Key / Sec-WebSocket-Version; it does NOT
; return Host or Path (measure P4.1: 4 headers even when we supply 2). The request line and Host are
; therefore ours.
; Puts the bytes to write in $sRequest and keeps the header array returned by the DLL alive in $tAdd
; (freed by WebSocketDeleteHandle).
; =============================================================================
Func _Wsp_BeginClient($iIdx, $sHost, $iPort, $sPath, ByRef $sRequest, $aSups = 0, $iPortDefault = 80)
    Local $h = _Wsp_Handle($iIdx)
    If @error Then Return SetError(1, @error, 0)
    Local $hDll = _Wsp_Dll($iIdx)

    ; Host and Path are supplied as INITIAL headers. MEASURE P4.1: the array returned by
    ; the DLL does NOT contain them (4 headers returned whether we supply 0 or 2:
    ; Sec-WebSocket-Key, Connection, Upgrade, Sec-WebSocket-Version). The request line,
    ; Host and Path therefore stay our responsibility.
    Local $tStr = DllStructCreate("char[64];char[64];char[8];char[8]")
    Local $iV = DllStructGetPtr($tStr, 1)
    Local $iV2 = DllStructGetPtr($tStr, 2)
    Local $iS = DllStructGetPtr($tStr, 3)
    Local $iS2 = DllStructGetPtr($tStr, 4)
    ; The scheme's default port is not written into Host (RFC 6455 4.1 / RFC 7230 5.4):
    ; 80 for ws://, 443 for wss://. Layer 3 does not know the scheme, the caller tells it
    ; ($iPortDefault).
    Local $sHostValue = ($iPort = $iPortDefault ? $sHost : $sHost & ":" & $iPort)
    DllStructSetData($tStr, 1, $sHostValue)
    DllStructSetData($tStr, 2, $sPath)
    DllStructSetData($tStr, 3, "Host")
    DllStructSetData($tStr, 4, "Path")
    Local $tInit = DllStructCreate("byte[" & ($g_iWspSzHeader * 2) & "]")
    _Wsp_SetHeader($tInit, 1, $iS, StringLen("Host"), $iV, StringLen($sHostValue))
    _Wsp_SetHeader($tInit, 2, $iS2, StringLen("Path"), $iV2, StringLen($sPath))

    ; SUBPROTOCOLS (measure V17): passed through the prototype's dedicated parameter, the
    ; component EMITS the header itself, as ONE "Sec-WebSocket-Protocol: a, b" header added to
    ; the returned array. Nothing to patch in the text. The array must stay alive until the call.
    Local $iNSup = (IsArray($aSups) ? UBound($aSups) : 0)
    Local $tSup = 0, $tSupStr = 0, $pSup = 0
    If $iNSup > 0 Then
        Local $sLayout = ""
        For $i = 1 To $iNSup
            $sLayout &= "ptr;"
        Next
        $tSup = DllStructCreate(StringTrimRight($sLayout, 1))
        $pSup = DllStructGetPtr($tSup)
        Local $iSupLen = 0
        For $i = 0 To $iNSup - 1
            $iSupLen += StringLen($aSups[$i]) + 1
        Next
        $tSupStr = DllStructCreate("char[" & ($iSupLen + 1) & "]")
        Local $pPool = DllStructGetPtr($tSupStr), $iUsed = 0
        For $i = 0 To $iNSup - 1
            Local $s = $aSups[$i]
            DllStructSetData(DllStructCreate("char[" & (StringLen($s) + 1) & "]", $pPool + $iUsed), 1, $s)
            ; SEPARATE MEMBERS, not "ptr[N]": writing by member number is the only form the
            ; DLL is happy with (spike6 S3b/S3c).
            DllStructSetData($tSup, $i + 1, $pPool + $iUsed)
            $iUsed += StringLen($s) + 1
        Next
    EndIf

    Local $tAdd = DllStructCreate("ptr")
    Local $tAddN = DllStructCreate("dword")
    Local $aCall = DllCall($hDll, "int", "WebSocketBeginClientHandshake", _
            "ptr", $h, "ptr", $pSup, "dword", $iNSup, "ptr", 0, "dword", 0, _
            "ptr", DllStructGetPtr($tInit), "dword", 2, _
            "ptr", DllStructGetPtr($tAdd), "ptr", DllStructGetPtr($tAddN))
    Local $e = @error
    If $e Then Return SetError(2, $e, 0)
    If $aCall[0] < 0 Then Return SetError(3, $aCall[0], 0)

    Local $iN = DllStructGetData($tAddN, 1)
    Local $pArr = DllStructGetData($tAdd, 1)
    If $iN = 0 Or String($pArr) = "0x00000000" Or $pArr = 0 Then Return SetError(4, 0, 0)

    Local $s = "GET " & $sPath & " HTTP/1.1" & @CRLF
    $s &= "Host: " & $sHostValue & @CRLF
    ; Path is not a header: it is the request line above.
    Local $iHdr = 0
    For $i = 0 To $iN - 1
        Local $tH = DllStructCreate("ptr;dword;ptr;dword", $pArr + $i * $g_iWspSzHeader)
        Local $sName = _Wsp_ReadAnsi(DllStructGetData($tH, 1), DllStructGetData($tH, 2))
        Local $sValue = _Wsp_ReadAnsi(DllStructGetData($tH, 3), DllStructGetData($tH, 4))
        If $sName = "" Or $sValue = "" Then ContinueLoop
        $s &= $sName & ": " & $sValue & @CRLF
        $iHdr += 1
    Next
    $s &= @CRLF
    $sRequest = $s
    Return SetError(0, $iN, $iHdr)
EndFunc   ;==>_Wsp_BeginClient

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_ParseResponse
; Description ...: Turn an HTTP response head into a WEB_SOCKET_HTTP_HEADER array we own.
; Syntax ........: _Wsp_ParseResponse($sHead, $tBlock, $iCount, $iStatus)
; Parameters ....: $sHead                - the response head, up to and including CRLFCRLF
;                  $tBlock               - receives the allocated byte[] block
;                  $iCount               - receives the number of headers
;                  $iStatus              - receives the HTTP status code
; Return values .: Success - 1. $tBlock receives the block, $iCount the header number, $iStatus the HTTP status code.
;                  Failure - 0, @error 1 = empty head, 2 = bad status line, 3 = malformed header line (@extended = line number), 4 = no header at all.
; Author ........: Numeric1
; Remarks .......: The component only asks for the headers, so checking the 101 stays the caller's job; the block must live until WebSocketEndClientHandshake.
; Related .......: _Wsp_EndClient, _Wsp_SetHeader
;===============================================================================================================================
; =============================================================================
; Parse an HTTP response into a WEB_SOCKET_HTTP_HEADER array OWNED BY US. The status line is checked
; separately (the component only wants the headers; the 101 stays our responsibility as callers).
; =============================================================================
Func _Wsp_ParseResponse($sHead, ByRef $tBlock, ByRef $iCount, ByRef $iStatus)
    $iStatus = 0
    $iCount = 0
    Local $sClean = StringStripCR($sHead)
    Local $aL = StringSplit($sClean, @LF)
    If $aL[0] < 1 Then Return SetError(1, 0, 0)

    Local $aStat = StringSplit($aL[1], " ")
    If $aStat[0] < 2 Or $aStat[1] <> "HTTP/1.1" Then Return SetError(2, 0, 0)
    $iStatus = Number($aStat[2])

    Local $n = 0
    For $i = 2 To $aL[0]
        If StringStripWS($aL[$i], 8) = "" Then ExitLoop
        Local $j = StringInStr($aL[$i], ":")
        If $j = 0 Then Return SetError(3, $i, 0)
        $n += 1
    Next
    If $n = 0 Then Return SetError(4, 0, 0)

    ; A single allocation: the array, then all the strings after it. Everything must stay
    ; alive until WebSocketEndClientHandshake -> the block is returned to the caller, which keeps it.
    $tBlock = DllStructCreate("byte[" & ($n * $g_iWspSzHeader) & "];char[" & (StringLen($sHead) + 4) & "]")
    Local $pPool = DllStructGetPtr($tBlock, 2)
    Local $iUsed = 0
    Local $iElem = 0
    For $i = 2 To $aL[0]
        Local $line = $aL[$i]
        If StringStripWS($line, 8) = "" Then ExitLoop
        Local $j = StringInStr($line, ":")
        Local $sName = StringStripWS(StringLeft($line, $j - 1), 3)
        Local $sValue = StringStripWS(StringMid($line, $j + 1), 3)
        Local $pName = $pPool + $iUsed
        Local $tN = DllStructCreate("byte[" & (StringLen($sName) + 1) & "]", $pName)
        DllStructSetData($tN, 1, StringToBinary($sName, 1))
        $iUsed += StringLen($sName) + 1
        Local $pValue = $pPool + $iUsed
        Local $tV = DllStructCreate("byte[" & (StringLen($sValue) + 1) & "]", $pValue)
        DllStructSetData($tV, 1, StringToBinary($sValue, 1))
        $iUsed += StringLen($sValue) + 1
        $iElem += 1
        _Wsp_SetHeader($tBlock, $iElem, $pName, StringLen($sName), $pValue, StringLen($sValue))
    Next
    $iCount = $iElem
    Return 1
EndFunc   ;==>_Wsp_ParseResponse

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_EndClient
; Description ...: Client side step 2: validate the 101 answer with WebSocketEndClientHandshake.
; Syntax ........: _Wsp_EndClient($iIdx, $sHead)
; Parameters ....: $iIdx                 - slot index
;                  $sHead                - response head to hand to the component
; Return values .: Success - 1, @extended = number of response headers. The response block is kept in $g_aWsp_RspBlock so the caller owns it.
;                  Failure - 0, @error 1 = dead slot, 2 = parse failure (step in @extended), 3 = status is not 101 (@extended = status), 4 = DllCall failure, 5 = component refusal (@extended = HRESULT).
; Author ........: Numeric1
; Remarks .......: On success the slot moves to open and the subprotocol index becomes readable through _Wsp_SelectedSub (V18: 0xFFFFFFFF means the peer chose nothing).
; Related .......: _Wsp_BeginClient, _Wsp_SelectedSub
;===============================================================================================================================
; =============================================================================
; Finish the client handshake.
; =============================================================================
Func _Wsp_EndClient($iIdx, $sHead)
    Local $h = _Wsp_Handle($iIdx)
    If @error Then Return SetError(1, @error, 0)
    Local $hDll = _Wsp_Dll($iIdx)

    Local $tBlock = 0, $iN = 0, $iStatus = 0
    _Wsp_ParseResponse($sHead, $tBlock, $iN, $iStatus)
    If @error Then Return SetError(2, @error, 0)
    If $iStatus <> 101 Then Return SetError(3, $iStatus, 0)

    Local $tExt = DllStructCreate("dword[4]")
    Local $tExtN = DllStructCreate("dword")
    Local $tSub = DllStructCreate("dword")
    Local $aCall = DllCall($hDll, "int", "WebSocketEndClientHandshake", _
            "ptr", $h, "ptr", DllStructGetPtr($tBlock), "dword", $iN, _
            "ptr", DllStructGetPtr($tExt), "ptr", DllStructGetPtr($tExtN), _
            "ptr", DllStructGetPtr($tSub))
    Local $e = @error
    If $e Then Return SetError(4, $e, 0)
    If $aCall[0] < 0 Then Return SetError(5, $aCall[0], 0)
    $g_aWsp_State[$iIdx] = $g_iWspOpen
    ; V18: the output is AN INDEX into the array offered to _Wsp_BeginClient, and is 0xFFFFFFFF
    ; when the peer chooses nothing (the value IS written, this is not a "left untouched"). -1 makes
    ; the absence readable by the caller.
    Local $iSel = DllStructGetData($tSub, 1)
    $g_aWsp_SelSub[$iIdx] = ($iSel = 0xFFFFFFFF ? -1 : Number($iSel))
    ; $tBlock must survive until here: it is returned so the caller keeps it.
    Return SetError(0, $iN, $tBlock)
EndFunc   ;==>_Wsp_EndClient

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_SelectedSub
; Description ...: Index of the subprotocol the peer chose, in the array offered to _Wsp_BeginClient.
; Syntax ........: _Wsp_SelectedSub($iIdx)
; Parameters ....: $iIdx                 - slot index
; Return values .: Success - Index >= 0, or -1 when the peer chose nothing (or nothing was offered).
;                  Failure - @error 1 = index out of table.
; Author ........: Numeric1
; Related .......: _Wsp_EndClient, _Wsp_BeginServer
;===============================================================================================================================
; Index of the subprotocol chosen by the peer, in the array offered to _Wsp_BeginClient.
; -1 = the peer chose nothing (or nothing was offered).
Func _Wsp_SelectedSub($iIdx)
    If $iIdx < 0 Or $iIdx >= $g_iWspSlots Then Return SetError(1, 0, -1)
    Return $g_aWsp_SelSub[$iIdx]
EndFunc   ;==>_Wsp_SelectedSub

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_BeginServer
; Description ...: Server side: feed the received request headers to WebSocketStartServerHandshake and get the 101 answer.
; Syntax ........: _Wsp_BeginServer($iIdx, $sRequestHead, $sResponse[, $sSubprotocol])
; Parameters ....: $iIdx                 - slot index
;                  $sRequestHead         - the client request head, up to CRLFCRLF
;                  $sResponse            - receives the "HTTP/1.1 101 ..." answer to write
;                  $sSubprotocol         - [optional] subprotocol the server selects; the component emits it in the 101 (V19)
; Return values .: Success - Number of request headers, @extended = number of headers in the answer. $sResponse receives the bytes to write.
;                  Failure - 0, @error 1 = dead slot, 2 = request head too short, 3 = header line without a colon (@extended = line), 4 = no header parsed, 5 = DllCall failure, 6 = component refusal (@extended = HRESULT), 7 = empty answer array.
; Author ........: Numeric1
; Related .......: _Wsp_EndServer, _Wsp_ReadHead
;===============================================================================================================================
; =============================================================================
; SERVER side: received request headers -> 101 response to write.
; =============================================================================
Func _Wsp_BeginServer($iIdx, $sRequestHead, ByRef $sResponse, $sSubprotocol = "")
    Local $h = _Wsp_Handle($iIdx)
    If @error Then Return SetError(1, @error, 0)
    Local $hDll = _Wsp_Dll($iIdx)

    Local $tBlock = 0, $iN = 0, $iStatus = 0
    Local $sClean = StringStripCR($sRequestHead)
    Local $aL = StringSplit($sClean, @LF)
    If $aL[0] < 2 Then Return SetError(2, 0, 0)

    Local $n = 0
    For $i = 2 To $aL[0]
        If StringStripWS($aL[$i], 8) = "" Then ExitLoop
        If StringInStr($aL[$i], ":") = 0 Then Return SetError(3, $i, 0)
        $n += 1
    Next
    If $n = 0 Then Return SetError(4, 0, 0)

    $tBlock = DllStructCreate("byte[" & ($n * $g_iWspSzHeader) & "];char[" & (StringLen($sRequestHead) + 4) & "]")
    Local $pPool = DllStructGetPtr($tBlock, 2)
    Local $iUsed = 0, $iElem = 0
    For $i = 2 To $aL[0]
        Local $line = $aL[$i]
        If StringStripWS($line, 8) = "" Then ExitLoop
        Local $j = StringInStr($line, ":")
        Local $sName = StringStripWS(StringLeft($line, $j - 1), 3)
        Local $sValue = StringStripWS(StringMid($line, $j + 1), 3)
        Local $pName = $pPool + $iUsed
        DllStructSetData(DllStructCreate("byte[" & (StringLen($sName) + 1) & "]", $pName), 1, StringToBinary($sName, 1))
        $iUsed += StringLen($sName) + 1
        Local $pValue = $pPool + $iUsed
        DllStructSetData(DllStructCreate("byte[" & (StringLen($sValue) + 1) & "]", $pValue), 1, StringToBinary($sValue, 1))
        $iUsed += StringLen($sValue) + 1
        $iElem += 1
        _Wsp_SetHeader($tBlock, $iElem, $pName, StringLen($sName), $pValue, StringLen($sValue))
    Next

    ; V19: a selected subprotocol is RETURNED by the component in the 101 ("Sec-WebSocket-Protocol:
    ; ..."); NULL = header absent (witness S6b).
    Local $tSel = 0, $pSel = 0
    If $sSubprotocol <> "" Then
        $tSel = DllStructCreate("char[" & (StringLen($sSubprotocol) + 1) & "]")
        DllStructSetData($tSel, 1, $sSubprotocol)
        $pSel = DllStructGetPtr($tSel)
    EndIf

    Local $tAdd = DllStructCreate("ptr")
    Local $tAddN = DllStructCreate("dword")
    Local $aCall = DllCall($hDll, "int", "WebSocketBeginServerHandshake", _
            "ptr", $h, "ptr", $pSel, "ptr", 0, "dword", 0, _
            "ptr", DllStructGetPtr($tBlock), "dword", $n, _
            "ptr", DllStructGetPtr($tAdd), "ptr", DllStructGetPtr($tAddN))
    Local $e = @error
    If $e Then Return SetError(5, $e, 0)
    If $aCall[0] < 0 Then Return SetError(6, $aCall[0], 0)

    Local $iRN = DllStructGetData($tAddN, 1)
    Local $pArr = DllStructGetData($tAdd, 1)
    If $iRN = 0 Or $pArr = 0 Then Return SetError(7, 0, 0)

    $sResponse = "HTTP/1.1 101 Switching Protocols" & @CRLF
    For $i = 0 To $iRN - 1
        Local $tH = DllStructCreate("ptr;dword;ptr;dword", $pArr + $i * $g_iWspSzHeader)
        Local $sName = _Wsp_ReadAnsi(DllStructGetData($tH, 1), DllStructGetData($tH, 2))
        Local $sValue = _Wsp_ReadAnsi(DllStructGetData($tH, 3), DllStructGetData($tH, 4))
        If $sName = "" Then ContinueLoop
        $sResponse &= $sName & ": " & $sValue & @CRLF
    Next
    $sResponse &= @CRLF
    Return SetError(0, $iRN, $n)
EndFunc   ;==>_Wsp_BeginServer

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_EndServer
; Description ...: Server side: confirm the handshake with WebSocketEndServerHandshake.
; Syntax ........: _Wsp_EndServer($iIdx)
; Parameters ....: $iIdx                 - slot index
; Return values .: Success - 1.
;                  Failure - 0, @error 1 = dead slot, 2 = DllCall failure, 3 = component refusal (@extended = HRESULT).
; Author ........: Numeric1
; Related .......: _Wsp_BeginServer
;===============================================================================================================================
Func _Wsp_EndServer($iIdx)
    Local $h = _Wsp_Handle($iIdx)
    If @error Then Return SetError(1, @error, 0)
    Local $hDll = _Wsp_Dll($iIdx)
    Local $aCall = DllCall($hDll, "int", "WebSocketEndServerHandshake", "ptr", $h)
    If @error Then Return SetError(2, @error, 0)
    If $aCall[0] < 0 Then Return SetError(3, $aCall[0], 0)
    $g_aWsp_State[$iIdx] = $g_iWspOpen
    Return 1
EndFunc   ;==>_Wsp_EndServer

; =============================================================================
; Network I/O serving the pump.
;
; TRANSPORT SEAM. Four sites touch the socket; they now go through the three helpers below. TLS is
; attached PER CONNECTION (see _Wsp_AttachTls) and the layer 2 functions are called BY NAME with
; Call(): wsp.au3 stays compilable and provable on its own (spike3, ws://), and any transport that
; honours the three signatures can be attached. The states compared below are tls.au3's
; ($Tls_ST_DEAD = 4, $Tls_ST_PEER_CLOSED = 5), copied here so no dependency is created.
; =============================================================================
Global $g_aWsp_TlsOn[$g_iWspSlots]
Global $g_aWsp_TlsSlot[$g_iWspSlots]
Global Const $g_iWspTlsDead = 4
Global Const $g_iWspTlsPeerClosed = 5

; THE NAMES ARE VARIABLES, NOT LITERALS. Measure: Au3Check resolves Call("_Name") statically and
; reports "undefined function" (6 errors) when layer 2 is not included; Call($name) gives 0 errors
; and the name is resolved only at run time. Without this form wsp.au3 no longer passes the syntax
; check ALONE, which is the whole point of the seam. And @error 57005 = "function not found"
; (measured, x86 and x64): the only error a ws:// program that never saw tls.au3 can produce.
Global $g_aWspXptFn[6] = ["_Tls_Send", "_Tls_PendingTx", "_Tls_Pump", _
        "_Tls_Read", "_Tls_State", "_Tls_Available"]
Global Const $g_iXptFnSend = 0, $g_iXptFnPend = 1, $g_iXptFnPump = 2
Global Const $g_iXptFnRead = 3, $g_iXptFnState = 4, $g_iXptFnAvail = 5
Global Const $g_iWspXptMissing = 13  ; layer 2 is not loaded in this program

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_AttachTls
; Description ...: Route a slot's network I/O through layer 2 (tls.au3) instead of the raw socket.
; Syntax ........: _Wsp_AttachTls($iIdx, $iSlotTls)
; Parameters ....: $iIdx                 - slot index
;                  $iSlotTls             - layer 2 slot already in state $Tls_ST_OPEN
; Return values .: Success - 1.
;                  Failure - 0, @error 1 = index out of table, 2 = layer 2 absent from this program (@extended = probed name), 3 = negative TLS slot.
; Author ........: Numeric1
; Remarks .......: Call it after the TLS slot is open and before the HTTP upgrade, so the upgrade leaves encrypted; existence of the names is probed with pure accessors only, because probing _Tls_Send would have a network effect.
; Related .......: _Wsp_XptWrite, _Wsp_XptRead, _Wsp_XptWait
;===============================================================================================================================
; Attach layer 2 (tls.au3) to an already created connection. Call it AFTER the TLS slot reached
; $Tls_ST_OPEN and BEFORE the HTTP upgrade: the upgrade then leaves encrypted and the answer is read
; in clear.
;
; The names are probed with the PURE accessors only (_Tls_State, _Tls_Available, _Tls_PendingTx: they
; touch one array element). Probing _Tls_Send or _Tls_Pump here would have a network effect, and
; reading $iSlotTls out of table would be an out-of-range subscript = a fatal AutoIt error, not an
; exploitable @error value.
Func _Wsp_AttachTls($iIdx, $iSlotTls)
    If $iIdx < 0 Or $iIdx >= $g_iWspSlots Then Return SetError(1, 0, 0)
    If $iSlotTls < 0 Then Return SetError(3, 0, 0)
    Local $aProbe[3] = [$g_iXptFnState, $g_iXptFnAvail, $g_iXptFnPend]
    For $i = 0 To 2
        Call($g_aWspXptFn[$aProbe[$i]], $iSlotTls)
        If @error = 57005 Then Return SetError(2, $aProbe[$i], 0)
    Next
    $g_aWsp_TlsOn[$iIdx] = 1
    $g_aWsp_TlsSlot[$iIdx] = $iSlotTls
    Return 1
EndFunc   ;==>_Wsp_AttachTls

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_XptWrite
; Description ...: Write bytes through the attached TLS connection (the wss:// branch of the seam).
; Syntax ........: _Wsp_XptWrite($iIdx, $bData, $iBudgetMs)
; Parameters ....: $iIdx                 - slot index
;                  $bData                - clear bytes to write
;                  $iBudgetMs            - maximum total time for the write
; Return values .: Success - Number of clear bytes handed to layer 2, @extended 0.
;                  Failure - @error 9 = budget exhausted (@extended = bytes that left anyway), 11 = TLS slot not open, 12 = TLS refusal (@extended = reason), 13 = layer 2 absent from this program.
; Author ........: Numeric1
; Remarks .......: _Tls_Send attempts one immediate write only; the rest sits in layer 2's queue, which the layer 3 pump does not drain by itself.
; Related .......: _Wsp_NetWrite, _Wsp_AttachTls
;===============================================================================================================================
; @error 0 = the n bytes are written on the wire, 9 = budget exhausted (@extended = bytes that left
; anyway), 11 = the TLS slot is not open, 12 = TLS refusal, 13 = layer 2 absent from this program.
Func _Wsp_XptWrite($iIdx, $bData, $iBudgetMs)
    Local $iLen = BinaryLen($bData)
    If $iLen = 0 Then Return 0
    If Not $g_aWsp_TlsOn[$iIdx] Then Return SetError(-1, 0, 0) ; not handled here
    Local $s = $g_aWsp_TlsSlot[$iIdx]
    Local $n = Call($g_aWspXptFn[$g_iXptFnSend], $s, $bData)
    Local $e = @error
    If $e = 57005 Then Return SetError($g_iWspXptMissing, 0, 0)
    If $e = 1 Then Return SetError(11, @extended, 0)
    If $e Then Return SetError(12, @extended, $n)
    ; _Tls_Send attempts one immediate write only: the rest sits in layer 2's queue, and the
    ; layer 3 pump does not drain it by itself.
    Local $t0 = TimerInit()
    While Call($g_aWspXptFn[$g_iXptFnPend], $s) > 0
        Call($g_aWspXptFn[$g_iXptFnPump], $s, 10)
        Local $ep = @error
        If $ep = 57005 Then Return SetError($g_iWspXptMissing, 0, $n)
        If $ep > 2 Then Return SetError(12, @extended, $n)
        If TimerDiff($t0) > $iBudgetMs Then Return SetError(9, $n, $n)
    WEnd
    Return SetError(0, 0, $iLen)
EndFunc   ;==>_Wsp_XptWrite

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_XptRead
; Description ...: Read decrypted bytes from the attached TLS connection (the wss:// branch of the seam).
; Syntax ........: _Wsp_XptRead($iIdx, $iMax)
; Parameters ....: $iIdx                 - slot index
;                  $iMax                 - maximum number of clear bytes to take
; Return values .: Success - Binary, possibly empty with @extended 4 when nothing is available yet.
;                  Failure - @error 1 = the peer closed, 2 = TLS slot dead (@extended = state), 13 = layer 2 absent.
; Author ........: Numeric1
; Related .......: _Wsp_NetRead, _Wsp_XptWait
;===============================================================================================================================
; @error 0 = n bytes (or nothing for now, @extended 4), 1 = the peer closed, 2 = named error in
; @extended, 13 = layer 2 absent.
Func _Wsp_XptRead($iIdx, $iMax)
    If Not $g_aWsp_TlsOn[$iIdx] Then Return SetError(-1, 0, Binary("0x")) ; not handled here
    Local $s = $g_aWsp_TlsSlot[$iIdx]
    Local $b = Call($g_aWspXptFn[$g_iXptFnRead], $s, $iMax)
    Local $e = @error
    If $e = 57005 Then Return SetError($g_iWspXptMissing, 0, Binary("0x"))
    If BinaryLen($b) > 0 Then Return SetError(0, 0, $b)
    Local $st = Call($g_aWspXptFn[$g_iXptFnState], $s)
    If @error = 57005 Then Return SetError($g_iWspXptMissing, 0, Binary("0x"))
    If $st = $g_iWspTlsPeerClosed Then Return SetError(1, 0, Binary("0x"))
    If $st = $g_iWspTlsDead Then Return SetError(2, $st, Binary("0x"))
    Return SetError(0, 4, Binary("0x"))
EndFunc   ;==>_Wsp_XptRead

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_XptWait
; Description ...: Report whether the TLS branch has anything readable (pumps layer 2 while waiting).
; Syntax ........: _Wsp_XptWait($iIdx, $iMs)
; Parameters ....: $iIdx                 - slot index
;                  $iMs                  - time to spend pumping layer 2
; Return values .: Success - 1 = at least one clear byte is available, or the slot already knows the peer closed.
;                  Failure - 0 = nothing for now. @error 13 = layer 2 absent from this program.
; Author ........: Numeric1
; Remarks .......: The "peer closed / dead" answer is the mirror of the bare-Winsock branch (measure spike10 S3/S4): a suspended receive action must still learn about the FIN, otherwise a decrypted close frame never leaves the component.
; Related .......: _Wsp_HasReadable, _Wsp_XptRead
;===============================================================================================================================
; Open the receive gate: 1 = there is (at least) one byte, 0 = nothing. On the TLS side "wait" means
; pumping layer 2: it is the one that reads the network, decrypts and queues the clear text.
Func _Wsp_XptWait($iIdx, $iMs)
    If Not $g_aWsp_TlsOn[$iIdx] Then Return SetError(-1, 0, 0) ; not handled here
    Local $s = $g_aWsp_TlsSlot[$iIdx]
    Local $n = Call($g_aWspXptFn[$g_iXptFnAvail], $s)
    If @error = 57005 Then Return SetError($g_iWspXptMissing, 0, 0)
    If $n > 0 Then Return 1
    Call($g_aWspXptFn[$g_iXptFnPump], $s, $iMs)
    $n = Call($g_aWspXptFn[$g_iXptFnAvail], $s)
    If @error = 57005 Then Return SetError($g_iWspXptMissing, 0, 0)
    If $n > 0 Then Return 1
    ; Mirror of the bare-Winsock branch (measure spike10 S3/S4, x86 AND x64): when layer 2 has
    ; ALREADY seen the peer's close, not one clear byte will come, yet a suspended receive action
    ; must still learn about the FIN. Answering "nothing" here kept the action open, the completed
    ; 0 bytes were never returned, and the already decrypted close frame never left the component:
    ; the server lost the code and the reason.
    Local $st = Call($g_aWspXptFn[$g_iXptFnState], $s)
    If @error = 57005 Then Return SetError($g_iWspXptMissing, 0, 0)
    Return ($st = $g_iWspTlsPeerClosed Or $st = $g_iWspTlsDead)
EndFunc   ;==>_Wsp_XptWait

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_NetWrite
; Description ...: Write bytes on the connection of a slot, TLS or bare Winsock.
; Syntax ........: _Wsp_NetWrite($iIdx, $bData, $iBudgetMs)
; Parameters ....: $iIdx                 - slot index
;                  $bData                - bytes to write
;                  $iBudgetMs            - maximum total time for the write
; Return values .: Success - Number of bytes written, @error 0 when all of them left.
;                  Failure - @error 9 = budget exhausted (partial write, @extended = layer 2 step when relevant); otherwise the transport's own @error, with the Winsock code in @extended for layer 1.
; Author ........: Numeric1
; Related .......: _Wsp_XptWrite, _Wsp_PumpOnce
;===============================================================================================================================
Func _Wsp_NetWrite($iIdx, $bData, $iBudgetMs)
    Local $iSent = 0
    Local $iLen = BinaryLen($bData)
    If $iLen = 0 Then Return 0
    If $g_aWsp_TlsOn[$iIdx] Then
        Local $w = _Wsp_XptWrite($iIdx, $bData, $iBudgetMs)
        Local $ew = @error
        If $iLen <= 64 Then $g_aWsp_LastSmallWrite[$iIdx] = $bData
        $g_aWsp_PrevWriteDesc[$iIdx] = $g_aWsp_LastWriteDesc[$iIdx]
        $g_aWsp_LastWriteDesc[$iIdx] = $iLen & "@TLS" & ($iLen <= 65600 ? BinaryMid($bData, 1, 10) : Binary("0x"))
        $g_aWsp_BytesWritten[$iIdx] += $w
        Return SetError($ew, 0, $w)
    EndIf
    If $iLen <= 64 Then $g_aWsp_LastSmallWrite[$iIdx] = $bData
    Local $sDesc = $iLen & "@" & ($iLen <= 65600 ? BinaryMid($bData, 1, 10) : Binary("0x"))
    $g_aWsp_PrevWriteDesc[$iIdx] = $g_aWsp_LastWriteDesc[$iIdx]
    $g_aWsp_LastWriteDesc[$iIdx] = $sDesc
    Local $t0 = TimerInit()
    While $iSent < $iLen
        Local $chunk = BinaryMid($bData, $iSent + 1, 65536)
        Local $n = _Wsk_SendChunk($g_aWsp_Socket[$iIdx], $chunk)
        Local $e = @error
        If $e = 0 Then
            $iSent += $n
        ElseIf $e = 4 Then
            $iSent += $n ; partiel
            Local $rv = _Wsk_Poll($g_aWsp_Socket[$iIdx], $Wsk_POLLWRNORM, 20)
            If TimerDiff($t0) > $iBudgetMs Then ExitLoop
        Else
            Return SetError($e, $e = 5 ? _Wsk_LastError() : 0, $iSent)
        EndIf
        If TimerDiff($t0) > $iBudgetMs Then ExitLoop
    WEnd
    $g_aWsp_BytesWritten[$iIdx] += $iSent
    Return SetError($iSent < $iLen ? 9 : 0, 0, $iSent)
EndFunc   ;==>_Wsp_NetWrite

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_NoteRead
; Description ...: Add bytes to the per-slot read totals and the sliding wire trace.
; Syntax ........: _Wsp_NoteRead($iIdx, $bData)
; Parameters ....: $iIdx                 - slot index
;                  $bData                - bytes that were just read
; Return values .: Success - The number of bytes counted.
;                  Failure - 0 for an empty read.
; Author ........: Numeric1
; Remarks .......: The totals are the only evidence that separates "the frame bytes never reached the socket" from "they arrived and our pump never handed them over".
; Related .......: _Wsp_WireTrace, _Wsp_NetRead
;===============================================================================================================================
; Read INTO the DLL's memory (no copy): this is what proves the buffers returned by
; WebSocketGetAction are really writable.
; RULE (measure P3.3): every exit names its own @error. A plain "Return 0" inherits the @error of
; WSARecv, so 4 (WSAEWOULDBLOCK) reported as "nothing read and @error=4" made the pump believe the
; peer had closed cleanly.
; @error 0 = $iGot bytes read (0 = nothing for now)
; @error 1 = clean close (FIN received, 0 bytes)
; @error 2 = Winsock error named in @extended
Func _Wsp_NoteRead($iIdx, $bData)
    Local $iGot = BinaryLen($bData)
    If $iGot = 0 Then Return 0
    If $iGot <= 64 Then $g_aWsp_LastSmallRead[$iIdx] = $bData
    Local $bTail = ($iGot >= 48 ? BinaryMid($bData, $iGot - 47, 48) : _
            BinaryMid($g_aWsp_TailRead[$iIdx] & $bData, BinaryLen($g_aWsp_TailRead[$iIdx] & $bData) - 47, 48))
    $g_aWsp_TailRead[$iIdx] = $bTail
    $g_aWsp_BytesRead[$iIdx] += $iGot
    Return $iGot
EndFunc   ;==>_Wsp_NoteRead

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_NetRead
; Description ...: Read up to $iMax bytes of the connection into a DLL-side pointer or into the pending queue.
; Syntax ........: _Wsp_NetRead($iIdx, $ptr, $iMax)
; Parameters ....: $iIdx                 - slot index
;                  $ptr                  - destination pointer inside the component's memory (0 = queue the bytes instead)
;                  $iMax                 - room available
; Return values .: Success - Number of bytes taken (0 with @extended 4 = nothing for now).
;                  Failure - @error 1 = clean close (FIN, 0 bytes), 2 = Winsock error named in @extended, 13 = layer 2 absent.
; Author ........: Numeric1
; Remarks .......: Every exit names its own @error (measure P3.3): a plain "Return 0" inherits WSARecv's WSAEWOULDBLOCK and made the pump believe the peer had closed.
; Related .......: _Wsp_XptRead, _Wsp_QueueBytes
;===============================================================================================================================
Func _Wsp_NetRead($iIdx, $ptr, $iMax)
    If $iMax <= 0 Then Return SetError(0, 0, 0)
    ; 1) what was already read (the bytes that followed the 101 or a frame)
    If BinaryLen($g_aWsp_Pending[$iIdx]) > 0 Then
        Local $bHave = $g_aWsp_Pending[$iIdx]
        Local $iTake = (BinaryLen($bHave) < $iMax ? BinaryLen($bHave) : $iMax)
        Local $b = BinaryMid($bHave, 1, $iTake)
        DllStructSetData(DllStructCreate("byte[" & $iTake & "]", $ptr), 1, $b)
        $g_aWsp_Pending[$iIdx] = BinaryMid($bHave, $iTake + 1)
        _Wsp_NoteRead($iIdx, $b)
        Return SetError(0, 0, $iTake)
    EndIf
    Local $bRecv = 0
    If $g_aWsp_TlsOn[$iIdx] Then
        $bRecv = _Wsp_XptRead($iIdx, $iMax)
        Local $et = @error
        If $et = 1 Then Return SetError(1, 0, 0)
        If $et = 2 Then Return SetError(2, @extended, 0)
        Local $iGot = BinaryLen($bRecv)
        If $iGot > 0 Then
            _Wsp_NoteRead($iIdx, $bRecv)
            DllStructSetData(DllStructCreate("byte[" & $iGot & "]", $ptr), 1, $bRecv)
        EndIf
        Return SetError(0, ($iGot = 0 ? 4 : 0), $iGot)
    EndIf
    $bRecv = _Wsk_Recv($g_aWsp_Socket[$iIdx], $iMax)
    Local $e = @error
    If $e = 4 Then Return SetError(0, 4, 0)  ; WSAEWOULDBLOCK: nothing for now
    If $e = 6 Then Return SetError(1, 0, 0)  ; clean close by the peer
    If $e <> 0 Then Return SetError(2, $e, 0)
    Local $iGot = BinaryLen($bRecv)
    If $iGot > 0 Then
        _Wsp_NoteRead($iIdx, $bRecv)
        DllStructSetData(DllStructCreate("byte[" & $iGot & "]", $ptr), 1, $bRecv)
    EndIf
    Return SetError(0, 0, $iGot)
EndFunc   ;==>_Wsp_NetRead

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_QueueBytes
; Description ...: Append bytes read before the component asked for them to the slot's pending buffer.
; Syntax ........: _Wsp_QueueBytes($iIdx, $bData)
; Parameters ....: $iIdx                 - slot index
;                  $bData                - bytes to park
; Return values .: Success - None - $g_aWsp_Pending is updated.
; Author ........: Numeric1
; Remarks .......: Needed because the bytes that follow the 101 (or follow a frame) already belong to the WebSocket stream and must never be dropped.
; Related .......: _Wsp_ReadHead, _Wsp_FillOpenReceive
;===============================================================================================================================
Func _Wsp_QueueBytes($iIdx, $bData)
    $g_aWsp_Pending[$iIdx] &= $bData
EndFunc   ;==>_Wsp_QueueBytes

; The pump's structures are allocated ONCE (globals): recreating them every turn would cost more
; than the DLL call itself and would distort the throughput measurement. The pump is never reentrant
; here (one slot at a time).
Global $g_tWspBufs = 0, $g_tWspN = 0, $g_tWspAct = 0, $g_tWspBT = 0, $g_tWspApp = 0, $g_tWspActCtx = 0
Global Const $g_iWspMaxBuffers = 8
; Must an INDICATE_* action be finished with CompleteAction? The component does not say in the
; header: this is a measurement (probe_indicate), not an opinion. 1 = we complete. The value 0 is
; kept only for the measurement.
Global $g_fWspCompleteIndicate = 1

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_PumpInit
; Description ...: Allocate the shared pump structures once (they are never recreated per turn).
; Syntax ........: _Wsp_PumpInit() :None
; Return values .: Success - 1.
; Author ........: Numeric1
; Remarks .......: Recreating them every turn would cost more than the DLL call and distort the throughput measurement; the pump is never reentrant (one slot at a time), which is why one global block is safe.
; Related .......: _Wsp_PumpOnce
;===============================================================================================================================
Func _Wsp_PumpInit()
    If $g_tWspBufs <> 0 Then Return 1
    $g_tWspBufs = DllStructCreate("byte[" & ($g_iWspMaxBuffers * $g_iWspSzBuffer) & "]")
    $g_tWspN = DllStructCreate("dword")
    $g_tWspAct = DllStructCreate("dword")
    $g_tWspBT = DllStructCreate("dword")
    $g_tWspApp = DllStructCreate("ptr")
    $g_tWspActCtx = DllStructCreate("ptr")
    Return 1
EndFunc   ;==>_Wsp_PumpInit

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_HasReadable
; Description ...: Ask honestly whether there is enough to fill the component's action.
; Syntax ........: _Wsp_HasReadable($iIdx, $iBudgetMs)
; Parameters ....: $iIdx                 - slot index
;                  $iBudgetMs            - time to spend waiting
; Return values .: Success - 1 = we can read (or the peer closed and the read that follows will say).
;                  Failure - 0 = nothing for now.
; Author ........: Numeric1
; Remarks .......: Pending bytes count first; then the transport is polled. _Wsk_Poll returns revents, not a count, and its @error 3 means "expired" which is not an error. POLLERR/POLLHUP alone are enough because the following read returns the FIN or the named error.
; Related .......: _Wsp_XptWait, _Wsp_FillOpenReceive
;===============================================================================================================================
; =============================================================================
; "Is there enough to fill the component's action?" The answer is always honest: 0 = nothing for
; now, 1 = we can read (or the peer closed, the read that follows will say).
; SIGNATURE WARNING: _Wsk_Poll returns the REVENTS, not a count, and its @error 3 means "expired" =
; nothing to read (that is not an error).
; =============================================================================
Func _Wsp_HasReadable($iIdx, $iBudgetMs)
    If BinaryLen($g_aWsp_Pending[$iIdx]) > 0 Then Return 1
    If $g_aWsp_TlsOn[$iIdx] Then _
            Return (_Wsp_XptWait($iIdx, $iBudgetMs) = 1)  ; clear text, not network bytes
    Local $iRv = _Wsk_Poll($g_aWsp_Socket[$iIdx], $Wsk_POLLRDNORM, $iBudgetMs)
    Local $ePoll = @error
    ; POLLERR/POLLHUP alone are enough: the read that follows returns the FIN (eR=1) or the named
    ; Winsock error (eR=2), so the truth and nothing else.
    Return Not($ePoll = 3 Or ($ePoll = 0 And _
                    BitAND($iRv, BitOR($Wsk_POLLRDNORM, $Wsk_POLLERR, $Wsk_POLLHUP)) = 0))
EndFunc   ;==>_Wsp_HasReadable

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_ClearOpenReceive
; Description ...: Forget a receive action that was left open (slot closing, hand-over).
; Syntax ........: _Wsp_ClearOpenReceive($iIdx)
; Parameters ....: $iIdx                 - slot index
; Return values .: Success - 1.
; Author ........: Numeric1
; Related .......: _Wsp_FillOpenReceive, _Wsp_PumpOnce
;===============================================================================================================================
Func _Wsp_ClearOpenReceive($iIdx)
    $g_aWsp_RxOpenCtx[$iIdx] = 0
    $g_aWsp_RxOpenPtr[$iIdx] = 0
    $g_aWsp_RxOpenLen[$iIdx] = 0
    $g_aWsp_ParserBusy[$iIdx] = 0
    Return 1
EndFunc   ;==>_Wsp_ClearOpenReceive

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_FillOpenReceive
; Description ...: Resolve a receive action that was left OPEN because the peer had nothing to put in it.
; Syntax ........: _Wsp_FillOpenReceive($iIdx, $iBudgetMs, $iType)
; Parameters ....: $iIdx                 - slot index
;                  $iBudgetMs            - time allowed for the read
;                  $iType                - receives the buffer type when the action completes
; Return values .: Success - Number of bytes handed over (0 = still open), $iType = -1 when nothing was indicated.
;                  Failure - @error 5 = the peer closed, step in @extended (0 = clean FIN, 2 = named Winsock error).
; Author ........: Numeric1
; Remarks .......: The action is never completed with a lying 0 (measures A6 and probe_sendq P7/P8) - the frame count handed over is the real one, and a 0-byte completion is only produced when a FIN or a Winsock error was really read.
; Related .......: _Wsp_HasReadable, _Wsp_Complete, _Wsp_PumpOnce
;===============================================================================================================================
; =============================================================================
; Resolve the receive action LEFT OPEN: the component is waiting for bytes the peer had not sent
; yet on the turn they were requested. Hand over what arrived, complete with the REAL COUNT, and
; only return a completed 0 bytes when the FIN or the Winsock error was really read (measure A6: a 0
; returned for an expired budget is read as "the peer closed").
; Returns the number of bytes handed over (0 = still open). @error 5 = the peer closed, the step in
; @extended (0 = clean FIN, 2 = named Winsock error).
; =============================================================================
Func _Wsp_FillOpenReceive($iIdx, $iBudgetMs, ByRef $iType)
    Local $pCtx = $g_aWsp_RxOpenCtx[$iIdx]
    If Not _Wsp_HasReadable($iIdx, $iBudgetMs) Then
        $g_aWsp_Gated[$iIdx] += 1
        Return SetError(0, 0, 0)
    EndIf
    Local $g = _Wsp_NetRead($iIdx, $g_aWsp_RxOpenPtr[$iIdx], $g_aWsp_RxOpenLen[$iIdx])
    Local $eR = @error
    If $eR = 1 Or $eR = 2 Then
        Local $x = ($eR = 2 ? @extended : 0)
        _Wsp_ClearOpenReceive($iIdx)
        _Wsp_Complete($iIdx, $pCtx, 0)
        Return SetError(5, $x, 0)
    EndIf
    If $g = 0 Then
        ; the poll promised and did not deliver (peer died silently): keep the action
        ; open, NEVER a completed 0 bytes over a plain nothing.
        $g_aWsp_Gated[$iIdx] += 1
        Return SetError(0, 0, 0)
    EndIf
    _Wsp_ClearOpenReceive($iIdx)
    $g_aWsp_Counters[$iIdx][2] += 1
    _Wsp_Complete($iIdx, $pCtx, $g)
    Return SetError(0, 0, $g)
EndFunc   ;==>_Wsp_FillOpenReceive

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_PumpOnce
; Description ...: Serve exactly one action of the named queue.
; Syntax ........: _Wsp_PumpOnce($iIdx, $iBudgetMs, $iAction, $iType[, $iQueue])
; Parameters ....: $iIdx                 - slot index
;                  $iBudgetMs            - time allowed to wait for the network
;                  $iAction              - receives the WEB_SOCKET_ACTION that was served
;                  $iType                - receives the buffer type of the delivered piece (normalised)
;                  $iQueue               - [optional] $Wsp_QUEUE_SEND, $Wsp_QUEUE_RECEIVE or $Wsp_QUEUE_ALL
; Return values .: Success - 1 when a message is delivered to the caller (INDICATE_RECEIVE_COMPLETE), $iType = its buffer type; 0 otherwise, $iAction = action served, 6 = INDICATE action left to complete (measure probe_indicate).
;                  Failure - @error 1 = dead slot, 2 = DllCall failure, 3 = component refusal (@extended = HRESULT), 4 = write failure, 5 = peer closed (@extended = step), 6 = an INDICATE action is still open.
; Author ........: Numeric1
; Remarks .......: With QUEUE_ALL and an armed receive, SEND_TO_NETWORK never comes (measures A2/A4/S3), so callers must name the queue they serve. pvApplicationContext [7] is our token and never goes to CompleteAction (segfault); pvActionContext [8] is the component's and is the only accepted argument.
; Related .......: _Wsp_Pump, _Wsp_FlushSend, _Wsp_Complete
;===============================================================================================================================
; =============================================================================
; The pump: one turn = one action. $iBudgetMs bounds the time spent waiting for the network.
; Returns 1 when a message is delivered to the caller (INDICATE_RECEIVE_COMPLETE).
; =============================================================================
Func _Wsp_PumpOnce($iIdx, $iBudgetMs, ByRef $iAction, ByRef $iType, $iQueue = $Wsp_QUEUE_ALL)
    $iAction = -1
    $iType = -1
    Local $h = _Wsp_Handle($iIdx)
    If @error Then Return SetError(1, @error, 0)
    Local $hDll = _Wsp_Dll($iIdx)
    _Wsp_PumpInit()

    ; Step 1 (measured probe_sendq P7/P8): a receive action may have stayed OPEN because
    ; the peer had nothing to put in it. Resolve it HERE, before any fresh GetAction: the
    ; component accepts one action at a time, so the receive queue returns nothing while it
    ; waits. The SEND queue, on the other hand, keeps being served during the wait (P7:
    ; SEND_TO_NETWORK returned 1 ms after the open).
    If $iQueue <> $Wsp_QUEUE_SEND And $g_aWsp_RxOpenCtx[$iIdx] <> 0 Then
        $iAction = $Wsp_NO_ACTION
        _Wsp_FillOpenReceive($iIdx, $iBudgetMs, $iType)
        Local $eF = @error
        Local $xF = @extended
        $g_aWsp_Counters[$iIdx][0] += 1
        If $eF = 5 Then Return SetError(5, $xF, 0)
        Return SetError(0, 0, 0)
    EndIf

    ; No GATE in front of GetAction any more (measure 2 of the $g_aWsp_ParserBusy block):
    ; asking for an action no longer lies because what cannot be filled is SUSPENDED. This is
    ; what lets messages already parsed inside the component come out while the socket can no
    ; longer read anything.

    DllStructSetData($g_tWspN, 1, $g_iWspMaxBuffers)
    Local $aCall = DllCall($hDll, "int", "WebSocketGetAction", _
            "ptr", $h, "dword", $iQueue, _
            "ptr", DllStructGetPtr($g_tWspBufs), "ptr", DllStructGetPtr($g_tWspN), _
            "ptr", DllStructGetPtr($g_tWspAct), "ptr", DllStructGetPtr($g_tWspBT), _
            "ptr", DllStructGetPtr($g_tWspApp), "ptr", DllStructGetPtr($g_tWspActCtx))
    If @error Then Return SetError(2, @error, 0)
    If $aCall[0] < 0 Then Return SetError(3, $aCall[0], 0)

    $iAction = DllStructGetData($g_tWspAct, 1)
    $iType = _Wsp_TypeNorm(DllStructGetData($g_tWspBT, 1))
    Local $iN = DllStructGetData($g_tWspN, 1)
    ; TWO values returned by GetAction, one use each (measure probe_actionctx):
    ; [7] pvApplicationContext = THE VALUE WE SUPPLIED to WebSocketSend/Receive. An
    ; application token only. Passing it to CompleteAction = SEGFAULT ("app" mode: rc 139).
    ; [8] pvActionContext = allocated by the component: THIS is what
    ; WebSocketCompleteAction expects. Passing 0 survives but leaves the action running:
    ; every later GetAction returns NO_ACTION ("zero" mode), so the send never finishes.
    Local $pAppActCtx = DllStructGetData($g_tWspApp, 1)
    Local $pActCtx = DllStructGetData($g_tWspActCtx, 1)
    If $iN > $g_aWsp_Counters[$iIdx][5] Then $g_aWsp_Counters[$iIdx][5] = $iN
    $g_aWsp_Counters[$iIdx][0] += 1
    Switch $iAction
        Case $Wsp_NO_ACTION
            ; Nothing to tell the component this turn. NEVER touch $g_aWsp_ParserBusy here:
            ; it no longer means "the parser is hungry", it is the state of the OPEN receive
            ; action, and an open action never returns NO_ACTION (we never query it).
            Return SetError(0, 0, 0)

        Case $Wsp_SEND_TO_NETWORK
            Local $bAll = Binary("0x")
            For $i = 1 To $iN
                Local $p = _Wsp_GetBufferPtr($g_tWspBufs, $i, 1)
                Local $l = _Wsp_GetBufferPtr($g_tWspBufs, $i, 2)
                If $l > 0 Then $bAll &= DllStructGetData(DllStructCreate("byte[" & $l & "]", $p), 1)
            Next
            Local $w = _Wsp_NetWrite($iIdx, $bAll, $iBudgetMs)
            Local $eW = @error
            $g_aWsp_Counters[$iIdx][1] += 1
            _Wsp_Complete($iIdx, $pActCtx, $w)
            If $eW Then Return SetError(4, $eW, 0)
            Return SetError(0, $w, 0)

        Case $Wsp_INDICATE_SEND_COMPLETE
            $g_aWsp_Counters[$iIdx][3] += 1
            $g_aWsp_MsgCtx[$iIdx] = $pAppActCtx
            ; The returned token is the one whose send is finishing: its send-ring slot can be
            ; freed, the component no longer needs the buffer. Measure (S4c x86): without this,
            ; a second send armed with the same buffer overwrote the first one still in flight.
            If $pAppActCtx <> 0 Then _Wsp_TxDrop($iIdx, $pAppActCtx)
            If $g_fWspCompleteIndicate Then _Wsp_Complete($iIdx, $pActCtx, 0)
            ; RETRACTATION (measure probe_sendq 2026-11-15, P2/P4/P5): the old rule V26 - "the
            ; component admits ONE armed send at a time and only releases the last frame when a
            ; new WebSocketSend arrives" - is FALSE. Three frames armed one by one leave in
            ; ~88 ms with no second WebSocketSend (P2/P4: written 158 -> 196, sendCompletion 3;
            ; P5 goes through _WS_Flush alone and writes all three). The real defect was OURS:
            ; the receive gate (block $g_aWsp_ParserBusy) starved the receive queue. One armed
            ; send stays OUR invariant ($g_aWspArmed, _Wsp_ArmNext): it frees the buffer slot
            ; only when the component is done reading it.
            _Wsp_ArmNext($iIdx)
            If @error Then $g_aWsp_ArmErr[$iIdx] += 1
            Return SetError(0, $pAppActCtx, 0)

        Case $Wsp_RECEIVE_FROM_NETWORK
            ; The action receives ONLY what is really there. Measure probe_sendq: our receives
            ; arm ONE buffer (n=1 returned); the loop stays so we do not lie if the component
            ; ever asked for several.
            Local $iTotal = 0
            For $i = 1 To $iN
                Local $p = _Wsp_GetBufferPtr($g_tWspBufs, $i, 1)
                Local $l = _Wsp_GetBufferPtr($g_tWspBufs, $i, 2)
                If $l = 0 Then ContinueLoop
                Local $g = 0, $eR = 0
                If _Wsp_HasReadable($iIdx, $iBudgetMs) Then
                    $g = _Wsp_NetRead($iIdx, $p, $l)
                    $eR = @error
                EndIf
                If $eR = 1 Or $eR = 2 Then
                    ; FIN or Winsock error really READ: complete with what we hold, and the
                    ; zero bytes are only returned in THIS case (measure A6: it is the only
                    ; truth the component reads as "the peer closed").
                    Local $x = ($eR = 2 ? @extended : 0)
                    _Wsp_ClearOpenReceive($iIdx)
                    _Wsp_Complete($iIdx, $pActCtx, $iTotal)
                    If $iTotal = 0 Then $g_aWsp_ZeroRecv[$iIdx] += 1
                    Return SetError(5, $x, 0)
                EndIf
                If $g = 0 Then
                    If $iTotal > 0 Then ExitLoop  ; never lose what is already read
                    ; Nothing to hand over: the action STAYS OPEN instead of being completed
                    ; with a lying 0. That is the missing half of the fix - the gate refused to
                    ; ask, and messages already parsed inside the component never came out
                    ; (measure 2 of the $g_aWsp_ParserBusy block).
                    $g_aWsp_RxOpenCtx[$iIdx] = $pActCtx
                    $g_aWsp_RxOpenPtr[$iIdx] = $p
                    $g_aWsp_RxOpenLen[$iIdx] = $l
                    $g_aWsp_ParserBusy[$iIdx] = 1
                    Return SetError(0, 0, 0)
                EndIf
                $iTotal += $g
                If $g < $l Then ExitLoop  ; the DLL will ask for the rest again
            Next
            $g_aWsp_Counters[$iIdx][2] += 1
            _Wsp_Complete($iIdx, $pActCtx, $iTotal)
            Return SetError(0, $iTotal, 0)

        Case $Wsp_INDICATE_RECEIVE_COMPLETE
            $g_aWsp_Counters[$iIdx][4] += 1
            $g_aWsp_MsgType[$iIdx] = $iType
            ; The application token [7] is stored as is, NEVER dereferenced.
            $g_aWsp_MsgCtx[$iIdx] = $pAppActCtx
            ; Copy BEFORE any CompleteAction: that is the only guaranteed lifetime of the
            ; returned pointers.
            Local $bMsg = Binary("0x")
            For $kB = 1 To $iN
                Local $pB = _Wsp_GetBufferPtr($g_tWspBufs, $kB, 1)
                Local $lB = _Wsp_GetBufferPtr($g_tWspBufs, $kB, 2)
                If $lB > 0 Then $bMsg &= DllStructGetData(DllStructCreate("byte[" & $lB & "]", $pB), 1)
            Next
            $g_aWsp_MsgBin[$iIdx] = $bMsg
            $g_aWsp_MsgLen[$iIdx] = BinaryLen($bMsg)
            ; Queue FOR THE CALLER as well: the "last value" slot stays exact, but a pump
            ; turn that delivers two messages must no longer make one disappear (V22).
            If _Wsp_QPush($iIdx, $bMsg, $iType) = 3 Then $g_aWsp_QOverflow[$iIdx] = 1
            If $iType = $Wsp_CLOSE_BUFFER Then
                ; The status is read from the buffer the DLL has just filled (CloseStatus.usStatus
                ; member of the union, offset 8 in x86 / 12 in x64).
                Local $tS = DllStructCreate("ushort", DllStructGetPtr($g_tWspBufs) + $g_iWspOffBufStatus)
                $g_aWsp_CloseCode[$iIdx] = DllStructGetData($tS, 1)
                ; The REASON is what the DLL puts in pbReason/ulReasonLength, so the bytes the loop
                ; above already concatenated: the delivered bytes ARE the reason, not
                ; "status + reason" (measure A8/x86: the server reads "au revoir" without the 2
                ; status bytes).
                $g_aWsp_CloseReason[$iIdx] = $bMsg
                $g_aWsp_CloseFromPeer[$iIdx] = 1
            EndIf
            If $g_fWspCompleteIndicate Then _Wsp_Complete($iIdx, $pActCtx, 0)
            ; Message delivered: no receive action is pending any more (the hand-over at pump
            ; step 1 completed it all).
            _Wsp_ClearOpenReceive($iIdx)
            ; IMMEDIATE RE-ARM: the component returns ONE fragment per WebSocketReceive (measure
            ; A4/A8: 1 MiB = 4 fragments of 65536 then a final MESSAGE; 204800 = 3 fragments +
            ; 8206). Without re-arming, the receive queue never delivers anything again. Complete
            ; the action BEFORE re-arming: that is the order the contract demands.
            If $g_aWsp_RxArmed[$iIdx] = 1 And $g_aWsp_RxSize[$iIdx] > 0 Then
                _Wsp_Receive($iIdx, $g_aWsp_RxSize[$iIdx])
                $g_aWsp_ReArmErr[$iIdx] = @error
            EndIf
            Return SetError(0, $iType, 1)
    EndSwitch
    Return SetError(6, $iAction, 0)
EndFunc   ;==>_Wsp_PumpOnce

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_Complete
; Description ...: Finish an action with WebSocketCompleteAction.
; Syntax ........: _Wsp_Complete($iIdx, $pActCtx, $iBytes)
; Parameters ....: $iIdx                 - slot index
;                  $pActCtx              - pvActionContext returned by GetAction, never our own token
;                  $iBytes               - number of bytes really read or written
; Return values .: Success - 0 = the component accepted it.
;                  Failure - The component's HRESULT, or @error 1 for a dead slot.
; Author ........: Numeric1
; Related .......: _Wsp_PumpOnce, _Wsp_FillOpenReceive
;===============================================================================================================================
Func _Wsp_Complete($iIdx, $pActCtx, $iBytes)
    Local $h = _Wsp_Handle($iIdx)
    If @error Then Return 0
    Local $hDll = _Wsp_Dll($iIdx)
    DllCall($hDll, "none", "WebSocketCompleteAction", "ptr", $h, "ptr", $pActCtx, "dword", $iBytes)
    Return @error
EndFunc   ;==>_Wsp_Complete

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_PumpUntil
; Description ...: Pump until a message is delivered, a send finishes, or both.
; Syntax ........: _Wsp_PumpUntil($iIdx, $fWant, $iBudgetMs[, $iQueue])
; Parameters ....: $iIdx                 - slot index
;                  $fWant                - 1 = a delivered message, 2 = a finished send, 3 = either
;                  $iBudgetMs            - total time allowed
;                  $iQueue               - [optional] queue to serve; name it, QUEUE_ALL starves the send while a receive is armed
; Return values .: Success - Number of actions served, @extended = buffer type when a message arrives.
;                  Failure - @error = the pump's own error (@extended = action), 9 = budget expired (@extended = actions served).
; Author ........: Numeric1
; Related .......: _Wsp_PumpOnce, _Wsp_FlushSend
;===============================================================================================================================
; =============================================================================
; Pump until a given state. $fWant: 1 = a message delivered to the caller, 2 = a send finished,
; 3 = either.
; $iQueue: NAME the queue being served. Measure x86 A2/A4: with QUEUE_ALL and an armed receive,
; GetAction always returns the receive-queue action (which waits for the network) and
; SEND_TO_NETWORK never comes - the send is starved. Sending = pump QUEUE_SEND, receiving = pump
; QUEUE_RECEIVE.
; =============================================================================
Func _Wsp_PumpUntil($iIdx, $fWant, $iBudgetMs, $iQueue = $Wsp_QUEUE_ALL)
    Local $t0 = TimerInit()
    Local $iActions = 0
    Do
        ; Advance the layer 3 arming queue at EVERY turn: a finished frame must be replaced
        ; without the caller interfering. (The old attribution "measure spike7 N5: without
        ; re-arming the next one slept 6 s" is TAKEN BACK: those 6 s came from the receive gate,
        ; not from the arming - see the $g_aWsp_ParserBusy block.)
        _Wsp_ArmNext($iIdx)
        Local $iAction = -1, $iType = -1
        Local $r = _Wsp_PumpOnce($iIdx, $iBudgetMs, $iAction, $iType, $iQueue)
        Local $e = @error
        If $e <> 0 Then Return SetError($e, $iAction, $iActions)
        $iActions += 1
        If $r = 1 And ($fWant = 1 Or $fWant = 3) Then Return SetError(0, $iType, $iActions)
        If $iAction = $Wsp_INDICATE_SEND_COMPLETE And ($fWant = 2 Or $fWant = 3) Then _
                Return SetError(0, $iActions, $iActions)
        If $iAction = $Wsp_NO_ACTION And $fWant <> 0 Then _
                Sleep(1)  ; avoids a full busypoll while the pair is thinking
    Until TimerDiff($t0) > $iBudgetMs
    Return SetError(9, $iActions, $iActions)
EndFunc   ;==>_Wsp_PumpUntil

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_FlushSend
; Description ...: Drain the send queue: arm frames one after the other until every armed frame is finished.
; Syntax ........: _Wsp_FlushSend($iIdx, $iBudgetMs)
; Parameters ....: $iIdx                 - slot index
;                  $iBudgetMs            - total time allowed for the drain
; Return values .: Success - Number of finished frames, @error 0 = queue empty.
;                  Failure - @error 1 = budget expired with n frames still queued in @extended, 2 = the peer closed, 3 = arming failure (step in @extended).
; Author ........: Numeric1
; Remarks .......: "WebSocketSend returned S_OK" does not mean the frame left (measure A6). Stopping at the first completion is wrong (A4: only 3 of 19 send actions produced a completion) and trusting two NO_ACTION is wrong too (spike7 N5: the queue idles between frames for seconds). A frame counts as finished when its completion came back, or after 4 idle turns following at least one served action for it.
; Related .......: _Wsp_ArmNext, _Wsp_SendClose, _Wsp_Pump
;===============================================================================================================================
; =============================================================================
; Drain the send queue. RULE (measure A6): "WebSocketSend returned S_OK" does not mean "the frame
; left". Send ARMS the frame inside the component; it only leaves the socket when the pump has
; served SEND_TO_NETWORK. And the pump must name QUEUE_SEND: with QUEUE_ALL and an armed receive the
; send queue never returns anything, so a close "sent" without a drain = TCP FIN instead of frame
; 1000.
; STOPPING AT THE FIRST INDICATE_SEND_COMPLETE IS WRONG (measure A4): over 19 send actions of a
; 1 MiB message, only 3 completions came out, so a "fresh" completion can designate the PREVIOUS
; frame.
; TRUSTING "NO_ACTION two turns in a row" IS WRONG TOO (measure spike7 N5): with several sends armed
; before the first pump, the queue returns NO_ACTION BETWEEN frames, then the next frame only leaves
; 6 s later.
; Layer 3 therefore hands only ONE send at a time to the component (see _Wsp_ArmNext) and this
; function is the queue's engine: it arms, serves the QUEUE_SEND queue, and arms the next one only
; when the current frame is DONE. A frame is done when its completion came back ($g_aWspArmed
; released) or, as a measured safety net A4 (completions can stay silent while the frame IS written),
; after 4 idle turns following at least one served action for that frame.
; Returns the number of finished frames. @error 0 = queue empty, 1 = budget expired with n frames
; left in @extended, 2 = the peer closed, 3 = arming failure, step in @extended.
; =============================================================================
Func _Wsp_FlushSend($iIdx, $iBudgetMs)
    Local $t0 = TimerInit()
    Local $iActions = 0, $iIdle = 0, $iDone = 0
    Local $iInFlight = 0, $iActAtArm = 0
    Do
        If $iInFlight = 0 Then
            ; CONDITIONAL arming: very often the frame was already armed by the _Wsp_Send call
            ; that found the machine free. _Wsp_ArmNext returns 0 in THAT case too, so it is the
            ; $g_aWspArmed state that tells the truth, never the returned value (measure spike7
            ; N5 rerun: trusting the returned value left the drain with 0 confirmed frame while
            ; all three had gone out).
            _Wsp_ArmNext($iIdx)
            Local $eA = @error
            If $eA Then Return SetError(3, $eA, $iDone)
            $iInFlight = $g_aWspArmed[$iIdx]
            If $iInFlight = 0 Then ExitLoop  ; no frame left to send
            $iIdle = 0
            $iActAtArm = $iActions
        EndIf

        Local $iAction = -1, $iType = -1
        Local $r = _Wsp_PumpOnce($iIdx, 200, $iAction, $iType, $Wsp_QUEUE_SEND)
        Local $e = @error
        If $e = 5 Then Return SetError(2, 0, $iDone)  ; the peer closed before our drain
        If $e <> 0 And $e <> 6 Then Return SetError(3, $e, $iDone)
        If $iAction = $Wsp_NO_ACTION Then
            $iIdle += 1
        ElseIf $e = 0 Then
            $iIdle = 0
            $iActions += 1
        EndIf

        If $g_aWspArmed[$iIdx] <> $iInFlight Then
            $iDone += 1
            $iInFlight = 0
        ElseIf $iIdle >= 4 And $iActions > $iActAtArm Then
            _Wsp_TxDrop($iIdx, $iInFlight)
            $iDone += 1
            $iInFlight = 0
        EndIf
    Until TimerDiff($t0) > $iBudgetMs

    Local $iLeft = _Wsp_OqCount($iIdx)
    If $iLeft = 0 Then Return SetError(0, 0, $iDone)
    Return SetError(1, $iLeft, $iDone)
EndFunc   ;==>_Wsp_FlushSend

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_ReplyCloseIfNeeded
; Description ...: Answer a close frame received from the peer (RFC 6455 5.5.1).
; Syntax ........: _Wsp_ReplyCloseIfNeeded($iIdx)
; Parameters ....: $iIdx                 - slot index
; Return values .: Success - 2 = the answer was delivered, $g_aWsp_CloseReplyErr = 0.
;                  Failure - @error 0 = nothing to do, 1 = the answer failed (the _Wsp_SendClose contract in @extended).
; Author ........: Numeric1
; Remarks .......: Never call this from _Wsp_PumpOnce: the answer goes through _Wsp_FlushSend which calls the pump back, and the shared pump structures would be wiped mid-read (the spike 1 segfault). Call it from _Wsp_Pump or _Wsp_WaitMessage, outside the pump. Codes 1005/1006 and out-of-range values are answered with 1000.
; Related .......: _Wsp_SendClose, _Wsp_Pump
;===============================================================================================================================
; =============================================================================
; Answer a close frame received from the peer (RFC 6455 5.5.1).
; WHERE TO CALL IT: never from _Wsp_PumpOnce. The answer goes through _Wsp_FlushSend, which calls
; _Wsp_PumpOnce back: the pump structures are global and shared, a reentry would wipe the buffers
; being read (that is exactly the defect that produced the spike 1 segfault). So it is called as soon
; as we are OUT of the pump: _Wsp_WaitMessage and _Wsp_Pump.
; The code sent back is the one received, except 1005/1006 (never put on the wire) and out of range:
; then we return 1000. @error = 0 nothing to do, 1 answer failed (reason in @extended, the
; _Wsp_SendClose contract), 2 answer delivered.
; =============================================================================
Func _Wsp_ReplyCloseIfNeeded($iIdx)
    If $g_fWspAutoCloseReply <> 1 Then Return SetError(0, 0, 0)
    If $g_aWsp_CloseFromPeer[$iIdx] <> 1 Then Return SetError(0, 0, 0)
    If $g_aWsp_CloseSent[$iIdx] = 1 Then Return SetError(0, 0, 0)
    Local $iCode = Number($g_aWsp_CloseCode[$iIdx])
    If $iCode = 1005 Or $iCode = 1006 Or $iCode < 1000 Or $iCode > 4999 Then $iCode = 1000
    _Wsp_SendClose($iIdx, $iCode, "")
    Local $e = @error
    $g_aWsp_CloseReplyErr[$iIdx] = $e
    Return SetError($e = 0 ? 2 : 1, $e, $iCode)
EndFunc   ;==>_Wsp_ReplyCloseIfNeeded

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_Pump
; Description ...: The caller's pump line: serve both queues, separately, within one budget.
; Syntax ........: _Wsp_Pump($iIdx, $iBudgetMs)
; Parameters ....: $iIdx                 - slot index
;                  $iBudgetMs            - total time this turn may take
; Return values .: Success - Number of messages delivered during this turn (@error 0 = normal).
;                  Failure - @error 1 = the peer closed the socket (FIN), 2 = named failure in @extended, 3 = delivery queue full, cumulative loss count in @extended.
; Author ........: Numeric1
; Remarks .......: QUEUE_RECEIVE then QUEUE_SEND, never QUEUE_ALL (measure S3). While the caller writes "While 1 / _Wsp_Pump($i, 20) / WEnd" it receives sends, receives, fragments, pongs and close - no event loop of its own.
; Related .......: _Wsp_PumpOnce, _Wsp_FlushSend, _Wsp_TakeMessage
;===============================================================================================================================
; =============================================================================
; The caller's pump LINE. A network UDF must never force the caller to write an event loop: here the
; caller writes
;     While 1
;         _Wsp_Pump($iIdx, 20)
;     WEnd
; and receives sends, receives, fragments, pongs and close. The two queues are served SEPARATELY
; (QUEUE_RECEIVE then QUEUE_SEND) because QUEUE_ALL starves the send as soon as a receive is armed
; (measure S3).
; Return = number of messages delivered during this turn. @error 0 = normal, 1 = the peer closed the
; socket (FIN), 2 = named error in @extended, 3 = DELIVERY QUEUE FULL: at least one message was
; refused this turn, the cumulative loss count is in @extended (see _Wsp_QPush).
; =============================================================================
Func _Wsp_Pump($iIdx, $iBudgetMs)
    Local $t0 = TimerInit()
    Local $iDelivered = 0
    Do
        Local $iAction = -1, $iType = -1
        Local $r = _Wsp_PumpOnce($iIdx, 50, $iAction, $iType, $Wsp_QUEUE_RECEIVE)
        Local $e = @error
        If $e = 5 Then
            _Wsp_ReplyCloseIfNeeded($iIdx)
            Return SetError(1, 0, $iDelivered)
        ElseIf $e <> 0 And $e <> 6 Then
            Return SetError(2, $e, $iDelivered)
        EndIf
        $iDelivered += $r
        If $r = 1 Then
            If $iType = $Wsp_CLOSE_BUFFER Then $g_aWsp_PendingClose[$iIdx] = 1
            _Wsp_ReplyCloseIfNeeded($iIdx)
        EndIf
        ; The send queue is served right after: a close answer or a message armed during this
        ; turn leaves within the same budget.
        _Wsp_ArmNext($iIdx)  ; the frame finished on the previous turn must be replaced
        Local $iA2 = -1, $iT2 = -1
        Local $r2 = _Wsp_PumpOnce($iIdx, 50, $iA2, $iT2, $Wsp_QUEUE_SEND)
        Local $e2 = @error
        If $e2 <> 0 And $e2 <> 5 And $e2 <> 6 Then Return SetError(2, $e2, $iDelivered)
    Until TimerDiff($t0) > $iBudgetMs
    ; Full queue = delivery REFUSED during this turn. Signalled here, never swallowed.
    If $g_aWsp_QOverflow[$iIdx] = 1 Then
        $g_aWsp_QOverflow[$iIdx] = 0
        Return SetError(3, $g_aWspQDropped[$iIdx], $iDelivered)
    EndIf
    Return SetError(0, 0, $iDelivered)
EndFunc   ;==>_Wsp_Pump

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_Receive
; Description ...: Arm the receive of an application message with WebSocketReceive.
; Syntax ........: _Wsp_Receive($iIdx, $iMax)
; Parameters ....: $iIdx                 - slot index
;                  $iMax                 - maximum message size to accept
; Return values .: Success - 1.
;                  Failure - @error 1 = dead slot, 2 = DllCall failure, 3 = component refusal (@extended = HRESULT), 4 = allocation failure, 6 = a receive action is still open (the pump must run _Wsp_PumpOnce first).
; Author ........: Numeric1
; Remarks .......: WebSocketReceive takes 3 arguments and no buffer type (the type comes back from GetAction). The armed buffer lives in the slot table, not on the stack: a local would be destroyed while the DLL is writing into it. The recipient is allocated once per size because a 1 MiB message arrives as 65536-byte fragments, one per call (measures A4/A8).
; Related .......: _Wsp_PumpOnce, _Wsp_Send, _Wsp_WaitMessage
;===============================================================================================================================
; =============================================================================
; Arm the receive of an application message.
; CONTRACT WARNING (header): WebSocketReceive(h, pBuffer, Context) = 3 arguments, NO buffer type on
; input. It is WebSocketSend that takes one. The type suffered comes back through
; WebSocketGetAction (pBufferType).
; The WEB_SOCKET_BUFFER and its recipient must stay ALIVE for the whole pump: kept in the slot
; table, a local variable would be destroyed with the stack while the DLL is writing into it (that
; is exactly the spike 1 segfault).
;
; The buffer is allocated ONCE per requested size. Measure A4: a 1 MiB message is returned in
; 65536-byte fragments, so this function is called once per fragment; recreating it per fragment
; would cost a multi-megabyte allocation every pump turn.
; =============================================================================
Func _Wsp_Receive($iIdx, $iMax)
    Local $h = _Wsp_Handle($iIdx)
    If @error Then Return SetError(1, @error, 0)
    Local $hDll = _Wsp_Dll($iIdx)

    ; ONLY ONE WebSocketReceive at a time without a hand-over: while a receive action is open
    ; (measures P7/P8: it stays open until the peer supplies what fills it), re-arming would lose
    ; the open pvActionContext, hence an action never completed. @error 6 = the pump must go
    ; through _Wsp_PumpOnce first.
    If $g_aWsp_RxOpenCtx[$iIdx] <> 0 Then Return SetError(6, $g_aWsp_RxOpenLen[$iIdx], 0)

    If Number($g_aWsp_RxSize[$iIdx]) <> $iMax Then
        $g_aWsp_RxData[$iIdx] = DllStructCreate("byte[" & $iMax & "]")
        If @error Then Return SetError(4, 0, 0)
        $g_aWsp_RxStruct[$iIdx] = DllStructCreate("ptr;dword;ushort")
        DllStructSetData($g_aWsp_RxStruct[$iIdx], 1, DllStructGetPtr($g_aWsp_RxData[$iIdx]))
        DllStructSetData($g_aWsp_RxStruct[$iIdx], 2, $iMax)
        $g_aWsp_RxSize[$iIdx] = $iMax
    EndIf
    $g_aWsp_RxArmed[$iIdx] = 1

    Local $aCall = DllCall($hDll, "int", "WebSocketReceive", "ptr", $h, _
            "ptr", DllStructGetPtr($g_aWsp_RxStruct[$iIdx]), "ptr", $iIdx + 1)
    Local $eCall = @error
    If $eCall Then Return SetError(2, $eCall, 0)
    If $aCall[0] < 0 Then Return SetError(3, $aCall[0], 0)
    Return 1
EndFunc   ;==>_Wsp_Receive

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_Send
; Description ...: Queue an application payload (UTF-8 or binary) and arm it at once when nothing is in flight.
; Syntax ........: _Wsp_Send($iIdx, $bData[, $iType])
; Parameters ....: $iIdx                 - slot index
;                  $bData                - payload bytes
;                  $iType                - [optional] $Wsp_BINARY_MESSAGE or $Wsp_UTF8_MESSAGE
; Return values .: Success - 1, @extended = the frame token (identity for the caller, armed or not).
;                  Failure - @error 1 = dead slot, 4 = allocation failure, 5 = send ring full (64 in flight), 6 = arming queue full, otherwise the arming error.
; Author ........: Numeric1
; Remarks .......: This only ARMS the frame: the bytes leave when the SEND queue is served by _Wsp_FlushSend, _Wsp_Request or _Wsp_Pump (rule V21).
; Related .......: _Wsp_FlushSend, _Wsp_SendText, _Wsp_ArmNext
;===============================================================================================================================
Func _Wsp_Send($iIdx, $bData, $iType = $Wsp_BINARY_MESSAGE)
    Local $h = _Wsp_Handle($iIdx)
    If @error Then Return SetError(1, @error, 0)

    Local $iLen = BinaryLen($bData)
    Local $tData = 0
    If $iLen > 0 Then
        $tData = DllStructCreate("byte[" & $iLen & "]")
        DllStructSetData($tData, 1, $bData)
        If @error Then Return SetError(4, 0, 0)
    EndIf
    Local $tBuf = DllStructCreate("ptr;dword;ushort")
    DllStructSetData($tBuf, 1, ($iLen > 0 ? DllStructGetPtr($tData) : 0))
    DllStructSetData($tBuf, 2, $iLen)

    Local $iTok = _Wsp_TxKeep($iIdx, $tBuf, $tData, $iType)
    If $iTok = 0 Then Return SetError(5, $g_aWspTxCount[$iIdx], 0)  ; send ring full

    If _Wsp_OqPush($iIdx, $iTok) = 0 Then
        _Wsp_TxDrop($iIdx, $iTok)
        Return SetError(6, $g_iWspOqCap, 0)  ; arming queue full
    EndIf
    ; IMMEDIATE arming when nothing is in flight, otherwise the layer 3 queue handles it on the
    ; next pump turn (measure spike7 N5: two frames left, the third waited 6 s). @extended returns
    ; the token ALWAYS, armed or not: it is the frame's identity for the caller.
    _Wsp_ArmNext($iIdx)
    Local $e = @error
    If $e Then Return SetError($e, 0, 0)
    Return SetError(0, $iTok, 1)
EndFunc   ;==>_Wsp_Send

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_SendText
; Description ...: Send a string as a UTF-8 application message.
; Syntax ........: _Wsp_SendText($iIdx, $sText)
; Parameters ....: $iIdx                 - slot index
;                  $sText                - text to encode in UTF-8
; Return values .: Success - 1, @extended = frame token.
;                  Failure - Same contract as _Wsp_Send.
; Author ........: Numeric1
; Remarks .......: Delegation writes SetError(@error, @extended, $v) explicitly because "Return OtherFunc()" resets both to 0 (measured, t_propagate.au3).
; Related .......: _Wsp_Send
;===============================================================================================================================
Func _Wsp_SendText($iIdx, $sText)
    Local $v = _Wsp_Send($iIdx, StringToBinary($sText, 1), $Wsp_UTF8_MESSAGE)
    Return SetError(@error, @extended, $v)
EndFunc   ;==>_Wsp_SendText

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_SendClose
; Description ...: Send a close frame with status and reason, then drain the queue so the frame really leaves.
; Syntax ........: _Wsp_SendClose($iIdx, $iStatus[, $sReason[, $iFlushMs]])
; Parameters ....: $iIdx                 - slot index
;                  $iStatus              - RFC 6455 status code (1000, 1001, ...)
;                  $sReason              - [optional] UTF-8 reason, truncated to 123 bytes
;                  $iFlushMs             - [optional] drain budget, 1500 ms
; Return values .: Success - 1 = the close frame left the socket.
;                  Failure - @error 1 = dead slot, 4 = frame armed but never drained (@extended = drain error), 5 = send ring full, 6 = arming queue full.
; Author ........: Numeric1
; Remarks .......: We never write the two status bytes ourselves: the component composes the frame from CloseStatus (websocket.h union). The reason length counts BYTES, not characters (WEB_SOCKET_MAX_CLOSE_REASON = 123). The close goes through the same queue as the data (measure spike7 N5).
; Related .......: _Wsp_ReplyCloseIfNeeded, _Wsp_FlushSend, _Wsp_Close
;===============================================================================================================================
; Clean close. The WEB_SOCKET_BUFFER union has a CloseStatus member (websocket.h): pbReason,
; ulReasonLength, usStatus. WE do not write the two status bytes on the wire: we fill the member and
; the component builds the frame. The reason is UTF-8 (RFC 6455) and its length counts BYTES, not
; characters (WEB_SOCKET_MAX_CLOSE_REASON = 123). The drain is INCLUDED: a caller writing
; "_Wsp_SendClose" must get a CLEAN close, not a TCP FIN (@error 4 = frame armed but never sent).
Func _Wsp_SendClose($iIdx, $iStatus, $sReason = "", $iFlushMs = 1500)
    Local $h = _Wsp_Handle($iIdx)
    If @error Then Return SetError(1, @error, 0)
    Local $hDll = _Wsp_Dll($iIdx)

    Local $bReason = StringToBinary($sReason, 8)
    If BinaryLen($bReason) > $Wsp_MAX_CLOSE_REASON Then _
            $bReason = BinaryMid($bReason, 1, $Wsp_MAX_CLOSE_REASON)
    Local $iLen = BinaryLen($bReason)
    Local $tReason = 0

    If $iLen > 0 Then
        $tReason = DllStructCreate("byte[" & $iLen & "]")
        DllStructSetData($tReason, 1, $bReason)
        If @error Then Return SetError(4, 0, 0)
    EndIf
    Local $tBuf = DllStructCreate("ptr;dword;ushort")
    DllStructSetData($tBuf, 1, ($iLen > 0 ? DllStructGetPtr($tReason) : 0))
    DllStructSetData($tBuf, 2, $iLen)
    DllStructSetData($tBuf, 3, $iStatus)

    Local $iTok = _Wsp_TxKeep($iIdx, $tBuf, $tReason, $Wsp_CLOSE_BUFFER)
    If $iTok = 0 Then Return SetError(5, $g_aWspTxCount[$iIdx], 0)

    If _Wsp_OqPush($iIdx, $iTok) = 0 Then
        _Wsp_TxDrop($iIdx, $iTok)
        Return SetError(6, $g_iWspOqCap, 0)
    EndIf
    ; The close frame goes through the SAME queue as the data (measure spike7 N5): a close armed
    ; while data is in flight would wait 6 s inside the component, which looks like a failed clean
    ; close.
    _Wsp_ArmNext($iIdx)
    Local $eA = @error
    If $eA Then Return SetError($eA, 0, 0)
    $g_aWsp_CloseSent[$iIdx] = 1
    $g_aWsp_CloseReplyErr[$iIdx] = 0
    _Wsp_FlushSend($iIdx, $iFlushMs)
    Local $eF = @error
    If $eF Then Return SetError(4, $eF, 0)  ; 4 = armed but not drained, reason in @extended
    Return 1
EndFunc   ;==>_Wsp_SendClose

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_Message
; Description ...: Last assembled payload handed to the caller (the "last value" view).
; Syntax ........: _Wsp_Message($iIdx)
; Parameters ....: $iIdx                 - slot index
; Return values .: Success - Binary, or empty when nothing is armed or delivered.
; Author ........: Numeric1
; Remarks .......: Prefer _Wsp_TakeMessage: a pump turn can deliver several messages and this slot only holds the last one (V22).
; Related .......: _Wsp_TakeMessage
;===============================================================================================================================
Func _Wsp_Message($iIdx)
    If $g_aWsp_RxArmed[$iIdx] <> 1 Then Return Binary("0x")
    Return $g_aWsp_MsgBin[$iIdx]
EndFunc   ;==>_Wsp_Message

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_Close
; Description ...: Delete the websocket.dll handle of a slot and release its socket reference.
; Syntax ........: _Wsp_Close($iIdx)
; Parameters ....: $iIdx                 - slot index
; Return values .: Success - 1.
;                  Failure - The WebSocketDeleteHandle HRESULT in @error when the DLL complained.
; Author ........: Numeric1
; Remarks .......: The socket number is reset to zero after the close, otherwise the next connection on this slot - in wss:// where layer 2 owns the socket - would try to close a socket that no longer belongs to it.
; Related .......: _Wsp_Create, _WS_CloseHandle
;===============================================================================================================================
Func _Wsp_Close($iIdx)
    Local $h = _Wsp_Handle($iIdx)
    If @error Then Return 1
    Local $hDll = _Wsp_Dll($iIdx)
    DllCall($hDll, "none", "WebSocketDeleteHandle", "ptr", $h)
    Local $e = @error
    ; The socket is reset to zero AFTER the close: otherwise the slot keeps a recycled number and
    ; the NEXT connection on this slot (in wss:// for instance, where layer 2 owns the socket) would
    ; believe it must close a socket that no longer belongs to it.
    Local $hSock = $g_aWsp_Socket[$iIdx]
    $g_aWsp_Socket[$iIdx] = 0
    If $hSock <> 0 And Not _Wsk_IsInvalid($hSock) Then _Wsk_Close($hSock)
    $g_aWsp_Handle[$iIdx] = ""
    $g_aWsp_State[$iIdx] = $g_iWspFree
    $g_aWsp_RxArmed[$iIdx] = 0
    $g_aWsp_RxSize[$iIdx] = 0
    $g_aWsp_ReArmErr[$iIdx] = 0
    $g_aWsp_MsgBin[$iIdx] = Binary("0x")
    _Wsp_QReset($iIdx)
    $g_aWsp_CloseReason[$iIdx] = Binary("0x")
    $g_aWsp_CloseFromPeer[$iIdx] = 0
    $g_aWsp_CloseSent[$iIdx] = 0
    $g_aWsp_CloseReplyErr[$iIdx] = 0
    $g_aWsp_PendingClose[$iIdx] = 0
    $g_aWsp_LastSmallWrite[$iIdx] = Binary("0x")
    $g_aWsp_LastSmallRead[$iIdx] = Binary("0x")
    $g_aWsp_TailRead[$iIdx] = Binary("0x")
    $g_aWsp_LastWriteDesc[$iIdx] = ""
    $g_aWsp_PrevWriteDesc[$iIdx] = ""
    $g_aWsp_BytesRead[$iIdx] = 0
    $g_aWsp_BytesWritten[$iIdx] = 0
    $g_aWsp_ZeroRecv[$iIdx] = 0
    _Wsp_ClearOpenReceive($iIdx)
    $g_aWsp_Gated[$iIdx] = 0
    $g_aWsp_TlsOn[$iIdx] = 0
    $g_aWsp_TlsSlot[$iIdx] = -1
    DllClose($hDll)
    Return SetError($e, 0, 1)
EndFunc   ;==>_Wsp_Close

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_WireTrace
; Description ...: One-line dump of what really reached the wire for a slot.
; Syntax ........: _Wsp_WireTrace($iIdx)
; Parameters ....: $iIdx                 - slot index
; Return values .: Success - String with the last write descriptions, the short read/write traces, the sliding 48-byte read tail and the TCP totals.
; Author ........: Numeric1
; Remarks .......: The only way to tell, when a peer announces a FIN instead of a frame, whether the bytes ever left or arrived.
; Related .......: _Wsp_Counters, _Wsp_NoteRead
;===============================================================================================================================
Func _Wsp_WireTrace($iIdx)
    Return "writes=[" & $g_aWsp_PrevWriteDesc[$iIdx] & "][" & $g_aWsp_LastWriteDesc[$iIdx] & "]" & _
            " last48read=" & $g_aWsp_TailRead[$iIdx] & _
            " bytesRead=" & $g_aWsp_BytesRead[$iIdx] & " bytesWritten=" & $g_aWsp_BytesWritten[$iIdx] & _
            " pendingArms=" & $g_aWspOqCount[$iIdx] & " armRefused=" & $g_aWsp_ArmErr[$iIdx] & _
            " gates=" & $g_aWsp_Gated[$iIdx] & " zeroRecv=" & $g_aWsp_ZeroRecv[$iIdx] & _
            " openAction=" & ($g_aWsp_RxOpenCtx[$iIdx] <> 0 ? 1 : 0) & _
            " roomLeft=" & $g_aWsp_RxOpenLen[$iIdx]
EndFunc   ;==>_Wsp_WireTrace

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_Counters
; Description ...: Pump statistics of a slot as a slash-separated string.
; Syntax ........: _Wsp_Counters($iIdx)
; Parameters ....: $iIdx                 - slot index
; Return values .: Success - "turns/sendIO/recvIO/sendDone/recvDone/maxBuffers[/gated/zeroRecv]".
; Author ........: Numeric1
; Related .......: _Wsp_WireTrace
;===============================================================================================================================
Func _Wsp_Counters($iIdx)
    Return $g_aWsp_Counters[$iIdx][0] & "/" & $g_aWsp_Counters[$iIdx][1] & "/" & $g_aWsp_Counters[$iIdx][2] & _
            "/" & $g_aWsp_Counters[$iIdx][3] & "/" & $g_aWsp_Counters[$iIdx][4] & "/" & $g_aWsp_Counters[$iIdx][5]
EndFunc   ;==>_Wsp_Counters

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_ReadHead
; Description ...: Read an HTTP head up to CRLFCRLF, queueing whatever follows it.
; Syntax ........: _Wsp_ReadHead($iIdx, $iBudgetMs)
; Parameters ....: $iIdx                 - slot index
;                  $iBudgetMs            - time allowed to receive the whole head
; Return values .: Success - The head text.
;                  Failure - "", @error 1 = transport failure (@extended = step), 2 = budget expired with the received byte count in @extended, 3 = the peer closed the transport while the head was still incomplete (bytes received in @extended). Measured: a plain ws:// client that reads a FIN instead of the 101 must not be reported as a timeout.
; Author ........: Numeric1
; Remarks .......: The bytes after the head already belong to the WebSocket stream: they are queued (measure: dropping them loses the first frame). On the wss:// server side the head arrives in the clear because layer 2 decrypts, and the byte counters are fed so the "arrived in the clear" witness can be compared with layer 2's own totals.
; Related .......: _Wsp_BeginServer, _Wsp_EndClient
;===============================================================================================================================
; =============================================================================
; High-level functions: the "caller API" half of the UDF. The spike must stay short to read, and if
; these lines are wrong the spike sees it immediately.
; =============================================================================

; Read an HTTP head (the 101's, or the request's on the server side) up to CRLFCRLF. The bytes that
; follow ALREADY belong to the WebSocket stream: they are queued instead of dropped, otherwise the
; first frame is lost.
Func _Wsp_ReadHead($iIdx, $iBudgetMs)
    Local $b = Binary("0x")
    Local $t1 = TimerInit()
    While TimerDiff($t1) < $iBudgetMs
        Local $c, $e
        If $g_aWsp_TlsOn[$iIdx] Then
            ; The 101 (or the request on the server side) already arrives IN THE CLEAR: it is
            ; layer 2 that reads the network and decrypts.
            _Wsp_XptWait($iIdx, 20)
            $c = _Wsp_XptRead($iIdx, 4096)
            $e = @error
            If $e = 1 Then ExitLoop
            If $e = 2 Then Return SetError(1, @extended, "")
        Else
            $c = _Wsk_Recv($g_aWsp_Socket[$iIdx], 4096)
            $e = @error
            If $e = 4 Then
                _Wsk_Poll($g_aWsp_Socket[$iIdx], $Wsk_POLLRDNORM, 20)
                ContinueLoop
            EndIf
            If $e = 6 Then Return SetError(3, BinaryLen($b), "") ; clean FIN, head incomplete
            If $e <> 0 Then Return SetError(1, $e, "")
        EndIf
        If BinaryLen($c) > 0 Then
            ; The layer 3 counter must count the head bytes TOO: without this call, bytesRead stayed
            ; empty on a wss server and the "the request arrived in the clear" witness could no
            ; longer be opposed to the bytes layer 2 counted on the wire.
            _Wsp_NoteRead($iIdx, $c)
            $b &= $c
        EndIf
        Local $s = BinaryToString($b, 1)
        Local $p = StringInStr($s, @CRLF & @CRLF)
        If $p > 0 Then
            Local $iApr = $p + 4
            If $iApr <= BinaryLen($b) Then _Wsp_QueueBytes($iIdx, BinaryMid($b, $iApr))
            Return StringLeft($s, $p + 2)
        EndIf
    WEnd
    Return SetError(2, BinaryLen($b), "")
EndFunc   ;==>_Wsp_ReadHead

Global $g_aWsp_RspBlock[$g_iWspSlots]  ; keeps our header arrays alive
Global $g_aWsp_LastRequest[$g_iWspSlots]
Global $g_aWsp_LastHead[$g_iWspSlots]

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_Connect
; Description ...: Full client opening on layer 3 alone: TCP (layer 1) plus the HTTP upgrade.
; Syntax ........: _Wsp_Connect($sHost, $iPort, $sPath, $iRx, $iTx, $iMaxMsg, $iBudgetMs)
; Parameters ....: $sHost                - host or address to reach
;                  $iPort                - TCP port
;                  $sPath                - request target
;                  $iRx                  - receive buffer size for the component
;                  $iTx                  - send buffer size for the component
;                  $iMaxMsg              - maximum message size to arm
;                  $iBudgetMs            - total time allowed
; Return values .: Success - Slot index, @extended = number of headers returned by the DLL.
;                  Failure - 1, @error 1 = resolution, 2 = connect, 3 = socket, 4..10 = named upgrade steps with the underlying code in @extended.
; Author ........: Numeric1
; Remarks .......: Convenience entry for the ws:// spike; the shipping API is _WS_Connect in layer 4, which adds TLS, the address-list walk and the named errors.
; Related .......: _Wsp_BeginClient, _Wsp_EndClient, _WS_Connect
;===============================================================================================================================
; Full client-side opening: TCP (layer 1) + upgrade (layer 3).
Func _Wsp_Connect($sHost, $iPort, $sPath, $iRx, $iTx, $iMaxMsg, $iBudgetMs)
    Local $iIdx = _Wsp_Create(0, $iRx, $iTx)
    If @error Then Return SetError(1, @error, -1)

    Local $hSock = _Wsk_Socket()
    If @error Then Return SetError(2, @error, -1)
    _Wsk_NonBlocking($hSock)
    If @error Then Return SetError(3, @error, -1)
    $g_aWsp_Socket[$iIdx] = $hSock

    _Wsk_Connect($hSock, $sHost, $iPort)
    Local $iStep = 4
    If @error = 3 Then
        _Wsk_ConnectFinish($hSock, $iBudgetMs)
        If @error Then Return SetError($iStep, @extended, -1)
    ElseIf @error <> 0 Then
        Return SetError(5, @extended, -1)
    EndIf

    Local $sReq = ""
    Local $nT = _Wsp_BeginClient($iIdx, $sHost, $iPort, $sPath, $sReq)
    If @error Then Return SetError(6, @extended, -1)
    $g_aWsp_LastRequest[$iIdx] = $sReq

    _Wsp_NetWrite($iIdx, StringToBinary($sReq, 1), $iBudgetMs)
    If @error Then Return SetError(7, @extended, -1)

    Local $sHead = _Wsp_ReadHead($iIdx, $iBudgetMs)
    If @error Or $sHead = "" Then Return SetError(8, @error, -1)
    $g_aWsp_LastHead[$iIdx] = $sHead

    Local $tBlock = _Wsp_EndClient($iIdx, $sHead)
    If @error Then Return SetError(9, @extended, -1)
    $g_aWsp_RspBlock[$iIdx] = $tBlock

    _Wsp_Receive($iIdx, $iMaxMsg)
    If @error Then Return SetError(10, @extended, -1)
    Return SetError(0, $nT, $iIdx)
EndFunc   ;==>_Wsp_Connect

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_Request
; Description ...: Send a payload and pump the queues until an answer arrives or the timeout expires.
; Syntax ........: _Wsp_Request($iIdx, $bData, $iTimeoutMs[, $iType])
; Parameters ....: $iIdx                 - slot index
;                  $bData                - payload to send
;                  $iTimeoutMs           - total budget for send + answer
;                  $iType                - [optional] buffer type of the payload
; Return values .: Success - 1 when an answer was delivered.
;                  Failure - @error 1 = send failed (@extended = step), 2 = pump failure (@extended = action), 3 = timeout with the bytes already written in @extended.
; Author ........: Numeric1
; Remarks .......: Serves the SEND queue first, which is what makes "send then wait" work at all (rule V21, measure S4b).
; Related .......: _Wsp_Send, _Wsp_WaitMessage
;===============================================================================================================================
; Send and wait until the component confirms the end of the send.
Func _Wsp_Request($iIdx, $bData, $iTimeoutMs, $iType = $Wsp_BINARY_MESSAGE)
    _Wsp_Send($iIdx, $bData, $iType)
    If @error Then Return SetError(1, @extended, 0)
    Local $r = _Wsp_PumpUntil($iIdx, 2, $iTimeoutMs, $Wsp_QUEUE_SEND)
    Local $e = @error
    If $e And $e <> 9 Then Return SetError(2, $e, $r)
    Return SetError($e = 9 ? 3 : 0, $r, $r)
EndFunc   ;==>_Wsp_Request

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_WaitMessage
; Description ...: Wait for one complete application message, re-arming and assembling fragments as needed.
; Syntax ........: _Wsp_WaitMessage($iIdx, $iTimeoutMs)
; Parameters ....: $iIdx                 - slot index
;                  $iTimeoutMs           - total time allowed
; Return values .: Success - The message binary, @extended = its type; a pong seen during assembly only increments $g_aWsp_Pongs.
;                  Failure - @error 1 = timeout, returning the partial assembly in the binary so the loss is visible; 2 = named pump failure in @extended; 3 = the peer closed (@extended = close code, $g_aWsp_CloseReason = reason); 4 = transport closed mid-message (@extended = action); 5 = delivery queue full, losses in @extended.
; Author ........: Numeric1
; Remarks .......: One call = one complete message (measures A4/A8: a 1 MiB message arrives as 65536-byte BINARY_FRAGMENT pieces then a final BINARY_MESSAGE). A close is answered before being returned, so a peer that sent its frame sees a clean end instead of an error (measure A8/x64).
; Related .......: _Wsp_Receive, _Wsp_PumpOnce, _Wsp_ReplyCloseIfNeeded
;===============================================================================================================================
; Wait for an application message (the buffer must have been armed).
;
; ONE call = ONE complete message. Measured rule (server A4/A8): the component returns a 1 MiB
; message in successive 65536-byte fragments of type BINARY_FRAGMENT, then the last piece as
; BINARY_MESSAGE. The sum of the pieces is exactly the message sent (204800 = 65522 + 65536 + 65536
; + 8206, verified by the third-party websockets library). So concatenate until a "_MESSAGE" type,
; and a pong occurring during the assembly is counted without interrupting the message.
Func _Wsp_WaitMessage($iIdx, $iTimeoutMs)
    Local $t0 = TimerInit()
    Local $iAction = -1, $iType = -1
    While 1
        ; A message already queued by an earlier pump leaves BEFORE any wait: the caller must
        ; never pump again to read what it already has.
        If _Wsp_QCount($iIdx) > 0 Then
            Local $bQ = _Wsp_TakeMessage($iIdx)
            Local $eQ0 = @error, $tQ0 = @extended
            If $eQ0 = 0 Then
                $g_aWsp_MsgType[$iIdx] = $tQ0
                $g_aWsp_MsgLen[$iIdx] = BinaryLen($bQ)
                Return SetError(0, $tQ0, $bQ)
            EndIf
        EndIf
        ; A close seen by an EARLIER _Wsp_Pump lives nowhere but in this flag (rule V28: a close
        ; frame is never queued). Tested BEFORE the timeout exit so that the zero-timeout slice a
        ; server loop uses reports it too - otherwise the connection looks alive forever.
        If $g_aWsp_PendingClose[$iIdx] = 1 And _Wsp_QCount($iIdx) = 0 Then
            $g_aWsp_PendingClose[$iIdx] = 0
            Return SetError(3, $g_aWsp_CloseCode[$iIdx], $g_aWsp_CloseReason[$iIdx])
        EndIf
        If TimerDiff($t0) >= $iTimeoutMs Then ExitLoop

        Local $r = _Wsp_PumpOnce($iIdx, 200, $iAction, $iType, $Wsp_QUEUE_RECEIVE)
        Local $e = @error
        If $e = 5 Then Return SetError(4, $iAction, $g_aWspAsmBin[$iIdx]) ; peer closed
        If $e <> 0 Then Return SetError(2, $e, Binary("0x"))

        ; V21 (measured spike6 S4b): serve the SEND queue in this turn TOO. Without this line
        ; "_Wsp_Send then _Wsp_WaitMessage" is a dead end: the armed frame never leaves the
        ; machine, because the RECEIVE queue never serves SEND_TO_NETWORK (rule A6). A caller
        ; that sends then waits must get the answer.
        Local $iA2 = -1, $iT2 = -1
        _Wsp_PumpOnce($iIdx, 50, $iA2, $iT2, $Wsp_QUEUE_SEND)
        Local $e2 = @error
        If $e2 And $e2 <> 5 And $e2 <> 6 Then Return SetError(2, $e2, Binary("0x"))

        If $r <> 1 Then ContinueLoop

        Switch $iType
            Case $Wsp_CLOSE_BUFFER
                ; ANSWER FIRST, RETURN AFTER: a peer that sent its frame waits for ours to finish
                ; the close handshake, otherwise its application sees an error instead of a clean
                ; end (measure A8/x64).
                _Wsp_ReplyCloseIfNeeded($iIdx)
                Return SetError(3, $g_aWsp_CloseCode[$iIdx], $g_aWsp_CloseReason[$iIdx])
            Case $Wsp_UNSOLICITED_PONG, $Wsp_PING_PONG_BUFFER
                $g_aWsp_Pongs[$iIdx] += 1
                If _Wsp_QCount($iIdx) = 0 And BinaryLen($g_aWspAsmBin[$iIdx]) = 0 Then _
                        Return SetError(0, $iType, $g_aWsp_MsgBin[$iIdx])
            Case $Wsp_UTF8_FRAGMENT, $Wsp_BINARY_FRAGMENT
                ; _Wsp_QPush stored it in the assembly: nothing to return here.
            Case Else  ; UTF8_MESSAGE / BINARY_MESSAGE: the message is complete
                Local $b = _Wsp_TakeMessage($iIdx)
                Local $eQ = @error, $tQ = @extended
                If $eQ = 0 Then
                    $g_aWsp_MsgType[$iIdx] = $tQ
                    $g_aWsp_MsgLen[$iIdx] = BinaryLen($b)
                    Return SetError(0, $tQ, $b)
                EndIf
                ; Empty queue although a message was just completed = delivery REFUSED by the full
                ; queue. Say it, do not loop in the void.
                If $g_aWspQDropped[$iIdx] > 0 Then _
                        Return SetError(5, $g_aWspQDropped[$iIdx], Binary("0x"))
        EndSwitch
    WEnd
    Return SetError(1, 0, $g_aWspAsmBin[$iIdx])
EndFunc   ;==>_Wsp_WaitMessage

;#FUNCTION#=====================================================================================================================
; Name ..........: _Wsp_Ping
; Description ...: Attempt a protocol-level ping (kept so the caller gets a named failure instead of a false success).
; Syntax ........: _Wsp_Ping($iIdx, $sData)
; Parameters ....: $iIdx                 - slot index
;                  $sData                - ping payload
; Return values .: Success - Never on a live connection.
;                  Failure - @error/extended propagated from _Wsp_Send: the component answers E_INVALIDARG 0x80070057.
; Author ........: Numeric1
; Remarks .......: Measured (probe_pingpoison P1b): WebSocketSend with WEB_SOCKET_PING_PONG_BUFFER schedules no network action, so this stack cannot initiate a ping through layer 3. It suffers the peer's pings and the component answers them alone (proof A8: the third-party client received our pong although we never wrote one).
; Related .......: _Wsp_Send, $g_aWsp_Pongs
;===============================================================================================================================
; Protocol-level ping (PING_PONG type). MEASURED, not assumed: on an open connection,
; WebSocketSend(h, WEB_SOCKET_PING_PONG_BUFFER, ...) returns E_INVALIDARG (0x80070057,
; probe_pingpoison P1b) and schedules no network action at all. This stack therefore CANNOT initiate
; a ping through layer 3; it suffers the peer's pings and the component answers alone (proof A8: the
; third-party client receives our pong although we never wrote one). The function stays so the caller
; gets a NAMED failure instead of a false success.
; MEASURED AutoIt 3.3.16.1 RULE (t_propagate.au3): "Return OtherFunc()" returns the VALUE but resets
; @error and @extended to 0. A delegation must therefore write SetError(@error, @extended, $v)
; explicitly.
Func _Wsp_Ping($iIdx, $sData)
    Local $v = _Wsp_Send($iIdx, StringToBinary($sData, 8), $Wsp_PING_PONG_BUFFER)
    Return SetError(@error, @extended, $v)
EndFunc   ;==>_Wsp_Ping
