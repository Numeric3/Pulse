; =============================================================================
; Pulse.au3 -- a flight recorder and live console for AutoIt scripts.
;
;     Pulse.au3                     open the dashboard and listen
;     Pulse.au3 --auto              the self test: no window, no second process
;     Pulse.au3 --headless --seconds 20 --out out
;     Pulse.au3 --capture out/pulse.png --seconds 12
;     Pulse.au3 --port 49000        when 48411 is already taken
;
; Five UDFs, one process, each doing the job it is for:
;
;   WebSocket        the ingestion port. Any script on this machine sends one
;                    flat JSON object per text frame to
;                    ws://127.0.0.1:48411/stream.
;   WinEventManager  the bus. Every frame that parses becomes a named event and
;                    four prioritised handlers count, record, mark and escalate.
;                    Errors also go to the Windows Event Log, which is where they
;                    are still readable after this process is gone.
;   Tree             the index of dotted event names. Each node carries the
;                    count of its own subtree, so "Build.Compile is 40 % of the
;                    run" is a fact and not a guess, and the whole index exports
;                    into the archive.
;   CompoundFile     the archive. One .cfb per session with storages inside it:
;                    journal, name index, ring tail as NDJSON, manifest. One file
;                    to attach to a ticket.
;   WebView2         the view. Local files on a virtual host; the console pushes
;                    JSON to the page and the page never reaches the network.
;
; The loop owns every effect. A handler only touches state, because pumping the
; socket or the bus from inside a callback re-enters the dispatch and the queue
; order stops meaning anything.
;
; Author : Numeric1 -- Licence : MIT (Copyright (c) 2026 Numeric1)
; =============================================================================

Opt("MustDeclareVars", 1)
Opt("WinTitleMatchMode", 2)

#include <GUIConstantsEx.au3>
#include "Lib/WebView2.au3"
#include "Lib/WebSocket.au3"
#include "Lib/Tree.au3"
#include "Lib/CompoundFile.au3"
#include "Lib/WinEventManager.au3"
#include "Pulse_Json.au3"

Global Const $g_sVersion = "1.0.0"
Global Const $g_sHost = "pulse.local"
Global Const $g_iFrameCap = 8000 ; bytes of text accepted from one frame

Global $g_iPort = 48411
Global $g_bHeadless = False
Global $g_iRunSeconds = 0 ; 0 = until the window is closed
Global $g_sCapture = ""
Global $g_bCaptured = False
Global $g_sOutDir = ""
Global $g_sSession = ""
Global $g_sCfbPath = ""
Global $g_bQuit = False

; Bounds. All of them are printed by --auto and quoted in README.md.
Global $g_iRingCap = 5000 ; rows kept in memory, and the tail written to the archive
Global $g_iMaxPerTurn = 120 ; frames read from one connection per loop turn
Global $g_iTreeCap = 20000 ; nodes; past this the counts live in the Map only
Global $g_iCommitMs = 5000 ; archive flush cadence
Global $g_iGrabMs = 12000  ; --capture takes the screenshot this long after start-up
Global $g_iUiRows = 400 ; rows per push to the page
Global $g_iUiTicks = 10 ; dispatch events per turn before giving the loop back
Global $g_iEscalateMs = 1000 ; minimum gap between Event Log writes
Global $g_iTreeRows = 220 ; rows the tree panel can hold

; State
Global $g_hGui = 0, $g_hView = 0
Global $g_hListener = -1, $g_hCF = -1
Global $g_aConn[1] ; layer 3 slot -> 1 live / 0 free
; These four are Maps, and they have to be declared as Maps: a variable that
; starts life as the integer 0 does not become a container the first time
; something writes a key into it, it stops the process with "Subscript used on
; non-accessible variable". The self test passed for exactly this reason -- it
; assigns fresh Maps -- while the first real Agent.Hello over a socket killed the
; console. Measured on both bitnesses in tests/out/live_x86_console.log.
Global $g_mSrcN[] ; source -> events seen
Global $g_mSrcErr[] ; source -> errors seen
Global $g_mSrcPid[] ; source -> "pid bitness", from Agent.Hello
Global $g_mName[] ; event name -> count, the fallback when the tree is full
Global $g_mWorst[] ; tree node id -> worst level seen below it
Global $g_aR[1][7] ; the ring: time, lvl, name, src, ms, txt, cut
Global $g_iSeq = 0 ; rows ever written to the ring
Global $g_iSent = 0 ; rows ever pushed to the page
Global $g_iTreeNodes = 1, $g_iTreeOverflow = 0
; What the last commit actually put into Index\tree.txt: the row count returned by
; Tree_Export and the live node count at that instant. The archive must be checked
; against its own record, not against a tree that kept growing after the write.
Global $g_iArchRows = -1, $g_iArchNodes = -1
Global $g_iConns = 0, $g_iConnsPeak = 0, $g_iShed = 0, $g_iRejected = 0
Global $g_bDirtyStream = False, $g_bDirtySide = False, $g_bDirtyArch = False
Global $g_tStart = 0, $g_tCommit = 0, $g_tEscalate = 0, $g_tRate = 0
Global $g_tGui = 0 ; when the view was asked to navigate
Global $g_bPageReady = False ; set by the page's own ready message, nothing else
Global $g_fRate = 0, $g_iRateSeen = 0, $g_iTick = 0
Global $g_sLastErr = ""
Global $g_sTreeBuf = ""
Global $g_iTreeSeen = 0
Global $g_iRowIdx = -1

; -----------------------------------------------------------------------------
; Dispatch. --auto runs the self test and nothing else.
; -----------------------------------------------------------------------------
If $CmdLine[0] >= 1 And ($CmdLine[1] = "--auto" Or $CmdLine[1] = "/auto") Then
	__Pulse_SelfTest()
	Exit(@error ? 1 : 0)
EndIf
__Pulse_Main()

; =============================================================================
; start up
; =============================================================================
Func __Pulse_Main()
	__Pulse_ReadArgs()
	$g_tStart = TimerInit()
	$g_tRate = TimerInit()
	__Pulse_Log("Pulse " & $g_sVersion & " session " & $g_sSession)

	__Pulse_BootBus()
	Tree_Create("events")
	__Pulse_BootSockets()
	If Not __Pulse_BootArchive() Then
		__Pulse_Finish()
		Return
	EndIf
	__Pulse_Log("listening on ws://127.0.0.1:" & $g_iPort & "/stream" & ($g_bHeadless ? " (headless)" : ""))
	If Not $g_bHeadless Then __Pulse_BootGui()
	Local $iLimit = $g_iRunSeconds * 1000
	While 1
		__Pulse_Turn()
		If $g_bQuit Then ExitLoop
		If $iLimit > 0 And TimerDiff($g_tStart) >= $iLimit Then
			__Pulse_Log("run limit of " & $g_iRunSeconds & " s reached")
			ExitLoop
		EndIf
	WEnd
	__Pulse_Finish()
EndFunc   ;>__Pulse_Main

Func __Pulse_ReadArgs()
	Local $i, $s
	$g_sOutDir = @ScriptDir & "\out"
	For $i = 1 To $CmdLine[0]
		$s = $CmdLine[$i]
		Switch $s
			Case "--headless"
				$g_bHeadless = True
			Case "--capture"
				If $i < $CmdLine[0] Then
					$g_sCapture = $CmdLine[$i + 1]
					$i += 1
				EndIf
			Case "--port"
				If $i < $CmdLine[0] Then
					$g_iPort = Number($CmdLine[$i + 1])
					$i += 1
				EndIf
			Case "--seconds"
				If $i < $CmdLine[0] Then
					$g_iRunSeconds = Number($CmdLine[$i + 1])
					$i += 1
				EndIf
			Case "--grab-ms"
				; The screenshot is worth nothing if the panels are still empty, so it
				; waits for a commit cycle; this is how long it waits.
				If $i < $CmdLine[0] Then
					$g_iGrabMs = Number($CmdLine[$i + 1])
					$i += 1
				EndIf
			Case "--out"
				If $i < $CmdLine[0] Then
					$g_sOutDir = $CmdLine[$i + 1]
					$i += 1
				EndIf
		EndSwitch
	Next
	; WebView2 refuses a relative user data folder: measured as @error 6 with HRESULT
	; 0x80080005 (CO_E_SERVER_EXEC_FAILURE) for "tmp_gui\wv2" against a clean success
	; for the same folder spelled in full. Everything downstream of this line, the
	; .cfb path included, is therefore an absolute path.
	$g_sOutDir = _PathFull($g_sOutDir)
	DirCreate($g_sOutDir)
	$g_sSession = @YEAR & @MON & @MDAY & "-" & @HOUR & @MIN & @SEC & "-" & @AutoItPID
	$g_sCfbPath = $g_sOutDir & "\Pulse_" & $g_sSession & "_" & (@AutoItX64 ? "x64" : "x86") & ".cfb"
	ReDim $g_aR[$g_iRingCap][7]
	ReDim $g_aConn[$g_iWspSlots]
EndFunc   ;>__Pulse_ReadArgs

; The bus: four handlers on every name, in the order the consequences matter.
;
; All four accept, which is why the dead-letter store of THIS process stays empty
; in normal use: WinEventManager counts an event delivered as soon as one handler
; takes it. The store is still exercised, by --auto, which lifts the catch-all
; handlers off the bus and shows what an event nobody takes becomes.
Func __Pulse_BootBus()
	_WinEvent_Startup()
	_WinEvent_RetryLimit(2)
	_WinEvent_DeadMax(200)
	_WinEvent_RegisterHandler("*", "__Pulse_HCount", 100, 2)
	_WinEvent_RegisterHandler("*", "__Pulse_HRecord", 90, 2)
	_WinEvent_RegisterHandler("*", "__Pulse_HMark", 80, 2)
	_WinEvent_RegisterHandler("*", "__Pulse_HEscalate", 70, 2)
EndFunc   ;>__Pulse_BootBus

Func __Pulse_UnbootBus()
	_WinEvent_UnregisterHandler("*", "__Pulse_HCount")
	_WinEvent_UnregisterHandler("*", "__Pulse_HRecord")
	_WinEvent_UnregisterHandler("*", "__Pulse_HMark")
	_WinEvent_UnregisterHandler("*", "__Pulse_HEscalate")
EndFunc   ;>__Pulse_UnbootBus

Func __Pulse_BootSockets()
	If Not _WS_Startup() Then
		__Pulse_Die("the websocket layer refused to start: " & _WS_LastWalk())
		$g_bQuit = True
		Return False
	EndIf
	$g_hListener = _WS_Listen($g_iPort, "127.0.0.1")
	If $g_hListener < 0 Then
		__Pulse_Die("cannot listen on " & $g_iPort & " @error " & @error & " extended " & @extended)
		$g_bQuit = True
		Return False
	EndIf
	$g_iPort = _WS_ListenPort($g_hListener)
	Return True
EndFunc   ;>__Pulse_BootSockets

Func __Pulse_BootArchive()
	$g_hCF = _CF_Create($g_sCfbPath)
	If $g_hCF < 1 Then
		__Pulse_Die("cannot create " & $g_sCfbPath & " @error " & @error & " " & _CF_GetLastErrorMessage())
		$g_hCF = -1
		Return False
	EndIf
	_CF_CreateStorage($g_hCF, "Sessions\" & $g_sSession & "\Index")
	$g_tCommit = TimerInit()
	Return True
EndFunc   ;>__Pulse_BootArchive

; The view is created here, and that call blocks for as long as the browser takes to
; answer: 8.7 s for a fresh profile on this machine, measured. The loop is the only
; thing that answers a handshake, so an agent launched inside that window is refused,
; and it is Pulse_Agent.au3's grace window (a retry every 2 s for the first 20 s of a
; process) that carries a short script through it. _WV2_CreateStart plus a polled
; wait was tried first and cannot work from the public surface: _WV2_IsReady only
; turns true inside _WV2_CreateWait, and a _WV2_CreateWait that times out releases the
; handle, so there is nothing to poll and no cheap way to wait.
Func __Pulse_BootGui()
	$g_hGui = GUICreate("Pulse " & $g_sVersion & "  " & $g_sSession, 1340, 840)
	DirCreate($g_sOutDir & "\wv2")
	Local $t = TimerInit()
	; _WV2_Create answers 0 on failure and handles start at 1: a test against < 0
	; accepted the failure and every later call then said ERR_HANDLE, which is how a
	; GUI run looked alive with an empty window.
	$g_hView = _WV2_Create($g_hGui, 0, 0, -1, -1, $g_sOutDir & "\wv2")
	If $g_hView < 1 Then
		__Pulse_Log("no WebView2 view @error " & @error & " (" & _WV2_GetLastErrorMessage() & "), continuing headless")
		GUIDelete($g_hGui)
		$g_hGui = 0
		$g_hView = 0
		$g_bHeadless = True
		Return
	EndIf
	GUISetState(@SW_SHOW, $g_hGui)
	; The mapping has to exist before the navigation: a request for a host with
	; no mapping is a 404, and it is never allowed to fall back to the network.
	_WV2_SetVirtualHostNameToFolderMapping($g_hView, $g_sHost, @ScriptDir & "\Web")
	_WV2_SetEventHandler($g_hView, $WV2_EVENT_WEB_MESSAGE, "__Pulse_OnWebMessage")
	_WV2_Navigate($g_hView, "http://" & $g_sHost & "/index.html")
	; No blocking wait for the navigation, and that is load-bearing. A 15 s
	; _WV2_WaitNavigation here (the first version) starved __Pulse_AcceptOne, so an
	; agent that attached 4 s into the run was refused although the socket was already
	; bound (measured). The page says ready when it is up; that message resets the
	; stream cursor so the ring tail is pushed from scratch.
	$g_tGui = TimerInit()
	__Pulse_Log("dashboard at http://" & $g_sHost & "/index.html (browser took " & Round(TimerDiff($t)) & " ms)")
EndFunc   ;>__Pulse_BootGui

; =============================================================================
; the loop: one turn, every effect in order, nothing inside a callback
; =============================================================================
Func __Pulse_Turn()
	Local $iWork = 0, $iMsg
	If Not $g_bHeadless Then
		$iMsg = GUIGetMsg()
		Switch $iMsg
			Case $GUI_EVENT_CLOSE
				$g_bQuit = True
			Case $GUI_EVENT_RESIZED, $GUI_EVENT_MAXIMIZE, $GUI_EVENT_RESTORE
				_WV2_FitToParent($g_hView)
		EndSwitch
		$iWork += 1
	EndIf

	$iWork += __Pulse_AcceptOne()
	$iWork += __Pulse_PumpConns()
	; The queue holds 1000 events and one turn can ingest at most
	; $g_iMaxPerTurn * $g_iWspSlots = 960, so draining it completely here is what
	; keeps the ceiling out of reach. A bounded drain (200 per turn, measured) let a
	; burst overflow the queue and lose events that the socket had already accepted.
	$iWork += _WinEvent_Process(0)
	If Not $g_bHeadless Then $iWork += _WV2_DispatchEvents($g_hView, $g_iUiTicks)

	If $g_bDirtyStream Or $g_bDirtySide Then
		__Pulse_Refresh()
		$g_bDirtyStream = False
		$g_bDirtySide = False
		$iWork += 1
	EndIf
	If TimerDiff($g_tCommit) >= $g_iCommitMs Then
		__Pulse_Commit()
		$iWork += 1
	EndIf
	; A screenshot of a page that has not said ready proves nothing, so the shot
	; waits for the message; if it never comes, the shot still goes at twice the
	; delay, because a picture of a blank window is evidence and no picture is not.
	If $g_sCapture <> "" And Not $g_bCaptured And TimerDiff($g_tStart) >= $g_iGrabMs And _
			($g_bPageReady Or TimerDiff($g_tStart) >= $g_iGrabMs * 2) Then __Pulse_Grab()

	If $iWork = 0 Then Sleep(2)
EndFunc   ;>__Pulse_Turn

; One accept per turn, so a burst of peers cannot starve the loop.
Func __Pulse_AcceptOne()
	If $g_hListener < 0 Then Return 0
	Local $h = _WS_Accept($g_hListener)
	If @error = 2 Then Return 0 ; nothing waiting, which is the normal answer
	If $h < 0 Then
		If @error <> 1 Then $g_sLastErr = "accept @error " & @error & " extended " & @extended
		Return 0
	EndIf
	_WS_Upgrade($h, 2000)
	If @error Then
		$g_iRejected += 1
		$g_sLastErr = "handshake refused on slot " & $h & " @error " & @error
		_WS_CloseHandle($h)
		Return 1
	EndIf
	$g_aConn[$h] = 1
	$g_iConns += 1
	If $g_iConns > $g_iConnsPeak Then $g_iConnsPeak = $g_iConns
	__Pulse_Log("agent connected on slot " & $h & " from " & _WS_PeerAddress($h))
	$g_bDirtySide = True
	Return 1
EndFunc   ;>__Pulse_AcceptOne

Func __Pulse_PumpConns()
	Local $i, $h, $e, $x, $n = 0, $read, $s
	For $i = 0 To $g_iWspSlots - 1
		If $g_aConn[$i] <> 1 Then ContinueLoop
		$h = $i
		_WS_Pump($h, 0)
		$e = @error
		$x = @extended
		$n += 1
		If $e = 1 Then
			__Pulse_Gone($h, "the peer closed the socket")
			ContinueLoop
		ElseIf $e = 2 Then
			__Pulse_Gone($h, "named error " & $x)
			ContinueLoop
		ElseIf $e = 3 Then
			$g_iShed += $x ; delivery queue was full, $x messages lost
		EndIf
		$read = 0
		While $read < $g_iMaxPerTurn
			$s = _WS_MessageText($h)
			If @error Then ExitLoop ; 1 = the queue is empty
			$read += 1
			__Pulse_Ingest($s)
		WEnd
		$n += $read
	Next
	Return $n
EndFunc   ;>__Pulse_PumpConns

Func __Pulse_Gone($h, $sWhy)
	Local $sInfo = _WS_CloseInfo($h)
	__Pulse_Log("agent on slot " & $h & " went away (" & $sWhy & (StringLen($sInfo) ? ", " & $sInfo : "") & ")")
	_WS_CloseHandle($h)
	$g_aConn[$h] = 0
	If $g_iConns > 0 Then $g_iConns -= 1
	$g_bDirtySide = True
EndFunc   ;>__Pulse_Gone

; =============================================================================
; ingestion: bytes in, one named event out
; =============================================================================
Func __Pulse_Ingest($sJson)
	If StringLen($sJson) > $g_iFrameCap Then
		$g_iRejected += 1
		$g_sLastErr = "frame of " & StringLen($sJson) & " bytes refused (cap " & $g_iFrameCap & ")"
		Return False
	EndIf
	Local $m[]
	If Not _Pulse_JParse($sJson, $m) Then
		$g_iRejected += 1
		$g_sLastErr = "frame refused at offset " & @extended & ": " & StringLeft($sJson, 60)
		$g_bDirtySide = True
		Return False
	EndIf
	Local $sName = _Pulse_JGet($m, "name")
	If $sName = "" Then
		$g_iRejected += 1
		$g_sLastErr = "frame without a name: " & StringLeft($sJson, 60)
		$g_bDirtySide = True
		Return False
	EndIf
	; The row is what every handler receives: already decoded, already stamped.
	; Index 6 is the truncation flag, kept apart because it colours the row.
	Local $aRow[7]
	$aRow[0] = @HOUR & ":" & @MIN & ":" & @SEC & "." & @MSEC
	$aRow[1] = __Pulse_Lvl(_Pulse_JGet($m, "lvl"))
	$aRow[2] = $sName
	$aRow[3] = _Pulse_JGet($m, "src", "unknown")
	$aRow[4] = _Pulse_JGet($m, "ms", "")
	$aRow[5] = _Pulse_JGet($m, "txt", "")
	$aRow[6] = (_Pulse_JHas($m, "truncated") ? 1 : 0)
	Local $sExtra = __Pulse_Extras($m)
	If $sExtra <> "" Then $aRow[5] = ($aRow[5] = "" ? "" : $aRow[5] & "  ") & $sExtra
	If $sName = "Agent.Hello" Then $g_mSrcPid[$aRow[3]] = _Pulse_JGet($m, "pid", "") & " " & (_Pulse_JGet($m, "x64") = 1 ? "x64" : "x86")
	; A refused post is a lost event, and the bus refuses when 1000 are already
	; waiting (measured: a 5050-frame burst with no drain in between put 1006 rows
	; in the ring and said nothing). The loop drains every turn, which keeps the
	; queue far below that ceiling; this counter is the proof it never happened.
	If Not _WinEvent_Post($sName, $aRow) Then
		$g_iShed += 1
		$g_sLastErr = "bus queue full, event lost: " & $sName
		$g_bDirtySide = True
		Return False
	EndIf
	Return True
EndFunc   ;>__Pulse_Ingest

Func __Pulse_Lvl($s)
	Switch StringLower($s)
		Case "ok"
			Return "ok"
			Case "warn", "warning"
			Return "warn"
		Case "error", "err", "fatal"
			Return "error"
		Case "debug", "trace"
			Return "debug"
		Case Else
			Return "info"
	EndSwitch
EndFunc   ;>__Pulse_Lvl

; Every key the sender invented that is not part of the envelope travels along as
; one flat string, so a custom field is visible without the console having ever
; heard of it. A nested value is already raw text here, which is the deal.
Func __Pulse_Extras(ByRef $m)
	Local $aK = MapKeys($m), $i, $k, $s = ""
	For $i = 0 To UBound($aK) - 1
		$k = $aK[$i]
		Switch $k
			Case "v", "name", "src", "lvl", "ms", "txt", "truncated"
				ContinueLoop
		EndSwitch
		$s &= $k & "=" & $m[$k] & " "
	Next
	Return StringStripWS($s, 3)
EndFunc   ;>__Pulse_Extras

; =============================================================================
; bus handlers: state only, never an effect
; =============================================================================
Func __Pulse_HCount($sEvent, $vData)
	If Not IsArray($vData) Then Return True
	__Pulse_BumpTree($vData[2], $vData[1])
	__Pulse_BumpSource($vData[3], $vData[1])
	Return True
EndFunc   ;>__Pulse_HCount

Func __Pulse_HRecord($sEvent, $vData)
	If Not IsArray($vData) Then Return True
	__Pulse_RingPush($vData)
	Return True
EndFunc   ;>__Pulse_HRecord

Func __Pulse_HMark($sEvent, $vData)
	$g_bDirtyStream = True
	Return True
EndFunc   ;>__Pulse_HMark

; An error is the one event worth a second, independent record: the Windows Event
; Log outlives this process. Rate limited, because an error inside a tight loop
; must not turn into a disk problem.
Func __Pulse_HEscalate($sEvent, $vData)
	If Not IsArray($vData) Then Return True
	If $vData[1] <> "error" Then Return True
	If TimerDiff($g_tEscalate) < $g_iEscalateMs Then Return True
	$g_tEscalate = TimerInit()
	_WinEvent_Write("Pulse " & $vData[2] & " from " & $vData[3] & " : " & StringLeft($vData[5], 900), _
			"", $WINEVENT_TYPE_ERROR, 0, 1000)
	If @error Then $g_sLastErr = "event log write failed @error " & @error & " extended " & @extended
	Return True
EndFunc   ;>__Pulse_HEscalate

Func __Pulse_HRefuse($sEvent, $vData)
	; The sink --auto installs once the catch-all handlers are off the bus. It
	; always refuses, so the retry budget runs out and the event ends up in the
	; dead-letter store with its reason: the only honest place for it.
	Return False
EndFunc   ;>__Pulse_HRefuse

; =============================================================================
; the index of names
;
; A Tree name is unique across the whole tree, so the segments of an event name
; cannot be used as-is: Build.Compile and Test.Compile.Start would collide. The
; node name is therefore the full dotted prefix (Build, Build.Compile,
; Build.Compile.Step) and the parent links are what make it a trie. One
; Tree_Find per segment, and the display name is the node name itself.
; =============================================================================
Func __Pulse_BumpTree($sName, $sLvl)
	If Tree_Count() >= $g_iTreeCap Then
		$g_iTreeOverflow += 1
		__Pulse_MapInc($g_mName, $sName)
		Return
	EndIf
	Local $a = StringSplit($sName, ".", 1), $k, $iParent = Tree_Root(), $sPath = "", $id
	For $k = 1 To $a[0]
		$sPath &= ($sPath = "" ? "" : ".") & $a[$k]
		$id = Tree_Find($sPath)
		If $id = 0 Then
			$id = Tree_Add($iParent, 0, $sPath)
			If @error Or $id <= 0 Then
				$g_iTreeOverflow += 1
				__Pulse_MapInc($g_mName, $sName)
				Return
			EndIf
		EndIf
		; Every prefix on the way counts the events below it, which is the whole
		; point of the panel: a branch is a share of the run, not a folder.
		Tree_SetData($id, Number(Tree_GetData($id)) + 1)
		$g_mWorst[$id] = __Pulse_Worse(__Pulse_MapGet($g_mWorst, $id, "0"), $sLvl)
		$iParent = $id
	Next
	$g_iTreeNodes = Tree_Count()
EndFunc   ;>__Pulse_BumpTree

Func __Pulse_Worse($iNow, $sLvl)
	Local $iNew = 1
	Switch $sLvl
		Case "error"
			$iNew = 4
			Case "warn"
			$iNew = 3
		Case "ok"
			$iNew = 2
		Case "debug"
			$iNew = 1
	EndSwitch
	Return ($iNew > Number($iNow) ? $iNew : Number($iNow))
EndFunc   ;>__Pulse_Worse

Func __Pulse_LvlName($i)
	Switch Number($i)
		Case 4
			Return "error"
			Case 3
			Return "warn"
		Case 2
			Return "ok"
		Case Else
			Return "info"
	EndSwitch
EndFunc   ;>__Pulse_LvlName

Func __Pulse_BumpSource($sSrc, $sLvl)
	__Pulse_MapInc($g_mSrcN, $sSrc)
	If $sLvl = "error" Then __Pulse_MapInc($g_mSrcErr, $sSrc)
	$g_bDirtySide = True
EndFunc   ;>__Pulse_BumpSource

; A Map hands back the Default keyword for a key it does not hold, and Default is
; equal to nothing, not even to "". Every counter and every read here therefore
; asks MapExists first; __Pulse_MapGet exists so that no call site forgets.
Func __Pulse_MapInc(ByRef $m, $sKey)
	Local $v = 1
	If MapExists($m, $sKey) Then $v = Number($m[$sKey]) + 1
	$m[$sKey] = $v
EndFunc   ;>__Pulse_MapInc

Func __Pulse_MapGet(ByRef $m, $sKey, $sDefault = "")
	If Not MapExists($m, $sKey) Then Return $sDefault
	Return String($m[$sKey])
EndFunc   ;>__Pulse_MapGet

; =============================================================================
; the ring
; =============================================================================
Func __Pulse_RingPush($aRow)
	Local $i = Mod($g_iSeq, $g_iRingCap), $k
	For $k = 0 To 6
		$g_aR[$i][$k] = $aRow[$k]
	Next
	$g_iSeq += 1
EndFunc   ;>__Pulse_RingPush

Func __Pulse_RingRows()
	Return ($g_iSeq < $g_iRingCap ? $g_iSeq : $g_iRingCap)
EndFunc   ;>__Pulse_RingRows

Func __Pulse_RingFirst()
	Return ($g_iSeq < $g_iRingCap ? 0 : $g_iSeq - $g_iRingCap)
EndFunc   ;>__Pulse_RingFirst

; =============================================================================
; the view
; =============================================================================
Func __Pulse_Refresh()
	If $g_bHeadless Or $g_hView = 0 Then
		__Pulse_TickPrint()
		Return
	EndIf
	__Pulse_PushStream()
	__Pulse_PushStat()
	__Pulse_PushTree()
	__Pulse_PushSrcs()
	__Pulse_PushArch()
EndFunc   ;>__Pulse_Refresh

Func __Pulse_PushStream()
	; Only rows the page has not seen go out, and never more than $g_iUiRows:
	; behind a stalled page the ring simply overwrites and the cursor jumps.
	Local $iFirst = __Pulse_RingFirst(), $iN = __Pulse_RingRows()
	If $g_iSent < $iFirst Then $g_iSent = $iFirst
	If $iN - ($g_iSent - $iFirst) > $g_iUiRows Then $g_iSent = $iN + $iFirst - $g_iUiRows
	Local $i, $s = "", $idx
	For $i = $g_iSent To $iFirst + $iN - 1
		$idx = Mod($i, $g_iRingCap)
		$s &= ($s = "" ? "" : ",") & __Pulse_RowArr($idx)
	Next
	$g_iSent = $iFirst + $iN
	If $s <> "" Then _WV2_PostWebMessage($g_hView, '{"k":"evs","a":[' & $s & "]}")
EndFunc   ;>__Pulse_PushStream

Func __Pulse_RowArr($idx)
	Return '["' & $g_aR[$idx][0] & '","' & $g_aR[$idx][1] & '","' & _Pulse_JEscape($g_aR[$idx][2]) & _
			'","' & _Pulse_JEscape($g_aR[$idx][3]) & '","' & _Pulse_JEscape(String($g_aR[$idx][4])) & _
			'","' & _Pulse_JEscape($g_aR[$idx][5]) & '",' & ($g_aR[$idx][6] ? 1 : 0) & ']'
EndFunc   ;>__Pulse_RowArr

Func __Pulse_PushStat()
	Local $ms = TimerDiff($g_tRate)
	If $ms > 500 Then
		$g_fRate = ($g_iSeq - $g_iRateSeen) * 1000 / $ms
		$g_iRateSeen = $g_iSeq
		$g_tRate = TimerInit()
	EndIf
	Local $m[]
	$m["k"] = "stat"
	$m["total"] = $g_iSeq
	$m["rate"] = Round($g_fRate, 1)
	$m["srcs"] = UBound(MapKeys($g_mSrcN))
	$m["nodes"] = Tree_Count()
	$m["dead"] = _WinEvent_DeadLettered()
	$m["q"] = _WinEvent_Queued()
	$m["journal"] = _WinEvent_Journal()
	$m["conns"] = $g_iConns
	$m["peak"] = $g_iConnsPeak
	$m["shed"] = $g_iShed
	$m["rejected"] = $g_iRejected
	$m["overflow"] = $g_iTreeOverflow
	$m["port"] = $g_iPort
	$m["listening"] = ($g_hListener >= 0 ? 1 : 0)
	$m["bytes"] = FileGetSize($g_sCfbPath)
	$m["file"] = $g_sCfbPath
	$m["err"] = $g_sLastErr
	$m["session"] = $g_sSession
	$m["secs"] = Round(TimerDiff($g_tStart) / 1000, 1)
	_WV2_PostWebMessage($g_hView, _Pulse_JBuild($m))
EndFunc   ;>__Pulse_PushStat

; Tree_Walk is not reentrant and its callback must be a top-level function, so the
; rows are collected in a global string and sent once the walk is over.
Func __Pulse_PushTree()
	$g_sTreeBuf = ""
	$g_iTreeSeen = 0
	Tree_Walk("__Pulse_TreeEmit")
	_WV2_PostWebMessage($g_hView, '{"k":"tree","a":[' & $g_sTreeBuf & "]}")
EndFunc   ;>__Pulse_PushTree

Func __Pulse_TreeEmit($iNode)
	If $iNode = Tree_Root() Then Return 1
	If $g_iTreeSeen >= $g_iTreeRows Then Return -1 ; stop the walk, the panel is full
	; Flat triples, exactly as docs/PROTOCOL.md and the page's own loop describe them:
	; a nested array per node rendered nothing at all, because onTree walks with i += 3.
	$g_iTreeSeen += 1
	$g_sTreeBuf &= ($g_sTreeBuf = "" ? "" : ",") & _Pulse_JQuote(Tree_Name($iNode)) & "," & _
			Number(Tree_GetData($iNode)) & ',"' & __Pulse_LvlName(__Pulse_MapGet($g_mWorst, $iNode, "0")) & '"'
	Return 1
EndFunc   ;>__Pulse_TreeEmit

Func __Pulse_PushSrcs()
	_WV2_PostWebMessage($g_hView, '{"k":"srcs","a":[' & __Pulse_SrcsJson() & "]}")
EndFunc   ;>__Pulse_PushSrcs

Func __Pulse_SrcsJson()
	Local $aK = MapKeys($g_mSrcN), $i, $s = "", $k
	For $i = 0 To UBound($aK) - 1
		$k = $aK[$i]
		$s &= ($s = "" ? "" : ",") & "[" & _Pulse_JQuote($k) & "," & _
				_Pulse_JQuote(__Pulse_MapGet($g_mSrcPid, $k)) & "," & _
				Number(__Pulse_MapGet($g_mSrcN, $k, "0")) & "," & Number(__Pulse_MapGet($g_mSrcErr, $k, "0")) & "]"
	Next
	Return $s
EndFunc   ;>__Pulse_SrcsJson

Func __Pulse_PushArch()
	If Not $g_bDirtyArch Then Return
	$g_bDirtyArch = False
	_WV2_PostWebMessage($g_hView, '{"k":"arch","a":[' & __Pulse_ArchList("Sessions\" & $g_sSession) & "]}")
EndFunc   ;>__Pulse_PushArch

; One level of the archive: name and size of every stream, storage marked as such.
Func __Pulse_ArchList($sPath)
	If $g_hCF < 1 Then Return ""
	Local $a = _CF_Enum($g_hCF, $sPath)
	If @error Or Not IsArray($a) Then Return ""
	Local $i, $s = "", $st[1]
	For $i = 1 To $a[0][0]
		$s &= ($s = "" ? "" : ",")
		If $a[$i][1] = $CF_TYPE_STORAGE Then
			$s &= "[" & _Pulse_JQuote($a[$i][0] & "/") & ',"storage"]'
		Else
			$st = _CF_Stat($g_hCF, $sPath & "\" & $a[$i][0])
			$s &= "[" & _Pulse_JQuote($a[$i][0]) & "," & _Pulse_JQuote(__Pulse_Size(IsArray($st) ? $st[1] : 0)) & "]"
		EndIf
	Next
	Return $s
EndFunc   ;>__Pulse_ArchList

Func __Pulse_Size($i)
	$i = Number($i)
	If $i >= 1048576 Then Return Round($i / 1048576, 1) & " MB"
	If $i >= 1024 Then Return Round($i / 1024, 1) & " KB"
	Return $i & " B"
EndFunc   ;>__Pulse_Size

; A headless run still has to say something or it looks hung from the outside.
Func __Pulse_TickPrint()
	$g_iTick += 1
	If BitAnd($g_iTick, 3) <> 0 Then Return
	ConsoleWrite("tick events=" & $g_iSeq & " ring=" & __Pulse_RingRows() & " tree=" & Tree_Count() & _
			" srcs=" & UBound(MapKeys($g_mSrcN)) & " conns=" & $g_iConns & _
			" dead=" & _WinEvent_DeadLettered() & " rejected=" & $g_iRejected & @CRLF)
EndFunc   ;>__Pulse_TickPrint

; =============================================================================
; the archive
; =============================================================================
Func __Pulse_Commit()
	$g_tCommit = TimerInit()
	If $g_hCF < 1 Then Return False
	Local $sDir = $g_sOutDir & "\_scratch_" & $g_sSession
	DirCreate($sDir)
	Local $sBase = "Sessions\" & $g_sSession

	; 1. the bus journal: every delivery, with its retry and dead-letter state.
	_WinEvent_SaveToFile($sDir & "\journal.txt", "w", 7)
	__Pulse_PutFile($sDir & "\journal.txt", $sBase & "\journal.txt")

	; 2. the name index, straight out of the tree.
	$g_iArchRows = Tree_Export($sDir & "\tree.txt")
	$g_iArchNodes = Tree_Count()
	__Pulse_PutFile($sDir & "\tree.txt", $sBase & "\Index\tree.txt")

	; 3. the tail of the ring as NDJSON: one object per line, loadable anywhere.
	Local $sNd = __Pulse_RingNdjson()
	__Pulse_WriteText($sDir & "\events.ndjson", $sNd)
	__Pulse_PutFile($sDir & "\events.ndjson", $sBase & "\events.ndjson")
	Local $iRingRows = __Pulse_RingRows()

	; 4. the manifest, so the file explains itself in six months.
	Local $m[]
	$m["session"] = $g_sSession
	$m["pulse"] = $g_sVersion
	$m["autoit"] = @AutoItVersion
	$m["bitness"] = (@AutoItX64 ? "x64" : "x86")
	$m["host"] = @ComputerName
	$m["user"] = @UserName
	$m["port"] = $g_iPort
	$m["events_seen"] = $g_iSeq
	$m["events_ring"] = $iRingRows
	$m["events_archive"] = $iRingRows
	$m["tree_nodes"] = $g_iArchNodes
	$m["tree_rows"] = $g_iArchRows
	$m["tree_overflow"] = $g_iTreeOverflow
	$m["sources"] = UBound(MapKeys($g_mSrcN))
	$m["connections_peak"] = $g_iConnsPeak
	$m["rejected"] = $g_iRejected
	$m["shed"] = $g_iShed
	$m["journal_rows"] = _WinEvent_Journal()
	$m["dead_letters"] = _WinEvent_DeadLettered()
	$m["queue"] = _WinEvent_Queued()
	$m["elapsed_s"] = Round(TimerDiff($g_tStart) / 1000, 1)
	_CF_WriteStream($g_hCF, $sBase & "\Manifest.json", _Pulse_JBuild($m) & @CRLF, $CF_TEXT)
	If @error Then $g_sLastErr = "Manifest.json refused: " & _CF_GetLastErrorMessage()

	_CF_Commit($g_hCF)
	$g_bDirtyArch = True
	FileDelete($sDir & "\journal.txt")
	FileDelete($sDir & "\tree.txt")
	FileDelete($sDir & "\events.ndjson")
	Return True
EndFunc   ;>__Pulse_Commit

Func __Pulse_PutFile($sSrc, $sStream)
	; The bytes go in exactly as they are on disk, read in binary. This matters:
	; a string handed to a $CF_BINARY stream has a BinaryLen of 0, and the storage
	; writes that as a perfectly valid empty stream without saying so (measured).
	Local $h = FileOpen($sSrc, 16)
	If $h = -1 Then
		$g_sLastErr = "no scratch file for " & $sStream & " (" & $sSrc & ")"
		Return False
	EndIf
	Local $b = FileRead($h)
	FileClose($h)
	If @error Then
		$g_sLastErr = "scratch read failed for " & $sStream & " (" & $sSrc & ")"
		Return False
	EndIf
	_CF_WriteStream($g_hCF, $sStream, $b, $CF_BINARY)
	If @error Then
		$g_sLastErr = $sStream & " refused: " & _CF_GetLastErrorMessage()
		Return False
	EndIf
	$g_bDirtyArch = True
	Return True
EndFunc   ;>__Pulse_PutFile

Func __Pulse_RingNdjson()
	Local $i, $s = "", $iFirst = __Pulse_RingFirst(), $iN = __Pulse_RingRows()
	For $i = $iFirst To $iFirst + $iN - 1
		$s &= __Pulse_RowJson(Mod($i, $g_iRingCap)) & @LF
	Next
	Return $s
EndFunc   ;>__Pulse_RingNdjson

Func __Pulse_RowJson($idx)
	Local $m[]
	$m["t"] = $g_aR[$idx][0]
	$m["lvl"] = $g_aR[$idx][1]
	$m["name"] = $g_aR[$idx][2]
	$m["src"] = $g_aR[$idx][3]
	If $g_aR[$idx][4] <> "" Then $m["ms"] = Number($g_aR[$idx][4])
	If $g_aR[$idx][5] <> "" Then $m["txt"] = $g_aR[$idx][5]
	If $g_aR[$idx][6] Then $m["truncated"] = "1"
	Return _Pulse_JBuild($m)
EndFunc   ;>__Pulse_RowJson

Func __Pulse_WriteText($sPath, $sText)
	Local $h = FileOpen($sPath, 10) ; write, create the path, truncate
	If $h = -1 Then Return False
	FileWrite($h, $sText)
	FileClose($h)
	Return True
EndFunc   ;>__Pulse_WriteText

; =============================================================================
; messages from the page
; =============================================================================
Func __Pulse_OnWebMessage($iHandle, $iEvent, $sData, $iValue)
	; $iValue 1 = a plain string, 0 = JSON. The page sends objects, but a typed
	; string still has to land somewhere, so it is quoted before it is parsed.
	Local $s = ($iValue = 1 ? _Pulse_JQuote($sData) : $sData)
	Local $m[]
	If Not _Pulse_JParse($s, $m) Then
		$g_sLastErr = "the page sent something that is not an object"
		Return
	EndIf
	Switch _Pulse_JGet($m, "k")
		Case "ready"
			$g_bPageReady = True
			$g_iSent = 0
			$g_bDirtyStream = True
			$g_bDirtySide = True
			$g_bDirtyArch = True
			__Pulse_Log("dashboard attached")
		Case "commit"
			__Pulse_Commit()
		Case "clear"
			$g_iSeq = 0
			$g_iSent = 0
			$g_bDirtyStream = True
		Case "log"
			ConsoleWrite("page: " & _Pulse_JGet($m, "text") & @CRLF)
		Case Else
			__Pulse_Log("page message [" & _Pulse_JGet($m, "k") & "] has no meaning here")
	EndSwitch
EndFunc   ;>__Pulse_OnWebMessage

Func __Pulse_Grab()
	$g_bCaptured = True
	Local $sFile = $g_sCapture
	If $g_hView < 1 Then
		ConsoleWrite("CAPTURE_SKIP no view (handle " & $g_hView & "), nothing to photograph" & @CRLF)
		Return
	EndIf
	_WV2_CapturePreview($g_hView, $sFile, $WV2_IMAGE_PNG, 20000)
	If @error Then
		ConsoleWrite("CAPTURE_FAIL @error=" & @error & " " & _WV2_GetLastErrorMessage() & " (handle " & $g_hView & ")" & @CRLF)
	Else
		ConsoleWrite("CAPTURE_OK " & $sFile & " " & FileGetSize($sFile) & " bytes" & @CRLF)
	EndIf
EndFunc   ;>__Pulse_Grab

; =============================================================================
; shared helpers
; =============================================================================
Func __Pulse_Log($s)
	ConsoleWrite("[" & @HOUR & ":" & @MIN & ":" & @SEC & "] " & $s & @CRLF)
EndFunc   ;>__Pulse_Log

Func __Pulse_Die($s)
	$g_sLastErr = $s
	ConsoleWrite("FATAL " & $s & @CRLF)
	$g_bQuit = True
EndFunc   ;>__Pulse_Die

Func __Pulse_State()
	Return "events=" & $g_iSeq & " ring=" & __Pulse_RingRows() & " nodes=" & Tree_Count() & _
			" srcs=" & UBound(MapKeys($g_mSrcN)) & " dead=" & _WinEvent_DeadLettered() & _
			" rejected=" & $g_iRejected & " shed=" & $g_iShed & " cfb=" & FileGetSize($g_sCfbPath) & " bytes"
EndFunc   ;>__Pulse_State

Func __Pulse_Finish()
	__Pulse_Log("closing: " & __Pulse_State())
	; Filled in just before the bus is torn down: __Pulse_State reads live counters,
	; and after _WinEvent_Shutdown the bus answers with False instead of a count.
	Local $sState = ""
	; The path is on its own line because the gate greps for exactly this prefix to
	; find the archive of the run it just watched.
	__Pulse_Log("ARCHIVE " & $g_sCfbPath)
	__Pulse_Commit()
	If $g_hCF > 0 Then
		_CF_Close($g_hCF)
		$g_hCF = -1
	EndIf
	Local $i
	For $i = 0 To $g_iWspSlots - 1
		If $g_aConn[$i] = 1 Then _WS_CloseHandle($i)
	Next
	If $g_hListener >= 0 Then
		_WS_CloseListener($g_hListener)
		$g_hListener = -1
	EndIf
	_WS_Cleanup()
	_WinEvent_SaveToFile($g_sOutDir & "\bus_" & $g_sSession & ".log", "w", 7)
	$sState = __Pulse_State() ; the last moment the bus can still answer with numbers
	_WinEvent_Shutdown()
	If $g_hView <> 0 Then
		_WV2_Destroy($g_hView)
		$g_hView = 0
	EndIf
	If $g_hGui Then GUIDelete($g_hGui)
	ConsoleWrite("FINAL " & $sState & @CRLF)
EndFunc   ;>__Pulse_Finish

; =============================================================================
; Self test:  bash tests/one.sh <interpreter> Pulse.au3 --auto
;
;   No window and no second process. Everything the loop does with a frame is
;   exercised by handing __Pulse_Ingest the exact bytes an agent would put on the
;   wire, then reading the ring, the tree, the bus and the .cfb back out. The
;   socket half is tests/gate.sh, which starts the console and the demo agents as
;   separate processes, because a listener cannot answer itself.
; =============================================================================
Func __Pulse_SelfTest()
	Local $iOk = 0, $iKo = 0
	$g_bHeadless = True
	$g_sOutDir = @ScriptDir & "\out"
	DirCreate($g_sOutDir)
	$g_sSession = "selftest-" & @AutoItPID & (@AutoItX64 ? "-x64" : "-x86")
	$g_sCfbPath = $g_sOutDir & "\Pulse_" & $g_sSession & ".cfb"
	If FileExists($g_sCfbPath) Then FileDelete($g_sCfbPath)
	ReDim $g_aR[$g_iRingCap][7]
	ReDim $g_aConn[$g_iWspSlots]
	$g_mSrcN = __Pulse_Map()
	$g_mSrcErr = __Pulse_Map()
	$g_mSrcPid = __Pulse_Map()
	$g_mWorst = __Pulse_Map()
	$g_mName = __Pulse_Map()

	__Pulse_BootBus()
	Tree_Create("events")
	; The bounds, printed rather than remembered: README.md quotes this line, so a
	; changed constant shows up as a contradiction instead of a silent lie. The
	; agent's own frame cap lives in Pulse_Agent.au3 and is quoted there.
	ConsoleWrite("bounds ring=" & $g_iRingCap & " perTurn=" & $g_iMaxPerTurn & " tree=" & $g_iTreeCap & _
			" frame=" & $g_iFrameCap & " commitMs=" & $g_iCommitMs & " grabMs=" & $g_iGrabMs & _
			" uiRows=" & $g_iUiRows & " uiTicks=" & $g_iUiTicks & " escalateMs=" & $g_iEscalateMs & _
			" treeRows=" & $g_iTreeRows & " slots=" & $g_iWspSlots & @CRLF)
	__Pulse_BootArchive()
	If $g_hCF < 1 Then
		ConsoleWrite("FATAL no archive: " & $g_sLastErr & @CRLF)
		_WinEvent_Shutdown()
		Return SetError(1, 0, False)
	EndIf
	Local $sBase = "Sessions\" & $g_sSession
	Local $bEmptyArchive = __Pulse_Commit()
	Local $mEmptyMan[]
	If _CF_Exists($g_hCF, $sBase & "\journal.txt") <> $CF_TYPE_STREAM Or _
			_CF_Exists($g_hCF, $sBase & "\Index\tree.txt") <> $CF_TYPE_STREAM Or _
			_CF_Exists($g_hCF, $sBase & "\events.ndjson") <> $CF_TYPE_STREAM Then $bEmptyArchive = False
	If Not _Pulse_JParse(String(_CF_ReadStream($g_hCF, $sBase & "\Manifest.json", $CF_TEXT)), $mEmptyMan) Then
		$bEmptyArchive = False
	ElseIf Number(_Pulse_JGet($mEmptyMan, "events_archive")) <> 0 Then
		$bEmptyArchive = False
	EndIf

	; --- the frames, exactly as they arrive on the wire ----------------------
	Local $aFrames[6]
	$aFrames[0] = '{"v":1,"name":"Build.Compile.Start","src":"Demo","lvl":"info"}'
	$aFrames[1] = '{"v":1,"name":"Build.Compile.Step","src":"Demo","lvl":"ok","ms":812,"txt":"37 units"}'
	$aFrames[2] = '{"v":1,"name":"Build.Link.Fail","src":"Demo","lvl":"error","txt":"unresolved symbol _Foo"}'
	$aFrames[3] = '{"v":1,"name":"Net.Connect","src":"Other","lvl":"warn","files":7,"path":"C:\\Temp"}'
	$aFrames[4] = '{"v":1,"name":"Net.Ping","src":"Other","lvl":"info"}'
	$aFrames[5] = '{"name":"Nested.Is.Text","src":"Demo","lvl":"info","txt":"kept as raw","blob":"{\"a\":[1,2]}"}'
	Local $i, $bAll = True
	For $i = 0 To UBound($aFrames) - 1
		If Not __Pulse_Ingest($aFrames[$i]) Then $bAll = False
	Next
	_WinEvent_Process(0)

	If $bAll And $g_iSeq = 6 And $bEmptyArchive Then
		$iOk += 1
		ConsoleWrite("  ok    empty archive has all streams and count 0; six frames ingested, ring holds " & __Pulse_RingRows() & @CRLF)
	Else
		$iKo += 1
		ConsoleWrite("  FAIL  ingest: " & $g_sLastErr & " rows=" & $g_iSeq & " emptyArchive=" & $bEmptyArchive & @CRLF)
	EndIf

	; A frame that is not an object, and a frame with no name, must be refused and
	; said so: silence here would lose events nobody ever sees again.
	Local $bRefused = Not __Pulse_Ingest('[1,2,3]')
	Local $bNoName = Not __Pulse_Ingest('{"src":"Demo","lvl":"info"}')
	If $bRefused And $bNoName And $g_iRejected = 2 Then
		$iOk += 1
		ConsoleWrite("  ok    two bad frames refused, rejected=" & $g_iRejected & @CRLF)
	Else
		$iKo += 1
		ConsoleWrite("  FAIL  refusal " & $bRefused & "/" & $bNoName & " rejected=" & $g_iRejected & @CRLF)
	EndIf
	_WinEvent_Process(0)

	; --- the index of names --------------------------------------------------
	; Build.Compile must carry the two events under it, not one, and Build must
	; carry all three of its children: that is the aggregation the panel claims.
	Local $idC = Tree_Find("Build.Compile"), $idB = Tree_Find("Build")
	If $idC > 0 And Number(Tree_GetData($idC)) = 2 And Number(Tree_GetData($idB)) = 3 Then
		$iOk += 1
		ConsoleWrite("  ok    subtree counts: Build=" & Tree_GetData($idB) & " Build.Compile=" & Tree_GetData($idC) & _
				" over " & Tree_Count() & " nodes" & @CRLF)
	Else
		$iKo += 1
		ConsoleWrite("  FAIL  subtree counts Build=" & Tree_GetData($idB) & " Compile=" & Tree_GetData($idC) & @CRLF)
	EndIf
	; The worst level seen below a branch rides up, so Build is red because of
	; Build.Link.Fail and not because of anything the page decided.
	If Number(__Pulse_MapGet($g_mWorst, $idB, "0")) = 4 Then
		$iOk += 1
		ConsoleWrite("  ok    the error under Build coloured the whole branch" & @CRLF)
	Else
		$iKo += 1
		ConsoleWrite("  FAIL  branch level " & __Pulse_MapGet($g_mWorst, $idB, "0") & @CRLF)
	EndIf
	; A nested value must have survived as text: that is the documented deal.
	__Pulse_FindRow("Nested.Is.Text")
	If @error Or StringInStr(__Pulse_RowTxt(), "blob=") = 0 Then
		$iKo += 1
		ConsoleWrite("  FAIL  nested frame lost -> [" & __Pulse_RowTxt() & "]" & @CRLF)
	Else
		$iOk += 1
		ConsoleWrite("  ok    nested value carried as text: " & __Pulse_RowTxt() & @CRLF)
	EndIf
	; The caller's own keys must be on the row.
	__Pulse_FindRow("Net.Connect")
	If @error Or StringInStr(__Pulse_RowTxt(), "files=7") = 0 Then
		$iKo += 1
		ConsoleWrite("  FAIL  extra fields lost -> [" & __Pulse_RowTxt() & "]" & @CRLF)
	Else
		$iOk += 1
		ConsoleWrite("  ok    custom fields kept on the row: " & __Pulse_RowTxt() & @CRLF)
	EndIf

	; --- the ring ------------------------------------------------------------
	; Over the cap the oldest rows are gone and the newest are intact, which is
	; what makes a fixed memory cost worth defending. This goes through the whole
	; path -- decode, post, dispatch, count, index -- because a number measured on
	; a bypass would only describe the bypass.
	Local $iBefore = $g_iSeq, $iShedBefore = $g_iShed, $tStress = TimerInit()
	For $i = 1 To $g_iRingCap + 50
		__Pulse_Ingest('{"v":1,"name":"Stress.Row.' & $i & '","src":"SelfTest","lvl":"debug","txt":"ring"}')
		; Exactly what the loop does: a drain between batches, not one at the end.
		; With a single drain at the end the bus queue (1000) overflows and the
		; frames the socket already accepted are lost -- measured, and the reason
		; $g_iShed is asserted here instead of merely printed.
		If Mod($i, 250) = 0 Then _WinEvent_Process(0)
	Next
	_WinEvent_Process(0)
	Local $iStressMs = Int(TimerDiff($tStress))
	If __Pulse_RingRows() = $g_iRingCap And $g_iSeq = $iBefore + $g_iRingCap + 50 And $g_iShed = $iShedBefore Then
		$iOk += 1
		ConsoleWrite("  ok    " & ($g_iSeq - $iBefore) & " frames end to end in " & $iStressMs & " ms (" & _
				Round(($g_iSeq - $iBefore) / ($iStressMs / 1000 + 0.0001)) & "/s), none shed, ring stays at " & _
				__Pulse_RingRows() & " and keeps the newest" & @CRLF)
	Else
		$iKo += 1
		ConsoleWrite("  FAIL  ring rows=" & __Pulse_RingRows() & " of cap " & $g_iRingCap & _
				" seen +" & ($g_iSeq - $iBefore) & " shed +" & ($g_iShed - $iShedBefore) & @CRLF)
	EndIf

	; --- the bus -------------------------------------------------------------
	Local $nSrc = UBound(MapKeys($g_mSrcN))
	Local $sPid = '123 "<img src=x onerror=alert(1)>" \agent'
	$g_mSrcPid["Demo"] = $sPid
	Local $sSrcs = __Pulse_SrcsJson()
	If $nSrc >= 2 And Number(__Pulse_MapGet($g_mSrcErr, "Demo", "0")) = 1 And _
			StringInStr($sSrcs, '["Demo",' & _Pulse_JQuote($sPid)) > 0 Then
		$iOk += 1
		ConsoleWrite("  ok    " & $nSrc & " sources counted, Demo has 1 error, PID text is JSON-escaped" & @CRLF)
	Else
		$iKo += 1
		ConsoleWrite("  FAIL  sources=" & $nSrc & " DemoErr=" & __Pulse_MapGet($g_mSrcErr, "Demo", "0") & _
				" srcs=" & StringLeft($sSrcs, 160) & @CRLF)
	EndIf
	; What an event nobody takes becomes. The console's own catch-all handlers
	; accept everything, and WinEventManager counts an event delivered as soon as
	; one handler takes it, so the only honest way to reach the dead-letter store
	; is to lift those handlers off the bus first: routing is by subscription, not
	; by name. Then the refusing sink is the sole subscriber and the budget runs
	; out for real.
	__Pulse_UnbootBus()
	_WinEvent_RegisterHandler("Demo.Archive.*", "__Pulse_HRefuse", 10, 2)
	_WinEvent_Post("Demo.Archive.Old", "a payload nobody takes")
	_WinEvent_Post("Demo.Archive.AlsoOld", "a second one")
	Local $iRound = 0
	While _WinEvent_DeadLettered() < 2 And $iRound < 20
		_WinEvent_Process(0)
		$iRound += 1
	WEnd
	Local $nDead = _WinEvent_DeadLettered()
	_WinEvent_UnregisterHandler("Demo.Archive.*", "__Pulse_HRefuse")
	__Pulse_BootBus()
	If $nDead = 2 Then
		Local $aDead = _WinEvent_DeadLetter(1)
		$iOk += 1
		ConsoleWrite("  ok    dead letters " & $nDead & " after " & $iRound & " drains: [" & $aDead[1] & _
				"] reason " & $aDead[3] & " attempts " & $aDead[4] & @CRLF)
	Else
		$iKo += 1
		ConsoleWrite("  FAIL  dead letters " & $nDead & " after " & $iRound & " drains, queue " & _WinEvent_Queued() & @CRLF)
	EndIf
	; The catch-alls are back, so a normal event is accepted again on the first try.
	Local $iSeqBefore = $g_iSeq
	_WinEvent_Post("Build.Restored", __Pulse_MakeRow("Build.Restored", "info"))
	_WinEvent_Process(0)
	If _WinEvent_DeadLettered() = 2 And $g_iSeq = $iSeqBefore + 1 Then
		$iOk += 1
		ConsoleWrite("  ok    handlers restored, the next event was accepted at once" & @CRLF)
	Else
		$iKo += 1
		ConsoleWrite("  FAIL  restore: dead=" & _WinEvent_DeadLettered() & " rows +" & ($g_iSeq - $iSeqBefore) & @CRLF)
	EndIf

	; --- escalation ----------------------------------------------------------
	; Same call the error handler makes. A failure here is a real limit, so the
	; line says what happened instead of passing quietly.
	_WinEvent_Write("Pulse self test entry", "", $WINEVENT_TYPE_INFORMATION, 0, 1000)
	If @error Then
		$iKo += 1
		ConsoleWrite("  FAIL  event log write @error " & @error & " extended " & @extended & @CRLF)
	Else
		$iOk += 1
		ConsoleWrite("  ok    an entry went to the Windows Event Log" & @CRLF)
	EndIf

	; The tree message is the one place the console and the page agree only by
	; convention: onTree walks the array with i += 3, so a bracket per node renders
	; nothing at all and every headless test stays green. The shape is asserted here
	; instead of being looked for in a screenshot.
	$g_sTreeBuf = ""
	$g_iTreeSeen = 0
	Tree_Walk("__Pulse_TreeEmit")
	; Two quoted fields per node (name and level), so the quote count says the shape
	; without depending on a parser that would accept either spelling.
	Local $iQuotes = StringLen($g_sTreeBuf) - StringLen(StringReplace($g_sTreeBuf, '"', ""))
	$g_bDirtyStream = False
	$g_bDirtySide = False
	__Pulse_OnWebMessage(0, 0, '{"k":"ready"}', 0)
	If $g_iTreeSeen > 1 And StringLeft($g_sTreeBuf, 1) = '"' And StringRight($g_sTreeBuf, 1) = '"' And _
			StringInStr($g_sTreeBuf, "],[") = 0 And $iQuotes = 4 * $g_iTreeSeen And _
			$g_iSent = 0 And $g_bDirtyStream And $g_bDirtySide Then
		$iOk += 1
		ConsoleWrite("  ok    tree message is " & $g_iTreeSeen & " flat triples; ready requests a full refresh" & @CRLF)
	Else
		$iKo += 1
		ConsoleWrite("  FAIL  tree/page contract: rows=" & $g_iTreeSeen & " quotes=" & $iQuotes & _
				" sent=" & $g_iSent & " dirty=" & $g_bDirtyStream & "/" & $g_bDirtySide & @CRLF)
	EndIf

	; --- the archive ---------------------------------------------------------
	__Pulse_Commit()
	Local $sMan = _CF_ReadStream($g_hCF, $sBase & "\Manifest.json", $CF_TEXT)
	Local $mMan[]
	If _Pulse_JParse($sMan, $mMan) And Number(_Pulse_JGet($mMan, "events_seen")) >= $g_iSeq And _
			Number(_Pulse_JGet($mMan, "events_archive")) = __Pulse_RingRows() And _
			Number(_Pulse_JGet($mMan, "dead_letters")) >= 1 Then
		$iOk += 1
		ConsoleWrite("  ok    Manifest.json reads back with " & _Pulse_JGet($mMan, "events_archive") & _
				" archived rows and " & _Pulse_JGet($mMan, "dead_letters") & " dead letters" & @CRLF)
	Else
		$iKo += 1
		ConsoleWrite("  FAIL  Manifest.json -> [" & StringLeft($sMan, 220) & "]" & @CRLF)
	EndIf
	If _CF_Exists($g_hCF, $sBase & "\journal.txt") = $CF_TYPE_STREAM And _
			_CF_Exists($g_hCF, $sBase & "\Index\tree.txt") = $CF_TYPE_STREAM Then
		$iOk += 1
		ConsoleWrite("  ok    the archive holds journal, name index, events and manifest" & @CRLF)
	Else
		$iKo += 1
		ConsoleWrite("  FAIL  a stream is missing: " & _CF_GetLastErrorMessage() & @CRLF)
	EndIf
	; The ring tail must read back as NDJSON, one object per line, every line
	; parsing. A count that does not match is reported, not rounded away.
	Local $sNd = String(_CF_ReadStream($g_hCF, $sBase & "\events.ndjson", $CF_AUTO))
	Local $aNd = StringSplit(StringStripCR($sNd), @LF, 2)
	Local $j, $mRow[], $iGood = 0
	For $j = 0 To UBound($aNd) - 1
		If $aNd[$j] = "" Then ContinueLoop
		$mRow = __Pulse_Map()
		If _Pulse_JParse($aNd[$j], $mRow) Then $iGood += 1
	Next
	If $iGood = __Pulse_RingRows() And $iGood > 0 Then
		$iOk += 1
		ConsoleWrite("  ok    events.ndjson: " & $iGood & " lines, all parse" & @CRLF)
	Else
		$iKo += 1
		ConsoleWrite("  FAIL  events.ndjson parsed " & $iGood & " of " & __Pulse_RingRows() & @CRLF)
	EndIf
	; The exported index must still be inside the archive and still describe the
	; same tree: the TREE1 header, then one row per node. The row count is compared
	; with what the commit recorded, not with the live tree, because the self test
	; keeps inventing event names after the commit and every one of them is a node.
	; (StringSplit with flag 6 also returns the empty field after the final @LF, so
	; the raw line count is one more than the rows; empties are skipped here.)
	Local $sTree = String(_CF_ReadStream($g_hCF, $sBase & "\Index\tree.txt", $CF_AUTO))
	Local $aTree = StringSplit(StringStripCR($sTree), @LF, 6)
	Local $k, $iHdr = 0, $iRowsArch = 0
	For $k = 0 To UBound($aTree) - 1
		If $aTree[$k] = "" Then ContinueLoop
		If $aTree[$k] = "TREE1" Then
			$iHdr += 1
		Else
			$iRowsArch += 1
		EndIf
	Next
	If $iHdr = 1 And $aTree[0] = "TREE1" And $iRowsArch = $g_iArchRows And _
			$g_iArchRows = $g_iArchNodes And $g_iArchRows > 1 Then
		$iOk += 1
		ConsoleWrite("  ok    Index\tree.txt carries " & $iRowsArch & " rows for the " & $g_iArchNodes & _
				" nodes live at commit, in " & FileGetSize($g_sCfbPath) & " bytes of .cfb" & @CRLF)
	Else
		$iKo += 1
		ConsoleWrite("  FAIL  Index\tree.txt: [" & StringLeft($sTree, 40) & "] rows " & $iRowsArch & _
				" headers " & $iHdr & " first[" & $aTree[0] & "] written@" & $g_iArchRows & "/" & $g_iArchNodes & _
				" live=" & Tree_Count() & " valid=" & Tree_Validate() & "/" & @error & " " & _CF_GetLastErrorMessage() & @CRLF)
	EndIf
	; The journal is the bus's own account of the run, and it must be non-empty.
	Local $sJr = String(_CF_ReadStream($g_hCF, $sBase & "\journal.txt", $CF_AUTO))
	If StringInStr($sJr, "DISPATCHED") > 0 And StringLen($sJr) > 40 Then
		$iOk += 1
		ConsoleWrite("  ok    journal.txt carries the dispatch rows (" & StringLen($sJr) & " bytes)" & @CRLF)
	Else
		$iKo += 1
		ConsoleWrite("  FAIL  journal.txt -> [" & StringLeft($sJr, 120) & "]" & @CRLF)
	EndIf

	; Reopening what was just written is the only proof the bytes are on disk. This
	; comes last because closing the handle would take every read above with it.
	Local $iSize = FileGetSize($g_sCfbPath)
	_CF_Close($g_hCF)
	$g_hCF = -1
	Local $h2 = _CF_Open($g_sCfbPath)
	If $h2 >= 1 And _CF_Exists($h2, $sBase & "\Manifest.json") = $CF_TYPE_STREAM Then
		$iOk += 1
		ConsoleWrite("  ok    " & $iSize & " byte .cfb reopens with its manifest, journal, index and events" & @CRLF)
	Else
		$iKo += 1
		ConsoleWrite("  FAIL  the .cfb does not reopen (" & $iSize & " bytes) @error " & @error & " " & _CF_GetLastErrorMessage() & @CRLF)
	EndIf
	If $h2 >= 1 Then _CF_Close($h2)

	_WinEvent_Shutdown()
	ConsoleWrite("RESULT ok=" & $iOk & " fail=" & $iKo & @CRLF)
	Return SetError(($iKo > 0) ? 1 : 0, 0, $iKo = 0)
EndFunc   ;>__Pulse_SelfTest

Func __Pulse_Map()
	Local $m[]
	Return $m
EndFunc   ;>__Pulse_Map

Func __Pulse_MakeRow($sName, $sLvl)
	Local $a[7]
	$a[0] = @HOUR & ":" & @MIN & ":" & @SEC
	$a[1] = $sLvl
	$a[2] = $sName
	$a[3] = "SelfTest"
	$a[4] = ""
	$a[5] = ""
	$a[6] = 0
	Return $a
EndFunc   ;>__Pulse_MakeRow

Func __Pulse_FindRow($sName)
	Local $i, $iFirst = __Pulse_RingFirst(), $iN = __Pulse_RingRows()
	For $i = $iFirst + $iN - 1 To $iFirst Step -1
		If $g_aR[Mod($i, $g_iRingCap)][2] = $sName Then
			$g_iRowIdx = Mod($i, $g_iRingCap)
			Return SetError(0, 0, True)
		EndIf
	Next
	Return SetError(1, 0, False)
EndFunc   ;>__Pulse_FindRow

Func __Pulse_RowTxt()
	Return ($g_iRowIdx >= 0 ? $g_aR[$g_iRowIdx][5] : "")
EndFunc   ;>__Pulse_RowTxt
