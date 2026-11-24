; =============================================================================
; Pulse_Agent.au3 -- two lines in any AutoIt script, and that script appears
;                    live in the Pulse console.
;
;     #include "C:\path\to\Pulse\Pulse_Agent.au3"
;     _Pulse_Attach("NightlyBackup")
;     _Pulse_Send("Backup.Start", "share \\nas\backup")
;     ; ... the work happens here ...
;     _Pulse_Send("Backup.Done", "142 files", "ok", 38120)
;
; What it is: a WebSocket client on layer 4 of the WebSocket UDF, one text frame
; per event, flat JSON. Nothing else. The agent deliberately carries no
; WinEventManager, no Tree and no CompoundFile: an instrument must not be able
; to crash the thing it measures. If Pulse is not running, every call here costs
; one connect attempt and then goes quiet.
;
; Named limits of this include:
;   * one connection per process, and the console holds at most $g_iWspSlots (8)
;     connections, so eight agents fill the box. A ninth attach fails and the
;     host script does not notice.
;   * the console does not run this include against itself. _WS_Connect waits
;     for the server's 101, and a listener in the same process cannot answer
;     itself until it is serviced; the console posts its own events on the
;     WinEventManager bus instead.
;   * a frame is capped at $PULSE_MAX_FRAME bytes. A longer payload is trimmed
;     and the frame carries "truncated":"1" so the console shows it was cut.
;   * _Pulse_Attach blocks up to $g_iPulseBudgetMs (1200 ms) when nothing
;     listens. Attach once at start-up, not in a loop.
;   * a script that never attached pays one retry per $g_iPulseRetryMs (15 s), except
;     during the first $g_iPulseGraceMs (20 s) of its own life, when the gap is
;     $g_iPulseGraceGapMs (2 s). The exception exists because the console cannot
;     answer a handshake while its browser boots (8.7 s measured for a fresh
;     profile): a demo launched next to Pulse is refused once and has to try again
;     before its own run is over. Against a truly closed port a refusal is
;     immediate, so the grace window costs time only when something is listening.
;   * the agent never reads. What the console sends back stays in the socket
;     buffer until the close, which costs the 64 KB receive buffer and nothing
;     else.
;
; Author : Numeric1 -- Licence : MIT (Copyright (c) 2026 Numeric1)
; =============================================================================

#include-once
#include "Lib/WebSocket.au3"
#include "Pulse_Json.au3"

Global Const $PULSE_DEFAULT_URL = "ws://127.0.0.1:48411/stream"
Global Const $PULSE_MAX_FRAME = 4000 ; bytes of JSON handed to one text frame
Global Const $PULSE_MAX_NAME = 128   ; characters of an event name
Global $g_hPulseAgent = -1 ; layer 3 slot index; 0 is a valid handle
Global $g_sPulseSrc = ""
Global $g_sPulseUrl = $PULSE_DEFAULT_URL
Global $g_iPulseSent = 0, $g_iPulseLost = 0
Global $g_iPulseFlushMs = 250
Global $g_iPulseBudgetMs = 1200
Global $g_iPulseRetryMs = 15000
Global $g_tPulseNextTry = 0 ; one attempt per gap, no retry storm
Global $g_iPulseGraceMs = 20000 ; how long a process is allowed to be eager
Global $g_iPulseGraceGapMs = 2000 ; the gap during that window
Global $g_tPulseLife = TimerInit() ; when this process loaded the include
Global $g_bPulseAtExit = False

; Run this file by itself to exercise it over a real socket; --child is the
; spawned half of that test. The @ScriptName guard keeps either from firing when
; another script is launched with the same switch.
If @ScriptName = "Pulse_Agent.au3" And $CmdLine[0] >= 1 Then
	Switch $CmdLine[1]
		Case "--auto", "/auto"
			__Pulse_AgentSelfTest()
		Case "--child"
			__Pulse_AgentChild()
		EndSwitch
EndIf

; -----------------------------------------------------------------------------
; _Pulse_Attach
;   Open the connection. Calling it twice is allowed: the second call with the
;   same source is a no-op, so a library and its host script can both ask.
; Returns True on a live connection, False with @error from _WS_Connect.
; -----------------------------------------------------------------------------
Func _Pulse_Attach($sSource = "", $sUrl = $PULSE_DEFAULT_URL)
	$sSource = ($sSource = "" ? @AutoItExe : $sSource)
	If $g_hPulseAgent >= 0 And $g_sPulseSrc = $sSource And $g_sPulseUrl = $sUrl Then Return SetError(0, 0, True)
	If $g_hPulseAgent >= 0 Then _Pulse_Detach("reattach")
	If Not _WS_Startup() Then Return SetError(100, 0, False)
	$g_sPulseSrc = StringLeft($sSource, 64)
	$g_sPulseUrl = $sUrl
	$g_tPulseNextTry = TimerInit()
	Local $h = _WS_Connect($sUrl, $g_iPulseBudgetMs)
	Local $e = @error
	If $h < 0 Or $e <> 0 Then
		$g_iPulseLost += 1
		$g_hPulseAgent = -1
		Return SetError($e, $h, False)
	EndIf
	$g_hPulseAgent = $h
	If Not $g_bPulseAtExit Then
		$g_bPulseAtExit = True
		OnAutoItExitRegister("__Pulse_AgentAtExit")
	EndIf
	; The first frame says who this is, in fields rather than in prose, so the
	; console can label the process before it sends anything interesting.
	Local $m[]
	$m["v"] = 1
	$m["name"] = "Agent.Hello"
	$m["src"] = $g_sPulseSrc
	$m["lvl"] = "info"
	$m["pid"] = @AutoItPID
	$m["x64"] = @AutoItX64
	$m["aver"] = @AutoItVersion
	$m["script"] = @ScriptName
	$g_iPulseSent += 1
	__Pulse_SendRaw(_Pulse_JBuild($m))
	Return SetError(0, 0, True)
EndFunc   ;==>_Pulse_Attach

Func _Pulse_IsAttached()
	Return $g_hPulseAgent >= 0
EndFunc   ;==>_Pulse_IsAttached

; -----------------------------------------------------------------------------
; _Pulse_Send
;   One event. $sLevel is info, ok, warn, error or debug; $iMs >= 0 attaches a
;   duration, which is what makes a timeline readable.
; -----------------------------------------------------------------------------
Func _Pulse_Send($sName, $sTxt = "", $sLevel = "info", $iMs = -1)
	If $g_hPulseAgent < 0 And Not __Pulse_TryLate() Then Return SetError(1, 0, False)
	If Not __Pulse_SendRaw(__Pulse_Frame($sName, $sLevel, $iMs, $sTxt)) Then Return SetError(2, 0, False)
	Return True
EndFunc   ;==>_Pulse_Send

; -----------------------------------------------------------------------------
; _Pulse_SendData
;   The same, with the caller's own Map merged into the frame: every key of the
;   Map becomes a field. That is how a script passes counts, paths and ids
;   without anybody writing JSON by hand.
; -----------------------------------------------------------------------------
Func _Pulse_SendData($sName, $mData, $sLevel = "info", $iMs = -1)
	If $g_hPulseAgent < 0 And Not __Pulse_TryLate() Then Return SetError(1, 0, False)
	Local $sFrame = __Pulse_BuildData($sName, $mData, $sLevel, $iMs)
	If Not __Pulse_SendRaw($sFrame) Then Return SetError(2, 0, False)
	Return True
EndFunc   ;==>_Pulse_SendData

; The frame for the Map form, built apart from the send so the self test can
; read the exact bytes the wire would carry.
Func __Pulse_BuildData($sName, $mData, $sLevel, $iMs)
	Local $m[]
	If VarGetType($mData) = "Map" Then
		Local $aK = MapKeys($mData), $i
		For $i = 0 To UBound($aK) - 1
			$m[$aK[$i]] = $mData[$aK[$i]]
		Next
	ElseIf VarGetType($mData) = "Array" Then
		; A 2D key/value array is the other shape a developer already has.
		Local $i
		For $i = 0 To UBound($mData, 1) - 1
			$m[String($mData[$i][0])] = $mData[$i][1]
		Next
	EndIf
	__Pulse_FrameInto($m, $sName, $sLevel, $iMs, "")
	Local $sFrame = _Pulse_JBuild($m)
	If StringLen($sFrame) > $PULSE_MAX_FRAME Then
		; Too wide to carry as it is. The event still goes out, with the fields
		; that did not fit named but not sent: losing one row is worse than
		; losing the knowledge that a row happened.
		Local $iFields = UBound(MapKeys($m))
		Local $n[]
		__Pulse_FrameInto($n, $sName, $sLevel, $iMs, $iFields & " fields dropped, frame over " & $PULSE_MAX_FRAME & " bytes")
		$n["truncated"] = "1"
		$sFrame = _Pulse_JBuild($n)
		$g_iPulseLost += 1
	EndIf
	Return $sFrame
EndFunc   ;>__Pulse_BuildData

Func _Pulse_Stats()
	Return "sent=" & $g_iPulseSent & " lost=" & $g_iPulseLost & " handle=" & $g_hPulseAgent
EndFunc   ;==>_Pulse_Stats

; -----------------------------------------------------------------------------
; _Pulse_Detach
;   Close politely. The console records the goodbye as Agent.Gone.
; -----------------------------------------------------------------------------
Func _Pulse_Detach($sReason = "")
	If $g_hPulseAgent < 0 Then Return True
	If $sReason <> "" Then __Pulse_SendRaw(__Pulse_Frame("Agent.Gone", "info", -1, $sReason))
	_WS_Flush($g_hPulseAgent, 500)
	_WS_Close($g_hPulseAgent, 1000, "", 800)
	$g_hPulseAgent = -1
	Return True
EndFunc   ;==>_Pulse_Detach

Func __Pulse_AgentAtExit()
	If $g_hPulseAgent >= 0 Then _Pulse_Detach("exit")
EndFunc   ;>__Pulse_AgentAtExit

; -----------------------------------------------------------------------------
; internals
; -----------------------------------------------------------------------------
Func __Pulse_Level($s)
	$s = StringLower($s)
	Switch $s
		Case "ok", "warn", "error", "debug"
			Return SetError(0, 0, $s)
			Case "information", "info"
				Return SetError(0, 0, "info")
		Case Else
			Return SetError(1, 0, "info")
	EndSwitch
EndFunc   ;>__Pulse_Level

Func __Pulse_FrameInto(ByRef $m, $sName, $sLevel, $iMs, $sTxt)
	$m["v"] = 1
	$m["name"] = StringLeft($sName, $PULSE_MAX_NAME)
	$m["src"] = $g_sPulseSrc
	$m["lvl"] = __Pulse_Level($sLevel)
	If $iMs >= 0 Then $m["ms"] = $iMs
	If $sTxt <> "" Then
		If StringLen($sTxt) > $PULSE_MAX_FRAME - 200 Then
			$m["txt"] = StringLeft($sTxt, $PULSE_MAX_FRAME - 220)
			$m["truncated"] = "1"
		Else
			$m["txt"] = $sTxt
		EndIf
	EndIf
	$g_iPulseSent += 1
EndFunc   ;>__Pulse_FrameInto

Func __Pulse_Frame($sName, $sLevel, $iMs, $sTxt)
	Local $m[]
	__Pulse_FrameInto($m, $sName, $sLevel, $iMs, $sTxt)
	Return _Pulse_JBuild($m)
EndFunc   ;>__Pulse_Frame

; One frame out. A dead socket is noticed here and the handle is dropped, so the
; next call pays one connect attempt instead of a send on a closed slot.
Func __Pulse_SendRaw($sFrame)
	If $g_hPulseAgent < 0 Then
		$g_iPulseLost += 1
		Return False
	EndIf
	_WS_Pump($g_hPulseAgent, 0)
	_WS_Send($g_hPulseAgent, $sFrame)
	If @error Then
		$g_iPulseLost += 1
		_WS_CloseHandle($g_hPulseAgent)
		$g_hPulseAgent = -1
		Return False
	EndIf
	_WS_Flush($g_hPulseAgent, $g_iPulseFlushMs)
	If @error Then
		$g_iPulseLost += 1
		_WS_CloseHandle($g_hPulseAgent)
		$g_hPulseAgent = -1
		Return False
	EndIf
	Return True
EndFunc   ;>__Pulse_SendRaw

; The gap depends on how old this process is: eager while the console it was launched
; next to is still booting its browser, patient afterwards.
Func __Pulse_RetryGap()
	Return (TimerDiff($g_tPulseLife) < $g_iPulseGraceMs ? $g_iPulseGraceGapMs : $g_iPulseRetryMs)
EndFunc   ;>__Pulse_RetryGap

; A developer who never called _Pulse_Attach still gets connected the first time
; the console is up: at most one attempt per __Pulse_RetryGap().
Func __Pulse_TryLate()
	If TimerDiff($g_tPulseNextTry) < __Pulse_RetryGap() Then Return SetError(3, 0, False)
	$g_tPulseNextTry = TimerInit()
	_Pulse_Attach($g_sPulseSrc, $g_sPulseUrl)
	Local $e = @error
	If $e <> 0 Then Return SetError(1, $e, False)
	Return True
EndFunc   ;>__Pulse_TryLate

; -----------------------------------------------------------------------------
; Self test:  bash tests/one.sh <interpreter> Pulse_Agent.au3 --auto
;   Single process, no socket: it reads back the exact bytes each call would put
;   on the wire. The socket half is tests/agent_pair.sh, because _WS_Connect
;   waits for the server's 101 and a listener inside the same process can only
;   answer itself after a timeout.
; -----------------------------------------------------------------------------
Func __Pulse_AgentSelfTest()
	Local $iOk = 0, $iKo = 0
	$g_sPulseSrc = "SelfTest.Agent"

	; The plain frame: envelope, level, duration, text with the two characters
	; that need escaping.
	Local $m[]
	If Not _Pulse_JParse(__Pulse_Frame("Demo.Step", "warn", 1234, 'a "quote" and \ a slash' & @LF & "newline"), $m) Then
		$iKo += 1
		ConsoleWrite("  FAIL  plain frame does not parse back" & @CRLF)
	ElseIf _Pulse_JGet($m, "name") <> "Demo.Step" Or _Pulse_JGet($m, "src") <> "SelfTest.Agent" Or _
			_Pulse_JGet($m, "lvl") <> "warn" Or _Pulse_JGetInt($m, "ms") <> 1234 Or _
			_Pulse_JGet($m, "txt") <> 'a "quote" and \ a slash' & @LF & "newline" Then
		$iKo += 1
		ConsoleWrite("  FAIL  plain frame fields -> [" & _Pulse_JGet($m, "txt") & "]" & @CRLF)
	Else
		$iOk += 1
		ConsoleWrite("  ok    plain frame round trip" & @CRLF)
	EndIf

	; The Map frame keeps the caller's keys beside the envelope, numbers as
	; numbers, and never lets a caller overwrite the event name.
	Local $d[]
	$d["files"] = 7
	$d["path"] = "C:\Temp\a b"
	$d["quote"] = 'he said "hi"'
	$d["name"] = "caller must not win"
	Local $sFrame = __Pulse_BuildData("Demo.Build", $d, "ok", 42)
	$m = 0
	If _Pulse_JParse($sFrame, $m) And _Pulse_JGetInt($m, "files") = 7 And _Pulse_JGet($m, "path") = "C:\Temp\a b" And _
			_Pulse_JGet($m, "quote") = 'he said "hi"' And _Pulse_JGet($m, "name") = "Demo.Build" And _
			_Pulse_JGetInt($m, "ms") = 42 Then
		$iOk += 1
		ConsoleWrite("  ok    data frame, reserved keys won (" & StringLen($sFrame) & " bytes)" & @CRLF)
	Else
		$iKo += 1
		ConsoleWrite("  FAIL  data frame -> [" & $sFrame & "]" & @CRLF)
	EndIf

	; Wider than the cap: the envelope must still go out, saying what it lost.
	Local $k
	For $k = 1 To 90
		$d["field" & $k] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" & $k
	Next
	$sFrame = __Pulse_BuildData("Demo.Wide", $d, "warn", 7)
	$m = 0
	If StringLen($sFrame) <= $PULSE_MAX_FRAME And _Pulse_JParse($sFrame, $m) And _Pulse_JGet($m, "truncated") = "1" And _
			_Pulse_JGet($m, "lvl") = "warn" And StringInStr(_Pulse_JGet($m, "txt"), "fields dropped") > 0 Then
		$iOk += 1
		ConsoleWrite("  ok    wide frame trimmed to " & StringLen($sFrame) & " bytes and still describes itself" & @CRLF)
	Else
		$iKo += 1
		ConsoleWrite("  FAIL  wide frame (" & StringLen($sFrame) & " bytes) -> [" & $sFrame & "]" & @CRLF)
	EndIf

	; A level nobody defined must not reach the wire as itself.
	If __Pulse_Level("shout") = "info" And __Pulse_Level("ERROR") = "error" And __Pulse_Level("information") = "info" Then
		$iOk += 1
		ConsoleWrite("  ok    level map normalises" & @CRLF)
	Else
		$iKo += 1
		ConsoleWrite("  FAIL  level map kept [" & __Pulse_Level("shout") & "]" & @CRLF)
	EndIf

	; Nothing listening: the call must fail quietly, and must not be slow. The
	; two numbers printed here are the ones the README quotes.
	$g_hPulseAgent = -1
	$g_tPulseNextTry = TimerInit()
	$g_iPulseRetryMs = 0
	$g_iPulseBudgetMs = 500
	Local $t = TimerInit()
	Local $r = _Pulse_Send("Demo.Nobody")
	Local $eSend = @error, $msSend = TimerDiff($t)
	If $msSend < 4000 Then
		$iOk += 1
		ConsoleWrite("  ok    closed port costs " & Round($msSend) & " ms (budget " & $g_iPulseBudgetMs & _
				" ms), @error " & $eSend & @CRLF)
	Else
		$iKo += 1
		ConsoleWrite("  FAIL  send with no server took " & Round($msSend) & " ms" & @CRLF)
	EndIf

	; With a window armed, a second send must not pay for the connect again.
	$g_iPulseRetryMs = 15000
	$g_tPulseNextTry = TimerInit()
	$t = TimerInit()
	$r = _Pulse_Send("Demo.Nobody3")
	Local $eGate = @error
	Local $msGate = TimerDiff($t)
	If Not $r And $msGate < 50 Then
		$iOk += 1
		ConsoleWrite("  ok    retry gate refused the second attempt in " & Round($msGate) & " ms, @error " & $eGate & @CRLF)
	Else
		$iKo += 1
		ConsoleWrite("  FAIL  retry gate let an attempt through (" & Round($msGate) & " ms)" & @CRLF)
	EndIf

	; The schedule itself: eager while a console launched next to this process is
	; still booting its browser, patient once the process is old enough that a missing
	; console really is missing. The window is moved rather than the clock, because a
	; TimerInit value cannot be shifted into the past (measured: TimerDiff of
	; "TimerInit() - 20001" answers 2 ms, not 20001).
	Local $iAge = TimerDiff($g_tPulseLife), $iGrace = $g_iPulseGraceMs
	$g_iPulseGraceMs = $iAge + 60000
	Local $iGapYoung = __Pulse_RetryGap()
	$g_iPulseGraceMs = 0
	Local $iGapOld = __Pulse_RetryGap()
	$g_iPulseGraceMs = $iGrace
	If $iGapYoung = $g_iPulseGraceGapMs And $iGapOld = $g_iPulseRetryMs Then
		$iOk += 1
		ConsoleWrite("  ok    retry gap is " & $iGapYoung & " ms inside the " & $iGrace & " ms window, " & $iGapOld & " ms outside" & @CRLF)
	Else
		$iKo += 1
		ConsoleWrite("  FAIL  retry gap " & $iGapYoung & "/" & $iGapOld & @CRLF)
	EndIf

	ConsoleWrite("RESULT ok=" & $iOk & " fail=" & $iKo & @CRLF)
	Exit(($iKo > 0) ? 1 : 0)
EndFunc   ;>__Pulse_AgentSelfTest

; -----------------------------------------------------------------------------
; Child role for the pair test:  bash tests/one.sh <interpreter> Pulse_Agent.au3 --child 8000
;   $CmdLine[2] raises the handshake budget so the server process has time to
;   accept and answer the 101. It also prints every note on stdout, which is what
;   tests/agent_pair.sh reads.
; -----------------------------------------------------------------------------
Func __Pulse_AgentChild()
	$g_iPulseBudgetMs = ($CmdLine[0] >= 2 ? Number($CmdLine[2]) : 6000)
	If $g_iPulseBudgetMs < 1000 Then $g_iPulseBudgetMs = 6000
	Local $b = _Pulse_Attach("SelfTest.Child." & (@AutoItX64 ? "x64" : "x86"))
	ConsoleWrite("child attach=" & ($b ? 1 : 0) & " @error=" & @error & " extended=" & @extended & @CRLF)
	_Pulse_Send("Demo.Step", "middle of the run", "warn", 1234)
	Local $d[]
	$d["files"] = 7
	$d["path"] = "C:\Temp\a b"
	$d["quote"] = 'he said "hi"'
	_Pulse_SendData("Demo.Build", $d, "ok", 42)
	Local $k
	For $k = 1 To 90
		$d["field" & $k] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" & $k
	Next
	_Pulse_SendData("Demo.Wide", $d, "warn", 7)
	_Pulse_Detach("child over")
	ConsoleWrite("child " & _Pulse_Stats() & @CRLF)
	Exit 0
EndFunc   ;>__Pulse_AgentChild
