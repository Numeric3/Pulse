; =============================================================================
; demo_watch.au3 -- watches a folder and reports every change to Pulse.
;
;   Run the console first, then this:
;       Pulse.au3
;       Examples\demo_watch.au3 --path "C:\Users\me\projects" --seconds 60
;   and drop a file in that folder: the row appears in the console the next
;   poll, and the branch File.New grows in the name index.
;
;   Switches
;     --path DIR      folder to watch (default: the folder of this script)
;     --port N        console port (default 48411)
;     --every MS      poll interval (default 1000)
;     --seconds N     stop after N seconds (default 30; 0 = never)
;
;   This is a real watcher, not a recording: it walks the folder with
;   FileFindFirstFile, keeps "name|size|mtime" in a Map and diffs on the next
;   pass. Named limits: one folder level deep, no recursive watch, and a file
;   that changes between two polls is reported once, not twice.
; =============================================================================
#include "../Pulse_Agent.au3"

Local $sPath = @ScriptDir, $iPort = 48411, $iEvery = 1000, $iSeconds = 30
Local $k
For $k = 1 To $CmdLine[0]
	Switch $CmdLine[$k]
		Case "--path"
			$k += 1
			If $k <= $CmdLine[0] Then $sPath = $CmdLine[$k]
		Case "--port"
			$k += 1
			If $k <= $CmdLine[0] Then $iPort = Number($CmdLine[$k])
		Case "--every"
			$k += 1
			If $k <= $CmdLine[0] Then $iEvery = Number($CmdLine[$k])
		Case "--seconds"
			$k += 1
			If $k <= $CmdLine[0] Then $iSeconds = Number($CmdLine[$k])
	EndSwitch
Next
If $iEvery < 100 Then $iEvery = 100

Local $sUrl = "ws://127.0.0.1:" & $iPort & "/stream"
Local $bLive = _Pulse_Attach("DemoWatch", $sUrl)
__Say("attach " & ($bLive ? "ok -> " & $sUrl : "no console listening, logging locally only"))
__Say("watch " & $sPath & " every " & $iEvery & " ms for " & $iSeconds & " s")

Local $mNow[], $mOld[], $iPass = 0, $iEvents = 0
Local $tStart = TimerInit()

While 1
	$mNow = __Scan($sPath)
	$iPass += 1
	$iEvents += __Diff($mOld, $mNow, $iPass)
	If $iPass = 1 Or Mod($iPass, 5) = 0 Then
		; A periodic sample of the watcher itself, so an empty console can be told
		; apart from a quiet folder.
		If $iPass > 1 Then
			Local $mBeat[]
			$mBeat["pass"] = $iPass
			$mBeat["files"] = UBound(MapKeys($mNow))
			$mBeat["events"] = $iEvents
			_Pulse_SendData("Watch.Heartbeat", $mBeat, "debug")
			$iEvents += 1
		EndIf
	EndIf
	$mOld = $mNow
	If $iSeconds > 0 And TimerDiff($tStart) >= $iSeconds * 1000 Then ExitLoop
	Sleep($iEvery)
WEnd

__Say("stopped after " & $iPass & " passes, " & $iEvents & " events (" & _Pulse_Stats() & ")")
_Pulse_Detach("watcher stopped")

; One level, names only relative to the watched folder.
Func __Scan($sDir)
	Local $m[], $h = FileFindFirstFile($sDir & "\*")
	If $h = -1 Then Return $m
	While 1
		Local $s = FileFindNextFile($h)
		If @error Then ExitLoop
		If @extended Then ContinueLoop ; a subfolder: this demo stays one level deep
		Local $sFull = $sDir & "\" & $s
		$m[$s] = FileGetSize($sFull) & "|" & FileGetTime($sFull, 0, 1)
	WEnd
	FileClose($h)
	Return $m
EndFunc   ;>__Scan

Func __Diff(ByRef $mOld, ByRef $mNow, $iPass)
	Local $aK = MapKeys($mNow), $i, $s, $n = 0
	For $i = 0 To UBound($aK) - 1
		$s = $aK[$i]
		If Not MapExists($mOld, $s) Then
			_Pulse_Send("File.New", $s & " (" & $mNow[$s] & ")", "ok")
			$n += 1
		ElseIf $mOld[$s] <> $mNow[$s] Then
			_Pulse_Send("File.Changed", $s & " -> " & $mNow[$s], "warn")
			$n += 1
		EndIf
	Next
	Local $aO = MapKeys($mOld)
	For $i = 0 To UBound($aO) - 1
		$s = $aO[$i]
		If Not MapExists($mNow, $s) Then
			_Pulse_Send("File.Gone", $s, "error")
			$n += 1
		EndIf
	Next
	If $n = 0 Then __Say("pass " & $iPass & ": quiet, " & UBound($aK) & " files")
	Return $n
EndFunc   ;>__Diff


Func __Say($s)
	ConsoleWrite($s & @CRLF)
EndFunc   ;>__Say
