; =============================================================================
; demo_build.au3 -- a pretend build pipeline wired to Pulse.
;
;   Run the console first, then this:
;       Pulse.au3
;       Examples\demo_build.au3
;   They are ordinary separate processes; the only link between them is
;   ws://127.0.0.1:48411/stream.
;
;   Switches
;     --port N    talk to a console listening on another port
;     --loops N   how many build cycles to run (default 3)
;     --ms N      sleep inside each stage, in ms (default 400)
;
;   Without a console this script still works: _Pulse_Attach fails once, the
;   later sends cost nothing, and the same lines go to stdout -- which is what a
;   build log is for anyway.
; =============================================================================
#include "../Pulse_Agent.au3"

Local $iPort = 48411, $iLoops = 3, $iStepMs = 400
Local $k
For $k = 1 To $CmdLine[0]
	Switch $CmdLine[$k]
		Case "--port"
			$k += 1
			If $k <= $CmdLine[0] Then $iPort = Number($CmdLine[$k])
		Case "--loops"
			$k += 1
			If $k <= $CmdLine[0] Then $iLoops = Number($CmdLine[$k])
		Case "--ms"
			$k += 1
			If $k <= $CmdLine[0] Then $iStepMs = Number($CmdLine[$k])
	EndSwitch
Next

Local $sUrl = "ws://127.0.0.1:" & $iPort & "/stream"
Local $bLive = _Pulse_Attach("DemoBuild", $sUrl)
__Say("attach " & ($bLive ? "ok -> " & $sUrl : "no console listening, logging locally only"))

Local $aStages[5] = ["Fetch", "Compile", "Link", "Test", "Package"]
Local $iSent = 0, $tAll = TimerInit()
Local $j, $i, $mCfg[], $mEnd[]

For $j = 1 To $iLoops
	Local $tRun = TimerInit(), $iDone = 0
	$iSent += __Emit("Build.Start", "cycle " & $j, "info")
	$mCfg["cycle"] = $j
	$mCfg["branch"] = "main"
	$mCfg["runner"] = @ComputerName
	$iSent += __EmitData("Build.Config", $mCfg)
	For $i = 0 To UBound($aStages) - 1
		Local $t = TimerInit()
		Sleep($iStepMs)
		Local $sName = "Build." & $aStages[$i]
		Local $iMs = Int(TimerDiff($t))
		If $i = 1 Then
			; A warning that does not stop the run ...
			$iSent += __Emit($sName, "37 units, 2 rebuilt", "warn", $iMs)
		ElseIf $i = 3 And $j = $iLoops Then
			; ... and a stage that does stop the last one.
			$iSent += __Emit($sName, "assert Unit.Math.Round failed in tests\math.au3:118", "error", $iMs)
			ExitLoop
		Else
			$iSent += __Emit($sName, "done", "ok", $iMs)
		EndIf
		$iDone += 1
	Next
	$mEnd["cycle"] = $j
	$mEnd["stages"] = $iDone
	$iSent += __EmitData("Build.Done", $mEnd, ($iDone = UBound($aStages) ? "ok" : "error"), Int(TimerDiff($tRun)))
Next

$iSent += __Emit("Build.Summary", $iLoops & " cycles, " & $iSent & " events", "info", Int(TimerDiff($tAll)))
__Say("events handed to the agent: " & $iSent & "  (" & _Pulse_Stats() & ")")
_Pulse_Detach("demo finished")

Func __Emit($sName, $sTxt, $sLvl, $iMs = -1)
	__Say($sLvl & "  " & $sName & ($iMs >= 0 ? " (" & $iMs & " ms)" : "") & "  " & $sTxt)
	_Pulse_Send($sName, $sTxt, $sLvl, $iMs)
	Return 1
EndFunc   ;>__Emit

Func __EmitData($sName, ByRef $m, $sLvl = "info", $iMs = -1)
	__Say($sLvl & "  " & $sName & "  " & _Pulse_JBuild($m))
	_Pulse_SendData($sName, $m, $sLvl, $iMs)
	Return 1
EndFunc   ;>__EmitData

Func __Say($s)
	ConsoleWrite($s & @CRLF)
EndFunc   ;>__Say
