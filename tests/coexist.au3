; =============================================================================
; tests/coexist.au3 -- does one process carry all five UDFs at the same time?
;
; This runs BEFORE any application code, because a redeclared global between two
; includes kills the script at load time with no line number worth having. Each
; layer is then exercised with its cheapest real call, no GUI and no socket, so a
; failure here means the includes themselves clash and not the application.
;
; Run:  bash tests/one.sh <interpreter> tests/coexist.au3
; Author : Numeric1 -- Licence : MIT
; =============================================================================

#include "../Lib/WebView2.au3"
#include "../Lib/WebSocket.au3"
#include "../Lib/Tree.au3"
#include "../Lib/CompoundFile.au3"
#include "../Lib/WinEventManager.au3"

Opt("MustDeclareVars", 1)

Global $g_iOk = 0, $g_iKo = 0

Func _Say($s)
	ConsoleWrite($s & @CRLF)
EndFunc   ;==>_Say

Func _Check($b, $s)
	If $b Then
		$g_iOk += 1
		_Say("  ok    " & $s)
	Else
		$g_iKo += 1
		_Say("  FAIL  " & $s)
	EndIf
EndFunc   ;==>_Check

_Say("coexist: five includes, one process, pid " & @AutoItPID & ", x64=" & @AutoItX64)

; --- 1. the version of every layer, as loaded --------------------------------
_Say("== loaded versions ==")
Local $sLib = @ScriptDir & "/../Lib/"
_Say("  WebView2        " & $WV2_VERSION)
_Say("  Tree            " & $TREE_VERSION)
_Say("  CompoundFile    " & __Ver($sLib & "CompoundFile.au3"))
_Say("  WebSocket       " & __Ver($sLib & "ws.au3") & " (ws " & FileGetSize($sLib & "ws.au3") & _
		" bytes, wsp " & FileGetSize($sLib & "wsp.au3") & ", tls " & FileGetSize($sLib & "tls.au3") & _
		", wsk " & FileGetSize($sLib & "wsk.au3") & ")")
_Say("  WinEventManager " & __Ver($sLib & "WinEventManager.au3"))

Func __Ver($sFile)
	Local $h = FileOpen($sFile, 0)
	If $h = -1 Then Return "?unreadable"
	Local $i, $l, $p, $a
	For $i = 0 To 15
		$l = FileReadLine($h)
		If @error Then ExitLoop
		; The marker is a header line such as "; Version ........: 1.4.1 (notes...)".
		; "AutoIt Version" is skipped: it names the interpreter the file wants, not itself.
		If StringInStr($l, "AutoIt Version") Then ContinueLoop
		$p = StringInStr($l, "Version")
		If $p = 0 Then ContinueLoop
		$l = StringMid($l, $p + 7)
		$p = StringInStr($l, ":")
		If $p = 0 Then ContinueLoop
		$l = StringStripWS(StringMid($l, $p + 1), 3)
		$a = StringSplit($l, " ", 2)
		FileClose($h)
		Return $a[0]
	Next
	FileClose($h)
	Return "?none"
EndFunc   ;>__Ver

; --- 2. WebView2: runtime present, no view created ---------------------------
_Say("== WebView2 ==")
Local $sRt = _WV2_GetRuntimePath()
_Check($sRt <> "", "_WV2_GetRuntimePath -> " & $sRt)

; --- 3. WebSocket: layer 1..4 up and down ------------------------------------
_Say("== WebSocket ==")
Local $bWs = _WS_Startup()
Local $eWs = @error
_Check($bWs <> 0 And $eWs = 0, "_WS_Startup")
Local $bCl = _WS_Cleanup()
_Say("  slots=" & $g_iWspSlots & "  cleanup=" & $bCl & "/" & @error)

; --- 4. Tree: build, find, count ---------------------------------------------
_Say("== Tree ==")
Tree_Create("root")
Local $iA = Tree_AddPath("App.Bus.Post", ".")
Local $eA = @error
_Say("  root=" & Tree_Root() & " count=" & Tree_Count())
_Check($iA > 0 And $eA = 0, "Tree_AddPath('App.Bus.Post') -> id " & $iA)
Local $iF = Tree_Find("Post")
_Check($iF = $iA, "Tree_Find('Post') -> " & $iF & " (expected " & $iA & ")")
Local $iSize = Tree_SubtreeSize(Tree_Root())
_Check($iSize = Tree_Count(), "Tree_SubtreeSize(root)=" & $iSize & " count=" & Tree_Count() & " (both must agree)")

; --- 5. CompoundFile: create, write, read, close, delete ---------------------
_Say("== CompoundFile ==")
Local $sCfb = @ScriptDir & "/../out/_coexist.cfb"
FileDelete($sCfb)
Local $hCF = _CF_Create($sCfb)
Local $eCF = @error
If Not (IsInt($hCF) And $hCF > 0) Then _Say("  step=" & $eCF & " :: " & _CF_GetLastErrorMessage())
_Check(IsInt($hCF) And $hCF > 0, "_CF_Create -> " & $hCF)
If IsInt($hCF) And $hCF > 0 Then
	_Check(_CF_WriteStream($hCF, "Sessions/x/meta.txt", "hello"), "_CF_WriteStream")
	_Check(_CF_ReadStream($hCF, "Sessions/x/meta.txt") = "hello", "_CF_ReadStream round trip")
	_CF_Close($hCF)
	_Check(FileExists($sCfb), "file on disk: " & FileGetSize($sCfb) & " bytes")
EndIf

; --- 6. WinEventManager: bus up, one handler, one trigger --------------------
_Say("== WinEventManager ==")
Local $bWe = _WinEvent_Startup()
_Check($bWe <> 0, "_WinEvent_Startup")
Local $iId = _WinEvent_RegisterHandler("Coexist.*", "__Sink", 0, 2)
Local $eId = @error
_Check($iId > 0 And $eId = 0, "_WinEvent_RegisterHandler -> id " & $iId)
Local $iRan = _WinEvent_Trigger("Coexist.Test", "payload")
Local $eTr = @error
_Check($iRan = 1 And $eTr = 0, "_WinEvent_Trigger ran " & $iRan & " handler(s)")
_Check(_WinEvent_Journal() >= 1, "_WinEvent_Journal -> " & _WinEvent_Journal())
_WinEvent_Shutdown()

Func __Sink($sEvent, $vData)
	_Say("  sink saw [" & $sEvent & "] = [" & $vData & "]")
EndFunc   ;>__Sink

_Say("RESULT ok=" & $g_iOk & " fail=" & $g_iKo)
If $g_iKo Then Exit 1
