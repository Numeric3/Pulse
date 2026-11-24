; =============================================================================
; tests/readcfb.au3 -- reads a Pulse archive back from the outside.
;
;   bash tests/one.sh <interpreter> tests/readcfb.au3 <file.cfb> [src ...]
;
; The console verifies itself in --auto, but that is the same process that wrote
; the bytes. This one opens the file as a stranger would: the storages, the four
; streams, the manifest fields, every NDJSON line, and one row per expected
; source. The gate calls it on the archive produced by a live run, so a line here
; is a real event that travelled over a socket into a .cfb.
;
; Author : Numeric1 -- Licence : MIT
; =============================================================================
#include "../Lib/CompoundFile.au3"
#include "../Pulse_Json.au3"

Opt("MustDeclareVars", 1)

Global $iOk = 0, $iKo = 0

Func _Say($s)
	ConsoleWrite($s & @CRLF)
EndFunc   ;>_Say

Func _Check($b, $sMsg)
	If $b Then
		$iOk += 1
		_Say("  ok    " & $sMsg)
	Else
		$iKo += 1
		_Say("  FAIL  " & $sMsg)
	EndIf
EndFunc   ;>_Check

If $CmdLine[0] < 1 Then
	_Say("usage: readcfb.au3 <file.cfb> [expected source ...]")
	Exit 2
EndIf

Local $sFile = $CmdLine[1]
Local $h = _CF_Open($sFile)
If $h < 1 Then
	_Say("FATAL open " & $sFile & " @error " & @error & " " & _CF_GetLastErrorMessage())
	_Say("RESULT ok=0 fail=1")
	Exit 1
EndIf
_Check(True, "opened " & $sFile & " (" & FileGetSize($sFile) & " bytes)")

; The session folder is the only child of Sessions, and its name is the id.
Local $aRoot = _CF_Enum($h)
Local $bSess = False, $i
For $i = 1 To $aRoot[0][0]
	If $aRoot[$i][0] = "Sessions" Then $bSess = True
Next
_Check($bSess, "root holds a Sessions storage")

Local $aSess = _CF_Enum($h, "Sessions")
Local $sId = ""
If IsArray($aSess) And $aSess[0][0] >= 1 Then $sId = $aSess[1][0]
_Check($sId <> "", "a session id is inside: " & $sId)
Local $sBase = "Sessions\" & $sId

Local $iType = _CF_Stat($h, $sBase & "\Manifest.json")
Local $iSzMan = IsArray($iType) ? $iType[1] : -1
_Check(IsArray($iType) And $iType[0] = $CF_TYPE_STREAM And $iSzMan > 40, "Manifest.json is a stream of " & $iSzMan & " bytes")
Local $sNames[4] = ["journal.txt", "events.ndjson", "Index\tree.txt", "Manifest.json"]
Local $sFound = "", $sSt
For $i = 0 To 3
	$sSt = _CF_Stat($h, $sBase & "\" & $sNames[$i])
	If IsArray($sSt) And $sSt[0] = $CF_TYPE_STREAM Then
		$sFound &= $sNames[$i] & "=" & $sSt[1] & " "
	Else
		$sFound &= $sNames[$i] & "=MISSING "
	EndIf
Next
_Check(StringInStr($sFound, "MISSING") = 0, "all four streams present: " & $sFound)

; The manifest is the file that explains the rest, so its fields are named here.
Local $sMan = String(_CF_ReadStream($h, $sBase & "\Manifest.json", $CF_TEXT))
Local $mMan[]
Local $bMan = _Pulse_JParse($sMan, $mMan)
_Check($bMan And _Pulse_JHas($mMan, "session") And _Pulse_JHas($mMan, "events_seen") And _
		_Pulse_JHas($mMan, "tree_rows") And _Pulse_JHas($mMan, "pulse"), _
		"manifest parses with session, events_seen, tree_rows, pulse: " & StringLeft($sMan, 90))
If $bMan Then _Check(String(_Pulse_JGet($mMan, "session")) = $sId, "manifest session matches the storage name")

; Every NDJSON line must parse, and the sources the gate expects must appear.
Local $sNd = String(_CF_ReadStream($h, $sBase & "\events.ndjson", $CF_AUTO))
Local $aNd = StringSplit(StringStripCR($sNd), @LF, 2)
Local $mRow[], $iGood = 0, $iLines = 0
Local $mSrc[]
For $i = 0 To UBound($aNd) - 1
	If $aNd[$i] = "" Then ContinueLoop
	$iLines += 1
	$mRow = __Map()
	If _Pulse_JParse($aNd[$i], $mRow) Then
		$iGood += 1
		Local $sSrc = String(_Pulse_JGet($mRow, "src", "?"))
		$mSrc[$sSrc] = Number(_Pulse_JGet($mSrc, $sSrc, "0")) + 1
	EndIf
Next
_Check($iLines > 0 And $iGood = $iLines And $bMan And Number(_Pulse_JGet($mMan, "events_archive")) = $iLines, _
		"events.ndjson: " & $iGood & " of " & $iLines & " lines parse; manifest count agrees")

Local $k, $sMiss = "", $iWant = 0
For $k = 2 To $CmdLine[0]
	$iWant += 1
	If Not MapExists($mSrc, $CmdLine[$k]) Then $sMiss &= $CmdLine[$k] & " "
Next
_Check($iWant = 0 Or $sMiss = "", "expected sources all reached the archive, missing [" & $sMiss & "]")

; The name index is what makes the archive searchable a month later.
Local $sTree = String(_CF_ReadStream($h, $sBase & "\Index\tree.txt", $CF_AUTO))
Local $aTree = StringSplit(StringStripCR($sTree), @LF, 6)
Local $iRows = 0
For $i = 0 To UBound($aTree) - 1
	If $aTree[$i] <> "" And $aTree[$i] <> "TREE1" Then $iRows += 1
Next
_Check(StringLeft($sTree, 5) = "TREE1" And $iRows >= 4, "Index\tree.txt: " & $iRows & " rows, header intact")

Local $sJr = String(_CF_ReadStream($h, $sBase & "\journal.txt", $CF_AUTO))
_Check(StringInStr($sJr, "DISPATCHED") > 0, "journal.txt carries dispatch rows (" & StringLen($sJr) & " chars)")

_CF_Close($h)
_Say("sources: " & __DumpSrcs())
_Say("RESULT ok=" & $iOk & " fail=" & $iKo)
Exit($iKo > 0 ? 1 : 0)

Func __Map()
	Local $m[]
	Return $m
EndFunc   ;>__Map

Func __DumpSrcs()
	Local $aK = MapKeys($mSrc), $i, $s = ""
	For $i = 0 To UBound($aK) - 1
		$s &= ($s = "" ? "" : " ") & $aK[$i] & "=" & $mSrc[$aK[$i]]
	Next
	Return $s
EndFunc   ;>__DumpSrcs
