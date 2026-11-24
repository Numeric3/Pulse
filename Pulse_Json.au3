; =============================================================================
; Pulse_Json.au3 -- the flat JSON reader and writer shared by the console and
;                   by the agent include.
;
; The wire format of Pulse is one JSON object per WebSocket text frame, with
; string and number values only. That is a decision, not an oversight: a flat
; object needs no recursion, cannot blow a stack, and can be read by any
; language in a dozen lines, which is the whole point of an ingestion port.
;
; Documented limits, measured by the self test at the bottom of this file:
;   * nesting is not parsed. A value that starts with "{" or "[" is captured as
;     raw text (balanced scan) and handed back as a string, so a sender that
;     nests loses nothing but the structure.
;   * keys are matched case-sensitively, as written by the sender.
;   * a missing key reads as "" (AutoIt reads an absent Map key as an empty
;     string), so a key whose value IS the empty string cannot be told apart
;     from an absent one. Use _Pulse_JHas when that difference matters.
;   * \uXXXX escapes inside a string are passed through as the six characters
;     they are, not decoded: Pulse treats a payload as bytes, and the browser
;     decodes what it renders.
;
; Author : Numeric1 -- Licence : MIT (Copyright (c) 2026 Numeric1)
; =============================================================================

#include-once

; The self test is dispatched before any function body so that the whole file is
; compiled when the call below runs. The @ScriptName guard keeps it from firing
; when another script is launched with the same switch.
If @ScriptName = "Pulse_Json.au3" And $CmdLine[0] >= 1 And ($CmdLine[1] = "--auto" Or $CmdLine[1] = "/auto") Then _
		__Pulse_JsonSelfTest()

; -----------------------------------------------------------------------------
; _Pulse_JEscape
;   Turn any byte string into the body of a JSON string literal. Backslash and
;   the double quote go first, or they would escape their own replacement.
; -----------------------------------------------------------------------------
Func _Pulse_JEscape($s)
	$s = StringReplace($s, "\", "\\")
	$s = StringReplace($s, '"', '\"')
	$s = StringReplace($s, @CR, "\r")
	$s = StringReplace($s, @LF, "\n")
	$s = StringReplace($s, @TAB, "\t")
	If StringRegExp($s, "[\001-\010\013\014\016-\037]") Then
		; Control bytes nobody sends but a fuzzer. \u00XX is the only legal way
		; to carry them, and this path is rare enough to afford the loop.
		Local $i, $c, $sOut = ""
		For $i = 1 To StringLen($s)
			$c = Asc(StringMid($s, $i, 1))
			If $c >= 1 And $c <= 31 Then
				$sOut &= "\u00" & StringRight("0" & Hex($c), 2)
			Else
				$sOut &= StringMid($s, $i, 1)
			EndIf
		Next
		$s = $sOut
	EndIf
	Return $s
EndFunc   ;==>_Pulse_JEscape

; -----------------------------------------------------------------------------
; _Pulse_JQuote
;   A whole JSON string literal, quotes included.
; -----------------------------------------------------------------------------
Func _Pulse_JQuote($s)
	Return '"' & _Pulse_JEscape($s) & '"'
EndFunc   ;==>_Pulse_JQuote

; -----------------------------------------------------------------------------
; _Pulse_JBuild
;   Map (or a 2D array of key/value rows) to one JSON object, compact.
;   A value that is numeric and typed as a number goes out unquoted; anything
;   else goes out as a string.
; -----------------------------------------------------------------------------
Func _Pulse_JBuild($m)
	Local $sOut = "{", $bFirst = True
	Local $aKeys = MapKeys($m), $i, $v
	For $i = 0 To UBound($aKeys) - 1
		$v = $m[$aKeys[$i]]
		$sOut &= ($bFirst ? "" : ",") & _Pulse_JQuote($aKeys[$i]) & ":"
		If VarGetType($v) = "Int32" Or VarGetType($v) = "Int64" Or VarGetType($v) = "Float" Then
			$sOut &= String($v)
		Else
			$sOut &= _Pulse_JQuote($v)
		EndIf
		$bFirst = False
	Next
	Return $sOut & "}"
EndFunc   ;==>_Pulse_JBuild

; -----------------------------------------------------------------------------
; _Pulse_JParse
;   Read one flat JSON object into a Map the caller owns.
;   Return True with @error 0, or False with @error 1 (not an object) and
;   @extended = the offset where the reader stopped, which is what a developer
;   needs to fix a hand-written frame.
; -----------------------------------------------------------------------------
Func _Pulse_JParse($sJson, ByRef $mMap)
	; Only the frame's own padding goes: a sender may put spaces inside a value,
	; and stripping every space would silently rewrite the payload.
	Local $s = StringStripWS($sJson, 3)
	If StringLeft($s, 1) <> "{" Or StringRight($s, 1) <> "}" Then
		$mMap = 0
		Return SetError(1, 0, False)
	EndIf
	Local $m[]
	Local $i = 2, $iLen = StringLen($s), $sKey, $vVal, $c
	While $i <= $iLen
		$c = StringMid($s, $i, 1)
		If $c = "}" Or $c = "," Or $c = " " Then
			$i += 1
			ContinueLoop
		EndIf
		; --- key ---
		If $c <> '"' Then
			$mMap = 0
			Return SetError(1, $i, False)
		EndIf
		$i += 1 ; step over the opening quote: the reader starts inside the string
		$sKey = __Pulse_JReadString($s, $i)
		If @error Then
			$mMap = 0
			Return SetError(1, $i, False)
		EndIf
		; --- colon ---
		While $i <= $iLen And StringMid($s, $i, 1) = " "
			$i += 1
		WEnd
		$c = StringMid($s, $i, 1)
		$i += 1
		If $c <> ":" Then
			$mMap = 0
			Return SetError(1, $i - 1, False)
		EndIf
		; --- value ---
		While $i <= $iLen And StringMid($s, $i, 1) = " "
			$i += 1
		WEnd
		$c = StringMid($s, $i, 1)
		$i += 1
		If $c = '"' Then
			$vVal = __Pulse_JReadString($s, $i)
			If @error Then
				$mMap = 0
				Return SetError(1, $i, False)
			EndIf
		ElseIf $c = "{" Or $c = "[" Then
			$vVal = __Pulse_JReadRaw($s, $i, $c)
			If @error Then
				$mMap = 0
				Return SetError(1, $i, False)
			EndIf
		Else
			; number, true, false or null: take the token up to the next comma
			Local $j = $i - 1, $sTok = ""
			While $j <= $iLen
				$c = StringMid($s, $j, 1)
				If $c = "," Or $c = "}" Then ExitLoop
				$sTok &= $c
				$j += 1
			WEnd
			$i = $j
			$sTok = StringStripWS($sTok, 3)
			If $sTok = "true" Then
				$vVal = "true"
			ElseIf $sTok = "false" Then
				$vVal = "false"
			ElseIf $sTok = "null" Then
				$vVal = ""
			ElseIf __Pulse_IsNum($sTok) Then
				$vVal = Number($sTok)
			Else
				$mMap = 0
				Return SetError(1, $i, False)
			EndIf
		EndIf
		$m[$sKey] = $vVal
	WEnd
	$mMap = $m
	Return SetError(0, UBound(MapKeys($m)), True)
EndFunc   ;==>_Pulse_JParse

; Read a string literal; $i arrives on the opening quote and leaves after the
; closing one. Escapes are undone for the three that matter to a human reader.
Func __Pulse_JReadString($s, ByRef $i)
	Local $iLen = StringLen($s), $sOut = "", $c, $e
	; $i points at the first character after the opening quote
	While $i <= $iLen
		$c = StringMid($s, $i, 1)
		$i += 1
		If $c = '"' Then Return SetError(0, 0, $sOut)
		If $c = "\" Then
			$e = StringMid($s, $i, 1)
			$i += 1
			Switch $e
				Case "n"
					$sOut &= @LF
				Case "r"
					$sOut &= @CR
				Case "t"
					$sOut &= @TAB
				Case "u"
					; keep the escape visible: \u0041 becomes the six characters
					$sOut &= "\u" & StringMid($s, $i, 4)
					$i += 4
				Case Else
					$sOut &= $e
			EndSwitch
			ContinueLoop
		EndIf
		$sOut &= $c
	WEnd
	Return SetError(1, 0, $sOut)
EndFunc   ;>__Pulse_JReadString

; Capture a balanced nested value as raw text. Depth is counted, not parsed.
Func __Pulse_JReadRaw($s, ByRef $i, $cOpen)
	Local $cClose = ($cOpen = "{" ? "}" : "]")
	Local $iLen = StringLen($s), $d = 0, $j = $i - 1, $c, $sOut = ""
	Local $bInStr = False
	While $j <= $iLen
		$c = StringMid($s, $j, 1)
		$sOut &= $c
		If $bInStr Then
			If $c = "\" Then
				$j += 1
				$sOut &= StringMid($s, $j, 1)
			ElseIf $c = '"' Then
				$bInStr = False
			EndIf
			$j += 1
			ContinueLoop
		EndIf
		If $c = '"' Then
			$bInStr = True
		ElseIf $c = $cOpen Then
			$d += 1
		ElseIf $c = $cClose Then
			$d -= 1
			If $d = 0 Then
				$i = $j + 1
				Return SetError(0, 0, $sOut)
			EndIf
		EndIf
		$j += 1
	WEnd
	$i = $j
	Return SetError(1, 0, $sOut)
EndFunc   ;>__Pulse_JReadRaw

; -----------------------------------------------------------------------------
; Accessors that make the two documented Map behaviours explicit.
; -----------------------------------------------------------------------------
Func _Pulse_JHas($m, $sKey)
	If VarGetType($m) <> "Map" Then Return False
	Return MapExists($m, $sKey)
EndFunc   ;==>_Pulse_JHas

; Existence is asked for BEFORE the value is read. A Map gives back the Default
; keyword for a key it does not hold, and Default compares equal to neither ""
; nor anything else, so a missing field would travel down the whole chain as a
; value that is not a value -- measured, and the reason this order is not
; negotiable.
Func _Pulse_JGet($m, $sKey, $sDefault = "")
	If VarGetType($m) <> "Map" Then Return $sDefault
	If Not MapExists($m, $sKey) Then Return $sDefault
	Return $m[$sKey]
EndFunc   ;==>_Pulse_JGet

Func _Pulse_JGetInt($m, $sKey, $iDefault = 0)
	Local $v = _Pulse_JGet($m, $sKey, "")
	If $v = "" Then Return $iDefault
	If Not __Pulse_IsNum($v) Then Return $iDefault
	Return Number($v)
EndFunc   ;==>_Pulse_JGetInt

; AutoIt has no StringIsNumber: an integer or a float, sign included.
Func __Pulse_IsNum($s)
	Return StringIsInt($s) = 1 Or StringIsFloat($s) = 1
EndFunc   ;>__Pulse_IsNum

; -----------------------------------------------------------------------------
; Self test:  bash tests/one.sh <interpreter> Pulse_Json.au3 --auto
; -----------------------------------------------------------------------------
Func __Pulse_JsonSelfTest()
	Local $iOk = 0, $iKo = 0
	Local $m[]
	$m["name"] = "Build.Compile.Start"
	$m["ms"] = 42
	$m["txt"] = 'quote " backslash \ and' & @LF & "newline"
	$m["nested"] = '{"a":[1,2]}'
	Local $s = _Pulse_JBuild($m)
	ConsoleWrite("built " & $s & @CRLF)

	Local $m2[]
	Local $b = _Pulse_JParse($s, $m2)
	If $b And _Pulse_JGet($m2, "name") = "Build.Compile.Start" Then
		$iOk += 1
		ConsoleWrite("  ok    name round trip" & @CRLF)
	Else
		$iKo += 1
		ConsoleWrite("  FAIL  name round trip" & @CRLF)
	EndIf
	If _Pulse_JGetInt($m2, "ms") = 42 Then
		$iOk += 1
		ConsoleWrite("  ok    number round trip" & @CRLF)
	Else
		$iKo += 1
		ConsoleWrite("  FAIL  number round trip -> [" & _Pulse_JGet($m2, "ms") & "]" & @CRLF)
	EndIf
	If _Pulse_JGet($m2, "txt") = 'quote " backslash \ and' & @LF & "newline" Then
		$iOk += 1
		ConsoleWrite("  ok    escapes round trip" & @CRLF)
	Else
		$iKo += 1
		ConsoleWrite("  FAIL  escapes round trip -> [" & _Pulse_JGet($m2, "txt") & "]" & @CRLF)
	EndIf
	; A value that was a string holding braces must come back as that same text.
	If _Pulse_JGet($m2, "nested") = '{"a":[1,2]}' Then
		$iOk += 1
		ConsoleWrite("  ok    nested value kept as text -> [" & _Pulse_JGet($m2, "nested") & "]" & @CRLF)
	Else
		$iKo += 1
		ConsoleWrite("  FAIL  nested value -> [" & _Pulse_JGet($m2, "nested") & "]" & @CRLF)
	EndIf
	; Malformed frames must be refused with an offset, not accepted silently.
	Local $m3[]
	If Not _Pulse_JParse('{"name" "x"}', $m3) And @extended > 0 Then
		$iOk += 1
		ConsoleWrite("  ok    missing colon refused at offset " & @extended & @CRLF)
	Else
		$iKo += 1
		ConsoleWrite("  FAIL  missing colon accepted" & @CRLF)
	EndIf
	If Not _Pulse_JParse('[1,2]', $m3) Then
		$iOk += 1
		ConsoleWrite("  ok    non-object refused" & @CRLF)
	Else
		$iKo += 1
		ConsoleWrite("  FAIL  non-object accepted" & @CRLF)
	EndIf
	; A sender that nests does get the raw text, which is the documented deal.
	Local $m4[]
	If _Pulse_JParse('{"a":{"b":{"c":1}},"d":2}', $m4) And _Pulse_JGet($m4, "a") = '{"b":{"c":1}}' And _
			_Pulse_JGetInt($m4, "d") = 2 Then
		$iOk += 1
		ConsoleWrite("  ok    deep nesting kept as raw text" & @CRLF)
	Else
		$iKo += 1
		ConsoleWrite("  FAIL  deep nesting -> [" & _Pulse_JGet($m4, "a") & "]" & @CRLF)
	EndIf
	; A hand-written frame with padding and interior spaces must survive both.
	Local $m5[]
	If _Pulse_JParse('  {"txt":"a b  c", "n":1}  ', $m5) And _Pulse_JGet($m5, "txt") = "a b  c" And _
			_Pulse_JGetInt($m5, "n") = 1 Then
		$iOk += 1
		ConsoleWrite("  ok    padding and interior spaces kept" & @CRLF)
	Else
		$iKo += 1
		ConsoleWrite("  FAIL  padding -> [" & _Pulse_JGet($m5, "txt") & "]" & @CRLF)
	EndIf
	ConsoleWrite("RESULT ok=" & $iOk & " fail=" & $iKo & @CRLF)
	Exit($iKo ? 1 : 0)
EndFunc   ;>__Pulse_JsonSelfTest
