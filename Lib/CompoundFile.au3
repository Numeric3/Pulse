; #INDEX# =======================================================================================================================
; Title .........: CompoundFile UDF
; AutoIt Version : 3.3.16+
; Language .......: English
; Version ........: 1.0.0
; Modified .......: 2026/10/27
; Description ...: Hierarchical, binary-safe virtual file system built on Windows Structured Storage
;                  (IStorage / IStream). Named streams live in a tree inside a single compound file
;                  (.cfb), a native Windows format readable by any OLE-aware tool.
; Author ........: Numeric1
; Link ..........: https://www.autoitscript.com/forum/topic/213931-udf-compoundfile-%E2%80%94-structured-storage-virtual-file-system-pure-autoit/
; ===============================================================================================================================

#include-once

; #CONSTANTS# ===================================================================================================================
; Public flags for _CF_Create / _CF_Open
Global Const $CF_TRANSACTED = 0x00010000

; Data modes for _CF_WriteStream / _CF_ReadStream
Global Const $CF_AUTO = 0
Global Const $CF_TEXT = 1
Global Const $CF_BINARY = 2

; Element types returned by _CF_Exists, _CF_Stat and _CF_Enum
Global Const $CF_TYPE_STORAGE = 1
Global Const $CF_TYPE_STREAM = 2

; Error codes returned through @error
Global Const $CF_ERR_NONE = 0
Global Const $CF_ERR_HANDLE = 1        ; invalid or closed handle
Global Const $CF_ERR_PATH = 2          ; invalid path or element name
Global Const $CF_ERR_NOT_FOUND = 3     ; file or element does not exist
Global Const $CF_ERR_EXISTS = 4        ; element or file already exists
Global Const $CF_ERR_ACCESS = 5        ; access denied, element already open
Global Const $CF_ERR_FLAGS = 6         ; invalid flag or parameter for this call
Global Const $CF_ERR_STORAGE = 7       ; internal storage creation failure
Global Const $CF_ERR_STREAM = 8        ; stream read/write failure
Global Const $CF_ERR_ENCODING = 9      ; data is not valid UTF-8 in text mode
Global Const $CF_ERR_NOT_TRANSACTED = 10
Global Const $CF_ERR_MEMORY = 11       ; buffer allocation failure
Global Const $CF_ERR_FORMAT = 12       ; file is not a compound file
Global Const $CF_ERR_HRESULT = 13      ; unmapped HRESULT

; Internal constants
Global Const $__CF_STGM_READ = 0x00000000
Global Const $__CF_STGM_READWRITE = 0x00000002
Global Const $__CF_STGM_SHARE_EXCLUSIVE = 0x00000010
Global Const $__CF_STGM_CREATE = 0x00001000
Global Const $__CF_STGM_TRANSACTED = 0x00010000
Global Const $__CF_STGFMT_STORAGE = 0
Global Const $__CF_STGC_DEFAULT = 0
Global Const $__CF_STATFLAG_NONAME = 1
Global Const $__CF_STREAM_SEEK_SET = 0
Global Const $__CF_MAX_NAME = 31
Global Const $__CF_CHUNK = 65536
Global Const $__CF_HT_ROOT = 1
Global Const $__CF_HT_VIEW = 2
Global Const $__CF_HANDLE_COLS = 9

Global Const $__CF_IID_IUnknown = "{00000000-0000-0000-C000-000000000046}"
Global Const $__CF_IID_IStorage = "{0000000B-0000-0000-C000-000000000046}"
Global Const $__CF_IID_IStream = "{0000000C-0000-0000-C000-000000000046}"
Global Const $__CF_IID_IEnumSTATSTG = "{0000000D-0000-0000-C000-000000000046}"

Global Const $__CF_STGTY_STORAGE = 1
Global Const $__CF_STGTY_STREAM = 2

Global Const $__CF_tagIStorage = "CreateStream hresult(wstr;dword;dword;dword;ptr*);" & _
		"OpenStream hresult(wstr;ptr;dword;dword;ptr*);" & _
		"CreateStorage hresult(wstr;dword;dword;dword;ptr*);" & _
		"OpenStorage hresult(wstr;ptr;dword;dword;dword;ptr*);" & _
		"CopyTo hresult(dword;ptr*;ptr;wstr*;ptr*);" & _
		"MoveElementTo hresult(wstr;ptr;wstr;dword);" & _
		"Commit hresult(dword);Revert hresult();" & _
		"EnumElements hresult(dword;ptr;dword;ptr*);" & _
		"DestroyElement hresult(wstr);RenameElement hresult(wstr;wstr);" & _
		"SetElementTimes hresult(wstr;ptr;ptr;ptr);" & _
		"SetClass hresult(byte[16]);SetStateBits hresult(dword;dword);" & _
		"Stat hresult(ptr;dword);"

Global Const $__CF_tagIStream = "Read hresult(ptr;dword;dword*);Write hresult(ptr;dword;dword*);" & _
		"Seek hresult(int64;dword;uint64*);SetSize hresult(int64);" & _
		"CopyTo hresult(ptr;int64;uint64*;uint64*);Commit hresult(dword);Revert hresult();" & _
		"LockRegion hresult(int64;int64;dword);UnlockRegion hresult(int64;int64;dword);" & _
		"Stat hresult(ptr;dword);Clone hresult(ptr*);"

Global Const $__CF_tagSTATSTG = "ptr pwcsName;dword type;uint64 cbSize;" & _
		"dword mtime_low;dword mtime_high;dword ctime_low;dword ctime_high;" & _
		"dword atime_low;dword atime_high;dword grfMode;dword grfLocksSupported;" & _
		"byte clsid[16];dword grfStateBits;dword reserved;"

Global Const $__CF_tagIEnumSTATSTG = "Next hresult(dword;ptr;dword*);" & _
		"Skip hresult(dword);Reset hresult();Clone hresult(ptr*);"

; #VARIABLES# ===================================================================================================================
; Handle table columns: 0 id, 1 type, 2 IStorage object, 3 file, 4 grfMode,
;                       5 view base path, 6 parent handle id, 7 transacted,
;                       8 ancestor chain array (kepts parents alive)
Global $__CF_aHandles[1][$__CF_HANDLE_COLS]
Global $__CF_iHandleRows = 0
Global $__CF_iNextHandle = 1

Global $__CF_iLastError = $CF_ERR_NONE
Global $__CF_iLastHR = 0
Global $__CF_sLastFunc = ""

; #FUNCTION# ====================================================================================================================
; Name ..........: _CF_Create
; Description ...: Creates a new empty compound file and returns its handle.
; Syntax ........: _CF_Create($sFile[, $iFlags = Default])
; Parameters ....: $sFile - Path of the file to create. Must not already exist.
;                  $iFlags - Optional flags: $CF_TRANSACTED to open the root storage in transacted mode.
; Return values .: Success: handle >= 1.
;                  Failure: 0, with @error set to a $CF_ERR_* code and @extended set to the raw HRESULT (0 if none).
; Author ........: Numeric1
; Remarks .......: An existing file is never overwritten (fails with $CF_ERR_EXISTS).
;                  Transacted mode defers disk changes until _CF_Close commits them.
; Related .......: _CF_Open, _CF_Close
; ===============================================================================================================================
Func _CF_Create($sFile, $iFlags = Default)
	$__CF_iLastError = $CF_ERR_NONE
	$__CF_iLastHR = 0
	If Not IsString($sFile) Or $sFile = "" Then
		__CF_Fail($CF_ERR_PATH, 0, "_CF_Create")
		Return SetError($__CF_iLastError, $__CF_iLastHR, 0)
	EndIf
	If FileExists($sFile) Then
		__CF_Fail($CF_ERR_EXISTS, 0, "_CF_Create")
		Return SetError($__CF_iLastError, $__CF_iLastHR, 0)
	EndIf
	If $iFlags = Default Then $iFlags = 0
	If BitAND($iFlags, BitNOT($CF_TRANSACTED)) <> 0 Then
		__CF_Fail($CF_ERR_FLAGS, 0, "_CF_Create")
		Return SetError($__CF_iLastError, $__CF_iLastHR, 0)
	EndIf

	Local $bTrans = BitAND($iFlags, $CF_TRANSACTED) <> 0
	Local $iMode = BitOR($__CF_STGM_CREATE, $__CF_STGM_READWRITE, $__CF_STGM_SHARE_EXCLUSIVE)
	If $bTrans Then $iMode = BitOR($iMode, $__CF_STGM_TRANSACTED)

	Local $oRoot = __CF_CreateRoot($sFile, $iMode)
	Local $iErr = @error, $iExt = @extended
	If $iErr Then
		If $iExt Then
			__CF_Fail(__CF_HResultToError($iExt), $iExt, "_CF_Create")
		Else
			__CF_Fail($CF_ERR_STORAGE, 0, "_CF_Create")
		EndIf
		Return SetError($__CF_iLastError, $__CF_iLastHR, 0)
	EndIf

	Return __CF_HandleAlloc($__CF_HT_ROOT, $oRoot, $sFile, $iMode, "", 0, $bTrans)
EndFunc   ;==>_CF_Create

; #FUNCTION# ====================================================================================================================
; Name ..........: _CF_Open
; Description ...: Opens an existing compound file and returns its handle.
; Syntax ........: _CF_Open($sFile[, $iFlags = Default])
; Parameters ....: $sFile - Path of an existing compound file.
;                  $iFlags - Optional flags: $CF_TRANSACTED to open the root storage in transacted mode.
; Return values .: Success: handle >= 1.
;                  Failure: 0, with @error set to a $CF_ERR_* code and @extended set to the raw HRESULT (0 if none).
; Author ........: Numeric1
; Remarks .......: The file is opened with exclusive sharing: a second _CF_Open on the same file fails
;                  with $CF_ERR_ACCESS until the first handle is closed.
; Related .......: _CF_Create, _CF_Close
; ===============================================================================================================================
Func _CF_Open($sFile, $iFlags = Default)
	$__CF_iLastError = $CF_ERR_NONE
	$__CF_iLastHR = 0
	If Not IsString($sFile) Or $sFile = "" Then
		__CF_Fail($CF_ERR_PATH, 0, "_CF_Open")
		Return SetError($__CF_iLastError, $__CF_iLastHR, 0)
	EndIf
	If Not FileExists($sFile) Then
		__CF_Fail($CF_ERR_NOT_FOUND, 0, "_CF_Open")
		Return SetError($__CF_iLastError, $__CF_iLastHR, 0)
	EndIf
	If $iFlags = Default Then $iFlags = 0
	If BitAND($iFlags, BitNOT($CF_TRANSACTED)) <> 0 Then
		__CF_Fail($CF_ERR_FLAGS, 0, "_CF_Open")
		Return SetError($__CF_iLastError, $__CF_iLastHR, 0)
	EndIf
	If Not __CF_IsStorageFile($sFile) Then
		__CF_Fail($CF_ERR_FORMAT, 0, "_CF_Open")
		Return SetError($__CF_iLastError, $__CF_iLastHR, 0)
	EndIf

	Local $bTrans = BitAND($iFlags, $CF_TRANSACTED) <> 0
	Local $iMode = BitOR($__CF_STGM_READWRITE, $__CF_STGM_SHARE_EXCLUSIVE)
	If $bTrans Then $iMode = BitOR($iMode, $__CF_STGM_TRANSACTED)

	Local $oRoot = __CF_OpenRoot($sFile, $iMode)
	Local $iErr = @error, $iExt = @extended
	If $iErr Then
		If $iExt Then
			__CF_Fail(__CF_HResultToError($iExt), $iExt, "_CF_Open")
		Else
			__CF_Fail($CF_ERR_STORAGE, 0, "_CF_Open")
		EndIf
		Return SetError($__CF_iLastError, $__CF_iLastHR, 0)
	EndIf

	Return __CF_HandleAlloc($__CF_HT_ROOT, $oRoot, $sFile, $iMode, "", 0, $bTrans)
EndFunc   ;==>_CF_Open

; #FUNCTION# ====================================================================================================================
; Name ..........: _CF_Close
; Description ...: Closes a handle. Views opened from it are closed first; a transacted handle is committed.
; Syntax ........: _CF_Close($hCF)
; Parameters ....: $hCF - Handle returned by _CF_Create, _CF_Open or _CF_OpenStorage.
; Return values .: Success: True.
;                  Failure: False, with @error set to a $CF_ERR_* code and @extended set to the raw HRESULT (0 if none).
; Author ........: Numeric1
; Remarks .......: The handle is always released, even when the final commit fails. Closing a root handle
;                  invalidates every view opened from it, directly or indirectly.
; Related .......: _CF_Create, _CF_Open, _CF_OpenStorage
; ===============================================================================================================================
Func _CF_Close($hCF)
	$__CF_iLastError = $CF_ERR_NONE
	$__CF_iLastHR = 0
	Local $iRow = __CF_HandleRow($hCF)
	If $iRow < 0 Then
		__CF_Fail($CF_ERR_HANDLE, 0, "_CF_Close")
		Return SetError($__CF_iLastError, $__CF_iLastHR, False)
	EndIf

	Local $bTrans = $__CF_aHandles[$iRow][7]
	Local $oStorage = $__CF_aHandles[$iRow][2]
	Local $aChain = $__CF_aHandles[$iRow][8]

	Local $bChildOk = __CF_CloseViews($hCF)
	Local $iChildHR = @extended

	Local $iHR = 0
	If $bTrans And IsObj($oStorage) Then
		$iHR = $oStorage.Commit($__CF_STGC_DEFAULT)
		If $iHR = 0 Then
			Local $bChainOk = __CF_CommitChain($aChain)
			If Not $bChainOk Then
				$iHR = @extended
			EndIf
		EndIf
	EndIf

	__CF_HandleRelease($iRow)

	If $iHR <> 0 Then
		__CF_Fail(__CF_HResultToError($iHR), $iHR, "_CF_Close")
		Return SetError($__CF_iLastError, $__CF_iLastHR, False)
	EndIf
	If Not $bChildOk Then
		__CF_Fail(__CF_HResultToError($iChildHR), $iChildHR, "_CF_Close")
		Return SetError($__CF_iLastError, $__CF_iLastHR, False)
	EndIf
	Return True
EndFunc   ;==>_CF_Close

; #FUNCTION# ====================================================================================================================
; Name ..........: _CF_CreateStorage
; Description ...: Creates a sub-storage (a folder) at the given path.
; Syntax ........: _CF_CreateStorage($hCF, $sPath)
; Parameters ....: $hCF   - Handle returned by _CF_Create, _CF_Open or _CF_OpenStorage.
;                  $sPath - Relative path of the storage to create, e.g. "Config" or "Plugins\Audio".
; Return values .: Success: True.
;                  Failure: False, with @error set to a $CF_ERR_* code and @extended set to the raw HRESULT (0 if none).
; Author ........: Numeric1
; Remarks .......: Intermediate storages are created automatically. Existing elements are never replaced.
; Related .......: _CF_OpenStorage, _CF_WriteStream
; ===============================================================================================================================
Func _CF_CreateStorage($hCF, $sPath)
	$__CF_iLastError = $CF_ERR_NONE
	$__CF_iLastHR = 0
	Local $iRow = __CF_HandleRow($hCF)
	If $iRow < 0 Then
		__CF_Fail($CF_ERR_HANDLE, 0, "_CF_CreateStorage")
		Return SetError($__CF_iLastError, $__CF_iLastHR, False)
	EndIf

	Local $bTrans = $__CF_aHandles[$iRow][7]
	Local $sLeaf = ""
	Local $aChain = 0
	Local $oParent = __CF_OpenParent($hCF, $sPath, True, $sLeaf, $aChain)
	Local $iErr = @error, $iExt = @extended
	If Not IsObj($oParent) Then
		__CF_MapWalkError($iErr, $iExt, "_CF_CreateStorage")
		Return SetError($__CF_iLastError, $__CF_iLastHR, False)
	EndIf

	Local $iFlags = BitOR($__CF_STGM_READWRITE, $__CF_STGM_SHARE_EXCLUSIVE)
	If $bTrans Then $iFlags = BitOR($iFlags, $__CF_STGM_TRANSACTED)

	Local $pStorage = 0
	Local $iHR = $oParent.CreateStorage($sLeaf, $iFlags, 0, 0, $pStorage)
	If $iHR <> 0 Then
		__CF_Fail(__CF_HResultToError($iHR), $iHR, "_CF_CreateStorage")
		Return SetError($__CF_iLastError, $__CF_iLastHR, False)
	EndIf
	__CF_ReleaseRaw($pStorage)

	If $bTrans Then
		Local $bOk = __CF_CommitChain($aChain)
		Local $iCH = @extended
		If Not $bOk Then
			__CF_Fail(__CF_HResultToError($iCH), $iCH, "_CF_CreateStorage")
			Return SetError($__CF_iLastError, $__CF_iLastHR, False)
		EndIf
	EndIf
	Return True
EndFunc   ;==>_CF_CreateStorage

; #FUNCTION# ====================================================================================================================
; Name ..........: _CF_OpenStorage
; Description ...: Opens a sub-storage and returns a new view handle whose paths are relative to it.
; Syntax ........: _CF_OpenStorage($hCF, $sPath)
; Parameters ....: $hCF   - Handle returned by _CF_Create, _CF_Open or _CF_OpenStorage.
;                  $sPath - Relative path of an existing storage.
; Return values .: Success: handle >= 1 (view handle).
;                  Failure: 0, with @error set to a $CF_ERR_* code and @extended set to the raw HRESULT (0 if none).
; Author ........: Numeric1
; Remarks .......: Storages are opened with exclusive sharing: opening an element that is already open
;                  fails with $CF_ERR_ACCESS. Close the view with _CF_Close before opening it again.
; Related .......: _CF_CreateStorage, _CF_Close
; ===============================================================================================================================
Func _CF_OpenStorage($hCF, $sPath)
	$__CF_iLastError = $CF_ERR_NONE
	$__CF_iLastHR = 0
	Local $iRow = __CF_HandleRow($hCF)
	If $iRow < 0 Then
		__CF_Fail($CF_ERR_HANDLE, 0, "_CF_OpenStorage")
		Return SetError($__CF_iLastError, $__CF_iLastHR, 0)
	EndIf
	If Not IsString($sPath) Or $sPath = "" Then
		__CF_Fail($CF_ERR_PATH, 0, "_CF_OpenStorage")
		Return SetError($__CF_iLastError, $__CF_iLastHR, 0)
	EndIf

	Local $aParts
	If Not __CF_SplitPath($sPath, $aParts) Then
		__CF_Fail($CF_ERR_PATH, 0, "_CF_OpenStorage")
		Return SetError($__CF_iLastError, $__CF_iLastHR, 0)
	EndIf
	Local $sLeaf = $aParts[UBound($aParts) - 1]
	Local $sDir = __CF_JoinParts($aParts, UBound($aParts) - 1)
	Local $sRelative = __CF_JoinParts($aParts, UBound($aParts))

	Local $bTrans = $__CF_aHandles[$iRow][7]
	Local $aChain = 0
	Local $oParent = __CF_WalkStorage($hCF, $sDir, False, $aChain)
	Local $iErr = @error, $iExt = @extended
	If Not IsObj($oParent) Then
		__CF_MapWalkError($iErr, $iExt, "_CF_OpenStorage")
		Return SetError($__CF_iLastError, $__CF_iLastHR, 0)
	EndIf

	Local $iFlags = BitOR($__CF_STGM_READWRITE, $__CF_STGM_SHARE_EXCLUSIVE)
	If $bTrans Then $iFlags = BitOR($iFlags, $__CF_STGM_TRANSACTED)

	Local $pStorage = 0
	Local $iHR = $oParent.OpenStorage($sLeaf, 0, $iFlags, 0, 0, $pStorage)
	If $iHR <> 0 Then
		__CF_Fail(__CF_HResultToError($iHR), $iHR, "_CF_OpenStorage")
		Return SetError($__CF_iLastError, $__CF_iLastHR, 0)
	EndIf

	Local $oStorage = ObjCreateInterface($pStorage, $__CF_IID_IStorage, $__CF_tagIStorage)
	If Not IsObj($oStorage) Then
		__CF_ReleaseRaw($pStorage)
		__CF_Fail($CF_ERR_STORAGE, 0, "_CF_OpenStorage")
		Return SetError($__CF_iLastError, $__CF_iLastHR, 0)
	EndIf

	Local $sBase = __CF_JoinPath($__CF_aHandles[$iRow][5], $sRelative)
	Return __CF_HandleAlloc($__CF_HT_VIEW, $oStorage, $__CF_aHandles[$iRow][3], _
			$__CF_aHandles[$iRow][4], $sBase, $hCF, $bTrans, $aChain)
EndFunc   ;==>_CF_OpenStorage

; #FUNCTION# ====================================================================================================================
; Name ..........: _CF_WriteStream
; Description ...: Writes a stream, creating intermediate storages as needed.
; Syntax ........: _CF_WriteStream($hCF, $sPath, $vData[, $iMode = $CF_AUTO[, $bOverwrite = True]])
; Parameters ....: $hCF        - Handle returned by _CF_Create, _CF_Open or _CF_OpenStorage.
;                  $sPath      - Relative path of the stream, e.g. "Assets\Images\logo.png".
;                  $vData      - String (text) or binary to write.
;                  $iMode      - $CF_AUTO (default), $CF_TEXT or $CF_BINARY.
;                  $bOverwrite - Default True. When False, an existing stream is not replaced.
; Return values .: Success: True.
;                  Failure: False, with @error set to a $CF_ERR_* code and @extended set to the raw HRESULT (0 if none).
; Author ........: Numeric1
; Remarks .......: $CF_AUTO writes strings as UTF-8 without BOM and binary data as raw bytes. A binary holding
;                  valid UTF-8 is still written byte for byte. Contents are written in 64 KiB blocks.
; Related .......: _CF_ReadStream, _CF_CreateStorage
; ===============================================================================================================================
Func _CF_WriteStream($hCF, $sPath, $vData, $iMode = Default, $bOverwrite = True)
	$__CF_iLastError = $CF_ERR_NONE
	$__CF_iLastHR = 0
	Local $iRow = __CF_HandleRow($hCF)
	If $iRow < 0 Then
		__CF_Fail($CF_ERR_HANDLE, 0, "_CF_WriteStream")
		Return SetError($__CF_iLastError, $__CF_iLastHR, False)
	EndIf
	If $iMode = Default Then $iMode = $CF_AUTO
	If $iMode <> $CF_AUTO And $iMode <> $CF_TEXT And $iMode <> $CF_BINARY Then
		__CF_Fail($CF_ERR_FLAGS, 0, "_CF_WriteStream")
		Return SetError($__CF_iLastError, $__CF_iLastHR, False)
	EndIf

	Local $bData = Binary("")
	Switch $iMode
		Case $CF_TEXT
			If Not IsString($vData) Then
				__CF_Fail($CF_ERR_FLAGS, 0, "_CF_WriteStream")
				Return SetError($__CF_iLastError, $__CF_iLastHR, False)
			EndIf
			$bData = StringToBinary($vData, 4)
		Case $CF_BINARY
			If Not (IsString($vData) Or IsBinary($vData)) Then
				__CF_Fail($CF_ERR_FLAGS, 0, "_CF_WriteStream")
				Return SetError($__CF_iLastError, $__CF_iLastHR, False)
			EndIf
			$bData = Binary($vData)
		Case Else
			If IsBinary($vData) Then
				$bData = $vData
			ElseIf IsString($vData) Then
				$bData = StringToBinary($vData, 4)
			Else
				__CF_Fail($CF_ERR_FLAGS, 0, "_CF_WriteStream")
				Return SetError($__CF_iLastError, $__CF_iLastHR, False)
			EndIf
	EndSwitch

	Local $bTrans = $__CF_aHandles[$iRow][7]
	Local $sLeaf = ""
	Local $aChain = 0
	Local $oParent = __CF_OpenParent($hCF, $sPath, True, $sLeaf, $aChain)
	Local $iErr = @error, $iExt = @extended
	If Not IsObj($oParent) Then
		__CF_MapWalkError($iErr, $iExt, "_CF_WriteStream")
		Return SetError($__CF_iLastError, $__CF_iLastHR, False)
	EndIf

	Local $iFlags = BitOR($__CF_STGM_READWRITE, $__CF_STGM_SHARE_EXCLUSIVE)
	If $bOverwrite Then $iFlags = BitOR($iFlags, $__CF_STGM_CREATE)

	Local $pStream = 0
	Local $iHR = $oParent.CreateStream($sLeaf, $iFlags, 0, 0, $pStream)
	If $iHR <> 0 Then
		__CF_Fail(__CF_HResultToError($iHR), $iHR, "_CF_WriteStream")
		Return SetError($__CF_iLastError, $__CF_iLastHR, False)
	EndIf

	Local $oStream = ObjCreateInterface($pStream, $__CF_IID_IStream, $__CF_tagIStream)
	If Not IsObj($oStream) Then
		__CF_ReleaseRaw($pStream)
		__CF_Fail($CF_ERR_STREAM, 0, "_CF_WriteStream")
		Return SetError($__CF_iLastError, $__CF_iLastHR, False)
	EndIf

	Local $bWritten = __CF_WriteAll($oStream, $bData)
	Local $iWE = @error, $iWX = @extended
	$oStream = 0
	If Not $bWritten Then
		If $iWE = 1 Then
			__CF_Fail(__CF_HResultToError($iWX), $iWX, "_CF_WriteStream")
		Else
			__CF_Fail($CF_ERR_STREAM, $iWX, "_CF_WriteStream")
		EndIf
		Return SetError($__CF_iLastError, $__CF_iLastHR, False)
	EndIf

	If $bTrans Then
		Local $bOk = __CF_CommitChain($aChain)
		Local $iCH = @extended
		If Not $bOk Then
			__CF_Fail(__CF_HResultToError($iCH), $iCH, "_CF_WriteStream")
			Return SetError($__CF_iLastError, $__CF_iLastHR, False)
		EndIf
	EndIf
	Return True
EndFunc   ;==>_CF_WriteStream

; #FUNCTION# ====================================================================================================================
; Name ..........: _CF_ReadStream
; Description ...: Reads a stream and returns its content as a string or as binary data.
; Syntax ........: _CF_ReadStream($hCF, $sPath[, $iMode = $CF_AUTO])
; Parameters ....: $hCF   - Handle returned by _CF_Create, _CF_Open or _CF_OpenStorage.
;                  $sPath - Relative path of an existing stream.
;                  $iMode - $CF_AUTO (default), $CF_TEXT or $CF_BINARY.
; Return values .: Success: the stream content (string in text mode, binary in binary mode).
;                  Failure: "", with @error set to a $CF_ERR_* code and @extended set to the raw HRESULT (0 if none).
; Author ........: Numeric1
; Remarks .......: $CF_AUTO returns text when the bytes are valid UTF-8 without NUL, binary otherwise.
;                  $CF_TEXT fails with $CF_ERR_ENCODING when the stream is not valid UTF-8.
; Related .......: _CF_WriteStream
; ===============================================================================================================================
Func _CF_ReadStream($hCF, $sPath, $iMode = Default)
	$__CF_iLastError = $CF_ERR_NONE
	$__CF_iLastHR = 0
	Local $iRow = __CF_HandleRow($hCF)
	If $iRow < 0 Then
		__CF_Fail($CF_ERR_HANDLE, 0, "_CF_ReadStream")
		Return SetError($__CF_iLastError, $__CF_iLastHR, "")
	EndIf
	If $iMode = Default Then $iMode = $CF_AUTO
	If $iMode <> $CF_AUTO And $iMode <> $CF_TEXT And $iMode <> $CF_BINARY Then
		__CF_Fail($CF_ERR_FLAGS, 0, "_CF_ReadStream")
		Return SetError($__CF_iLastError, $__CF_iLastHR, "")
	EndIf

	Local $sLeaf = ""
	Local $aChain = 0
	Local $oParent = __CF_OpenParent($hCF, $sPath, False, $sLeaf, $aChain)
	Local $iErr = @error, $iExt = @extended
	If Not IsObj($oParent) Then
		__CF_MapWalkError($iErr, $iExt, "_CF_ReadStream")
		Return SetError($__CF_iLastError, $__CF_iLastHR, "")
	EndIf

	Local $pStream = 0
	Local $iHR = $oParent.OpenStream($sLeaf, 0, _
			BitOR($__CF_STGM_READ, $__CF_STGM_SHARE_EXCLUSIVE), 0, $pStream)
	If $iHR <> 0 Then
		__CF_Fail(__CF_HResultToError($iHR), $iHR, "_CF_ReadStream")
		Return SetError($__CF_iLastError, $__CF_iLastHR, "")
	EndIf

	Local $oStream = ObjCreateInterface($pStream, $__CF_IID_IStream, $__CF_tagIStream)
	If Not IsObj($oStream) Then
		__CF_ReleaseRaw($pStream)
		__CF_Fail($CF_ERR_STREAM, 0, "_CF_ReadStream")
		Return SetError($__CF_iLastError, $__CF_iLastHR, "")
	EndIf

	Local $bData = Binary("")
	Local $bRead = __CF_ReadAll($oStream, $bData)
	Local $iRE = @error, $iRX = @extended
	$oStream = 0
	If Not $bRead Then
		If $iRE = 1 Or $iRE = 3 Then
			__CF_Fail(__CF_HResultToError($iRX), $iRX, "_CF_ReadStream")
		Else
			__CF_Fail($CF_ERR_STREAM, $iRX, "_CF_ReadStream")
		EndIf
		Return SetError($__CF_iLastError, $__CF_iLastHR, "")
	EndIf

	Switch $iMode
		Case $CF_BINARY
			Return $bData
		Case $CF_TEXT
			If Not __CF_IsUtf8($bData) Then
				__CF_Fail($CF_ERR_ENCODING, 0, "_CF_ReadStream")
				Return SetError($__CF_iLastError, $__CF_iLastHR, "")
			EndIf
			Return BinaryToString($bData, 4)
		Case Else
			If __CF_LooksText($bData) Then Return BinaryToString($bData, 4)
			Return $bData
	EndSwitch
EndFunc   ;==>_CF_ReadStream

; #FUNCTION# ====================================================================================================================
; Name ..........: _CF_GetLastErrorMessage
; Description ...: Returns a human readable description of the last CompoundFile error.
; Syntax ........: _CF_GetLastErrorMessage()
; Parameters ....: None.
; Return values .: Success: description string ("" when no error occurred since the last call).
; Author ........: Numeric1
; Remarks .......: The text includes the failing function, the error code and the raw HRESULT when available.
; Related .......: _CF_Create, _CF_Open, _CF_WriteStream, _CF_ReadStream
; ===============================================================================================================================
Func _CF_GetLastErrorMessage()
	If $__CF_iLastError = $CF_ERR_NONE Then Return ""
	Local $sText = $__CF_sLastFunc & ": " & __CF_ErrorText($__CF_iLastError)
	If $__CF_iLastHR <> 0 Then
		$sText &= " (0x" & Hex($__CF_iLastHR, 8) & __CF_HResultName($__CF_iLastHR) & ")"
	EndIf
	Return $sText
EndFunc   ;==>_CF_GetLastErrorMessage

; #FUNCTION# ====================================================================================================================
; Name ..........: _CF_Exists
; Description ...: Checks whether an element exists and returns its type.
; Syntax ........: _CF_Exists($hCF, $sPath)
; Parameters ....: $hCF   - Handle returned by _CF_Create, _CF_Open or _CF_OpenStorage.
;                  $sPath - Relative path of the element.
; Return values .: Success: 0 (absent), $CF_TYPE_STORAGE or $CF_TYPE_STREAM.
;                  Failure: -1, with @error set to a $CF_ERR_* code and @extended set to the raw HRESULT (0 if none).
; Author ........: Numeric1
; Remarks .......: Names are matched case-insensitively, like OLE does.
; Related .......: _CF_Stat, _CF_Enum
; ===============================================================================================================================
Func _CF_Exists($hCF, $sPath)
	$__CF_iLastError = $CF_ERR_NONE
	$__CF_iLastHR = 0
	Local $iRow = __CF_HandleRow($hCF)
	If $iRow < 0 Then
		__CF_Fail($CF_ERR_HANDLE, 0, "_CF_Exists")
		Return SetError($__CF_iLastError, $__CF_iLastHR, -1)
	EndIf
	Local $iSize = 0
	Local $iType = __CF_ProbeElement($hCF, $sPath, $iSize)
	Local $iErr = @error, $iExt = @extended
	If $iErr Then
		__CF_MapWalkError($iErr, $iExt, "_CF_Exists")
		Return SetError($__CF_iLastError, $__CF_iLastHR, -1)
	EndIf
	Return $iType
EndFunc   ;==>_CF_Exists

; #FUNCTION# ====================================================================================================================
; Name ..........: _CF_Stat
; Description ...: Returns the type and the size of an element.
; Syntax ........: _CF_Stat($hCF, $sPath)
; Parameters ....: $hCF   - Handle returned by _CF_Create, _CF_Open or _CF_OpenStorage.
;                  $sPath - Relative path of the element.
; Return values .: Success: 2-element array: [0] type ($CF_TYPE_STORAGE or $CF_TYPE_STREAM),
;                  [1] size in bytes (0 for storages).
;                  Failure: 0, with @error set to a $CF_ERR_* code and @extended set to the raw HRESULT (0 if none).
; Author ........: Numeric1
; Remarks .......: The size reflects the committed content: it does not change until the
;                  next commit in transacted mode. Modification times are not reported:
;                  Structured Storage does not maintain reliable timestamps.
; Related .......: _CF_Exists, _CF_Enum
; ===============================================================================================================================
Func _CF_Stat($hCF, $sPath)
	$__CF_iLastError = $CF_ERR_NONE
	$__CF_iLastHR = 0
	Local $iRow = __CF_HandleRow($hCF)
	If $iRow < 0 Then
		__CF_Fail($CF_ERR_HANDLE, 0, "_CF_Stat")
		Return SetError($__CF_iLastError, $__CF_iLastHR, 0)
	EndIf
	Local $iSize = 0
	Local $iType = __CF_ProbeElement($hCF, $sPath, $iSize)
	Local $iErr = @error, $iExt = @extended
	If $iErr Then
		__CF_MapWalkError($iErr, $iExt, "_CF_Stat")
		Return SetError($__CF_iLastError, $__CF_iLastHR, 0)
	EndIf
	If $iType = 0 Then
		__CF_Fail($CF_ERR_NOT_FOUND, 0, "_CF_Stat")
		Return SetError($__CF_iLastError, $__CF_iLastHR, 0)
	EndIf
	Local $aResult[2] = [$iType, $iSize]
	Return $aResult
EndFunc   ;==>_CF_Stat

; #FUNCTION# ====================================================================================================================
; Name ..........: _CF_Enum
; Description ...: Lists the direct children of a storage.
; Syntax ........: _CF_Enum($hCF[, $sPath = ""])
; Parameters ....: $hCF   - Handle returned by _CF_Create, _CF_Open or _CF_OpenStorage.
;                  $sPath - Relative path of a storage ("" lists the handle's own storage).
; Return values .: Success: 2D array, [0][0] holds the entry count and [i][0] the name,
;                  [i][1] the type ($CF_TYPE_STORAGE or $CF_TYPE_STREAM) of the i-th entry,
;                  sorted ascending by name (case-insensitive). An empty storage gives [0][0] = 0.
;                  Failure: 0, with @error set to a $CF_ERR_* code and @extended set to the raw HRESULT (0 if none).
; Author ........: Numeric1
; Remarks .......: The snapshot is taken at call time; it does not refresh automatically.
; Related .......: _CF_Exists, _CF_Stat
; ===============================================================================================================================
Func _CF_Enum($hCF, $sPath = Default)
	$__CF_iLastError = $CF_ERR_NONE
	$__CF_iLastHR = 0
	Local $iRow = __CF_HandleRow($hCF)
	If $iRow < 0 Then
		__CF_Fail($CF_ERR_HANDLE, 0, "_CF_Enum")
		Return SetError($__CF_iLastError, $__CF_iLastHR, 0)
	EndIf
	If $sPath = Default Then $sPath = ""
	If Not IsString($sPath) Then
		__CF_Fail($CF_ERR_PATH, 0, "_CF_Enum")
		Return SetError($__CF_iLastError, $__CF_iLastHR, 0)
	EndIf
	Local $aChain = 0
	Local $oStorage = __CF_WalkStorage($hCF, $sPath, False, $aChain)
	Local $iErr = @error, $iExt = @extended
	If Not IsObj($oStorage) Then
		__CF_MapWalkError($iErr, $iExt, "_CF_Enum")
		Return SetError($__CF_iLastError, $__CF_iLastHR, 0)
	EndIf
	Local $aList = 0
	Local $bOk = __CF_EnumElements($oStorage, $aList)
	$iErr = @error
	$iExt = @extended
	If Not $bOk Then
		If $iErr = 1 Then
			__CF_Fail(__CF_HResultToError($iExt), $iExt, "_CF_Enum")
		Else
			__CF_Fail($CF_ERR_STORAGE, 0, "_CF_Enum")
		EndIf
		Return SetError($__CF_iLastError, $__CF_iLastHR, 0)
	EndIf
	Return $aList
EndFunc   ;==>_CF_Enum

; #FUNCTION# ====================================================================================================================
; Name ..........: _CF_Delete
; Description ...: Deletes a stream or a storage with its entire content.
; Syntax ........: _CF_Delete($hCF, $sPath)
; Parameters ....: $hCF   - Handle returned by _CF_Create, _CF_Open or _CF_OpenStorage.
;                  $sPath - Relative path of the element to delete.
; Return values .: Success: True.
;                  Failure: False, with @error set to a $CF_ERR_* code and @extended set to the raw HRESULT (0 if none).
; Author ........: Numeric1
; Remarks .......: Deleting an element at or below a storage held by an open view fails with
;                  $CF_ERR_ACCESS: the view would otherwise be orphaned.
; Related .......: _CF_Rename, _CF_CreateStorage
; ===============================================================================================================================
Func _CF_Delete($hCF, $sPath)
	$__CF_iLastError = $CF_ERR_NONE
	$__CF_iLastHR = 0
	Local $iRow = __CF_HandleRow($hCF)
	If $iRow < 0 Then
		__CF_Fail($CF_ERR_HANDLE, 0, "_CF_Delete")
		Return SetError($__CF_iLastError, $__CF_iLastHR, False)
	EndIf
	If Not IsString($sPath) Or $sPath = "" Then
		__CF_Fail($CF_ERR_PATH, 0, "_CF_Delete")
		Return SetError($__CF_iLastError, $__CF_iLastHR, False)
	EndIf

	Local $sAbs = __CF_JoinPath($__CF_aHandles[$iRow][5], StringReplace($sPath, "/", "\"))
	If __CF_ViewUnder($__CF_aHandles[$iRow][3], $sAbs) Then
		__CF_Fail($CF_ERR_ACCESS, 0, "_CF_Delete")
		Return SetError($__CF_iLastError, $__CF_iLastHR, False)
	EndIf

	Local $bTrans = $__CF_aHandles[$iRow][7]
	Local $sLeaf = ""
	Local $aChain = 0
	Local $oParent = __CF_OpenParent($hCF, $sPath, False, $sLeaf, $aChain)
	Local $iErr = @error, $iExt = @extended
	If Not IsObj($oParent) Then
		__CF_MapWalkError($iErr, $iExt, "_CF_Delete")
		Return SetError($__CF_iLastError, $__CF_iLastHR, False)
	EndIf

	Local $iHR = $oParent.DestroyElement($sLeaf)
	If $iHR <> 0 Then
		__CF_Fail(__CF_HResultToError($iHR), $iHR, "_CF_Delete")
		Return SetError($__CF_iLastError, $__CF_iLastHR, False)
	EndIf

	If $bTrans Then
		Local $bOk = __CF_CommitChain($aChain)
		Local $iCH = @extended
		If Not $bOk Then
			__CF_Fail(__CF_HResultToError($iCH), $iCH, "_CF_Delete")
			Return SetError($__CF_iLastError, $__CF_iLastHR, False)
		EndIf
	EndIf
	Return True
EndFunc   ;==>_CF_Delete

; #FUNCTION# ====================================================================================================================
; Name ..........: _CF_Rename
; Description ...: Renames a stream or a storage inside its parent.
; Syntax ........: _CF_Rename($hCF, $sPath, $sNewName)
; Parameters ....: $hCF      - Handle returned by _CF_Create, _CF_Open or _CF_OpenStorage.
;                  $sPath    - Relative path of the element to rename.
;                  $sNewName - New name, a single component without separators.
; Return values .: Success: True.
;                  Failure: False, with @error set to a $CF_ERR_* code and @extended set to the raw HRESULT (0 if none).
; Author ........: Numeric1
; Remarks .......: Renaming to an existing name fails with $CF_ERR_EXISTS. Renaming to the same
;                  name (same case) succeeds without doing anything. Renaming an element at or
;                  below a storage held by an open view fails with $CF_ERR_ACCESS.
; Related .......: _CF_Delete, _CF_CreateStorage
; ===============================================================================================================================
Func _CF_Rename($hCF, $sPath, $sNewName)
	$__CF_iLastError = $CF_ERR_NONE
	$__CF_iLastHR = 0
	Local $iRow = __CF_HandleRow($hCF)
	If $iRow < 0 Then
		__CF_Fail($CF_ERR_HANDLE, 0, "_CF_Rename")
		Return SetError($__CF_iLastError, $__CF_iLastHR, False)
	EndIf
	If Not __CF_ValidName($sNewName) Then
		__CF_Fail($CF_ERR_PATH, 0, "_CF_Rename")
		Return SetError($__CF_iLastError, $__CF_iLastHR, False)
	EndIf

	Local $aParts
	If Not __CF_SplitPath($sPath, $aParts) Then
		__CF_Fail($CF_ERR_PATH, 0, "_CF_Rename")
		Return SetError($__CF_iLastError, $__CF_iLastHR, False)
	EndIf
	Local $sLeaf = $aParts[UBound($aParts) - 1]
	Local $sDir = __CF_JoinParts($aParts, UBound($aParts) - 1)

	If $sNewName == $sLeaf Then
		Return True
	EndIf

	Local $sAbs = __CF_JoinPath($__CF_aHandles[$iRow][5], __CF_JoinParts($aParts, UBound($aParts)))
	If __CF_ViewUnder($__CF_aHandles[$iRow][3], $sAbs) Then
		__CF_Fail($CF_ERR_ACCESS, 0, "_CF_Rename")
		Return SetError($__CF_iLastError, $__CF_iLastHR, False)
	EndIf

	Local $iSize = 0
	Local $iTarget = __CF_ProbeElement($hCF, __CF_JoinPath($sDir, $sNewName), $iSize)
	Local $iErr = @error, $iExt = @extended
	If $iErr Then
		__CF_MapWalkError($iErr, $iExt, "_CF_Rename")
		Return SetError($__CF_iLastError, $__CF_iLastHR, False)
	EndIf
	If $iTarget <> 0 Then
		__CF_Fail($CF_ERR_EXISTS, 0, "_CF_Rename")
		Return SetError($__CF_iLastError, $__CF_iLastHR, False)
	EndIf

	Local $bTrans = $__CF_aHandles[$iRow][7]
	Local $aChain = 0
	Local $oParent = __CF_OpenParent($hCF, $sPath, False, $sLeaf, $aChain)
	$iErr = @error
	$iExt = @extended
	If Not IsObj($oParent) Then
		__CF_MapWalkError($iErr, $iExt, "_CF_Rename")
		Return SetError($__CF_iLastError, $__CF_iLastHR, False)
	EndIf

	Local $iHR = $oParent.RenameElement($sLeaf, $sNewName)
	If $iHR <> 0 Then
		__CF_Fail(__CF_HResultToError($iHR), $iHR, "_CF_Rename")
		Return SetError($__CF_iLastError, $__CF_iLastHR, False)
	EndIf

	If $bTrans Then
		Local $bOk = __CF_CommitChain($aChain)
		Local $iCH = @extended
		If Not $bOk Then
			__CF_Fail(__CF_HResultToError($iCH), $iCH, "_CF_Rename")
			Return SetError($__CF_iLastError, $__CF_iLastHR, False)
		EndIf
	EndIf
	Return True
EndFunc   ;==>_CF_Rename

; #FUNCTION# ====================================================================================================================
; Name ..........: _CF_Commit
; Description ...: Commits the changes of a transacted handle to the underlying storage.
; Syntax ........: _CF_Commit($hCF)
; Parameters ....: $hCF - Handle returned by _CF_Create or _CF_Open with the $CF_TRANSACTED flag,
;                        or a view opened from such a handle.
; Return values .: Success: True.
;                  Failure: False, with @error set to a $CF_ERR_* code and @extended set to the raw HRESULT (0 if none).
; Author ........: Numeric1
; Remarks .......: Committing a root handle also commits every open transacted view first.
;                  On a direct-mode handle this fails with $CF_ERR_NOT_TRANSACTED.
; Related .......: _CF_Revert, _CF_Close
; ===============================================================================================================================
Func _CF_Commit($hCF)
	$__CF_iLastError = $CF_ERR_NONE
	$__CF_iLastHR = 0
	Local $iRow = __CF_HandleRow($hCF)
	If $iRow < 0 Then
		__CF_Fail($CF_ERR_HANDLE, 0, "_CF_Commit")
		Return SetError($__CF_iLastError, $__CF_iLastHR, False)
	EndIf
	If Not $__CF_aHandles[$iRow][7] Then
		__CF_Fail($CF_ERR_NOT_TRANSACTED, 0, "_CF_Commit")
		Return SetError($__CF_iLastError, $__CF_iLastHR, False)
	EndIf

	Local $bViewsOk = __CF_CommitViews($hCF)
	Local $iVHR = @extended

	Local $oStorage = $__CF_aHandles[$iRow][2]
	Local $iHR = $oStorage.Commit($__CF_STGC_DEFAULT)
	If $iHR = 0 Then
		Local $aChain = $__CF_aHandles[$iRow][8]
		Local $bChainOk = __CF_CommitChain($aChain)
		If Not $bChainOk Then
			$iHR = @extended
		EndIf
	EndIf
	If $iHR <> 0 Then
		__CF_Fail(__CF_HResultToError($iHR), $iHR, "_CF_Commit")
		Return SetError($__CF_iLastError, $__CF_iLastHR, False)
	EndIf
	If Not $bViewsOk Then
		__CF_Fail(__CF_HResultToError($iVHR), $iVHR, "_CF_Commit")
		Return SetError($__CF_iLastError, $__CF_iLastHR, False)
	EndIf
	Return True
EndFunc   ;==>_CF_Commit

; #FUNCTION# ====================================================================================================================
; Name ..........: _CF_Revert
; Description ...: Discards the uncommitted changes of a transacted handle.
; Syntax ........: _CF_Revert($hCF)
; Parameters ....: $hCF - Handle returned by _CF_Create or _CF_Open with the $CF_TRANSACTED flag,
;                        or a view opened from such a handle.
; Return values .: Success: True.
;                  Failure: False, with @error set to a $CF_ERR_* code and @extended set to the raw HRESULT (0 if none).
; Author ........: Numeric1
; Remarks .......: Open views are closed without committing: their changes are discarded too.
;                  On a direct-mode handle this fails with $CF_ERR_NOT_TRANSACTED.
; Related .......: _CF_Commit, _CF_Close
; ===============================================================================================================================
Func _CF_Revert($hCF)
	$__CF_iLastError = $CF_ERR_NONE
	$__CF_iLastHR = 0
	Local $iRow = __CF_HandleRow($hCF)
	If $iRow < 0 Then
		__CF_Fail($CF_ERR_HANDLE, 0, "_CF_Revert")
		Return SetError($__CF_iLastError, $__CF_iLastHR, False)
	EndIf
	If Not $__CF_aHandles[$iRow][7] Then
		__CF_Fail($CF_ERR_NOT_TRANSACTED, 0, "_CF_Revert")
		Return SetError($__CF_iLastError, $__CF_iLastHR, False)
	EndIf

	__CF_DiscardViews($hCF)

	Local $oStorage = $__CF_aHandles[$iRow][2]
	Local $iHR = $oStorage.Revert()
	If $iHR <> 0 Then
		__CF_Fail(__CF_HResultToError($iHR), $iHR, "_CF_Revert")
		Return SetError($__CF_iLastError, $__CF_iLastHR, False)
	EndIf
	Return True
EndFunc   ;==>_CF_Revert

; #INTERNAL# ====================================================================================================================

; Records the failure state. Callers must issue "Return SetError($__CF_iLastError, $__CF_iLastHR, $value)"
; in their own body: AutoIt does not propagate @error through nested function calls.
Func __CF_Fail($iCode, $iHR, $sFunc)
	$__CF_iLastError = $iCode
	$__CF_iLastHR = $iHR
	$__CF_sLastFunc = $sFunc
EndFunc   ;==>__CF_Fail

Func __CF_MapWalkError($iErr, $iExt, $sFunc)
	Switch $iErr
		Case 3
			__CF_Fail($CF_ERR_PATH, 0, $sFunc)
		Case 1
			__CF_Fail(__CF_HResultToError($iExt), $iExt, $sFunc)
		Case Else
			__CF_Fail($CF_ERR_STORAGE, 0, $sFunc)
	EndSwitch
EndFunc   ;==>__CF_MapWalkError

Func __CF_ErrorText($iCode)
	Switch $iCode
		Case $CF_ERR_HANDLE
			Return "invalid or closed handle"
		Case $CF_ERR_PATH
			Return "invalid path or element name"
		Case $CF_ERR_NOT_FOUND
			Return "file or element not found"
		Case $CF_ERR_EXISTS
			Return "element or file already exists"
		Case $CF_ERR_ACCESS
			Return "access denied, element already open"
		Case $CF_ERR_FLAGS
			Return "invalid flag or parameter for this call"
		Case $CF_ERR_STORAGE
			Return "internal storage failure"
		Case $CF_ERR_STREAM
			Return "stream read or write failure"
		Case $CF_ERR_ENCODING
			Return "data is not valid UTF-8"
		Case $CF_ERR_NOT_TRANSACTED
			Return "storage is not in transacted mode"
		Case $CF_ERR_MEMORY
			Return "buffer allocation failure"
		Case $CF_ERR_FORMAT
			Return "file is not a compound file"
		Case Else
			Return "unexpected compound file error"
	EndSwitch
EndFunc   ;==>__CF_ErrorText

Func __CF_HResultName($iHR)
	Switch Hex($iHR, 8)
		Case "80030002"
			Return " STG_E_FILENOTFOUND"
		Case "80030003"
			Return " STG_E_PATHNOTFOUND"
		Case "80030005"
			Return " STG_E_ACCESSDENIED"
		Case "80030050"
			Return " STG_E_FILEALREADYEXISTS"
		Case "80030057"
			Return " STG_E_INVALIDPARAMETER"
		Case "800300FF"
			Return " STG_E_INVALIDFLAG"
		Case "80030102"
			Return " STG_E_REVERTED"
		Case Else
			Return ""
	EndSwitch
EndFunc   ;==>__CF_HResultName

Func __CF_HResultToError($iHR)
	Switch Hex($iHR, 8)
		Case "80030002", "80030003"
			Return $CF_ERR_NOT_FOUND
		Case "80030005", "80030102"
			Return $CF_ERR_ACCESS
		Case "80030020", "80030057", "800300FF"
			Return $CF_ERR_FLAGS
		Case "80030050"
			Return $CF_ERR_EXISTS
		Case Else
			Return $CF_ERR_HRESULT
	EndSwitch
EndFunc   ;==>__CF_HResultToError

Func __CF_GUIDStruct($sIID)
	Local $tGUID = DllStructCreate("byte[16]")
	Local $aCall = DllCall("ole32.dll", "long", "CLSIDFromString", "wstr", $sIID, "ptr", DllStructGetPtr($tGUID))
	If @error Then Return SetError(1, 0, 0)
	If $aCall[0] <> 0 Then Return SetError(2, $aCall[0], 0)
	Return $tGUID
EndFunc   ;==>__CF_GUIDStruct

Func __CF_IsStorageFile($sFile)
	Local $aCall = DllCall("ole32.dll", "long", "StgIsStorageFile", "wstr", $sFile)
	If @error Then Return False
	Return $aCall[0] = 0
EndFunc   ;==>__CF_IsStorageFile

Func __CF_CreateRoot($sFile, $iMode)
	Local $tIID = __CF_GUIDStruct($__CF_IID_IStorage)
	If @error Then Return SetError(1, 0, 0)
	Local $aCall = DllCall("ole32.dll", "long", "StgCreateStorageEx", "wstr", $sFile, _
			"dword", $iMode, "dword", $__CF_STGFMT_STORAGE, "dword", 0, _
			"ptr", 0, "ptr", 0, "struct*", $tIID, "ptr*", 0)
	If @error Then Return SetError(1, 0, 0)
	If $aCall[0] <> 0 Then Return SetError(2, $aCall[0], 0)
	Local $pRoot = $aCall[8]
	If Not $pRoot Then Return SetError(3, 0, 0)
	Local $oRoot = ObjCreateInterface($pRoot, $__CF_IID_IStorage, $__CF_tagIStorage)
	If Not IsObj($oRoot) Then
		__CF_ReleaseRaw($pRoot)
		Return SetError(4, 0, 0)
	EndIf
	Return $oRoot
EndFunc   ;==>__CF_CreateRoot

Func __CF_OpenRoot($sFile, $iMode)
	Local $tIID = __CF_GUIDStruct($__CF_IID_IStorage)
	If @error Then Return SetError(1, 0, 0)
	Local $aCall = DllCall("ole32.dll", "long", "StgOpenStorageEx", "wstr", $sFile, _
			"dword", $iMode, "dword", $__CF_STGFMT_STORAGE, "dword", 0, _
			"ptr", 0, "ptr", 0, "struct*", $tIID, "ptr*", 0)
	If @error Then Return SetError(1, 0, 0)
	If $aCall[0] <> 0 Then Return SetError(2, $aCall[0], 0)
	Local $pRoot = $aCall[8]
	If Not $pRoot Then Return SetError(3, 0, 0)
	Local $oRoot = ObjCreateInterface($pRoot, $__CF_IID_IStorage, $__CF_tagIStorage)
	If Not IsObj($oRoot) Then
		__CF_ReleaseRaw($pRoot)
		Return SetError(4, 0, 0)
	EndIf
	Return $oRoot
EndFunc   ;==>__CF_OpenRoot

Func __CF_ReleaseRaw($pUnk)
	If Not $pUnk Then Return
	Local $oUnk = ObjCreateInterface($pUnk, $__CF_IID_IUnknown)
	If Not IsObj($oUnk) Then Return
	$oUnk = 0
EndFunc   ;==>__CF_ReleaseRaw

Func __CF_HandleRow($iId)
	If Not IsInt($iId) And Not IsNumber($iId) Then Return -1
	Local $i = 0
	For $i = 0 To $__CF_iHandleRows - 1
		If $__CF_aHandles[$i][0] = $iId Then Return $i
	Next
	Return -1
EndFunc   ;==>__CF_HandleRow

Func __CF_HandleAlloc($iType, $oStorage, $sFile, $iFlags, $sBase, $iParent, $bTransacted, $aChain = 0)
	Local $iRow = -1
	Local $i = 0
	For $i = 0 To $__CF_iHandleRows - 1
		If $__CF_aHandles[$i][0] = 0 Then
			$iRow = $i
			ExitLoop
		EndIf
	Next
	If $iRow < 0 Then
		$iRow = $__CF_iHandleRows
		$__CF_iHandleRows += 1
		ReDim $__CF_aHandles[$__CF_iHandleRows][$__CF_HANDLE_COLS]
	EndIf

	Local $iId = $__CF_iNextHandle
	$__CF_iNextHandle += 1
	$__CF_aHandles[$iRow][0] = $iId
	$__CF_aHandles[$iRow][1] = $iType
	$__CF_aHandles[$iRow][2] = $oStorage
	$__CF_aHandles[$iRow][3] = $sFile
	$__CF_aHandles[$iRow][4] = $iFlags
	$__CF_aHandles[$iRow][5] = $sBase
	$__CF_aHandles[$iRow][6] = $iParent
	$__CF_aHandles[$iRow][7] = $bTransacted
	$__CF_aHandles[$iRow][8] = $aChain
	Return $iId
EndFunc   ;==>__CF_HandleAlloc

Func __CF_HandleRelease($iRow)
	Local $oStorage = $__CF_aHandles[$iRow][2]
	__CF_HandleClear($iRow)
	If IsObj($oStorage) Then $oStorage = 0
EndFunc   ;==>__CF_HandleRelease

Func __CF_HandleClear($iRow)
	Local $i = 0
	For $i = 0 To $__CF_HANDLE_COLS - 1
		Switch $i
			Case 3, 5
				$__CF_aHandles[$iRow][$i] = ""
			Case Else
				$__CF_aHandles[$iRow][$i] = 0
		EndSwitch
	Next
EndFunc   ;==>__CF_HandleClear

Func __CF_CloseViews($iParentHandle)
	Local $i = 0
	For $i = 0 To $__CF_iHandleRows - 1
		If $__CF_aHandles[$i][0] <> 0 And $__CF_aHandles[$i][1] = $__CF_HT_VIEW _
				And $__CF_aHandles[$i][6] = $iParentHandle Then
			Local $iChild = $__CF_aHandles[$i][0]
			Local $bTrans = $__CF_aHandles[$i][7]
			Local $oChild = $__CF_aHandles[$i][2]
			Local $aChain = $__CF_aHandles[$i][8]
			Local $bGrandOk = __CF_CloseViews($iChild)
			Local $iGrandHR = @extended
			Local $iHR = 0
			If $bTrans And IsObj($oChild) Then
				$iHR = $oChild.Commit($__CF_STGC_DEFAULT)
				If $iHR = 0 Then
					Local $bChainOk = __CF_CommitChain($aChain)
					If Not $bChainOk Then $iHR = @extended
				EndIf
			EndIf
			__CF_HandleRelease($i)
			If $iHR <> 0 Then Return SetError(1, $iHR, False)
			If Not $bGrandOk Then Return SetError(1, $iGrandHR, False)
		EndIf
	Next
	Return True
EndFunc   ;==>__CF_CloseViews

Func __CF_CommitChain($aChain)
	If Not IsArray($aChain) Then Return True
	Local $i = $aChain[0]
	Local $oStorage = 0
	Local $iHR = 0
	While $i >= 1
		$oStorage = $aChain[$i]
		If IsObj($oStorage) Then
			$iHR = $oStorage.Commit($__CF_STGC_DEFAULT)
			If $iHR <> 0 Then Return SetError(1, $iHR, False)
		EndIf
		$i -= 1
	WEnd
	Return True
EndFunc   ;==>__CF_CommitChain

Func __CF_ValidName($sName)
	If Not IsString($sName) Then Return False
	Local $iLen = StringLen($sName)
	If $iLen = 0 Or $iLen > $__CF_MAX_NAME Then Return False
	If $sName = "." Or $sName = ".." Then Return False
	If StringRegExp($sName, "[\\/:!]") Then Return False
	If StringRegExp($sName, "[\x00-\x1F]") Then Return False
	Return True
EndFunc   ;==>__CF_ValidName

Func __CF_SplitPath($sPath, ByRef $aParts)
	$aParts = 0
	If Not IsString($sPath) Then Return False
	Local $sPathClean = StringReplace($sPath, "/", "\")
	If $sPathClean = "" Then Return False
	If StringLeft($sPathClean, 1) = "\" Or StringRight($sPathClean, 1) = "\" Then Return False
	Local $aSplit = StringSplit($sPathClean, "\", 2)
	If UBound($aSplit) = 0 Then Return False
	Local $i = 0
	For $i = 0 To UBound($aSplit) - 1
		If Not __CF_ValidName($aSplit[$i]) Then Return False
	Next
	$aParts = $aSplit
	Return True
EndFunc   ;==>__CF_SplitPath

Func __CF_JoinParts($aParts, $iCount)
	Local $sResult = ""
	Local $i = 0
	For $i = 0 To $iCount - 1
		If $i > 0 Then $sResult &= "\"
		$sResult &= $aParts[$i]
	Next
	Return $sResult
EndFunc   ;==>__CF_JoinParts

Func __CF_JoinPath($sBase, $sPath)
	If $sBase = "" Then Return $sPath
	Return $sBase & "\" & $sPath
EndFunc   ;==>__CF_JoinPath

; Returns the storage for $sDir (an IStorage object) and fills $aChain with every storage opened
; on the way: $aChain[0] is the count, $aChain[1..n] the storage objects from first to last.
; Those parents must stay referenced while the returned storage is used, otherwise OLE reports
; STG_E_REVERTED.
Func __CF_WalkStorage($iHandle, $sDir, $bCreate, ByRef $aChain)
	Local $aEmpty[1] = [0]
	$aChain = $aEmpty
	Local $iRow = __CF_HandleRow($iHandle)
	If $iRow < 0 Then Return SetError(4, 0, 0)
	Local $oCurrent = $__CF_aHandles[$iRow][2]
	If $sDir = "" Then Return $oCurrent

	Local $aParts
	If Not __CF_SplitPath($sDir, $aParts) Then Return SetError(3, 0, 0)

	Local $iOpenFlags = BitOR($__CF_STGM_READWRITE, $__CF_STGM_SHARE_EXCLUSIVE)
	If $__CF_aHandles[$iRow][7] Then $iOpenFlags = BitOR($iOpenFlags, $__CF_STGM_TRANSACTED)
	Local $iCreateFlags = $iOpenFlags

	Local $pStorage = 0
	Local $iHR = 0
	Local $oNext = 0
	Local $i = 0
	For $i = 0 To UBound($aParts) - 1
		$pStorage = 0
		$iHR = $oCurrent.OpenStorage($aParts[$i], 0, $iOpenFlags, 0, 0, $pStorage)
		If $iHR <> 0 And $bCreate Then
			$pStorage = 0
			$iHR = $oCurrent.CreateStorage($aParts[$i], $iCreateFlags, 0, 0, $pStorage)
		EndIf
		If $iHR <> 0 Or $pStorage = 0 Then Return SetError(1, $iHR, 0)
		$oNext = ObjCreateInterface($pStorage, $__CF_IID_IStorage, $__CF_tagIStorage)
		If Not IsObj($oNext) Then
			__CF_ReleaseRaw($pStorage)
			Return SetError(2, 0, 0)
		EndIf
		$aChain[0] += 1
		ReDim $aChain[$aChain[0] + 1]
		$aChain[$aChain[0]] = $oNext
		$oCurrent = $oNext
	Next
	Return $oCurrent
EndFunc   ;==>__CF_WalkStorage

Func __CF_OpenParent($iHandle, $sPath, $bCreate, ByRef $sLeaf, ByRef $aChain)
	$sLeaf = ""
	Local $aEmpty[1] = [0]
	$aChain = $aEmpty
	Local $iRow = __CF_HandleRow($iHandle)
	If $iRow < 0 Then Return SetError(4, 0, 0)
	Local $aParts
	If Not __CF_SplitPath($sPath, $aParts) Then Return SetError(3, 0, 0)
	$sLeaf = $aParts[UBound($aParts) - 1]
	Local $sDir = __CF_JoinParts($aParts, UBound($aParts) - 1)
	Local $oResult = __CF_WalkStorage($iHandle, $sDir, $bCreate, $aChain)
	Local $iErr = @error, $iExt = @extended
	If $iErr Then Return SetError($iErr, $iExt, 0)
	Return $oResult
EndFunc   ;==>__CF_OpenParent

; Returns the type of the element named by $sPath: 0 = absent, $CF_TYPE_STORAGE,
; $CF_TYPE_STREAM. $iSize receives the stream size (0 otherwise).
; Failure: 0 with @error set: 1 = COM failure (@extended = HRESULT), 2 = interface
; failure, 3 = invalid path, 4 = bad handle, 5 = unknown element type.
Func __CF_ProbeElement($iHandle, $sPath, ByRef $iSize)
	$iSize = 0
	Local $sLeaf = ""
	Local $aChain = 0
	Local $oParent = __CF_OpenParent($iHandle, $sPath, False, $sLeaf, $aChain)
	Local $iErr = @error, $iExt = @extended
	If Not IsObj($oParent) Then Return SetError($iErr, $iExt, 0)

	Local $pEnum = 0
	Local $iHR = $oParent.EnumElements(0, 0, 0, $pEnum)
	If $iHR <> 0 Then Return SetError(1, $iHR, 0)
	Local $oEnum = ObjCreateInterface($pEnum, $__CF_IID_IEnumSTATSTG, $__CF_tagIEnumSTATSTG)
	If Not IsObj($oEnum) Then
		__CF_ReleaseRaw($pEnum)
		Return SetError(2, 0, 0)
	EndIf

	Local $iGot = 0
	Local $tStat = 0
	Local $pName = 0
	Local $sName = ""
	While True
		$tStat = DllStructCreate($__CF_tagSTATSTG)
		$iGot = 0
		$iHR = $oEnum.Next(1, DllStructGetPtr($tStat), $iGot)
		If $iHR < 0 Then
			$oEnum = 0
			Return SetError(1, $iHR, 0)
		EndIf
		If $iGot = 0 Then ExitLoop
		$pName = DllStructGetData($tStat, "pwcsName")
		$sName = __CF_ReadWideString($pName)
		If $pName Then
			DllCall("ole32.dll", "none", "CoTaskMemFree", "ptr", $pName)
		EndIf
		If $sName = "" Then
			$oEnum = 0
			Return SetError(2, 0, 0)
		EndIf
		If $sName = $sLeaf Then
			Local $iType = DllStructGetData($tStat, "type")
			If $iType = $__CF_STGTY_STORAGE Then
				$oEnum = 0
				Return 1
			EndIf
			If $iType = $__CF_STGTY_STREAM Then
				$iSize = Int(DllStructGetData($tStat, "cbSize"))
				$oEnum = 0
				Return 2
			EndIf
			$oEnum = 0
			Return SetError(5, 0, 0)
		EndIf
	WEnd
	$oEnum = 0
	Return 0
EndFunc   ;==>__CF_ProbeElement

; Lists the children of $oStorage into $aList ([0][0] = count, [i][0] = name,
; [i][1] = type), sorted case-insensitively by name.
; Failure: False with @error set: 1 = COM failure (@extended = HRESULT), 2 = other.
Func __CF_EnumElements($oStorage, ByRef $aList)
	Local $aEmpty[1][2] = [[0, 0]]
	$aList = $aEmpty

	Local $pEnum = 0
	Local $iHR = $oStorage.EnumElements(0, 0, 0, $pEnum)
	If $iHR <> 0 Then Return SetError(1, $iHR, False)
	Local $oEnum = ObjCreateInterface($pEnum, $__CF_IID_IEnumSTATSTG, $__CF_tagIEnumSTATSTG)
	If Not IsObj($oEnum) Then
		__CF_ReleaseRaw($pEnum)
		Return SetError(2, 0, False)
	EndIf

	Local $iCount = 0
	Local $iGot = 0
	Local $tStat = 0
	Local $pName = 0
	Local $sName = ""
	Local $iType = 0
	While True
		$tStat = DllStructCreate($__CF_tagSTATSTG)
		$iGot = 0
		$iHR = $oEnum.Next(1, DllStructGetPtr($tStat), $iGot)
		If $iHR < 0 Then
			$oEnum = 0
			Return SetError(1, $iHR, False)
		EndIf
		If $iGot = 0 Then ExitLoop
		$pName = DllStructGetData($tStat, "pwcsName")
		$sName = __CF_ReadWideString($pName)
		If $pName Then
			DllCall("ole32.dll", "none", "CoTaskMemFree", "ptr", $pName)
		EndIf
		If $sName = "" Then
			$oEnum = 0
			Return SetError(2, 0, False)
		EndIf
		$iType = DllStructGetData($tStat, "type")
		If $iType <> $__CF_STGTY_STORAGE And $iType <> $__CF_STGTY_STREAM Then
			ContinueLoop
		EndIf
		$iCount += 1
		ReDim $aList[$iCount + 1][2]
		$aList[$iCount][0] = $sName
		$aList[$iCount][1] = $iType
		$aList[0][0] = $iCount
	WEnd
	$oEnum = 0
	__CF_SortEnum($aList)
	Return True
EndFunc   ;==>__CF_EnumElements

; Copies a zero-terminated wide string from COM memory.
Func __CF_ReadWideString($pWide)
	If Not $pWide Then Return SetError(1, 0, "")
	Local $aCall = DllCall("kernel32.dll", "int", "lstrlenW", "ptr", $pWide)
	If @error Or Not IsArray($aCall) Then Return SetError(2, 0, "")
	Local $iLen = $aCall[0]
	If $iLen <= 0 Then Return SetError(3, 0, "")
	Local $tWide = DllStructCreate("wchar[" & $iLen & "]")
	If Not IsDllStruct($tWide) Then Return SetError(4, 0, "")
	DllCall("kernel32.dll", "none", "RtlMoveMemory", "ptr", DllStructGetPtr($tWide), "ptr", $pWide, "ulong_ptr", $iLen * 2)
	Return DllStructGetData($tWide, 1)
EndFunc   ;==>__CF_ReadWideString

; Sorts an enumeration array in place by name, case-insensitive ascending.
Func __CF_SortEnum(ByRef $aList)
	Local $iN = $aList[0][0]
	If $iN < 2 Then Return
	Local $i = 1
	Local $j = 0
	Local $sName = ""
	Local $iType = 0
	For $i = 1 To $iN - 1
		$sName = $aList[$i][0]
		$iType = $aList[$i][1]
		$j = $i - 1
		While $j >= 0 And StringCompare($aList[$j][0], $sName) > 0
			$aList[$j + 1][0] = $aList[$j][0]
			$aList[$j + 1][1] = $aList[$j][1]
			$j -= 1
		WEnd
		$aList[$j + 1][0] = $sName
		$aList[$j + 1][1] = $iType
	Next
EndFunc   ;==>__CF_SortEnum

; Returns True when a view of $sFile is open at or below the absolute path $sAbs.
Func __CF_ViewUnder($sFile, $sAbs)
	Local $i = 0
	For $i = 0 To $__CF_iHandleRows - 1
		If $__CF_aHandles[$i][0] = 0 Or $__CF_aHandles[$i][1] <> $__CF_HT_VIEW Then ContinueLoop
		If $__CF_aHandles[$i][3] <> $sFile Then ContinueLoop
		Local $sBase = $__CF_aHandles[$i][5]
		If $sBase = $sAbs Then Return True
		If StringInStr($sBase, $sAbs & "\") = 1 Then Return True
	Next
	Return False
EndFunc   ;==>__CF_ViewUnder

; Commits every transacted view opened (directly or indirectly) from $iHandle.
; Children are committed before their parents, leaves first.
Func __CF_CommitViews($iHandle)
	Local $i = 0
	For $i = 0 To $__CF_iHandleRows - 1
		If $__CF_aHandles[$i][0] <> 0 And $__CF_aHandles[$i][1] = $__CF_HT_VIEW _
				And $__CF_aHandles[$i][6] = $iHandle Then
			Local $iChild = $__CF_aHandles[$i][0]
			Local $oChild = $__CF_aHandles[$i][2]
			Local $aChain = $__CF_aHandles[$i][8]
			Local $bGrandOk = __CF_CommitViews($iChild)
			Local $iGrandHR = @extended
			Local $iHR = 0
			If IsObj($oChild) And $__CF_aHandles[$i][7] Then
				$iHR = $oChild.Commit($__CF_STGC_DEFAULT)
				If $iHR = 0 Then
					Local $bChainOk = __CF_CommitChain($aChain)
					If Not $bChainOk Then $iHR = @extended
				EndIf
			EndIf
			If $iHR <> 0 Then Return SetError(1, $iHR, False)
			If Not $bGrandOk Then Return SetError(1, $iGrandHR, False)
		EndIf
	Next
	Return True
EndFunc   ;==>__CF_CommitViews

; Releases every view opened (directly or indirectly) from $iHandle without committing.
Func __CF_DiscardViews($iHandle)
	Local $i = 0
	For $i = 0 To $__CF_iHandleRows - 1
		If $__CF_aHandles[$i][0] <> 0 And $__CF_aHandles[$i][1] = $__CF_HT_VIEW _
				And $__CF_aHandles[$i][6] = $iHandle Then
			Local $iChild = $__CF_aHandles[$i][0]
			__CF_DiscardViews($iChild)
			__CF_HandleRelease($i)
		EndIf
	Next
EndFunc   ;==>__CF_DiscardViews

Func __CF_ReadAll($oStream, ByRef $bData)
	$bData = Binary("")
	Local $dPos = 0
	Local $iHR = $oStream.Seek(0, $__CF_STREAM_SEEK_SET, $dPos)
	If $iHR <> 0 Then Return SetError(1, $iHR, False)

	Local $tStat = DllStructCreate($__CF_tagSTATSTG)
	$iHR = $oStream.Stat(DllStructGetPtr($tStat), $__CF_STATFLAG_NONAME)
	If $iHR <> 0 Then Return SetError(1, $iHR, False)

	Local $dSize = DllStructGetData($tStat, "cbSize")
	If $dSize < 0 Or $dSize > 0x7FFFFFFF Then Return SetError(2, 0, False)
	Local $iSize = Int($dSize)
	If $iSize = 0 Then Return True

	Local $tAll = DllStructCreate("byte[" & $iSize & "]")
	If Not IsDllStruct($tAll) Then Return SetError(5, 0, False)
	Local $pAll = DllStructGetPtr($tAll)
	Local $iOffset = 0
	Local $iWant = 0
	Local $iRead = 0
	Local $tChunk = 0
	While $iOffset < $iSize
		$iWant = $iSize - $iOffset
		If $iWant > $__CF_CHUNK Then $iWant = $__CF_CHUNK
		$tChunk = DllStructCreate("byte[" & $iWant & "]", $pAll + $iOffset)
		$iRead = 0
		$iHR = $oStream.Read(DllStructGetPtr($tChunk), $iWant, $iRead)
		If $iHR <> 0 Then Return SetError(3, $iHR, False)
		If $iRead <> $iWant Then Return SetError(4, $iRead, False)
		$iOffset += $iRead
	WEnd

	$bData = DllStructGetData($tAll, 1)
	Return True
EndFunc   ;==>__CF_ReadAll

Func __CF_WriteAll($oStream, $bData)
	Local $iSize = BinaryLen($bData)
	If $iSize = 0 Then Return True
	If $iSize > 0x7FFFFFFF Then Return SetError(2, 0, False)

	Local $tAll = DllStructCreate("byte[" & $iSize & "]")
	If Not IsDllStruct($tAll) Then Return SetError(2, 0, False)
	DllStructSetData($tAll, 1, $bData)
	Local $pAll = DllStructGetPtr($tAll)
	Local $iOffset = 0
	Local $iWant = 0
	Local $iWritten = 0
	Local $iHR = 0
	Local $tChunk = 0
	While $iOffset < $iSize
		$iWant = $iSize - $iOffset
		If $iWant > $__CF_CHUNK Then $iWant = $__CF_CHUNK
		$tChunk = DllStructCreate("byte[" & $iWant & "]", $pAll + $iOffset)
		$iWritten = 0
		$iHR = $oStream.Write(DllStructGetPtr($tChunk), $iWant, $iWritten)
		If $iHR <> 0 Then Return SetError(1, $iHR, False)
		If $iWritten <> $iWant Then Return SetError(3, $iWritten, False)
		$iOffset += $iWritten
	WEnd

	Return True
EndFunc   ;==>__CF_WriteAll

Func __CF_IsUtf8($bData)
	If BinaryLen($bData) = 0 Then Return True
	Local $sText = BinaryToString($bData, 4)
	If StringInStr($sText, Chr(0)) Then Return False
	Return StringToBinary($sText, 4) = $bData
EndFunc   ;==>__CF_IsUtf8

Func __CF_LooksText($bData)
	Return __CF_IsUtf8($bData)
EndFunc   ;==>__CF_LooksText
