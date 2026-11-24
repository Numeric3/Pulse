#include-once

; #INDEX# =======================================================================================================================
; Title .........: WinEventManager
; AutoIt Version : v3.3.14.0 or higher
; Language ......: English
; Description ...: Professional, production-ready Windows Event Log and custom event manager for AutoIt.
;                 Enables creation, registration, writing, processing and persistence of Windows
;                 events. Designed to coexist with other event handlers in the same script.
;                 Uses the native Win32 Event Log API (advapi32.dll) via DllCall.
; Author ........: Numeric1
; Version .......: 1.4.1 (stable handler IDs, * and ? subscriptions, one-shot handlers, refusal by returning False, retry budget and dead-letter store)
;                  1.4.1 fixes the ownership read of _WinEvent_RegisterSource: a source this UDF
;                  registered was reported as belonging to another application when it was
;                  registered a second time.
; ===============================================================================================================================

; #COMMENTS# ====================================================================================================================
; --- Lifecycle; call Startup once, Shutdown on exit ----------------------------------------------------------------------------
; _WinEvent_Startup, _WinEvent_Shutdown, _WinEvent_IsInitialized
; --- Windows Event Log; writing entries and owning a source requires administrator rights -----------------------------------
; _WinEvent_RegisterSource, _WinEvent_UnregisterSource, _WinEvent_Write
; --- Custom events; handlers are plain AutoIt functions, 0, 1 or 2 parameters -------------------------------------------------
; _WinEvent_RegisterHandler, _WinEvent_UnregisterHandler, _WinEvent_UnregisterHandlerById
; Names may carry the wildcards * and ?, a handler may be armed to run once, and every
; registration gets a stable ID that never moves while the handler lives.
; --- Synchronous dispatch, queue, journal, dead letters, export -------------------------------------------------------------
; _WinEvent_Trigger, _WinEvent_Post, _WinEvent_Queued, _WinEvent_Process, _WinEvent_Journal, _WinEvent_ClearJournal
; _WinEvent_RetryLimit, _WinEvent_DeadMax, _WinEvent_DeadLettered, _WinEvent_DeadLetter, _WinEvent_Redeadmit, _WinEvent_ClearDeadLetters
; _WinEvent_SaveToFile
; --- Background pumping and diagnostics ---------------------------------------------------------------------------------------
; _WinEvent_EnableAdlib, _WinEvent_DisableAdlib, _WinEvent_GetLastError, _WinEvent_GetLastErrorMsg
; ===============================================================================================================================

; #CURRENT# =====================================================================================================================
; _WinEvent_Startup
; _WinEvent_Shutdown
; _WinEvent_RegisterSource
; _WinEvent_UnregisterSource
; _WinEvent_Write
; _WinEvent_RegisterHandler
; _WinEvent_UnregisterHandler
; _WinEvent_UnregisterHandlerById
; _WinEvent_Trigger
; _WinEvent_Post
; _WinEvent_Queued
; _WinEvent_Process
; _WinEvent_RetryLimit
; _WinEvent_DeadMax
; _WinEvent_DeadLettered
; _WinEvent_DeadLetter
; _WinEvent_Redeadmit
; _WinEvent_ClearDeadLetters
; _WinEvent_Journal
; _WinEvent_ClearJournal
; _WinEvent_SaveToFile
; _WinEvent_GetLastError
; _WinEvent_GetLastErrorMsg
; _WinEvent_IsInitialized
; _WinEvent_EnableAdlib
; _WinEvent_DisableAdlib
; ===============================================================================================================================

; #INTERNAL_USE_ONLY# ===========================================================================================================
; __WinEvent_SetError
; __WinEvent_RegCreateKey
; __WinEvent_RegQueryValueEx
; __WinEvent_RegCloseKey
; __WinEvent_RegSetValueEx
; __WinEvent_RegDeleteTree
; __WinEvent_LastError
; __WinEvent_QueueResize
; __WinEvent_QueueReset
; __WinEvent_QueuePush
; __WinEvent_QueuePop
; __WinEvent_JournalResize
; __WinEvent_JournalReset
; __WinEvent_JournalPush
; __WinEvent_Stamp
; __WinEvent_Cell
; __WinEvent_CheckSourceName
; __WinEvent_IsReservedSource
; __WinEvent_OwnedTest
; __WinEvent_OwnedAdd
; __WinEvent_OwnedRemove
; __WinEvent_MaskToRe
; __WinEvent_RemoveById
; __WinEvent_Invoke
; __WinEvent_Dispatch
; __WinEvent_Deliver
; __WinEvent_DeadPush
; __WinEvent_DeadReset
; __WinEvent_AdlibDispatch
; ===============================================================================================================================

; #CONSTANTS# ===================================================================================================================
; Error codes
Global Const $WINEVENT_OK                    = 0
Global Const $WINEVENT_ERR_GENERAL           = 1
Global Const $WINEVENT_ERR_NOT_INIT          = 2
Global Const $WINEVENT_ERR_INVALID_PARAM     = 3
Global Const $WINEVENT_ERR_REGISTRY          = 4
Global Const $WINEVENT_ERR_API_CALL          = 5
Global Const $WINEVENT_ERR_ALREADY_EXISTS    = 6
Global Const $WINEVENT_ERR_NOT_FOUND         = 7
Global Const $WINEVENT_ERR_ACCESS_DENIED     = 8
Global Const $WINEVENT_ERR_QUEUE_FULL        = 9
Global Const $WINEVENT_ERR_CALLBACK          = 10
Global Const $WINEVENT_ERR_BAD_NAME          = 11 ; source or log name outside the accepted charset
Global Const $WINEVENT_ERR_RESERVED_SOURCE   = 12 ; a source Windows owns, never registered or deleted here
Global Const $WINEVENT_ERR_NOT_OURS          = 13 ; this process did not register that source

; Value this UDF writes to EventMessageFile; a source found with any other value is
; considered somebody else's and is never claimed for deletion.
Global Const $WINEVENT_DEFAULT_MESSAGE_FILE = "%SystemRoot%\System32\eventlog.dll"

; Names that belong to Windows or to a component. Entries ending in "-" are prefixes.
Global Const $WINEVENT_RESERVED_SOURCES = "|EventLog|Application Error|Application Popup|Security Accounts Manager|Service Control Manager|SideBySide|Winlogon|Microsoft-Windows-|Microsoft Office|"

; Windows Event Log types. The values are the winbase.h EVENTLOG_* flags, so the
; $EVENTLOG_* constants of the standard <EventLog.au3> can be passed as-is. This UDF
; keeps its own names because <EventLog.au3> declares those six as Global Const and
; two Global Const with the same name make a script die at load time.
Global Const $WINEVENT_TYPE_SUCCESS          = 0
Global Const $WINEVENT_TYPE_ERROR            = 1
Global Const $WINEVENT_TYPE_WARNING          = 2
Global Const $WINEVENT_TYPE_INFORMATION      = 4
Global Const $WINEVENT_TYPE_AUDIT_SUCCESS    = 8
Global Const $WINEVENT_TYPE_AUDIT_FAILURE    = 16

; Registry base path for event sources
Global Const $WINEVENT_REG_BASE = "SYSTEM\CurrentControlSet\Services\EventLog"

; Registry access rights
Global Const $WINEVENT_KEY_READ       = 0x20019
Global Const $WINEVENT_KEY_WRITE      = 0x20006
Global Const $WINEVENT_KEY_ALL_ACCESS = 0xF003F

; Column count of the handler table. Every resize goes through this constant: a stale
; literal in one of them silently rebuilds a narrower table (measured on 1.3.2, where the
; "keep" pass of _WinEvent_UnregisterHandler still said [5] and returned cols=5).
Global Const $WINEVENT_H_COLS      = 8 ; event, callback, priority, enabled, parameters, id, once, mask
Global Const $WINEVENT_H_ID        = 5 ; handler ID column
Global Const $WINEVENT_H_ONCE      = 6 ; one-shot flag column
Global Const $WINEVENT_H_MASK      = 7 ; compiled wildcard column
; Same rule for the dead-letter store: one constant per table width.
Global Const $WINEVENT_D_COLS      = 5 ; stamp, event, data, reason, attempts
; ===============================================================================================================================

; #GLOBAL VARIABLES# ============================================================================================================
Global $__g_WinEvent_bInitialized   = False
Global $__g_WinEvent_hAdvapi32      = 0
Global $__g_WinEvent_sSource        = "AutoItScript"
Global $__g_WinEvent_sLogFile       = "Application"
Global $__g_WinEvent_iLastError     = $WINEVENT_OK
Global $__g_WinEvent_sLastErrorMsg  = ""
Global $__g_WinEvent_iLastApi       = 0
Global $__g_WinEvent_aHandlers[0][$WINEVENT_H_COLS] ; event, callback, priority, enabled, parameters, id, once, mask
Global $__g_WinEvent_iHandlerSeq    = 0    ; monotonic source of handler IDs (never reused)
Global $__g_WinEvent_aQueue[0][3]     ; ring buffer of [event, data, timestamp]
Global $__g_WinEvent_iQueueMax      = 1000 ; pending events allowed at once
Global $__g_WinEvent_iQueueHead     = 0    ; ring index of the oldest queued event
Global $__g_WinEvent_iQueueCount    = 0    ; events currently queued
Global $__g_WinEvent_iQueueCap      = 0    ; rows allocated in $__g_WinEvent_aQueue
Global $__g_WinEvent_bAdlibActive   = False
Global $__g_WinEvent_iDispatchDepth = 0    ; above 0 while handlers are running
Global $__g_WinEvent_aJournal[0][5]   ; ring of [stamp, kind, event, data, detail]
Global $__g_WinEvent_iJournalMax      = 5000 ; journal rows kept, oldest dropped when full
Global $__g_WinEvent_iJournalHead     = 0
Global $__g_WinEvent_iJournalCount    = 0
Global $__g_WinEvent_iJournalCap      = 0
Global $__g_WinEvent_iJournalDropped  = 0    ; rows evicted because the journal was full
Global $__g_WinEvent_sOwnedSources    = ""   ; "|log|source|" keys this process registered
Global $__g_WinEvent_sStampPrefix     = ""   ; cached "YYYY-MM-DD HH:MM:SS"
Global $__g_WinEvent_iStampSec        = -1   ; @SEC the prefix above was built for
Global $__g_WinEvent_iLastDisposition = 0    ; RegCreateKeyExW: 1 = created, 2 = already existed
Global $__g_WinEvent_aDead[0][$WINEVENT_D_COLS] ; bounded store of events no handler took
Global $__g_WinEvent_iDeadMax         = 200  ; dead letters kept, oldest dropped when full
Global $__g_WinEvent_iDeadDropped     = 0    ; dead letters evicted because the store was full
Global $__g_WinEvent_iRetryLimit      = 0    ; extra delivery attempts (0 = try once, today's behaviour)
Global $__g_WinEvent_iLastRefused     = 0    ; handlers that refused the last dispatched event
; ===============================================================================================================================


; ===============================================================================================================================
;                    PUBLIC FUNCTIONS
; ===============================================================================================================================

; #FUNCTION# ====================================================================================================================
; Name ..........: _WinEvent_Startup
; Description ...: Initializes the WinEventManager UDF. Must be called before any other function.
; Syntax ........: _WinEvent_Startup()
; Parameters ....: None.
; Return values .: Success - True
;                  Failure - False and sets @error
; Author ........: Numeric1
; ===============================================================================================================================
Func _WinEvent_Startup()
    If $__g_WinEvent_bInitialized Then Return SetError($WINEVENT_OK, 0, True)

    Local $hDll = DllOpen("advapi32.dll")
    If $hDll = -1 Then Return SetError(__WinEvent_SetError($WINEVENT_ERR_API_CALL, "Failed to load advapi32.dll"), 0, False)
    $__g_WinEvent_hAdvapi32 = $hDll

    If Not IsInt($__g_WinEvent_iQueueMax) Or $__g_WinEvent_iQueueMax < 1 Then $__g_WinEvent_iQueueMax = 1000
    __WinEvent_QueueResize($__g_WinEvent_iQueueMax)

    $__g_WinEvent_iLastError    = $WINEVENT_OK
    $__g_WinEvent_sLastErrorMsg = ""
    $__g_WinEvent_iLastApi      = 0
    $__g_WinEvent_bInitialized  = True

    Return SetError($WINEVENT_OK, 0, True)
EndFunc   ;==>_WinEvent_Startup

; #FUNCTION# ====================================================================================================================
; Name ..........: _WinEvent_Shutdown
; Description ...: Releases all resources, closes handles, clears queues and handlers.
; Syntax ........: _WinEvent_Shutdown()
; Parameters ....: None.
; Return values .: Success - True
; Author ........: Numeric1
; ===============================================================================================================================
Func _WinEvent_Shutdown()
    If Not $__g_WinEvent_bInitialized Then Return SetError($WINEVENT_OK, 0, True)

    ; Disable background processing
    _WinEvent_DisableAdlib()

    ; Close the DLL handle
    If $__g_WinEvent_hAdvapi32 <> 0 And $__g_WinEvent_hAdvapi32 <> -1 Then
        DllClose($__g_WinEvent_hAdvapi32)
        $__g_WinEvent_hAdvapi32 = 0
    EndIf

    ; Clear internal structures
    $__g_WinEvent_bInitialized   = False
    $__g_WinEvent_sSource        = "AutoItScript"
    $__g_WinEvent_sLogFile       = "Application"
    $__g_WinEvent_iLastError     = $WINEVENT_OK
    $__g_WinEvent_sLastErrorMsg  = ""
    $__g_WinEvent_iLastApi       = 0
    $__g_WinEvent_iDispatchDepth = 0
    $__g_WinEvent_sOwnedSources  = ""
    $__g_WinEvent_iStampSec      = -1
    $__g_WinEvent_sStampPrefix   = ""

    ReDim $__g_WinEvent_aHandlers[0][$WINEVENT_H_COLS]
    __WinEvent_QueueReset()
    __WinEvent_JournalReset()
    __WinEvent_DeadReset()
    $__g_WinEvent_iLastRefused = 0

    Return SetError($WINEVENT_OK, 0, True)
EndFunc   ;==>_WinEvent_Shutdown

; #FUNCTION# ====================================================================================================================
; Name ..........: _WinEvent_RegisterSource
; Description ...: Registers a custom event source in the Windows registry and makes it the
;                  default source used by _WinEvent_Write.
; Syntax ........: _WinEvent_RegisterSource($sSource[, $sLogFile = "Application"])
; Parameters ....: $sSource   - Name of the event source to register. Accepted characters are
;                                letters, digits, space, dot, underscore and hyphen, 1 to 255
;                                of them. Names Windows owns (EventLog, Application Error,
;                                anything "Microsoft-Windows-...") are refused.
;                  $sLogFile  - [optional] Event log name (default "Application"), same charset.
; Return values .: Success - True
;                  @extended - 0 = this process created the key, 1 = the key already existed
;                              with this UDF's message file and was re-written
;                  Failure - False and sets @error:
;                            2 = not initialized, 3 = invalid parameter,
;                            6 = the name exists and belongs to another application, its
;                                registry values were left untouched (@extended = 2),
;                            8 = administrator privileges missing,
;                            11 = name outside the accepted charset,
;                            12 = reserved source name,
;                            4 = registry call failed (@extended holds the LSTATUS)
; Author ........: Numeric1
; Notes .........: Writing to HKLM requires administrator privileges.
;                  The name is validated BEFORE the privilege check and before any registry
;                  call, so a rejected name never reaches the registry.
; Related .......: _WinEvent_UnregisterSource, _WinEvent_Write
; ===============================================================================================================================
Func _WinEvent_RegisterSource($sSource, $sLogFile = "Application")
    ; Helpers report failure through their RETURN VALUE, never through @error:
    ; "Return OtherFunc()" resets @error, so a guard on @error would be dead code.
    If Not $__g_WinEvent_bInitialized Then Return SetError(__WinEvent_SetError($WINEVENT_ERR_NOT_INIT, "WinEventManager not initialized"), 0, False)

    If Not IsString($sLogFile) Or $sLogFile = "" Then $sLogFile = "Application"

    Local $iNameErr = __WinEvent_CheckSourceName($sSource, $sLogFile)
    If $iNameErr <> 0 Then Return SetError($__g_WinEvent_iLastError, $__g_WinEvent_iLastApi, False)
    If __WinEvent_IsReservedSource($sSource) <> 0 Then Return SetError(__WinEvent_SetError($WINEVENT_ERR_RESERVED_SOURCE, "'" & $sSource & "' is a source Windows owns; registering over it is refused"), 0, False)
    If Not IsAdmin() Then Return SetError(__WinEvent_SetError($WINEVENT_ERR_ACCESS_DENIED, "Administrator privileges required to register event source"), 0, False)

    Local $sRegPath = $WINEVENT_REG_BASE & "\" & $sLogFile & "\" & $sSource

    ; Create registry key with READ|WRITE: QUERY_VALUE is needed to look at whatever is
    ; already there before writing over it.
    Local $hKey = __WinEvent_RegCreateKey(0x80000002, $sRegPath, BitOR($WINEVENT_KEY_READ, $WINEVENT_KEY_WRITE)) ; HKEY_LOCAL_MACHINE
    If $hKey = 0 Then Return SetError($__g_WinEvent_iLastError, $__g_WinEvent_iLastApi, False)

    ; Disposition of RegCreateKeyExW: 1 = we created it, 2 = it was already there.
    Local $iFound = 0
    If $__g_WinEvent_iLastDisposition <> 1 Then
        Local $sPrev = __WinEvent_RegQueryValueEx($hKey, "EventMessageFile")
        If StringLower($sPrev) = StringLower($WINEVENT_DEFAULT_MESSAGE_FILE) Then
            $iFound = 1 ; an earlier run of this UDF wrote it, so it is ours to re-write and remove
        Else
            ; Somebody else owns that name. Its values are left exactly as they were:
            ; overwriting another application's EventMessageFile would break its logging.
            __WinEvent_RegCloseKey($hKey)
            Return SetError(__WinEvent_SetError($WINEVENT_ERR_ALREADY_EXISTS, "'" & $sSource & "' already exists and belongs to another application; its registry values were not modified"), 2, False)
        EndIf
    EndIf

    ; Set EventMessageFile
    If __WinEvent_RegSetValueEx($hKey, "EventMessageFile", $WINEVENT_DEFAULT_MESSAGE_FILE, "REG_EXPAND_SZ") = 0 Then
        Local $iApi1 = $__g_WinEvent_iLastApi
        __WinEvent_RegCloseKey($hKey)
        Return SetError($__g_WinEvent_iLastError, $iApi1, False)
    EndIf

    ; Set TypesSupported (all types = 7)
    If __WinEvent_RegSetValueEx($hKey, "TypesSupported", 7, "REG_DWORD") = 0 Then
        Local $iApi2 = $__g_WinEvent_iLastApi
        __WinEvent_RegCloseKey($hKey)
        Return SetError($__g_WinEvent_iLastError, $iApi2, False)
    EndIf

    __WinEvent_RegCloseKey($hKey)

    ; Last registered source becomes the default for _WinEvent_Write (it was forgotten
    ; before, so Write kept signing "AutoItScript").
    $__g_WinEvent_sSource  = $sSource
    $__g_WinEvent_sLogFile = $sLogFile
    __WinEvent_OwnedAdd($sSource, $sLogFile)

    Return SetError($WINEVENT_OK, $iFound, True)
EndFunc   ;==>_WinEvent_RegisterSource

; #FUNCTION# ====================================================================================================================
; Name ..........: _WinEvent_UnregisterSource
; Description ...: Removes an event source from the registry. Refuses anything this process
;                  did not register, and anything Windows owns.
; Syntax ........: _WinEvent_UnregisterSource($sSource[, $sLogFile = "Application"])
; Parameters ....: $sSource  - Name previously given to _WinEvent_RegisterSource
;                  $sLogFile - [optional] Event log name (default "Application")
; Return values .: Success - True, @extended = number of registry keys deleted
;                  Failure - False and sets @error:
;                            2 = not initialized, 8 = administrator privileges missing,
;                            11 = name outside the accepted charset,
;                            12 = reserved source name,
;                            13 = this process never registered that source,
;                            4 = registry call failed (@extended holds the LSTATUS,
;                                2 = ERROR_FILE_NOT_FOUND)
;                  Deleting an arbitrary sub-key of the EventLog tree used to reach system
;                  sources such as "Application Error"; it is now refused by name.
; Author ........: Numeric1
; Notes .........: Ownership is per process. A source registered by an installer in a previous
;                  run is refused unless its EventMessageFile is the one this UDF writes.
; Related .......: _WinEvent_RegisterSource, _WinEvent_Write
; ===============================================================================================================================
Func _WinEvent_UnregisterSource($sSource, $sLogFile = "Application")
    If Not $__g_WinEvent_bInitialized Then Return SetError(__WinEvent_SetError($WINEVENT_ERR_NOT_INIT, "WinEventManager not initialized"), 0, False)

    If Not IsString($sLogFile) Or $sLogFile = "" Then $sLogFile = "Application"

    Local $iNameErr = __WinEvent_CheckSourceName($sSource, $sLogFile)
    If $iNameErr <> 0 Then Return SetError($__g_WinEvent_iLastError, $__g_WinEvent_iLastApi, False)
    If __WinEvent_IsReservedSource($sSource) <> 0 Then Return SetError(__WinEvent_SetError($WINEVENT_ERR_RESERVED_SOURCE, "'" & $sSource & "' is a source Windows owns; deleting it is refused"), 0, False)
    If Not __WinEvent_OwnedTest($sSource, $sLogFile) Then
        Return SetError(__WinEvent_SetError($WINEVENT_ERR_NOT_OURS, "'" & $sSource & "' was not registered by this process; nothing was deleted"), 0, False)
    EndIf
    If Not IsAdmin() Then Return SetError(__WinEvent_SetError($WINEVENT_ERR_ACCESS_DENIED, "Administrator privileges required"), 0, False)

    Local $sRegPath = $WINEVENT_REG_BASE & "\" & $sLogFile & "\" & $sSource
    ; @extended carries the LSTATUS: 2 = ERROR_FILE_NOT_FOUND (nothing was registered).
    Local $iDeleted = __WinEvent_RegDeleteTree(0x80000002, $sRegPath) ; HKEY_LOCAL_MACHINE
    If $iDeleted = 0 Then Return SetError($__g_WinEvent_iLastError, $__g_WinEvent_iLastApi, False)

    __WinEvent_OwnedRemove($sSource, $sLogFile)
    If $__g_WinEvent_sSource = $sSource Then $__g_WinEvent_sSource = "AutoItScript"

    Return SetError($WINEVENT_OK, 1, True)
EndFunc   ;==>_WinEvent_UnregisterSource

; #FUNCTION# ====================================================================================================================
; Name ..........: _WinEvent_Write
; Description ...: Writes an entry to the Windows Event Log.
; Syntax ........: _WinEvent_Write($sMessage[, $sSource = ""[, $iType = $WINEVENT_TYPE_INFORMATION[, $iCategory = 0[, $iEventID = 1000[, $sLogFile = ""]]]]])
; Parameters ....: $sMessage   - Message text
;                  $sSource    - [optional] Source name (default: startup source)
;                  $iType      - [optional] Event type: $WINEVENT_TYPE_* (0, 1, 2, 4, 8, 16).
;                                The $EVENTLOG_* constants of <EventLog.au3> hold the same
;                                values and work here too.
;                  $iCategory  - [optional] Event category
;                  $iEventID   - [optional] Event identifier
;                  $sLogFile   - [optional] Log name (default: "Application")
; Return values .: Success - True
;                  Failure - False and sets @error: 2 not started, 3 empty or non-string message,
;                  5 RegisterEventSourceW or ReportEventW refused
; Author ........: Numeric1
; ===============================================================================================================================
Func _WinEvent_Write($sMessage, $sSource = "", $iType = $WINEVENT_TYPE_INFORMATION, $iCategory = 0, $iEventID = 1000, $sLogFile = "")
    If Not $__g_WinEvent_bInitialized Then Return SetError(__WinEvent_SetError($WINEVENT_ERR_NOT_INIT, "WinEventManager not initialized"), 0, False)
    If Not IsString($sMessage) Or $sMessage = "" Then Return SetError(__WinEvent_SetError($WINEVENT_ERR_INVALID_PARAM, "Message must be a non-empty string"), 0, False)

    If $sSource = "" Then $sSource = $__g_WinEvent_sSource
    If $sLogFile = "" Then $sLogFile = $__g_WinEvent_sLogFile

    ; RegisterEventSourceW resolves the target log from the SOURCE NAME: $sLogFile cannot
    ; redirect a write, it only documents where the source was registered.
    Local $aSource = DllCall($__g_WinEvent_hAdvapi32, "handle", "RegisterEventSourceW", _
            "wstr", "", _
            "wstr", $sSource)
    If @error Or Not IsArray($aSource) Or $aSource[0] = 0 Then
        Local $iApi0 = __WinEvent_LastError()
        Return SetError(__WinEvent_SetError($WINEVENT_ERR_API_CALL, "RegisterEventSourceW failed for source '" & $sSource & "'", $iApi0), $iApi0, False)
    EndIf
    Local $hSource = $aSource[0]

    ; Build the string array for ReportEventW
    Local $tString = DllStructCreate("wchar[" & StringLen($sMessage) + 1 & "]")
    DllStructSetData($tString, 1, $sMessage)

    Local $tStrings = DllStructCreate("ptr[1]")
    DllStructSetData($tStrings, 1, DllStructGetPtr($tString), 1)

    ; ReportEventW(hEventLog, wType, wCategory, dwEventID, lpUserSid, wNumStrings, dwDataSize, *lpStrings, lpRawData)
    Local $aRet = DllCall($__g_WinEvent_hAdvapi32, "bool", "ReportEventW", _
            "handle", $hSource, _
            "ushort", $iType, _
            "ushort", $iCategory, _
            "dword", $iEventID, _
            "ptr", 0, _
            "ushort", 1, _
            "dword", 0, _
            "struct*", $tStrings, _
            "ptr", 0)

    ; The outcome is captured BEFORE DeregisterEventSource: that call overwrites both
    ; @error and GetLastError, which belong to ReportEventW here.
    Local $fCalled = (Not @error)
    Local $fOk = False
    If $fCalled Then $fOk = ($aRet[0] <> 0)
    Local $iApi = 0
    If Not $fOk Then $iApi = __WinEvent_LastError()

    ; Always deregister the source
    DllCall($__g_WinEvent_hAdvapi32, "bool", "DeregisterEventSource", "handle", $hSource)

    If $fOk Then Return SetError($WINEVENT_OK, 0, True)
    If Not $fCalled Then Return SetError(__WinEvent_SetError($WINEVENT_ERR_API_CALL, "ReportEventW could not be called"), 0, False)
    Return SetError(__WinEvent_SetError($WINEVENT_ERR_API_CALL, "ReportEventW failed for source '" & $sSource & "'", $iApi), $iApi, False)
EndFunc   ;==>_WinEvent_Write

; #FUNCTION# ====================================================================================================================
; Name ..........: _WinEvent_RegisterHandler
; Description ...: Registers a callback for an event name, and returns the stable ID that
;                  identifies this registration for the whole life of the handler.
; Syntax ........: _WinEvent_RegisterHandler($sEventName, $vCallback[, $iPriority = 0[, $iParams = 2[, $bOnce = False]]])
; Parameters ....: $sEventName - Name of the custom event. Two characters are wildcards when
;                                  the name contains them: "*" stands for any run of
;                                  characters and "?" for a single character, so "Audit.*"
;                                  fires for Audit.Logon, Audit.Logoff, ... The comparison is
;                                  case-insensitive, like every AutoIt "=" on strings.
;                                A masked registration is removed by its ID or by giving the
;                                same mask text to _WinEvent_UnregisterHandler.
;                  $vCallback  - Function name (string) or function reference
;                  $iPriority  - [optional] Higher priority is invoked first; equal
;                                priority keeps registration order
;                  $iParams    - [optional] Parameters the handler declares:
;                                  0 = Func H()
;                                  1 = Func H($sEventName)
;                                  2 = Func H($sEventName, $vData) (default)
;                  $bOnce      - [optional] True = the handler is removed by the UDF right
;                                after it has run once (default False). "Run once" counts the
;                                attempts it could not be called too, so a broken one-shot
;                                cannot stay armed forever.
; Return values .: Success - Handler ID, a number that never changes while the handler is
;                            registered and is never handed to another handler
;                            (use it with _WinEvent_UnregisterHandlerById).
;                  Failure - False and sets @error:
;                            2 = not initialized, 3 = invalid parameter,
;                            6 = already registered
;                  An unknown function name is not rejected here (it cannot be probed
;                  without calling it): _WinEvent_Trigger then reports @error 10.
; Author ........: Numeric1
; Notes .........: One registration = one ID, even when the same callback is registered for
;                  two events. Registering the same callback twice for the same name is
;                  refused with @error 6.
; Related .......: _WinEvent_UnregisterHandler, _WinEvent_UnregisterHandlerById, _WinEvent_Trigger
; ===============================================================================================================================
Func _WinEvent_RegisterHandler($sEventName, $vCallback, $iPriority = 0, $iParams = 2, $bOnce = False)
    If Not $__g_WinEvent_bInitialized Then Return SetError(__WinEvent_SetError($WINEVENT_ERR_NOT_INIT, "WinEventManager not initialized"), 0, False)
    If Not IsString($sEventName) Or $sEventName = "" Then Return SetError(__WinEvent_SetError($WINEVENT_ERR_INVALID_PARAM, "Invalid event name"), 0, False)

    ; Accept both function references and function name strings
    Local $sCallbackName = ""
    If IsFunc($vCallback) Then
        $sCallbackName = FuncName($vCallback)
    ElseIf IsString($vCallback) And $vCallback <> "" Then
        $sCallbackName = $vCallback
    Else
        Return SetError(__WinEvent_SetError($WINEVENT_ERR_INVALID_PARAM, "Callback must be a function reference or function name string"), 0, False)
    EndIf

    ; A callback given by NAME cannot be validated here: IsFunc() only accepts a function
    ; reference (measured on 3.3.16.1 - IsFunc("MsgBox") is 0). An unknown name therefore
    ; fails at dispatch time, where it is now reported as @error 10 instead of being
    ; counted as a call that happened.
    Local $iParams2 = Int($iParams)
    If $iParams2 < 0 Or $iParams2 > 2 Or ($iParams <> $iParams2) Then Return SetError(__WinEvent_SetError($WINEVENT_ERR_INVALID_PARAM, "A handler must declare 0, 1 or 2 parameters"), 0, False)

    ; Check for duplicate registration
    For $i = 0 To UBound($__g_WinEvent_aHandlers) - 1
        If $__g_WinEvent_aHandlers[$i][0] = $sEventName And $__g_WinEvent_aHandlers[$i][1] = $sCallbackName Then
            Return SetError(__WinEvent_SetError($WINEVENT_ERR_ALREADY_EXISTS, "Handler '" & $sCallbackName & "' already registered for '" & $sEventName & "'"), 0, False)
        EndIf
    Next

    ; Add handler
    Local $iNew = UBound($__g_WinEvent_aHandlers)
    ReDim $__g_WinEvent_aHandlers[$iNew + 1][$WINEVENT_H_COLS]
    $__g_WinEvent_aHandlers[$iNew][0] = $sEventName
    $__g_WinEvent_aHandlers[$iNew][1] = $sCallbackName
    $__g_WinEvent_aHandlers[$iNew][2] = Int($iPriority)
    $__g_WinEvent_aHandlers[$iNew][3] = 1 ; enabled
    $__g_WinEvent_aHandlers[$iNew][4] = $iParams2
    $__g_WinEvent_iHandlerSeq += 1
    $__g_WinEvent_aHandlers[$iNew][$WINEVENT_H_ID] = $__g_WinEvent_iHandlerSeq
    ; The flag follows the rule AutoIt's If uses: a non-empty string is True, so "0" and
    ; "False" arm the one-shot as well (measured on 3.3.16.1).
    $__g_WinEvent_aHandlers[$iNew][$WINEVENT_H_ONCE] = 0
    If $bOnce Then $__g_WinEvent_aHandlers[$iNew][$WINEVENT_H_ONCE] = 1
    ; The mask is compiled once here instead of per dispatched event: an event name is
    ; matched against every registration on every dispatch.
    $__g_WinEvent_aHandlers[$iNew][$WINEVENT_H_MASK] = __WinEvent_MaskToRe($sEventName)

    Return SetError($WINEVENT_OK, 0, $__g_WinEvent_iHandlerSeq)
EndFunc   ;==>_WinEvent_RegisterHandler

; #FUNCTION# ====================================================================================================================
; Name ..........: _WinEvent_UnregisterHandler
; Description ...: Removes one or all handlers registered for an event name.
; Syntax ........: _WinEvent_UnregisterHandler($sEventName[, $vCallback = ""])
; Parameters ....: $sEventName - Name the handler was registered under. A wildcard
;                                registration ("Audit.*") is matched by that exact text: the
;                                stars are not expanded here, use _WinEvent_UnregisterHandlerById
;                                to drop masked handlers one by one.
;                  $vCallback  - [optional] Specific callback to remove. Empty = remove ALL.
; Return values .: Success - Number of handlers removed (@extended holds the same count)
;                  Failure - False and sets @error (2 = not initialized, 3 = invalid name,
;                            7 = nothing matched)
; Author ........: Numeric1
; Related .......: _WinEvent_RegisterHandler, _WinEvent_UnregisterHandlerById
; ===============================================================================================================================
Func _WinEvent_UnregisterHandler($sEventName, $vCallback = "")
    If Not $__g_WinEvent_bInitialized Then Return SetError(__WinEvent_SetError($WINEVENT_ERR_NOT_INIT, "WinEventManager not initialized"), 0, False)
    If Not IsString($sEventName) Or $sEventName = "" Then Return SetError(__WinEvent_SetError($WINEVENT_ERR_INVALID_PARAM, "Invalid event name"), 0, False)

    ; Convert callback to name string if needed
    Local $sCallbackName = ""
    If IsFunc($vCallback) Then
        $sCallbackName = FuncName($vCallback)
    ElseIf IsString($vCallback) Then
        $sCallbackName = $vCallback
    EndIf

    ; One pass into a fresh table: removing element by element would re-enter the table
    ; the dispatcher may still be walking, and would cost O(n^2) for "remove all".
    Local $iTotal = UBound($__g_WinEvent_aHandlers)
    If $iTotal = 0 Then Return SetError(__WinEvent_SetError($WINEVENT_ERR_NOT_FOUND, "No handler found for event '" & $sEventName & "'"), 0, False)

    Local $aKeep[$iTotal][$WINEVENT_H_COLS]
    Local $iKept = 0
    Local $iRemoved = 0
    For $i = 0 To $iTotal - 1
        Local $bMatch = ($__g_WinEvent_aHandlers[$i][0] = $sEventName)
        If $bMatch And $sCallbackName <> "" Then $bMatch = ($__g_WinEvent_aHandlers[$i][1] = $sCallbackName)
        If $bMatch Then
            $iRemoved += 1
        Else
            For $c = 0 To $WINEVENT_H_COLS - 1
                $aKeep[$iKept][$c] = $__g_WinEvent_aHandlers[$i][$c]
            Next
            $iKept += 1
        EndIf
    Next

    If $iRemoved = 0 Then Return SetError(__WinEvent_SetError($WINEVENT_ERR_NOT_FOUND, "No handler found for event '" & $sEventName & "'"), 0, False)

    If $iKept = 0 Then
        ReDim $__g_WinEvent_aHandlers[0][$WINEVENT_H_COLS]
    Else
        ReDim $aKeep[$iKept][$WINEVENT_H_COLS]
        $__g_WinEvent_aHandlers = $aKeep
    EndIf

    Return SetError($WINEVENT_OK, $iRemoved, $iRemoved)
EndFunc   ;==>_WinEvent_UnregisterHandler

; #FUNCTION# ====================================================================================================================
; Name ..........: _WinEvent_UnregisterHandlerById
; Description ...: Removes the handler carrying a handler ID returned by _WinEvent_RegisterHandler.
; Syntax ........: _WinEvent_UnregisterHandlerById($iHandlerId)
; Parameters ....: $iHandlerId - the ID returned at registration time.
; Return values .: Success - 1 (the handler is gone)
;                  Failure - False and sets @error (2 = not initialized, 3 = invalid ID,
;                            7 = no registered handler carries that ID, which is also the case
;                            for an ID already removed, including by its own $bOnce flag)
; Author ........: Numeric1
; Notes .........: The only way to remove a masked registration precisely, and the way to drop a
;                  handler when several callbacks share one event name without naming the callback.
; Related .......: _WinEvent_RegisterHandler, _WinEvent_UnregisterHandler
; ===============================================================================================================================
Func _WinEvent_UnregisterHandlerById($iHandlerId)
    If Not $__g_WinEvent_bInitialized Then Return SetError(__WinEvent_SetError($WINEVENT_ERR_NOT_INIT, "WinEventManager not initialized"), 0, False)

    Local $iId = Int($iHandlerId)
    If Not StringIsInt($iHandlerId) Or $iId < 1 Then Return SetError(__WinEvent_SetError($WINEVENT_ERR_INVALID_PARAM, "Handler ID must be a positive integer"), 0, False)

    If __WinEvent_RemoveById($iId) = 0 Then Return SetError(__WinEvent_SetError($WINEVENT_ERR_NOT_FOUND, "No handler with ID " & $iId), 0, False)
    Return SetError($WINEVENT_OK, 1, 1)
EndFunc   ;==>_WinEvent_UnregisterHandlerById

; #FUNCTION# ====================================================================================================================
; Name ..........: _WinEvent_Trigger
; Description ...: Synchronously invokes every enabled registration matching an event name,
;                  including the wildcard ones made with _WinEvent_RegisterHandler.
; Syntax ........: _WinEvent_Trigger($sEventName[, $vData = ""])
; Parameters ....: $sEventName - name of the event to raise.
;                  $vData      - value handed to every matching handler as its second parameter (default "").
; Return values .: Success - Number of handlers that ran (0 when none is registered,
;                  which is not an error)
;                  Failure - False and sets @error (2 = not initialized, 3 = invalid name)
;                  @error 10 (callback) = at least one handler could not be called,
;                  @extended then holds the number of failures
; Author ........: Numeric1
; Notes .........: A handler that returns the literal False refuses the event; it is then not
;                  counted among the handlers that ran, the event is retried as many times as
;                  _WinEvent_RetryLimit allows, and if nothing takes it, it ends up in the
;                  dead-letter store (_WinEvent_DeadLettered). Returning nothing, 0 or "" is
;                  not a refusal - only the Boolean False is.
; Related .......: _WinEvent_RegisterHandler, _WinEvent_Post, _WinEvent_RetryLimit, _WinEvent_DeadLettered
; ===============================================================================================================================
Func _WinEvent_Trigger($sEventName, $vData = "")
    If Not $__g_WinEvent_bInitialized Then Return SetError(__WinEvent_SetError($WINEVENT_ERR_NOT_INIT, "WinEventManager not initialized"), 0, False)
    If Not IsString($sEventName) Or $sEventName = "" Then Return SetError(__WinEvent_SetError($WINEVENT_ERR_INVALID_PARAM, "Invalid event name"), 0, False)

    Local $iInvoked = __WinEvent_Deliver($sEventName, $vData)
    Local $e = @error
    Local $x = @extended
    Return SetError($e, $x, $iInvoked)
EndFunc   ;==>_WinEvent_Trigger

; #FUNCTION# ====================================================================================================================
; Name ..........: _WinEvent_Post
; Description ...: Asynchronously posts an event to the internal queue.
; Syntax ........: _WinEvent_Post($sEventName[, $vData = ""])
; Parameters ....: $sEventName - name of the event to queue.
;                  $vData      - value delivered to the handlers later, when the queue is pumped (default "").
;                                Masked registrations match at pumping time, exactly like with _WinEvent_Trigger.
; Return values .: Success - True
;                  Failure - False and sets @error (2 = not initialized,
;                            3 = invalid event name, 9 = queue full)
; Author ........: Numeric1
; ===============================================================================================================================
Func _WinEvent_Post($sEventName, $vData = "")
    If Not $__g_WinEvent_bInitialized Then Return SetError(__WinEvent_SetError($WINEVENT_ERR_NOT_INIT, "WinEventManager not initialized"), 0, False)
    If Not IsString($sEventName) Or $sEventName = "" Then Return SetError(__WinEvent_SetError($WINEVENT_ERR_INVALID_PARAM, "Invalid event name"), 0, False)

    Local $bPushed = __WinEvent_QueuePush($sEventName, $vData)
    Local $e = @error
    Return SetError($e, 0, $bPushed)
EndFunc   ;==>_WinEvent_Post

; #FUNCTION# ====================================================================================================================
; Name ..........: _WinEvent_Queued
; Description ...: Returns how many posted events are waiting to be processed.
; Syntax ........: _WinEvent_Queued()
; Parameters ....: None.
; Return values .: Number of pending events (0 when the queue is empty)
; Author ........: Numeric1
; ===============================================================================================================================
Func _WinEvent_Queued()
    Return $__g_WinEvent_iQueueCount
EndFunc   ;==>_WinEvent_Queued

; #FUNCTION# ====================================================================================================================
; Name ..........: _WinEvent_Journal
; Description ...: Returns how many events the journal still holds. The journal records every
;                  event that reached a handler (POSTED by _WinEvent_Post, DISPATCHED by
;                  _WinEvent_Trigger or _WinEvent_Process), so it keeps the history the queue
;                  itself loses when an event is popped.
; Syntax ........: _WinEvent_Journal()
; Parameters ....: None.
; Return values .: Success - Number of journaled rows
;                  @extended - Rows dropped because the journal was full ($__g_WinEvent_iJournalMax)
; Author ........: Numeric1
; Related .......: _WinEvent_SaveToFile, _WinEvent_ClearJournal, _WinEvent_Queued
; ===============================================================================================================================
Func _WinEvent_Journal()
    Return SetError($WINEVENT_OK, $__g_WinEvent_iJournalDropped, $__g_WinEvent_iJournalCount)
EndFunc   ;==>_WinEvent_Journal

; #FUNCTION# ====================================================================================================================
; Name ..........: _WinEvent_ClearJournal
; Description ...: Forgets every journaled row without touching the pending queue.
; Syntax ........: _WinEvent_ClearJournal()
; Parameters ....: None.
; Return values .: Success - Number of rows cleared
;                  Failure - False and sets @error (2 = not initialized)
; Author ........: Numeric1
; Related .......: _WinEvent_Journal, _WinEvent_SaveToFile
; ===============================================================================================================================
Func _WinEvent_ClearJournal()
    If Not $__g_WinEvent_bInitialized Then Return SetError(__WinEvent_SetError($WINEVENT_ERR_NOT_INIT, "WinEventManager not initialized"), 0, False)

    Local $iCleared = $__g_WinEvent_iJournalCount
    __WinEvent_JournalReset()
    Return SetError($WINEVENT_OK, $__g_WinEvent_iJournalDropped, $iCleared)
EndFunc   ;==>_WinEvent_ClearJournal

; #FUNCTION# ====================================================================================================================
; Name ..........: _WinEvent_Process
; Description ...: Processes (dispatches) pending events from the internal queue.
; Syntax ........: _WinEvent_Process([$iMaxEvents = 0])
; Parameters ....: $iMaxEvents - [optional] Maximum events to process (0 = all)
; Return values .: Number of events processed (0 = nothing was pending)
;                  Failure - 0 and sets @error (2 = not initialized)
;                  @error 10 (callback) = at least one handler could not be called,
;                  @extended then holds how many events were affected
; Author ........: Numeric1
; Notes .........: $iMaxEvents counts deliveries, not distinct events: with
;                  _WinEvent_RetryLimit above 0, an event that keeps failing is retried inside
;                  this call and each attempt uses one of the budget. An event nobody takes
;                  after those attempts leaves the queue for the dead-letter store, so the
;                  queue always drains and no event disappears without a trace.
; ===============================================================================================================================
Func _WinEvent_Process($iMaxEvents = 0)
    If Not $__g_WinEvent_bInitialized Then Return SetError(__WinEvent_SetError($WINEVENT_ERR_NOT_INIT, "WinEventManager not initialized"), 0, False)

    ; Int() rather than IsInt(): a computed limit such as 2.5 used to mean
    ; "process the whole queue" instead of "process two".
    Local $iMax = Int($iMaxEvents)
    If $iMax < 0 Then $iMax = 0

    Local $iProcessed = 0
    Local $iFailed = 0
    While $__g_WinEvent_iQueueCount > 0
        If $iMax > 0 And $iProcessed >= $iMax Then ExitLoop

        Local $aEvent = __WinEvent_QueuePop()
        If @error Then ExitLoop

        __WinEvent_Deliver($aEvent[0], $aEvent[1])
        If @error Then $iFailed += 1
        $iProcessed += 1
    WEnd

    If $iFailed > 0 Then Return SetError(__WinEvent_SetError($WINEVENT_ERR_CALLBACK, $iFailed & " of " & $iProcessed & " dispatched events had a failing handler"), $iFailed, $iProcessed)
    Return SetError($WINEVENT_OK, $iProcessed, $iProcessed)
EndFunc   ;==>_WinEvent_Process

; #FUNCTION# ====================================================================================================================
; Name ..........: _WinEvent_RetryLimit
; Description ...: Reads or sets how many EXTRA delivery attempts an event gets before it is
;                  parked in the dead-letter store.
; Syntax ........: _WinEvent_RetryLimit([$iNew = -1])
; Parameters ....: $iNew - [optional] New limit (0 = deliver once, which is the default and the
;                           behaviour of every earlier version). Left out or negative = read only.
; Return values .: Success - The limit in force after the call
;                  Failure - False and sets @error (2 = not initialized, 3 = invalid value)
; Author ........: Numeric1
; Notes .........: A retry re-runs the handlers immediately, which is what a handler failing on a
;                  transient condition (a locked file, a busy device) needs. It does not wait for
;                  the next pump; use _WinEvent_Redeadmit for that. Each attempt journals its own
;                  DISPATCHED row, so the export shows how many times an event was tried.
; Related .......: _WinEvent_DeadLettered, _WinEvent_Redeadmit, _WinEvent_Trigger, _WinEvent_Process
; ===============================================================================================================================
Func _WinEvent_RetryLimit($iNew = -1)
    If Not $__g_WinEvent_bInitialized Then Return SetError(__WinEvent_SetError($WINEVENT_ERR_NOT_INIT, "WinEventManager not initialized"), 0, False)

    If $iNew <> -1 Then
        If Not StringIsInt($iNew) Then Return SetError(__WinEvent_SetError($WINEVENT_ERR_INVALID_PARAM, "Retry limit must be a whole number"), 0, False)
        Local $iLimit = Int($iNew)
        If $iLimit < 0 Then Return SetError(__WinEvent_SetError($WINEVENT_ERR_INVALID_PARAM, "Retry limit must be 0 or more"), 0, False)
        $__g_WinEvent_iRetryLimit = $iLimit
    EndIf

    Return SetError($WINEVENT_OK, 0, $__g_WinEvent_iRetryLimit)
EndFunc   ;==>_WinEvent_RetryLimit

; #FUNCTION# ====================================================================================================================
; Name ..........: _WinEvent_DeadMax
; Description ...: Reads or sets how many dead letters the store keeps before dropping the oldest.
; Syntax ........: _WinEvent_DeadMax([$iNew = -1])
; Parameters ....: $iNew - [optional] New capacity (1 or more). Left out = read only.
; Return values .: Success - The capacity in force after the call
;                  Failure - False and sets @error (2 = not initialized, 3 = invalid value)
; Author ........: Numeric1
; Notes .........: Shrinking the capacity does not delete the rows already stored; the next
;                  overflow evicts them, and _WinEvent_DeadLettered reports how many were dropped.
; Related .......: _WinEvent_DeadLettered, _WinEvent_ClearDeadLetters
; ===============================================================================================================================
Func _WinEvent_DeadMax($iNew = -1)
    If Not $__g_WinEvent_bInitialized Then Return SetError(__WinEvent_SetError($WINEVENT_ERR_NOT_INIT, "WinEventManager not initialized"), 0, False)

    If $iNew <> -1 Then
        If Not StringIsInt($iNew) Then Return SetError(__WinEvent_SetError($WINEVENT_ERR_INVALID_PARAM, "Dead-letter capacity must be a whole number"), 0, False)
        Local $iMax = Int($iNew)
        If $iMax < 1 Then Return SetError(__WinEvent_SetError($WINEVENT_ERR_INVALID_PARAM, "Dead-letter capacity must be 1 or more"), 0, False)
        $__g_WinEvent_iDeadMax = $iMax
    EndIf

    Return SetError($WINEVENT_OK, 0, $__g_WinEvent_iDeadMax)
EndFunc   ;==>_WinEvent_DeadMax

; #FUNCTION# ====================================================================================================================
; Name ..........: _WinEvent_DeadLettered
; Description ...: Returns how many events are waiting in the dead-letter store.
; Syntax ........: _WinEvent_DeadLettered()
; Parameters ....: None.
; Return values .: Success - Number of stored events (0 = nothing was lost)
;                  @extended - number of dead letters evicted because the store was full
;                  Failure - False and sets @error (2 = not initialized)
; Author ........: Numeric1
; Related .......: _WinEvent_DeadLetter, _WinEvent_Redeadmit, _WinEvent_ClearDeadLetters
; ===============================================================================================================================
Func _WinEvent_DeadLettered()
    If Not $__g_WinEvent_bInitialized Then Return SetError(__WinEvent_SetError($WINEVENT_ERR_NOT_INIT, "WinEventManager not initialized"), 0, False)
    Return SetError($WINEVENT_OK, $__g_WinEvent_iDeadDropped, UBound($__g_WinEvent_aDead))
EndFunc   ;==>_WinEvent_DeadLettered

; #FUNCTION# ====================================================================================================================
; Name ..........: _WinEvent_DeadLetter
; Description ...: Reads one dead letter, oldest first.
; Syntax ........: _WinEvent_DeadLetter($iIndex)
; Parameters ....: $iIndex - 1-based position, 1 = the oldest event nobody took.
; Return values .: Success - Array of 5 elements:
;                            [0] stamp of the failed delivery (YYYY-MM-DD HH:MM:SS.mmm)
;                            [1] event name
;                            [2] payload, exactly as it was posted (an array stays an array)
;                            [3] reason, such as "uncallable=1 refused=2"
;                            [4] delivery attempts spent on it
;                  Failure - 0 (not an array) and sets @error
;                            2 = not initialized, 3 = invalid index, 7 = nothing at that index
; Author ........: Numeric1
; Notes .........: An array payload has to be copied out of the row before it can be indexed:
;                  $p = $a[2] then $p[0]. AutoIt reads $a[2][0] as a two-dimensional subscript and
;                  stops with "subscript dimension range exceeded" (measured).
; Related .......: _WinEvent_DeadLettered, _WinEvent_Redeadmit, _WinEvent_SaveToFile
; ===============================================================================================================================
Func _WinEvent_DeadLetter($iIndex)
    If Not $__g_WinEvent_bInitialized Then Return SetError(__WinEvent_SetError($WINEVENT_ERR_NOT_INIT, "WinEventManager not initialized"), 0, 0)

    Local $i = Int($iIndex)
    If $i < 1 Then Return SetError(__WinEvent_SetError($WINEVENT_ERR_INVALID_PARAM, "Dead-letter index must be 1 or more"), 0, 0)
    If $i > UBound($__g_WinEvent_aDead) Then Return SetError(__WinEvent_SetError($WINEVENT_ERR_NOT_FOUND, "No dead letter at index " & $i), 0, 0)

    Local $aRow[$WINEVENT_D_COLS]
    For $c = 0 To $WINEVENT_D_COLS - 1
        $aRow[$c] = $__g_WinEvent_aDead[$i - 1][$c]
    Next

    Return SetError($WINEVENT_OK, 0, $aRow)
EndFunc   ;==>_WinEvent_DeadLetter

; #FUNCTION# ====================================================================================================================
; Name ..........: _WinEvent_Redeadmit
; Description ...: Puts dead letters back into the pending queue, oldest first, with their
;                  payload intact and their attempt counter reset.
; Syntax ........: _WinEvent_Redeadmit([$iMax = 0])
; Parameters ....: $iMax - [optional] Maximum events to re-admit (0 = all of them).
; Return values .: Success - Number of events put back in the queue (@error 0)
;                  Failure - 0 and sets @error (2 = not initialized, 3 = invalid limit,
;                            7 = the store is empty)
;                  9 = the pending queue filled up: the count returned says how many got in, the
;                  rest stay in the dead-letter store for the next call.
; Author ........: Numeric1
; Notes .........: This is the delayed-retry path: call it from the pump loop once the condition
;                  that made the handlers fail is gone (file unlocked, link back up). The
;                  re-admitted events go to the tail, behind anything already queued.
; Related .......: _WinEvent_DeadLettered, _WinEvent_DeadLetter, _WinEvent_Process, _WinEvent_Queued
; ===============================================================================================================================
Func _WinEvent_Redeadmit($iMax = 0)
    If Not $__g_WinEvent_bInitialized Then Return SetError(__WinEvent_SetError($WINEVENT_ERR_NOT_INIT, "WinEventManager not initialized"), 0, 0)

    Local $iWant = Int($iMax)
    If $iWant < 0 Then $iWant = 0

    Local $iCount = UBound($__g_WinEvent_aDead)
    If $iCount = 0 Then Return SetError(__WinEvent_SetError($WINEVENT_ERR_NOT_FOUND, "No dead letter to re-admit"), 0, 0)
    If $iWant = 0 Or $iWant > $iCount Then $iWant = $iCount

    Local $iMoved = 0
    While $iMoved < $iWant
        If Not __WinEvent_QueuePush($__g_WinEvent_aDead[$iMoved][1], $__g_WinEvent_aDead[$iMoved][2]) Then ExitLoop
        $iMoved += 1
    WEnd
    If $iMoved = 0 Then Return SetError(__WinEvent_SetError($WINEVENT_ERR_QUEUE_FULL, "Pending queue is full, nothing re-admitted"), 0, 0)

    ; Drop the rows that got in, keeping the store in oldest-first order.
    Local $iLeft = $iCount - $iMoved
    If $iLeft = 0 Then
        __WinEvent_DeadReset()
    Else
        Local $aNew[$iLeft][$WINEVENT_D_COLS]
        For $i = 0 To $iLeft - 1
            For $c = 0 To $WINEVENT_D_COLS - 1
                $aNew[$i][$c] = $__g_WinEvent_aDead[$i + $iMoved][$c]
            Next
        Next
        $__g_WinEvent_aDead = $aNew
    EndIf

    If $iMoved < $iWant Then Return SetError(__WinEvent_SetError($WINEVENT_ERR_QUEUE_FULL, "Pending queue is full after " & $iMoved & " of " & $iWant), $iMoved, $iMoved)
    Return SetError($WINEVENT_OK, $iMoved, $iMoved)
EndFunc   ;==>_WinEvent_Redeadmit

; #FUNCTION# ====================================================================================================================
; Name ..........: _WinEvent_ClearDeadLetters
; Description ...: Forgets every dead letter and the eviction counter that goes with them.
; Syntax ........: _WinEvent_ClearDeadLetters()
; Parameters ....: None.
; Return values .: Success - Number of events cleared
;                  Failure - False and sets @error (2 = not initialized)
; Author ........: Numeric1
; Related .......: _WinEvent_DeadLettered, _WinEvent_Redeadmit, _WinEvent_ClearJournal
; ===============================================================================================================================
Func _WinEvent_ClearDeadLetters()
    If Not $__g_WinEvent_bInitialized Then Return SetError(__WinEvent_SetError($WINEVENT_ERR_NOT_INIT, "WinEventManager not initialized"), 0, False)

    Local $iCount = UBound($__g_WinEvent_aDead)
    __WinEvent_DeadReset()
    Return SetError($WINEVENT_OK, $iCount, $iCount)
EndFunc   ;==>_WinEvent_ClearDeadLetters

; #FUNCTION# ====================================================================================================================
; Name ..........: _WinEvent_SaveToFile
; Description ...: Writes the pending queue, the journal and the dead letters to a pipe-separated text file.
; Syntax ........: _WinEvent_SaveToFile($sFilePath[, $sMode = "a"[, $iWhat = 3]])
; Parameters ....: $sFilePath - File to write
;                  $sMode     - [optional] "a" to append (default), "w" to overwrite
;                  $iWhat     - [optional] bit flags added together:
;                                1 = pending queue, 2 = journal, 4 = dead letters
;                                3 = queue + journal (default), 7 = everything
; Return values .: Success - True, @extended = number of data rows written
;                  Failure - False and sets @error (2 = not initialized,
;                            3 = invalid path, 5 = the file could not be opened)
; Author ........: Numeric1
; Notes .........: The queue only holds what has not been dispatched yet; the journal is what
;                  remembers the events that already ran, which the previous version lost.
; Related .......: _WinEvent_Journal, _WinEvent_ClearJournal, _WinEvent_Process
; Format ........: One line per record: timestamp|state|event|data|detail
;                  state is PENDING (still in the queue, with its age in milliseconds in
;                  detail) or POSTED / DISPATCHED (journal) or DEAD (a dead letter, whose
;                  detail holds attempts= plus the reason). Structural lines start with
;                  "[" or "===" and never with a timestamp.
;                  Backslash, pipe and line breaks inside a field are escaped as \\, \|, \r, \n;
;                  an array given as $vData is written as [a, b] instead of nothing.
; ===============================================================================================================================
Func _WinEvent_SaveToFile($sFilePath, $sMode = "a", $iWhat = 3)
    If Not $__g_WinEvent_bInitialized Then Return SetError(__WinEvent_SetError($WINEVENT_ERR_NOT_INIT, "WinEventManager not initialized"), 0, False)
    If Not IsString($sFilePath) Or $sFilePath = "" Then Return SetError(__WinEvent_SetError($WINEVENT_ERR_INVALID_PARAM, "Invalid file path"), 0, False)

    Local $iMode = 1 ; append
    If $sMode = "w" Then $iMode = 2 ; overwrite

    Local $hFile = FileOpen($sFilePath, $iMode)
    If $hFile = -1 Then Return SetError(__WinEvent_SetError($WINEVENT_ERR_API_CALL, "Cannot open file: " & $sFilePath), 0, False)

    Local $iWhat2 = Int($iWhat)
    If $iWhat2 < 1 Or $iWhat2 > 7 Then $iWhat2 = 3

    Local $iRows = 0
    FileWriteLine($hFile, "=== WinEventManager export " & __WinEvent_Stamp() & " ===")

    If BitAND($iWhat2, 1) Then
        FileWriteLine($hFile, "[pending] " & $__g_WinEvent_iQueueCount & " event(s) not dispatched yet, oldest first")
        For $i = 0 To $__g_WinEvent_iQueueCount - 1
            Local $iRow = Mod($__g_WinEvent_iQueueHead + $i, $__g_WinEvent_iQueueCap)
            FileWriteLine($hFile, $__g_WinEvent_aQueue[$iRow][2] & "|PENDING|" & _
                    __WinEvent_Cell($__g_WinEvent_aQueue[$iRow][0]) & "|" & _
                    __WinEvent_Cell($__g_WinEvent_aQueue[$iRow][1]) & "|queued=" & ($i + 1))
            $iRows += 1
        Next
    EndIf

    If BitAND($iWhat2, 2) Then
        Local $sDropped = ""
        If $__g_WinEvent_iJournalDropped > 0 Then $sDropped = " (" & $__g_WinEvent_iJournalDropped & " dropped)"
        FileWriteLine($hFile, "[journal] " & $__g_WinEvent_iJournalCount & " record(s), oldest first" & $sDropped)
        For $i = 0 To $__g_WinEvent_iJournalCount - 1
            Local $iRowJ = Mod($__g_WinEvent_iJournalHead + $i, $__g_WinEvent_iJournalCap)
            ; Column 3 was rendered when the row was written: rendering it again would
            ; escape its own escapes.
            FileWriteLine($hFile, $__g_WinEvent_aJournal[$iRowJ][0] & "|" & _
                    $__g_WinEvent_aJournal[$iRowJ][1] & "|" & _
                    __WinEvent_Cell($__g_WinEvent_aJournal[$iRowJ][2]) & "|" & _
                    $__g_WinEvent_aJournal[$iRowJ][3] & "|" & _
                    __WinEvent_Cell($__g_WinEvent_aJournal[$iRowJ][4]))
            $iRows += 1
        Next
    EndIf

    If BitAND($iWhat2, 4) Then
        Local $iDead = UBound($__g_WinEvent_aDead)
        Local $sDeadDropped = ""
        If $__g_WinEvent_iDeadDropped > 0 Then $sDeadDropped = " (" & $__g_WinEvent_iDeadDropped & " dropped)"
        FileWriteLine($hFile, "[deadletter] " & $iDead & " event(s) no handler took, oldest first" & $sDeadDropped)
        For $i = 0 To $iDead - 1
            FileWriteLine($hFile, $__g_WinEvent_aDead[$i][0] & "|DEAD|" & _
                    __WinEvent_Cell($__g_WinEvent_aDead[$i][1]) & "|" & _
                    __WinEvent_Cell($__g_WinEvent_aDead[$i][2]) & "|" & _
                    "attempts=" & $__g_WinEvent_aDead[$i][4] & " " & $__g_WinEvent_aDead[$i][3])
            $iRows += 1
        Next
    EndIf

    FileClose($hFile)
    Return SetError($WINEVENT_OK, $iRows, True)
EndFunc   ;==>_WinEvent_SaveToFile

; #FUNCTION# ====================================================================================================================
; Name ..........: _WinEvent_GetLastError
; Description ...: Returns the last error code set by the UDF.
; Syntax ........: _WinEvent_GetLastError()
; Parameters ....: None.
; Return values .: The code of the last failure recorded by this UDF, $WINEVENT_OK (0) when nothing failed since _WinEvent_Startup. A successful call does not clear it, only _WinEvent_Startup and _WinEvent_Shutdown do. This function never fails.
; Author ........: Numeric1
; ===============================================================================================================================
Func _WinEvent_GetLastError()
    Return $__g_WinEvent_iLastError
EndFunc   ;==>_WinEvent_GetLastError

; #FUNCTION# ====================================================================================================================
; Name ..........: _WinEvent_GetLastErrorMsg
; Description ...: Returns the last error message set by the UDF.
; Syntax ........: _WinEvent_GetLastErrorMsg()
; Parameters ....: None.
; Return values .: The message of the last failure recorded by this UDF, "" when nothing failed. It follows the same rule as _WinEvent_GetLastError: a success does not clear it. This function never fails.
; Author ........: Numeric1
; ===============================================================================================================================
Func _WinEvent_GetLastErrorMsg()
    Return $__g_WinEvent_sLastErrorMsg
EndFunc   ;==>_WinEvent_GetLastErrorMsg

; #FUNCTION# ====================================================================================================================
; Name ..........: _WinEvent_IsInitialized
; Description ...: Indicates whether the UDF has been started.
; Syntax ........: _WinEvent_IsInitialized()
; Parameters ....: None.
; Return values .: True after _WinEvent_Startup succeeded and before _WinEvent_Shutdown, False otherwise. This function never fails.
; Author ........: Numeric1
; ===============================================================================================================================
Func _WinEvent_IsInitialized()
    Return $__g_WinEvent_bInitialized
EndFunc   ;==>_WinEvent_IsInitialized

; #FUNCTION# ====================================================================================================================
; Name ..........: _WinEvent_EnableAdlib
; Description ...: Enables automatic background queue processing via AdlibRegister.
; Syntax ........: _WinEvent_EnableAdlib([$iInterval = 100])
; Parameters ....: $iInterval - milliseconds between background pumps (default 100). A value below 25 ms falls back to 100 ms because AutoIt clamps such intervals anyway.
; Return values .: Success - True
;                  Failure - False and sets @error
; Author ........: Numeric1
; ===============================================================================================================================
Func _WinEvent_EnableAdlib($iInterval = 100)
    If Not $__g_WinEvent_bInitialized Then Return SetError(__WinEvent_SetError($WINEVENT_ERR_NOT_INIT, "WinEventManager not initialized"), 0, False)
    If $__g_WinEvent_bAdlibActive Then Return SetError($WINEVENT_OK, 0, True)

    ; Int() rather than IsInt(): 200.5 used to be thrown away and replaced by 100.
    Local $iMs = Int($iInterval)
    If $iMs < 25 Then $iMs = 100 ; AutoIt clamps anything below 25 ms to 25 ms anyway

    AdlibRegister("__WinEvent_AdlibDispatch", $iMs)
    If @error Then Return SetError(__WinEvent_SetError($WINEVENT_ERR_API_CALL, "AdlibRegister failed"), 0, False)

    $__g_WinEvent_bAdlibActive = True
    Return SetError($WINEVENT_OK, 0, True)
EndFunc   ;==>_WinEvent_EnableAdlib

; #FUNCTION# ====================================================================================================================
; Name ..........: _WinEvent_DisableAdlib
; Description ...: Disables automatic background queue processing.
; Syntax ........: _WinEvent_DisableAdlib()
; Parameters ....: None.
; Return values .: Always True with @error set to $WINEVENT_OK, even when no background pump was active.
; Author ........: Numeric1
; ===============================================================================================================================
Func _WinEvent_DisableAdlib()
    If $__g_WinEvent_bAdlibActive Then
        AdlibUnRegister("__WinEvent_AdlibDispatch")
        $__g_WinEvent_bAdlibActive = False
    EndIf
    Return SetError($WINEVENT_OK, 0, True)
EndFunc   ;==>_WinEvent_DisableAdlib


; ===============================================================================================================================
;                    INTERNAL FUNCTIONS
; ===============================================================================================================================

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WinEvent_SetError
; Description ...: Records a failure in the module globals (code, message, API status) and hands the code back as a value.
; Syntax ........: __WinEvent_SetError($iCode, $sMsg = "", $iApi = 0)
; Parameters ....: $iCode - error code to report.
;                  $sMsg  - human readable detail kept for _WinEvent_GetLastErrorMsg (default "").
;                  $iApi  - Win32 or LSTATUS code of the failing call, 0 when not applicable (default 0).
; Return values .: The code in $iCode. @error cannot cross a Return, so the code travels as a value and the caller re-emits it with SetError.
; Author ........: Numeric1
; ===============================================================================================================================
Func __WinEvent_SetError($iCode, $sMsg = "", $iApi = 0)
    $__g_WinEvent_iLastError    = $iCode
    $__g_WinEvent_sLastErrorMsg = $sMsg
    $__g_WinEvent_iLastApi      = $iApi
    ; The code comes back as a VALUE on purpose: @error does not survive "Return OtherFunc()".
    Return $iCode
EndFunc   ;==>__WinEvent_SetError

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WinEvent_RegCreateKey
; Description ...: Creates or opens a registry key using Win32 API.
; Syntax ........: __WinEvent_RegCreateKey($hKey, $sSubKey, $iAccess = $WINEVENT_KEY_WRITE)
; Parameters ....: $hKey      - Root key handle (e.g., 0x80000002 for HKEY_LOCAL_MACHINE)
;                  $sSubKey   - Registry sub-key path
;                  $iAccess   - Access mask (default KEY_WRITE)
; Return values .: Success - Handle to the opened/created key
;                  Failure - 0 and sets @error
; Author ........: Numeric1
; ===============================================================================================================================
Func __WinEvent_RegCreateKey($hKey, $sSubKey, $iAccess = $WINEVENT_KEY_WRITE)
    Local $aRet = DllCall($__g_WinEvent_hAdvapi32, "long", "RegCreateKeyExW", _
            "handle", $hKey, _
            "wstr", $sSubKey, _
            "dword", 0, _
            "wstr", "", _
            "dword", 0, _
            "dword", $iAccess, _
            "ptr", 0, _
            "handle*", 0, _
            "dword*", 0)

    If @error Or Not IsArray($aRet) Then
        __WinEvent_SetError($WINEVENT_ERR_REGISTRY, "RegCreateKeyExW could not be called")
        Return 0
    EndIf

    If $aRet[0] <> 0 Then
        __WinEvent_SetError($WINEVENT_ERR_REGISTRY, "RegCreateKeyExW failed for '" & $sSubKey & "'", $aRet[0])
        Return 0
    EndIf

    ; $aRet[8] holds the key handle, $aRet[9] the disposition: 1 = created, 2 = already there.
    $__g_WinEvent_iLastDisposition = $aRet[9]
    Return SetError($WINEVENT_OK, 0, $aRet[8])
EndFunc   ;==>__WinEvent_RegCreateKey

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WinEvent_RegQueryValueEx
; Description ...: Reads one registry value as a string, used before writing over a key that
;                  may belong to another application.
; Syntax ........: __WinEvent_RegQueryValueEx($hKey, $sValueName)
; Parameters ....: $hKey        - Handle returned by __WinEvent_RegCreateKey
;                  $sValueName  - Name of the value to read
; Return values .: Success - The value as a string (REG_EXPAND_SZ is returned unexpanded,
;                           which is what was written)
;                  Failure - "" and the error state holds the LSTATUS
; Author ........: Numeric1
; Notes .........: RegQueryValueExW returns its out-parameters in the DllCall result array, not
;                  in any struct: "dword*", DllStructGetPtr($t) only seeds AutoIt's own storage
;                  with the pointer value and leaves $t at zero.
; ===============================================================================================================================
Func __WinEvent_RegQueryValueEx($hKey, $sValueName)
    ; First call with a zero-size buffer: the returned size is the real one.
    Local $aRet = DllCall($__g_WinEvent_hAdvapi32, "long", "RegQueryValueExW", _
            "handle", $hKey, _
            "wstr", $sValueName, _
            "ptr", 0, _
            "dword*", 0, _
            "ptr", 0, _
            "dword*", 0)
    If @error Or Not IsArray($aRet) Then
        __WinEvent_SetError($WINEVENT_ERR_REGISTRY, "RegQueryValueExW could not be called")
        Return ""
    EndIf
    If $aRet[0] <> 0 Then
        __WinEvent_SetError($WINEVENT_ERR_REGISTRY, "RegQueryValueExW failed for '" & $sValueName & "'", $aRet[0])
        Return ""
    EndIf

    Local $iType = $aRet[4]
    Local $iSize = $aRet[6]
    If $iSize < 2 Or ($iType <> 1 And $iType <> 2) Then Return "" ; REG_SZ / REG_EXPAND_SZ only

    Local $tData = DllStructCreate("wchar[" & Ceiling($iSize / 2) & "]")
    $aRet = DllCall($__g_WinEvent_hAdvapi32, "long", "RegQueryValueExW", _
            "handle", $hKey, _
            "wstr", $sValueName, _
            "ptr", 0, _
            "dword*", 0, _
            "ptr", DllStructGetPtr($tData), _
            "dword*", $iSize)
    If @error Or Not IsArray($aRet) Then
        __WinEvent_SetError($WINEVENT_ERR_REGISTRY, "RegQueryValueExW read failed for '" & $sValueName & "'")
        Return ""
    EndIf
    If $aRet[0] <> 0 Then
        __WinEvent_SetError($WINEVENT_ERR_REGISTRY, "RegQueryValueExW read failed for '" & $sValueName & "'", $aRet[0])
        Return ""
    EndIf

    Return DllStructGetData($tData, 1)
EndFunc   ;==>__WinEvent_RegQueryValueEx

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WinEvent_RegCloseKey
; Description ...: Closes a key handle opened by __WinEvent_RegCreateKey.
; Syntax ........: __WinEvent_RegCloseKey($hKey)
; Parameters ....: $hKey - handle returned by __WinEvent_RegCreateKey.
; Return values .: The LSTATUS of RegCloseKey, 0 when the handle was closed.
; Author ........: Numeric1
; ===============================================================================================================================
Func __WinEvent_RegCloseKey($hKey)
    If $hKey = 0 Then Return 0
    Local $aRet = DllCall($__g_WinEvent_hAdvapi32, "long", "RegCloseKey", "handle", $hKey)
    If @error Or Not IsArray($aRet) Then Return 0
    Return $aRet[0]
EndFunc   ;==>__WinEvent_RegCloseKey

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WinEvent_LastError
; Description ...: GetLastError, read immediately after the failing Win32 call.
;                  Must be stored in a local variable: the next DllCall overwrites it.
; Syntax ........: __WinEvent_LastError()
; Parameters ....: None.
; Return values .: The Win32 error code of the most recent failed call in this thread, 0 when kernel32 could not be queried.
; Author ........: Numeric1
; ===============================================================================================================================
Func __WinEvent_LastError()
    Local $aRet = DllCall("kernel32.dll", "dword", "GetLastError")
    If @error Or Not IsArray($aRet) Then Return 0
    Return $aRet[0]
EndFunc   ;==>__WinEvent_LastError

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WinEvent_RegSetValueEx
; Description ...: Sets a registry value using Win32 API.
; Syntax ........: __WinEvent_RegSetValueEx($hKey, $sValueName, $vValue, $sType = "REG_SZ")
; Parameters ....: $hKey       - open key handle.
;                  $sValueName - name of the value to write.
;                  $vValue     - data to store.
;                  $sType      - "REG_SZ" (default), "REG_EXPAND_SZ" or "REG_DWORD"; anything else is refused.
; Return values .: Success - 1.
;                  Failure - 0. These low-level helpers record the reason in the last-error globals for _WinEvent_GetLastError; the public functions read the value and re-emit @error themselves.
; Author ........: Numeric1
; ===============================================================================================================================
Func __WinEvent_RegSetValueEx($hKey, $sValueName, $vValue, $sType = "REG_SZ")
    Local $iTypeId = 1 ; REG_SZ
    Local $tData = 0
    Local $iDataSize = 0

    Switch $sType
        Case "REG_SZ"
            $iTypeId = 1
            $iDataSize = (StringLen($vValue) + 1) * 2
            $tData = DllStructCreate("wchar[" & StringLen($vValue) + 1 & "]")
            DllStructSetData($tData, 1, $vValue)

        Case "REG_EXPAND_SZ"
            $iTypeId = 2
            $iDataSize = (StringLen($vValue) + 1) * 2
            $tData = DllStructCreate("wchar[" & StringLen($vValue) + 1 & "]")
            DllStructSetData($tData, 1, $vValue)

        Case "REG_DWORD"
            $iTypeId = 4
            $iDataSize = 4
            $tData = DllStructCreate("dword")
            DllStructSetData($tData, 1, $vValue)

        Case Else
            __WinEvent_SetError($WINEVENT_ERR_INVALID_PARAM, "Unsupported registry type: " & $sType)
            Return 0
    EndSwitch

    Local $aRet = DllCall($__g_WinEvent_hAdvapi32, "long", "RegSetValueExW", _
            "handle", $hKey, _
            "wstr", $sValueName, _
            "dword", 0, _
            "dword", $iTypeId, _
            "ptr", DllStructGetPtr($tData), _
            "dword", $iDataSize)

    If @error Or Not IsArray($aRet) Then
        __WinEvent_SetError($WINEVENT_ERR_REGISTRY, "RegSetValueExW could not be called")
        Return 0
    EndIf

    If $aRet[0] <> 0 Then
        __WinEvent_SetError($WINEVENT_ERR_REGISTRY, "RegSetValueExW failed for '" & $sValueName & "'", $aRet[0])
        Return 0
    EndIf

    Return 1
EndFunc   ;==>__WinEvent_RegSetValueEx

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WinEvent_RegDeleteTree
; Description ...: Deletes a registry key and all its subkeys/values.
; Syntax ........: __WinEvent_RegDeleteTree($hKey, $sSubKey)
; Parameters ....: $hKey    - parent handle, usually $HKEY_LOCAL_MACHINE.
;                  $sSubKey - relative path of the key to delete together with its subkeys.
; Return values .: Success - 1.
;                  Failure - 0. The reason is stored in the last-error globals, see __WinEvent_RegSetValueEx.
; Author ........: Numeric1
; ===============================================================================================================================
Func __WinEvent_RegDeleteTree($hKey, $sSubKey)
    Local $aRet = DllCall($__g_WinEvent_hAdvapi32, "long", "RegDeleteTreeW", _
            "handle", $hKey, _
            "wstr", $sSubKey)

    If @error Or Not IsArray($aRet) Then
        __WinEvent_SetError($WINEVENT_ERR_REGISTRY, "RegDeleteTreeW could not be called")
        Return 0
    EndIf

    If $aRet[0] <> 0 Then
        __WinEvent_SetError($WINEVENT_ERR_REGISTRY, "RegDeleteTreeW failed for '" & $sSubKey & "'", $aRet[0])
        Return 0
    EndIf

    Return 1
EndFunc   ;==>__WinEvent_RegDeleteTree

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WinEvent_QueueResize
; Description ...: Resizes the ring buffer, keeping the events already queued.
; Syntax ........: __WinEvent_QueueResize($iRows)
; Parameters ....: $iRows - smallest number of pending events that must fit after the resize.
; Return values .: The number of events that survived the resize.
; Author ........: Numeric1
; ===============================================================================================================================
Func __WinEvent_QueueResize($iRows)
    If $iRows < 1 Then $iRows = 1
    If $iRows = $__g_WinEvent_iQueueCap Then Return 1

    Local $iKept = $__g_WinEvent_iQueueCount
    If $iKept > $iRows Then $iKept = $iRows

    Local $aNew[$iRows][3]
    For $i = 0 To $iKept - 1
        Local $iSrc = Mod($__g_WinEvent_iQueueHead + $i, $__g_WinEvent_iQueueCap)
        $aNew[$i][0] = $__g_WinEvent_aQueue[$iSrc][0]
        $aNew[$i][1] = $__g_WinEvent_aQueue[$iSrc][1]
        $aNew[$i][2] = $__g_WinEvent_aQueue[$iSrc][2]
    Next

    $__g_WinEvent_aQueue = $aNew
    $__g_WinEvent_iQueueCap = $iRows
    $__g_WinEvent_iQueueHead = 0
    $__g_WinEvent_iQueueCount = $iKept
    Return $iKept
EndFunc   ;==>__WinEvent_QueueResize

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WinEvent_QueueReset
; Description ...: Forgets every queued event without reallocating.
; Syntax ........: __WinEvent_QueueReset()
; Parameters ....: None.
; Return values .: 1 once the ring is empty and its counters are back to zero.
; Author ........: Numeric1
; ===============================================================================================================================
Func __WinEvent_QueueReset()
    Local $iCap = $__g_WinEvent_iQueueCap
    For $i = 0 To $iCap - 1
        $__g_WinEvent_aQueue[$i][0] = ""
        $__g_WinEvent_aQueue[$i][1] = ""
        $__g_WinEvent_aQueue[$i][2] = 0
    Next
    $__g_WinEvent_iQueueHead = 0
    $__g_WinEvent_iQueueCount = 0
    Return 1
EndFunc   ;==>__WinEvent_QueueReset

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WinEvent_QueuePush
; Description ...: Appends one event in constant time: the buffer is allocated once
;                  instead of being grown per event, which is what made the previous
;                  ReDim version quadratic.
; Syntax ........: __WinEvent_QueuePush($sEventName, $vData)
; Parameters ....: $sEventName - name of the event to queue.
;                  $vData      - payload delivered at dispatch time.
; Return values .: Success - True and @extended = events pending.
;                  Failure - False and @error set to 9 (queue full); the oldest events are never dropped silently.
; Author ........: Numeric1
; ===============================================================================================================================
Func __WinEvent_QueuePush($sEventName, $vData)
    If $__g_WinEvent_iQueueCap < $__g_WinEvent_iQueueMax Then __WinEvent_QueueResize($__g_WinEvent_iQueueMax)

    If $__g_WinEvent_iQueueCount >= $__g_WinEvent_iQueueMax Then
        Return SetError(__WinEvent_SetError($WINEVENT_ERR_QUEUE_FULL, "Event queue is full (max: " & $__g_WinEvent_iQueueMax & ")"), 0, False)
    EndIf

    Local $iRow = Mod($__g_WinEvent_iQueueHead + $__g_WinEvent_iQueueCount, $__g_WinEvent_iQueueCap)
    $__g_WinEvent_aQueue[$iRow][0] = $sEventName
    $__g_WinEvent_aQueue[$iRow][1] = $vData
    ; A readable date, not a TimerInit() tick: the tick could not be placed in time and
    ; made every exported row look identical.
    $__g_WinEvent_aQueue[$iRow][2] = __WinEvent_Stamp()
    $__g_WinEvent_iQueueCount += 1

    __WinEvent_JournalPush("POSTED", $sEventName, $vData, "queued=" & $__g_WinEvent_iQueueCount)

    Return SetError($WINEVENT_OK, $__g_WinEvent_iQueueCount, True)
EndFunc   ;==>__WinEvent_QueuePush

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WinEvent_QueuePop
; Description ...: Takes the oldest event out of the ring (FIFO, constant time).
; Syntax ........: __WinEvent_QueuePop()
; Parameters ....: None.
; Return values .: Success - Array [0]=event, [1]=data, [2]=timestamp
;                  Failure - 0 and @error 7 (queue empty)
; Author ........: Numeric1
; ===============================================================================================================================
Func __WinEvent_QueuePop()
    If $__g_WinEvent_iQueueCount = 0 Then
        Return SetError(__WinEvent_SetError($WINEVENT_ERR_NOT_FOUND, "Event queue is empty"), 0, 0)
    EndIf

    Local $iHead = $__g_WinEvent_iQueueHead
    Local $aEvent[3]
    $aEvent[0] = $__g_WinEvent_aQueue[$iHead][0]
    $aEvent[1] = $__g_WinEvent_aQueue[$iHead][1]
    $aEvent[2] = $__g_WinEvent_aQueue[$iHead][2]

    ; Release the slot: it can hold an array, and nothing else reaches it again.
    $__g_WinEvent_aQueue[$iHead][0] = ""
    $__g_WinEvent_aQueue[$iHead][1] = ""
    $__g_WinEvent_aQueue[$iHead][2] = 0
    $__g_WinEvent_iQueueHead = Mod($iHead + 1, $__g_WinEvent_iQueueCap)
    $__g_WinEvent_iQueueCount -= 1

    Return SetError($WINEVENT_OK, $__g_WinEvent_iQueueCount, $aEvent)
EndFunc   ;==>__WinEvent_QueuePop

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WinEvent_MaskToRe
; Description ...: Compiles a registration name into a case-insensitive regular expression,
;                  or into an empty string when the name carries no wildcard.
; Syntax ........: __WinEvent_MaskToRe($sPattern)
; Parameters ....: $sPattern - registration name; "*" means any run of characters, "?" one character.
; Return values .: "" (plain name, match with "=") or the "(?i)^...$" pattern to feed StringRegExp.
; Author ........: Numeric1
; Notes .........: (?i) is there because AutoIt "=" on strings is case-insensitive: a mask would
;                  otherwise be the only comparison in this UDF that cares about case. Every other
;                  regular-expression character is escaped by hand - one Switch pass, so a name
;                  such as "Audit.V1 (x)" stays literal.
; ===============================================================================================================================
Func __WinEvent_MaskToRe($sPattern)
    If StringInStr($sPattern, "*") = 0 And StringInStr($sPattern, "?") = 0 Then Return ""

    Local $sRe = ""
    For $i = 1 To StringLen($sPattern)
        Local $c = StringMid($sPattern, $i, 1)
        Switch $c
            Case "*"
                $sRe &= ".*"
            Case "?"
                $sRe &= "."
            Case "\", ".", "[", "]", "(", ")", "{", "}", "+", "^", "$", "|"
                $sRe &= "\" & $c
            Case Else
                $sRe &= $c
        EndSwitch
    Next

    Return "(?i)^" & $sRe & "$"
EndFunc   ;==>__WinEvent_MaskToRe

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WinEvent_RemoveById
; Description ...: Drops every registered handler carrying a handler ID (one pass into a fresh
;                  table, the same way _WinEvent_UnregisterHandler removes by name).
; Syntax ........: __WinEvent_RemoveById($iId)
; Parameters ....: $iId - handler ID to drop.
; Return values .: Number of handlers removed (0 = no row carries that ID). Never touches the
;                  UDF error state, so the dispatcher cannot overwrite a handler's failure.
; Author ........: Numeric1
; ===============================================================================================================================
Func __WinEvent_RemoveById($iId)
    Local $iTotal = UBound($__g_WinEvent_aHandlers)
    If $iTotal = 0 Then Return 0

    Local $aKeep[$iTotal][$WINEVENT_H_COLS]
    Local $iKept = 0
    Local $iRemoved = 0
    For $i = 0 To $iTotal - 1
        If $__g_WinEvent_aHandlers[$i][$WINEVENT_H_ID] = $iId Then
            $iRemoved += 1
        Else
            For $c = 0 To $WINEVENT_H_COLS - 1
                $aKeep[$iKept][$c] = $__g_WinEvent_aHandlers[$i][$c]
            Next
            $iKept += 1
        EndIf
    Next
    If $iRemoved = 0 Then Return 0

    If $iKept = 0 Then
        ReDim $__g_WinEvent_aHandlers[0][$WINEVENT_H_COLS]
    Else
        ReDim $aKeep[$iKept][$WINEVENT_H_COLS]
        $__g_WinEvent_aHandlers = $aKeep
    EndIf

    Return $iRemoved
EndFunc   ;==>__WinEvent_RemoveById

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WinEvent_Invoke
; Description ...: Calls one handler with the number of parameters it declares, returns the
;                  call error as a value (a return value always survives a function hop,
;                  @error does not) and hands the handler's own return value back by reference.
; Syntax ........: __WinEvent_Invoke($sCallback, $sEventName, $vData, $iParams, ByRef $vRet)
; Parameters ....: $sCallback  - function name or function reference stored at registration time.
;                  $sEventName - passed as the first parameter when $iParams is 1 or 2.
;                  $vData      - passed as the second parameter when $iParams is 2.
;                  $iParams    - number of parameters the callback declares: 0, 1 or 2.
;                  $vRet       - ByRef, receives whatever the handler returned ("" when it never ran).
; Return values .: 0 = the handler ran, otherwise the @error given by Call()
; Author ........: Numeric1
; Notes .........: $vRet is what lets the dispatcher tell a refusal (the handler returned the
;                  literal False) from a handler that returned nothing: measured on 3.3.16.1 a
;                  handler without a Return gives Int32 0, and 0 = False is True in AutoIt, so
;                  only VarGetType() separates the two.
; ===============================================================================================================================
Func __WinEvent_Invoke($sCallback, $sEventName, $vData, $iParams, ByRef $vRet)
    Local $iErr = 0
    $vRet = ""
    If $iParams <= 0 Then
        $vRet = Call($sCallback)
        $iErr = @error
    ElseIf $iParams = 1 Then
        $vRet = Call($sCallback, $sEventName)
        $iErr = @error
    Else
        $vRet = Call($sCallback, $sEventName, $vData)
        $iErr = @error
    EndIf
    Return $iErr
EndFunc   ;==>__WinEvent_Invoke

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WinEvent_Dispatch
; Description ...: Invokes all enabled handlers whose registration matches a given event
;                  name (plain equality or compiled wildcard mask), highest priority first,
;                  then removes the one-shot handlers collected in that snapshot.
; Syntax ........: __WinEvent_Dispatch($sEventName, $vData)
; Parameters ....: $sEventName - event to deliver.
;                  $vData      - payload passed to every matching handler.
; Return values .: Success - Number of handlers that accepted the event, in @extended as well
;                  Failure - @error 10 when at least one handler could not be called;
;                            @extended then holds the number of failures
;                  Handlers that refused (returned the literal False) are in neither count: they
;                  are reported through $__g_WinEvent_iLastRefused, which __WinEvent_Deliver reads.
; Author ........: Numeric1
; ===============================================================================================================================
Func __WinEvent_Dispatch($sEventName, $vData)
    $__g_WinEvent_iLastRefused = 0
    Local $iTotal = UBound($__g_WinEvent_aHandlers)
    If $iTotal = 0 Then Return SetError($WINEVENT_OK, 0, 0)

    ; Snapshot the matching handlers: a handler may register or unregister handlers, and
    ; walking the live table in place used to crash on the first self-removal.
    Local $aCall[$iTotal][3]
    Local $aOnce[$iTotal] ; handler IDs armed once, removed after this dispatch is over
    Local $iOnce = 0
    Local $n = 0
    For $i = 0 To $iTotal - 1
        If $__g_WinEvent_aHandlers[$i][3] <> 1 Then ContinueLoop

        Local $sMask = $__g_WinEvent_aHandlers[$i][$WINEVENT_H_MASK]
        Local $bHit = False
        If $sMask = "" Then
            $bHit = ($__g_WinEvent_aHandlers[$i][0] = $sEventName)
        Else
            $bHit = (StringRegExp($sEventName, $sMask) = 1)
        EndIf
        If $bHit Then
            $aCall[$n][0] = $__g_WinEvent_aHandlers[$i][1]
            $aCall[$n][1] = $__g_WinEvent_aHandlers[$i][2]
            $aCall[$n][2] = $__g_WinEvent_aHandlers[$i][4]
            If $__g_WinEvent_aHandlers[$i][$WINEVENT_H_ONCE] = 1 Then
                $aOnce[$iOnce] = $__g_WinEvent_aHandlers[$i][$WINEVENT_H_ID]
                $iOnce += 1
            EndIf
            $n += 1
        EndIf
    Next
    If $n = 0 Then Return SetError($WINEVENT_OK, 0, 0)
    ReDim $aCall[$n][3]

    ; Highest priority first, registration order kept between equal priorities
    ; (insertion sort is stable and handler lists are short).
    For $i = 1 To $n - 1
        Local $sName = $aCall[$i][0]
        Local $iPrio = $aCall[$i][1]
        Local $iArgs = $aCall[$i][2]
        Local $j = $i - 1
        While $j >= 0 And $aCall[$j][1] < $iPrio
            $aCall[$j + 1][0] = $aCall[$j][0]
            $aCall[$j + 1][1] = $aCall[$j][1]
            $aCall[$j + 1][2] = $aCall[$j][2]
            $j -= 1
        WEnd
        $aCall[$j + 1][0] = $sName
        $aCall[$j + 1][1] = $iPrio
        $aCall[$j + 1][2] = $iArgs
    Next

    $__g_WinEvent_iDispatchDepth += 1
    Local $iInvoked = 0
    Local $iFailed = 0
    Local $iRefused = 0
    Local $iFirstErr = 0
    Local $sFirstBad = ""
    For $i = 0 To $n - 1
        Local $vRet = ""
        Local $iErr = __WinEvent_Invoke($aCall[$i][0], $sEventName, $vData, $aCall[$i][2], $vRet)
        If $iErr <> 0 Then
            $iFailed += 1
            If $iFirstErr = 0 Then
                $iFirstErr = $iErr
                $sFirstBad = $aCall[$i][0]
            EndIf
        ElseIf VarGetType($vRet) = "Bool" And Not $vRet Then
            ; The handler ran, looked at the event and refused it. Only the literal False means
            ; that: a handler returning nothing gives Int32 0, which would compare equal to False.
            $iRefused += 1
        Else
            $iInvoked += 1
        EndIf
    Next
    $__g_WinEvent_iDispatchDepth -= 1
    $__g_WinEvent_iLastRefused = $iRefused

    ; One-shot handlers are removed here, after the walk and after the handlers ran: the
    ; table may have been rebuilt by a handler in the meantime, and the removal also has to
    ; happen when the call itself failed, otherwise a broken one-shot would stay armed forever.
    If $iOnce > 0 Then
        For $i = 0 To $iOnce - 1
            __WinEvent_RemoveById($aOnce[$i])
        Next
    EndIf

    ; One journal row per dispatched event: the export still tells what happened after the
    ; queue has been drained. Events that matched no handler are not journaled.
    __WinEvent_JournalPush("DISPATCHED", $sEventName, $vData, "invoked=" & $iInvoked & " failed=" & $iFailed & ($iRefused > 0 ? " refused=" & $iRefused : "") & ($iOnce > 0 ? " once=" & $iOnce : ""))

    If $iFailed > 0 Then
        Return SetError(__WinEvent_SetError($WINEVENT_ERR_CALLBACK, $iFailed & " handler(s) of '" & $sEventName & "' could not be called, first: " & $sFirstBad _
                        & " (Call @error " & $iFirstErr & "; the handler must declare exactly the number of parameters given to _WinEvent_RegisterHandler)"), _
                $iFailed, $iInvoked)
    EndIf

    Return SetError($WINEVENT_OK, $iInvoked, $iInvoked)
EndFunc   ;==>__WinEvent_Dispatch

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WinEvent_DeadPush
; Description ...: Stores one event no handler took, dropping the oldest when the store is full.
; Syntax ........: __WinEvent_DeadPush($sEventName, $vData, $iAttempts, $sReason)
; Parameters ....: $sEventName - event that could not be delivered.
;                  $vData      - its payload, kept as it is so _WinEvent_Redeadmit can hand it back.
;                  $iAttempts  - delivery attempts already spent on it.
;                  $sReason    - text naming the failure (uncallable=N, refused=M).
; Return values .: Number of events the store holds afterwards.
; Author ........: Numeric1
; Notes .........: A plain bounded array instead of a third ring buffer: dead letters are the rare
;                  failure path, so the ReDim cost never shows, while a ring would double the code
;                  of every access. An array payload stays an array (stored in the cell, handed back
;                  by _WinEvent_DeadLetter); what the reader gets is a copy, measured - mutating it
;                  does not change the store.
; ===============================================================================================================================
Func __WinEvent_DeadPush($sEventName, $vData, $iAttempts, $sReason)
    Local $iMax = $__g_WinEvent_iDeadMax
    If $iMax < 1 Then $iMax = 1

    Local $iCount = UBound($__g_WinEvent_aDead)
    If $iCount >= $iMax Then
        For $i = 0 To $iCount - 2
            For $c = 0 To $WINEVENT_D_COLS - 1
                $__g_WinEvent_aDead[$i][$c] = $__g_WinEvent_aDead[$i + 1][$c]
            Next
        Next
        $__g_WinEvent_iDeadDropped += 1
        $iCount -= 1
    EndIf

    ReDim $__g_WinEvent_aDead[$iCount + 1][$WINEVENT_D_COLS]
    $__g_WinEvent_aDead[$iCount][0] = __WinEvent_Stamp()
    $__g_WinEvent_aDead[$iCount][1] = $sEventName
    $__g_WinEvent_aDead[$iCount][2] = $vData
    $__g_WinEvent_aDead[$iCount][3] = $sReason
    $__g_WinEvent_aDead[$iCount][4] = $iAttempts

    Return UBound($__g_WinEvent_aDead)
EndFunc   ;==>__WinEvent_DeadPush

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WinEvent_DeadReset
; Description ...: Empties the dead-letter store and forgets its eviction counter.
; Syntax ........: __WinEvent_DeadReset()
; Parameters ....: None.
; Return values .: 1.
; Author ........: Numeric1
; ===============================================================================================================================
Func __WinEvent_DeadReset()
    ReDim $__g_WinEvent_aDead[0][$WINEVENT_D_COLS]
    $__g_WinEvent_iDeadDropped = 0
    Return 1
EndFunc   ;==>__WinEvent_DeadReset

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WinEvent_Deliver
; Description ...: Dispatches one event, retries it while the retry budget allows, and parks it
;                  in the dead-letter store when nothing took it.
; Syntax ........: __WinEvent_Deliver($sEventName, $vData)
; Parameters ....: $sEventName - event to deliver.
;                  $vData      - payload passed to every matching handler.
; Return values .: Same as __WinEvent_Dispatch: number of handlers that accepted the event,
;                  @error 10 when at least one could not be called, @extended the dispatch report.
; Author ........: Numeric1
; Notes .........: One place holds the whole loss policy, so _WinEvent_Trigger and _WinEvent_Process
;                  behave identically. A retry re-runs the handlers immediately (AutoIt gives no
;                  timer here); the delayed path is _WinEvent_Redeadmit, which the host calls when
;                  its own resource is back.
;                  A handler that accepted the event settles it, even when another handler refused
;                  or could not be called: re-dispatching would run the accepting handler a second
;                  time, so a mixed result is never retried and never dead-lettered. The event is
;                  only lost when no handler at all accepted it.
; ===============================================================================================================================
Func __WinEvent_Deliver($sEventName, $vData)
    Local $iInvoked = __WinEvent_Dispatch($sEventName, $vData)
    Local $e = @error
    Local $x = @extended
    Local $iRefused = $__g_WinEvent_iLastRefused
    Local $iTries = 1

    ; Somebody accepted it: the event is delivered, whatever the other handlers did.
    If $iInvoked > 0 Then Return SetError($e, $x, $iInvoked)
    ; Nothing refused and nothing failed means no handler subscribed: not a loss.
    If ($e <> $WINEVENT_ERR_CALLBACK) And ($iRefused = 0) Then Return SetError($e, $x, $iInvoked)

    Local $iLimit = $__g_WinEvent_iRetryLimit
    If $iLimit < 0 Then $iLimit = 0

    While $iTries <= $iLimit
        $iTries += 1
        $iInvoked = __WinEvent_Dispatch($sEventName, $vData)
        $e = @error
        $x = @extended
        $iRefused = $__g_WinEvent_iLastRefused
        If $iInvoked > 0 Then ExitLoop
        If ($e <> $WINEVENT_ERR_CALLBACK) And ($iRefused = 0) Then ExitLoop
    WEnd

    If $iInvoked = 0 And ($e = $WINEVENT_ERR_CALLBACK Or $iRefused > 0) Then
        Local $sReason = ""
        If $e = $WINEVENT_ERR_CALLBACK Then $sReason = "uncallable=" & $x
        If $iRefused > 0 Then $sReason &= ($sReason = "" ? "" : " ") & "refused=" & $iRefused
        __WinEvent_DeadPush($sEventName, $vData, $iTries, $sReason)
    EndIf

    Return SetError($e, $x, $iInvoked)
EndFunc   ;==>__WinEvent_Deliver

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WinEvent_AdlibDispatch
; Description ...: Internal Adlib callback for background queue processing.
; Syntax ........: __WinEvent_AdlibDispatch()
; Parameters ....: None.
; Return values .: None. The function pumps up to 10 queued events and reports nothing; diagnostics stay in the queue and in the journal.
; Author ........: Numeric1
; ===============================================================================================================================
Func __WinEvent_AdlibDispatch()
    If Not $__g_WinEvent_bInitialized Then Return
    _WinEvent_Process(10) ; Process up to 10 events per tick
EndFunc   ;==>__WinEvent_AdlibDispatch

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WinEvent_Stamp
; Description ...: Current local time as "YYYY-MM-DD HH:MM:SS.mmm".
; Syntax ........: __WinEvent_Stamp()
; Parameters ....: None.
; Return values .: The stamp string.
; Author ........: Numeric1
; Notes .........: The date part is rebuilt only when @SEC changes, so 1000 events inside one
;                  second cost one concatenation each instead of seven (measured 1.4 ms over
;                  1000 calls, against 15.6 ms when rebuilt every time).
; ===============================================================================================================================
Func __WinEvent_Stamp()
    Local $iSec = @SEC
    If $iSec <> $__g_WinEvent_iStampSec Then
        $__g_WinEvent_iStampSec = $iSec
        $__g_WinEvent_sStampPrefix = @YEAR & "-" & @MON & "-" & @MDAY & " " & @HOUR & ":" & @MIN & ":" & @SEC
    EndIf
    Return $__g_WinEvent_sStampPrefix & "." & @MSEC
EndFunc   ;==>__WinEvent_Stamp

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WinEvent_Cell
; Description ...: Renders one value as a single export field.
; Syntax ........: __WinEvent_Cell($vValue)
; Parameters ....: $vValue - Any value: string, number, bool, array (1 or 2 dimensions), object.
; Return values .: The escaped text. "|" becomes \|, backslash \\, CR \r, LF \n.
;                  An array becomes [a, b] - it used to export as an empty field.
; Author ........: Numeric1
; ===============================================================================================================================
Func __WinEvent_Cell($vValue)
    If IsArray($vValue) Then
        Local $iRows = UBound($vValue)
        Local $iCols = UBound($vValue, 2)
        If $iCols > 1 Then Return "[rows=" & $iRows & ", cols=" & $iCols & "]"
        If $iRows = 0 Then Return "[]"
        Local $sOut = "["
        For $i = 0 To $iRows - 1
            If $i > 0 Then $sOut &= ", "
            $sOut &= __WinEvent_Cell($vValue[$i])
        Next
        Return $sOut & "]"
    EndIf
    If IsObj($vValue) Then Return "[object]"

    Local $s = String($vValue)
    ; Four StringInStr calls cost 13.8 microseconds (measured), four StringReplace 15.6, so
    ; the common case - a value with nothing to escape - is screened by one StringRegExp,
    ; which costs 6.8 microseconds in total for the call.
    If StringRegExp($s, "[\\\|\r\n]", 0) = 0 Then Return $s
    ; Escaping runs last, and backslash first, so a stored "\|" cannot look like an escape.
    $s = StringReplace($s, "\", "\\")
    $s = StringReplace($s, "|", "\|")
    $s = StringReplace($s, @CR, "\r")
    $s = StringReplace($s, @LF, "\n")
    Return $s
EndFunc   ;==>__WinEvent_Cell

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WinEvent_JournalResize
; Description ...: Resizes the journal ring, keeping the rows already written.
; Syntax ........: __WinEvent_JournalResize($iRows)
; Parameters ....: $iRows - Number of rows to allocate (at least 1)
; Return values .: Rows kept.
; Author ........: Numeric1
; ===============================================================================================================================
Func __WinEvent_JournalResize($iRows)
    If $iRows < 1 Then $iRows = 1
    If $iRows = $__g_WinEvent_iJournalCap Then Return $__g_WinEvent_iJournalCount

    Local $iKept = $__g_WinEvent_iJournalCount
    If $iKept > $iRows Then $iKept = $iRows

    Local $aNew[$iRows][5]
    Local $iOldCap = $__g_WinEvent_iJournalCap
    If $iOldCap < 1 Then $iOldCap = 1
    For $i = 0 To $iKept - 1
        Local $iSrc = Mod($__g_WinEvent_iJournalHead + $i, $iOldCap)
        For $c = 0 To 4
            $aNew[$i][$c] = $__g_WinEvent_aJournal[$iSrc][$c]
        Next
    Next

    $__g_WinEvent_aJournal = $aNew
    $__g_WinEvent_iJournalCap = $iRows
    $__g_WinEvent_iJournalHead = 0
    $__g_WinEvent_iJournalCount = $iKept
    Return $iKept
EndFunc   ;==>__WinEvent_JournalResize

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WinEvent_JournalReset
; Description ...: Clears the journal (rows are released: they can hold rendered data).
; Syntax ........: __WinEvent_JournalReset()
; Parameters ....: None.
; Return values .: Rows that were held.
; Author ........: Numeric1
; ===============================================================================================================================
Func __WinEvent_JournalReset()
    Local $iHeld = $__g_WinEvent_iJournalCount
    Local $iCap = $__g_WinEvent_iJournalCap
    For $i = 0 To $iCap - 1
        For $c = 0 To 4
            $__g_WinEvent_aJournal[$i][$c] = ""
        Next
    Next
    $__g_WinEvent_iJournalHead = 0
    $__g_WinEvent_iJournalCount = 0
    $__g_WinEvent_iJournalDropped = 0
    Return $iHeld
EndFunc   ;==>__WinEvent_JournalReset

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WinEvent_JournalPush
; Description ...: Appends one journal row in constant time.
; Syntax ........: __WinEvent_JournalPush($sKind, $sEvent, $vData, $sDetail)
; Parameters ....: $sKind   - POSTED or DISPATCHED
;                  $sEvent  - Event name
;                  $vData   - Data as given to the handler
;                  $sDetail - queued=N, or invoked=N failed=M
; Return values .: Total rows held. When the journal is full the OLDEST row is overwritten and
;                  $__g_WinEvent_iJournalDropped counts what was lost.
; Author ........: Numeric1
; ===============================================================================================================================
Func __WinEvent_JournalPush($sKind, $sEvent, $vData, $sDetail)
    If $__g_WinEvent_iJournalMax < 1 Then Return 0 ; journal disabled on purpose
    If $__g_WinEvent_iJournalCap < $__g_WinEvent_iJournalMax Then __WinEvent_JournalResize($__g_WinEvent_iJournalMax)

    ; $__g_WinEvent_iJournalMax is the live limit, $__g_WinEvent_iJournalCap only the
    ; allocation: lowering the limit must take effect at once. The row always goes at the
    ; tail; when that overflows the limit the head moves and the oldest row is lost.
    Local $iRow = Mod($__g_WinEvent_iJournalHead + $__g_WinEvent_iJournalCount, $__g_WinEvent_iJournalCap)
    If $__g_WinEvent_iJournalCount >= $__g_WinEvent_iJournalMax Then
        $__g_WinEvent_iJournalHead = Mod($__g_WinEvent_iJournalHead + 1, $__g_WinEvent_iJournalCap)
        $__g_WinEvent_iJournalDropped += 1
    Else
        $__g_WinEvent_iJournalCount += 1
    EndIf

    Local $sStamp = __WinEvent_Stamp()
    $__g_WinEvent_aJournal[$iRow][0] = $sStamp
    $__g_WinEvent_aJournal[$iRow][1] = $sKind
    $__g_WinEvent_aJournal[$iRow][2] = $sEvent
    ; Rendered here, not at export time: assigning an array into a cell keeps a reference,
    ; so a handler that modifies the data it was given would otherwise change the journal
    ; afterwards (measured). One row is one frozen picture of the event at that instant.
    $__g_WinEvent_aJournal[$iRow][3] = __WinEvent_Cell($vData)
    $__g_WinEvent_aJournal[$iRow][4] = $sDetail
    Return $__g_WinEvent_iJournalCount
EndFunc   ;==>__WinEvent_JournalPush

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WinEvent_CheckSourceName
; Description ...: Validates a source and log name before any registry call.
; Syntax ........: __WinEvent_CheckSourceName($sSource, $sLogFile)
; Parameters ....: $sSource  - Source name
;                  $sLogFile - Event log name
; Return values .: 0 = accepted. Otherwise the error code, as a VALUE (the message is left in
;                  $__g_WinEvent_sLastErrorMsg): 3 = empty, 11 = outside the accepted charset.
;                  A name is built into an HKLM path, so a separator or a control character
;                  must never reach RegCreateKeyExW.
; Author ........: Numeric1
; ===============================================================================================================================
Func __WinEvent_CheckSourceName($sSource, $sLogFile)
    If Not IsString($sSource) Then Return __WinEvent_SetError($WINEVENT_ERR_INVALID_PARAM, "Source name must be a string")
    If $sSource = "" Then Return __WinEvent_SetError($WINEVENT_ERR_INVALID_PARAM, "Source name must not be empty")
    If StringLen($sSource) > 255 Then Return __WinEvent_SetError($WINEVENT_ERR_BAD_NAME, "Source name longer than 255 characters")
    If StringRegExp($sSource, "^[A-Za-z0-9 ._\-]+$", 0) = 0 Then _
            Return __WinEvent_SetError($WINEVENT_ERR_BAD_NAME, "Source name '" & $sSource & "' uses a character outside letters, digits, space, dot, underscore, hyphen")

    If Not IsString($sLogFile) Or $sLogFile = "" Then Return 0 ; the caller supplies the default
    If StringLen($sLogFile) > 255 Or StringRegExp($sLogFile, "^[A-Za-z0-9 ._\-]+$", 0) = 0 Then _
            Return __WinEvent_SetError($WINEVENT_ERR_BAD_NAME, "Event log name '" & $sLogFile & "' uses a character outside letters, digits, space, dot, underscore, hyphen")

    Return 0
EndFunc   ;==>__WinEvent_CheckSourceName

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WinEvent_IsReservedSource
; Description ...: Tells whether a name belongs to Windows or to a component.
; Syntax ........: __WinEvent_IsReservedSource($sSource)
; Parameters ....: $sSource - Source name
; Return values .: 1 = reserved (as a VALUE), 0 = free to use.
;                  $WINEVENT_RESERVED_SOURCES holds exact names and, for entries ending in a
;                  hyphen, prefixes. Matching is case-insensitive like the registry.
; Author ........: Numeric1
; ===============================================================================================================================
Func __WinEvent_IsReservedSource($sSource)
    Local $sLow = StringLower($sSource)
    Local $aList = StringSplit(StringLower($WINEVENT_RESERVED_SOURCES), "|", 2)
    If Not IsArray($aList) Then Return 0
    For $i = 0 To UBound($aList) - 1
        Local $sItem = $aList[$i]
        If $sItem = "" Then ContinueLoop
        If StringRight($sItem, 1) = "-" Then
            If StringLeft($sLow, StringLen($sItem)) = $sItem Then Return 1
        ElseIf $sLow = $sItem Then
            Return 1
        EndIf
    Next
    Return 0
EndFunc   ;==>__WinEvent_IsReservedSource

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WinEvent_OwnedTest
; Description ...: Tells whether this process registered that source.
; Syntax ........: __WinEvent_OwnedTest($sSource, $sLogFile)
; Parameters ....: $sSource, $sLogFile
; Return values .: True or False. Ownership lives in memory only: a source registered by
;                  another process is never deleted from here.
; Author ........: Numeric1
; ===============================================================================================================================
Func __WinEvent_OwnedTest($sSource, $sLogFile)
    Local $sKey = StringLower("|" & $sLogFile & "|" & $sSource & "|")
    Return StringInStr(StringLower($__g_WinEvent_sOwnedSources), $sKey, 1) > 0
EndFunc   ;==>__WinEvent_OwnedTest

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WinEvent_OwnedAdd
; Description ...: Claims a source for this process.
; Syntax ........: __WinEvent_OwnedAdd($sSource, $sLogFile)
; Parameters ....: $sSource  - source name to remember.
;                  $sLogFile - event log the source belongs to.
; Return values .: The ownership list, as a string.
; Author ........: Numeric1
; ===============================================================================================================================
Func __WinEvent_OwnedAdd($sSource, $sLogFile)
    If __WinEvent_OwnedTest($sSource, $sLogFile) Then Return $__g_WinEvent_sOwnedSources
    $__g_WinEvent_sOwnedSources &= "|" & StringLower($sLogFile) & "|" & StringLower($sSource) & "|"
    Return $__g_WinEvent_sOwnedSources
EndFunc   ;==>__WinEvent_OwnedAdd

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WinEvent_OwnedRemove
; Description ...: Gives up a source after it has been deleted from the registry.
; Syntax ........: __WinEvent_OwnedRemove($sSource, $sLogFile)
; Parameters ....: $sSource  - source name to forget.
;                  $sLogFile - event log the source belongs to.
; Return values .: 1 = the entry was there, 0 = it was not.
; Author ........: Numeric1
; ===============================================================================================================================
Func __WinEvent_OwnedRemove($sSource, $sLogFile)
    Local $sKey = StringLower("|" & $sLogFile & "|" & $sSource & "|")
    Local $iPos = StringInStr(StringLower($__g_WinEvent_sOwnedSources), $sKey, 1)
    If $iPos = 0 Then Return 0
    $__g_WinEvent_sOwnedSources = StringLeft($__g_WinEvent_sOwnedSources, $iPos - 1) & _
            StringTrimLeft($__g_WinEvent_sOwnedSources, $iPos - 1 + StringLen($sKey))
    Return 1
EndFunc   ;==>__WinEvent_OwnedRemove

; ===============================================================================================================================
; END OF WinEventManager UDF
; ===============================================================================================================================
