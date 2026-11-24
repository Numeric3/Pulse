; #INDEX# =======================================================================================================================
; Title .........: WebView2 UDF
; AutoIt Version : 3.3.16+
; Language .......: English
; Version ........: 0.10.1
; Modified .......: 2026-11-11
; Description ...: Embeds the Microsoft Edge (Chromium) rendering engine inside an AutoIt GUI window.
;                  The UDF talks to the WebView2 runtime that Windows already provides through its own
;                  COM interfaces: no SDK, no DLL to ship, no wrapper binary, no registration, no
;                  download. Only kernel32, user32, ole32 and the system EmbeddedBrowserWebView.dll
;                  are touched.
;                  Navigation, bounds, zoom, JavaScript, the two way web message bridge, the page
;                  settings, event queueing, PNG/JPEG snapshots, a PDF export of the page, the
;                  downloads raised by a page and the cookies of the profile are all driven from
;                  AutoIt. Find in page, typed script results, the whole cookie jar, print settings
;                  and printing to memory, download control, script dialogs, accelerator keys,
;                  context menus, favicons, profile cleaning and the DevTools protocol join them.
;                  The colour the page believes the system is in, the colour behind a page that has not
;                  painted, the dark title bar of the host window and the folder the profile downloads to
;                  are the four appearances of 0.6.4. Six element helpers - exists, count, read, write,
;                  click, wait, in CSS or in XPath - take the page by the hand without a hand-written
;                  script, 0.7.0 adds the DPI awareness of the process and the one line that explains
;                  a failure, and 0.8.0 folds the whole first window into _WV2_Simple and the whole loop
;                  into _WV2_Run, with _WV2_CountViews as the proof that nothing was left behind.
;                  0.9.0 hands the queue to functions: an event kind that has been given a name is
;                  answered by that name, at the four places the queue is read and nowhere else, so a
;                  script that never reads events by hand writes no loop for them.
;                  0.10.0 loads extensions: an unpacked folder reaches the browser before the environment
;                  through _WV2_LoadExtension, or a live profile through _WV2_AddExtension, and the list of
;                  what the profile holds, the switch that turns one off and the removal come with it.
;                  0.10.1 is a patch and not a lot. The dispatcher that refuses a handler whose name is no
;                  longer a function used to rewrite the slot it had just read even when that handler had
;                  released its own view on the way out; it now writes back only while the slot is still
;                  this pass's to write. The nineteen $pThis parameters of the options object, which are
;                  there for the signature and read by nothing, are answered with #forceref, so a check of
;                  this file with Au3Check -w 5 is silent. No interface, function,
;                  event kind, handler slot, pointer cell, error code or runtime floor moves.
; Author ........: Numeric1
; Link ..........: https://www.autoitscript.com/forum/
; License .......: MIT, Copyright (c) 2026 Numeric1. Keep this header and the LICENSE file in any
;                  copy or redistribution. WebView2 interface identifiers and vtable layout follow
;                  the Microsoft WebView2 SDK (MIT); no Microsoft code is reproduced here.
; ===============================================================================================================================
; Requirements: Windows 10 or later carrying the "Microsoft Edge WebView2 Runtime", which every
; maintained Windows 10/11 installation already has. _WV2_GetRuntimePath() locates it; a missing
; runtime is reported as $WV2_ERR_RUNTIME, never installed.
;
; Design notes:
;   * One handle = one environment + one controller + one web view, all living in the thread that
;     called _WV2_Create. Up to 16 handles can be alive at the same time.
;   * COM pointers received as a callback argument are borrowed, so every wrapper is built with
;     ObjCreateInterface(..., False): the tag then starts at vtable slot 0 and the wrapper neither
;     adds nor releases a reference. The UDF calls AddRef/Release explicitly, which is what makes
;     _WV2_Destroy balanced and crash free.
;   * ICoreWebView2Controller::put_Bounds receives its RECT *by value*, so the x86 tag declares four
;     longs. Declaring "struct*" pushes a pointer, the callee reads the stack as coordinates and
;     the call never returns. On x64 neither four longs, nor two int64, nor AutoIt's own by-value
;     "struct" survive the call: the runtime reads the address of the sixteen bytes, so
;     __WV2_PutBounds calls that one method through the vtable with a pointer to a DllStruct.
;   * A method that only exists on a newer version of an interface is reached by QueryInterface on the
;     raw pointer, then called through DllCallAddress: an ObjCreateInterface tag would have to declare
;     every method of that interface, eighty of them before PrintToPdf alone.
;   * The UDF never shows a dialog and never writes to the console. Every failure is reported by
;     @error (a $WV2_ERR_* code) and @extended (the raw HRESULT when there is one).
;   * A close deletes nothing. The temporary profile of a released view is queued by __WV2_Free and
;     collected by the next _WV2_Create: deleting it inside the close measured 15 542 ms with the
;     window still on screen, and it survived anyway because the browser holds it for seconds.
;     Nothing is registered with OnAutoItExitRegister either - an exit function runs after the message
;     loop the runtime answers through, and the same teardown that costs 113 ms in the loop costs 1.4
;     to 2.7 s there. _WV2_DestroyAll is the net, and it belongs in the loop.

#include-once
#include <File.au3>

; #CONSTANTS# ===================================================================================================================
; Error codes returned through @error
Global Const $WV2_ERR_NONE = 0
Global Const $WV2_ERR_HANDLE = 1          ; invalid or destroyed handle
Global Const $WV2_ERR_ARG = 2             ; invalid argument for this call
Global Const $WV2_ERR_RUNTIME = 3         ; WebView2 runtime not found on this machine
Global Const $WV2_ERR_COM = 4             ; COM initialisation or interface wrapper failure
Global Const $WV2_ERR_ENV = 5             ; environment creation failed
Global Const $WV2_ERR_CONTROLLER = 6      ; controller creation failed
Global Const $WV2_ERR_NOT_READY = 7       ; instance not usable yet
Global Const $WV2_ERR_CALL = 8            ; a WebView2 method returned a failure HRESULT
Global Const $WV2_ERR_TIMEOUT = 9         ; operation did not complete in the allowed time
Global Const $WV2_ERR_FULL = 10           ; too many live instances
Global Const $WV2_ERR_FILE = 11           ; a file given to the UDF could not be written
Global Const $WV2_ERR_BUSY = 12           ; a resource handler is running, the UDF cannot re-enter
Global Const $WV2_ERR_GUI = 13            ; a window this UDF was asked to build could not be built
Global Const $WV2_ERR_CB = 14             ; the function named as an event handler could not be called
Global Const $WV2_ERR_EXT = 15            ; extension support refused: the environment was created without it, or the runtime has no Profile7

; Version of this file, so a script can check what it is running against.
Global Const $WV2_VERSION = "0.10.1"

; Default timeouts, in milliseconds
; 60 seconds, and not the 15 that earlier builds used. A cold start is not a fixed cost: measured on a
; 3,7 GB Windows 10 box with the runtime busy, the same _WV2_Create that answers in 1,2 s when the
; machine is quiet took 25,3 s and 47,6 s when it was not. A shorter limit does not fail fast, it fails
; a start that was going to succeed - and the browser it leaves behind keeps the profile folder, which
; makes the next start slower still. A GUI that cannot afford to wait uses _WV2_CreateStart and
; _WV2_CreateWait, and stays responsive in between.
Global Const $WV2_CREATE_TIMEOUT = 60000
Global Const $WV2_NAV_TIMEOUT = 30000

; Prefix of the profile folders _WV2_Create builds in the temporary directory when the caller does
; not name one. The name carries the process id, the handle and a serial, which is what lets
; __WV2_SweepStale recognise a folder of ours and tell a dead one from a live one.
Global Const $__WV2_PROFILE_PREFIX = "AutoItWebView2_"
; A browser needs a couple of seconds of message loop after the controller is closed to let go of its
; profile folder. The sweep only touches a released folder once it is older than this, so it never
; spends a walk on a folder it cannot delete yet.
Global Const $__WV2_SWEEP_AGE = 1000
; The teardown keeps the thread pumping so that the callbacks the runtime still owes can arrive, but it
; stops as soon as the queue has stayed silent for this long: the two hundred milliseconds a fixed pump
; costs every close are only worth paying when messages are actually still coming.
Global Const $__WV2_DRAIN_QUIET = 20
; ... and it never pumps longer than this, however busy the queue is. Closing has to have a bound the
; caller can rely on.
Global Const $__WV2_DRAIN_CAP = 100

; Interface identifiers published by the WebView2 SDK
Global Const $WV2_IID_UNKNOWN = "{00000000-0000-0000-C000-000000000046}"
Global Const $WV2_IID_ENV = "{B96D755E-0319-4E92-A296-23436F46A1FC}"
Global Const $WV2_IID_CTL = "{4D00C0D1-9434-4EB6-8078-8697A560334F}"
; The version of the controller that carries the background colour of the view.
Global Const $WV2_IID_CTL2 = "{C979903E-D4CA-4228-92EB-47EE3FA96EAB}"
Global Const $WV2_IID_WV = "{76ECEACB-0462-4D94-AC83-423A6793775E}"
Global Const $WV2_IID_ENVCB = "{4E8A3389-C9D8-4BD2-B6B5-124FEE6CC14D}"
Global Const $WV2_IID_CTLCB = "{6C4819F3-C9B7-4260-8127-C9F5BDE7F68C}"
Global Const $WV2_IID_NAVH = "{D33A35BF-1C49-4F98-93AB-006E0533FE1C}"
Global Const $WV2_IID_NAVARGS = "{30D68B7D-20D9-4752-A9CA-EC8448FBB5C1}"
Global Const $WV2_IID_NAVSH = "{9ADBE429-F36D-432B-9DDC-F8881FBD76E3}"
Global Const $WV2_IID_NAVSARGS = "{5B495469-E119-438A-9B18-7604F25F2E49}"
Global Const $WV2_IID_MSGH = "{57213F19-00E6-49FA-8E07-898EA01ECBD2}"
Global Const $WV2_IID_MSGARGS = "{0F99A40C-E962-4207-9E92-E3D542EFF849}"
Global Const $WV2_IID_NEWH = "{D4C185FE-C81C-4989-97AF-2D3FA7AB5651}"
Global Const $WV2_IID_NEWARGS = "{34ACB11C-FC37-4418-9132-F9C21D1EAFB9}"
Global Const $WV2_IID_PROCARGS = "{8155A9A4-1474-4A86-8CAE-151B0FA6B8CA}"
Global Const $WV2_IID_PROCH = "{79E0AEA4-990B-42D9-AA1D-0FCC2E5BC7F1}"
Global Const $WV2_IID_TITLEH = "{F5F2B923-953E-4042-9F95-F3A118E1AFD4}"
Global Const $WV2_IID_HISTH = "{C79A420C-EFD9-4058-9295-3E8B4BCAB645}"
Global Const $WV2_IID_EXECH = "{49511172-CC67-4BCA-9923-137112F4C4CC}"
Global Const $WV2_IID_ADDSCH = "{B99369F3-9B11-47B5-BC6F-8E7895FCEA17}"
Global Const $WV2_IID_CAPH = "{697E05E9-3D8F-45FA-96F4-8FFE1EDEDAF5}"
Global Const $WV2_IID_SETTINGS = "{E562E4F0-D7FA-43AC-8D71-C05150499F00}"
; The newer versions of ICoreWebView2 asked for through QueryInterface, and the interfaces they hand out.
Global Const $WV2_IID_WV2 = "{9E8F0CF8-E670-4B5E-B2BC-73E061E3184C}"
Global Const $WV2_IID_WV3 = "{A0D6DF20-3B92-416D-AA0C-437A9C727857}"
Global Const $WV2_IID_WV4 = "{20D02D59-6DF2-42DC-BD06-F98A694B1302}"
Global Const $WV2_IID_WV7 = "{79C24D83-09A3-45AE-9418-487F32A58740}"
Global Const $WV2_IID_PRINTH = "{CCF1EF04-FD8E-4D5F-B2DE-0983E41B8C36}"
Global Const $WV2_IID_DLH = "{EFEDC989-C396-41CA-83F7-07F845A55724}"
Global Const $WV2_IID_DLARGS = "{E99BBE21-43E9-4544-A732-282764EAFA60}"
Global Const $WV2_IID_COOKIE = "{177CD9E7-B6F5-451A-94A0-5D7A3A4C4141}"
Global Const $WV2_IID_RES = "{AB00B74C-15F1-4646-80E8-E76341D25D71}"
; Lot 2: search, typed scripts, cookies, printing, downloads, dialogs, menus, favicon and the
; DevTools protocol. Every identifier below is the one the SDK publishes for that interface.
Global Const $WV2_IID_WV16 = "{0EB34DC9-9F91-41E1-8639-95CD5943906B}"
Global Const $WV2_IID_WV21 = "{C4980DEA-587B-43B9-8143-3EF3BF552D95}"
Global Const $WV2_IID_WV28 = "{62E50381-5BF5-51A8-AAE0-F20A3A9C8A90}"
Global Const $WV2_IID_FIND = "{A3EC0F5F-DDBC-54ED-8546-AF75A785B9A6}"
Global Const $WV2_IID_FINDOPT = "{E82E3B2B-A4AF-5BC6-94C6-18B44157A16C}"
Global Const $WV2_IID_FINDIDXH = "{0054F514-9A8E-5876-AED5-30B37F8C86A5}"
Global Const $WV2_IID_FINDCNTH = "{DA0D6827-4254-5B10-A6D9-412076AFC9F3}"
Global Const $WV2_IID_FINDSTARTH = "{6A90ECAF-44B0-5BD9-8F07-1967E17BE9FB}"
Global Const $WV2_IID_EXECRESH = "{1BB5317B-8238-4C67-A7FF-BAF6558F289D}"
Global Const $WV2_IID_EXECRES = "{0CE15963-3698-4DF7-9399-71ED6CDD8C9F}"
Global Const $WV2_IID_SCRIPTEX = "{054DAE00-84A3-49FF-BC17-4012A90BC9FD}"
Global Const $WV2_IID_COOKIEH = "{5A4F5069-5C15-47C3-8646-F4DE1C116670}"
Global Const $WV2_IID_COOKIELIST = "{F7F6F714-5D2A-43C6-9503-346ECE02D186}"
Global Const $WV2_IID_COOKIE1 = "{AD26D6BE-1486-43E6-BF87-A2034006CA21}"
Global Const $WV2_IID_PDFSTREAMH = "{4C9F8229-8F93-444F-A711-2C0DFD6359D5}"
Global Const $WV2_IID_PRINTSET = "{377F3721-C74E-48CA-8DB1-DF68E51D60E2}"
Global Const $WV2_IID_DLSTATEH = "{81336594-7EDE-4BA9-BF71-ACF0A95B58DD}"
Global Const $WV2_IID_DLPROGH = "{828E8AB6-D94C-4264-9CEF-5217170D6251}"
Global Const $WV2_IID_DLOP = "{3D6B6CF2-AFE1-44C7-A995-C65117714336}"
Global Const $WV2_IID_DIALOGH = "{EF381BF9-AFA8-4E37-91C4-8AC48524BDFB}"
Global Const $WV2_IID_DIALOGARGS = "{7390BB70-ABE0-4843-9529-F143B31B03D6}"
Global Const $WV2_IID_ACCELH = "{B29C7E28-FA79-41A8-8E44-65811C76DCB2}"
Global Const $WV2_IID_ACCELARGS = "{9F760F8A-FB79-42BE-9990-7B56900FA9C7}"
Global Const $WV2_IID_CTXH = "{04D3FE1D-AB87-42FB-A898-DA241D35B63C}"
Global Const $WV2_IID_CTXARGS = "{A1D309EE-C03F-11EB-8529-0242AC130003}"
Global Const $WV2_IID_CTXITEM = "{7AED49E3-A93F-497A-811C-749C6B6B6C65}"
Global Const $WV2_IID_CTXITEMS = "{F562A2F5-C415-45CF-B909-D4B7C1E276D3}"
Global Const $WV2_IID_FAVH = "{2913DA94-833D-4DE0-8DCA-900FC524A1A4}"
Global Const $WV2_IID_FAVGET = "{A2508329-7DA8-49D7-8C05-FA125E4AEE8D}"
Global Const $WV2_IID_PROFH = "{E9710A06-1D1D-49B2-8234-226F35846AE5}"
Global Const $WV2_IID_PROFILE = "{79110AD3-CD5D-4373-8BC3-C60658F17A5F}"
Global Const $WV2_IID_PROFILE2 = "{FA740D4B-5EAE-4344-A8AD-74BE31925397}"
Global Const $WV2_IID_CDPCALLH = "{5C4889F0-5EF6-4C5A-952C-D8F1B92D0574}"
Global Const $WV2_IID_CDPEVTH = "{E2FDA4BE-5456-406C-A261-3D452138362C}"
Global Const $WV2_IID_CDPEVTARGS = "{653C2959-BB3A-4377-8632-B58ADA4E66C4}"
Global Const $WV2_IID_CDPRECV = "{B32CA51A-8371-45E9-9317-AF021D080367}"
Global Const $WV2_IID_ENV6 = "{E59EE362-ACBD-4857-9A8E-D3644D9459A9}"
Global Const $WV2_IID_ENV15 = "{2AC5EBFB-E654-5961-A667-7971885C7B27}"
Global Const $WV2_IID_WV8 = "{E9632730-6E1E-43AB-B7B8-7B2C9E62E094}"
; The theme lot: _13 is the version of the view that hands out the profile, and the profile itself is
; what stores the preferred colour scheme and the default download folder.
Global Const $WV2_IID_WV13 = "{F75F09A8-667E-4983-88D6-C8773F315E84}"
Global Const $WV2_IID_AUDIOH = "{5DEF109A-2F4B-49FA-B7F6-11C39E513328}"
Global Const $WV2_IID_MUTEDH = "{57D90347-CD0E-4952-A4A2-7483A2756F08}"
Global Const $WV2_IID_FULLH = "{E45D98B1-AFEF-45BE-8BAF-6C7728867F73}"
Global Const $WV2_IID_PERMH = "{15E1C6A3-C72A-4DF3-91D7-D097FBEC6BFD}"
; The four handlers of the life cycle of a document, and the arguments object each of them is handed.
Global Const $WV2_IID_CNTLOADH = "{364471E7-F2BE-4910-BDBA-D72077D51C4B}"
Global Const $WV2_IID_SRCCHGH = "{3C067F9F-5388-4772-8B48-79F7EF1AB37C}"
Global Const $WV2_IID_DOMCBH = "{4BAC7E9C-199E-49ED-87ED-249303ACF019}"
Global Const $WV2_IID_WINCLOSEH = "{5C19E9E0-092F-486B-AFFA-CA8231913039}"
Global Const $WV2_IID_CNTLOADARGS = "{0C8A1275-9B6B-4901-87AD-70DF25BAFA6E}"
Global Const $WV2_IID_SRCCHGARGS = "{31E0E545-1DBA-4266-8914-F63848A1F7D7}"
Global Const $WV2_IID_DOMCBARGS = "{16B1E21A-C503-44F2-84C9-70ABA5031283}"

; The extensions lot. Profile7 is the version of the profile that carries AddBrowserExtension and
; GetBrowserExtensions; the four handler IIDs are the interfaces the fake sinks of slots 40 to 43 claim,
; and the last two are the objects the list handler and GetValueAtIndex answer with. Every value was
; read from the SDK header, not from the documentation pages.
Global Const $WV2_IID_PROFILE7 = "{7B4C7906-A1AA-4CB4-B723-DB09F813D541}"
Global Const $WV2_IID_EXTADDH = "{DF1AAB27-82B9-4AB6-AAE8-017A49398C14}"
Global Const $WV2_IID_EXTGETH = "{FCE16A1C-F107-4601-8B75-FC4940AE25D0}"
Global Const $WV2_IID_EXTREMOVEH = "{8E41909A-9B18-4BB1-8CDF-930F467A50BE}"
Global Const $WV2_IID_EXTENABLEH = "{30C186CE-7FAD-421F-A3BC-A8EAF071DDB8}"
Global Const $WV2_IID_BREXT = "{7EF7FFA0-FAC5-462C-B189-3D9EDBE575DA}"
Global Const $WV2_IID_BREXTLIST = "{2EF3D2DC-BD5F-4F4D-90AF-FD67798F0C2F}"
; The options lot. The six IIDs the hand-built options object answers for: the runtime asks for each of
; them in turn and reads only the ones it gets, so an object that carries the scalar properties and
; refuses the two array ones is enough to reach every option this UDF exposes. Settings2 is the version
; of the settings that holds the user agent.
Global Const $WV2_IID_OPTB = "{2FDE08A8-1E9A-4766-8C05-95A9CEB9D1C5}"
Global Const $WV2_IID_OPT2 = "{FF85C98A-1BA7-4A6B-90C8-2B752C89E9E2}"
Global Const $WV2_IID_OPT3 = "{4A5C436E-A9E3-4A2E-89C3-910D3513F5CC}"
Global Const $WV2_IID_OPT5 = "{0AE35D64-C47F-4464-814E-259C345D1501}"
Global Const $WV2_IID_OPT6 = "{57D29CC3-C84F-42A0-B0E2-EFFBD5E179DE}"
Global Const $WV2_IID_OPT8 = "{7C7ECF51-E918-5CAF-853C-E9A2BCC27775}"
Global Const $WV2_IID_SET2 = "{EE9A0F68-F46C-4E32-AC23-EF8CAC224D2A}"

; Event types reported through _WV2_GetEvent and _WV2_WaitEvent
Global Const $WV2_EVENT_NAVIGATION_STARTING = 1        ; $sData = uri, $iValue = 1 if user initiated
Global Const $WV2_EVENT_NAVIGATION_COMPLETED = 2       ; $sData = uri, $iValue = 1 success / web error id
Global Const $WV2_EVENT_WEB_MESSAGE = 3                ; $sData = message, $iValue = 1 plain / 0 json
Global Const $WV2_EVENT_NEW_WINDOW = 4                 ; $sData = uri the page tried to open
Global Const $WV2_EVENT_TITLE_CHANGED = 5              ; $sData = new title
Global Const $WV2_EVENT_HISTORY_CHANGED = 6            ; back or forward availability changed
Global Const $WV2_EVENT_PROCESS_FAILED = 7             ; $iValue = a $WV2_PROCFAIL_* code
Global Const $WV2_EVENT_DOWNLOAD_STARTING = 8          ; $sData = uri, $iValue = 1 refused / 0 accepted
Global Const $WV2_EVENT_RESOURCE_REQUESTED = 9         ; $sData = uri, $iValue = 1 answered / 0 let through / 2 handler failed
Global Const $WV2_EVENT_FIND = 10                      ; $sData = match count, $iValue = active match index (0 based, -1 none)
Global Const $WV2_EVENT_DOWNLOAD_STATE = 11            ; $sData = uri, $iValue = a $WV2_DL_* state
Global Const $WV2_EVENT_DOWNLOAD_PROGRESS = 12         ; $sData = "received/total", $iValue = download index
Global Const $WV2_EVENT_SCRIPT_DIALOG = 13             ; $sData = message, $iValue = a $WV2_DIALOG_* kind
Global Const $WV2_EVENT_ACCELERATOR = 14               ; $sData = virtual key, $iValue = a $WV2_KEYEVENT_* kind
Global Const $WV2_EVENT_CONTEXT_MENU = 15              ; $sData = "", $iValue = the command id the handler answered with, -1 for none
Global Const $WV2_EVENT_FAVICON_CHANGED = 16           ; $sData = favicon uri
Global Const $WV2_EVENT_DEVTOOLS = 17                  ; $sData = parameters as JSON
Global Const $WV2_EVENT_PLAYING_AUDIO_CHANGED = 18     ; $iValue = 1 an audible sound is playing, 0 none is
Global Const $WV2_EVENT_MUTED_CHANGED = 19             ; $iValue = 1 the view is muted, 0 it is not
Global Const $WV2_EVENT_FULLSCREEN_CHANGED = 20        ; $iValue = 1 an element of the page is in full screen, 0 none is
Global Const $WV2_EVENT_PERMISSION_REQUESTED = 21      ; $sData = origin uri, $iValue = a $WV2_PERM_* kind
Global Const $WV2_EVENT_CONTENT_LOADING = 22           ; $sData = uri being shown, $iValue = 1 an error page / 0 the document itself
Global Const $WV2_EVENT_SOURCE_CHANGED = 23            ; $sData = new uri, $iValue = 1 a new document / 0 the same document moved
Global Const $WV2_EVENT_DOM_CONTENT_LOADED = 24        ; $sData = uri, $iValue = the navigation id shared with its NavigationCompleted
Global Const $WV2_EVENT_WINDOW_CLOSE = 25              ; $sData = uri of the document that called window.close(), $iValue = 0

; What the page asked for (COREWEBVIEW2_PERMISSION_KIND). The list is the one of the SDK header, in its
; order: the number is what the runtime reports, so it is never chosen by the host.
Global Const $WV2_PERM_UNKNOWN = 0
Global Const $WV2_PERM_MICROPHONE = 1
Global Const $WV2_PERM_CAMERA = 2
Global Const $WV2_PERM_GEOLOCATION = 3
Global Const $WV2_PERM_NOTIFICATIONS = 4
Global Const $WV2_PERM_OTHER_SENSORS = 5
Global Const $WV2_PERM_CLIPBOARD_READ = 6
Global Const $WV2_PERM_MULTIPLE_DOWNLOADS = 7
Global Const $WV2_PERM_FILE_READ_WRITE = 8
Global Const $WV2_PERM_AUTOPLAY = 9
Global Const $WV2_PERM_LOCAL_FONTS = 10
Global Const $WV2_PERM_MIDI_SYSEX = 11
Global Const $WV2_PERM_WINDOW_MANAGEMENT = 12
Global Const $WV2_PERM_PERSISTENT_STORAGE = 13
Global Const $__WV2_PERM_KIND_MAX = 13              ; the highest kind this UDF can store a policy for

; What the host answers a request with. The three first are the states of the runtime
; (COREWEBVIEW2_PERMISSION_STATE); $WV2_PERM_ASK is only a policy, it is never handed to the runtime:
; it means the request waits in the queue until _WV2_PermissionRespond gives one of the three states.
Global Const $WV2_PERM_DEFAULT = 0
Global Const $WV2_PERM_ALLOW = 1
Global Const $WV2_PERM_DENY = 2
Global Const $WV2_PERM_ASK = 3
Global Const $WV2_PERM_MAX = 8                    ; requests kept waiting at one time per view

; Cookie SameSite policies (COREWEBVIEW2_COOKIE_SAME_SITE_KIND)
Global Const $WV2_COOKIE_SAMESITE_NONE = 0
Global Const $WV2_COOKIE_SAMESITE_LAX = 1
Global Const $WV2_COOKIE_SAMESITE_STRICT = 2

; Print settings that take a choice rather than a number
Global Const $WV2_PRINT_PORTRAIT = 0
Global Const $WV2_PRINT_LANDSCAPE = 1
Global Const $WV2_PRINT_UI_BROWSER = 0                 ; COREWEBVIEW2_PRINT_DIALOG_KIND
Global Const $WV2_PRINT_UI_SYSTEM = 1
Global Const $WV2_PRINT_SETTINGS_MAX = 8               ; live settings objects at once

; Download states (COREWEBVIEW2_DOWNLOAD_STATE)
Global Const $WV2_DL_IN_PROGRESS = 0
Global Const $WV2_DL_INTERRUPTED = 1
Global Const $WV2_DL_COMPLETED = 2
Global Const $WV2_DL_MAX = 8                           ; downloads remembered per view

; Kinds of script dialog (COREWEBVIEW2_SCRIPT_DIALOG_KIND)
Global Const $WV2_DIALOG_ALERT = 0
Global Const $WV2_DIALOG_CONFIRM = 1
Global Const $WV2_DIALOG_PROMPT = 2
Global Const $WV2_DIALOG_BEFORE_UNLOAD = 3

; Kinds of key event (COREWEBVIEW2_KEY_EVENT_KIND)
Global Const $WV2_KEYEVENT_DOWN = 0
Global Const $WV2_KEYEVENT_UP = 1
Global Const $WV2_KEYEVENT_SYS_DOWN = 2
Global Const $WV2_KEYEVENT_SYS_UP = 3

; Profiles cleared by _WV2_ClearBrowsingData (COREWEBVIEW2_BROWSING_DATA_KINDS, bit flags)
Global Const $WV2_DATA_BROWSING_HISTORY = 1
Global Const $WV2_DATA_DOWNLOADS = 2
Global Const $WV2_DATA_COOKIES = 4
Global Const $WV2_DATA_CACHE = 8
Global Const $WV2_DATA_ALL = 15

; Favicon formats (COREWEBVIEW2_FAVICON_IMAGE_FORMAT)
Global Const $WV2_FAVICON_PNG = 0
Global Const $WV2_FAVICON_JPEG = 1

; Process failure kinds, COREWEBVIEW2_PROCESS_FAILED_KIND
Global Const $WV2_PROCFAIL_BROWSER = 0
Global Const $WV2_PROCFAIL_RENDER_EXITED = 1
Global Const $WV2_PROCFAIL_RENDER_UNRESPONSIVE = 2
Global Const $WV2_PROCFAIL_FRAME_RENDER_EXITED = 3
Global Const $WV2_PROCFAIL_UTILITY_EXITED = 4
Global Const $WV2_PROCFAIL_SANDBOX_HELPER_EXITED = 5
Global Const $WV2_PROCFAIL_GPU_EXITED = 6
Global Const $WV2_PROCFAIL_PPAPI_PLUGIN_EXITED = 7
Global Const $WV2_PROCFAIL_PPAPI_BROKER_EXITED = 8
Global Const $WV2_PROCFAIL_UNKNOWN_EXITED = 9

; Image formats accepted by _WV2_CapturePreview
Global Const $WV2_IMAGE_PNG = 0
Global Const $WV2_IMAGE_JPEG = 1

; Colour scheme a page is told to prefer (COREWEBVIEW2_PREFERRED_COLOR_SCHEME). AUTO is what the runtime
; answers before anything has been set: the page follows the system. LIGHT and DARK are a promise the
; host makes for every page of that profile, whatever the system says.
Global Const $WV2_SCHEME_AUTO = 0
Global Const $WV2_SCHEME_LIGHT = 1
Global Const $WV2_SCHEME_DARK = 2
Global Const $__WV2_SCHEME_MAX = 2

; Scrollbars every page of the environment gets (COREWEBVIEW2_SCROLLBAR_STYLE). This one is an option of
; the environment, not of a view: it is read when the browser process starts, which is why the only way
; to see it is to ask before _WV2_Create.
Global Const $WV2_SCROLLBAR_DEFAULT = 0
Global Const $WV2_SCROLLBAR_FLUENT_OVERLAY = 1
Global Const $__WV2_SCROLLBAR_MAX = 1

; Access a page gets to the folder mapped by _WV2_SetVirtualHostNameToFolderMapping
; (COREWEBVIEW2_HOST_RESOURCE_ACCESS_KIND)
Global Const $WV2_HOST_DENY = 0
Global Const $WV2_HOST_ALLOW = 1
Global Const $WV2_HOST_DENY_CORS = 2

; Kinds of request a filter added by _WV2_AddResourceFilter catches
; (COREWEBVIEW2_WEB_RESOURCE_CONTEXT). ALL is the one to use when the handler decides by URI alone.
Global Const $WV2_RES_ALL = 0
Global Const $WV2_RES_DOCUMENT = 1
Global Const $WV2_RES_STYLESHEET = 2
Global Const $WV2_RES_IMAGE = 3
Global Const $WV2_RES_MEDIA = 4
Global Const $WV2_RES_FONT = 5
Global Const $WV2_RES_SCRIPT = 6
Global Const $WV2_RES_XHR = 7
Global Const $WV2_RES_FETCH = 8
Global Const $WV2_RES_TEXT_TRACK = 9
Global Const $WV2_RES_EVENT_SOURCE = 10
Global Const $WV2_RES_WEBSOCKET = 11
Global Const $WV2_RES_MANIFEST = 12
Global Const $WV2_RES_SIGNED_EXCHANGE = 13
Global Const $WV2_RES_PING = 14
Global Const $WV2_RES_CSP_REPORT = 15
Global Const $WV2_RES_OTHER = 16

; 10 s, not 5 s: a getBoundingClientRect or other script round-trip was measured
; timing out under load at 5 s, so the call failed while the page was still fine.
Global Const $WV2_EXEC_TIMEOUT = 10000
Global Const $WV2_PRINT_TIMEOUT = 30000

; Internal constants
Global Const $__WV2_MAX = 16
Global Const $__WV2_PTRS_PER_BLOCK = 5            ; 4 vtable slots + 1 object pointer
Global Const $__WV2_HR_E_NOINTERFACE = 0x80004002
Global Const $__WV2_HR_E_FAIL = 0x80004005         ; returned when a raw call could not even be made
Global Const $__WV2_CLSID_KEY = "Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
Global Const $__WV2_DLL_NAME = "EmbeddedBrowserWebView.dll"
Global Const $__WV2_QCAP = 64                     ; events kept per instance before they are dropped

; DWMWA_USE_IMMERSIVE_DARK_MODE, the attribute _WV2_SetDarkTitleBar hands to DwmSetWindowAttribute. It
; is published as 20, but the builds between 17763 and 18362 only answer to 19, the same thing under the
; number it carried before it was published; a build that knows neither returns an HRESULT this UDF
; reports instead of swallowing.
Global Const $__WV2_DWM_DARK_MODE = 20
Global Const $__WV2_DWM_DARK_MODE_OLD = 19

; Handler slots. One fake COM object is laid out per (instance, slot), which is what lets a single
; set of shared callbacks serve every view: the this-pointer gives back both the instance and the slot.
Global Const $__WV2_H_ENV = 1                     ; environment created
Global Const $__WV2_H_CTL = 2                     ; controller created
Global Const $__WV2_H_NAVC = 3                    ; NavigationCompleted
Global Const $__WV2_H_NAVS = 4                    ; NavigationStarting
Global Const $__WV2_H_MSG = 5                     ; WebMessageReceived
Global Const $__WV2_H_NEW = 6                     ; NewWindowRequested
Global Const $__WV2_H_TITLE = 7                   ; DocumentTitleChanged
Global Const $__WV2_H_HIST = 8                    ; HistoryChanged
Global Const $__WV2_H_PROC = 9                    ; ProcessFailed
Global Const $__WV2_H_EXEC = 10                   ; ExecuteScript answer
Global Const $__WV2_H_ADDSCRIPT = 11              ; AddScriptToExecuteOnDocumentCreated answer
Global Const $__WV2_H_CAP = 12                    ; CapturePreview answer
Global Const $__WV2_H_PRINT = 13                  ; PrintToPdf answer
Global Const $__WV2_H_DOWNLOAD = 14               ; DownloadStarting
Global Const $__WV2_H_RESOURCE = 15               ; WebResourceRequested
Global Const $__WV2_H_FINDIDX = 16                ; Find ActiveMatchIndexChanged
Global Const $__WV2_H_FINDCNT = 17                ; Find MatchCountChanged
Global Const $__WV2_H_FINDSTART = 18              ; Find Start answer
Global Const $__WV2_H_EXECRES = 19                ; ExecuteScriptWithResult answer
Global Const $__WV2_H_COOKIES = 20                ; GetCookies answer
Global Const $__WV2_H_PROFILE = 21                ; ClearBrowsingData answer
Global Const $__WV2_H_PDFSTREAM = 22              ; PrintToPdfStream answer
Global Const $__WV2_H_DLSTATE = 23                ; Download StateChanged
Global Const $__WV2_H_DLPROG = 24                 ; Download BytesReceivedChanged
Global Const $__WV2_H_DIALOG = 25                 ; ScriptDialogOpening
Global Const $__WV2_H_ACCEL = 26                  ; AcceleratorKeyPressed
Global Const $__WV2_H_CTXMENU = 27                ; ContextMenuRequested
Global Const $__WV2_H_FAVICON = 28                ; FaviconChanged
Global Const $__WV2_H_FAVICONGET = 29             ; GetFavicon answer
Global Const $__WV2_H_CDPCALL = 30                ; CallDevToolsProtocolMethod answer
Global Const $__WV2_H_CDPEVT = 31                 ; DevToolsProtocolEventReceived
Global Const $__WV2_H_AUDIO = 32                  ; IsDocumentPlayingAudioChanged
Global Const $__WV2_H_MUTED = 33                  ; IsMutedChanged
Global Const $__WV2_H_FULLSCREEN = 34             ; ContainsFullScreenElementChanged
Global Const $__WV2_H_PERMISSION = 35             ; PermissionRequested
Global Const $__WV2_H_CNTLOAD = 36                ; ContentLoading
Global Const $__WV2_H_SRCCHG = 37                 ; SourceChanged
Global Const $__WV2_H_DOMCONTENT = 38             ; DOMContentLoaded
Global Const $__WV2_H_WINCLOSE = 39               ; WindowCloseRequested
; The four operations of the extensions lot. Add and Get answer with a COM object - the extension that
; was just added, and the list of the ones the profile holds - so their Invoke carries three arguments
; like the cookie and stream handlers above; Remove and Enable answer with an HRESULT alone.
Global Const $__WV2_H_EXTADD = 40                 ; AddBrowserExtension answer
Global Const $__WV2_H_EXTGET = 41                 ; GetBrowserExtensions answer
Global Const $__WV2_H_EXTREMOVE = 42              ; BrowserExtension::Remove answer
Global Const $__WV2_H_EXTENABLE = 43              ; BrowserExtension::Enable answer
Global Const $__WV2_SLOT_COUNT = 43

; Vtable slots of the methods called raw through QueryInterface. Every number below was read from the
; official WebView2.h (SDK 1.0.4314.35) by Tools\gen_interfaces.py, never counted by hand: slot 0 is
; QueryInterface, slot 3 is the first method the interface itself declares. After an SDK update,
; "python Tools\gen_interfaces.py --header <WebView2.h> --audit WebView2.au3" re-checks every line.
Global Const $__WV2_SLOT_IUnknown_QueryInterface = 0
Global Const $__WV2_SLOT_IUnknown_Release = 2
Global Const $__WV2_SLOT_IStream_Read = 3
Global Const $__WV2_SLOT_IStream_Seek = 5
Global Const $__WV2_SEEK_SET = 0                       ; STREAM_SEEK_SET, the values IStream::Seek speaks
Global Const $__WV2_SEEK_END = 2                       ; STREAM_SEEK_END
Global Const $__WV2_STREAM_CHUNK = 1048576             ; one megabyte per IStream::Read round
Global Const $__WV2_SLOT_ICoreWebView2Environment_CreateWebResourceResponse = 4
Global Const $__WV2_SLOT_ICoreWebView2_add_WebResourceRequested = 55
Global Const $__WV2_SLOT_ICoreWebView2_remove_WebResourceRequested = 56
Global Const $__WV2_SLOT_ICoreWebView2_AddWebResourceRequestedFilter = 57
Global Const $__WV2_SLOT_ICoreWebView2_RemoveWebResourceRequestedFilter = 58
; Full-screen lot: the three methods ICoreWebView2 declares between OpenDevToolsWindow (51) and
; add_WebResourceRequested (55). They sit past get_DocumentTitle (48), the end of the wrapper tag.
Global Const $__WV2_SLOT_ICoreWebView2_add_ContainsFullScreenElementChanged = 52
Global Const $__WV2_SLOT_ICoreWebView2_remove_ContainsFullScreenElementChanged = 53
Global Const $__WV2_SLOT_ICoreWebView2_get_ContainsFullScreenElement = 54
; WindowCloseRequested is the base interface's own method again, past add_WebResourceRequestedFilter
; (57). The three getters of the arguments objects that come with it are the only methods those
; interfaces declare, so their slots are 3 and 4 counting from QueryInterface.
Global Const $__WV2_SLOT_ICoreWebView2_add_WindowCloseRequested = 59
Global Const $__WV2_SLOT_ICoreWebView2_remove_WindowCloseRequested = 60
Global Const $__WV2_SLOT_ICoreWebView2_get_Source = 4
Global Const $__WV2_SLOT_ICoreWebView2ContentLoadingEventArgs_get_IsErrorPage = 3
Global Const $__WV2_SLOT_ICoreWebView2ContentLoadingEventArgs_get_NavigationId = 4
Global Const $__WV2_SLOT_ICoreWebView2SourceChangedEventArgs_get_IsNewDocument = 3
Global Const $__WV2_SLOT_ICoreWebView2DOMContentLoadedEventArgs_get_NavigationId = 3
; DOMContentLoaded is the second method ICoreWebView2_2 adds of its own: the version repeats the whole
; base layout (0..60, WindowCloseRequested last) and only then declares
; add_WebResourceResponseReceived (61), remove_ (62) and NavigateWithWebResourceRequest (63). It is
; reached through the _2 pointer, the base one does not carry it.
Global Const $__WV2_SLOT_ICoreWebView2_2_add_DOMContentLoaded = 64
Global Const $__WV2_SLOT_ICoreWebView2_2_remove_DOMContentLoaded = 65
Global Const $__WV2_SLOT_ICoreWebView2_2_get_CookieManager = 66
Global Const $__WV2_SLOT_ICoreWebView2_3_SetVirtualHostNameToFolderMapping = 71
Global Const $__WV2_SLOT_ICoreWebView2_3_ClearVirtualHostNameToFolderMapping = 72
Global Const $__WV2_SLOT_ICoreWebView2_4_add_DownloadStarting = 75
Global Const $__WV2_SLOT_ICoreWebView2_4_remove_DownloadStarting = 76
Global Const $__WV2_SLOT_ICoreWebView2_7_PrintToPdf = 80
Global Const $__WV2_SLOT_ICoreWebView2Controller_put_Bounds = 6
Global Const $__WV2_SLOT_ICoreWebView2CookieManager_DeleteAllCookies = 10
Global Const $__WV2_SLOT_ICoreWebView2DownloadStartingEventArgs_get_DownloadOperation = 3
Global Const $__WV2_SLOT_ICoreWebView2DownloadStartingEventArgs_put_Cancel = 5
Global Const $__WV2_SLOT_ICoreWebView2DownloadStartingEventArgs_get_ResultFilePath = 6
Global Const $__WV2_SLOT_ICoreWebView2DownloadStartingEventArgs_put_ResultFilePath = 7
Global Const $__WV2_SLOT_ICoreWebView2DownloadOperation_get_Uri = 9
Global Const $__WV2_SLOT_ICoreWebView2WebResourceRequestedEventArgs_get_Request = 3
Global Const $__WV2_SLOT_ICoreWebView2WebResourceRequestedEventArgs_put_Response = 5
Global Const $__WV2_SLOT_ICoreWebView2WebResourceRequest_get_Uri = 3
Global Const $__WV2_SLOT_ICoreWebView2WebResourceRequest_get_Method = 5
Global Const $__WV2_SLOT_ICoreWebView2WebResourceRequest_get_Headers = 9
Global Const $__WV2_SLOT_ICoreWebView2HttpRequestHeaders_GetIterator = 8
Global Const $__WV2_SLOT_ICoreWebView2HttpHeadersCollectionIterator_GetCurrentHeader = 3
Global Const $__WV2_SLOT_ICoreWebView2HttpHeadersCollectionIterator_get_HasCurrentHeader = 4
Global Const $__WV2_SLOT_ICoreWebView2HttpHeadersCollectionIterator_MoveNext = 5
; Lot 2. Same rule: every number below comes from WebView2.h by Tools\gen_interfaces.py.
Global Const $__WV2_SLOT_ICoreWebView2_add_ScriptDialogOpening = 21
Global Const $__WV2_SLOT_ICoreWebView2_remove_ScriptDialogOpening = 22
Global Const $__WV2_SLOT_ICoreWebView2_CallDevToolsProtocolMethod = 36
Global Const $__WV2_SLOT_ICoreWebView2_GetDevToolsProtocolEventReceiver = 42
Global Const $__WV2_SLOT_ICoreWebView2_11_add_ContextMenuRequested = 100
Global Const $__WV2_SLOT_ICoreWebView2_11_remove_ContextMenuRequested = 101
Global Const $__WV2_SLOT_ICoreWebView2_13_get_Profile = 105
Global Const $__WV2_SLOT_ICoreWebView2_15_add_FaviconChanged = 109
Global Const $__WV2_SLOT_ICoreWebView2_15_remove_FaviconChanged = 110
Global Const $__WV2_SLOT_ICoreWebView2_15_get_FaviconUri = 111
Global Const $__WV2_SLOT_ICoreWebView2_15_GetFavicon = 112
Global Const $__WV2_SLOT_ICoreWebView2_16_Print = 113
Global Const $__WV2_SLOT_ICoreWebView2_16_ShowPrintUI = 114
Global Const $__WV2_SLOT_ICoreWebView2_16_PrintToPdfStream = 115
Global Const $__WV2_SLOT_ICoreWebView2_21_ExecuteScriptWithResult = 122
Global Const $__WV2_SLOT_ICoreWebView2_28_get_Find = 135
Global Const $__WV2_SLOT_ICoreWebView2Controller3_add_AcceleratorKeyPressed = 19
Global Const $__WV2_SLOT_ICoreWebView2Controller3_remove_AcceleratorKeyPressed = 20
Global Const $__WV2_SLOT_ICoreWebView2Environment6_CreatePrintSettings = 14
Global Const $__WV2_SLOT_ICoreWebView2Environment15_CreateFindOptions = 29
Global Const $__WV2_SLOT_ICoreWebView2Find_get_ActiveMatchIndex = 3
Global Const $__WV2_SLOT_ICoreWebView2Find_get_MatchCount = 4
Global Const $__WV2_SLOT_ICoreWebView2Find_add_ActiveMatchIndexChanged = 5
Global Const $__WV2_SLOT_ICoreWebView2Find_remove_ActiveMatchIndexChanged = 6
Global Const $__WV2_SLOT_ICoreWebView2Find_add_MatchCountChanged = 7
Global Const $__WV2_SLOT_ICoreWebView2Find_remove_MatchCountChanged = 8
Global Const $__WV2_SLOT_ICoreWebView2Find_Start = 9
Global Const $__WV2_SLOT_ICoreWebView2Find_FindNext = 10
Global Const $__WV2_SLOT_ICoreWebView2Find_FindPrevious = 11
Global Const $__WV2_SLOT_ICoreWebView2Find_Stop = 12
Global Const $__WV2_SLOT_ICoreWebView2FindOptions_put_FindTerm = 4
Global Const $__WV2_SLOT_ICoreWebView2FindOptions_put_IsCaseSensitive = 6
Global Const $__WV2_SLOT_ICoreWebView2FindOptions_put_ShouldHighlightAllMatches = 8
Global Const $__WV2_SLOT_ICoreWebView2FindOptions_put_ShouldMatchWord = 10
Global Const $__WV2_SLOT_ICoreWebView2FindOptions_put_SuppressDefaultFindDialog = 12
Global Const $__WV2_SLOT_ICoreWebView2ExecuteScriptResult_get_Succeeded = 3
Global Const $__WV2_SLOT_ICoreWebView2ExecuteScriptResult_get_ResultAsJson = 4
Global Const $__WV2_SLOT_ICoreWebView2ExecuteScriptResult_TryGetResultAsString = 5
Global Const $__WV2_SLOT_ICoreWebView2ExecuteScriptResult_get_Exception = 6
Global Const $__WV2_SLOT_ICoreWebView2ScriptException_get_LineNumber = 3
Global Const $__WV2_SLOT_ICoreWebView2ScriptException_get_ColumnNumber = 4
Global Const $__WV2_SLOT_ICoreWebView2ScriptException_get_Name = 5
Global Const $__WV2_SLOT_ICoreWebView2ScriptException_get_Message = 6
Global Const $__WV2_SLOT_ICoreWebView2CookieManager_CreateCookie = 3
Global Const $__WV2_SLOT_ICoreWebView2CookieManager_GetCookies = 5
Global Const $__WV2_SLOT_ICoreWebView2CookieManager_AddOrUpdateCookie = 6
Global Const $__WV2_SLOT_ICoreWebView2CookieManager_DeleteCookies = 8
Global Const $__WV2_SLOT_ICoreWebView2Cookie_get_Name = 3
Global Const $__WV2_SLOT_ICoreWebView2Cookie_get_Value = 4
Global Const $__WV2_SLOT_ICoreWebView2Cookie_put_Value = 5
Global Const $__WV2_SLOT_ICoreWebView2Cookie_get_Domain = 6
Global Const $__WV2_SLOT_ICoreWebView2Cookie_get_Path = 7
Global Const $__WV2_SLOT_ICoreWebView2Cookie_get_Expires = 8
Global Const $__WV2_SLOT_ICoreWebView2Cookie_put_Expires = 9
Global Const $__WV2_SLOT_ICoreWebView2Cookie_get_IsHttpOnly = 10
Global Const $__WV2_SLOT_ICoreWebView2Cookie_put_IsHttpOnly = 11
Global Const $__WV2_SLOT_ICoreWebView2Cookie_get_SameSite = 12
Global Const $__WV2_SLOT_ICoreWebView2Cookie_put_SameSite = 13
Global Const $__WV2_SLOT_ICoreWebView2Cookie_get_IsSecure = 14
Global Const $__WV2_SLOT_ICoreWebView2Cookie_put_IsSecure = 15
Global Const $__WV2_SLOT_ICoreWebView2Cookie_get_IsSession = 16
Global Const $__WV2_SLOT_ICoreWebView2CookieList_get_Count = 3
Global Const $__WV2_SLOT_ICoreWebView2CookieList_GetValueAtIndex = 4
Global Const $__WV2_SLOT_ICoreWebView2PrintSettings_get_Orientation = 3
Global Const $__WV2_SLOT_ICoreWebView2PrintSettings_put_Orientation = 4
Global Const $__WV2_SLOT_ICoreWebView2PrintSettings_get_ScaleFactor = 5
Global Const $__WV2_SLOT_ICoreWebView2PrintSettings_put_ScaleFactor = 6
Global Const $__WV2_SLOT_ICoreWebView2PrintSettings_get_PageWidth = 7
Global Const $__WV2_SLOT_ICoreWebView2PrintSettings_put_PageWidth = 8
Global Const $__WV2_SLOT_ICoreWebView2PrintSettings_get_PageHeight = 9
Global Const $__WV2_SLOT_ICoreWebView2PrintSettings_put_PageHeight = 10
Global Const $__WV2_SLOT_ICoreWebView2PrintSettings_get_MarginTop = 11
Global Const $__WV2_SLOT_ICoreWebView2PrintSettings_put_MarginTop = 12
Global Const $__WV2_SLOT_ICoreWebView2PrintSettings_get_MarginBottom = 13
Global Const $__WV2_SLOT_ICoreWebView2PrintSettings_put_MarginBottom = 14
Global Const $__WV2_SLOT_ICoreWebView2PrintSettings_get_MarginLeft = 15
Global Const $__WV2_SLOT_ICoreWebView2PrintSettings_put_MarginLeft = 16
Global Const $__WV2_SLOT_ICoreWebView2PrintSettings_get_MarginRight = 17
Global Const $__WV2_SLOT_ICoreWebView2PrintSettings_put_MarginRight = 18
Global Const $__WV2_SLOT_ICoreWebView2PrintSettings_get_ShouldPrintBackgrounds = 19
Global Const $__WV2_SLOT_ICoreWebView2PrintSettings_put_ShouldPrintBackgrounds = 20
Global Const $__WV2_SLOT_ICoreWebView2PrintSettings_get_ShouldPrintSelectionOnly = 21
Global Const $__WV2_SLOT_ICoreWebView2PrintSettings_put_ShouldPrintSelectionOnly = 22
Global Const $__WV2_SLOT_ICoreWebView2PrintSettings_get_ShouldPrintHeaderAndFooter = 23
Global Const $__WV2_SLOT_ICoreWebView2PrintSettings_put_ShouldPrintHeaderAndFooter = 24
Global Const $__WV2_SLOT_ICoreWebView2PrintSettings_get_HeaderTitle = 25
Global Const $__WV2_SLOT_ICoreWebView2PrintSettings_put_HeaderTitle = 26
Global Const $__WV2_SLOT_ICoreWebView2PrintSettings_get_FooterUri = 27
Global Const $__WV2_SLOT_ICoreWebView2PrintSettings_put_FooterUri = 28
Global Const $__WV2_SLOT_ICoreWebView2Profile2_ClearBrowsingData = 10
Global Const $__WV2_SLOT_ICoreWebView2DownloadOperation_add_BytesReceivedChanged = 3
Global Const $__WV2_SLOT_ICoreWebView2DownloadOperation_remove_BytesReceivedChanged = 4
Global Const $__WV2_SLOT_ICoreWebView2DownloadOperation_add_StateChanged = 7
Global Const $__WV2_SLOT_ICoreWebView2DownloadOperation_remove_StateChanged = 8
Global Const $__WV2_SLOT_ICoreWebView2DownloadOperation_get_TotalBytesToReceive = 12
Global Const $__WV2_SLOT_ICoreWebView2DownloadOperation_get_BytesReceived = 13
Global Const $__WV2_SLOT_ICoreWebView2DownloadOperation_get_EstimatedEndTime = 14
Global Const $__WV2_SLOT_ICoreWebView2DownloadOperation_get_ResultFilePath = 15
Global Const $__WV2_SLOT_ICoreWebView2DownloadOperation_get_State = 16
Global Const $__WV2_SLOT_ICoreWebView2DownloadOperation_get_InterruptReason = 17
Global Const $__WV2_SLOT_ICoreWebView2DownloadOperation_Cancel = 18
Global Const $__WV2_SLOT_ICoreWebView2DownloadOperation_Pause = 19
Global Const $__WV2_SLOT_ICoreWebView2DownloadOperation_Resume = 20
Global Const $__WV2_SLOT_ICoreWebView2DownloadOperation_get_CanResume = 21
Global Const $__WV2_SLOT_ICoreWebView2ScriptDialogOpeningEventArgs_get_Uri = 3
Global Const $__WV2_SLOT_ICoreWebView2ScriptDialogOpeningEventArgs_get_Kind = 4
Global Const $__WV2_SLOT_ICoreWebView2ScriptDialogOpeningEventArgs_get_Message = 5
Global Const $__WV2_SLOT_ICoreWebView2ScriptDialogOpeningEventArgs_Accept = 6
Global Const $__WV2_SLOT_ICoreWebView2ScriptDialogOpeningEventArgs_get_DefaultText = 7
Global Const $__WV2_SLOT_ICoreWebView2ScriptDialogOpeningEventArgs_put_ResultText = 9
Global Const $__WV2_SLOT_ICoreWebView2ContextMenuRequestedEventArgs_get_MenuItems = 3
Global Const $__WV2_SLOT_ICoreWebView2ContextMenuRequestedEventArgs_get_Location = 5
Global Const $__WV2_SLOT_ICoreWebView2ContextMenuRequestedEventArgs_put_SelectedCommandId = 6
Global Const $__WV2_SLOT_ICoreWebView2ContextMenuRequestedEventArgs_put_Handled = 8
Global Const $__WV2_SLOT_ICoreWebView2ContextMenuItem_get_Label = 4
Global Const $__WV2_SLOT_ICoreWebView2ContextMenuItem_get_CommandId = 5
Global Const $__WV2_SLOT_ICoreWebView2ContextMenuItem_get_Kind = 8
Global Const $__WV2_SLOT_ICoreWebView2ContextMenuItem_get_IsEnabled = 10
Global Const $__WV2_SLOT_ICoreWebView2ContextMenuItem_get_IsChecked = 12
Global Const $__WV2_SLOT_ICoreWebView2ContextMenuItemCollection_get_Count = 3
Global Const $__WV2_SLOT_ICoreWebView2ContextMenuItemCollection_GetValueAtIndex = 4
Global Const $__WV2_SLOT_ICoreWebView2AcceleratorKeyPressedEventArgs_get_KeyEventKind = 3
Global Const $__WV2_SLOT_ICoreWebView2AcceleratorKeyPressedEventArgs_get_VirtualKey = 4
Global Const $__WV2_SLOT_ICoreWebView2AcceleratorKeyPressedEventArgs_put_Handled = 8
Global Const $__WV2_SLOT_ICoreWebView2DevToolsProtocolEventReceiver_add_DevToolsProtocolEventReceived = 3
Global Const $__WV2_SLOT_ICoreWebView2DevToolsProtocolEventReceiver_remove_DevToolsProtocolEventReceived = 4
Global Const $__WV2_SLOT_ICoreWebView2DevToolsProtocolEventReceivedEventArgs_get_ParameterObjectAsJson = 3
; Audio lot: the seven methods ICoreWebView2_8 adds on top of _7, which stop at slot 80.
Global Const $__WV2_SLOT_ICoreWebView2_8_add_IsMutedChanged = 81
Global Const $__WV2_SLOT_ICoreWebView2_8_remove_IsMutedChanged = 82
Global Const $__WV2_SLOT_ICoreWebView2_8_get_IsMuted = 83
Global Const $__WV2_SLOT_ICoreWebView2_8_put_IsMuted = 84
Global Const $__WV2_SLOT_ICoreWebView2_8_add_IsDocumentPlayingAudioChanged = 85
Global Const $__WV2_SLOT_ICoreWebView2_8_remove_IsDocumentPlayingAudioChanged = 86
Global Const $__WV2_SLOT_ICoreWebView2_8_get_IsDocumentPlayingAudio = 87
; Permission lot: the arguments of PermissionRequested and the deferral it hands out. Both are called
; raw; the event itself (slot 23) is inside the wrapper tag, so only these numbers travel by vtable.
Global Const $__WV2_SLOT_ICoreWebView2PermissionRequestedEventArgs_get_Uri = 3
Global Const $__WV2_SLOT_ICoreWebView2PermissionRequestedEventArgs_get_PermissionKind = 4
Global Const $__WV2_SLOT_ICoreWebView2PermissionRequestedEventArgs_get_IsUserInitiated = 5
Global Const $__WV2_SLOT_ICoreWebView2PermissionRequestedEventArgs_get_State = 6
Global Const $__WV2_SLOT_ICoreWebView2PermissionRequestedEventArgs_put_State = 7
Global Const $__WV2_SLOT_ICoreWebView2PermissionRequestedEventArgs_GetDeferral = 8
Global Const $__WV2_SLOT_ICoreWebView2Deferral_Complete = 3
; Theme lot: the profile the view hands out, and the two colour slots of the controller. Generated from
; the SDK header, like every other number here. get_Profile itself is already declared above, with the
; numbers the browsing data call needed.
Global Const $__WV2_SLOT_ICoreWebView2Profile_get_DefaultDownloadFolderPath = 6
Global Const $__WV2_SLOT_ICoreWebView2Profile_put_DefaultDownloadFolderPath = 7
Global Const $__WV2_SLOT_ICoreWebView2Profile_get_PreferredColorScheme = 8
Global Const $__WV2_SLOT_ICoreWebView2Profile_put_PreferredColorScheme = 9
Global Const $__WV2_SLOT_ICoreWebView2Controller2_get_DefaultBackgroundColor = 26
Global Const $__WV2_SLOT_ICoreWebView2Controller2_put_DefaultBackgroundColor = 27
; Options lot. The user agent is a property of the settings, not of the environment, so it is reached
; through Settings2 on a live view. The eight slots of the base options interface are the four pairs the
; runtime reads first; each newer options interface adds its own pair at slot 3, which is why the numbers
; below repeat.
Global Const $__WV2_SLOT_ICoreWebView2Settings2_get_UserAgent = 21
Global Const $__WV2_SLOT_ICoreWebView2Settings2_put_UserAgent = 22
Global Const $__WV2_SLOT_ICoreWebView2EnvironmentOptions_get_AdditionalBrowserArguments = 3
Global Const $__WV2_SLOT_ICoreWebView2EnvironmentOptions_put_AdditionalBrowserArguments = 4
Global Const $__WV2_SLOT_ICoreWebView2EnvironmentOptions_get_Language = 5
Global Const $__WV2_SLOT_ICoreWebView2EnvironmentOptions_put_Language = 6
Global Const $__WV2_SLOT_ICoreWebView2EnvironmentOptions_get_TargetCompatibleBrowserVersion = 7
Global Const $__WV2_SLOT_ICoreWebView2EnvironmentOptions_put_TargetCompatibleBrowserVersion = 8
Global Const $__WV2_SLOT_ICoreWebView2EnvironmentOptions_get_AllowSingleSignOnUsingOSPrimaryAccount = 9
Global Const $__WV2_SLOT_ICoreWebView2EnvironmentOptions_put_AllowSingleSignOnUsingOSPrimaryAccount = 10
Global Const $__WV2_SLOT_ICoreWebView2EnvironmentOptions2_get_ExclusiveUserDataFolderAccess = 3
Global Const $__WV2_SLOT_ICoreWebView2EnvironmentOptions2_put_ExclusiveUserDataFolderAccess = 4
Global Const $__WV2_SLOT_ICoreWebView2EnvironmentOptions3_get_IsCustomCrashReportingEnabled = 3
Global Const $__WV2_SLOT_ICoreWebView2EnvironmentOptions3_put_IsCustomCrashReportingEnabled = 4
Global Const $__WV2_SLOT_ICoreWebView2EnvironmentOptions5_get_EnableTrackingPrevention = 3
Global Const $__WV2_SLOT_ICoreWebView2EnvironmentOptions5_put_EnableTrackingPrevention = 4
Global Const $__WV2_SLOT_ICoreWebView2EnvironmentOptions6_get_AreBrowserExtensionsEnabled = 3
Global Const $__WV2_SLOT_ICoreWebView2EnvironmentOptions6_put_AreBrowserExtensionsEnabled = 4
Global Const $__WV2_SLOT_ICoreWebView2EnvironmentOptions8_get_ScrollBarStyle = 3
Global Const $__WV2_SLOT_ICoreWebView2EnvironmentOptions8_put_ScrollBarStyle = 4
; Extensions lot. Profile6 stops at slot 21, so the two calls this UDF uses sit at 22 and 23; the numbers
; were produced by Tools\gen_interfaces.py from the SDK header, which walks the whole Profile chain.
Global Const $__WV2_SLOT_ICoreWebView2Profile7_AddBrowserExtension = 22
Global Const $__WV2_SLOT_ICoreWebView2Profile7_GetBrowserExtensions = 23
Global Const $__WV2_SLOT_ICoreWebView2BrowserExtension_get_Id = 3
Global Const $__WV2_SLOT_ICoreWebView2BrowserExtension_get_Name = 4
Global Const $__WV2_SLOT_ICoreWebView2BrowserExtension_Remove = 5
Global Const $__WV2_SLOT_ICoreWebView2BrowserExtension_get_IsEnabled = 6
Global Const $__WV2_SLOT_ICoreWebView2BrowserExtension_Enable = 7
Global Const $__WV2_SLOT_ICoreWebView2BrowserExtensionList_get_Count = 3
Global Const $__WV2_SLOT_ICoreWebView2BrowserExtensionList_GetValueAtIndex = 4
; Which newer version of ICoreWebView2 __WV2_ViewIf has to bring back.
Global Const $__WV2_IF_2 = 1
Global Const $__WV2_IF_3 = 2
Global Const $__WV2_IF_4 = 3
Global Const $__WV2_IF_7 = 4
Global Const $__WV2_IF_16 = 5
Global Const $__WV2_IF_21 = 6
Global Const $__WV2_IF_28 = 7
Global Const $__WV2_IF_8 = 8
Global Const $__WV2_IF_13 = 9
Global Const $__WV2_IF_MAX = 9

; Interface tags. Entry 1 maps to vtable slot 0 because every wrapper is built with flag = False.
; Method order and parameter types are those of the official WebView2.h.
Global Const $__WV2_TAG_IUNKNOWN = "QueryInterface hresult(ptr;ptr); AddRef dword(); Release dword(); "
Global Const $__WV2_TAG_ENV = $__WV2_TAG_IUNKNOWN & _
		"CreateCoreWebView2Controller hresult(ptr;ptr); CreateWebResourceResponse hresult(ptr;int;wstr;wstr;ptr); get_BrowserVersionString hresult(wstr*);"
Global Const $__WV2_TAG_CTL = $__WV2_TAG_IUNKNOWN & _
		"get_IsVisible hresult(int*); put_IsVisible hresult(int); get_Bounds hresult(struct*); put_Bounds hresult(long;long;long;long);" & _
		"get_ZoomFactor hresult(double*); put_ZoomFactor hresult(double); add_ZoomFactorChanged hresult(ptr;int64*); remove_ZoomFactorChanged hresult(int64);" & _
		"SetBoundsAndZoomFactor hresult(long;long;long;long;double); MoveFocus hresult(int); add_MoveFocusRequested hresult(ptr;int64*); remove_MoveFocusRequested hresult(int64);" & _
		"add_GotFocus hresult(ptr;int64*); remove_GotFocus hresult(int64); add_LostFocus hresult(ptr;int64*); remove_LostFocus hresult(int64);" & _
		"add_AcceleratorKeyPressed hresult(ptr;int64*); remove_AcceleratorKeyPressed hresult(int64); get_ParentWindow hresult(ptr*); put_ParentWindow hresult(ptr);" & _
		"NotifyParentWindowPositionChanged hresult(); Close hresult(); get_CoreWebView2 hresult(ptr*);"
Global Const $__WV2_TAG_WV = $__WV2_TAG_IUNKNOWN & _
		"get_Settings hresult(ptr*); get_Source hresult(wstr*); Navigate hresult(wstr); NavigateToString hresult(wstr);" & _
		"add_NavigationStarting hresult(ptr;int64*); remove_NavigationStarting hresult(int64);" & _
		"add_ContentLoading hresult(ptr;int64*); remove_ContentLoading hresult(int64);" & _
		"add_SourceChanged hresult(ptr;int64*); remove_SourceChanged hresult(int64);" & _
		"add_HistoryChanged hresult(ptr;int64*); remove_HistoryChanged hresult(int64);" & _
		"add_NavigationCompleted hresult(ptr;int64*); remove_NavigationCompleted hresult(int64);" & _
		"add_FrameNavigationStarting hresult(ptr;int64*); remove_FrameNavigationStarting hresult(int64);" & _
		"add_FrameNavigationCompleted hresult(ptr;int64*); remove_FrameNavigationCompleted hresult(int64);" & _
		"add_ScriptDialogOpening hresult(ptr;int64*); remove_ScriptDialogOpening hresult(int64);" & _
		"add_PermissionRequested hresult(ptr;int64*); remove_PermissionRequested hresult(int64);" & _
		"add_ProcessFailed hresult(ptr;int64*); remove_ProcessFailed hresult(int64);" & _
		"AddScriptToExecuteOnDocumentCreated hresult(wstr;ptr); RemoveScriptToExecuteOnDocumentCreated hresult(wstr);" & _
		"ExecuteScript hresult(wstr;ptr); CapturePreview hresult(dword;ptr;ptr); Reload hresult();" & _
		"PostWebMessageAsJson hresult(wstr); PostWebMessageAsString hresult(wstr);" & _
		"add_WebMessageReceived hresult(ptr;int64*); remove_WebMessageReceived hresult(int64);" & _
		"CallDevToolsProtocolMethod hresult(wstr;wstr;ptr); get_BrowserProcessId hresult(dword*);" & _
		"get_CanGoBack hresult(int*); get_CanGoForward hresult(int*); GoBack hresult(); GoForward hresult();" & _
		"GetDevToolsProtocolEventReceiver hresult(wstr;ptr*); Stop hresult();" & _
		"add_NewWindowRequested hresult(ptr;int64*); remove_NewWindowRequested hresult(int64);" & _
		"add_DocumentTitleChanged hresult(ptr;int64*); remove_DocumentTitleChanged hresult(int64);" & _
		"get_DocumentTitle hresult(wstr*);"
Global Const $__WV2_TAG_NAVARGS = $__WV2_TAG_IUNKNOWN & _
		"get_IsSuccess hresult(int*); get_WebErrorStatus hresult(dword*); get_NavigationId hresult(int64*);"
Global Const $__WV2_TAG_NAVSARGS = $__WV2_TAG_IUNKNOWN & _
		"get_Uri hresult(wstr*); get_IsUserInitiated hresult(int*); get_IsRedirected hresult(int*); get_RequestHeaders hresult(ptr*);" & _
		"get_Cancel hresult(int*); put_Cancel hresult(int); get_NavigationId hresult(int64*);"
Global Const $__WV2_TAG_MSGARGS = $__WV2_TAG_IUNKNOWN & _
		"get_Source hresult(wstr*); get_WebMessageAsJson hresult(wstr*); TryGetWebMessageAsString hresult(wstr*);"
Global Const $__WV2_TAG_NEWARGS = $__WV2_TAG_IUNKNOWN & _
		"get_Uri hresult(wstr*); put_NewWindow hresult(ptr); get_NewWindow hresult(ptr*); put_Handled hresult(int); get_Handled hresult(int*);" & _
		"get_IsUserInitiated hresult(int*); GetDeferral hresult(ptr*); get_WindowFeatures hresult(ptr*);"
Global Const $__WV2_TAG_PROCARGS = $__WV2_TAG_IUNKNOWN & _
		"get_ProcessFailedKind hresult(dword*);"
; The nine settings of this runtime version, in vtable order. All are BOOL, read with get_ and written with put_.
Global Const $__WV2_TAG_SETTINGS = $__WV2_TAG_IUNKNOWN & _
		"get_IsScriptEnabled hresult(int*); put_IsScriptEnabled hresult(int);" & _
		"get_IsWebMessageEnabled hresult(int*); put_IsWebMessageEnabled hresult(int);" & _
		"get_AreDefaultScriptDialogsEnabled hresult(int*); put_AreDefaultScriptDialogsEnabled hresult(int);" & _
		"get_IsStatusBarEnabled hresult(int*); put_IsStatusBarEnabled hresult(int);" & _
		"get_AreDevToolsEnabled hresult(int*); put_AreDevToolsEnabled hresult(int);" & _
		"get_AreDefaultContextMenusEnabled hresult(int*); put_AreDefaultContextMenusEnabled hresult(int);" & _
		"get_AreHostObjectsAllowed hresult(int*); put_AreHostObjectsAllowed hresult(int);" & _
		"get_IsZoomControlEnabled hresult(int*); put_IsZoomControlEnabled hresult(int);" & _
		"get_IsBuiltInErrorPageEnabled hresult(int*); put_IsBuiltInErrorPageEnabled hresult(int);"

; #VARIABLES# ===================================================================================================================
Global $__WV2_iLastError = $WV2_ERR_NONE
Global $__WV2_iLastHR = 0
Global $__WV2_sLastFunc = ""
Global $__WV2_iCoState = 0                            ; 1 once the UDF has initialised COM
Global $__WV2_iClientW = 0                            ; scratch client size of the parent window
Global $__WV2_iClientH = 0
Global $__WV2_iDpiLevel = -1                          ; what this process settled on, see _WV2_SetProcessDpiAware

; Instance table. Slot 0 is never used.
Global $__WV2_aUsed[$__WV2_MAX + 1]
Global $__WV2_oEnv[$__WV2_MAX + 1]
Global $__WV2_pEnv[$__WV2_MAX + 1]                  ; raw ICoreWebView2Environment pointer behind $__WV2_oEnv
Global $__WV2_oCtl[$__WV2_MAX + 1]
Global $__WV2_pCtl[$__WV2_MAX + 1]                  ; raw ICoreWebView2Controller pointer behind $__WV2_oCtl
Global $__WV2_oWv[$__WV2_MAX + 1]
Global $__WV2_pWv[$__WV2_MAX + 1]                  ; raw ICoreWebView2 pointer behind $__WV2_oWv
; The newer versions of ICoreWebView2, asked for through QueryInterface when a method first needs one
; and released with the view. Index: a $__WV2_IF_* constant, slot 0 is never used.
Global $__WV2_pWvIf[$__WV2_MAX + 1][$__WV2_IF_MAX + 1]
Global $__WV2_oSettings[$__WV2_MAX + 1]
Global $__WV2_pObj[$__WV2_MAX + 1][$__WV2_SLOT_COUNT + 1]   ; address of each fake handler object
Global $__WV2_iTok[$__WV2_MAX + 1][$__WV2_SLOT_COUNT + 1]   ; cookie returned by add_*, 0 when not subscribed
Global $__WV2_hParent[$__WV2_MAX + 1]
Global $__WV2_bOwnWin[$__WV2_MAX + 1]              ; 1 when _WV2_Simple created the window it is glued to
Global $__WV2_iLeft[$__WV2_MAX + 1]
Global $__WV2_iTop[$__WV2_MAX + 1]
Global $__WV2_iRight[$__WV2_MAX + 1]                  ; last bounds, held as a RECT
Global $__WV2_iBottom[$__WV2_MAX + 1]
Global $__WV2_bEnv[$__WV2_MAX + 1]                    ; environment callback answered
Global $__WV2_bCtl[$__WV2_MAX + 1]                    ; controller callback answered
Global $__WV2_bReady[$__WV2_MAX + 1]
Global $__WV2_bEnvErr[$__WV2_MAX + 1]
Global $__WV2_bCtlErr[$__WV2_MAX + 1]
Global $__WV2_bNavDone[$__WV2_MAX + 1]
Global $__WV2_bNavOK[$__WV2_MAX + 1]
Global $__WV2_iWebErr[$__WV2_MAX + 1]
Global $__WV2_iHR[$__WV2_MAX + 1]
Global $__WV2_sUser[$__WV2_MAX + 1]
Global $__WV2_bTempUser[$__WV2_MAX + 1]
Global $__WV2_aPend[$__WV2_MAX * 4]                   ; profile folders released and not deleted yet, see __WV2_SweepStale
Global $__WV2_tPend[$__WV2_MAX * 4]                   ; when each of them was released
Global $__WV2_iPend                                   ; how many are waiting
Global $__WV2_iTempSeq                                ; counts the temporary folders this script builds
Global $__WV2_bSwept                                  ; the rubbish of the previous runs was already collected
; One browser per user data folder. A second ICoreWebView2Environment on the same folder is a second
; round trip to a browser that is already up, and the second view of a window pays for it: measured,
; the first view of a fresh folder costs seconds and the next one on the same folder 0,7 s. The table
; below keeps the environment of a folder while at least one view of that folder is alive, so a later
; one borrows it instead of asking for a new one. It holds no COM reference of its own: the entry only
; exists while a view holds one, which is what keeps the pointer from ever going stale.
Global Const $__WV2_ENVSHARE = $__WV2_MAX
Global $__WV2_sEnvKey[$__WV2_ENVSHARE + 1]            ; user data folder, upper case
Global $__WV2_pEnvShared[$__WV2_ENVSHARE + 1]         ; raw ICoreWebView2Environment pointer
Global $__WV2_iEnvRefs[$__WV2_ENVSHARE + 1]           ; views of this slot that use that environment
Global $__WV2_iEnvShare[$__WV2_MAX + 1]               ; entry a handle borrows from, 0 when it owns its own
Global $__WV2_sVersion[$__WV2_MAX + 1]
Global $__WV2_sNavFilter[$__WV2_MAX + 1]              ; regular expression, empty means never cancel
Global $__WV2_sDlFilter[$__WV2_MAX + 1]               ; regular expression, empty means never refuse
Global $__WV2_sDlFolder[$__WV2_MAX + 1]               ; empty means the folder chosen by the runtime
Global $__WV2_sResFunc[$__WV2_MAX + 1]                ; name of the resource handler, empty means none
Global $__WV2_sResFilter[$__WV2_MAX + 1]              ; filter installed with the handler, empty means none
Global $__WV2_iResCtx[$__WV2_MAX + 1]                 ; context that filter was installed with
Global $__WV2_bInRes[$__WV2_MAX + 1]                  ; a resource handler is running on this thread
Global $__WV2_bInCb[$__WV2_MAX + 1]                   ; a dialog, key or menu handler is running on this thread
; Lot 2 state.
Global $__WV2_pFind[$__WV2_MAX + 1]                   ; ICoreWebView2Find of the view, 0 until first used
Global $__WV2_bFindOn[$__WV2_MAX + 1]                 ; a search is running on this view
Global $__WV2_sDlgFunc[$__WV2_MAX + 1]                ; name of the script dialog handler, empty means none
Global $__WV2_bDlgDefault[$__WV2_MAX + 1]             ; AreDefaultScriptDialogsEnabled before the handler took it, -1 while none
Global $__WV2_sAccelFunc[$__WV2_MAX + 1]              ; name of the accelerator handler, empty means none
Global $__WV2_sCtxFunc[$__WV2_MAX + 1]                ; name of the context menu handler, empty means none
Global $__WV2_sCdpEvent[$__WV2_MAX + 1]               ; name of the DevTools event subscribed, empty means none
Global $__WV2_pDl[$__WV2_MAX + 1][$WV2_DL_MAX + 1]  ; download operations remembered, reference held
Global $__WV2_iDlCount[$__WV2_MAX + 1]
Global $__WV2_iDlSeq[$__WV2_MAX + 1][$WV2_DL_MAX + 1] ; when each slot was filled, oldest goes first
Global $__WV2_iDlNext[$__WV2_MAX + 1]                 ; counter behind those stamps
Global $__WV2_bDlWatch[$__WV2_MAX + 1]                ; state and progress events are subscribed
Global $__WV2_iDlStateTok[$__WV2_MAX + 1][$WV2_DL_MAX + 1]
Global $__WV2_iDlProgTok[$__WV2_MAX + 1][$WV2_DL_MAX + 1]
Global $__WV2_pCdpRecv[$__WV2_MAX + 1]                ; ICoreWebView2DevToolsProtocolEventReceiver, reference held
Global $__WV2_iCdpTok[$__WV2_MAX + 1]
; Set when the host turns $WV2_EVENT_DEVTOOLS off on purpose. The subscription of
; _WV2_SetDevToolsProtocolEvent answers to it, so a name given after a disable stays unheard; a view
; that was never disabled answers False and keeps the ordinary behaviour.
Global $__WV2_bCdpOff[$__WV2_MAX + 1]
; What the view answers each kind of permission request with, indexed by $WV2_PERM_* (0 to 13).
; Zero is $WV2_PERM_DEFAULT: the runtime decides, which for a WebView2 with no prompt UI means the
; permission is not given. Only _WV2_SetPermissionPolicy writes here.
Global $__WV2_iPermPol[$__WV2_MAX + 1][$__WV2_PERM_KIND_MAX + 1]
; The requests answered with $WV2_PERM_ASK wait here: the arguments of the request, the deferral taken
; from it, and what was read off the arguments before the handler returned. Both pointers carry a
; reference of this UDF's own until _WV2_PermissionRespond or the teardown releases them.
Global $__WV2_pPermArgs[$__WV2_MAX + 1][$WV2_PERM_MAX + 1]
Global $__WV2_pPermDef[$__WV2_MAX + 1][$WV2_PERM_MAX + 1]
Global $__WV2_sPermUri[$__WV2_MAX + 1][$WV2_PERM_MAX + 1]
Global $__WV2_iPermKind[$__WV2_MAX + 1][$WV2_PERM_MAX + 1]
Global $__WV2_iPermSeq[$__WV2_MAX + 1][$WV2_PERM_MAX + 1]
Global $__WV2_iPermNext[$__WV2_MAX + 1]
; Print settings objects, shared by the script and released by _WV2_PrintSettingsDestroy or with the view.
Global $__WV2_pPrintSet[$WV2_PRINT_SETTINGS_MAX + 1]
Global $__WV2_iPrintInst[$WV2_PRINT_SETTINGS_MAX + 1]
; Theme lot. get_Profile hands out the profile with a reference of its own, so it is kept the way the
; search object is: one QueryInterface for ICoreWebView2_13 and one get_Profile per view, however many
; colour or folder calls follow. The teardown releases it before the view goes.
Global $__WV2_pProf[$__WV2_MAX + 1]                   ; ICoreWebView2Profile of the view, 0 until first used

; One block of five pointers per (instance, handler slot) holds a fake vtable and its object.
; A single global struct owns that memory for the life of the script, so no copy semantics apply.
Global $__WV2_tHeap = 0
Global $__WV2_pHeap = 0                           ; address of that block, kept as a plain number
Global $__WV2_iPtrSize = 0
; One set of callbacks serves every handler object of every instance: the this-pointer tells which
; instance and which slot is calling, so one registration per slot covers the whole life of the script.
Global $__WV2_hCbQI = 0
Global $__WV2_hCbAddRef = 0
Global $__WV2_hCbRelease = 0
Global $__WV2_hCbInv[$__WV2_SLOT_COUNT + 1]
; The Invoke function and the callback parameter list of every slot. Index 0 is never used.
Global $__WV2_aInvFunc[$__WV2_SLOT_COUNT + 1] = [ _
		"", "__WV2_InvEnv", "__WV2_InvCtl", "__WV2_InvNavC", "__WV2_InvNavS", "__WV2_InvMsg", "__WV2_InvNew", _
		"__WV2_InvTitle", "__WV2_InvHist", "__WV2_InvProc", "__WV2_InvExec", "__WV2_InvAddScript", "__WV2_InvCap", _
		"__WV2_InvPrint", "__WV2_InvDl", "__WV2_InvRes", _
		"__WV2_InvFindIdx", "__WV2_InvFindCnt", "__WV2_InvFindStart", "__WV2_InvExecRes", "__WV2_InvCookies", _
		"__WV2_InvProfile", "__WV2_InvPdfStream", "__WV2_InvDlState", "__WV2_InvDlProg", "__WV2_InvDialog", _
		"__WV2_InvAccel", "__WV2_InvCtxMenu", "__WV2_InvFavChanged", "__WV2_InvFavGet", "__WV2_InvCdpCall", _
		"__WV2_InvCdpEvt", "__WV2_InvAudio", "__WV2_InvMuted", "__WV2_InvFullscreen", "__WV2_InvPermission", _
		"__WV2_InvCntLoad", "__WV2_InvSrcChg", "__WV2_InvDomContent", "__WV2_InvWinClose", _
		"__WV2_InvExtAdd", "__WV2_InvExtGet", "__WV2_InvExtRemove", "__WV2_InvExtEnable"]
Global $__WV2_aInvArgs[$__WV2_SLOT_COUNT + 1] = [ _
		"", "ptr;ptr;ptr", "ptr;ptr;ptr", "ptr;ptr;ptr", "ptr;ptr;ptr", "ptr;ptr;ptr", "ptr;ptr;ptr", _
		"ptr;ptr;ptr", "ptr;ptr;ptr", "ptr;ptr;ptr", "ptr;ptr;ptr", "ptr;ptr;ptr", "ptr;ptr", "ptr;long;long", _
		"ptr;ptr;ptr", "ptr;ptr;ptr", _
		"ptr;ptr;ptr", "ptr;ptr;ptr", "ptr;long", "ptr;long;ptr", "ptr;long;ptr", _
		"ptr;long", "ptr;long;ptr", "ptr;ptr;ptr", "ptr;ptr;ptr", "ptr;ptr;ptr", _
		"ptr;ptr;ptr", "ptr;ptr;ptr", "ptr;ptr;ptr", "ptr;long;ptr", "ptr;long;wstr", _
		"ptr;ptr;ptr", "ptr;ptr;ptr", "ptr;ptr;ptr", "ptr;ptr;ptr", "ptr;ptr;ptr", _
		"ptr;ptr;ptr", "ptr;ptr;ptr", "ptr;ptr;ptr", "ptr;ptr;ptr", _
		"ptr;long;ptr", "ptr;long;ptr", "ptr;long", "ptr;long"]
; The handler IID accepted by QueryInterface for each slot, so a fake object never claims an interface
; whose vtable it does not carry.
Global $__WV2_aInvIID[$__WV2_SLOT_COUNT + 1] = [ _
		"", $WV2_IID_ENVCB, $WV2_IID_CTLCB, $WV2_IID_NAVH, $WV2_IID_NAVSH, $WV2_IID_MSGH, $WV2_IID_NEWH, _
		$WV2_IID_TITLEH, $WV2_IID_HISTH, $WV2_IID_PROCH, $WV2_IID_EXECH, $WV2_IID_ADDSCH, $WV2_IID_CAPH, _
		$WV2_IID_PRINTH, $WV2_IID_DLH, $WV2_IID_RES, _
		$WV2_IID_FINDIDXH, $WV2_IID_FINDCNTH, $WV2_IID_FINDSTARTH, $WV2_IID_EXECRESH, $WV2_IID_COOKIEH, _
		$WV2_IID_PROFH, $WV2_IID_PDFSTREAMH, $WV2_IID_DLSTATEH, $WV2_IID_DLPROGH, $WV2_IID_DIALOGH, _
		$WV2_IID_ACCELH, $WV2_IID_CTXH, $WV2_IID_FAVH, $WV2_IID_FAVGET, $WV2_IID_CDPCALLH, _
		$WV2_IID_CDPEVTH, $WV2_IID_AUDIOH, $WV2_IID_MUTEDH, $WV2_IID_FULLH, $WV2_IID_PERMH, _
		$WV2_IID_CNTLOADH, $WV2_IID_SRCCHGH, $WV2_IID_DOMCBH, $WV2_IID_WINCLOSEH, _
		$WV2_IID_EXTADDH, $WV2_IID_EXTGETH, $WV2_IID_EXTREMOVEH, $WV2_IID_EXTENABLEH]

; The options object. One set of values, read by the runtime when an environment is created, and one fake
; COM object per interface it answers for: QueryInterface hands out the cell whose vtable carries the
; property at the slot number that interface declares, so the same object can be met as six interfaces
; without a single slot number moving. Built on the first create that carries an option, never freed:
; the UDF owns it for the life of the script, like the handler objects.
Global $__WV2_bOptSet = False                         ; True once a script asked for an option
Global $__WV2_sOptAba = ""                           ; AdditionalBrowserArguments
Global $__WV2_sOptLang = ""                          ; Language
Global $__WV2_sOptTcbv = ""                          ; TargetCompatibleBrowserVersion, filled at create
Global $__WV2_bOptSso = False                        ; AllowSingleSignOnUsingOSPrimaryAccount
Global $__WV2_bOptExcl = False                       ; ExclusiveUserDataFolderAccess
Global $__WV2_bOptCrash = False                      ; IsCustomCrashReportingEnabled
Global $__WV2_bOptTrack = True                       ; EnableTrackingPrevention, TRUE as in the loader
Global $__WV2_bOptExt = False                        ; AreBrowserExtensionsEnabled
Global $__WV2_iOptScroll = $WV2_SCROLLBAR_DEFAULT    ; ScrollBarStyle
Global $__WV2_pOpt[7]                                ; one object cell per interface, index 0 unused
Global $__WV2_tOptVt[7]                              ; the vtable of each of them
Global $__WV2_tOptObj[7]                             ; the memory the cells live in
Global $__WV2_hCbOptQI = 0
Global $__WV2_hCbOptAddRef = 0
Global $__WV2_hCbOptRelease = 0
Global $__WV2_hCbOpt[19]                             ; the eighteen property callbacks, 1 To 9 getters then 10 To 18 setters
Global $__WV2_pOptIfIID[7] = [ _
		"", $WV2_IID_OPTB, $WV2_IID_OPT2, $WV2_IID_OPT3, $WV2_IID_OPT5, $WV2_IID_OPT6, $WV2_IID_OPT8]

; Queue of the events received per instance, read in order by _WV2_GetEvent.
Global $__WV2_aEvtType[$__WV2_MAX + 1][$__WV2_QCAP]
Global $__WV2_aEvtStr[$__WV2_MAX + 1][$__WV2_QCAP]
Global $__WV2_aEvtNum[$__WV2_MAX + 1][$__WV2_QCAP]
Global $__WV2_iEvtHead[$__WV2_MAX + 1]
Global $__WV2_iEvtCount[$__WV2_MAX + 1]
Global $__WV2_iEvtDrop[$__WV2_MAX + 1]

; The event kinds a function of the script owns, by name. A kind with a name here is taken out of the
; queue and handed to that function the next time the queue is read, instead of being read by hand;
; a kind without one is left for _WV2_GetEvent. See _WV2_SetEventHandler.
Global Const $__WV2_EV_MAX = 25                      ; the highest $WV2_EVENT_* kind
Global Const $__WV2_CB_CAP = 32                      ; handlers one pass may call
Global $__WV2_aEvtCb[$__WV2_MAX + 1][$__WV2_EV_MAX + 1]
Global $__WV2_iEvtCbCount[$__WV2_MAX + 1]            ; kinds this view owns, 0 = the queue is all the host's
Global $__WV2_bDispatching = False                   ; a pass is running on this thread

; State of the asynchronous operations, one set per (instance, slot): ExecuteScript,
; AddScriptToExecuteOnDocumentCreated, CapturePreview and PrintToPdf each answer through their own slot.
; PrintToPdf also keeps its BOOL answer in the text cell: a successful call that refused to write the
; file is a different failure from a call that failed.
Global $__WV2_bOpDone[$__WV2_MAX + 1][$__WV2_SLOT_COUNT + 1]
Global $__WV2_iOpHR[$__WV2_MAX + 1][$__WV2_SLOT_COUNT + 1]
Global $__WV2_sOpOut[$__WV2_MAX + 1][$__WV2_SLOT_COUNT + 1]
; Answer that comes back as a COM object (a cookie list, a stream, a script result...). The handler
; keeps the reference the runtime handed it; the caller reads it and releases it with the vtable.
Global $__WV2_pOpObj[$__WV2_MAX + 1][$__WV2_SLOT_COUNT + 1]

; ===============================================================================================================================
; Public API
; ===============================================================================================================================

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_GetRuntimePath
; Description ...: Locates the WebView2 runtime already installed on the machine.
; Syntax ........: _WV2_GetRuntimePath()
; Parameters ....: none
; Return values .: Success: full path of the EmbeddedBrowserWebView.dll matching this AutoIt bitness.
;                  Failure: "" with @error = $WV2_ERR_RUNTIME.
; Author ........: Numeric1
; Remarks .......: The version registered for all users is tried first, then the one registered for the
;                  current user, then the highest version found on disk. Nothing is downloaded.
; Related .......: _WV2_Create
; ===============================================================================================================================
Func _WV2_GetRuntimePath()
	Local $i, $j
	$__WV2_iLastError = $WV2_ERR_NONE
	$__WV2_iLastHR = 0
	$__WV2_sLastFunc = "_WV2_GetRuntimePath"

	Local $sVer = ""
	Local $bFound = False
	Local $aHives[3] = ["HKLM\", "HKLM64\", "HKCU\"]
	For $i = 0 To 2
		$sVer = RegRead($aHives[$i] & $__WV2_CLSID_KEY, "pv")
		If @Error = 0 And $sVer <> "" Then
			$bFound = True
			ExitLoop
		EndIf
	Next

	If $bFound Then
		Local $sPath = __WV2_DllForVersion($sVer)
		If $sPath <> "" Then Return SetError(0, 0, $sPath)
	EndIf

	; Fall back to the highest version found on disk.
	Local $sBest = "", $sFound = ""
	For $i = 1 To 2
		Local $sRoot = __WV2_ProgramFiles($i = 1) & "\Microsoft\EdgeWebView\Application"
		If Not FileExists($sRoot) Then ContinueLoop
		Local $aDirs = _FileListToArray($sRoot, "*", $FLTA_FOLDERS)
		If @Error Or Not IsArray($aDirs) Then ContinueLoop
		For $j = 1 To $aDirs[0]
			If Not StringRegExp($aDirs[$j], "^\d+\.\d+\.\d+\.\d+$") Then ContinueLoop
			Local $sDll = __WV2_DllForVersion($aDirs[$j])
			If $sDll <> "" And __WV2_CompareVersion($aDirs[$j], $sBest) > 0 Then
				$sBest = $aDirs[$j]
				$sFound = $sDll
			EndIf
		Next
	Next
	If $sFound <> "" Then Return SetError(0, 0, $sFound)

	$__WV2_iLastError = $WV2_ERR_RUNTIME
	Return SetError($__WV2_iLastError, 0, "")
EndFunc   ;==>_WV2_GetRuntimePath

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_CreateStart
; Description ...: Asks the runtime for a WebView2 view and returns at once, without waiting for the browser.
; Syntax ........: _WV2_CreateStart($hParent[, $iLeft = 0[, $iTop = 0[, $iWidth = -1[, $iHeight = -1[,
;                  $sUserDataFolder = ""]]]]])
; Parameters ....: $hParent - Handle of the window the browser is attached to, usually a GUICreate one.
;                  $iLeft - X coordinate of the browser area, in the client area of $hParent.
;                  $iTop - Y coordinate of the browser area, in the client area of $hParent.
;                  $iWidth - Width in pixels. -1 uses the rest of the client width.
;                  $iHeight - Height in pixels. -1 uses the rest of the client height.
;                  $sUserDataFolder - Folder holding the browser profile, as in _WV2_Create.
; Return values .: Success: handle >= 1, not usable yet. Finish with _WV2_CreateWait.
;                  Failure: 0, with @error set to a $WV2_ERR_* code and @extended set to the raw HRESULT (0 if none).
; Author ........: Numeric1
; Remarks .......: The browser boots in its own processes, so the script is free while it does: create
;                  the controls, show the window, write the "loading" line, and only then call
;                  _WV2_CreateWait. Any message loop in between is what delivers the runtime's answer,
;                  so the wait is short or nil. Until it ends, every function that needs the view
;                  answers $WV2_ERR_NOT_READY for this handle, and _WV2_Destroy releases it normally.
; Related .......: _WV2_CreateWait, _WV2_Create, _WV2_Destroy
; ===============================================================================================================================
Func _WV2_CreateStart($hParent, $iLeft = 0, $iTop = 0, $iWidth = -1, $iHeight = -1, $sUserDataFolder = "")
	$__WV2_iLastError = $WV2_ERR_NONE
	$__WV2_iLastHR = 0
	$__WV2_sLastFunc = "_WV2_CreateStart"

	If Not IsHWnd($hParent) Then
		$__WV2_iLastError = $WV2_ERR_ARG
		Return SetError($__WV2_iLastError, 0, 0)
	EndIf
	__WV2_InitHeap()
	Local $i = __WV2_Alloc()
	If $i = 0 Then
		$__WV2_iLastError = $WV2_ERR_FULL
		Return SetError($__WV2_iLastError, 0, 0)
	EndIf

	Local $sDll = _WV2_GetRuntimePath()
	If $sDll = "" Then
		$__WV2_iLastError = $WV2_ERR_RUNTIME
		__WV2_Free($i)
		Return SetError($__WV2_iLastError, 0, 0)
	EndIf

	; The runtime must be reached from a single threaded apartment. The UDF never calls
	; CoUninitialize, so a COM aware script keeps working after a view is destroyed.
	If $__WV2_iCoState = 0 Then
		Local $aCo = DllCall("ole32.dll", "long", "CoInitializeEx", "ptr", 0, "dword", 2)
		If @Error Or $aCo[0] < 0 Then
			$__WV2_iLastError = $WV2_ERR_COM
			$__WV2_iLastHR = (@Error ? 0 : $aCo[0])
			__WV2_Free($i)
			Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
		EndIf
		$__WV2_iCoState = 1
	EndIf

	__WV2_ClientSize($hParent)
	$__WV2_hParent[$i] = $hParent
	$__WV2_iLeft[$i] = Int($iLeft)
	$__WV2_iTop[$i] = Int($iTop)
	$__WV2_iRight[$i] = $__WV2_iLeft[$i] + ($iWidth < 0 ? $__WV2_iClientW - $__WV2_iLeft[$i] : Int($iWidth))
	$__WV2_iBottom[$i] = $__WV2_iTop[$i] + ($iHeight < 0 ? $__WV2_iClientH - $__WV2_iTop[$i] : Int($iHeight))

	$sUserDataFolder = StringStripWS(String($sUserDataFolder), 3)
	If $sUserDataFolder = "" Then
		; Every view gets a folder of its own. A folder still held by a browser that is dying cannot be
		; reused, and waiting for it would make this create pay for the last destroy; what is left
		; behind is collected by __WV2_SweepStale once the rubbish has come free.
		$__WV2_iTempSeq += 1
		$sUserDataFolder = @TempDir & "\" & $__WV2_PROFILE_PREFIX & @AutoItPID & "_" & $i & "_" & $__WV2_iTempSeq
		$__WV2_bTempUser[$i] = True
	Else
		$__WV2_bTempUser[$i] = False
	EndIf
	DirCreate($sUserDataFolder)
	$__WV2_sUser[$i] = $sUserDataFolder

	__WV2_BuildAllHandlers($i)

	Local $iShare = __WV2_EnvShareFind($sUserDataFolder)
	If $iShare <> 0 Then
		; The browser of this folder is already up and somebody is holding its environment: borrow it
		; and ask for a controller straight away. This is what makes the second view of a window cost
		; a fraction of a second instead of another round trip. The browser process of that folder was
		; started with the options of the view that created it, so an option set here changes nothing
		; for this view: only a folder whose browser is not running yet takes new ones.
		$__WV2_oEnv[$i] = ObjCreateInterface($__WV2_pEnvShared[$iShare], $WV2_IID_ENV, $__WV2_TAG_ENV, False)
		If @Error Or Not IsObj($__WV2_oEnv[$i]) Then
			__WV2_SetErr($WV2_ERR_COM, 0, "ICoreWebView2Environment borrow")
			__WV2_Fail($i)
			Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
		EndIf
		$__WV2_oEnv[$i].AddRef()
		$__WV2_pEnv[$i] = $__WV2_pEnvShared[$iShare]
		$__WV2_iEnvShare[$i] = $iShare
		$__WV2_iEnvRefs[$iShare] += 1
		$__WV2_bEnv[$i] = True
		$__WV2_iHR[$i] = $__WV2_oEnv[$i].CreateCoreWebView2Controller($__WV2_hParent[$i], $__WV2_pObj[$i][$__WV2_H_CTL])
		If $__WV2_iHR[$i] <> 0 Then
			__WV2_SetErr($WV2_ERR_CONTROLLER, $__WV2_iHR[$i], "ICoreWebView2Environment::CreateCoreWebView2Controller")
			__WV2_Fail($i)
			Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
		EndIf
	Else
		; The environment answers through __WV2_InvEnv, which immediately requests the controller.
		; The options pointer is 0 for every script that never called a _WV2_SetEnv* function, which keeps
		; this call exactly what it has been since 0.1; an options object is built only once it is asked for.
		Local $pOpts = __WV2_OptionsForCreate($sDll)
		If $pOpts < 0 Then
			__WV2_SetErr($WV2_ERR_COM, 0, "ICoreWebView2EnvironmentOptions")
			__WV2_Fail($i)
			Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
		EndIf
		Local $aCE = DllCall($sDll, "long", "CreateWebViewEnvironmentWithOptionsInternal", _
				"bool", 1, "int", 0, "wstr", $sUserDataFolder, "ptr", $pOpts, "ptr", $__WV2_pObj[$i][$__WV2_H_ENV])
		If @Error Then
			__WV2_SetErr($WV2_ERR_RUNTIME, 0, "CreateWebViewEnvironmentWithOptionsInternal")
			__WV2_Fail($i)
			Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
		EndIf
		If $aCE[0] <> 0 Then
			__WV2_SetErr($WV2_ERR_ENV, $aCE[0], "CreateWebViewEnvironmentWithOptionsInternal")
			__WV2_Fail($i)
			Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
		EndIf
	EndIf

	Return SetError(0, 0, $i)
EndFunc   ;==>_WV2_CreateStart

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_CreateWait
; Description ...: Waits for a view started by _WV2_CreateStart to become usable.
; Syntax ........: _WV2_CreateWait($iHandle[, $iTimeoutMs = $WV2_CREATE_TIMEOUT])
; Parameters ....: $iHandle - Handle returned by _WV2_CreateStart.
;                  $iTimeoutMs - Time allowed for the runtime to answer, in milliseconds.
; Return values .: Success: 1. The handle is then usable, exactly like the one _WV2_Create returns.
;                  Failure: 0, with @error set to a $WV2_ERR_* code and @extended set to the raw HRESULT (0 if none).
;                  The handle is released by this call when it fails, so a rejected view is never left live.
; Author ........: Numeric1
; Remarks .......: Messages are pumped while waiting, the same way _WV2_Create does it. Calling this on
;                  a handle that is already ready answers 1 without waiting, so a script may call it
;                  defensively before anything that needs the view.
; Related .......: _WV2_CreateStart, _WV2_Create, _WV2_Destroy
; ===============================================================================================================================
Func _WV2_CreateWait($iHandle, $iTimeoutMs = $WV2_CREATE_TIMEOUT)
	$__WV2_iLastError = $WV2_ERR_NONE
	$__WV2_iLastHR = 0
	$__WV2_sLastFunc = "_WV2_CreateWait"
	If Not __WV2_Valid($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	If $__WV2_bReady[$iHandle] Then Return SetError(0, 0, 1)
	Local $i = $iHandle

	If Not __WV2_WaitFor($i, $iTimeoutMs) Then
		__WV2_Fail($i)
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf

	; From here on everything runs on the calling thread, with a live controller.
	If __WV2_PutBounds($i, $__WV2_iLeft[$i], $__WV2_iTop[$i], $__WV2_iRight[$i], $__WV2_iBottom[$i]) = 0 Then
		__WV2_Fail($i)
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	Local $hr = $__WV2_oCtl[$i].put_IsVisible(1)
	If $hr <> 0 Then
		__WV2_SetErr($WV2_ERR_CALL, $hr, "ICoreWebView2Controller::put_IsVisible")
		__WV2_Fail($i)
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf

	; NavigationCompleted is the one event every handle needs: _WV2_WaitNavigation waits on it.
	If Not __WV2_Attach($i, $__WV2_H_NAVC) Then
		__WV2_Fail($i)
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf

	__WV2_ClientSize($__WV2_hParent[$i])
	Local $s = ""
	If $__WV2_oEnv[$i].get_BrowserVersionString($s) = 0 Then $__WV2_sVersion[$i] = $s
	$__WV2_bReady[$i] = True
	$__WV2_iLastError = $WV2_ERR_NONE
	$__WV2_iLastHR = 0
	; The browser is on screen and answering. Collecting the profile folders the previous views could
	; not let go of happens here, at the end: it is milliseconds nobody is waiting for any more.
	__WV2_SweepStale()
	Return SetError(0, 0, 1)
EndFunc   ;==>_WV2_CreateWait

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_Create
; Description ...: Creates a WebView2 view inside a window and returns its handle.
; Syntax ........: _WV2_Create($hParent[, $iLeft = 0[, $iTop = 0[, $iWidth = -1[, $iHeight = -1[,
;                  $sUserDataFolder = ""[, $iTimeoutMs = $WV2_CREATE_TIMEOUT]]]]])
; Parameters ....: $hParent - Handle of the window the browser is attached to, usually a GUICreate one.
;                  $iLeft - X coordinate of the browser area, in the client area of $hParent.
;                  $iTop - Y coordinate of the browser area, in the client area of $hParent.
;                  $iWidth - Width in pixels. -1 uses the rest of the client width.
;                  $iHeight - Height in pixels. -1 uses the rest of the client height.
;                  $sUserDataFolder - Folder holding the browser profile (cache, cookies, history).
;                     "" uses a private temporary folder, tied to the handle number, that is removed
;                     when the slot is used again. Views given the same folder share one browser and
;                     one environment: the second one of them costs a fraction of a second.
;                  $iTimeoutMs - Time allowed for the runtime to answer, in milliseconds.
; Return values .: Success: handle >= 1.
;                  Failure: 0, with @error set to a $WV2_ERR_* code and @extended set to the raw HRESULT (0 if none).
; Author ........: Numeric1
; Remarks .......: The browser is a real window inside $hParent and covers the AutoIt controls that
;                  overlap its area; leave a band of its client area free for a toolbar, or create the
;                  controls on a sibling window. Windows messages are pumped while waiting, so the GUI
;                  stays responsive. Call this from the thread that owns $hParent.
;
;                  This is _WV2_CreateStart followed by _WV2_CreateWait, and it blocks for as long as
;                  the browser takes to come up - 1,2 s on a quiet machine, and up to tens of seconds
;                  when the disk and the antivirus are busy. A window that must paint before that uses
;                  the two calls itself: show the GUI, do the rest of the start-up work, then wait.
;
;                  The temporary profile folder is not deleted by _WV2_Destroy: the browser process
;                  holds it for seconds, and waiting for it would freeze the window on close. Every
;                  view gets a folder of its own, and the folders left behind are collected once, by
;                  the first successful _WV2_Create - this process's own rubbish and the one a killed
;                  run dropped. Give $sUserDataFolder yourself when the profile matters.
; Related .......: _WV2_CreateStart, _WV2_CreateWait, _WV2_Destroy, _WV2_Navigate, _WV2_FitToParent
; ===============================================================================================================================
Func _WV2_Create($hParent, $iLeft = 0, $iTop = 0, $iWidth = -1, $iHeight = -1, $sUserDataFolder = "", $iTimeoutMs = $WV2_CREATE_TIMEOUT)
	Local $i = _WV2_CreateStart($hParent, $iLeft, $iTop, $iWidth, $iHeight, $sUserDataFolder)
	If $i = 0 Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	If Not _WV2_CreateWait($i, $iTimeoutMs) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	Return SetError(0, 0, $i)
EndFunc   ;==>_WV2_Create

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_Destroy
; Description ...: Releases a WebView2 view and everything its handle owns.
; Syntax ........: _WV2_Destroy($iHandle)
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
; Return values .: Success: 1. @extended holds the HRESULT of the controller Close call, 0 if none.
;                  Failure: 0 with @error = $WV2_ERR_HANDLE.
; Author ........: Numeric1
; Remarks .......: The release order is the one the runtime expects: unregister the event handler,
;                  release the web view, close the controller and release it, release the environment.
;                  A temporary user data folder is NOT deleted by this call - the browser process holds
;                  it for seconds, and waiting for it would freeze the window on close. It is swept by
;                  the next _WV2_Create, or by a later run once this process is gone. One supplied by
;                  the caller is left alone either way. The browser window disappears with the call.
; Related .......: _WV2_Create
; ===============================================================================================================================
Func _WV2_Destroy($iHandle)
	$__WV2_iLastError = $WV2_ERR_NONE
	$__WV2_iLastHR = 0
	$__WV2_sLastFunc = "_WV2_Destroy"
	If Not __WV2_Valid($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	; Tearing the view down while one of its own callbacks is running would free the objects the
	; callback is walking: the handler has to be gone first.
	If $__WV2_bInRes[$iHandle] Or $__WV2_bInCb[$iHandle] Then
		__WV2_SetErr($WV2_ERR_BUSY, 0, "_WV2_Destroy")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	__WV2_Teardown($iHandle)
	__WV2_Free($iHandle)
	Return SetError(0, $__WV2_iLastHR, 1)
EndFunc   ;==>_WV2_Destroy

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_DestroyAll
; Description ...: Releases every live view, whatever its number of handles.
; Syntax ........: _WV2_DestroyAll()
; Parameters ....: None.
; Return values .: Number of views released, 0 when none was live. @error is always 0.
; Author ........: Numeric1
; Remarks .......: Call this from the message loop, just before leaving it - not from an
;                  OnAutoItExitRegister handler. The release waits for the runtime to answer, and the
;                  answers travel through the message loop: outside it, the same work that costs 113 ms
;                  in the loop costs between 390 and 2 700 ms in an exit handler, measured. A view still
;                  inside one of its own callbacks is left alone (see _WV2_Destroy) and is not counted.
;                  A script that ends without releasing anything loses nothing for good: the profile
;                  folders are collected by the next _WV2_Create, and the browser processes leave on
;                  their own within seconds of the host.
; Related .......: _WV2_Create, _WV2_Destroy
; ===============================================================================================================================
Func _WV2_DestroyAll()
	$__WV2_iLastError = $WV2_ERR_NONE
	$__WV2_iLastHR = 0
	$__WV2_sLastFunc = "_WV2_DestroyAll"
	Local $i, $iDone = 0
	For $i = 1 To $__WV2_MAX
		If $__WV2_aUsed[$i] Then
			_WV2_Destroy($i)
			If @Error = 0 Then $iDone += 1
		EndIf
	Next
	Return SetError(0, 0, $iDone)
EndFunc   ;==>_WV2_DestroyAll

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_IsReady
; Description ...: Tells whether a handle is usable.
; Syntax ........: _WV2_IsReady($iHandle)
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
; Return values .: 1 ready, 0 not ready or invalid. @error is always 0.
; Author ........: Numeric1
; Related .......: _WV2_Create
; ===============================================================================================================================
Func _WV2_IsReady($iHandle)
	If Not __WV2_Valid($iHandle) Then Return SetError(0, 0, 0)
	Return SetError(0, 0, $__WV2_bReady[$iHandle] ? 1 : 0)
EndFunc   ;==>_WV2_IsReady

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_Navigate
; Description ...: Starts a navigation to an URL.
; Syntax ........: _WV2_Navigate($iHandle, $sUrl)
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $sUrl - Absolute http:, https:, file: or data: URL.
; Return values .: Success: 1. The navigation itself is asynchronous: use _WV2_WaitNavigation or poll
;                  _WV2_IsNavigationComplete.
;                  Failure: 0, with @error set to a $WV2_ERR_* code and @extended set to the raw HRESULT (0 if none).
; Author ........: Numeric1
; Related .......: _WV2_NavigateToString, _WV2_WaitNavigation
; ===============================================================================================================================
Func _WV2_Navigate($iHandle, $sUrl)
	$__WV2_sLastFunc = "_WV2_Navigate"
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	If Not IsString($sUrl) Or $sUrl = "" Then
		__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_Navigate")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	__WV2_BeginNavigation($iHandle)
	Local $hr = $__WV2_oWv[$iHandle].Navigate($sUrl)
	Local $bOk = __WV2_Result($hr, "ICoreWebView2::Navigate")
	Return SetError($__WV2_iLastError, $__WV2_iLastHR, $bOk)
EndFunc   ;==>_WV2_Navigate

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_NavigateToString
; Description ...: Renders an HTML string, with no file and no server.
; Syntax ........: _WV2_NavigateToString($iHandle, $sHtml)
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $sHtml - Complete HTML document.
; Return values .: Success: 1, failure: 0 with @error / @extended as for _WV2_Navigate.
; Author ........: Numeric1
; Remarks .......: The document is served from an internal data URI, so _WV2_GetSource does not return
;                  the HTML. Scripts, styles and images addressed by an absolute URL load normally.
; Related .......: _WV2_Navigate
; ===============================================================================================================================
Func _WV2_NavigateToString($iHandle, $sHtml)
	$__WV2_sLastFunc = "_WV2_NavigateToString"
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	If Not IsString($sHtml) Or $sHtml = "" Then
		__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_NavigateToString")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	__WV2_BeginNavigation($iHandle)
	Local $hr = $__WV2_oWv[$iHandle].NavigateToString($sHtml)
	Local $bOk = __WV2_Result($hr, "ICoreWebView2::NavigateToString")
	Return SetError($__WV2_iLastError, $__WV2_iLastHR, $bOk)
EndFunc   ;==>_WV2_NavigateToString

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_WaitNavigation
; Description ...: Waits until the running navigation is over.
; Syntax ........: _WV2_WaitNavigation($iHandle[, $iTimeoutMs = $WV2_NAV_TIMEOUT])
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $iTimeoutMs - Time allowed, in milliseconds.
; Return values .: Success: 1, @extended = 0 when the page loaded or the COREWEBVIEW2_WEB_ERROR_STATUS
;                  value when it failed.
;                  Failure: 0, with @error set to a $WV2_ERR_* code ($WV2_ERR_TIMEOUT when out of time).
; Author ........: Numeric1
; Remarks .......: Windows messages are pumped while waiting, so the GUI keeps working.
;                  A navigation refused by _WV2_SetNavigationFilter ends here with @extended = 14, the
;                  cancellation status, not a connection failure.
; Related .......: _WV2_IsNavigationComplete, _WV2_Navigate, _WV2_SetNavigationFilter
; ===============================================================================================================================
Func _WV2_WaitNavigation($iHandle, $iTimeoutMs = $WV2_NAV_TIMEOUT)
	$__WV2_sLastFunc = "_WV2_WaitNavigation"
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	Local $tEnd = TimerInit()
	While Not $__WV2_bNavDone[$iHandle]
		__WV2_Pump(20)
		If TimerDiff($tEnd) > $iTimeoutMs Then
			__WV2_SetErr($WV2_ERR_TIMEOUT, 0, "_WV2_WaitNavigation")
			Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
		EndIf
	WEnd
	$__WV2_iLastError = $WV2_ERR_NONE
	$__WV2_iLastHR = 0
	Return SetError(0, $__WV2_iWebErr[$iHandle], 1)
EndFunc   ;==>_WV2_WaitNavigation

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_IsNavigationComplete
; Description ...: Tells whether the last navigation of a handle is over.
; Syntax ........: _WV2_IsNavigationComplete($iHandle)
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
; Return values .: Success: 1 completed, 0 still running. @error is always 0.
;                  Failure: -1 with @error = $WV2_ERR_HANDLE.
;                  @extended carries the last COREWEBVIEW2_WEB_ERROR_STATUS value, 0 meaning no error.
; Author ........: Numeric1
; Related .......: _WV2_WaitNavigation
; ===============================================================================================================================
Func _WV2_IsNavigationComplete($iHandle)
	$__WV2_sLastFunc = "_WV2_IsNavigationComplete"
	If Not __WV2_Valid($iHandle) Then Return SetError($__WV2_iLastError, 0, -1)
	If Not $__WV2_bReady[$iHandle] Then Return SetError(0, 0, 0)
	Return SetError(0, $__WV2_iWebErr[$iHandle], $__WV2_bNavDone[$iHandle] ? 1 : 0)
EndFunc   ;==>_WV2_IsNavigationComplete

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_GetTitle
; Description ...: Reads the title of the current document.
; Syntax ........: _WV2_GetTitle($iHandle, $sTitle)
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $sTitle - Variable receiving the title, passed by reference.
; Return values .: Success: 1, @error = 0.
;                  Failure: 0, with @error set to a $WV2_ERR_* code and @extended set to the raw HRESULT (0 if none).
; Author ........: Numeric1
; Related .......: _WV2_GetSource
; ===============================================================================================================================
Func _WV2_GetTitle($iHandle, ByRef $sTitle)
	$__WV2_sLastFunc = "_WV2_GetTitle"
	$sTitle = ""
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	Local $s = ""
	Local $hr = $__WV2_oWv[$iHandle].get_DocumentTitle($s)
	If $hr <> 0 Then
		__WV2_Result($hr, "ICoreWebView2::get_DocumentTitle")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	$sTitle = $s
	Return SetError(0, 0, 1)
EndFunc   ;==>_WV2_GetTitle

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_GetSource
; Description ...: Reads the URI of the current document.
; Syntax ........: _WV2_GetSource($iHandle, $sUrl)
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $sUrl - Variable receiving the URI, passed by reference.
; Return values .: Success: 1, @error = 0.
;                  Failure: 0, with @error set to a $WV2_ERR_* code and @extended set to the raw HRESULT (0 if none).
; Author ........: Numeric1
; Related .......: _WV2_GetTitle
; ===============================================================================================================================
Func _WV2_GetSource($iHandle, ByRef $sUrl)
	$__WV2_sLastFunc = "_WV2_GetSource"
	$sUrl = ""
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	Local $s = ""
	Local $hr = $__WV2_oWv[$iHandle].get_Source($s)
	If $hr <> 0 Then
		__WV2_Result($hr, "ICoreWebView2::get_Source")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	$sUrl = $s
	Return SetError(0, 0, 1)
EndFunc   ;==>_WV2_GetSource

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_SetBounds
; Description ...: Moves and resizes the browser area inside its parent window.
; Syntax ........: _WV2_SetBounds($iHandle, $iLeft, $iTop, $iWidth, $iHeight)
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $iLeft - X coordinate in the client area of the parent window.
;                  $iTop - Y coordinate in the client area of the parent window.
;                  $iWidth - Width in pixels.
;                  $iHeight - Height in pixels.
; Return values .: Success: 1, failure: 0 with @error / @extended as for _WV2_Navigate.
; Author ........: Numeric1
; Related .......: _WV2_FitToParent, _WV2_SetVisible
; ===============================================================================================================================
Func _WV2_SetBounds($iHandle, $iLeft, $iTop, $iWidth, $iHeight)
	$__WV2_sLastFunc = "_WV2_SetBounds"
	If Not __WV2_GuardCtl($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	$__WV2_iLeft[$iHandle] = Int($iLeft)
	$__WV2_iTop[$iHandle] = Int($iTop)
	$__WV2_iRight[$iHandle] = $__WV2_iLeft[$iHandle] + Int($iWidth)
	$__WV2_iBottom[$iHandle] = $__WV2_iTop[$iHandle] + Int($iHeight)
	; The RECT is a by-value struct: x86 uses the wrapper, x64 a vtable call. See __WV2_PutBounds.
	Local $bOk = __WV2_PutBounds($iHandle, $__WV2_iLeft[$iHandle], $__WV2_iTop[$iHandle], $__WV2_iRight[$iHandle], $__WV2_iBottom[$iHandle])
	Return SetError($__WV2_iLastError, $__WV2_iLastHR, $bOk)
EndFunc   ;==>_WV2_SetBounds

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_GetBounds
; Description ...: Reads the browser area currently used inside the parent window.
; Syntax ........: _WV2_GetBounds($iHandle, $iLeft, $iTop, $iWidth, $iHeight)
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $iLeft - Variable receiving the X coordinate, passed by reference.
;                  $iTop - Variable receiving the Y coordinate, passed by reference.
;                  $iWidth - Variable receiving the width, passed by reference.
;                  $iHeight - Variable receiving the height, passed by reference.
; Return values .: Success: 1, @error = 0.
;                  Failure: 0, with @error set to a $WV2_ERR_* code and @extended set to the raw HRESULT (0 if none).
; Author ........: Numeric1
; Related .......: _WV2_SetBounds
; ===============================================================================================================================
Func _WV2_GetBounds($iHandle, ByRef $iLeft, ByRef $iTop, ByRef $iWidth, ByRef $iHeight)
	$__WV2_sLastFunc = "_WV2_GetBounds"
	$iLeft = 0
	$iTop = 0
	$iWidth = 0
	$iHeight = 0
	If Not __WV2_GuardCtl($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	Local $tRc = DllStructCreate("long left;long top;long right;long bottom")
	Local $hr = $__WV2_oCtl[$iHandle].get_Bounds($tRc)
	If $hr <> 0 Then
		__WV2_Result($hr, "ICoreWebView2Controller::get_Bounds")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	$iLeft = DllStructGetData($tRc, "left")
	$iTop = DllStructGetData($tRc, "top")
	$iWidth = DllStructGetData($tRc, "right") - $iLeft
	$iHeight = DllStructGetData($tRc, "bottom") - $iTop
	Return SetError(0, 0, 1)
EndFunc   ;==>_WV2_GetBounds

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_FitToParent
; Description ...: Resizes the browser so that it covers the whole client area of its parent window.
; Syntax ........: _WV2_FitToParent($iHandle)
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
; Return values .: Success: 1, failure: 0 with @error / @extended as for _WV2_Navigate.
; Author ........: Numeric1
; Remarks .......: Call it from a WM_SIZE handler to keep the browser in step with its window.
; Related .......: _WV2_SetBounds
; ===============================================================================================================================
Func _WV2_FitToParent($iHandle)
	$__WV2_sLastFunc = "_WV2_FitToParent"
	If Not __WV2_GuardCtl($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	__WV2_ClientSize($__WV2_hParent[$iHandle])
	Return _WV2_SetBounds($iHandle, 0, 0, $__WV2_iClientW, $__WV2_iClientH)
EndFunc   ;==>_WV2_FitToParent

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_SetVisible
; Description ...: Shows or hides the browser without destroying it.
; Syntax ........: _WV2_SetVisible($iHandle, $bVisible)
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $bVisible - True to show, False to hide.
; Return values .: Success: 1, failure: 0 with @error / @extended as for _WV2_Navigate.
; Author ........: Numeric1
; Related .......: _WV2_SetBounds
; ===============================================================================================================================
Func _WV2_SetVisible($iHandle, $bVisible)
	$__WV2_sLastFunc = "_WV2_SetVisible"
	If Not __WV2_GuardCtl($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	Local $hr = $__WV2_oCtl[$iHandle].put_IsVisible($bVisible ? 1 : 0)
	Local $bOk = __WV2_Result($hr, "ICoreWebView2Controller::put_IsVisible")
	Return SetError($__WV2_iLastError, $__WV2_iLastHR, $bOk)
EndFunc   ;==>_WV2_SetVisible

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_SetZoom
; Description ...: Sets the zoom factor of the page.
; Syntax ........: _WV2_SetZoom($iHandle, $fZoom)
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $fZoom - From 0.2 to 10; 1 is 100 %.
; Return values .: Success: 1, failure: 0 with @error / @extended as for _WV2_Navigate.
; Author ........: Numeric1
; Related .......: _WV2_GetZoom
; ===============================================================================================================================
Func _WV2_SetZoom($iHandle, $fZoom)
	$__WV2_sLastFunc = "_WV2_SetZoom"
	If Not __WV2_GuardCtl($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	$fZoom = Number($fZoom)
	If $fZoom < 0.2 Or $fZoom > 10 Then
		__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_SetZoom")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	Local $hr = $__WV2_oCtl[$iHandle].put_ZoomFactor($fZoom)
	Local $bOk = __WV2_Result($hr, "ICoreWebView2Controller::put_ZoomFactor")
	Return SetError($__WV2_iLastError, $__WV2_iLastHR, $bOk)
EndFunc   ;==>_WV2_SetZoom

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_GetZoom
; Description ...: Reads the zoom factor of the page.
; Syntax ........: _WV2_GetZoom($iHandle)
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
; Return values .: Success: the zoom as a number, @error = 0.
;                  Failure: -1, with @error set to a $WV2_ERR_* code and @extended set to the raw HRESULT (0 if none).
; Author ........: Numeric1
; Related .......: _WV2_SetZoom
; ===============================================================================================================================
Func _WV2_GetZoom($iHandle)
	$__WV2_sLastFunc = "_WV2_GetZoom"
	If Not __WV2_GuardCtl($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	Local $d = 0
	Local $hr = $__WV2_oCtl[$iHandle].get_ZoomFactor($d)
	If $hr <> 0 Then
		__WV2_Result($hr, "ICoreWebView2Controller::get_ZoomFactor")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	EndIf
	Return SetError(0, 0, $d)
EndFunc   ;==>_WV2_GetZoom

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_Reload
; Description ...: Reloads the current document.
; Syntax ........: _WV2_Reload($iHandle)
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
; Return values .: Success: 1, failure: 0 with @error / @extended as for _WV2_Navigate.
; Author ........: Numeric1
; Related .......: _WV2_GoBack, _WV2_GoForward, _WV2_Stop
; ===============================================================================================================================
Func _WV2_Reload($iHandle)
	$__WV2_sLastFunc = "_WV2_Reload"
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	__WV2_BeginNavigation($iHandle)
	Local $bOk = __WV2_Result($__WV2_oWv[$iHandle].Reload(), "ICoreWebView2::Reload")
	Return SetError($__WV2_iLastError, $__WV2_iLastHR, $bOk)
EndFunc   ;==>_WV2_Reload

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_GoBack
; Description ...: Moves one entry back in the navigation history.
; Syntax ........: _WV2_GoBack($iHandle)
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
; Return values .: Success: 1, failure: 0 with @error / @extended as for _WV2_Navigate.
; Author ........: Numeric1
; Related .......: _WV2_CanGoBack, _WV2_GoForward
; ===============================================================================================================================
Func _WV2_GoBack($iHandle)
	$__WV2_sLastFunc = "_WV2_GoBack"
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	__WV2_BeginNavigation($iHandle)
	Local $bOk = __WV2_Result($__WV2_oWv[$iHandle].GoBack(), "ICoreWebView2::GoBack")
	Return SetError($__WV2_iLastError, $__WV2_iLastHR, $bOk)
EndFunc   ;==>_WV2_GoBack

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_GoForward
; Description ...: Moves one entry forward in the navigation history.
; Syntax ........: _WV2_GoForward($iHandle)
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
; Return values .: Success: 1, failure: 0 with @error / @extended as for _WV2_Navigate.
; Author ........: Numeric1
; Related .......: _WV2_CanGoForward, _WV2_GoBack
; ===============================================================================================================================
Func _WV2_GoForward($iHandle)
	$__WV2_sLastFunc = "_WV2_GoForward"
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	__WV2_BeginNavigation($iHandle)
	Local $bOk = __WV2_Result($__WV2_oWv[$iHandle].GoForward(), "ICoreWebView2::GoForward")
	Return SetError($__WV2_iLastError, $__WV2_iLastHR, $bOk)
EndFunc   ;==>_WV2_GoForward

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_Stop
; Description ...: Cancels the navigation in progress.
; Syntax ........: _WV2_Stop($iHandle)
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
; Return values .: Success: 1, failure: 0 with @error / @extended as for _WV2_Navigate.
; Author ........: Numeric1
; ===============================================================================================================================
Func _WV2_Stop($iHandle)
	$__WV2_sLastFunc = "_WV2_Stop"
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	Local $bOk = __WV2_Result($__WV2_oWv[$iHandle].Stop(), "ICoreWebView2::Stop")
	Return SetError($__WV2_iLastError, $__WV2_iLastHR, $bOk)
EndFunc   ;==>_WV2_Stop

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_CanGoBack
; Description ...: Tells whether the history holds an entry before the current one.
; Syntax ........: _WV2_CanGoBack($iHandle)
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
; Return values .: Success: 1 or 0, @error = 0.
;                  Failure: -1, with @error set to a $WV2_ERR_* code and @extended set to the raw HRESULT (0 if none).
; Author ........: Numeric1
; Related .......: _WV2_GoBack, _WV2_CanGoForward
; ===============================================================================================================================
Func _WV2_CanGoBack($iHandle)
	$__WV2_sLastFunc = "_WV2_CanGoBack"
	Local $iValue = __WV2_BoolMethod($iHandle, "get_CanGoBack", "ICoreWebView2::get_CanGoBack")
	Return SetError($__WV2_iLastError, $__WV2_iLastHR, $iValue)
EndFunc   ;==>_WV2_CanGoBack

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_CanGoForward
; Description ...: Tells whether the history holds an entry after the current one.
; Syntax ........: _WV2_CanGoForward($iHandle)
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
; Return values .: Success: 1 or 0, @error = 0.
;                  Failure: -1, with @error set to a $WV2_ERR_* code and @extended set to the raw HRESULT (0 if none).
; Author ........: Numeric1
; Related .......: _WV2_GoForward, _WV2_CanGoBack
; ===============================================================================================================================
Func _WV2_CanGoForward($iHandle)
	$__WV2_sLastFunc = "_WV2_CanGoForward"
	Local $iValue = __WV2_BoolMethod($iHandle, "get_CanGoForward", "ICoreWebView2::get_CanGoForward")
	Return SetError($__WV2_iLastError, $__WV2_iLastHR, $iValue)
EndFunc   ;==>_WV2_CanGoForward

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_GetBrowserVersion
; Description ...: Reads the version of the runtime driving a view.
; Syntax ........: _WV2_GetBrowserVersion($iHandle, $sVersion)
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $sVersion - Variable receiving the version, for instance "155.0.4283.62".
; Return values .: Success: 1, @error = 0.
;                  Failure: 0, with @error set to a $WV2_ERR_* code and @extended set to the raw HRESULT (0 if none).
; Author ........: Numeric1
; Related .......: _WV2_GetRuntimePath
; ===============================================================================================================================
Func _WV2_GetBrowserVersion($iHandle, ByRef $sVersion)
	$__WV2_sLastFunc = "_WV2_GetBrowserVersion"
	$sVersion = ""
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	If $__WV2_sVersion[$iHandle] <> "" Then
		$sVersion = $__WV2_sVersion[$iHandle]
		Return SetError(0, 0, 1)
	EndIf
	Local $s = ""
	Local $hr = $__WV2_oEnv[$iHandle].get_BrowserVersionString($s)
	If $hr <> 0 Then
		__WV2_Result($hr, "ICoreWebView2Environment::get_BrowserVersionString")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	$sVersion = $s
	$__WV2_sVersion[$iHandle] = $s
	Return SetError(0, 0, 1)
EndFunc   ;==>_WV2_GetBrowserVersion

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_GetLastErrorMessage
; Description ...: Builds a human readable description of the last failure.
; Syntax ........: _WV2_GetLastErrorMessage()
; Parameters ....: none
; Return values .: A string such as "Method call failed in ICoreWebView2::Navigate (HRESULT 0x80070057)",
;                  or "" when the last call succeeded. @error is always 0.
; Author ........: Numeric1
; Remarks .......: Read only view of the information every function reports through @error and
;                  @extended, which is handy while debugging.
; Related .......: _WV2_Create
; ===============================================================================================================================
Func _WV2_GetLastErrorMessage()
	If $__WV2_iLastError = $WV2_ERR_NONE Then Return SetError(0, 0, "")
	Local $s = $__WV2_sLastFunc
	If $__WV2_iLastHR <> 0 Then $s &= " (HRESULT 0x" & Hex($__WV2_iLastHR, 8) & ")"
	Return SetError(0, 0, __WV2_ErrText($__WV2_iLastError) & " in " & $s)
EndFunc   ;==>_WV2_GetLastErrorMessage

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_EnableEvent
; Description ...: Turns the queueing of one WebView2 event on or off for a view.
; Syntax ........: _WV2_EnableEvent($iHandle, $iEvent[, $bEnable = True])
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $iEvent - One of the $WV2_EVENT_* constants.
;                  $bEnable - True to receive the event, False to stop receiving it.
; Return values .: Success: 1.
;                  Failure: 0, with @error set to a $WV2_ERR_* code and @extended set to the raw HRESULT (0 if none).
; Author ........: Numeric1
; Remarks .......: $WV2_EVENT_NAVIGATION_COMPLETED is already enabled by _WV2_Create: leaving it off
;                  breaks _WV2_WaitNavigation, which waits on it. Two events carry a policy with them:
;                  while $WV2_EVENT_NAVIGATION_STARTING is enabled the filter of
;                  _WV2_SetNavigationFilter can cancel a navigation, and while
;                  $WV2_EVENT_NEW_WINDOW is enabled the popup window the page asks for is always
;                  cancelled, so a script embedding a page never has to chase a window it did not open.
;                  Enabling an event twice is allowed and does nothing. $WV2_EVENT_DEVTOOLS is the one
;                  event whose object belongs to another call: it hangs off the receiver that
;                  _WV2_SetDevToolsProtocolEvent asks for, so it may be written before or after that one -
;                  measured on runtime 156, an enable written first succeeds and the events of a name given
;                  afterwards reach the queue. A disable is the answer that is kept: while
;                  $WV2_EVENT_DEVTOOLS is off, a new event name subscribes nothing and stays unheard until
;                  the event is enabled again.
; Related .......: _WV2_GetEvent, _WV2_WaitEvent, _WV2_SetNavigationFilter
; ===============================================================================================================================
Func _WV2_EnableEvent($iHandle, $iEvent, $bEnable = True)
	$__WV2_sLastFunc = "_WV2_EnableEvent"
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	Local $iSlot = __WV2_EventSlot($iEvent)
	If $iSlot = 0 Then
		__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_EnableEvent")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	; The two download events are not events of the view: they hang off each operation, so what is
	; turned on here is the subscription of every download the view already keeps.
	If $iEvent = $WV2_EVENT_DOWNLOAD_STATE Or $iEvent = $WV2_EVENT_DOWNLOAD_PROGRESS Then
		$__WV2_bDlWatch[$iHandle] = $bEnable
		Local $j
		For $j = 1 To $WV2_DL_MAX
			If $__WV2_pDl[$iHandle][$j] = 0 Then ContinueLoop
			If $bEnable Then
				__WV2_DlSubscribe($iHandle, $j)
			Else
				__WV2_DlUnsubscribe($iHandle, $j)
			EndIf
		Next
		$__WV2_iLastError = $WV2_ERR_NONE
		$__WV2_iLastHR = 0
		Return SetError(0, 0, 1)
	EndIf
	; The DevTools event does not hang off the view but off the receiver object that
	; _WV2_SetDevToolsProtocolEvent asks for, so there is nothing to subscribe while no name is set.
	; Refusing that call was a mistake: it made the two depend on the order they were written in. The
	; intent is recorded instead and the call succeeds; only a disable is remembered, because a name
	; given afterwards subscribes as it always did unless the host asked for this event to stay off.
	If $iEvent = $WV2_EVENT_DEVTOOLS Then
		$__WV2_bCdpOff[$iHandle] = Not $bEnable
		If $__WV2_pCdpRecv[$iHandle] = 0 Then
			$__WV2_iLastError = $WV2_ERR_NONE
			$__WV2_iLastHR = 0
			Return SetError(0, 0, 1)
		EndIf
	EndIf
	If $bEnable Then
		If Not __WV2_Attach($iHandle, $iSlot) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	Else
		__WV2_Detach($iHandle, $iSlot)
	EndIf
	$__WV2_iLastError = $WV2_ERR_NONE
	$__WV2_iLastHR = 0
	Return SetError(0, 0, 1)
EndFunc   ;==>_WV2_EnableEvent

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_GetEvent
; Description ...: Reads the oldest event the view has queued.
; Syntax ........: _WV2_GetEvent($iHandle, $sData, $iValue)
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $sData - Variable receiving the text of the event, passed by reference.
;                  $iValue - Variable receiving the number of the event, passed by reference.
; Return values .: Success: a $WV2_EVENT_* code, 0 when the queue is empty. @error is always 0.
;                  Failure: -1 with @error set to a $WV2_ERR_* code.
;                  @extended carries the number of events dropped because the queue was full.
; Author ........: Numeric1
; Remarks .......: Nothing is read here: events are collected by the message loop of the thread, so
;                  call this from the GUI loop, after GUIGetMsg. Each event puts the meaning of $sData
;                  and $iValue in the $WV2_EVENT_* constant, and $iValue is 0 when it carries nothing.
;                  The queue keeps 64 events per view; the oldest is dropped when it overflows.
; Related .......: _WV2_WaitEvent, _WV2_EnableEvent
; ===============================================================================================================================
Func _WV2_GetEvent($iHandle, ByRef $sData, ByRef $iValue)
	$__WV2_sLastFunc = "_WV2_GetEvent"
	$sData = ""
	$iValue = 0
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	; The kinds this view gave a name to are answered here first: they are not what a by-hand read is
	; owed, and leaving them in front of the queue would make every later event wait for a pump.
	__WV2_DispatchQueued($iHandle, $__WV2_CB_CAP)
	Local $iType = 0
	__WV2_PopEvent($iHandle, $iType, $sData, $iValue)
	Return SetError(0, $__WV2_iEvtDrop[$iHandle], $iType)
EndFunc   ;==>_WV2_GetEvent

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_WaitEvent
; Description ...: Waits for the next event, of one type or of any type.
; Syntax ........: _WV2_WaitEvent($iHandle, $iEvent, $iTimeoutMs, $sData, $iValue)
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $iEvent - The $WV2_EVENT_* code to wait for, or 0 for the next event of any type.
;                  $iTimeoutMs - Time allowed, in milliseconds.
;                  $sData - Variable receiving the text of the event, passed by reference.
;                  $iValue - Variable receiving the number of the event, passed by reference.
; Return values .: Success: 1. @extended = 0, or the $WV2_EVENT_* code that arrived when $iEvent was 0.
;                  Failure: 0, with @error set to a $WV2_ERR_* code ($WV2_ERR_TIMEOUT when out of
;                  time, $WV2_ERR_ARG when the event cannot be waited for).
; Author ........: Numeric1
; Remarks .......: A named event has to be enabled first; 0 needs nothing, it empties the queue in the
;                  order the events arrived. With a type asked for, events of another type already in the
;                  queue stay there: this function takes the oldest event of the type asked for and leaves
;                  the rest in order for _WV2_GetEvent. With 0, the type is not known in advance, so it is
;                  reported in @extended only on this path - it stays 0 when a type was asked for, which is
;                  what callers of earlier builds could check. Windows messages are pumped while waiting.
;                  A kind that _WV2_SetEventHandler gave a name to belongs to that name, and waiting for
;                  it here is refused with $WV2_ERR_ARG rather than left to starve; so is a kind outside
;                  the $WV2_EVENT_* range, which is checked before the table of names is looked at.
; Related .......: _WV2_GetEvent, _WV2_EnableEvent
; ===============================================================================================================================
Func _WV2_WaitEvent($iHandle, $iEvent, $iTimeoutMs, ByRef $sData, ByRef $iValue)
	$__WV2_sLastFunc = "_WV2_WaitEvent"
	$sData = ""
	$iValue = 0
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	Local $bAny = ($iEvent = 0)
	If Not $bAny Then
		$iEvent = Number($iEvent)
		If $iEvent < 1 Or $iEvent > $__WV2_EV_MAX Then
			__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_WaitEvent")
			Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
		EndIf
		If $__WV2_aEvtCb[$iHandle][$iEvent] <> "" Then
			; This caller would be answered by its own handler before it could see the event, so the
			; wait would end in a timeout the script cannot explain. Said as an argument error.
			__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_WaitEvent")
			Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
		EndIf
		If Not __WV2_EventReady($iHandle, $iEvent) Then
			__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_WaitEvent")
			Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
		EndIf
	EndIf
	Local $tEnd = TimerInit()
	Local $iType = 0
	While 1
		__WV2_DispatchQueued($iHandle, $__WV2_CB_CAP)
		If $bAny Then
			If __WV2_PopEvent($iHandle, $iType, $sData, $iValue) Then
				$__WV2_iLastError = $WV2_ERR_NONE
				$__WV2_iLastHR = 0
				Return SetError(0, $iType, 1)
			EndIf
		ElseIf __WV2_PopEventOfType($iHandle, $iEvent, $sData, $iValue) Then
			$__WV2_iLastError = $WV2_ERR_NONE
			$__WV2_iLastHR = 0
			Return SetError(0, 0, 1)
		EndIf
		__WV2_Pump(20)
		If TimerDiff($tEnd) > $iTimeoutMs Then
			__WV2_SetErr($WV2_ERR_TIMEOUT, 0, "_WV2_WaitEvent")
			$sData = ""
			$iValue = 0
			Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
		EndIf
	WEnd
EndFunc   ;==>_WV2_WaitEvent

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_SetEventHandler
; Description ...: Names the AutoIt function that owns one event kind of one view, or removes it.
; Syntax ........: _WV2_SetEventHandler($iHandle, $iEvent[, $sFunc = ""])
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $iEvent - One $WV2_EVENT_* constant.
;                  $sFunc - Name of a function of the script, as a string. "" gives the kind back to
;                    the queue.
; Return values .: Success: 1, @error = 0, @extended = 0 when the name was new to this kind and 1 when
;                  it replaced the one already there.
;                  Failure: 0, with @error set to a $WV2_ERR_* code and @extended set to the raw HRESULT
;                  (0 if none); $WV2_ERR_ARG covers a kind this UDF does not know, a kind with no
;                  subscription to take and a malformed name, and $WV2_ERR_CALL the runtime refusing the
;                  subscription.
; Author ........: Numeric1
; Remarks .......: The function is called as Func Handler($iHandle, $iEvent, $sData, $iValue) with the
;                  same two payload cells _WV2_GetEvent would have given, and its return value is
;                  ignored: this is a notice, not a question. The four handlers that do have to answer -
;                  the dialog, the key, the menu and the resource one - are separate calls and keep
;                  their own contract.
;
;                  Installing here also enables the kind, exactly as _WV2_EnableEvent would, so the two
;                  orders of writing it both work; removing the name leaves the subscription on, which
;                  means the events keep arriving in the queue for a host that reads them by hand.
;
;                  The name is not a function of the script until the first event says so. Measured:
;                  IsDeclared does not look at functions at all, and Call answers the same @error
;                  57005 whether the name is missing or its shape does not fit, so there is nothing to
;                  check here. When that happens the name comes off the kind, the event goes back at the
;                  head of the queue and stays readable by hand - a wrong name costs one notice and
;                  nothing else - and the last error reads $WV2_ERR_CB with the name in it, which
;                  _WV2_GetLastErrorMessage gives.
;
;                  The handler runs when the queue is next read, not the moment the runtime speaks: in
;                  _WV2_GetEvent, in _WV2_WaitEvent, in _WV2_Run and in _WV2_DispatchEvents. That is a
;                  choice made on a measurement, not a limitation of the plumbing. A function entered
;                  while the UDF waits for an answer shares the answer slot with the call that waits:
;                  eight trials of a nested _WV2_ExecuteScript from that position brought back the wrong
;                  result seven times under AutoIt3.exe and all eight under AutoIt3_x64.exe, silently,
;                  with @error 0 on both sides. So no handler of this kind is ever entered from a wait
;                  for an answer, and a handler is free to call anything, including another call that
;                  waits.
;
;                  A kind with a name belongs to that name: _WV2_GetEvent, _WV2_WaitEvent with 0 and
;                  _WV2_WaitEvent with that kind no longer see it. The last of those answers
;                  $WV2_ERR_ARG, because the event the caller waits for would be taken by the handler
;                  first - measured, a draining handler and a waiting host on the same kind leaves the
;                  host with a timeout.
; Related .......: _WV2_GetEventHandler, _WV2_DispatchEvents, _WV2_ClearEventHandlers, _WV2_EnableEvent
; ===============================================================================================================================
Func _WV2_SetEventHandler($iHandle, $iEvent, $sFunc = "")
	$__WV2_sLastFunc = "_WV2_SetEventHandler"
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	$iEvent = Number($iEvent)
	If $iEvent < 1 Or $iEvent > $__WV2_EV_MAX Or __WV2_EventSlot($iEvent) = 0 Then
		__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_SetEventHandler")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	$sFunc = StringStripWS(String($sFunc), 3)
	If $sFunc <> "" And Not StringRegExp($sFunc, "^(?i)[a-z_][a-z0-9_]*$") Then
		__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_SetEventHandler")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	Local $sWas = $__WV2_aEvtCb[$iHandle][$iEvent]
	If $sFunc = $sWas Then Return SetError(0, 1, 1)
	If $sFunc = "" Then
		$__WV2_aEvtCb[$iHandle][$iEvent] = ""
		$__WV2_iEvtCbCount[$iHandle] -= 1
		$__WV2_iLastError = $WV2_ERR_NONE
		$__WV2_iLastHR = 0
		Return SetError(0, 1, 1)
	EndIf
	; The kind has to reach the queue before a handler can be given it, and the runtime has to be asked
	; for that. _WV2_EnableEvent is the one call that knows how, including the two download events and
	; the DevTools one that do not hang off the view; if it says no, it has already said why.
	If $sWas = "" And Not _WV2_EnableEvent($iHandle, $iEvent, True) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	$__WV2_aEvtCb[$iHandle][$iEvent] = $sFunc
	If $sWas = "" Then $__WV2_iEvtCbCount[$iHandle] += 1
	$__WV2_iLastError = $WV2_ERR_NONE
	$__WV2_iLastHR = 0
	Return SetError(0, $sWas <> "" ? 1 : 0, 1)
EndFunc   ;==>_WV2_SetEventHandler

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_GetEventHandler
; Description ...: Reads back the function that owns one event kind of one view.
; Syntax ........: _WV2_GetEventHandler($iHandle, $iEvent)
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $iEvent - One $WV2_EVENT_* constant.
; Return values .: Success: the name, as a string, "" when the kind has none, with @error = 0 and
;                  @extended = 1 when a handler owns it.
;                  Failure: "", with @error set to a $WV2_ERR_* code.
; Author ........: Numeric1
; Remarks .......: The name is the one that was given, not a check that the script carries it: measured,
;                  there is no way to ask AutoIt whether a name is a function before calling it.
; Related .......: _WV2_SetEventHandler
; ===============================================================================================================================
Func _WV2_GetEventHandler($iHandle, $iEvent)
	$__WV2_sLastFunc = "_WV2_GetEventHandler"
	$iEvent = Number($iEvent)
	If Not __WV2_Guard($iHandle) Or $iEvent < 1 Or $iEvent > $__WV2_EV_MAX Then
		If $__WV2_iLastError = $WV2_ERR_NONE Then __WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_GetEventHandler")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, "")
	EndIf
	Local $sName = $__WV2_aEvtCb[$iHandle][$iEvent]
	$__WV2_iLastError = $WV2_ERR_NONE
	$__WV2_iLastHR = 0
	Return SetError(0, $sName <> "" ? 1 : 0, $sName)
EndFunc   ;==>_WV2_GetEventHandler

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_ClearEventHandlers
; Description ...: Gives every event kind of one view back to the queue.
; Syntax ........: _WV2_ClearEventHandlers($iHandle)
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
; Return values .: Success: the number of names removed, with @error = 0 and @extended = the events of
;                  those kinds already waiting in the queue.
;                  Failure: -1, with @error set to a $WV2_ERR_* code.
; Author ........: Numeric1
; Remarks .......: The subscriptions stay as they were, so what the removed handlers used to swallow
;                  becomes readable by hand at once - which is what the @extended count is for: it is
;                  the number of events the next reads will give back.
; Related .......: _WV2_SetEventHandler, _WV2_GetEvent
; ===============================================================================================================================
Func _WV2_ClearEventHandlers($iHandle)
	$__WV2_sLastFunc = "_WV2_ClearEventHandlers"
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	Local $i, $n = 0
	For $i = 1 To $__WV2_EV_MAX
		If $__WV2_aEvtCb[$iHandle][$i] <> "" Then
			$__WV2_aEvtCb[$iHandle][$i] = ""
			$__WV2_iEvtCbCount[$iHandle] -= 1
			$n += 1
		EndIf
	Next
	$__WV2_iLastError = $WV2_ERR_NONE
	$__WV2_iLastHR = 0
	Return SetError(0, $__WV2_iEvtCount[$iHandle], $n)
EndFunc   ;==>_WV2_ClearEventHandlers

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_DispatchEvents
; Description ...: Hands the events the handlers own to those functions, now.
; Syntax ........: _WV2_DispatchEvents([$iHandle = 0[, $iMax = $__WV2_CB_CAP]])
; Parameters ....: $iHandle - Handle returned by _WV2_Create, or 0 for every live view.
;                  $iMax - Longest run of handlers this one call may start, 1 To 64.
; Return values .: Success: the number of handlers called, with @error = 0 and @extended = the events
;                  still in the queue or queues, of every kind.
;                  Failure: -1, with @error set to a $WV2_ERR_* code; $WV2_ERR_BUSY means the call came
;                  from inside a handler or from one of the four answering callbacks, which is the one
;                  position a second handler must not be entered in.
; Author ........: Numeric1
; Remarks .......: Nothing is pumped here: the events are already in the queue, and this takes the ones
;                  with a name in arrival order and calls. A script that never reads the queue by hand
;                  and does not use _WV2_Run has one line to write in its own loop, and that line is
;                  this call - with 0 it is cheap, a view with no handler is skipped before its queue is
;                  looked at.
;                  Events are taken one kind at a time in the order they arrived, so a page that posts a
;                  message and then navigates is answered in that order. When a handler cannot be called
;                  the pass stops there, having put that event back, so the order of what is left is the
;                  order it arrived in.
; Related .......: _WV2_SetEventHandler, _WV2_GetEvent, _WV2_Run
; ===============================================================================================================================
Func _WV2_DispatchEvents($iHandle = 0, $iMax = $__WV2_CB_CAP)
	$__WV2_sLastFunc = "_WV2_DispatchEvents"
	If $iHandle <> 0 And Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	$iMax = Number($iMax)
	If $iMax < 1 Then $iMax = 1
	If $iMax > $__WV2_QCAP Then $iMax = $__WV2_QCAP
	; The one position a second handler must not be entered in is a callback that has to answer: the
	; page stands still for it, and the objects it walks are its own. Said here rather than left to
	; the silent refusal the internal hooks get.
	Local $bBusy = $__WV2_bDispatching, $j
	If Not $bBusy And $iHandle <> 0 Then $bBusy = ($__WV2_bInCb[$iHandle] Or $__WV2_bInRes[$iHandle])
	If Not $bBusy Then
		For $j = 1 To $__WV2_MAX
			If $__WV2_aUsed[$j] And ($__WV2_bInCb[$j] Or $__WV2_bInRes[$j]) Then
				$bBusy = True
				ExitLoop
			EndIf
		Next
	EndIf
	If $bBusy Then
		__WV2_SetErr($WV2_ERR_BUSY, 0, "_WV2_DispatchEvents")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	EndIf
	Local $iCalled = __WV2_DispatchQueued($iHandle, $iMax)
	Local $i, $iLeft = 0
	For $i = 1 To $__WV2_MAX
		If $__WV2_aUsed[$i] And ($iHandle = 0 Or $i = $iHandle) Then $iLeft += $__WV2_iEvtCount[$i]
	Next
	Return SetError(0, $iLeft, $iCalled)
EndFunc   ;==>_WV2_DispatchEvents

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_SetNavigationFilter
; Description ...: Refuses the navigations whose URL matches a regular expression.
; Syntax ........: _WV2_SetNavigationFilter($iHandle, $sFilter)
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $sFilter - PCRE pattern matched against the URL, "" (the default) allows everything.
; Return values .: Success: 1, @error = 0.
;                  Failure: 0, with @error set to a $WV2_ERR_* code.
; Author ........: Numeric1
; Remarks .......: The filter is read inside the NavigationStarting callback, so it only works while
;                  $WV2_EVENT_NAVIGATION_STARTING is enabled. A cancelled navigation still reaches
;                  the queue: _WV2_GetEvent reports which URL was refused.
; Related .......: _WV2_EnableEvent
; ===============================================================================================================================
Func _WV2_SetNavigationFilter($iHandle, $sFilter)
	$__WV2_sLastFunc = "_WV2_SetNavigationFilter"
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	If Not IsString($sFilter) Then $sFilter = String($sFilter)
	$__WV2_sNavFilter[$iHandle] = $sFilter
	Return SetError(0, 0, 1)
EndFunc   ;==>_WV2_SetNavigationFilter

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_SetDownloadFolder
; Description ...: Chooses the folder the downloads of the page land in.
; Syntax ........: _WV2_SetDownloadFolder($iHandle, $sFolder)
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $sFolder - An existing folder, "" (the default) leaving the choice to the runtime.
; Return values .: Success: 1, @error = 0.
;                  Failure: 0, with @error set to a $WV2_ERR_* code ($WV2_ERR_ARG when $sFolder is not
;                  an existing folder, the error of the subscription otherwise) and @extended set to
;                  the raw HRESULT (0 if none).
; Author ........: Numeric1
; Remarks .......: The file name chosen by the runtime - it comes from the server or from the link - is
;                  kept, only its folder is replaced. The download itself goes on in the browser
;                  process: this says where the file ends up, nothing else. A relative path is completed
;                  with the current directory and a trailing separator is dropped.
;
;                  The call enables $WV2_EVENT_DOWNLOAD_STARTING so the folder applies without a
;                  separate _WV2_EnableEvent, and every download is then queued: _WV2_GetEvent gives the
;                  URI the page asked for, with $iValue = 0. Pass "" to hand the choice back to the
;                  runtime.
; Related .......: _WV2_SetDownloadFilter, _WV2_EnableEvent, _WV2_SetNavigationFilter
; ===============================================================================================================================
Func _WV2_SetDownloadFolder($iHandle, $sFolder)
	$__WV2_sLastFunc = "_WV2_SetDownloadFolder"
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	If Not IsString($sFolder) Then $sFolder = String($sFolder)
	Local $sPath = StringStripWS($sFolder, 3)
	; A separator left at the end would double up when the file name is appended to the folder.
	While StringRight($sPath, 1) = "\" Or StringRight($sPath, 1) = "/"
		$sPath = StringTrimRight($sPath, 1)
	WEnd
	If $sPath <> "" And Not StringInStr($sPath, "\") And Not StringInStr($sPath, "/") Then $sPath = _PathFull($sPath)
	If $sPath <> "" And Not StringInStr(FileGetAttrib($sPath), "D") Then
		__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_SetDownloadFolder")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	If Not __WV2_Attach($iHandle, $__WV2_H_DOWNLOAD) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	$__WV2_sDlFolder[$iHandle] = $sPath
	$__WV2_iLastError = $WV2_ERR_NONE
	$__WV2_iLastHR = 0
	Return SetError(0, 0, 1)
EndFunc   ;==>_WV2_SetDownloadFolder

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_SetDownloadFilter
; Description ...: Refuses the downloads whose URI matches a regular expression.
; Syntax ........: _WV2_SetDownloadFilter($iHandle, $sFilter)
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $sFilter - PCRE pattern matched against the URI of the download, "" (the default)
;                   allows everything.
; Return values .: Success: 1, @error = 0.
;                  Failure: 0, with @error set to a $WV2_ERR_* code and @extended set to the raw
;                  HRESULT (0 if none).
; Author ........: Numeric1
; Remarks .......: A refused download never reaches the disk and the browser process is told before a
;                  single byte moves. It still goes to the event queue, with $iValue = 1, so the program
;                  can say what was blocked. Like _WV2_SetDownloadFolder, the call enables
;                  $WV2_EVENT_DOWNLOAD_STARTING by itself.
; Related .......: _WV2_SetDownloadFolder, _WV2_SetNavigationFilter, _WV2_GetEvent
; ===============================================================================================================================
Func _WV2_SetDownloadFilter($iHandle, $sFilter)
	$__WV2_sLastFunc = "_WV2_SetDownloadFilter"
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	If Not IsString($sFilter) Then $sFilter = String($sFilter)
	If Not __WV2_Attach($iHandle, $__WV2_H_DOWNLOAD) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	$__WV2_sDlFilter[$iHandle] = $sFilter
	$__WV2_iLastError = $WV2_ERR_NONE
	$__WV2_iLastHR = 0
	Return SetError(0, 0, 1)
EndFunc   ;==>_WV2_SetDownloadFilter

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_ExecuteScript
; Description ...: Runs JavaScript in the page and brings the answer back.
; Syntax ........: _WV2_ExecuteScript($iHandle, $sScript, $sResult[, $iTimeoutMs = $WV2_EXEC_TIMEOUT])
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $sScript - JavaScript to run.
;                  $sResult - Variable receiving the answer, passed by reference.
;                  $iTimeoutMs - Time allowed for the page to answer, in milliseconds.
; Return values .: Success: 1, @extended = 0.
;                  Failure: 0, with @error set to a $WV2_ERR_* code and @extended set to the raw
;                  HRESULT (0 if none).
; Author ........: Numeric1
; Remarks .......: $sResult is the JSON text produced by the runtime for the last expression: a number
;                  comes back bare (42), a string between quotes ("text"), an object as its JSON
;                  ({"a":1}). A script that throws is not a failure: the runtime answers successfully
;                  and $sResult becomes null, which is also what a script with no result gives. When a
;                  script can fail, have it return something you can test instead.
;                  Only one script may run at a time per view. Windows messages are pumped while
;                  waiting.
; Related .......: _WV2_AddScriptToExecuteOnDocumentCreated, _WV2_PostWebMessageAsString
; ===============================================================================================================================
Func _WV2_ExecuteScript($iHandle, $sScript, ByRef $sResult, $iTimeoutMs = $WV2_EXEC_TIMEOUT)
	$__WV2_sLastFunc = "_WV2_ExecuteScript"
	$sResult = ""
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	If Not IsString($sScript) Or $sScript = "" Then
		__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_ExecuteScript")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	__WV2_BeginOp($iHandle, $__WV2_H_EXEC)
	Local $hr = $__WV2_oWv[$iHandle].ExecuteScript($sScript, $__WV2_pObj[$iHandle][$__WV2_H_EXEC])
	If $hr <> 0 Then
		__WV2_SetErr($WV2_ERR_CALL, $hr, "ICoreWebView2::ExecuteScript")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	If Not __WV2_WaitOp($iHandle, $__WV2_H_EXEC, $iTimeoutMs) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	Local $iScriptHR = $__WV2_iOpHR[$iHandle][$__WV2_H_EXEC]
	$sResult = $__WV2_sOpOut[$iHandle][$__WV2_H_EXEC]
	If $iScriptHR <> 0 Then
		__WV2_SetErr($WV2_ERR_CALL, 1, "ICoreWebView2::ExecuteScript")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	$__WV2_iLastError = $WV2_ERR_NONE
	$__WV2_iLastHR = 0
	Return SetError(0, 0, 1)
EndFunc   ;==>_WV2_ExecuteScript

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_AddScriptToExecuteOnDocumentCreated
; Description ...: Registers JavaScript that runs in every document as soon as it is created.
; Syntax ........: _WV2_AddScriptToExecuteOnDocumentCreated($iHandle, $sScript, $sId[, $iTimeoutMs = $WV2_EXEC_TIMEOUT])
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $sScript - JavaScript, run before the scripts of the page.
;                  $sId - Variable receiving the identifier the runtime gives the script, passed by
;                    reference; keep it for _WV2_RemoveScriptToExecuteOnDocumentCreated.
;                  $iTimeoutMs - Time allowed for the runtime to answer, in milliseconds.
; Return values .: Success: 1, @error = 0.
;                  Failure: 0, with @error set to a $WV2_ERR_* code and @extended set to the raw HRESULT (0 if none).
; Author ........: Numeric1
; Remarks .......: The script reaches the main frame of every page loaded afterwards by this view,
;                  which is how a page is given a bridge before its own code runs.
; Related .......: _WV2_RemoveScriptToExecuteOnDocumentCreated, _WV2_ExecuteScript
; ===============================================================================================================================
Func _WV2_AddScriptToExecuteOnDocumentCreated($iHandle, $sScript, ByRef $sId, $iTimeoutMs = $WV2_EXEC_TIMEOUT)
	$__WV2_sLastFunc = "_WV2_AddScriptToExecuteOnDocumentCreated"
	$sId = ""
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	If Not IsString($sScript) Or $sScript = "" Then
		__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_AddScriptToExecuteOnDocumentCreated")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	__WV2_BeginOp($iHandle, $__WV2_H_ADDSCRIPT)
	Local $hr = $__WV2_oWv[$iHandle].AddScriptToExecuteOnDocumentCreated($sScript, $__WV2_pObj[$iHandle][$__WV2_H_ADDSCRIPT])
	If $hr <> 0 Then
		__WV2_SetErr($WV2_ERR_CALL, $hr, "ICoreWebView2::AddScriptToExecuteOnDocumentCreated")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	If Not __WV2_WaitOp($iHandle, $__WV2_H_ADDSCRIPT, $iTimeoutMs) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	If $__WV2_iOpHR[$iHandle][$__WV2_H_ADDSCRIPT] <> 0 Then
		__WV2_SetErr($WV2_ERR_CALL, $__WV2_iOpHR[$iHandle][$__WV2_H_ADDSCRIPT], "ICoreWebView2::AddScriptToExecuteOnDocumentCreated")
		$sId = $__WV2_sOpOut[$iHandle][$__WV2_H_ADDSCRIPT]
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	$sId = $__WV2_sOpOut[$iHandle][$__WV2_H_ADDSCRIPT]
	$__WV2_iLastError = $WV2_ERR_NONE
	$__WV2_iLastHR = 0
	Return SetError(0, 0, 1)
EndFunc   ;==>_WV2_AddScriptToExecuteOnDocumentCreated

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_RemoveScriptToExecuteOnDocumentCreated
; Description ...: Removes a script registered by _WV2_AddScriptToExecuteOnDocumentCreated.
; Syntax ........: _WV2_RemoveScriptToExecuteOnDocumentCreated($iHandle, $sId)
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $sId - Identifier returned with the script.
; Return values .: Success: 1, failure: 0 with @error / @extended as for _WV2_ExecuteScript.
; Author ........: Numeric1
; Remarks .......: Pages already loaded keep the script: it only stops running for the next documents.
; Related .......: _WV2_AddScriptToExecuteOnDocumentCreated
; ===============================================================================================================================
Func _WV2_RemoveScriptToExecuteOnDocumentCreated($iHandle, $sId)
	$__WV2_sLastFunc = "_WV2_RemoveScriptToExecuteOnDocumentCreated"
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	If Not IsString($sId) Or $sId = "" Then
		__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_RemoveScriptToExecuteOnDocumentCreated")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	Local $hr = $__WV2_oWv[$iHandle].RemoveScriptToExecuteOnDocumentCreated($sId)
	Local $bOk = __WV2_Result($hr, "ICoreWebView2::RemoveScriptToExecuteOnDocumentCreated")
	Return SetError($__WV2_iLastError, $__WV2_iLastHR, $bOk)
EndFunc   ;==>_WV2_RemoveScriptToExecuteOnDocumentCreated

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_PostWebMessage
; Description ...: Sends a JSON value from the host to the page.
; Syntax ........: _WV2_PostWebMessage($iHandle, $sJson)
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $sJson - Valid JSON, for instance '{"cmd":"refresh"}'.
; Return values .: Success: 1, failure: 0 with @error / @extended as for _WV2_Navigate.
; Author ........: Numeric1
; Remarks .......: The page receives it through window.chrome.webview.addEventListener("message").
;                  Malformed JSON is refused by the runtime, which reports it as $WV2_ERR_CALL.
; Related .......: _WV2_PostWebMessageAsString, _WV2_EnableEvent
; ===============================================================================================================================
Func _WV2_PostWebMessage($iHandle, $sJson)
	$__WV2_sLastFunc = "_WV2_PostWebMessage"
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	If Not IsString($sJson) Or $sJson = "" Then
		__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_PostWebMessage")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	Local $hr = $__WV2_oWv[$iHandle].PostWebMessageAsJson($sJson)
	Local $bOk = __WV2_Result($hr, "ICoreWebView2::PostWebMessageAsJson")
	Return SetError($__WV2_iLastError, $__WV2_iLastHR, $bOk)
EndFunc   ;==>_WV2_PostWebMessage

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_PostWebMessageAsString
; Description ...: Sends a plain string from the host to the page.
; Syntax ........: _WV2_PostWebMessageAsString($iHandle, $sText)
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $sText - The string, read as it is by the page.
; Return values .: Success: 1, failure: 0 with @error / @extended as for _WV2_Navigate.
; Author ........: Numeric1
; Remarks .......: The page listens with window.chrome.webview.addEventListener("message", handler)
;                  and finds the string in handler.data, which is what makes this form easier than
;                  JSON on both sides of the bridge.
; Related .......: _WV2_PostWebMessage
; ===============================================================================================================================
Func _WV2_PostWebMessageAsString($iHandle, $sText)
	$__WV2_sLastFunc = "_WV2_PostWebMessageAsString"
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	If Not IsString($sText) Then $sText = String($sText)
	Local $hr = $__WV2_oWv[$iHandle].PostWebMessageAsString($sText)
	Local $bOk = __WV2_Result($hr, "ICoreWebView2::PostWebMessageAsString")
	Return SetError($__WV2_iLastError, $__WV2_iLastHR, $bOk)
EndFunc   ;==>_WV2_PostWebMessageAsString

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_SettingRead
; Description ...: Reads one setting of a view.
; Syntax ........: _WV2_SettingRead($iHandle, $sName)
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $sName - One of: IsScriptEnabled, IsWebMessageEnabled, AreDefaultScriptDialogsEnabled,
;                    IsStatusBarEnabled, AreDevToolsEnabled, AreDefaultContextMenusEnabled,
;                    AreHostObjectsAllowed, IsZoomControlEnabled, IsBuiltInErrorPageEnabled.
; Return values .: Success: 1 or 0, @error = 0.
;                  Failure: -1, with @error set to a $WV2_ERR_* code and @extended set to the raw HRESULT (0 if none).
; Author ........: Numeric1
; Related .......: _WV2_SettingWrite
; ===============================================================================================================================
Func _WV2_SettingRead($iHandle, $sName)
	$__WV2_sLastFunc = "_WV2_SettingRead"
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	Local $oSettings = __WV2_Settings($iHandle)
	If Not IsObj($oSettings) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	Local $iValue = 0
	Local $hr = 0
	Switch StringStripWS($sName, 8)
		Case "IsScriptEnabled"
			$hr = $oSettings.get_IsScriptEnabled($iValue)
		Case "IsWebMessageEnabled"
			$hr = $oSettings.get_IsWebMessageEnabled($iValue)
		Case "AreDefaultScriptDialogsEnabled"
			$hr = $oSettings.get_AreDefaultScriptDialogsEnabled($iValue)
		Case "IsStatusBarEnabled"
			$hr = $oSettings.get_IsStatusBarEnabled($iValue)
		Case "AreDevToolsEnabled"
			$hr = $oSettings.get_AreDevToolsEnabled($iValue)
		Case "AreDefaultContextMenusEnabled"
			$hr = $oSettings.get_AreDefaultContextMenusEnabled($iValue)
		Case "AreHostObjectsAllowed"
			$hr = $oSettings.get_AreHostObjectsAllowed($iValue)
		Case "IsZoomControlEnabled"
			$hr = $oSettings.get_IsZoomControlEnabled($iValue)
		Case "IsBuiltInErrorPageEnabled"
			$hr = $oSettings.get_IsBuiltInErrorPageEnabled($iValue)
		Case Else
			__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_SettingRead")
			Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	EndSwitch
	If $hr <> 0 Then
		__WV2_SetErr($WV2_ERR_CALL, $hr, "ICoreWebView2Settings::get_" & $sName)
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	EndIf
	$__WV2_iLastError = $WV2_ERR_NONE
	Return SetError(0, 0, $iValue ? 1 : 0)
EndFunc   ;==>_WV2_SettingRead

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_SettingWrite
; Description ...: Changes one setting of a view.
; Syntax ........: _WV2_SettingWrite($iHandle, $sName, $bValue)
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $sName - The same nine names as _WV2_SettingRead.
;                  $bValue - True to turn the setting on, False to turn it off.
; Return values .: Success: 1, failure: 0 with @error / @extended as for _WV2_Navigate.
; Author ........: Numeric1
; Remarks .......: The change applies to every page this view loads from now on, and the name is
;                  matched without regard to case or spaces.
; Related .......: _WV2_SettingRead
; ===============================================================================================================================
Func _WV2_SettingWrite($iHandle, $sName, $bValue)
	$__WV2_sLastFunc = "_WV2_SettingWrite"
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	Local $oSettings = __WV2_Settings($iHandle)
	If Not IsObj($oSettings) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	Local $iValue = ($bValue ? 1 : 0)
	Local $hr = 0
	Switch StringStripWS($sName, 8)
		Case "IsScriptEnabled"
			$hr = $oSettings.put_IsScriptEnabled($iValue)
		Case "IsWebMessageEnabled"
			$hr = $oSettings.put_IsWebMessageEnabled($iValue)
		Case "AreDefaultScriptDialogsEnabled"
			$hr = $oSettings.put_AreDefaultScriptDialogsEnabled($iValue)
		Case "IsStatusBarEnabled"
			$hr = $oSettings.put_IsStatusBarEnabled($iValue)
		Case "AreDevToolsEnabled"
			$hr = $oSettings.put_AreDevToolsEnabled($iValue)
		Case "AreDefaultContextMenusEnabled"
			$hr = $oSettings.put_AreDefaultContextMenusEnabled($iValue)
		Case "AreHostObjectsAllowed"
			$hr = $oSettings.put_AreHostObjectsAllowed($iValue)
		Case "IsZoomControlEnabled"
			$hr = $oSettings.put_IsZoomControlEnabled($iValue)
		Case "IsBuiltInErrorPageEnabled"
			$hr = $oSettings.put_IsBuiltInErrorPageEnabled($iValue)
		Case Else
			__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_SettingWrite")
			Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndSwitch
	Local $bOk = __WV2_Result($hr, "ICoreWebView2Settings::put_" & $sName)
	Return SetError($__WV2_iLastError, $__WV2_iLastHR, $bOk)
EndFunc   ;==>_WV2_SettingWrite

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_CapturePreview
; Description ...: Saves what the view currently shows as a PNG or JPEG file.
; Syntax ........: _WV2_CapturePreview($iHandle, $sFile[, $iFormat = $WV2_IMAGE_PNG[, $iTimeoutMs = $WV2_EXEC_TIMEOUT]])
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $sFile - Full path of the image to write; an existing file is replaced.
;                  $iFormat - $WV2_IMAGE_PNG (default) or $WV2_IMAGE_JPEG.
;                  $iTimeoutMs - Time allowed for the runtime to draw, in milliseconds.
; Return values .: Success: 1, @error = 0.
;                  Failure: 0, with @error set to a $WV2_ERR_* code ($WV2_ERR_FILE when the image was
;                  produced but could not be written) and @extended set to the raw HRESULT (0 if none).
; Author ........: Numeric1
; Remarks .......: The image is built in memory by the runtime and written by this function, so no
;                  temporary file is left behind. A view that is hidden or has never painted gives an
;                  empty or black image, which is what Chromium itself reports.
; Related .......: _WV2_SetVisible
; ===============================================================================================================================
Func _WV2_CapturePreview($iHandle, $sFile, $iFormat = $WV2_IMAGE_PNG, $iTimeoutMs = $WV2_EXEC_TIMEOUT)
	$__WV2_sLastFunc = "_WV2_CapturePreview"
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	If Not IsString($sFile) Or StringStripWS($sFile, 3) = "" Then
		__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_CapturePreview")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	If $iFormat <> $WV2_IMAGE_PNG And $iFormat <> $WV2_IMAGE_JPEG Then
		__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_CapturePreview")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf

	; The folder is checked before the runtime is asked, so a missing one is a plain $WV2_ERR_FILE
	; instead of a capture the runtime refused for its own reasons.
	Local $sPath = _PathFull($sFile)
	Local $sDrv = "", $sDir = "", $sName = "", $sExt = ""
	_PathSplit($sPath, $sDrv, $sDir, $sName, $sExt)
	If $sDrv & $sDir <> "" And Not FileExists($sDrv & $sDir) Then
		__WV2_SetErr($WV2_ERR_FILE, 0, "_WV2_CapturePreview")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf

	; An in-memory IStream is enough: ole32 builds it, the runtime writes into it, and releasing the
	; stream releases the memory block it holds. The pointer is used raw all the way through.
	Local $aCS = DllCall("ole32.dll", "long", "CreateStreamOnHGlobal", "ptr", 0, "int", 1, "ptr*", 0)
	If @Error Or Not IsArray($aCS) Or $aCS[0] <> 0 Then
		__WV2_SetErr($WV2_ERR_COM, (@Error ? 0 : $aCS[0]), "CreateStreamOnHGlobal")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	Local $pStream = $aCS[3]

	__WV2_BeginOp($iHandle, $__WV2_H_CAP)
	Local $hr = $__WV2_oWv[$iHandle].CapturePreview($iFormat, $pStream, $__WV2_pObj[$iHandle][$__WV2_H_CAP])
	If $hr <> 0 Then
		__WV2_ReleaseExternal($pStream)
		__WV2_SetErr($WV2_ERR_CALL, $hr, "ICoreWebView2::CapturePreview")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	If Not __WV2_WaitOp($iHandle, $__WV2_H_CAP, $iTimeoutMs) Then
		__WV2_ReleaseExternal($pStream)
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	Local $iDrawHR = $__WV2_iOpHR[$iHandle][$__WV2_H_CAP]
	If $iDrawHR <> 0 Then
		__WV2_ReleaseExternal($pStream)
		__WV2_SetErr($WV2_ERR_CALL, $iDrawHR, "ICoreWebView2CapturePreviewCompletedHandler")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf

	; Read the block back before releasing the stream, which is what frees it.
	; GlobalSize is a SIZE_T, so it is asked for as uint_ptr: a "ptr" return would arrive as a
	; hexadecimal string instead of a number.
	Local $aGH = DllCall("ole32.dll", "long", "GetHGlobalFromStream", "ptr", $pStream, "ptr*", 0)
	Local $hGlob = ((Not @Error) And IsArray($aGH) And $aGH[0] = 0 ? $aGH[2] : 0)
	Local $bImage = Binary("")
	If $hGlob <> 0 Then
		Local $aSZ = DllCall("kernel32.dll", "uint_ptr", "GlobalSize", "ptr", $hGlob)
		Local $iSize = ((Not @Error) And IsArray($aSZ) ? $aSZ[0] : 0)
		If $iSize > 0 Then
			; GlobalLock also returns a pointer, which has to be turned back into a number before it
			; can be used as the address of a structure.
			Local $aLK = DllCall("kernel32.dll", "ptr", "GlobalLock", "ptr", $hGlob)
			If (Not @Error) And IsArray($aLK) And Number($aLK[0]) <> 0 Then
				Local $tRaw = DllStructCreate("byte[" & $iSize & "]", Number($aLK[0]))
				If Not @Error Then $bImage = DllStructGetData($tRaw, 1)
				DllCall("kernel32.dll", "int", "GlobalUnlock", "ptr", $hGlob)
			EndIf
		EndIf
	EndIf
	__WV2_ReleaseExternal($pStream)

	If BinaryLen($bImage) = 0 Then
		__WV2_SetErr($WV2_ERR_CALL, 0, "ICoreWebView2::CapturePreview")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	; 16 alone is binary read, which fails when the file does not exist yet: 2 is what asks for the
	; write, and it clears a file already sitting at that path.
	Local $hOut = FileOpen($sFile, 16 + 2)
	If $hOut = -1 Then
		__WV2_SetErr($WV2_ERR_FILE, 0, "_WV2_CapturePreview")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	Local $bWritten = FileWrite($hOut, $bImage)
	FileClose($hOut)
	If Not $bWritten Then
		__WV2_SetErr($WV2_ERR_FILE, 0, "_WV2_CapturePreview")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	$__WV2_iLastError = $WV2_ERR_NONE
	$__WV2_iLastHR = 0
	Return SetError(0, 0, 1)
EndFunc   ;==>_WV2_CapturePreview

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_PrintToPdf
; Description ...: Writes the page to a PDF file.
; Syntax ........: _WV2_PrintToPdf($iHandle, $sFile[, $iTimeoutMs = $WV2_PRINT_TIMEOUT])
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $sFile - Path of the PDF to write. A relative path is completed with the current
;                   directory. The folder it points to has to exist.
;                  $iTimeoutMs - Time allowed for the page to print, in milliseconds.
; Return values .: Success: 1, @error = 0.
;                  Failure: 0, with @error set to a $WV2_ERR_* code and @extended set to the raw
;                  HRESULT (0 if none). $WV2_ERR_FILE means the folder is missing or the runtime
;                  refused to write the file; $WV2_ERR_CALL carries the HRESULT of the refusal.
; Author ........: Numeric1
; Remarks .......: The page is printed with the defaults of the runtime: portrait, its own paper size,
;                  no header, no footer, backgrounds left out. ICoreWebView2_7::PrintToPdf takes an
;                  ICoreWebView2PrintSettings pointer for everything else; NULL is passed here, which is
;                  what gives those defaults. Windows messages are pumped while waiting, so the GUI stays
;                  responsive, and only one print may run at a time per view.
; Related .......: _WV2_CapturePreview, _WV2_WaitNavigation
; ===============================================================================================================================
Func _WV2_PrintToPdf($iHandle, $sFile, $iTimeoutMs = $WV2_PRINT_TIMEOUT)
	$__WV2_sLastFunc = "_WV2_PrintToPdf"
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	If Not IsString($sFile) Or StringStripWS($sFile, 3) = "" Then
		__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_PrintToPdf")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf

	; The runtime writes the file itself and wants a full path, so a relative path is completed here and
	; a missing folder is reported as $WV2_ERR_FILE instead of coming back as an opaque HRESULT.
	Local $sPath = _PathFull($sFile)
	Local $sDrv = "", $sDir = "", $sName = "", $sExt = ""
	_PathSplit($sPath, $sDrv, $sDir, $sName, $sExt)
	If $sDrv & $sDir <> "" And Not FileExists($sDrv & $sDir) Then
		__WV2_SetErr($WV2_ERR_FILE, 0, "_WV2_PrintToPdf")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf

	Local $p7 = __WV2_ViewIf($iHandle, $__WV2_IF_7)
	If $p7 = 0 Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	Local $pFn = __WV2_VtFn($p7, $__WV2_SLOT_ICoreWebView2_7_PrintToPdf)
	If $pFn = 0 Then
		__WV2_SetErr($WV2_ERR_COM, 0, "__WV2_VtFn")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf

	__WV2_BeginOp($iHandle, $__WV2_H_PRINT)
	; PrintToPdf(result file path, print settings, handler). NULL settings means the defaults.
	Local $aCall = DllCallAddress("long", $pFn, "ptr", $p7, "wstr", $sPath, "ptr", 0, _
			"ptr", $__WV2_pObj[$iHandle][$__WV2_H_PRINT])
	If @Error Or Not IsArray($aCall) Then
		__WV2_SetErr($WV2_ERR_COM, 0, "ICoreWebView2_7::PrintToPdf")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	If $aCall[0] <> 0 Then
		__WV2_SetErr($WV2_ERR_CALL, $aCall[0], "ICoreWebView2_7::PrintToPdf")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	If Not __WV2_WaitOp($iHandle, $__WV2_H_PRINT, $iTimeoutMs) Then
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	Local $iDoneHR = $__WV2_iOpHR[$iHandle][$__WV2_H_PRINT]
	If $iDoneHR <> 0 Then
		__WV2_SetErr($WV2_ERR_CALL, $iDoneHR, "ICoreWebView2PrintToPdfCompletedHandler")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	; The handler carries a BOOL as well: a call that ends with S_OK and FALSE produced nothing.
	If $__WV2_sOpOut[$iHandle][$__WV2_H_PRINT] = "0" Then
		__WV2_SetErr($WV2_ERR_FILE, 0, "ICoreWebView2PrintToPdfCompletedHandler")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	$__WV2_iLastError = $WV2_ERR_NONE
	$__WV2_iLastHR = 0
	Return SetError(0, 0, 1)
EndFunc   ;==>_WV2_PrintToPdf

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_ClearCookies
; Description ...: Empties the cookie jar of the view.
; Syntax ........: _WV2_ClearCookies($iHandle)
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
; Return values .: Success: 1, @error = 0.
;                  Failure: 0, with @error set to a $WV2_ERR_* code and @extended set to the raw
;                  HRESULT (0 if none).
; Author ........: Numeric1
; Remarks .......: The call is synchronous, but the page keeps whatever it already read: reload it
;                  before testing document.cookie again. Cookies live in the user data folder, so every
;                  view started with the same $sUserDataFolder shares the jar and is affected too. The
;                  cache, the history, the localStorage and the rest of the profile are left alone:
;                  clearing them needs ICoreWebView2Profile2::ClearBrowsingData, which the view itself
;                  does not expose.
; Related .......: _WV2_Create, _WV2_ExecuteScript
; ===============================================================================================================================
Func _WV2_ClearCookies($iHandle)
	$__WV2_sLastFunc = "_WV2_ClearCookies"
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)

	Local $p2 = __WV2_ViewIf($iHandle, $__WV2_IF_2)
	If $p2 = 0 Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	Local $pFn = __WV2_VtFn($p2, $__WV2_SLOT_ICoreWebView2_2_get_CookieManager)
	If $pFn = 0 Then
		__WV2_SetErr($WV2_ERR_COM, 0, "__WV2_VtFn")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	; get_CookieManager answers with a pointer that carries a reference of its own.
	Local $tOut = DllStructCreate("ptr")
	Local $aCall = DllCallAddress("long", $pFn, "ptr", $p2, "ptr", DllStructGetPtr($tOut))
	If @Error Or Not IsArray($aCall) Then
		__WV2_SetErr($WV2_ERR_COM, 0, "ICoreWebView2_2::get_CookieManager")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	If $aCall[0] <> 0 Then
		__WV2_SetErr($WV2_ERR_CALL, $aCall[0], "ICoreWebView2_2::get_CookieManager")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	Local $pCookie = DllStructGetData($tOut, 1)
	If $pCookie = 0 Then
		__WV2_SetErr($WV2_ERR_COM, 0, "ICoreWebView2_2::get_CookieManager")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf

	Local $hr = __WV2_CallNoArg($pCookie, $__WV2_SLOT_ICoreWebView2CookieManager_DeleteAllCookies)
	__WV2_ReleaseExternal($pCookie)
	Local $bOk = __WV2_Result($hr, "ICoreWebView2CookieManager::DeleteAllCookies")
	Return SetError($__WV2_iLastError, $__WV2_iLastHR, $bOk)
EndFunc   ;==>_WV2_ClearCookies

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_SetResourceHandler
; Description ...: Names the AutoIt function that answers the requests of the page, or removes it.
; Syntax ........: _WV2_SetResourceHandler($iHandle[, $sFunc = ""[, $sFilter = "*"[,
;                  $iContext = $WV2_RES_ALL]]])
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $sFunc - Name of a function of the script, as a string. "" removes the handler and the
;                   filter that came with it.
;                  $sFilter - URI pattern the handler is called for. "*" is every request; any other
;                   pattern is matched against the whole URI, e.g. "https://app.local/*".
;                  $iContext - Kind of resource to catch, one of the $WV2_RES_* constants.
; Return values .: Success: 1.
;                  Failure: 0, with @error set to a $WV2_ERR_* code and @extended set to the raw
;                  HRESULT (0 if none). $WV2_ERR_ARG covers an empty or malformed function name, an empty
;                  pattern and a context out of range; $WV2_ERR_BUSY means the call came from a resource
;                  handler of the same view.
; Author ........: Numeric1
; Remarks .......: The function is called as Func Handler($iHandle, $sUri, $sMethod, $sHeaders) and its
;                  return value decides what the browser gets:
;
;                     0                  the request goes on to the network, untouched;
;                     [status, reason,   the UDF answers itself, without any network access:
;                      headers, body]     status  - HTTP status code, 100 to 999, e.g. 200;
;                                         reason  - status text, "" for "OK";
;                                         headers - "Name: value" lines separated by @CRLF, "" for none,
;                                                   e.g. "Content-Type: text/html; charset=utf-8";
;                                         body    - what to send: an AutoIt string (sent as UTF-8) or
;                                                   a Binary holding the bytes. Left out, nothing is sent.
;
;                  Anything else is taken as a failure of the handler: the request goes on to the network
;                  and the event carries 2. $sHeaders holds the request headers as "Name: value" lines
;                  separated by @CRLF, as sent, so a POST can be read there.
;
;                  The name is only checked for shape here: a name no function of the script carries is
;                  seen when the first request arrives, and reported there as a failure of the handler.
;
;                  The call happens inside the message loop of the runtime. Reading a file, a variable or
;                  a DllStruct there is fine; anything that pumps messages (_WV2_Navigate,
;                  _WV2_ExecuteScript, _WV2_WaitEvent, _WV2_Destroy...) is refused with $WV2_ERR_BUSY,
;                  because the runtime only allows one request at a time on a thread.
;                  Every request reaches the queue as $WV2_EVENT_RESOURCE_REQUESTED, with $iValue set to
;                  1 answered by the handler, 0 let through, 2 handler failed.
; Related .......: _WV2_AddResourceFilter, _WV2_GetEvent, _WV2_SetVirtualHostNameToFolderMapping
; ===============================================================================================================================
Func _WV2_SetResourceHandler($iHandle, $sFunc = "", $sFilter = "*", $iContext = $WV2_RES_ALL)
	$__WV2_sLastFunc = "_WV2_SetResourceHandler"
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	$sFunc = StringStripWS(String($sFunc), 3)
	; IsFunc cannot be trusted to answer on every build, so the shape is checked here and the existence
	; of the function is left to Call() inside __WV2_InvRes, which reports it as a failed request.
	If $sFunc <> "" And Not StringRegExp($sFunc, "^(?i)[a-z_][a-z0-9_]*$") Then
		__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_SetResourceHandler")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf

	; Whatever the previous registration owned goes first, so the new one is the only one in force.
	If $__WV2_sResFilter[$iHandle] <> "" Then
		__WV2_Filter($iHandle, $__WV2_sResFilter[$iHandle], $__WV2_iResCtx[$iHandle], False)
		$__WV2_sResFilter[$iHandle] = ""
	EndIf
	If $sFunc = "" Then
		__WV2_Detach($iHandle, $__WV2_H_RESOURCE)
		$__WV2_sResFunc[$iHandle] = ""
		$__WV2_iLastError = $WV2_ERR_NONE
		$__WV2_iLastHR = 0
		Return SetError(0, 0, 1)
	EndIf

	$__WV2_sResFunc[$iHandle] = $sFunc
	If Not __WV2_Attach($iHandle, $__WV2_H_RESOURCE) Then
		$__WV2_sResFunc[$iHandle] = ""
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	If Not __WV2_Filter($iHandle, $sFilter, $iContext, True) Then
		__WV2_Detach($iHandle, $__WV2_H_RESOURCE)
		$__WV2_sResFunc[$iHandle] = ""
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	$__WV2_sResFilter[$iHandle] = $sFilter
	$__WV2_iResCtx[$iHandle] = $iContext
	$__WV2_iLastError = $WV2_ERR_NONE
	$__WV2_iLastHR = 0
	Return SetError(0, 0, 1)
EndFunc   ;==>_WV2_SetResourceHandler

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_AddResourceFilter
; Description ...: Widens the set of requests the resource handler is called for.
; Syntax ........: _WV2_AddResourceFilter($iHandle, $sPattern[, $iContext = $WV2_RES_ALL])
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $sPattern - URI pattern, matched against the whole URI. "*" is every request,
;                   "https://app.local/*" the pages of one host, "*.png" every PNG of the web.
;                  $iContext - Kind of resource to catch, one of the $WV2_RES_* constants.
; Return values .: Success: 1. Failure: 0, with @error and @extended as in _WV2_SetResourceHandler.
; Author ........: Numeric1
; Remarks .......: _WV2_SetResourceHandler already installs its own filter, so this is for a handler
;                  that has to watch several unrelated patterns at once; each one is added once.
;                  A filter catches nothing while no handler is set: requests are matched by the
;                  runtime before the handler exists and are then let through.
; Related .......: _WV2_SetResourceHandler, _WV2_RemoveResourceFilter
; ===============================================================================================================================
Func _WV2_AddResourceFilter($iHandle, $sPattern, $iContext = $WV2_RES_ALL)
	$__WV2_sLastFunc = "_WV2_AddResourceFilter"
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	Local $bOk = __WV2_Filter($iHandle, $sPattern, $iContext, True)
	Return SetError($__WV2_iLastError, $__WV2_iLastHR, $bOk)
EndFunc   ;==>_WV2_AddResourceFilter

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_RemoveResourceFilter
; Description ...: Takes back a filter added by _WV2_AddResourceFilter.
; Syntax ........: _WV2_RemoveResourceFilter($iHandle, $sPattern[, $iContext = $WV2_RES_ALL])
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $sPattern - The pattern that was added, unchanged.
;                  $iContext - The context it was added with.
; Return values .: Success: 1. Failure: 0, with @error and @extended as in _WV2_SetResourceHandler.
; Author ........: Numeric1
; Remarks .......: Pattern and context have to be the ones of the add: the runtime keeps the filters
;                  as a set, not as a list. The filter of _WV2_SetResourceHandler is removed by
;                  calling it again, not here.
; Related .......: _WV2_AddResourceFilter, _WV2_SetResourceHandler
; ===============================================================================================================================
Func _WV2_RemoveResourceFilter($iHandle, $sPattern, $iContext = $WV2_RES_ALL)
	$__WV2_sLastFunc = "_WV2_RemoveResourceFilter"
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	Local $bOk = __WV2_Filter($iHandle, $sPattern, $iContext, False)
	Return SetError($__WV2_iLastError, $__WV2_iLastHR, $bOk)
EndFunc   ;==>_WV2_RemoveResourceFilter

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_SetVirtualHostNameToFolderMapping
; Description ...: Serves the files of a local folder under a host name invented for the page.
; Syntax ........: _WV2_SetVirtualHostNameToFolderMapping($iHandle, $sHost, $sFolder[,
;                  $iAccess = $WV2_HOST_ALLOW])
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $sHost - Host name of the mapping, e.g. "app.local". It never reaches the network.
;                  $sFolder - Existing folder whose content answers https://<host>/<path>.
;                  $iAccess - What a page gets from the mapping: $WV2_HOST_ALLOW (the default),
;                   $WV2_HOST_DENY, or $WV2_HOST_DENY_CORS.
; Return values .: Success: 1.
;                  Failure: 0, with @error set to $WV2_ERR_ARG (host name or access kind), $WV2_ERR_FILE
;                  (folder missing) or $WV2_ERR_CALL, and @extended set to the raw HRESULT (0 if none).
;                  A runtime older than 98 refuses this with $WV2_ERR_CALL and E_NOINTERFACE
;                  (0x80004002) in @extended.
; Author ........: Numeric1
; Remarks .......: The browser answers the request from the folder: no web server, no port, no
;                  extraction to the temporary directory. The page is then a true web origin - it has
;                  its own storage, can run fetch and workers, and localStorage survives the session -
;                  which "file://" and NavigateToString cannot offer.
;                  $sFolder may be relative: it is completed here, the runtime wants a full path.
;                  The mapping lives with the page: it is applied to the next navigation, and calling
;                  this again with the same host replaces it. Nothing is copied or cached, so a file
;                  edited on disk is served as it is on the next request.
; Related .......: _WV2_ClearVirtualHostNameToFolderMapping, _WV2_Navigate, _WV2_SetResourceHandler
; ===============================================================================================================================
Func _WV2_SetVirtualHostNameToFolderMapping($iHandle, $sHost, $sFolder, $iAccess = $WV2_HOST_ALLOW)
	$__WV2_sLastFunc = "_WV2_SetVirtualHostNameToFolderMapping"
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	If Not IsString($sHost) Or Not StringRegExp($sHost, "^(?i)[a-z0-9]([a-z0-9.\-]*[a-z0-9])?$") Then
		__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_SetVirtualHostNameToFolderMapping")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	If $iAccess <> $WV2_HOST_DENY And $iAccess <> $WV2_HOST_ALLOW And $iAccess <> $WV2_HOST_DENY_CORS Then
		__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_SetVirtualHostNameToFolderMapping")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	Local $sDir = _PathFull(StringStripWS(String($sFolder), 3))
	If Not FileExists($sDir) Or Not StringInStr(FileGetAttrib($sDir), "D") Then
		__WV2_SetErr($WV2_ERR_FILE, 0, "_WV2_SetVirtualHostNameToFolderMapping")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf

	Local $p3 = __WV2_ViewIf($iHandle, $__WV2_IF_3)
	If $p3 = 0 Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	Local $pFn = __WV2_VtFn($p3, $__WV2_SLOT_ICoreWebView2_3_SetVirtualHostNameToFolderMapping)
	If $pFn = 0 Then
		__WV2_SetErr($WV2_ERR_COM, 0, "__WV2_VtFn")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	Local $aCall = DllCallAddress("long", $pFn, "ptr", $p3, "wstr", $sHost, "wstr", $sDir, "int", $iAccess)
	If @Error Or Not IsArray($aCall) Then
		__WV2_SetErr($WV2_ERR_COM, 0, "ICoreWebView2_3::SetVirtualHostNameToFolderMapping")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	Local $bOk = __WV2_Result($aCall[0], "ICoreWebView2_3::SetVirtualHostNameToFolderMapping")
	Return SetError($__WV2_iLastError, $__WV2_iLastHR, $bOk)
EndFunc   ;==>_WV2_SetVirtualHostNameToFolderMapping

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_ClearVirtualHostNameToFolderMapping
; Description ...: Removes a mapping made by _WV2_SetVirtualHostNameToFolderMapping.
; Syntax ........: _WV2_ClearVirtualHostNameToFolderMapping($iHandle, $sHost)
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $sHost - Host name of the mapping to remove, as it was given.
; Return values .: Success: 1. Failure: 0, with @error and @extended as in
;                  _WV2_SetVirtualHostNameToFolderMapping.
; Author ........: Numeric1
; Remarks .......: Requests already answered stay in the page; the next navigation to that host fails.
; Related .......: _WV2_SetVirtualHostNameToFolderMapping
; ===============================================================================================================================
Func _WV2_ClearVirtualHostNameToFolderMapping($iHandle, $sHost)
	$__WV2_sLastFunc = "_WV2_ClearVirtualHostNameToFolderMapping"
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	If Not IsString($sHost) Or StringStripWS($sHost, 3) = "" Then
		__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_ClearVirtualHostNameToFolderMapping")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf

	Local $p3 = __WV2_ViewIf($iHandle, $__WV2_IF_3)
	If $p3 = 0 Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	Local $pFn = __WV2_VtFn($p3, $__WV2_SLOT_ICoreWebView2_3_ClearVirtualHostNameToFolderMapping)
	If $pFn = 0 Then
		__WV2_SetErr($WV2_ERR_COM, 0, "__WV2_VtFn")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	Local $aCall = DllCallAddress("long", $pFn, "ptr", $p3, "wstr", $sHost)
	If @Error Or Not IsArray($aCall) Then
		__WV2_SetErr($WV2_ERR_COM, 0, "ICoreWebView2_3::ClearVirtualHostNameToFolderMapping")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	Local $bOk = __WV2_Result($aCall[0], "ICoreWebView2_3::ClearVirtualHostNameToFolderMapping")
	Return SetError($__WV2_iLastError, $__WV2_iLastHR, $bOk)
EndFunc   ;==>_WV2_ClearVirtualHostNameToFolderMapping

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_FindStart
; Description ...: Searches the page for a term and highlights the matches, the way the browser's own
;                  find bar does.
; Syntax ........: _WV2_FindStart($iHandle, $sTerm[, $bMatchCase = False[, $bMatchWholeWord = False[,
;                  $bHighlightAllMatches = True[, $iTimeoutMs = $WV2_EXEC_TIMEOUT]]]])
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $sTerm - Text to look for.
;                  $bMatchCase - True to tell "Page" from "page".
;                  $bMatchWholeWord - True to skip matches inside a longer word.
;                  $bHighlightAllMatches - True (the default) to mark every match on the page, not
;                  only the active one. Read the remarks before passing False.
;                  $iTimeoutMs - Time allowed for the search to start, in milliseconds.
; Return values .: Success: the number of matches found, 0 being "nothing found" (not a failure).
;                  Failure: -1, with @error set to a $WV2_ERR_* code and @extended set to the raw
;                  HRESULT (0 if none). $WV2_ERR_CALL with E_NOINTERFACE in @extended means the
;                  installed runtime has no ICoreWebView2Find (it needs 1.0.3240 or newer).
; Author ........: Numeric1
; Remarks .......: The search object belongs to the view and is asked for on the first call. The
;                  default find bar of the runtime is suppressed: the page shows the highlight, nothing
;                  else. MatchCount and the active index are read from the search object once the answer
;                  arrives, and every later change reaches the queue as $WV2_EVENT_FIND.
;                  Runtime 156.0.4314.50 with $bHighlightAllMatches = False never makes a match active:
;                  the active index stays 0 and _WV2_FindNext leaves the page still, while the documented
;                  answer is 1 on the first match and the page following the next ones. The option is
;                  passed on as asked, but the default is the mode that runtime carries out.
; Related .......: _WV2_FindNext, _WV2_FindPrevious, _WV2_FindStop, _WV2_FindCount, _WV2_FindActive
; ===============================================================================================================================
Func _WV2_FindStart($iHandle, $sTerm, $bMatchCase = False, $bMatchWholeWord = False, $bHighlightAllMatches = True, $iTimeoutMs = $WV2_EXEC_TIMEOUT)
	$__WV2_sLastFunc = "_WV2_FindStart"
	If Not __WV2_GuardCtl($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	If Not IsString($sTerm) Or $sTerm = "" Then
		__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_FindStart")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	EndIf
	Local $pFind = __WV2_FindObj($iHandle)
	If $pFind = 0 Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)

	; The options object is made by the environment: ICoreWebView2FindOptions has no other factory.
	Local $pEnv15 = __WV2_EnvIf($iHandle, $WV2_IID_ENV15)
	If $pEnv15 = 0 Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	Local $pOpt = __WV2_GetIface($pEnv15, $__WV2_SLOT_ICoreWebView2Environment15_CreateFindOptions)
	__WV2_ReleaseExternal($pEnv15)
	If $pOpt = 0 Then
		__WV2_SetErr($WV2_ERR_CALL, 0, "ICoreWebView2Environment15::CreateFindOptions")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	EndIf

	; Nothing in here can fail for a valid pointer, so the HRESULTs are not looked at one by one: what
	; matters is whether Start accepts the options, which is checked below.
	__WV2_CallWStr($pOpt, $__WV2_SLOT_ICoreWebView2FindOptions_put_FindTerm, $sTerm)
	__WV2_CallBool($pOpt, $__WV2_SLOT_ICoreWebView2FindOptions_put_IsCaseSensitive, $bMatchCase)
	__WV2_CallBool($pOpt, $__WV2_SLOT_ICoreWebView2FindOptions_put_ShouldMatchWord, $bMatchWholeWord)
	__WV2_CallBool($pOpt, $__WV2_SLOT_ICoreWebView2FindOptions_put_ShouldHighlightAllMatches, $bHighlightAllMatches)
	__WV2_CallBool($pOpt, $__WV2_SLOT_ICoreWebView2FindOptions_put_SuppressDefaultFindDialog, 1)

	; The two events are subscribed before the search starts, so the first change is not missed.
	If Not __WV2_Attach($iHandle, $__WV2_H_FINDIDX) Then
		__WV2_ReleaseExternal($pOpt)
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	EndIf

	Local $pFn = __WV2_VtFn($pFind, $__WV2_SLOT_ICoreWebView2Find_Start)
	If $pFn = 0 Then
		__WV2_ReleaseExternal($pOpt)
		__WV2_SetErr($WV2_ERR_COM, 0, "__WV2_VtFn")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	EndIf
	__WV2_BeginOp($iHandle, $__WV2_H_FINDSTART)
	Local $aCall = DllCallAddress("long", $pFn, "ptr", $pFind, "ptr", $pOpt, "ptr", $__WV2_pObj[$iHandle][$__WV2_H_FINDSTART])
	Local $iCallErr = @Error
	__WV2_ReleaseExternal($pOpt)
	If $iCallErr Or Not IsArray($aCall) Then
		__WV2_SetErr($WV2_ERR_COM, 0, "ICoreWebView2Find::Start")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	EndIf
	If $aCall[0] <> 0 Then
		__WV2_SetErr($WV2_ERR_CALL, $aCall[0], "ICoreWebView2Find::Start")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	EndIf
	If Not __WV2_WaitOp($iHandle, $__WV2_H_FINDSTART, $iTimeoutMs) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	If $__WV2_iOpHR[$iHandle][$__WV2_H_FINDSTART] <> 0 Then
		__WV2_SetErr($WV2_ERR_CALL, $__WV2_iOpHR[$iHandle][$__WV2_H_FINDSTART], "ICoreWebView2FindStartCompletedHandler")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	EndIf
	Local $iCount = __WV2_IntProp($pFind, $__WV2_SLOT_ICoreWebView2Find_get_MatchCount)
	If $iCount < 0 Then
		__WV2_SetErr($WV2_ERR_CALL, 0, "ICoreWebView2Find::get_MatchCount")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	EndIf
	$__WV2_bFindOn[$iHandle] = True
	$__WV2_iLastError = $WV2_ERR_NONE
	$__WV2_iLastHR = 0
	Return SetError(0, 0, $iCount)
EndFunc   ;==>_WV2_FindStart

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_FindNext / _WV2_FindPrevious / _WV2_FindStop
; Description ...: Moves to the next or previous match, or ends the search and clears the highlight.
; Syntax ........: _WV2_FindNext($iHandle) / _WV2_FindPrevious($iHandle) / _WV2_FindStop($iHandle)
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
; Return values .: Success: 1. Failure: 0, with @error set to a $WV2_ERR_* code and @extended set to the
;                  raw HRESULT (0 if none).
; Author ........: Numeric1
; Remarks .......: They are refused with $WV2_ERR_NOT_READY until _WV2_FindStart has run once.
; Related .......: _WV2_FindStart, _WV2_FindActive
; ===============================================================================================================================
Func _WV2_FindNext($iHandle)
	Local $iR = __WV2_FindStep($iHandle, $__WV2_SLOT_ICoreWebView2Find_FindNext, "_WV2_FindNext")
	Local $iErr = @Error, $iHR = @Extended
	Return SetError($iErr, $iHR, $iR)
EndFunc   ;==>_WV2_FindNext

Func _WV2_FindPrevious($iHandle)
	Local $iR = __WV2_FindStep($iHandle, $__WV2_SLOT_ICoreWebView2Find_FindPrevious, "_WV2_FindPrevious")
	Local $iErr = @Error, $iHR = @Extended
	Return SetError($iErr, $iHR, $iR)
EndFunc   ;==>_WV2_FindPrevious

Func _WV2_FindStop($iHandle)
	Local $iR = __WV2_FindStep($iHandle, $__WV2_SLOT_ICoreWebView2Find_Stop, "_WV2_FindStop")
	Local $iErr = @Error, $iHR = @Extended
	If $iR = 1 Then $__WV2_bFindOn[$iHandle] = False
	Return SetError($iErr, $iHR, $iR)
EndFunc   ;==>_WV2_FindStop

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_FindCount / _WV2_FindActive
; Description ...: How many matches the last search has, and which of them is the current one.
; Syntax ........: _WV2_FindCount($iHandle) / _WV2_FindActive($iHandle)
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
; Return values .: Success: the number of matches, or the index of the active one, counted from 1
;                  (-1 when the search has none).
;                  Failure: -1, with @error set to a $WV2_ERR_* code.
; Author ........: Numeric1
; Remarks .......: Both values are properties of the search object, so they are read on the spot and
;                  cost no message pumping. The active index follows the engine: the object still holds
;                  the previous number for a moment after a step, and $WV2_EVENT_FIND announces the new
;                  one, so wait for that event before reading it.
; Related .......: _WV2_FindStart, $WV2_EVENT_FIND
; ===============================================================================================================================
Func _WV2_FindCount($iHandle)
	Local $iV = __WV2_FindNumber($iHandle, $__WV2_SLOT_ICoreWebView2Find_get_MatchCount, "_WV2_FindCount")
	Local $iErr = @Error, $iHR = @Extended
	Return SetError($iErr, $iHR, $iV)
EndFunc   ;==>_WV2_FindCount

Func _WV2_FindActive($iHandle)
	Local $iV = __WV2_FindNumber($iHandle, $__WV2_SLOT_ICoreWebView2Find_get_ActiveMatchIndex, "_WV2_FindActive")
	Local $iErr = @Error, $iHR = @Extended
	Return SetError($iErr, $iHR, $iV)
EndFunc   ;==>_WV2_FindActive

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_ExecuteScriptEx
; Description ...: Runs JavaScript in the page and brings back its result as JSON, whether the script
;                  succeeded or threw.
; Syntax ........: _WV2_ExecuteScriptEx($iHandle, $sScript, $sResult, $bSucceeded, $sException[,
;                  $iTimeoutMs = $WV2_EXEC_TIMEOUT])
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $sScript - JavaScript to run, as an expression or as a block of statements.
;                  $sResult - Receives the result as JSON; "" when the script threw.
;                  $bSucceeded - Receives True or False.
;                  $sException - Receives the error as "Name: message (line L, column C)"; "" on success.
;                  $iTimeoutMs - Time allowed for the page to answer, in milliseconds.
; Return values .: Success: 1, whether the script itself succeeded or threw: $bSucceeded says which.
;                  Failure: 0, with @error set to a $WV2_ERR_* code and @extended set to the raw
;                  HRESULT (0 if none). $WV2_ERR_CALL with E_NOINTERFACE in @extended means the runtime
;                  has no ICoreWebView2_21 (it needs 1.0.2210 or newer).
; Author ........: Numeric1
; Remarks .......: _WV2_ExecuteScript hands back what the runtime prints, which turns an object into
;                  "[object Object]" and loses the difference between 3 and "3". This one gives the
;                  JSON text instead, and says why a script failed instead of returning nothing.
; Related .......: _WV2_ExecuteScript, _WV2_AddScriptToExecuteOnDocumentCreated
; ===============================================================================================================================
Func _WV2_ExecuteScriptEx($iHandle, $sScript, ByRef $sResult, ByRef $bSucceeded, ByRef $sException, $iTimeoutMs = $WV2_EXEC_TIMEOUT)
	$__WV2_sLastFunc = "_WV2_ExecuteScriptEx"
	$sResult = ""
	$bSucceeded = False
	$sException = ""
	If Not __WV2_GuardCtl($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	If Not IsString($sScript) Then $sScript = String($sScript)

	Local $p21 = __WV2_ViewIf($iHandle, $__WV2_IF_21)
	If $p21 = 0 Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	Local $pFn = __WV2_VtFn($p21, $__WV2_SLOT_ICoreWebView2_21_ExecuteScriptWithResult)
	If $pFn = 0 Then
		__WV2_SetErr($WV2_ERR_COM, 0, "__WV2_VtFn")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf

	__WV2_BeginOp($iHandle, $__WV2_H_EXECRES)
	Local $aCall = DllCallAddress("long", $pFn, "ptr", $p21, "wstr", $sScript, "ptr", $__WV2_pObj[$iHandle][$__WV2_H_EXECRES])
	If @Error Or Not IsArray($aCall) Then
		__WV2_SetErr($WV2_ERR_COM, 0, "ICoreWebView2_21::ExecuteScriptWithResult")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	If $aCall[0] <> 0 Then
		__WV2_SetErr($WV2_ERR_CALL, $aCall[0], "ICoreWebView2_21::ExecuteScriptWithResult")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	If Not __WV2_WaitOp($iHandle, $__WV2_H_EXECRES, $iTimeoutMs) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	Local $iDoneHR = $__WV2_iOpHR[$iHandle][$__WV2_H_EXECRES]
	Local $pRes = $__WV2_pOpObj[$iHandle][$__WV2_H_EXECRES]
	$__WV2_pOpObj[$iHandle][$__WV2_H_EXECRES] = 0
	If $iDoneHR <> 0 Or $pRes = 0 Then
		__WV2_SetErr($WV2_ERR_CALL, $iDoneHR, "ICoreWebView2ExecuteScriptWithResultCompletedHandler")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf

	$bSucceeded = (__WV2_BoolProp($pRes, $__WV2_SLOT_ICoreWebView2ExecuteScriptResult_get_Succeeded) = 1)
	; The runtime answers "null" for a script that threw, which says nothing that $bSucceeded and
	; $sException do not say better: only a script that ran leaves a result here.
	If $bSucceeded Then $sResult = __WV2_WStrProp($pRes, $__WV2_SLOT_ICoreWebView2ExecuteScriptResult_get_ResultAsJson)
	If Not $bSucceeded Then
		Local $pExc = __WV2_GetIface($pRes, $__WV2_SLOT_ICoreWebView2ExecuteScriptResult_get_Exception)
		If $pExc <> 0 Then
			Local $sName = __WV2_WStrProp($pExc, $__WV2_SLOT_ICoreWebView2ScriptException_get_Name)
			Local $sMsg = __WV2_WStrProp($pExc, $__WV2_SLOT_ICoreWebView2ScriptException_get_Message)
			Local $iLine = __WV2_IntProp($pExc, $__WV2_SLOT_ICoreWebView2ScriptException_get_LineNumber)
			Local $iCol = __WV2_IntProp($pExc, $__WV2_SLOT_ICoreWebView2ScriptException_get_ColumnNumber)
			$sException = $sName & ": " & $sMsg & " (line " & $iLine & ", column " & $iCol & ")"
			__WV2_ReleaseExternal($pExc)
		EndIf
	EndIf
	__WV2_ReleaseExternal($pRes)
	$__WV2_iLastError = $WV2_ERR_NONE
	$__WV2_iLastHR = 0
	Return SetError(0, 0, 1)
EndFunc   ;==>_WV2_ExecuteScriptEx

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_GetCookies
; Description ...: Asks the cookie jar for every cookie that would be sent to a URL.
; Syntax ........: _WV2_GetCookies($iHandle, $sUri, $aCookies[, $iTimeoutMs = $WV2_EXEC_TIMEOUT])
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $sUri - Address the cookies are wanted for, e.g. "https://app.local/".
;                  $aCookies - Receives the array, passed by reference.
;                  $iTimeoutMs - Time allowed for the answer, in milliseconds.
; Return values .: Success: the number of cookies found, the array holding:
;                     [n][0] name        [n][1] value     [n][2] domain      [n][3] path
;                     [n][4] expires     [n][5] httpOnly  [n][6] secure      [n][7] session
;                     [n][8] sameSite    a $WV2_COOKIE_SAMESITE_* constant
;                  When nothing matches, the array is 0 x 9: UBound() gives 0, not an error.
;                  Failure: -1, with @error set to a $WV2_ERR_* code and @extended set to the raw
;                  HRESULT (0 if none).
; Author ........: Numeric1
; Remarks .......: The jar belongs to the user data folder, not to the view: two views started on the
;                  same folder share it. $sUri decides which cookies are visible - a secure cookie is
;                  only listed for an https address. Expires is 0 for a session cookie; cookie dates are
;                  seconds since 1970, in UTC.
; Related .......: _WV2_SetCookie, _WV2_DeleteCookie, _WV2_ClearCookies
; ===============================================================================================================================
Func _WV2_GetCookies($iHandle, $sUri, ByRef $aCookies, $iTimeoutMs = $WV2_EXEC_TIMEOUT)
	$__WV2_sLastFunc = "_WV2_GetCookies"
	Local $aEmpty[0][9]
	$aCookies = $aEmpty
	If Not __WV2_GuardCtl($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	If Not IsString($sUri) Or $sUri = "" Then
		__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_GetCookies")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	EndIf
	Local $pJar = __WV2_CookieMgr($iHandle)
	If $pJar = 0 Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)

	Local $pFn = __WV2_VtFn($pJar, $__WV2_SLOT_ICoreWebView2CookieManager_GetCookies)
	__WV2_BeginOp($iHandle, $__WV2_H_COOKIES)
	Local $aCall = DllCallAddress("long", $pFn, "ptr", $pJar, "wstr", $sUri, "ptr", $__WV2_pObj[$iHandle][$__WV2_H_COOKIES])
	Local $iCallErr = @Error
	__WV2_ReleaseExternal($pJar)
	If $iCallErr Or Not IsArray($aCall) Or $aCall[0] <> 0 Then
		__WV2_SetErr($WV2_ERR_CALL, (IsArray($aCall) ? $aCall[0] : 0), "ICoreWebView2CookieManager::GetCookies")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	EndIf
	If Not __WV2_WaitOp($iHandle, $__WV2_H_COOKIES, $iTimeoutMs) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	Local $iDoneHR = $__WV2_iOpHR[$iHandle][$__WV2_H_COOKIES]
	Local $pList = $__WV2_pOpObj[$iHandle][$__WV2_H_COOKIES]
	$__WV2_pOpObj[$iHandle][$__WV2_H_COOKIES] = 0
	If $iDoneHR <> 0 Or $pList = 0 Then
		__WV2_SetErr($WV2_ERR_CALL, $iDoneHR, "ICoreWebView2GetCookiesCompletedHandler")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	EndIf

	Local $iCount = __WV2_IntProp($pList, $__WV2_SLOT_ICoreWebView2CookieList_get_Count)
	If $iCount < 0 Then $iCount = 0
	Local $aOut[$iCount][9]
	Local $k
	For $k = 0 To $iCount - 1
		Local $pCk = __WV2_GetIfaceAt($pList, $__WV2_SLOT_ICoreWebView2CookieList_GetValueAtIndex, $k)
		If $pCk = 0 Then ContinueLoop
		$aOut[$k][0] = __WV2_WStrProp($pCk, $__WV2_SLOT_ICoreWebView2Cookie_get_Name)
		$aOut[$k][1] = __WV2_WStrProp($pCk, $__WV2_SLOT_ICoreWebView2Cookie_get_Value)
		$aOut[$k][2] = __WV2_WStrProp($pCk, $__WV2_SLOT_ICoreWebView2Cookie_get_Domain)
		$aOut[$k][3] = __WV2_WStrProp($pCk, $__WV2_SLOT_ICoreWebView2Cookie_get_Path)
		$aOut[$k][4] = __WV2_DblProp($pCk, $__WV2_SLOT_ICoreWebView2Cookie_get_Expires)
		$aOut[$k][5] = __WV2_BoolProp($pCk, $__WV2_SLOT_ICoreWebView2Cookie_get_IsHttpOnly)
		$aOut[$k][6] = __WV2_BoolProp($pCk, $__WV2_SLOT_ICoreWebView2Cookie_get_IsSecure)
		$aOut[$k][7] = __WV2_BoolProp($pCk, $__WV2_SLOT_ICoreWebView2Cookie_get_IsSession)
		$aOut[$k][8] = __WV2_IntProp($pCk, $__WV2_SLOT_ICoreWebView2Cookie_get_SameSite)
		__WV2_ReleaseExternal($pCk)
	Next
	__WV2_ReleaseExternal($pList)
	$aCookies = $aOut
	$__WV2_iLastError = $WV2_ERR_NONE
	$__WV2_iLastHR = 0
	Return SetError(0, 0, $iCount)
EndFunc   ;==>_WV2_GetCookies

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_SetCookie
; Description ...: Writes one cookie into the jar of the view.
; Syntax ........: _WV2_SetCookie($iHandle, $sName, $sValue, $sDomain[, $sPath = "/"[,
;                  $fExpires = 0[, $iSameSite = $WV2_COOKIE_SAMESITE_LAX[, $bHttpOnly = False[,
;                  $bSecure = False]]]]])
; Parameters ....: $iHandle - Handle created by _WV2_Create.
;                  $sName - Cookie name.
;                  $sValue - Cookie value.
;                  $sDomain - Domain it belongs to, e.g. "app.local".
;                  $sPath - Path it is sent for, "/" by default.
;                  $fExpires - Expiry, in seconds since 1970 UTC; 0 makes it a session cookie.
;                  $iSameSite - One of the $WV2_COOKIE_SAMESITE_* constants, $WV2_COOKIE_SAMESITE_LAX by
;                  default.
;                  $bHttpOnly - True to hide the cookie from document.cookie.
;                  $bSecure - True to send it over https only.
; Return values .: Success: 1. Failure: 0, with @error set to a $WV2_ERR_* code and @extended set to the
;                  raw HRESULT (0 if none).
; Author ........: Numeric1
; Remarks .......: A cookie with the same name, domain and path is replaced. The jar is the one of the
;                  user data folder, so other views on the same folder see the change at once; a page
;                  already open keeps what it read until it is reloaded.
;                  The engine refuses $WV2_COOKIE_SAMESITE_NONE unless $bSecure is also True, and the jar
;                  says nothing about it: the call still answers 1, the cookie is simply not kept. That
;                  is why the default is LAX, the value a browser gives a cookie without SameSite.
;                  An expiry further out than 400 days is clamped by the engine to the day the cookie was
;                  written plus 400 days, so _WV2_GetCookies reports a different date than the one asked.
; Related .......: _WV2_GetCookies, _WV2_DeleteCookie
; ===============================================================================================================================
Func _WV2_SetCookie($iHandle, $sName, $sValue, $sDomain, $sPath = "/", $fExpires = 0, $iSameSite = $WV2_COOKIE_SAMESITE_LAX, $bHttpOnly = False, $bSecure = False)
	$__WV2_sLastFunc = "_WV2_SetCookie"
	If Not __WV2_GuardCtl($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	If Not IsString($sName) Or $sName = "" Or Not IsString($sDomain) Or $sDomain = "" Then
		__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_SetCookie")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	If $iSameSite <> $WV2_COOKIE_SAMESITE_NONE And $iSameSite <> $WV2_COOKIE_SAMESITE_LAX And $iSameSite <> $WV2_COOKIE_SAMESITE_STRICT Then
		__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_SetCookie")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	Local $pJar = __WV2_CookieMgr($iHandle)
	If $pJar = 0 Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)

	; CreateCookie(name, value, domain, path, &cookie) fills a cookie the manager owns until it is added.
	Local $pFn = __WV2_VtFn($pJar, $__WV2_SLOT_ICoreWebView2CookieManager_CreateCookie)
	Local $tOut = DllStructCreate("ptr")
	Local $aCall = DllCallAddress("long", $pFn, "ptr", $pJar, "wstr", String($sName), "wstr", String($sValue), _
			"wstr", String($sDomain), "wstr", String($sPath), "ptr", DllStructGetPtr($tOut))
	If @Error Or Not IsArray($aCall) Or $aCall[0] <> 0 Then
		__WV2_ReleaseExternal($pJar)
		__WV2_SetErr($WV2_ERR_CALL, (IsArray($aCall) ? $aCall[0] : 0), "ICoreWebView2CookieManager::CreateCookie")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	Local $pCk = DllStructGetData($tOut, 1)
	If $pCk = 0 Then
		__WV2_ReleaseExternal($pJar)
		__WV2_SetErr($WV2_ERR_COM, 0, "ICoreWebView2CookieManager::CreateCookie")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	If $fExpires > 0 Then __WV2_CallDbl($pCk, $__WV2_SLOT_ICoreWebView2Cookie_put_Expires, $fExpires)
	__WV2_CallBool($pCk, $__WV2_SLOT_ICoreWebView2Cookie_put_IsHttpOnly, $bHttpOnly)
	__WV2_CallBool($pCk, $__WV2_SLOT_ICoreWebView2Cookie_put_IsSecure, $bSecure)
	__WV2_CallLong($pCk, $__WV2_SLOT_ICoreWebView2Cookie_put_SameSite, $iSameSite)

	Local $pFnAdd = __WV2_VtFn($pJar, $__WV2_SLOT_ICoreWebView2CookieManager_AddOrUpdateCookie)
	Local $aAdd = DllCallAddress("long", $pFnAdd, "ptr", $pJar, "ptr", $pCk)
	Local $iAddErr = @Error
	__WV2_ReleaseExternal($pCk)
	__WV2_ReleaseExternal($pJar)
	If $iAddErr Or Not IsArray($aAdd) Then
		__WV2_SetErr($WV2_ERR_COM, 0, "ICoreWebView2CookieManager::AddOrUpdateCookie")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	Return SetError($__WV2_iLastError, $__WV2_iLastHR, __WV2_Result($aAdd[0], "ICoreWebView2CookieManager::AddOrUpdateCookie"))
EndFunc   ;==>_WV2_SetCookie

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_DeleteCookie
; Description ...: Removes every cookie of that name the URL would receive.
; Syntax ........: _WV2_DeleteCookie($iHandle, $sName, $sUri)
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $sName - Cookie name.
;                  $sUri - Address the cookies belong to, e.g. "https://app.local/".
; Return values .: Success: 1. Failure: 0, with @error set to a $WV2_ERR_* code and @extended set to the
;                  raw HRESULT (0 if none).
; Author ........: Numeric1
; Remarks .......: Deleting a cookie that is not there is a success: the jar is left as it is.
; Related .......: _WV2_GetCookies, _WV2_SetCookie, _WV2_ClearCookies
; ===============================================================================================================================
Func _WV2_DeleteCookie($iHandle, $sName, $sUri)
	$__WV2_sLastFunc = "_WV2_DeleteCookie"
	If Not __WV2_GuardCtl($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	If Not IsString($sName) Or $sName = "" Or Not IsString($sUri) Or $sUri = "" Then
		__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_DeleteCookie")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	Local $pJar = __WV2_CookieMgr($iHandle)
	If $pJar = 0 Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	Local $pFn = __WV2_VtFn($pJar, $__WV2_SLOT_ICoreWebView2CookieManager_DeleteCookies)
	Local $aCall = DllCallAddress("long", $pFn, "ptr", $pJar, "wstr", String($sName), "wstr", String($sUri))
	Local $iCallErr = @Error
	__WV2_ReleaseExternal($pJar)
	If $iCallErr Or Not IsArray($aCall) Then
		__WV2_SetErr($WV2_ERR_COM, 0, "ICoreWebView2CookieManager::DeleteCookies")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	Return SetError($__WV2_iLastError, $__WV2_iLastHR, __WV2_Result($aCall[0], "ICoreWebView2CookieManager::DeleteCookies"))
EndFunc   ;==>_WV2_DeleteCookie

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_PrintSettingsCreate
; Description ...: Makes a settings object for _WV2_PrintToPdfEx, _WV2_PrintToPdfStream and _WV2_ShowPrintUI.
; Syntax ........: _WV2_PrintSettingsCreate($iHandle, $hSettings)
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $hSettings - Receives the settings handle, passed by reference.
; Return values .: Success: 1, $hSettings holding a handle of 1 to $WV2_PRINT_SETTINGS_MAX.
;                  Failure: 0, with @error set to a $WV2_ERR_* code and @extended set to the raw
;                  HRESULT (0 if none). $WV2_ERR_FULL means the eight settings objects of the script are
;                  all live: one of them has to be destroyed first.
; Author ........: Numeric1
; Remarks .......: The object starts with the defaults of the runtime. Eight may live at once, whatever
;                  the view; they are released by _WV2_PrintSettingsDestroy, or with the view that made
;                  them when the script forgets.
; Related .......: _WV2_PrintSettingsSet, _WV2_PrintSettingsGet, _WV2_PrintSettingsDestroy
; ===============================================================================================================================
Func _WV2_PrintSettingsCreate($iHandle, ByRef $hSettings)
	$__WV2_sLastFunc = "_WV2_PrintSettingsCreate"
	$hSettings = 0
	If Not __WV2_GuardCtl($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	Local $pEnv6 = __WV2_EnvIf($iHandle, $WV2_IID_ENV6)
	If $pEnv6 = 0 Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	Local $pSet = __WV2_GetIface($pEnv6, $__WV2_SLOT_ICoreWebView2Environment6_CreatePrintSettings)
	__WV2_ReleaseExternal($pEnv6)
	If $pSet = 0 Then
		__WV2_SetErr($WV2_ERR_CALL, 0, "ICoreWebView2Environment6::CreatePrintSettings")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	Local $j, $iFree = 0
	For $j = 1 To $WV2_PRINT_SETTINGS_MAX
		If $__WV2_pPrintSet[$j] = 0 Then
			$iFree = $j
			ExitLoop
		EndIf
	Next
	If $iFree = 0 Then
		__WV2_ReleaseExternal($pSet)
		__WV2_SetErr($WV2_ERR_FULL, 0, "_WV2_PrintSettingsCreate")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	$__WV2_pPrintSet[$iFree] = $pSet
	$__WV2_iPrintInst[$iFree] = $iHandle
	$hSettings = $iFree
	$__WV2_iLastError = $WV2_ERR_NONE
	$__WV2_iLastHR = 0
	Return SetError(0, 0, 1)
EndFunc   ;==>_WV2_PrintSettingsCreate

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_PrintSettingsSet / _WV2_PrintSettingsGet
; Description ...: Writes or reads one setting of a settings object.
; Syntax ........: _WV2_PrintSettingsSet($hSettings, $sName, $vValue)
;                  _WV2_PrintSettingsGet($hSettings, $sName)
; Parameters ....: $hSettings - Handle from _WV2_PrintSettingsCreate.
;                  $sName - Name of the setting, in any case:
;                     "Orientation"            $WV2_PRINT_PORTRAIT or $WV2_PRINT_LANDSCAPE
;                     "ScaleFactor"            ratio of the page size, 0.1 to 2
;                     "PageWidth", "PageHeight"   inches
;                     "MarginTop", "MarginBottom", "MarginLeft", "MarginRight"   inches
;                     "ShouldPrintBackgrounds", "ShouldPrintSelectionOnly",
;                     "ShouldPrintHeaderAndFooter"   True or False
;                     "HeaderTitle", "FooterUri"   text printed in the header and the footer
;                  $vValue - The value to write.
; Return values .: Set: 1 on success, 0 on failure.
;                  Get: the value read; -1 for a number that could not be read.
;                  Both set @error to a $WV2_ERR_* code and @extended to the raw HRESULT (0 if none) when
;                  they fail; $WV2_ERR_ARG covers an unknown name or a value of the wrong kind.
; Author ........: Numeric1
; Remarks .......: The setters of the runtime take a long, a double or a text; the name decides which,
;                  and a value of the wrong kind is refused here rather than silently turned into 0.
; Related .......: _WV2_PrintSettingsCreate, _WV2_PrintToPdfEx
; ===============================================================================================================================
Func _WV2_PrintSettingsSet($hSettings, $sName, $vValue)
	$__WV2_sLastFunc = "_WV2_PrintSettingsSet"
	Local $pSet = __WV2_PrintSet($hSettings)
	If $pSet = 0 Then
		__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_PrintSettingsSet")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	Local $hr = $__WV2_HR_E_FAIL
	Switch StringLower(StringStripWS(String($sName), 3))
		Case "orientation"
			$hr = __WV2_CallLong($pSet, $__WV2_SLOT_ICoreWebView2PrintSettings_put_Orientation, $vValue)
		Case "scalefactor"
			$hr = __WV2_CallDbl($pSet, $__WV2_SLOT_ICoreWebView2PrintSettings_put_ScaleFactor, $vValue)
		Case "pagewidth"
			$hr = __WV2_CallDbl($pSet, $__WV2_SLOT_ICoreWebView2PrintSettings_put_PageWidth, $vValue)
		Case "pageheight"
			$hr = __WV2_CallDbl($pSet, $__WV2_SLOT_ICoreWebView2PrintSettings_put_PageHeight, $vValue)
		Case "margintop"
			$hr = __WV2_CallDbl($pSet, $__WV2_SLOT_ICoreWebView2PrintSettings_put_MarginTop, $vValue)
		Case "marginbottom"
			$hr = __WV2_CallDbl($pSet, $__WV2_SLOT_ICoreWebView2PrintSettings_put_MarginBottom, $vValue)
		Case "marginleft"
			$hr = __WV2_CallDbl($pSet, $__WV2_SLOT_ICoreWebView2PrintSettings_put_MarginLeft, $vValue)
		Case "marginright"
			$hr = __WV2_CallDbl($pSet, $__WV2_SLOT_ICoreWebView2PrintSettings_put_MarginRight, $vValue)
		Case "shouldprintbackgrounds"
			$hr = __WV2_CallBool($pSet, $__WV2_SLOT_ICoreWebView2PrintSettings_put_ShouldPrintBackgrounds, $vValue)
		Case "shouldprintselectiononly"
			$hr = __WV2_CallBool($pSet, $__WV2_SLOT_ICoreWebView2PrintSettings_put_ShouldPrintSelectionOnly, $vValue)
		Case "shouldprintheaderandfooter"
			$hr = __WV2_CallBool($pSet, $__WV2_SLOT_ICoreWebView2PrintSettings_put_ShouldPrintHeaderAndFooter, $vValue)
		Case "headertitle"
			$hr = __WV2_CallWStr($pSet, $__WV2_SLOT_ICoreWebView2PrintSettings_put_HeaderTitle, String($vValue))
		Case "footeruri"
			$hr = __WV2_CallWStr($pSet, $__WV2_SLOT_ICoreWebView2PrintSettings_put_FooterUri, String($vValue))
		Case Else
			__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_PrintSettingsSet")
			Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndSwitch
	Return SetError($__WV2_iLastError, $__WV2_iLastHR, __WV2_Result($hr, "_WV2_PrintSettingsSet"))
EndFunc   ;==>_WV2_PrintSettingsSet

Func _WV2_PrintSettingsGet($hSettings, $sName)
	$__WV2_sLastFunc = "_WV2_PrintSettingsGet"
	Local $pSet = __WV2_PrintSet($hSettings)
	If $pSet = 0 Then
		__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_PrintSettingsGet")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	EndIf
	Local $vOut = -1
	Local $bText = False
	Switch StringLower(StringStripWS(String($sName), 3))
		Case "orientation"
			$vOut = __WV2_IntProp($pSet, $__WV2_SLOT_ICoreWebView2PrintSettings_get_Orientation)
		Case "scalefactor"
			$vOut = __WV2_DblProp($pSet, $__WV2_SLOT_ICoreWebView2PrintSettings_get_ScaleFactor)
		Case "pagewidth"
			$vOut = __WV2_DblProp($pSet, $__WV2_SLOT_ICoreWebView2PrintSettings_get_PageWidth)
		Case "pageheight"
			$vOut = __WV2_DblProp($pSet, $__WV2_SLOT_ICoreWebView2PrintSettings_get_PageHeight)
		Case "margintop"
			$vOut = __WV2_DblProp($pSet, $__WV2_SLOT_ICoreWebView2PrintSettings_get_MarginTop)
		Case "marginbottom"
			$vOut = __WV2_DblProp($pSet, $__WV2_SLOT_ICoreWebView2PrintSettings_get_MarginBottom)
		Case "marginleft"
			$vOut = __WV2_DblProp($pSet, $__WV2_SLOT_ICoreWebView2PrintSettings_get_MarginLeft)
		Case "marginright"
			$vOut = __WV2_DblProp($pSet, $__WV2_SLOT_ICoreWebView2PrintSettings_get_MarginRight)
		Case "shouldprintbackgrounds"
			$vOut = __WV2_BoolProp($pSet, $__WV2_SLOT_ICoreWebView2PrintSettings_get_ShouldPrintBackgrounds)
		Case "shouldprintselectiononly"
			$vOut = __WV2_BoolProp($pSet, $__WV2_SLOT_ICoreWebView2PrintSettings_get_ShouldPrintSelectionOnly)
		Case "shouldprintheaderandfooter"
			$vOut = __WV2_BoolProp($pSet, $__WV2_SLOT_ICoreWebView2PrintSettings_get_ShouldPrintHeaderAndFooter)
		Case "headertitle"
			$vOut = __WV2_WStrProp($pSet, $__WV2_SLOT_ICoreWebView2PrintSettings_get_HeaderTitle)
			$bText = True
		Case "footeruri"
			$vOut = __WV2_WStrProp($pSet, $__WV2_SLOT_ICoreWebView2PrintSettings_get_FooterUri)
			$bText = True
		Case Else
			__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_PrintSettingsGet")
			Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	EndSwitch
	; A text setting answers with "" when it is empty, which is not a failure; a number answers with -1.
	If Not $bText And ($vOut = -1 Or $vOut < 0) Then
		__WV2_SetErr($WV2_ERR_CALL, 0, "ICoreWebView2PrintSettings::get_" & $sName)
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	EndIf
	$__WV2_iLastError = $WV2_ERR_NONE
	$__WV2_iLastHR = 0
	Return SetError(0, 0, $vOut)
EndFunc   ;==>_WV2_PrintSettingsGet

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_PrintSettingsDestroy
; Description ...: Releases a settings object.
; Syntax ........: _WV2_PrintSettingsDestroy($hSettings)
; Parameters ....: $hSettings - Handle from _WV2_PrintSettingsCreate.
; Return values .: Success: 1. Failure: 0, with @error set to $WV2_ERR_ARG when the handle is unknown.
; Author ........: Numeric1
; Remarks .......: The handle is dead afterwards and cannot be reused. The view keeps working: it only
;                  forgot how to print with those settings.
; Related .......: _WV2_PrintSettingsCreate
; ===============================================================================================================================
Func _WV2_PrintSettingsDestroy($hSettings)
	$__WV2_sLastFunc = "_WV2_PrintSettingsDestroy"
	Local $pSet = __WV2_PrintSet($hSettings)
	If $pSet = 0 Then
		__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_PrintSettingsDestroy")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	__WV2_ReleaseExternal($pSet)
	$__WV2_pPrintSet[$hSettings] = 0
	$__WV2_iPrintInst[$hSettings] = 0
	$__WV2_iLastError = $WV2_ERR_NONE
	$__WV2_iLastHR = 0
	Return SetError(0, 0, 1)
EndFunc   ;==>_WV2_PrintSettingsDestroy

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_PrintToPdfEx
; Description ...: Writes the page to a PDF file with the settings of a settings object.
; Syntax ........: _WV2_PrintToPdfEx($iHandle, $sFile[, $hSettings = 0[, $iTimeoutMs = $WV2_PRINT_TIMEOUT]])
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $sFile - Path of the PDF to write; the folder has to exist.
;                  $hSettings - Settings from _WV2_PrintSettingsCreate, 0 for the defaults.
;                  $iTimeoutMs - Time allowed for the page to print, in milliseconds.
; Return values .: Success: 1. Failure: 0, with @error set to a $WV2_ERR_* code and @extended set to the
;                  raw HRESULT (0 if none); $WV2_ERR_FILE means nothing was written.
; Author ........: Numeric1
; Remarks .......: Same call as _WV2_PrintToPdf, which is this one without the settings. Windows
;                  messages are pumped while the page prints.
; Related .......: _WV2_PrintToPdf, _WV2_PrintSettingsCreate, _WV2_PrintToPdfStream
; ===============================================================================================================================
Func _WV2_PrintToPdfEx($iHandle, $sFile, $hSettings = 0, $iTimeoutMs = $WV2_PRINT_TIMEOUT)
	$__WV2_sLastFunc = "_WV2_PrintToPdfEx"
	If Not __WV2_GuardCtl($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	If Not IsString($sFile) Or StringStripWS($sFile, 3) = "" Then
		__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_PrintToPdfEx")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	Local $pSet = 0
	If $hSettings <> 0 Then
		$pSet = __WV2_PrintSet($hSettings)
		If $pSet = 0 Then
			__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_PrintToPdfEx")
			Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
		EndIf
	EndIf
	Local $sPath = _PathFull($sFile)
	Local $sDrv = "", $sDir = "", $sName = "", $sExt = ""
	_PathSplit($sPath, $sDrv, $sDir, $sName, $sExt)
	If $sDrv & $sDir <> "" And Not FileExists($sDrv & $sDir) Then
		__WV2_SetErr($WV2_ERR_FILE, 0, "_WV2_PrintToPdfEx")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf

	Local $p7 = __WV2_ViewIf($iHandle, $__WV2_IF_7)
	If $p7 = 0 Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	Local $pFn = __WV2_VtFn($p7, $__WV2_SLOT_ICoreWebView2_7_PrintToPdf)
	If $pFn = 0 Then
		__WV2_SetErr($WV2_ERR_COM, 0, "__WV2_VtFn")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	__WV2_BeginOp($iHandle, $__WV2_H_PRINT)
	Local $aCall = DllCallAddress("long", $pFn, "ptr", $p7, "wstr", $sPath, "ptr", $pSet, _
			"ptr", $__WV2_pObj[$iHandle][$__WV2_H_PRINT])
	If @Error Or Not IsArray($aCall) Then
		__WV2_SetErr($WV2_ERR_COM, 0, "ICoreWebView2_7::PrintToPdf")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	If $aCall[0] <> 0 Then
		__WV2_SetErr($WV2_ERR_CALL, $aCall[0], "ICoreWebView2_7::PrintToPdf")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	If Not __WV2_WaitOp($iHandle, $__WV2_H_PRINT, $iTimeoutMs) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	If $__WV2_iOpHR[$iHandle][$__WV2_H_PRINT] <> 0 Then
		__WV2_SetErr($WV2_ERR_CALL, $__WV2_iOpHR[$iHandle][$__WV2_H_PRINT], "ICoreWebView2PrintToPdfCompletedHandler")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	If $__WV2_sOpOut[$iHandle][$__WV2_H_PRINT] = "0" Then
		__WV2_SetErr($WV2_ERR_FILE, 0, "ICoreWebView2PrintToPdfCompletedHandler")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	$__WV2_iLastError = $WV2_ERR_NONE
	$__WV2_iLastHR = 0
	Return SetError(0, 0, 1)
EndFunc   ;==>_WV2_PrintToPdfEx

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_PrintToPdfStream
; Description ...: Prints the page to memory instead of to a file.
; Syntax ........: _WV2_PrintToPdfStream($iHandle, $bPdf[, $hSettings = 0[, $iTimeoutMs = $WV2_PRINT_TIMEOUT]])
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $bPdf - Receives the PDF bytes as a Binary, passed by reference.
;                  $hSettings - Settings from _WV2_PrintSettingsCreate, 0 for the defaults.
;                  $iTimeoutMs - Time allowed for the page to print, in milliseconds.
; Return values .: Success: 1, $bPdf holding the file (BinaryLen() gives its size).
;                  Failure: 0, with @error set to a $WV2_ERR_* code and @extended set to the raw
;                  HRESULT (0 if none).
; Author ........: Numeric1
; Remarks .......: Nothing touches the disk: the bytes can be sent over a socket, hashed or shown in a
;                  viewer kept open with a temporary file of the script's own. The runtime has to be
;                  1.0.1587 or newer (ICoreWebView2_16).
; Related .......: _WV2_PrintToPdf, _WV2_PrintSettingsCreate, _WV2_CapturePreview
; ===============================================================================================================================
Func _WV2_PrintToPdfStream($iHandle, ByRef $bPdf, $hSettings = 0, $iTimeoutMs = $WV2_PRINT_TIMEOUT)
	$__WV2_sLastFunc = "_WV2_PrintToPdfStream"
	$bPdf = Binary("")
	If Not __WV2_GuardCtl($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	Local $pSet = 0
	If $hSettings <> 0 Then
		$pSet = __WV2_PrintSet($hSettings)
		If $pSet = 0 Then
			__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_PrintToPdfStream")
			Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
		EndIf
	EndIf
	Local $p16 = __WV2_ViewIf($iHandle, $__WV2_IF_16)
	If $p16 = 0 Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	Local $pFn = __WV2_VtFn($p16, $__WV2_SLOT_ICoreWebView2_16_PrintToPdfStream)
	If $pFn = 0 Then
		__WV2_SetErr($WV2_ERR_COM, 0, "__WV2_VtFn")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	__WV2_BeginOp($iHandle, $__WV2_H_PDFSTREAM)
	Local $aCall = DllCallAddress("long", $pFn, "ptr", $p16, "ptr", $pSet, "ptr", $__WV2_pObj[$iHandle][$__WV2_H_PDFSTREAM])
	If @Error Or Not IsArray($aCall) Then
		__WV2_SetErr($WV2_ERR_COM, 0, "ICoreWebView2_16::PrintToPdfStream")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	If $aCall[0] <> 0 Then
		__WV2_SetErr($WV2_ERR_CALL, $aCall[0], "ICoreWebView2_16::PrintToPdfStream")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	If Not __WV2_WaitOp($iHandle, $__WV2_H_PDFSTREAM, $iTimeoutMs) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	Local $iDoneHR = $__WV2_iOpHR[$iHandle][$__WV2_H_PDFSTREAM]
	Local $pStream = $__WV2_pOpObj[$iHandle][$__WV2_H_PDFSTREAM]
	$__WV2_pOpObj[$iHandle][$__WV2_H_PDFSTREAM] = 0
	If $iDoneHR <> 0 Or $pStream = 0 Then
		__WV2_SetErr($WV2_ERR_CALL, $iDoneHR, "ICoreWebView2PrintToPdfStreamCompletedHandler")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	; The stream is read before it is released: releasing it frees the memory behind it.
	$bPdf = __WV2_StreamBytes($pStream)
	__WV2_ReleaseExternal($pStream)
	If BinaryLen($bPdf) = 0 Then
		__WV2_SetErr($WV2_ERR_CALL, 0, "ICoreWebView2PrintToPdfStreamCompletedHandler")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	$__WV2_iLastError = $WV2_ERR_NONE
	$__WV2_iLastHR = 0
	Return SetError(0, 0, 1)
EndFunc   ;==>_WV2_PrintToPdfStream

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_ShowPrintUI
; Description ...: Opens the print dialog of the page.
; Syntax ........: _WV2_ShowPrintUI($iHandle[, $iKind = $WV2_PRINT_UI_BROWSER])
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $iKind - $WV2_PRINT_UI_BROWSER for the preview the browser shows, $WV2_PRINT_UI_SYSTEM
;                   for the dialog of Windows.
; Return values .: Success: 1. Failure: 0, with @error set to a $WV2_ERR_* code and @extended set to the
;                  raw HRESULT (0 if none).
; Author ........: Numeric1
; Remarks .......: The dialog belongs to the runtime and runs in its own window: the call returns at
;                  once, the user prints or cancels, and nothing else is needed. The runtime has to be
;                  1.0.1587 or newer (ICoreWebView2_16).
; Related .......: _WV2_PrintToPdf, _WV2_PrintToPdfStream
; ===============================================================================================================================
Func _WV2_ShowPrintUI($iHandle, $iKind = $WV2_PRINT_UI_BROWSER)
	$__WV2_sLastFunc = "_WV2_ShowPrintUI"
	If Not __WV2_GuardCtl($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	If $iKind <> $WV2_PRINT_UI_BROWSER And $iKind <> $WV2_PRINT_UI_SYSTEM Then
		__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_ShowPrintUI")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	Local $p16 = __WV2_ViewIf($iHandle, $__WV2_IF_16)
	If $p16 = 0 Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	Return SetError($__WV2_iLastError, $__WV2_iLastHR, __WV2_Result( _
			__WV2_CallLong($p16, $__WV2_SLOT_ICoreWebView2_16_ShowPrintUI, $iKind), "ICoreWebView2_16::ShowPrintUI"))
EndFunc   ;==>_WV2_ShowPrintUI

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_GetDownloadCount
; Description ...: How many downloads the view still remembers.
; Syntax ........: _WV2_GetDownloadCount($iHandle)
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
; Return values .: Success: the number of downloads kept, 0 to $WV2_DL_MAX.
;                  Failure: -1, with @error set to a $WV2_ERR_* code.
; Author ........: Numeric1
; Remarks .......: Every accepted download is kept from the moment it starts until the view is
;                  destroyed. The list holds at most $WV2_DL_MAX entries: a new download takes the
;                  slot of the oldest one, whose numbers then belong to the newcomer.
; Related .......: _WV2_GetDownload, _WV2_DownloadPause
; ===============================================================================================================================
Func _WV2_GetDownloadCount($iHandle)
	$__WV2_sLastFunc = "_WV2_GetDownloadCount"
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	$__WV2_iLastError = $WV2_ERR_NONE
	$__WV2_iLastHR = 0
	Return SetError(0, 0, $__WV2_iDlCount[$iHandle])
EndFunc   ;==>_WV2_GetDownloadCount

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_GetDownload
; Description ...: Reads the numbers of one remembered download.
; Syntax ........: _WV2_GetDownload($iHandle, $iIndex, $aInfo)
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $iIndex - Index of the download, 1 to _WV2_GetDownloadCount().
;                  $aInfo - Receives an array of eight cells, passed by reference:
;
;                     [0] uri            URI being downloaded;
;                     [1] path           file the runtime writes to;
;                     [2] state          $WV2_DL_IN_PROGRESS, _INTERRUPTED or _COMPLETED;
;                     [3] received       bytes written so far;
;                     [4] total          bytes announced by the server, 0 when it told nothing;
;                     [5] end time       text of the runtime, "" until it can estimate one;
;                     [6] canResume      True when a paused download can be resumed;
;                     [7] interrupt      reason code of an interrupted download (COREWEBVIEW2_
;                                        DOWNLOAD_INTERRUPT_REASON), 0 when there is none.
;
; Return values .: Success: 1. Failure: 0, with @error set to a $WV2_ERR_* code and @extended set to
;                  the raw HRESULT (0 if none); $WV2_ERR_ARG covers an index with no download in it.
; Author ........: Numeric1
; Remarks .......: The array is a copy: reading it later still tells the state of the moment of the
;                  call. Ask again after $WV2_EVENT_DOWNLOAD_STATE or _PROGRESS for fresh numbers.
; Related .......: _WV2_GetDownloadCount, _WV2_EnableEvent, _WV2_DownloadPause
; ===============================================================================================================================
Func _WV2_GetDownload($iHandle, $iIndex, ByRef $aInfo)
	$__WV2_sLastFunc = "_WV2_GetDownload"
	Local $aNone[8] = ["", "", $WV2_DL_INTERRUPTED, 0, 0, "", False, 0]
	$aInfo = $aNone
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	Local $pOp = __WV2_DlAt($iHandle, $iIndex)
	If $pOp = 0 Then
		__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_GetDownload")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	Local $aOut[8]
	$aOut[0] = __WV2_WStrProp($pOp, $__WV2_SLOT_ICoreWebView2DownloadOperation_get_Uri)
	$aOut[1] = __WV2_WStrProp($pOp, $__WV2_SLOT_ICoreWebView2DownloadOperation_get_ResultFilePath)
	Local $iState = __WV2_IntProp($pOp, $__WV2_SLOT_ICoreWebView2DownloadOperation_get_State)
	$aOut[2] = ($iState < 0 ? $WV2_DL_INTERRUPTED : $iState)
	Local $iGot = __WV2_I64Prop($pOp, $__WV2_SLOT_ICoreWebView2DownloadOperation_get_BytesReceived)
	$aOut[3] = ($iGot < 0 ? 0 : $iGot)
	Local $iTotal = __WV2_I64Prop($pOp, $__WV2_SLOT_ICoreWebView2DownloadOperation_get_TotalBytesToReceive)
	$aOut[4] = ($iTotal < 0 ? 0 : $iTotal)
	$aOut[5] = __WV2_WStrProp($pOp, $__WV2_SLOT_ICoreWebView2DownloadOperation_get_EstimatedEndTime)
	$aOut[6] = (__WV2_BoolProp($pOp, $__WV2_SLOT_ICoreWebView2DownloadOperation_get_CanResume) = 1)
	Local $iWhy = __WV2_IntProp($pOp, $__WV2_SLOT_ICoreWebView2DownloadOperation_get_InterruptReason)
	$aOut[7] = ($iWhy < 0 ? 0 : $iWhy)
	$aInfo = $aOut
	$__WV2_iLastError = $WV2_ERR_NONE
	$__WV2_iLastHR = 0
	Return SetError(0, 0, 1)
EndFunc   ;==>_WV2_GetDownload

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_DownloadPause / _WV2_DownloadResume / _WV2_DownloadCancel
; Description ...: Holds, restarts or abandons a download the view remembers.
; Syntax ........: _WV2_DownloadPause($iHandle, $iIndex)
;                  _WV2_DownloadResume($iHandle, $iIndex)
;                  _WV2_DownloadCancel($iHandle, $iIndex)
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $iIndex - Index of the download, 1 to _WV2_GetDownloadCount().
; Return values .: Success: 1. Failure: 0, with @error set to a $WV2_ERR_* code and @extended set to
;                  the raw HRESULT (0 if none); $WV2_ERR_ARG covers an index with no download in it,
;                  $WV2_ERR_CALL a download that cannot take the order (a resume of something that
;                  cannot resume, a cancel of a download already over).
; Author ........: Numeric1
; Remarks .......: The three tell the runtime what to do and return at once: the state that follows
;                  arrives as $WV2_EVENT_DOWNLOAD_STATE, which _WV2_EnableEvent turns on. A cancelled
;                  download is kept like the others, with its state and its place on the disk.
; Related .......: _WV2_GetDownload, _WV2_EnableEvent
; ===============================================================================================================================
Func _WV2_DownloadPause($iHandle, $iIndex)
	$__WV2_sLastFunc = "_WV2_DownloadPause"
	If Not __WV2_DlAction($iHandle, $iIndex, $__WV2_SLOT_ICoreWebView2DownloadOperation_Pause, "Pause") Then _
			Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	Return SetError(0, 0, 1)
EndFunc   ;==>_WV2_DownloadPause

Func _WV2_DownloadResume($iHandle, $iIndex)
	$__WV2_sLastFunc = "_WV2_DownloadResume"
	If Not __WV2_DlAction($iHandle, $iIndex, $__WV2_SLOT_ICoreWebView2DownloadOperation_Resume, "Resume") Then _
			Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	Return SetError(0, 0, 1)
EndFunc   ;==>_WV2_DownloadResume

Func _WV2_DownloadCancel($iHandle, $iIndex)
	$__WV2_sLastFunc = "_WV2_DownloadCancel"
	If Not __WV2_DlAction($iHandle, $iIndex, $__WV2_SLOT_ICoreWebView2DownloadOperation_Cancel, "Cancel") Then _
			Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	Return SetError(0, 0, 1)
EndFunc   ;==>_WV2_DownloadCancel

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_SetDialogHandler
; Description ...: Names the AutoIt function that answers the dialogs of the page, or removes it.
; Syntax ........: _WV2_SetDialogHandler($iHandle[, $sFunc = ""])
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $sFunc - Name of a function of the script, as a string. "" removes the handler and
;                   lets the runtime show its own dialog again.
; Return values .: Success: 1. Failure: 0, with @error set to a $WV2_ERR_* code and @extended set to
;                  the raw HRESULT (0 if none); $WV2_ERR_ARG covers a malformed name.
; Author ........: Numeric1
; Remarks .......: The function is called as Func Handler($iHandle, $iKind, $sMessage, $sDefault, $sUri)
;                  with $iKind one of the $WV2_DIALOG_* constants, and its answer decides what the
;                  page gets:
;
;                     True, 1          the dialog is accepted: OK for an alert, true for a confirm,
;                                      the default text for a prompt;
;                     a string         the dialog is accepted and the string becomes the answer of the
;                                      prompt (for an alert or a confirm the text is ignored);
;                     False, 0, other  the dialog is dismissed: the page sees no answer at all.
;
;                  The page stands still until the handler returns, so it has to answer at once: a
;                  message box of the script is fine, another call into the same view is refused with
;                  $WV2_ERR_BUSY. The name is only checked for shape here; a name no function of the
;                  script carries is seen when the first dialog opens, and counts as a dismissal.
;                  Every dialog reaches the queue as $WV2_EVENT_SCRIPT_DIALOG, with $iValue set to the
;                  kind, plus 16 when it was dismissed.
;                  While a handler is installed the UDF sets AreDefaultScriptDialogsEnabled to False,
;                  because the runtime only raises the event instead of drawing its own box when that
;                  setting is off; the value the host had is put back when the handler is removed. The
;                  setting is read when a document loads, so install the handler before navigating —
;                  or reload the view — for the page that is already open.
; Related .......: _WV2_GetEvent, _WV2_SetAcceleratorHandler
; ===============================================================================================================================
Func _WV2_SetDialogHandler($iHandle, $sFunc = "")
	$__WV2_sLastFunc = "_WV2_SetDialogHandler"
	If Not __WV2_SetHandlerFunc($iHandle, $sFunc, $__WV2_H_DIALOG, "_WV2_SetDialogHandler") Then _
			Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	Return SetError(0, 0, 1)
EndFunc   ;==>_WV2_SetDialogHandler

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_SetAcceleratorHandler
; Description ...: Names the AutoIt function that sees the keys pressed before the page, or removes it.
; Syntax ........: _WV2_SetAcceleratorHandler($iHandle[, $sFunc = ""])
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $sFunc - Name of a function of the script, as a string. "" removes the handler.
; Return values .: Success: 1. Failure: 0, with @error set to a $WV2_ERR_* code and @extended set to
;                  the raw HRESULT (0 if none); $WV2_ERR_ARG covers a malformed name.
; Author ........: Numeric1
; Remarks .......: The function is called as Func Handler($iHandle, $iVirtualKey, $iKind), with $iKind
;                  one of the $WV2_KEYEVENT_* constants, and its answer decides who gets the key:
;                  True or a number other than 0 keeps the key away from the page, anything else lets
;                  it through. The keys are the ones the page would not use anyway (a browser shortcut
;                  such as F5 or Ctrl+P); writing into the page, calling back into the view, is refused
;                  with $WV2_ERR_BUSY like in a resource handler.
;                  Every key reaches the queue as $WV2_EVENT_ACCELERATOR, with $sData set to the
;                  virtual key and $iValue to the kind, handled or not.
; Related .......: _WV2_GetEvent, _WV2_SetDialogHandler
; ===============================================================================================================================
Func _WV2_SetAcceleratorHandler($iHandle, $sFunc = "")
	$__WV2_sLastFunc = "_WV2_SetAcceleratorHandler"
	If Not __WV2_SetHandlerFunc($iHandle, $sFunc, $__WV2_H_ACCEL, "_WV2_SetAcceleratorHandler") Then _
			Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	Return SetError(0, 0, 1)
EndFunc   ;==>_WV2_SetAcceleratorHandler

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_SetContextMenuHandler
; Description ...: Names the AutoIt function that sees the context menu before it opens, or removes it.
; Syntax ........: _WV2_SetContextMenuHandler($iHandle[, $sFunc = ""])
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $sFunc - Name of a function of the script, as a string. "" removes the handler and
;                   gives the menu back to the runtime, which is what shows the page menu.
; Return values .: Success: 1. Failure: 0, with @error set to a $WV2_ERR_* code and @extended set to
;                  the raw HRESULT (0 if none); $WV2_ERR_ARG covers a malformed name.
; Author ........: Numeric1
; Remarks .......: The function is called as Func Handler($iHandle, $aItems, $iX, $iY) with the menu
;                  the runtime is about to show, the coordinates of the click included, and decides
;                  what happens:
;
;                     -1               the menu is shown as the runtime built it;
;                     a command id     the menu is not shown: the runtime runs that item instead, which
;                                      is how a menu of the script replaces the one of the page.
;
;                  $aItems is [count+1][5]: column 0, row 0 holds the count; each row has
;                  [label, command id, kind, enabled, checked], kind being a COREWEBVIEW2_CONTEXT_
;                  MENU_ITEM_KIND value. Every menu reaches the queue as $WV2_EVENT_CONTEXT_MENU, with
;                  $sData empty and $iValue set to the command id the handler answered with (-1 when
;                  it chose none): the queue records the decision, the menu itself was handed to the
;                  function.
; Related .......: _WV2_GetEvent, _WV2_SetDialogHandler
; ===============================================================================================================================
Func _WV2_SetContextMenuHandler($iHandle, $sFunc = "")
	$__WV2_sLastFunc = "_WV2_SetContextMenuHandler"
	If Not __WV2_SetHandlerFunc($iHandle, $sFunc, $__WV2_H_CTXMENU, "_WV2_SetContextMenuHandler") Then _
			Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	Return SetError(0, 0, 1)
EndFunc   ;==>_WV2_SetContextMenuHandler

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_GetFaviconUri
; Description ...: The address of the icon the page declares.
; Syntax ........: _WV2_GetFaviconUri($iHandle, $sUri)
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $sUri - Receives the URI, passed by reference. "" when the page declares no icon.
; Return values .: Success: 1, $sUri filled. Failure: 0, with @error set to a $WV2_ERR_* code and
;                  @extended set to the raw HRESULT (0 if none).
; Author ........: Numeric1
; Remarks .......: The URI is what the page says, not what the runtime downloaded: it may point at a
;                  file of the site that is not an image, or be empty. _WV2_GetFavicon fetches the
;                  picture itself. A change is reported as $WV2_EVENT_FAVICON_CHANGED. Right after a
;                  navigation the runtime can still answer with the uri of the previous document for a
;                  moment (measured): let the page settle, or wait for $WV2_EVENT_FAVICON_CHANGED,
;                  before reading it.
; Related .......: _WV2_GetFavicon, _WV2_EnableEvent
; ===============================================================================================================================
Func _WV2_GetFaviconUri($iHandle, ByRef $sUri)
	$__WV2_sLastFunc = "_WV2_GetFaviconUri"
	$sUri = ""
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	Local $p16 = __WV2_ViewIf($iHandle, $__WV2_IF_16)
	If $p16 = 0 Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	$sUri = __WV2_WStrProp($p16, $__WV2_SLOT_ICoreWebView2_15_get_FaviconUri)
	$__WV2_iLastError = $WV2_ERR_NONE
	$__WV2_iLastHR = 0
	Return SetError(0, 0, 1)
EndFunc   ;==>_WV2_GetFaviconUri

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_GetFavicon
; Description ...: Fetches the icon of the page as image bytes.
; Syntax ........: _WV2_GetFavicon($iHandle, $bImage[, $iFormat = $WV2_FAVICON_PNG[,
;                  $iTimeoutMs = $WV2_EXEC_TIMEOUT]])
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $bImage - Receives the image as a Binary, passed by reference.
;                  $iFormat - $WV2_FAVICON_PNG or $WV2_FAVICON_JPEG: the runtime converts the icon,
;                   so the bytes always match the chosen format, whatever the site published.
;                  $iTimeoutMs - Time allowed for the icon to arrive, in milliseconds.
; Return values .: Success: 1, $bImage holding the file (BinaryLen() gives its size; write it to get
;                  a picture). Failure: 0, with @error set to a $WV2_ERR_* code and @extended set to
;                  the raw HRESULT (0 if none); $WV2_ERR_FILE means the runtime has no icon at all.
; Author ........: Numeric1
; Remarks .......: Nothing touches the disk. The runtime downloads the icon of the current page, which
;                  needs the page to have declared one and the view to be on a http, https or file
;                  address. A page that declares no icon is not a failure: the runtime keeps answering
;                  with the icon the view already knows (measured), so read _WV2_GetFaviconUri first
;                  when the absence matters. Windows messages are pumped while waiting.
; Related .......: _WV2_GetFaviconUri, _WV2_CapturePreview
; ===============================================================================================================================
Func _WV2_GetFavicon($iHandle, ByRef $bImage, $iFormat = $WV2_FAVICON_PNG, $iTimeoutMs = $WV2_EXEC_TIMEOUT)
	$__WV2_sLastFunc = "_WV2_GetFavicon"
	$bImage = Binary("")
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	If $iFormat <> $WV2_FAVICON_PNG And $iFormat <> $WV2_FAVICON_JPEG Then
		__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_GetFavicon")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	Local $p16 = __WV2_ViewIf($iHandle, $__WV2_IF_16)
	If $p16 = 0 Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	Local $pFn = __WV2_VtFn($p16, $__WV2_SLOT_ICoreWebView2_15_GetFavicon)
	If $pFn = 0 Then
		__WV2_SetErr($WV2_ERR_COM, 0, "__WV2_VtFn")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	__WV2_BeginOp($iHandle, $__WV2_H_FAVICONGET)
	Local $aCall = DllCallAddress("long", $pFn, "ptr", $p16, "int", $iFormat, _
			"ptr", $__WV2_pObj[$iHandle][$__WV2_H_FAVICONGET])
	If @Error Or Not IsArray($aCall) Then
		__WV2_SetErr($WV2_ERR_COM, 0, "ICoreWebView2_15::GetFavicon")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	If $aCall[0] <> 0 Then
		__WV2_SetErr($WV2_ERR_CALL, $aCall[0], "ICoreWebView2_15::GetFavicon")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	If Not __WV2_WaitOp($iHandle, $__WV2_H_FAVICONGET, $iTimeoutMs) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	Local $iDoneHR = $__WV2_iOpHR[$iHandle][$__WV2_H_FAVICONGET]
	Local $pStream = $__WV2_pOpObj[$iHandle][$__WV2_H_FAVICONGET]
	$__WV2_pOpObj[$iHandle][$__WV2_H_FAVICONGET] = 0
	If $iDoneHR <> 0 Then
		If $pStream <> 0 Then __WV2_ReleaseExternal($pStream)
		__WV2_SetErr($WV2_ERR_CALL, $iDoneHR, "ICoreWebView2GetFaviconCompletedHandler")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	If $pStream = 0 Then
		__WV2_SetErr($WV2_ERR_FILE, 0, "ICoreWebView2GetFaviconCompletedHandler")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	$bImage = __WV2_StreamBytes($pStream)
	__WV2_ReleaseExternal($pStream)
	If BinaryLen($bImage) = 0 Then
		__WV2_SetErr($WV2_ERR_FILE, 0, "ICoreWebView2GetFaviconCompletedHandler")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	$__WV2_iLastError = $WV2_ERR_NONE
	$__WV2_iLastHR = 0
	Return SetError(0, 0, 1)
EndFunc   ;==>_WV2_GetFavicon

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_ClearBrowsingData
; Description ...: Clears part or all of what the profile of the view kept between pages.
; Syntax ........: _WV2_ClearBrowsingData($iHandle[, $iKinds = $WV2_DATA_ALL[,
;                  $iTimeoutMs = $WV2_PRINT_TIMEOUT]])
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $iKinds - What to clear, one value or several added together, of:
;                     $WV2_DATA_BROWSING_HISTORY   addresses visited;
;                     $WV2_DATA_DOWNLOADS          list of the downloads;
;                     $WV2_DATA_COOKIES            cookies and other site data;
;                     $WV2_DATA_CACHE              files the browser kept to go faster;
;                     $WV2_DATA_ALL                all four.
;                  $iTimeoutMs - Time allowed for the runtime to answer, in milliseconds.
; Return values .: Success: 1. Failure: 0, with @error set to a $WV2_ERR_* code and @extended set to
;                  the raw HRESULT (0 if none); $WV2_ERR_ARG covers a set of bits with none of the
;                  four in it, $WV2_ERR_CALL a runtime too old for the profile interface.
; Author ........: Numeric1
; Remarks .......: Everything happens in the user data folder, so every view sharing
;                  $sUserDataFolder is cleared at once, including the pages already loaded: reload
;                  them to see the result. ICoreWebView2Profile2 came with runtime 1.0.1108.
; Related .......: _WV2_ClearCookies, _WV2_Create
; ===============================================================================================================================
Func _WV2_ClearBrowsingData($iHandle, $iKinds = $WV2_DATA_ALL, $iTimeoutMs = $WV2_PRINT_TIMEOUT)
	$__WV2_sLastFunc = "_WV2_ClearBrowsingData"
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	If Not IsInt($iKinds) And Not IsNumber($iKinds) Then
		$iKinds = -1
	EndIf
	If $iKinds <= 0 Or BitAND($iKinds, BitNOT($WV2_DATA_ALL)) <> 0 Then
		__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_ClearBrowsingData")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	Local $p16 = __WV2_ViewIf($iHandle, $__WV2_IF_16)
	If $p16 = 0 Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	; get_Profile sits on ICoreWebView2_13, which the _16 pointer carries like the rest.
	Local $pProfile = __WV2_GetIface($p16, $__WV2_SLOT_ICoreWebView2_13_get_Profile)
	If $pProfile = 0 Then
		__WV2_SetErr($WV2_ERR_CALL, 0, "ICoreWebView2_13::get_Profile")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	Local $pP2 = __WV2_QiRaw($pProfile, $WV2_IID_PROFILE2)
	__WV2_ReleaseExternal($pProfile)
	If $pP2 = 0 Then
		__WV2_SetErr($WV2_ERR_CALL, $__WV2_HR_E_NOINTERFACE, "ICoreWebView2Profile2")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	Local $pFn = __WV2_VtFn($pP2, $__WV2_SLOT_ICoreWebView2Profile2_ClearBrowsingData)
	If $pFn = 0 Then
		__WV2_ReleaseExternal($pP2)
		__WV2_SetErr($WV2_ERR_COM, 0, "__WV2_VtFn")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	__WV2_BeginOp($iHandle, $__WV2_H_PROFILE)
	Local $aCall = DllCallAddress("long", $pFn, "ptr", $pP2, "int", $iKinds, _
			"ptr", $__WV2_pObj[$iHandle][$__WV2_H_PROFILE])
	Local $iCallErr = @Error
	__WV2_ReleaseExternal($pP2)
	If $iCallErr Or Not IsArray($aCall) Then
		__WV2_SetErr($WV2_ERR_COM, 0, "ICoreWebView2Profile2::ClearBrowsingData")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	If $aCall[0] <> 0 Then
		__WV2_SetErr($WV2_ERR_CALL, $aCall[0], "ICoreWebView2Profile2::ClearBrowsingData")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	If Not __WV2_WaitOp($iHandle, $__WV2_H_PROFILE, $iTimeoutMs) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	If $__WV2_iOpHR[$iHandle][$__WV2_H_PROFILE] <> 0 Then
		__WV2_SetErr($WV2_ERR_CALL, $__WV2_iOpHR[$iHandle][$__WV2_H_PROFILE], "ICoreWebView2ClearBrowsingDataCompletedHandler")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	$__WV2_iLastError = $WV2_ERR_NONE
	$__WV2_iLastHR = 0
	Return SetError(0, 0, 1)
EndFunc   ;==>_WV2_ClearBrowsingData

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_LoadExtension
; Description ...: One call that lets the next view load an unpacked extension folder.
; Syntax ........: _WV2_LoadExtension($sFolder)
; Parameters ....: $sFolder - Full path of the folder that holds the manifest.json of the extension.
; Return values .: Success: 1, @error = 0, @extended = 1 when a view is already created, which means the
;                  folders listed here reach only the next environment.
;                  Failure: -1 with @error = $WV2_ERR_ARG when $sFolder is not a folder, or carries a
;                  comma (see Remarks).
; Author ........: Numeric1
; Remarks .......: This is the developer route: it turns AreBrowserExtensionsEnabled on and appends the
;                  folder to --load-extension, which is how Chromium has always taken an unpacked
;                  extension. It has to run before the view is created, and it is the same switch for
;                  every view of the script: the folders belong to the user data folder, not to a view.
;                  _WV2_AddExtension is the other route: the stable profile call, which needs no browser
;                  argument at all but still needs the environment option, and can be done at any time.
; Related .......: _WV2_SetEnvBrowserExtensions, _WV2_SetEnvBrowserArguments, _WV2_AddExtension
; ===============================================================================================================================
Func _WV2_LoadExtension($sFolder)
	$__WV2_sLastFunc = "_WV2_LoadExtension"
	If Not IsString($sFolder) Or $sFolder = "" Then
		__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_LoadExtension")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	EndIf
	$sFolder = __WV2_ExtPath($sFolder)
	If $sFolder = "" Or StringInStr(FileGetAttrib($sFolder), "D") = 0 Then
		__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_LoadExtension")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	EndIf
	; A comma is how the command line separates the folders of one switch, and Chromium has no escape for
	; it, so a folder that carries one cannot be loaded this way. It is refused here rather than turned
	; into a browser that silently loads the wrong two paths.
	If StringInStr($sFolder, ",") Then
		__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_LoadExtension")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	EndIf
	; The same reason as in _WV2_AddExtension: a folder without a manifest is a wrong path, not a browser
	; that refuses extensions, and the developer route would otherwise answer by loading nothing at all.
	If Not FileExists($sFolder & "\manifest.json") Then
		__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_LoadExtension: the folder holds no manifest.json")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	EndIf
	Local $iLive = __WV2_OptLive()
	_WV2_SetEnvBrowserExtensions(True)
	; One --load-extension only, the folders separated by commas: on the command line the last switch is
	; the one Chromium keeps, so two of them would silently drop the first folder.
	Local $sNew
	If StringInStr($__WV2_sOptAba, "--load-extension=") Then
		$sNew = StringReplace($__WV2_sOptAba, "--load-extension=", "--load-extension=" & $sFolder & ",", 1)
	Else
		$sNew = ($__WV2_sOptAba = "" ? "" : $__WV2_sOptAba & " ") & "--load-extension=" & $sFolder
	EndIf
	_WV2_SetEnvBrowserArguments($sNew)
	Return SetError(0, $iLive, 1)
EndFunc   ;==>_WV2_LoadExtension

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_AddExtension
; Description ...: Adds an unpacked extension folder to the profile of a view and brings its id back.
; Syntax ........: _WV2_AddExtension($iHandle, $sFolder, $sExtId[, $iTimeoutMs = $WV2_EXEC_TIMEOUT])
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $sFolder - Full path of the folder that holds the manifest.json of the extension.
;                  $sExtId  - Receives the id the browser gave the extension, passed by reference.
;                  $iTimeoutMs - Time allowed for the answer, in milliseconds.
; Return values .: Success: 1 and @error = 0.
;                  Failure: -1, with @error set to a $WV2_ERR_* code and @extended set to the raw
;                  HRESULT (0 if none): $WV2_ERR_ARG for a folder that is not one, $WV2_ERR_EXT when the
;                  runtime has no extension API or refused the folder, $WV2_ERR_TIMEOUT when it did not
;                  answer in time.
; Author ........: Numeric1
; Remarks .......: The extension stays in the profile: it is loaded again the next time a view is created
;                  on the same user data folder, so a script that only wants it for one run should call
;                  _WV2_RemoveExtension with the id it reads back here. The environment has to have been
;                  created with _WV2_SetEnvBrowserExtensions(True) - measured on runtime 157.0.4341.42,
;                  without that option nothing loads an extension, and no browser argument replaces it.
;                  Content of the extension reaches the page only for the addresses its manifest allows;
;                  a file:// page needs "file:///*" in content_scripts matches. The id is a hash of the path
;                  the browser was handed, and the browser counts a trailing separator as part of it, so the
;                  two spellings of one folder would be two extensions; the separators are taken off here,
;                  which is also what makes _WV2_LoadExtension and this call agree on one id for one folder.
; Related .......: _WV2_ListExtensions, _WV2_RemoveExtension, _WV2_SetExtensionEnabled
; ===============================================================================================================================
Func _WV2_AddExtension($iHandle, $sFolder, ByRef $sExtId, $iTimeoutMs = $WV2_EXEC_TIMEOUT)
	$__WV2_sLastFunc = "_WV2_AddExtension"
	$sExtId = ""
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	If Not IsString($sFolder) Or $sFolder = "" Then
		__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_AddExtension")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	EndIf
	$sFolder = __WV2_ExtPath($sFolder)
	If $sFolder = "" Or StringInStr(FileGetAttrib($sFolder), "D") = 0 Then
		__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_AddExtension")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	EndIf
	; The runtime answers a folder without a manifest with 0x80070002, which reads as "extension support
	; not available" and sends the reader to the environment option. Looking for the file first turns the
	; same mistake into the argument error it is.
	If Not FileExists($sFolder & "\manifest.json") Then
		__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_AddExtension: the folder holds no manifest.json")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	EndIf
	Local $p7 = __WV2_ExtProfile7($iHandle)
	If $p7 = 0 Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	Local $pFn = __WV2_VtFn($p7, $__WV2_SLOT_ICoreWebView2Profile7_AddBrowserExtension)
	If $pFn = 0 Then
		__WV2_ReleaseExternal($p7)
		__WV2_SetErr($WV2_ERR_COM, 0, "__WV2_VtFn")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	EndIf
	__WV2_BeginOp($iHandle, $__WV2_H_EXTADD)
	Local $aCall = DllCallAddress("long", $pFn, "ptr", $p7, "wstr", $sFolder, _
			"ptr", $__WV2_pObj[$iHandle][$__WV2_H_EXTADD])
	Local $iCallErr = @Error
	__WV2_ReleaseExternal($p7)
	If $iCallErr Or Not IsArray($aCall) Then
		__WV2_SetErr($WV2_ERR_COM, 0, "ICoreWebView2Profile7::AddBrowserExtension")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	EndIf
	If $aCall[0] <> 0 Then
		__WV2_SetErr($WV2_ERR_EXT, $aCall[0], "ICoreWebView2Profile7::AddBrowserExtension")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	EndIf
	If Not __WV2_WaitOp($iHandle, $__WV2_H_EXTADD, $iTimeoutMs) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	Local $iDoneHR = $__WV2_iOpHR[$iHandle][$__WV2_H_EXTADD]
	Local $pExt = $__WV2_pOpObj[$iHandle][$__WV2_H_EXTADD]
	$__WV2_pOpObj[$iHandle][$__WV2_H_EXTADD] = 0
	If $iDoneHR <> 0 Or $pExt = 0 Then
		__WV2_ReleaseExternal($pExt)
		__WV2_SetErr($WV2_ERR_EXT, $iDoneHR, "ICoreWebView2ProfileAddBrowserExtensionCompletedHandler")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	EndIf
	$sExtId = __WV2_WStrProp($pExt, $__WV2_SLOT_ICoreWebView2BrowserExtension_get_Id)
	__WV2_ReleaseExternal($pExt)
	$__WV2_iLastError = $WV2_ERR_NONE
	$__WV2_iLastHR = 0
	Return SetError(0, 0, 1)
EndFunc   ;==>_WV2_AddExtension

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_ListExtensions
; Description ...: Lists the extensions the profile of a view holds.
; Syntax ........: _WV2_ListExtensions($iHandle, $aExt[, $iTimeoutMs = $WV2_EXEC_TIMEOUT])
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $aExt    - Receives the array, passed by reference.
;                  $iTimeoutMs - Time allowed for the answer, in milliseconds.
; Return values .: Success: the number of extensions, the array holding:
;                     [n][0] id      the string _WV2_AddExtension returned
;                     [n][1] name    the manifest name
;                     [n][2] enabled 1 on, 0 off
;                  When the profile holds none, the array is 0 x 3: UBound() gives 0, not an error.
;                  Failure: -1, with @error set to a $WV2_ERR_* code and @extended set to the raw
;                  HRESULT (0 if none).
; Author ........: Numeric1
; Remarks .......: The list is the profile's, not the view's: two views on the same user data folder read
;                  the same extensions. Reading it costs one round trip to the browser process, so a
;                  script that needs the id of an extension it just added should keep what
;                  _WV2_AddExtension gave back rather than list again.
; Related .......: _WV2_AddExtension, _WV2_RemoveExtension, _WV2_SetExtensionEnabled
; ===============================================================================================================================
Func _WV2_ListExtensions($iHandle, ByRef $aExt, $iTimeoutMs = $WV2_EXEC_TIMEOUT)
	$__WV2_sLastFunc = "_WV2_ListExtensions"
	Local $aEmpty[0][3]
	$aExt = $aEmpty
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	Local $pList = __WV2_ExtList($iHandle, $iTimeoutMs)
	If $pList = 0 Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	Local $iCount = __WV2_IntProp($pList, $__WV2_SLOT_ICoreWebView2BrowserExtensionList_get_Count)
	If $iCount < 0 Then $iCount = 0
	Local $aOut[$iCount][3]
	Local $k
	For $k = 0 To $iCount - 1
		Local $pExt = __WV2_GetIfaceAt($pList, $__WV2_SLOT_ICoreWebView2BrowserExtensionList_GetValueAtIndex, $k)
		If $pExt = 0 Then ContinueLoop
		$aOut[$k][0] = __WV2_WStrProp($pExt, $__WV2_SLOT_ICoreWebView2BrowserExtension_get_Id)
		$aOut[$k][1] = __WV2_WStrProp($pExt, $__WV2_SLOT_ICoreWebView2BrowserExtension_get_Name)
		$aOut[$k][2] = __WV2_BoolProp($pExt, $__WV2_SLOT_ICoreWebView2BrowserExtension_get_IsEnabled)
		__WV2_ReleaseExternal($pExt)
	Next
	__WV2_ReleaseExternal($pList)
	$aExt = $aOut
	$__WV2_iLastError = $WV2_ERR_NONE
	$__WV2_iLastHR = 0
	Return SetError(0, 0, $iCount)
EndFunc   ;==>_WV2_ListExtensions

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_SetExtensionEnabled
; Description ...: Turns an extension of the profile on or off.
; Syntax ........: _WV2_SetExtensionEnabled($iHandle, $sExtId, $bEnable[, $iTimeoutMs = $WV2_EXEC_TIMEOUT])
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $sExtId  - The id _WV2_AddExtension returned, or one read from _WV2_ListExtensions.
;                  $bEnable - True to enable, False to disable.
;                  $iTimeoutMs - Time allowed for the answer, in milliseconds.
; Return values .: Success: 1 and @error = 0.
;                  Failure: -1, with @error set to a $WV2_ERR_* code and @extended set to the raw
;                  HRESULT (0 if none). $WV2_ERR_ARG means no extension of the profile carries that id.
; Author ........: Numeric1
; Remarks .......: The state is remembered by the profile, and what a running page makes of it is the
;                  extension's own business: content scripts already injected stay in the document. Turn
;                  an extension off before the navigation it is meant to change, or reload the page.
; Related .......: _WV2_ListExtensions, _WV2_RemoveExtension
; ===============================================================================================================================
Func _WV2_SetExtensionEnabled($iHandle, $sExtId, $bEnable, $iTimeoutMs = $WV2_EXEC_TIMEOUT)
	$__WV2_sLastFunc = "_WV2_SetExtensionEnabled"
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	If Not IsString($sExtId) Or $sExtId = "" Then
		__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_SetExtensionEnabled")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	EndIf
	Local $pExt = __WV2_ExtById($iHandle, $sExtId, $iTimeoutMs)
	If $pExt = 0 Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	Local $pFn = __WV2_VtFn($pExt, $__WV2_SLOT_ICoreWebView2BrowserExtension_Enable)
	If $pFn = 0 Then
		__WV2_ReleaseExternal($pExt)
		__WV2_SetErr($WV2_ERR_COM, 0, "__WV2_VtFn")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	EndIf
	__WV2_BeginOp($iHandle, $__WV2_H_EXTENABLE)
	Local $aCall = DllCallAddress("long", $pFn, "ptr", $pExt, "int", ($bEnable ? 1 : 0), _
			"ptr", $__WV2_pObj[$iHandle][$__WV2_H_EXTENABLE])
	Local $iCallErr = @Error
	If $iCallErr Or Not IsArray($aCall) Then
		__WV2_ReleaseExternal($pExt)
		__WV2_SetErr($WV2_ERR_COM, 0, "ICoreWebView2BrowserExtension::Enable")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	EndIf
	If $aCall[0] <> 0 Then
		__WV2_ReleaseExternal($pExt)
		__WV2_SetErr($WV2_ERR_EXT, $aCall[0], "ICoreWebView2BrowserExtension::Enable")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	EndIf
	If Not __WV2_WaitOp($iHandle, $__WV2_H_EXTENABLE, $iTimeoutMs) Then
		__WV2_ReleaseExternal($pExt)
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	EndIf
	Local $iDoneHR = $__WV2_iOpHR[$iHandle][$__WV2_H_EXTENABLE]
	__WV2_ReleaseExternal($pExt)
	If $iDoneHR <> 0 Then
		__WV2_SetErr($WV2_ERR_EXT, $iDoneHR, "ICoreWebView2BrowserExtensionEnableCompletedHandler")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	EndIf
	$__WV2_iLastError = $WV2_ERR_NONE
	$__WV2_iLastHR = 0
	Return SetError(0, 0, 1)
EndFunc   ;==>_WV2_SetExtensionEnabled

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_RemoveExtension
; Description ...: Takes an extension out of the profile of a view.
; Syntax ........: _WV2_RemoveExtension($iHandle, $sExtId[, $iTimeoutMs = $WV2_EXEC_TIMEOUT])
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $sExtId  - The id _WV2_AddExtension returned.
;                  $iTimeoutMs - Time allowed for the answer, in milliseconds.
; Return values .: Success: 1 and @error = 0.
;                  Failure: -1, with @error set to a $WV2_ERR_* code and @extended set to the raw
;                  HRESULT (0 if none). $WV2_ERR_ARG means no extension of the profile carries that id.
; Author ........: Numeric1
; Remarks .......: Removal is the profile's, not the folder's: the files on disk stay where they are, and
;                  an extension that came from --load-extension is not a browser extension the profile
;                  holds, so it is not in _WV2_ListExtensions and cannot be removed here - it simply stops
;                  being loaded when the option and the argument are not set again.
; Related .......: _WV2_AddExtension, _WV2_ListExtensions, _WV2_SetExtensionEnabled
; ===============================================================================================================================
Func _WV2_RemoveExtension($iHandle, $sExtId, $iTimeoutMs = $WV2_EXEC_TIMEOUT)
	$__WV2_sLastFunc = "_WV2_RemoveExtension"
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	If Not IsString($sExtId) Or $sExtId = "" Then
		__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_RemoveExtension")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	EndIf
	Local $pExt = __WV2_ExtById($iHandle, $sExtId, $iTimeoutMs)
	If $pExt = 0 Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	Local $pFn = __WV2_VtFn($pExt, $__WV2_SLOT_ICoreWebView2BrowserExtension_Remove)
	If $pFn = 0 Then
		__WV2_ReleaseExternal($pExt)
		__WV2_SetErr($WV2_ERR_COM, 0, "__WV2_VtFn")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	EndIf
	__WV2_BeginOp($iHandle, $__WV2_H_EXTREMOVE)
	Local $aCall = DllCallAddress("long", $pFn, "ptr", $pExt, _
			"ptr", $__WV2_pObj[$iHandle][$__WV2_H_EXTREMOVE])
	Local $iCallErr = @Error
	If $iCallErr Or Not IsArray($aCall) Then
		__WV2_ReleaseExternal($pExt)
		__WV2_SetErr($WV2_ERR_COM, 0, "ICoreWebView2BrowserExtension::Remove")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	EndIf
	If $aCall[0] <> 0 Then
		__WV2_ReleaseExternal($pExt)
		__WV2_SetErr($WV2_ERR_EXT, $aCall[0], "ICoreWebView2BrowserExtension::Remove")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	EndIf
	If Not __WV2_WaitOp($iHandle, $__WV2_H_EXTREMOVE, $iTimeoutMs) Then
		__WV2_ReleaseExternal($pExt)
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	EndIf
	Local $iDoneHR = $__WV2_iOpHR[$iHandle][$__WV2_H_EXTREMOVE]
	__WV2_ReleaseExternal($pExt)
	If $iDoneHR <> 0 Then
		__WV2_SetErr($WV2_ERR_EXT, $iDoneHR, "ICoreWebView2BrowserExtensionRemoveCompletedHandler")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	EndIf
	$__WV2_iLastError = $WV2_ERR_NONE
	$__WV2_iLastHR = 0
	Return SetError(0, 0, 1)
EndFunc   ;==>_WV2_RemoveExtension

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_CallDevToolsProtocolMethod
; Description ...: Calls a method of the DevTools protocol and brings its answer back.
; Syntax ........: _WV2_CallDevToolsProtocolMethod($iHandle, $sMethod, $sParams, $sResult[,
;                  $iTimeoutMs = $WV2_EXEC_TIMEOUT])
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $sMethod - Full name of the method, e.g. "Network.enable" or "Page.captureScreenshot".
;                  $sParams - Arguments as a JSON object, e.g. '{"format":"png"}'; "" or "{}" for none.
;                  $sResult - Receives the answer as JSON text, passed by reference.
;                  $iTimeoutMs - Time allowed for the runtime to answer, in milliseconds.
; Return values .: Success: 1, $sResult holding the JSON of the answer. Failure: 0, with @error set to
;                  a $WV2_ERR_* code and @extended set to the raw HRESULT (0 if none). A method the
;                  protocol refuses is a success of the call and a failure of the method: the runtime
;                  answers {"code":-32601,...}, which $sResult carries.
; Author ........: Numeric1
; Remarks .......: This is the whole DevTools protocol, the one the F12 panel speaks: pages, network,
;                  emulation, DOM, tracing. The parameter text is handed to the runtime as written, so
;                  it has to be valid JSON; quotes are the ones of the script. Only one call may run
;                  at a time per view, and Windows messages are pumped while waiting.
; Related .......: _WV2_SetDevToolsProtocolEvent, _WV2_ExecuteScript
; ===============================================================================================================================
Func _WV2_CallDevToolsProtocolMethod($iHandle, $sMethod, $sParams, ByRef $sResult, $iTimeoutMs = $WV2_EXEC_TIMEOUT)
	$__WV2_sLastFunc = "_WV2_CallDevToolsProtocolMethod"
	$sResult = ""
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	$sMethod = StringStripWS(String($sMethod), 3)
	If $sMethod = "" Then
		__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_CallDevToolsProtocolMethod")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	If Not IsString($sParams) Then $sParams = String($sParams)
	If StringStripWS($sParams, 3) = "" Then $sParams = "{}"
	Local $pWv = $__WV2_pWv[$iHandle]
	Local $pFn = __WV2_VtFn($pWv, $__WV2_SLOT_ICoreWebView2_CallDevToolsProtocolMethod)
	If $pFn = 0 Then
		__WV2_SetErr($WV2_ERR_COM, 0, "__WV2_VtFn")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	__WV2_BeginOp($iHandle, $__WV2_H_CDPCALL)
	Local $aCall = DllCallAddress("long", $pFn, "ptr", $pWv, "wstr", $sMethod, "wstr", $sParams, _
			"ptr", $__WV2_pObj[$iHandle][$__WV2_H_CDPCALL])
	If @Error Or Not IsArray($aCall) Then
		__WV2_SetErr($WV2_ERR_COM, 0, "ICoreWebView2::CallDevToolsProtocolMethod")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	If $aCall[0] <> 0 Then
		__WV2_SetErr($WV2_ERR_CALL, $aCall[0], "ICoreWebView2::CallDevToolsProtocolMethod")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	If Not __WV2_WaitOp($iHandle, $__WV2_H_CDPCALL, $iTimeoutMs) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	$sResult = $__WV2_sOpOut[$iHandle][$__WV2_H_CDPCALL]
	; A refusal of the protocol itself (method it does not know, parameters it rejects) still answers
	; with JSON whose "error" object carries the code: E_INVALIDARG arrives here for an unknown method,
	; and the JSON is what the caller has to read. Only a call that brings no answer at all fails.
	If $sResult <> "" Then
		$__WV2_iLastError = $WV2_ERR_NONE
		$__WV2_iLastHR = 0
		Return SetError(0, 0, 1)
	EndIf
	If $__WV2_iOpHR[$iHandle][$__WV2_H_CDPCALL] <> 0 Then
		__WV2_SetErr($WV2_ERR_CALL, $__WV2_iOpHR[$iHandle][$__WV2_H_CDPCALL], "ICoreWebView2CallDevToolsProtocolMethodCompletedHandler")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	$__WV2_iLastError = $WV2_ERR_NONE
	$__WV2_iLastHR = 0
	Return SetError(0, 0, 1)
EndFunc   ;==>_WV2_CallDevToolsProtocolMethod

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_SetDevToolsProtocolEvent
; Description ...: Subscribes the script to a DevTools protocol event, or unsubscribes it.
; Syntax ........: _WV2_SetDevToolsProtocolEvent($iHandle[, $sEventName = ""])
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $sEventName - Full name of the event, e.g. "Network.requestWillBeSent". "" removes
;                   the subscription.
; Return values .: Success: 1. Failure: 0, with @error set to a $WV2_ERR_* code and @extended set to
;                  the raw HRESULT (0 if none); $WV2_ERR_ARG covers an empty name given to a call that
;                  is not a removal.
; Author ........: Numeric1
; Remarks .......: One event at a time per view: a second call replaces the first. The events of a
;                  domain only arrive once its methods are enabled, so "Network.requestWillBeSent"
;                  needs a _WV2_CallDevToolsProtocolMethod("Network.enable", "{}") first. Each event
;                  reaches the queue as $WV2_EVENT_DEVTOOLS, $sData holding its parameters as JSON,
;                  which is what makes _WV2_EnableEvent unnecessary here: the subscription is the
;                  switch. The two calls may be written in either order, but a view that was told to keep
;                  $WV2_EVENT_DEVTOOLS off stays unheard until it is enabled again, receiver or not.
;                  Pick the name from the DevTools protocol, not from habit: measured on runtime 156, a
;                  console.log line arrives as "Runtime.consoleAPICalled" with its arguments as JSON, while
;                  "Log.entryAdded" is the browser log and answered only with the failed load of a missing
;                  image.
; Related .......: _WV2_CallDevToolsProtocolMethod, _WV2_GetEvent
; ===============================================================================================================================
Func _WV2_SetDevToolsProtocolEvent($iHandle, $sEventName = "")
	$__WV2_sLastFunc = "_WV2_SetDevToolsProtocolEvent"
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	$sEventName = StringStripWS(String($sEventName), 3)

	; Whatever the previous subscription held goes first, so the new one is the only one in force.
	__WV2_Detach($iHandle, $__WV2_H_CDPEVT)
	If $__WV2_pCdpRecv[$iHandle] <> 0 Then
		__WV2_ReleaseExternal($__WV2_pCdpRecv[$iHandle])
		$__WV2_pCdpRecv[$iHandle] = 0
	EndIf
	$__WV2_sCdpEvent[$iHandle] = ""
	If $sEventName = "" Then
		$__WV2_iLastError = $WV2_ERR_NONE
		$__WV2_iLastHR = 0
		Return SetError(0, 0, 1)
	EndIf

	Local $pWv = $__WV2_pWv[$iHandle]
	Local $pFn = __WV2_VtFn($pWv, $__WV2_SLOT_ICoreWebView2_GetDevToolsProtocolEventReceiver)
	If $pFn = 0 Then
		__WV2_SetErr($WV2_ERR_COM, 0, "__WV2_VtFn")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	Local $tOut = DllStructCreate("ptr")
	Local $aCall = DllCallAddress("long", $pFn, "ptr", $pWv, "wstr", $sEventName, "ptr", DllStructGetPtr($tOut))
	If @Error Or Not IsArray($aCall) Then
		__WV2_SetErr($WV2_ERR_COM, 0, "ICoreWebView2::GetDevToolsProtocolEventReceiver")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	Local $pRecv = DllStructGetData($tOut, 1)
	If $aCall[0] <> 0 Or $pRecv = 0 Then
		__WV2_SetErr($WV2_ERR_CALL, $aCall[0], "ICoreWebView2::GetDevToolsProtocolEventReceiver")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf

	$__WV2_pCdpRecv[$iHandle] = $pRecv
	$__WV2_sCdpEvent[$iHandle] = $sEventName
	; A host that turned $WV2_EVENT_DEVTOOLS off with _WV2_EnableEvent keeps the answer: the receiver and
	; its name are remembered, so the event reaches the queue again if it is enabled later, but no handler
	; is subscribed here.
	If $__WV2_bCdpOff[$iHandle] Then
		$__WV2_iLastError = $WV2_ERR_NONE
		$__WV2_iLastHR = 0
		Return SetError(0, 0, 1)
	EndIf
	If Not __WV2_Attach($iHandle, $__WV2_H_CDPEVT) Then
		$__WV2_sCdpEvent[$iHandle] = ""
		__WV2_ReleaseExternal($__WV2_pCdpRecv[$iHandle])
		$__WV2_pCdpRecv[$iHandle] = 0
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	$__WV2_iLastError = $WV2_ERR_NONE
	$__WV2_iLastHR = 0
	Return SetError(0, 0, 1)
EndFunc   ;==>_WV2_SetDevToolsProtocolEvent

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_IsPlayingAudio
; Description ...: Tells whether the document of this view is playing audio.
; Syntax ........: _WV2_IsPlayingAudio($iHandle)
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
; Return values .: Success: 1 (something is playing) or 0 (nothing is), @error = 0.
;                  Failure: -1, with @error set to a $WV2_ERR_* code and @extended set to the raw
;                  HRESULT (0 if none).
; Author ........: Numeric1
; Remarks .......: This is the state of the document as a whole - "is any audio reaching the user from
;                  this view" - not the state of one element, and it says nothing about video that carries
;                  no sound track. Measured on runtime 156: the runtime answers from the samples it is
;                  really producing, so a file of digital silence never raises it (an element can sit at
;                  paused:false, readyState:4, volume:0.7 and the answer stays 0), and the Chromium switch
;                  --mute-audio keeps it at 0 for the whole view. A host mute through _WV2_SetMuted does
;                  NOT: the tone is silenced for the user and the state still reads 1, which is what lets a
;                  test of this function stay inaudible. Because the answer comes from the media pipeline,
;                  a sound shorter than one scheduler tick can be missed: wait for
;                  $WV2_EVENT_PLAYING_AUDIO_CHANGED when the moment matters. Needs a WebView2 runtime of
;                  97.0.1072.54 or newer; on an older one the call fails with @error = $WV2_ERR_CALL and
;                  @extended = 0x80004002 (E_NOINTERFACE), it never crashes.
; Related .......: _WV2_IsMuted, _WV2_SetMuted, _WV2_EnableEvent
; ===============================================================================================================================
Func _WV2_IsPlayingAudio($iHandle)
	$__WV2_sLastFunc = "_WV2_IsPlayingAudio"
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	Local $p8 = __WV2_ViewIf($iHandle, $__WV2_IF_8)
	If $p8 = 0 Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	Local $iValue = __WV2_BoolProp($p8, $__WV2_SLOT_ICoreWebView2_8_get_IsDocumentPlayingAudio)
	If $iValue < 0 Then
		__WV2_SetErr($WV2_ERR_CALL, 0, "ICoreWebView2_8::get_IsDocumentPlayingAudio")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	EndIf
	$__WV2_iLastError = $WV2_ERR_NONE
	$__WV2_iLastHR = 0
	Return SetError(0, 0, $iValue)
EndFunc   ;==>_WV2_IsPlayingAudio

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_IsMuted
; Description ...: Tells whether this view is muted by the host.
; Syntax ........: _WV2_IsMuted($iHandle)
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
; Return values .: Success: 1 or 0, @error = 0.
;                  Failure: -1, with @error set to a $WV2_ERR_* code and @extended set to the raw HRESULT.
; Author ........: Numeric1
; Remarks .......: The mute set here belongs to the view, not to the page: a script that sets
;                  element.volume still changes what the page believes, while the user hears nothing. It
;                  is not the system mute and it does not touch other views of the same process.
; Related .......: _WV2_SetMuted, _WV2_IsPlayingAudio
; ===============================================================================================================================
Func _WV2_IsMuted($iHandle)
	$__WV2_sLastFunc = "_WV2_IsMuted"
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	Local $p8 = __WV2_ViewIf($iHandle, $__WV2_IF_8)
	If $p8 = 0 Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	Local $iValue = __WV2_BoolProp($p8, $__WV2_SLOT_ICoreWebView2_8_get_IsMuted)
	If $iValue < 0 Then
		__WV2_SetErr($WV2_ERR_CALL, 0, "ICoreWebView2_8::get_IsMuted")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	EndIf
	$__WV2_iLastError = $WV2_ERR_NONE
	$__WV2_iLastHR = 0
	Return SetError(0, 0, $iValue)
EndFunc   ;==>_WV2_IsMuted

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_SetMuted
; Description ...: Mutes or unmutes every sound this view plays, without asking the page.
; Syntax ........: _WV2_SetMuted($iHandle, $bMuted)
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $bMuted - True mutes the view, False lets it sound again.
; Return values .: Success: 1. Failure: 0, with @error set to a $WV2_ERR_* code and @extended set to the
;                  raw HRESULT (0 if none).
; Author ........: Numeric1
; Remarks .......: The change is remembered by the view, so it survives a navigation of the same handle;
;                  it is not written back to the page, which keeps believing it plays at its own volume.
;                  Measured on runtime 156: muting here does not silence the state read by
;                  _WV2_IsPlayingAudio - the user hears nothing and the view still answers 1 - which is
;                  how a test of the audio events can be both automatic and inaudible. Every call that
;                  changes the state raises $WV2_EVENT_MUTED_CHANGED, including one the host makes itself,
;                  so a handler counting mutes must not assume the page was the author.
; Related .......: _WV2_IsMuted, _WV2_EnableEvent
; ===============================================================================================================================
Func _WV2_SetMuted($iHandle, $bMuted)
	$__WV2_sLastFunc = "_WV2_SetMuted"
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	Local $p8 = __WV2_ViewIf($iHandle, $__WV2_IF_8)
	If $p8 = 0 Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	Local $bOk = __WV2_Result(__WV2_CallBool($p8, $__WV2_SLOT_ICoreWebView2_8_put_IsMuted, $bMuted ? 1 : 0), _
			"ICoreWebView2_8::put_IsMuted")
	Return SetError($__WV2_iLastError, $__WV2_iLastHR, $bOk)
EndFunc   ;==>_WV2_SetMuted

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_IsFullScreen
; Description ...: Tells whether an element of this view is displayed in full screen.
; Syntax ........: _WV2_IsFullScreen($iHandle)
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
; Return values .: Success: 1 (an element is in full screen) or 0 (none is), @error = 0.
;                  Failure: -1, with @error set to a $WV2_ERR_* code and @extended set to the raw
;                  HRESULT (0 if none).
; Author ........: Numeric1
; Remarks .......: This reports the page's own full screen - the one an element reaches through
;                  requestFullscreen(), which is also what the full-screen button of a <video> uses. It
;                  is not the host window: a view whose GUI has been maximised with WinAPI calls answers
;                  0 here. There is no way for the host to put an element in full screen; the page has to
;                  do it, and _WV2_ExecuteScript or a button in the page is how a test drives it. The
;                  state is read on the base interface, so any runtime that hosts this UDF answers it -
;                  ContainsFullScreenElementChanged is one of the oldest events of WebView2.
;                  Measured on runtime 156: a requestFullscreen() called from _WV2_ExecuteScript is
;                  accepted, so a test needs no keyboard and no mouse. Measured on 157.0.4341.42: the same
;                  call answers TypeError "not granted" while the document is not the foreground one, and
;                  is accepted again as soon as the protocol has brought it forward - "Page.bringToFront"
;                  through _WV2_CallDevToolsProtocolMethod is enough, with no press and no gesture, and a
;                  script exitFullscreen() is accepted too. The --autoplay-policy browser argument does not
;                  cover this, and neither does a click the page dispatches itself. Entering raises the
;                  event with $iValue = 1 and leaving raises it again with 0; asking for full screen while
;                  already in it changes nothing and raises nothing.
;                  Element full screen resizes the view over the whole monitor, so an automatic test
;                  should leave it as soon as it has seen the 1.
; Related .......: _WV2_EnableEvent, $WV2_EVENT_FULLSCREEN_CHANGED
; ===============================================================================================================================
Func _WV2_IsFullScreen($iHandle)
	$__WV2_sLastFunc = "_WV2_IsFullScreen"
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	Local $iValue = __WV2_BoolProp($__WV2_pWv[$iHandle], $__WV2_SLOT_ICoreWebView2_get_ContainsFullScreenElement)
	If $iValue < 0 Then
		__WV2_SetErr($WV2_ERR_CALL, 0, "ICoreWebView2::get_ContainsFullScreenElement")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	EndIf
	$__WV2_iLastError = $WV2_ERR_NONE
	$__WV2_iLastHR = 0
	Return SetError(0, 0, $iValue)
EndFunc   ;==>_WV2_IsFullScreen

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_SetPermissionPolicy
; Description ...: Decides in advance how this view answers a request for one kind of permission.
; Syntax ........: _WV2_SetPermissionPolicy($iHandle, $iKind, $iPolicy)
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $iKind - one of the $WV2_PERM_* kinds the page can ask for.
;                  $iPolicy - $WV2_PERM_DEFAULT lets the runtime decide, $WV2_PERM_ALLOW grants,
;                  $WV2_PERM_DENY refuses, $WV2_PERM_ASK holds the request in the queue until
;                  _WV2_PermissionRespond answers it.
; Return values .: Success: 1. Failure: 0, with @error set to $WV2_ERR_ARG for a kind or a policy
;                  outside the list, or to the other $WV2_ERR_* codes.
; Author ........: Numeric1
; Remarks .......: The decision is read when the request arrives, so it has to be set before the page
;                  asks; a WebView2 has no prompt of its own and what nobody answered is not granted.
;                  It is remembered per view and per kind, never per origin: a policy of $WV2_PERM_ALLOW
;                  on $WV2_PERM_MICROPHONE opens the microphone to every page this view shows, which is
;                  what a kiosk wants and what a browser must not want. Ask for the origin in the event
;                  and answer it with $WV2_PERM_ASK when the host should choose.
;                  The kinds $WV2_PERM_AUTOPLAY and $WV2_PERM_MIDI_SYSEX are only ever reported by a
;                  runtime of 111.0.1661.34 or newer; a policy set for them on an older one is simply
;                  never read.
;                  Measured on runtime 156 with a page asking for four permissions at once: microphone
;                  with $WV2_PERM_ALLOW came back granted, camera with $WV2_PERM_DENY came back as
;                  NotAllowedError inside the page, and geolocation and notifications set to
;                  $WV2_PERM_ASK waited until _WV2_PermissionRespond answered - the notification promise
;                  resolved only at that moment. The camera request is the slowest of the four and can
;                  arrive seconds after the page asked, so a test that waits for it must wait long.
; Related .......: _WV2_PermissionRespond, _WV2_GetPendingPermissions, _WV2_EnableEvent
; ===============================================================================================================================
Func _WV2_SetPermissionPolicy($iHandle, $iKind, $iPolicy)
	$__WV2_sLastFunc = "_WV2_SetPermissionPolicy"
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	If $iKind < 0 Or $iKind > $__WV2_PERM_KIND_MAX Or $iPolicy < 0 Or $iPolicy > $WV2_PERM_ASK Then
		__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_SetPermissionPolicy")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	$__WV2_iPermPol[$iHandle][$iKind] = $iPolicy
	$__WV2_iLastError = $WV2_ERR_NONE
	$__WV2_iLastHR = 0
	Return SetError(0, 0, 1)
EndFunc   ;==>_WV2_SetPermissionPolicy

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_GetPendingPermissions
; Description ...: Lists the permission requests this view is holding because their policy was
;                  $WV2_PERM_ASK, oldest first.
; Syntax ........: _WV2_GetPendingPermissions($iHandle, ByRef $aList)
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $aList - Receives the list: [0][0] counts the requests waiting, and every later row
;                  holds one request as index, origin and kind.
; Return values .: Success: 1, @error = 0. Failure: 0, with @error set to a $WV2_ERR_* code.
; Author ........: Numeric1
; Remarks .......: $aList[0][0] is how many requests wait; $aList[$n][0] is the index to give to
;                  _WV2_PermissionRespond, $aList[$n][1] the origin that asked and $aList[$n][2] the
;                  kind, a $WV2_PERM_* value. The index counts the waiting requests, so it changes when
;                  one is answered: read the list again rather than reuse an old row.
; Related .......: _WV2_PermissionRespond, _WV2_SetPermissionPolicy
; ===============================================================================================================================
Func _WV2_GetPendingPermissions($iHandle, ByRef $aList)
	$__WV2_sLastFunc = "_WV2_GetPendingPermissions"
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	Local $iWait = __WV2_PermWait($iHandle)
	Local $aOut[$iWait + 1][3]
	$aOut[0][0] = $iWait
	Local $n, $iSlot
	For $n = 1 To $iWait
		$iSlot = __WV2_PermSlot($iHandle, $n)
		$aOut[$n][0] = $n
		$aOut[$n][1] = $__WV2_sPermUri[$iHandle][$iSlot]
		$aOut[$n][2] = $__WV2_iPermKind[$iHandle][$iSlot]
	Next
	$aList = $aOut
	$__WV2_iLastError = $WV2_ERR_NONE
	$__WV2_iLastHR = 0
	Return SetError(0, 0, 1)
EndFunc   ;==>_WV2_GetPendingPermissions

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_PermissionRespond
; Description ...: Answers one of the permission requests the view is holding, after its handler
;                  returned.
; Syntax ........: _WV2_PermissionRespond($iHandle, $iIndex, $iState)
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $iIndex - which waiting request, 1 being the oldest, as _WV2_GetPendingPermissions
;                  numbers them.
;                  $iState - $WV2_PERM_ALLOW, $WV2_PERM_DENY or $WV2_PERM_DEFAULT.
; Return values .: Success: 1. Failure: 0, with @error set to $WV2_ERR_ARG when nothing waits at that
;                  index or the state is not one of the three, or to the other $WV2_ERR_* codes.
; Author ........: Numeric1
; Remarks .......: This is what $WV2_PERM_ASK is for: the page waits, the host shows its own dialog, and
;                  the answer goes to the runtime when the user has chosen. The request is closed either
;                  way - answering an index twice fails, and a request nobody answers stays open until
;                  the view is destroyed, which leaves the page waiting.
; Related .......: _WV2_SetPermissionPolicy, _WV2_GetPendingPermissions
; ===============================================================================================================================
Func _WV2_PermissionRespond($iHandle, $iIndex, $iState)
	$__WV2_sLastFunc = "_WV2_PermissionRespond"
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	If $iState < 0 Or $iState > $WV2_PERM_DENY Then
		__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_PermissionRespond")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	Local $j = __WV2_PermSlot($iHandle, $iIndex)
	If $j = 0 Then
		__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_PermissionRespond")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	Local $pArgs = $__WV2_pPermArgs[$iHandle][$j]
	__WV2_CallLong($pArgs, $__WV2_SLOT_ICoreWebView2PermissionRequestedEventArgs_put_State, $iState)
	__WV2_PermForget($iHandle, $j)
	$__WV2_iLastError = $WV2_ERR_NONE
	$__WV2_iLastHR = 0
	Return SetError(0, 0, 1)
EndFunc   ;==>_WV2_PermissionRespond

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_SetColorScheme
; Description ...: Tells the pages and the browser UI of a view which colour scheme to draw themselves in.
; Syntax ........: _WV2_SetColorScheme($iHandle, $iScheme)
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $iScheme - $WV2_SCHEME_AUTO, $WV2_SCHEME_LIGHT or $WV2_SCHEME_DARK.
; Return values .: Success: 1, @error = 0.
;                  Failure: 0, with @error set to a $WV2_ERR_* code ($WV2_ERR_ARG for a number outside
;                  the three schemes, $WV2_ERR_CALL on a runtime older than ICoreWebView2_13) and
;                  @extended set to the raw HRESULT (0 if none).
; Author ........: Numeric1
; Remarks .......: The scheme is a property of the profile, not of the page: it is written once and
;                  every navigation of that view answers to it. A page that reads
;                  matchMedia("(prefers-color-scheme: dark)") sees what is set here, and so do the
;                  dialogs, prompts and context menus of the browser. AUTO - which is what the runtime
;                  answers before anything has been written - follows the Windows theme instead.
;
;                  Nothing is redrawn: a page that is already on screen keeps the colours it chose until
;                  it is navigated again. That is the runtime's behaviour, and _WV2_Reload is what makes
;                  it visible.
; Related .......: _WV2_GetColorScheme, _WV2_SetBackgroundColor, _WV2_SetDarkTitleBar
; ===============================================================================================================================
Func _WV2_SetColorScheme($iHandle, $iScheme)
	$__WV2_sLastFunc = "_WV2_SetColorScheme"
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	If $iScheme < 0 Or $iScheme > $__WV2_SCHEME_MAX Then
		__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_SetColorScheme")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	Local $pProf = __WV2_ProfileObj($iHandle)
	If $pProf = 0 Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	Local $bOk = __WV2_Result(__WV2_CallLong($pProf, _
			$__WV2_SLOT_ICoreWebView2Profile_put_PreferredColorScheme, $iScheme), _
			"ICoreWebView2Profile::put_PreferredColorScheme")
	Return SetError($__WV2_iLastError, $__WV2_iLastHR, $bOk)
EndFunc   ;==>_WV2_SetColorScheme

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_GetColorScheme
; Description ...: Reads back the colour scheme a view was given.
; Syntax ........: _WV2_GetColorScheme($iHandle)
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
; Return values .: Success: one of $WV2_SCHEME_AUTO, $WV2_SCHEME_LIGHT or $WV2_SCHEME_DARK, @error = 0.
;                  Failure: -1, with @error set to a $WV2_ERR_* code and @extended set to the raw
;                  HRESULT (0 if none).
; Author ........: Numeric1
; Remarks .......: AUTO is both the default of a profile and the answer of a view that was never given a
;                  scheme, so this is where a program finds out what it is really asking for: the value
;                  read back after $WV2_SCHEME_DARK is 2, not 0.
; Related .......: _WV2_SetColorScheme
; ===============================================================================================================================
Func _WV2_GetColorScheme($iHandle)
	$__WV2_sLastFunc = "_WV2_GetColorScheme"
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	Local $pProf = __WV2_ProfileObj($iHandle)
	If $pProf = 0 Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	Local $iScheme = __WV2_IntProp($pProf, $__WV2_SLOT_ICoreWebView2Profile_get_PreferredColorScheme)
	If $iScheme < 0 Then
		__WV2_SetErr($WV2_ERR_CALL, 0, "ICoreWebView2Profile::get_PreferredColorScheme")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	EndIf
	Return SetError(0, 0, $iScheme)
EndFunc   ;==>_WV2_GetColorScheme

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_SetBackgroundColor
; Description ...: Sets the colour the view renders underneath the web content.
; Syntax ........: _WV2_SetBackgroundColor($iHandle, $iRed, $iGreen, $iBlue[, $iAlpha])
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $iRed    - 0 to 255.
;                  $iGreen  - 0 to 255.
;                  $iBlue   - 0 to 255.
;                  $iAlpha  - Optional: 255 (the default) for an opaque colour, 0 for a transparent one.
; Return values .: Success: 1, @error = 0.
;                  Failure: 0, with @error set to a $WV2_ERR_* code ($WV2_ERR_ARG for a channel outside
;                  0 to 255, or an alpha that is neither 0 nor 255) and @extended set to the raw HRESULT
;                  (0 if none).
; Author ........: Numeric1
; Remarks .......: This is the colour of the view itself, not of the page: it shows before the first
;                  navigation, between two of them, and wherever the page leaves its own background
;                  undefined or transparent. A page that paints an opaque background over the whole
;                  document hides it completely. The runtime defaults to white.
;
;                  Semi-transparent colours are not accepted, by the runtime as much as here: the only
;                  alpha values that exist for this property are 0 and 255, and anything in between comes
;                  back as E_INVALIDARG.
;
;                  A view that is created and then painted can still flash white once before this colour
;                  takes effect - the runtime is not done with its first frame yet. The SDK's own answer
;                  to that is the WEBVIEW2_DEFAULT_BACKGROUND_COLOR environment variable, which is read
;                  before the browser comes up; the colour set here is what a running view is changed
;                  with.
; Related .......: _WV2_GetBackgroundColor, _WV2_SetColorScheme
; ===============================================================================================================================
Func _WV2_SetBackgroundColor($iHandle, $iRed, $iGreen, $iBlue, $iAlpha = 255)
	$__WV2_sLastFunc = "_WV2_SetBackgroundColor"
	If Not __WV2_GuardCtl($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	If __WV2_BadByte($iRed) Or __WV2_BadByte($iGreen) Or __WV2_BadByte($iBlue) Then
		__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_SetBackgroundColor")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	If $iAlpha <> 0 And $iAlpha <> 255 Then
		__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_SetBackgroundColor")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	Local $bOk = __WV2_SetColor($iHandle, $iAlpha, $iRed, $iGreen, $iBlue)
	Return SetError($__WV2_iLastError, $__WV2_iLastHR, $bOk)
EndFunc   ;==>_WV2_SetBackgroundColor

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_GetBackgroundColor
; Description ...: Reads the colour the view renders underneath the web content.
; Syntax ........: _WV2_GetBackgroundColor($iHandle, $iRed, $iGreen, $iBlue, $iAlpha)
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $iRed    - Returned: 0 to 255.
;                  $iGreen  - Returned: 0 to 255.
;                  $iBlue   - Returned: 0 to 255.
;                  $iAlpha  - Returned: 0 or 255.
; Return values .: Success: 1, @error = 0. The four channels are 0 when the read failed.
;                  Failure: 0, with @error set to a $WV2_ERR_* code and @extended set to the raw HRESULT
;                  (0 if none).
; Author ........: Numeric1
; Remarks .......: What comes back is what the runtime holds, so this is also how the colour of a view
;                  that was made with WEBVIEW2_DEFAULT_BACKGROUND_COLOR is read: the environment variable
;                  is a one time default, and the answer here is the value that survived from it.
; Related .......: _WV2_SetBackgroundColor
; ===============================================================================================================================
Func _WV2_GetBackgroundColor($iHandle, ByRef $iRed, ByRef $iGreen, ByRef $iBlue, ByRef $iAlpha)
	$__WV2_sLastFunc = "_WV2_GetBackgroundColor"
	$iRed = 0
	$iGreen = 0
	$iBlue = 0
	$iAlpha = 0
	If Not __WV2_GuardCtl($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	Local $iA = 0, $iR = 0, $iG = 0, $iB = 0
	Local $bOk = __WV2_ReadColor($iHandle, $iA, $iR, $iG, $iB)
	If Not $bOk Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	$iRed = $iR
	$iGreen = $iG
	$iBlue = $iB
	$iAlpha = $iA
	Return SetError(0, 0, 1)
EndFunc   ;==>_WV2_GetBackgroundColor

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_SetDarkTitleBar
; Description ...: Paints the title bar and frame of a window dark, the way the theme lot paints a page.
; Syntax ........: _WV2_SetDarkTitleBar($hWnd[, $bDark])
; Parameters ....: $hWnd  - Handle of a window of this script (the GUI, not the view).
;                  $bDark - Optional: True (the default) for a dark bar, False for the light one.
; Return values .: Success: 1, @error = 0.
;                  Failure: 0, with @error set to $WV2_ERR_ARG for a window that does not exist, or to
;                  $WV2_ERR_CALL with @extended set to the HRESULT DwmSetWindowAttribute answered.
; Author ........: Numeric1
; Remarks .......: The window manager, not the browser, owns the title bar: nothing in WebView2 can
;                  darken it, so this goes to dwmapi.dll directly and takes a window handle rather than
;                  a view handle. It is what makes a dark page and a dark frame agree - the frame of a
;                  window is the one part of a WebView2 application a colour scheme never reaches.
;
;                  The attribute is published as DWMWA_USE_IMMERSIVE_DARK_MODE (20). The builds between
;                  17763 and 18362 answer only to 19, the number the same thing had before it was
;                  published, so 20 is tried first and 19 only when 20 is refused. A Windows 7 or an
;                  ordinary Server SKU has no dark mode to give: the failure is reported, not hidden.
; Related .......: _WV2_SetColorScheme, _WV2_SetBackgroundColor
; ===============================================================================================================================
Func _WV2_SetDarkTitleBar($hWnd, $bDark = True)
	$__WV2_sLastFunc = "_WV2_SetDarkTitleBar"
	$__WV2_iLastError = $WV2_ERR_NONE
	$__WV2_iLastHR = 0
	If Not IsHWnd($hWnd) Then
		__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_SetDarkTitleBar")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	Local $aWin = DllCall("user32.dll", "bool", "IsWindow", "hwnd", $hWnd)
	If @Error Or Not IsArray($aWin) Or $aWin[0] = 0 Then
		__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_SetDarkTitleBar")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	; DwmSetWindowAttribute wants the address of a BOOL, not the value: four bytes the callee reads.
	Local $tOn = DllStructCreate("int")
	DllStructSetData($tOn, 1, ($bDark ? 1 : 0))
	Local $iAttr, $hr = 0
	For $iAttr = 0 To 1
		Local $aDwm = DllCall("dwmapi.dll", "long", "DwmSetWindowAttribute", "hwnd", $hWnd, _
				"dword", ($iAttr = 0 ? $__WV2_DWM_DARK_MODE : $__WV2_DWM_DARK_MODE_OLD), _
				"ptr", DllStructGetPtr($tOn), "dword", 4)
		If @Error Or Not IsArray($aDwm) Then
			__WV2_SetErr($WV2_ERR_CALL, 0, "DwmSetWindowAttribute")
			Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
		EndIf
		$hr = $aDwm[0]
		If $hr = 0 Then ExitLoop
	Next
	If $hr <> 0 Then
		__WV2_SetErr($WV2_ERR_CALL, $hr, "DwmSetWindowAttribute")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	Return SetError(0, 0, 1)
EndFunc   ;==>_WV2_SetDarkTitleBar

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_SetDefaultDownloadFolder
; Description ...: Names the folder the browser downloads into when nothing else says otherwise.
; Syntax ........: _WV2_SetDefaultDownloadFolder($iHandle, $sFolder)
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
;                  $sFolder - Absolute path of a folder the user and the application can write to.
; Return values .: Success: 1, @error = 0.
;                  Failure: 0, with @error set to a $WV2_ERR_* code ($WV2_ERR_ARG for an empty or
;                  relative path) and @extended set to the raw HRESULT (0 if none).
; Author ........: Numeric1
; Remarks .......: The runtime writes the answer in the user data folder, so the choice is still there
;                  the next time the same profile opens - which is what separates this call from
;                  _WV2_SetDownloadFolder: that one intercepts every DownloadStarting of the session and
;                  rewrites the target, this one changes what the browser itself considers its downloads
;                  folder, for the pages, the browser UI and the Save As dialog alike. A folder set by
;                  _WV2_SetDownloadFolder still wins for the downloads that go through it.
;
;                  The folder does not have to exist: the runtime creates it when the first download
;                  arrives. A path it cannot use is refused with E_INVALIDARG and the old answer is kept,
;                  so a failed call leaves the profile as it was.
; Related .......: _WV2_GetDefaultDownloadFolder, _WV2_SetDownloadFolder
; ===============================================================================================================================
Func _WV2_SetDefaultDownloadFolder($iHandle, $sFolder)
	$__WV2_sLastFunc = "_WV2_SetDefaultDownloadFolder"
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	If Not IsString($sFolder) Then $sFolder = String($sFolder)
	Local $sPath = StringStripWS($sFolder, 3)
	While StringRight($sPath, 1) = "\" Or StringRight($sPath, 1) = "/"
		$sPath = StringTrimRight($sPath, 1)
	WEnd
	If $sPath <> "" And Not StringInStr($sPath, "\") And Not StringInStr($sPath, "/") Then $sPath = _PathFull($sPath)
	; The SDK asks for an absolute path; "" would hand the choice back to the runtime, and the runtime
	; answers with the system Downloads folder rather than an empty string, so it is refused here.
	If $sPath = "" Or Not StringInStr($sPath, "\") Then
		__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_SetDefaultDownloadFolder")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	Local $pProf = __WV2_ProfileObj($iHandle)
	If $pProf = 0 Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	Local $bOk = __WV2_Result(__WV2_CallWStr($pProf, _
			$__WV2_SLOT_ICoreWebView2Profile_put_DefaultDownloadFolderPath, $sPath), _
			"ICoreWebView2Profile::put_DefaultDownloadFolderPath")
	Return SetError($__WV2_iLastError, $__WV2_iLastHR, $bOk)
EndFunc   ;==>_WV2_SetDefaultDownloadFolder

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_GetDefaultDownloadFolder
; Description ...: Reads the folder the browser downloads into when nothing else says otherwise.
; Syntax ........: _WV2_GetDefaultDownloadFolder($iHandle)
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
; Return values .: Success: the path, and @error = 0. It is never empty: a profile that was never given
;                  one answers with the system Downloads folder of the user.
;                  Failure: "", with @error set to a $WV2_ERR_* code and @extended set to the raw HRESULT
;                  (0 if none).
; Author ........: Numeric1
; Remarks .......: The answer is what the profile holds, so a folder set before the program started - by
;                  an earlier run on the same user data folder - reads back here. That is the only way to
;                  see it: the property is persisted in the profile, not in the script.
; Related .......: _WV2_SetDefaultDownloadFolder, _WV2_SetDownloadFolder
; ===============================================================================================================================
Func _WV2_GetDefaultDownloadFolder($iHandle)
	$__WV2_sLastFunc = "_WV2_GetDefaultDownloadFolder"
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, "")
	Local $pProf = __WV2_ProfileObj($iHandle)
	If $pProf = 0 Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, "")
	Local $sPath = __WV2_WStrProp($pProf, $__WV2_SLOT_ICoreWebView2Profile_get_DefaultDownloadFolderPath)
	If $sPath = "" Then
		__WV2_SetErr($WV2_ERR_CALL, 0, "ICoreWebView2Profile::get_DefaultDownloadFolderPath")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, "")
	EndIf
	Return SetError(0, 0, $sPath)
EndFunc   ;==>_WV2_GetDefaultDownloadFolder

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_SetEnvBrowserArguments
; Description ...: Adds command line arguments to the browser process an environment starts.
; Syntax ........: _WV2_SetEnvBrowserArguments($sArguments)
; Parameters ....: $sArguments - Arguments in one string, the way Chromium takes them and without the name
;                               of the program: "--disable-features=Translate --user-agent=MyAgent/1.0".
;                               Pass "" to take them back.
; Return values .: Success: 1, @error = 0.
;                  Failure: 0, @error = $WV2_ERR_ARG (a non-string handed over).
; Author ........: Numeric1
; Remarks .......: An option of the environment, not of a view: it is read when the browser process of the
;                  user data folder is started, so it has to be set before _WV2_Create and it changes
;                  nothing for a folder whose browser is already running. What is recorded here is what
;                  the UDF hands the runtime as ICoreWebView2EnvironmentOptions, an object the UDF builds
;                  itself - no loader is needed, and none is asked for.
; Related .......: _WV2_GetEnvBrowserArguments, _WV2_ResetEnvOptions, _WV2_SetUserAgent
; ===============================================================================================================================
Func _WV2_SetEnvBrowserArguments($sArguments)
	$__WV2_sLastFunc = "_WV2_SetEnvBrowserArguments"
	If Not IsString($sArguments) Then
		__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_SetEnvBrowserArguments")
		Return SetError($__WV2_iLastError, 0, 0)
	EndIf
	$__WV2_sOptAba = $sArguments
	$__WV2_bOptSet = ($__WV2_sOptAba <> "")
	Return SetError(0, __WV2_OptLive(), 1)
EndFunc   ;==>_WV2_SetEnvBrowserArguments

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_GetEnvBrowserArguments
; Description ...: Reads the browser arguments recorded for the next environment.
; Syntax ........: _WV2_GetEnvBrowserArguments()
; Parameters ....: None.
; Return values .: The string recorded, empty when none was ever set. Always @error = 0.
; Author ........: Numeric1
; Remarks .......: What comes back is what this script set, not what the running browser was started with:
;                  the runtime reads the string once, at the create, and keeps the result to itself.
; Related .......: _WV2_SetEnvBrowserArguments
; ===============================================================================================================================
Func _WV2_GetEnvBrowserArguments()
	Return SetError(0, 0, $__WV2_sOptAba)
EndFunc   ;==>_WV2_GetEnvBrowserArguments

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_SetEnvLanguage
; Description ...: Picks the language the browser process announces to the pages.
; Syntax ........: _WV2_SetEnvLanguage($sLanguage)
; Parameters ....: $sLanguage - A language tag the way HTTP writes them: "fr-FR", "en-GB", "es". Pass ""
;                               for the language of the system, which is what the runtime does anyway.
; Return values .: Success: 1, @error = 0, @extended = 1 when a browser process is already running,
;                  which means this value reaches only the next environment (see Remarks).
;                  Failure: 0, @error = $WV2_ERR_ARG (a non-string handed over).
; Author ........: Numeric1
; Remarks .......: One value for the whole browser process, and read at the create. It is the language the
;                  page sees - Accept-Language, navigator.language - not the language of the browser's own
;                  user interface, which belongs to Edge and to the --lang argument of
;                  _WV2_SetEnvBrowserArguments.
; Related .......: _WV2_GetEnvLanguage, _WV2_SetEnvBrowserArguments
; ===============================================================================================================================
Func _WV2_SetEnvLanguage($sLanguage)
	$__WV2_sLastFunc = "_WV2_SetEnvLanguage"
	If Not IsString($sLanguage) Then
		__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_SetEnvLanguage")
		Return SetError($__WV2_iLastError, 0, 0)
	EndIf
	$__WV2_sOptLang = $sLanguage
	$__WV2_bOptSet = True
	Return SetError(0, __WV2_OptLive(), 1)
EndFunc   ;==>_WV2_SetEnvLanguage

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_GetEnvLanguage
; Description ...: Reads the language recorded for the next environment.
; Syntax ........: _WV2_GetEnvLanguage()
; Parameters ....: None.
; Return values .: The tag recorded, empty when the system language is left alone. Always @error = 0.
; Author ........: Numeric1
; Related .......: _WV2_SetEnvLanguage
; ===============================================================================================================================
Func _WV2_GetEnvLanguage()
	Return SetError(0, 0, $__WV2_sOptLang)
EndFunc   ;==>_WV2_GetEnvLanguage

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_SetEnvBrowserVersion
; Description ...: Pins the environment to one installed browser version.
; Syntax ........: _WV2_SetEnvBrowserVersion($sVersion)
; Parameters ....: $sVersion - Four dotted numbers, as _WV2_GetBrowserVersion gives them: "156.0.4314.58".
;                               Pass "" to let the create fill in the version of the DLL it is about to
;                               call, which is what every script wants.
; Return values .: Success: 1, @error = 0, @extended = 1 when a browser process is already running,
;                  which means this value reaches only the next environment (see Remarks).
;                  Failure: 0, @error = $WV2_ERR_ARG (a non-string, or a string that is not four dotted
;                  numbers).
; Author ........: Numeric1
; Remarks .......: The one option that is not a preference: an options object whose version is empty is
;                  refused outright by the factory this UDF calls - 0x80070057, measured on x86 and x64 -
;                  so the UDF fills in the version of the runtime it found and hands that over. A version
;                  that is not installed is a create that fails, and the failure says the same thing on
;                  both bitnesses: $WV2_ERR_ENV.
; Related .......: _WV2_GetEnvBrowserVersion, _WV2_GetBrowserVersion
; ===============================================================================================================================
Func _WV2_SetEnvBrowserVersion($sVersion)
	$__WV2_sLastFunc = "_WV2_SetEnvBrowserVersion"
	If Not IsString($sVersion) Then
		__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_SetEnvBrowserVersion")
		Return SetError($__WV2_iLastError, 0, 0)
	EndIf
	If $sVersion <> "" And Not StringRegExp($sVersion, "^\d+\.\d+\.\d+\.\d+$") Then
		__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_SetEnvBrowserVersion")
		Return SetError($__WV2_iLastError, 0, 0)
	EndIf
	$__WV2_sOptTcbv = $sVersion
	$__WV2_bOptSet = True
	Return SetError(0, __WV2_OptLive(), 1)
EndFunc   ;==>_WV2_SetEnvBrowserVersion

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_GetEnvBrowserVersion
; Description ...: Reads the browser version the next environment is pinned to.
; Syntax ........: _WV2_GetEnvBrowserVersion()
; Parameters ....: None.
; Return values .: The version recorded. Empty until a create fills it in with the version of the runtime
;                  it found - after that, the string the options object answered with. Always @error = 0.
; Author ........: Numeric1
; Related .......: _WV2_SetEnvBrowserVersion
; ===============================================================================================================================
Func _WV2_GetEnvBrowserVersion()
	Return SetError(0, 0, $__WV2_sOptTcbv)
EndFunc   ;==>_WV2_GetEnvBrowserVersion

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_SetEnvSingleSignOn
; Description ...: Lets the browser sign pages in with the account the user is logged into Windows with.
; Syntax ........: _WV2_SetEnvSingleSignOn($bAllow)
; Parameters ....: $bAllow - True to allow it, False (the default) to keep it to the browser's own logins.
; Return values .: Success: 1, @error = 0, @extended = 1 when a browser process is already running,
;                  which means this value reaches only the next environment (see Remarks).
; Author ........: Numeric1
; Remarks .......: This is the credential of the Windows account itself, so a script that turns it on has
;                  decided what a page may do with it - it is off for exactly that reason, and off is what
;                  a program that never asks gets.
; Related .......: _WV2_GetEnvSingleSignOn, _WV2_ResetEnvOptions
; ===============================================================================================================================
Func _WV2_SetEnvSingleSignOn($bAllow)
	$__WV2_sLastFunc = "_WV2_SetEnvSingleSignOn"
	$__WV2_bOptSso = ($bAllow ? True : False)
	$__WV2_bOptSet = True
	Return SetError(0, __WV2_OptLive(), 1)
EndFunc   ;==>_WV2_SetEnvSingleSignOn

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_GetEnvSingleSignOn
; Description ...: Reads whether the browser may use the Windows account for single sign-on.
; Syntax ........: _WV2_GetEnvSingleSignOn()
; Parameters ....: None.
; Return values .: 1 allowed, 0 not. Always @error = 0.
; Author ........: Numeric1
; Related .......: _WV2_SetEnvSingleSignOn
; ===============================================================================================================================
Func _WV2_GetEnvSingleSignOn()
	Return SetError(0, 0, ($__WV2_bOptSso ? 1 : 0))
EndFunc   ;==>_WV2_GetEnvSingleSignOn

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_SetEnvExclusiveFolder
; Description ...: Takes the user data folder for this process alone.
; Syntax ........: _WV2_SetEnvExclusiveFolder($bExclusive)
; Parameters ....: $bExclusive - True to hold the folder to this process, False (the default) to let two
;                               programs share it.
; Return values .: Success: 1, @error = 0, @extended = 1 when a browser process is already running,
;                  which means this value reaches only the next environment (see Remarks).
; Author ........: Numeric1
; Remarks .......: What changes is who may open the folder, not where it is: with True, a second program
;                  that asks for the same folder fails at the create instead of joining the browser
;                  already running there. It is the option to reach for when two instances of one program
;                  must not meet, and the reason _WV2_Create gives a folder of its own to every view.
; Related .......: _WV2_GetEnvExclusiveFolder, _WV2_Create
; ===============================================================================================================================
Func _WV2_SetEnvExclusiveFolder($bExclusive)
	$__WV2_sLastFunc = "_WV2_SetEnvExclusiveFolder"
	$__WV2_bOptExcl = ($bExclusive ? True : False)
	$__WV2_bOptSet = True
	Return SetError(0, __WV2_OptLive(), 1)
EndFunc   ;==>_WV2_SetEnvExclusiveFolder

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_GetEnvExclusiveFolder
; Description ...: Reads whether the user data folder is held to this process alone.
; Syntax ........: _WV2_GetEnvExclusiveFolder()
; Parameters ....: None.
; Return values .: 1 exclusive, 0 shared. Always @error = 0.
; Author ........: Numeric1
; Related .......: _WV2_SetEnvExclusiveFolder
; ===============================================================================================================================
Func _WV2_GetEnvExclusiveFolder()
	Return SetError(0, 0, ($__WV2_bOptExcl ? 1 : 0))
EndFunc   ;==>_WV2_GetEnvExclusiveFolder

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_SetEnvCustomCrashReporting
; Description ...: Sends a crash of the browser process to the host application instead of to Edge.
; Syntax ........: _WV2_SetEnvCustomCrashReporting($bEnable)
; Parameters ....: $bEnable - True for the host, False (the default) for the reporting Edge uses.
; Return values .: Success: 1, @error = 0, @extended = 1 when a browser process is already running,
;                  which means this value reaches only the next environment (see Remarks).
; Author ........: Numeric1
; Remarks .......: What the host gets is a Windows Error Reporting callback in its own process, so the
;                  program has to have registered one to be worth anything; for a script, the default is
;                  the right answer.
; Related .......: _WV2_GetEnvCustomCrashReporting
; ===============================================================================================================================
Func _WV2_SetEnvCustomCrashReporting($bEnable)
	$__WV2_sLastFunc = "_WV2_SetEnvCustomCrashReporting"
	$__WV2_bOptCrash = ($bEnable ? True : False)
	$__WV2_bOptSet = True
	Return SetError(0, __WV2_OptLive(), 1)
EndFunc   ;==>_WV2_SetEnvCustomCrashReporting

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_GetEnvCustomCrashReporting
; Description ...: Reads who receives a crash of the browser process.
; Syntax ........: _WV2_GetEnvCustomCrashReporting()
; Parameters ....: None.
; Return values .: 1 the host application, 0 Edge. Always @error = 0.
; Author ........: Numeric1
; Related .......: _WV2_SetEnvCustomCrashReporting
; ===============================================================================================================================
Func _WV2_GetEnvCustomCrashReporting()
	Return SetError(0, 0, ($__WV2_bOptCrash ? 1 : 0))
EndFunc   ;==>_WV2_GetEnvCustomCrashReporting

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_SetEnvTrackingPrevention
; Description ...: Turns the tracking prevention of the browser on or off.
; Syntax ........: _WV2_SetEnvTrackingPrevention($bEnable)
; Parameters ....: $bEnable - True (the default, and what Edge does) to block the trackers of other sites,
;                               False to let them through.
; Return values .: Success: 1, @error = 0, @extended = 1 when a browser process is already running,
;                  which means this value reaches only the next environment (see Remarks).
; Author ........: Numeric1
; Remarks .......: The only option whose default is on, because the browser's own default is on: a script
;                  that never speaks of it gets tracking prevention, and one that wants a page to see a
;                  third-party tracker has to say so here, before the create.
; Related .......: _WV2_GetEnvTrackingPrevention, _WV2_ResetEnvOptions
; ===============================================================================================================================
Func _WV2_SetEnvTrackingPrevention($bEnable)
	$__WV2_sLastFunc = "_WV2_SetEnvTrackingPrevention"
	$__WV2_bOptTrack = ($bEnable ? True : False)
	$__WV2_bOptSet = True
	Return SetError(0, __WV2_OptLive(), 1)
EndFunc   ;==>_WV2_SetEnvTrackingPrevention

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_GetEnvTrackingPrevention
; Description ...: Reads whether tracking prevention is on.
; Syntax ........: _WV2_GetEnvTrackingPrevention()
; Parameters ....: None.
; Return values .: 1 on, 0 off. Always @error = 0.
; Author ........: Numeric1
; Related .......: _WV2_SetEnvTrackingPrevention
; ===============================================================================================================================
Func _WV2_GetEnvTrackingPrevention()
	Return SetError(0, 0, ($__WV2_bOptTrack ? 1 : 0))
EndFunc   ;==>_WV2_GetEnvTrackingPrevention

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_SetEnvBrowserExtensions
; Description ...: Lets the browser load extensions.
; Syntax ........: _WV2_SetEnvBrowserExtensions($bEnable)
; Parameters ....: $bEnable - True to load the extensions of a folder, False (the default) to run without
;                               any.
; Return values .: Success: 1, @error = 0, @extended = 1 when a browser process is already running,
;                  which means this value reaches only the next environment (see Remarks).
; Author ........: Numeric1
; Remarks .......: Turning this on is only half of it: the extensions themselves are loaded from the
;                  browser arguments, --load-extension=<folder>, which _WV2_SetEnvBrowserArguments writes.
;                  Both have to be set before the create, and both belong to the folder, not to a view.
; Related .......: _WV2_GetEnvBrowserExtensions, _WV2_SetEnvBrowserArguments
; ===============================================================================================================================
Func _WV2_SetEnvBrowserExtensions($bEnable)
	$__WV2_sLastFunc = "_WV2_SetEnvBrowserExtensions"
	$__WV2_bOptExt = ($bEnable ? True : False)
	$__WV2_bOptSet = True
	Return SetError(0, __WV2_OptLive(), 1)
EndFunc   ;==>_WV2_SetEnvBrowserExtensions

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_GetEnvBrowserExtensions
; Description ...: Reads whether the browser may load extensions.
; Syntax ........: _WV2_GetEnvBrowserExtensions()
; Parameters ....: None.
; Return values .: 1 allowed, 0 not. Always @error = 0.
; Author ........: Numeric1
; Related .......: _WV2_SetEnvBrowserExtensions
; ===============================================================================================================================
Func _WV2_GetEnvBrowserExtensions()
	Return SetError(0, 0, ($__WV2_bOptExt ? 1 : 0))
EndFunc   ;==>_WV2_GetEnvBrowserExtensions

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_SetEnvScrollBarStyle
; Description ...: Picks the scrollbar style every page of the environment gets.
; Syntax ........: _WV2_SetEnvScrollBarStyle($iStyle)
; Parameters ....: $iStyle - $WV2_SCROLLBAR_DEFAULT (0, what the system says) or
;                           $WV2_SCROLLBAR_FLUENT_OVERLAY (1, the thin overlays that float over content).
; Return values .: Success: 1, @error = 0, @extended = 1 when a browser process is already running,
;                  which means this value reaches only the next environment (see Remarks).
;                  Failure: 0, @error = $WV2_ERR_ARG (a style outside those two).
; Author ........: Numeric1
; Remarks .......: An option of the environment, so it is decided when the browser process starts and holds
;                  for every view of that folder - the one appearance choice of this lot that is not made
;                  per view, and the reason it is spelled Env in the name.
; Related .......: _WV2_GetEnvScrollBarStyle, _WV2_SetColorScheme
; ===============================================================================================================================
Func _WV2_SetEnvScrollBarStyle($iStyle)
	$__WV2_sLastFunc = "_WV2_SetEnvScrollBarStyle"
	$iStyle = Int($iStyle)
	If $iStyle < 0 Or $iStyle > $__WV2_SCROLLBAR_MAX Then
		__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_SetEnvScrollBarStyle")
		Return SetError($__WV2_iLastError, 0, 0)
	EndIf
	$__WV2_iOptScroll = $iStyle
	$__WV2_bOptSet = True
	Return SetError(0, __WV2_OptLive(), 1)
EndFunc   ;==>_WV2_SetEnvScrollBarStyle

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_GetEnvScrollBarStyle
; Description ...: Reads the scrollbar style recorded for the next environment.
; Syntax ........: _WV2_GetEnvScrollBarStyle()
; Parameters ....: None.
; Return values .: $WV2_SCROLLBAR_DEFAULT or $WV2_SCROLLBAR_FLUENT_OVERLAY. Always @error = 0.
; Author ........: Numeric1
; Related .......: _WV2_SetEnvScrollBarStyle
; ===============================================================================================================================
Func _WV2_GetEnvScrollBarStyle()
	Return SetError(0, 0, $__WV2_iOptScroll)
EndFunc   ;==>_WV2_GetEnvScrollBarStyle

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_ResetEnvOptions
; Description ...: Takes every option of the environment back to what the runtime does when nothing is set.
; Syntax ........: _WV2_ResetEnvOptions()
; Parameters ....: None.
; Return values .: Always 1, @error = 0, @extended = 1 when a browser process is already running, which
;                  is the case the Remarks below describe.
; Author ........: Numeric1
; Remarks .......: The values come back to the defaults the loader itself uses - no arguments, no language,
;                  the version of the runtime found on the machine, no single sign-on, a shared folder, no
;                  custom crash reporting, extensions off, tracking prevention on, default scrollbars. It
;                  does not disturb a browser already running: the next create is what reads it, which is
;                  also what makes it the way a test puts one option back between two views.
; Related .......: _WV2_SetEnvBrowserArguments, _WV2_SetEnvTrackingPrevention
; ===============================================================================================================================
Func _WV2_ResetEnvOptions()
	$__WV2_sLastFunc = "_WV2_ResetEnvOptions"
	$__WV2_sOptAba = ""
	$__WV2_sOptLang = ""
	$__WV2_sOptTcbv = ""
	$__WV2_bOptSso = False
	$__WV2_bOptExcl = False
	$__WV2_bOptCrash = False
	$__WV2_bOptTrack = True
	$__WV2_bOptExt = False
	$__WV2_iOptScroll = $WV2_SCROLLBAR_DEFAULT
	$__WV2_bOptSet = False
	Return SetError(0, __WV2_OptLive(), 1)
EndFunc   ;==>_WV2_ResetEnvOptions

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_SetUserAgent
; Description ...: Replaces the string a view announces to the pages as its user agent.
; Syntax ........: _WV2_SetUserAgent($iHandle, $sUserAgent)
; Parameters ....: $iHandle    - Handle returned by _WV2_Create.
;                  $sUserAgent - The whole string the page is to see. It replaces what the browser would
;                               have sent, so it has to look like one: "Mozilla/5.0 (Windows NT 10.0;
;                               Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0
;                               Safari/537.36". "" is refused - a page with no agent is a page that cannot
;                               be served.
; Return values .: Success: 1, @error = 0, @extended = 1 when a browser process is already running,
;                  which means this value reaches only the next environment (see Remarks).
;                  Failure: 0, with @error set to a $WV2_ERR_* code and @extended set to the raw HRESULT
;                  (0 if none).
; Author ........: Numeric1
; Remarks .......: Not an option of the environment: this is a property of the settings of one view, so it
;                  can be set at any time and it holds for that view alone. A page that reads
;                  navigator.userAgent after this sees the string given here; the browser process, the
;                  download manager and every other view keep their own. The property comes from
;                  ICoreWebView2Settings2, asked for on the call and let go again: an older runtime that
;                  does not carry it answers $WV2_ERR_CALL with E_NOINTERFACE in @extended.
; Related .......: _WV2_GetUserAgent, _WV2_SettingWrite, _WV2_SetEnvBrowserArguments
; ===============================================================================================================================
Func _WV2_SetUserAgent($iHandle, $sUserAgent)
	$__WV2_sLastFunc = "_WV2_SetUserAgent"
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	If Not IsString($sUserAgent) Or $sUserAgent = "" Then
		__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_SetUserAgent")
		Return SetError($__WV2_iLastError, 0, 0)
	EndIf
	Local $pSet2 = __WV2_Settings2($iHandle)
	If $pSet2 = 0 Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	Local $hr = __WV2_CallWStr($pSet2, $__WV2_SLOT_ICoreWebView2Settings2_put_UserAgent, $sUserAgent)
	__WV2_ReleaseExternal($pSet2)
	Local $bOk = __WV2_Result($hr, "ICoreWebView2Settings2::put_UserAgent")
	Return SetError($__WV2_iLastError, $__WV2_iLastHR, $bOk)
EndFunc   ;==>_WV2_SetUserAgent

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_GetUserAgent
; Description ...: Reads the user agent a view announces to the pages.
; Syntax ........: _WV2_GetUserAgent($iHandle)
; Parameters ....: $iHandle - Handle returned by _WV2_Create.
; Return values .: Success: the string, and @error = 0.
;                  Failure: "", with @error set to a $WV2_ERR_* code and @extended set to the raw HRESULT
;                  (0 if none).
; Author ........: Numeric1
; Remarks .......: What the settings hold, which is what the page sees - not what the browser process sent
;                  on the wire for the navigation that is still in flight. Take this string before
;                  _WV2_SetUserAgent and give it back to that function to put the view as it was.
; Related .......: _WV2_SetUserAgent
; ===============================================================================================================================
Func _WV2_GetUserAgent($iHandle)
	$__WV2_sLastFunc = "_WV2_GetUserAgent"
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, "")
	Local $pSet2 = __WV2_Settings2($iHandle)
	If $pSet2 = 0 Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, "")
	Local $sUA = __WV2_WStrProp($pSet2, $__WV2_SLOT_ICoreWebView2Settings2_get_UserAgent)
	__WV2_ReleaseExternal($pSet2)
	If $sUA = "" Then
		__WV2_SetErr($WV2_ERR_CALL, 0, "ICoreWebView2Settings2::get_UserAgent")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, "")
	EndIf
	Return SetError(0, 0, $sUA)
EndFunc   ;==>_WV2_GetUserAgent

; ===============================================================================================================================
; Element helpers
;
; These read and drive the page with a selector instead of hand-written JavaScript, so a login form, a
; button or a value that changes is a one-liner rather than a document.querySelector round-trip typed out
; in a script string. Nothing here asks the view for a COM slot it does not already have: the work is done
; by document.querySelector (a plain CSS selector) or, when the selector starts with "/", "./" or "(", by
; document.evaluate (an XPath). That is why the same call answers both dialects and the caller never has
; to say which one it meant. Every helper needs the page to be loaded; on a page that is still navigating
; they report "not found" (an empty result or @extended = 1), which is not the same as an error, and
; _WV2_WaitForElement exists precisely to sit out that wait. Strings given to or read from the page are
; JSON-escaped on the way in and unescaped on the way out, so quotes and newlines survive the round trip.
; ===============================================================================================================================

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_ElementExists
; Description ...: Reports whether the page holds an element that matches the selector.
; Syntax ........: _WV2_ElementExists($iHandle, $sSelector)
; Parameters ....: $iHandle   - Handle returned by _WV2_Create.
;                  $sSelector - A CSS selector, or an XPath when it starts with "/", "./" or "(".
; Return values .: Success: 1 when an element matches, 0 when none does, @error = 0.
;                  Failure: 0, @error set to $WV2_ERR_* (bad handle, or the script could not run).
; Author ........: Numeric1
; Remarks .......: A page that has not finished navigating simply holds no element yet, so this returns 0
;                  with @error = 0, not an error. Pair it with _WV2_WaitNavigation or _WV2_WaitForElement
;                  when the element is expected to appear.
; Related .......: _WV2_ExecuteScript, _WV2_ElementCount, _WV2_WaitForElement
; ===============================================================================================================================
Func _WV2_ElementExists($iHandle, $sSelector)
	$__WV2_sLastFunc = "_WV2_ElementExists"
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	If Not __WV2_SelArg($sSelector, "_WV2_ElementExists") Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	Local $sOut = ""
	If Not _WV2_ExecuteScript($iHandle, "(function(){return " & __WV2_DomExpr($sSelector) & "!==null;})()", $sOut) Then _
			Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	Return SetError(0, 0, (__WV2_Unquote($sOut) = "true") ? 1 : 0)
EndFunc   ;==>_WV2_ElementExists

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_ElementCount
; Description ...: Counts the elements on the page that match the selector.
; Syntax ........: _WV2_ElementCount($iHandle, $sSelector)
; Parameters ....: $iHandle   - Handle returned by _WV2_Create.
;                  $sSelector - A CSS selector, or an XPath when it starts with "/", "./" or "(".
; Return values .: Success: the number of matches (0 or more), @error = 0.
;                  Failure: 0, @error set to $WV2_ERR_* (bad handle, or the script could not run).
; Author ........: Numeric1
; Related .......: _WV2_ElementExists
; ===============================================================================================================================
Func _WV2_ElementCount($iHandle, $sSelector)
	$__WV2_sLastFunc = "_WV2_ElementCount"
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	If Not __WV2_SelArg($sSelector, "_WV2_ElementCount") Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	Local $sJs = "(function(){return " & __WV2_DomCountExpr($sSelector) & ";})()"
	Local $sOut = ""
	If Not _WV2_ExecuteScript($iHandle, $sJs, $sOut) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	Return SetError(0, 0, Number(StringStripWS($sOut, 8)))
EndFunc   ;==>_WV2_ElementCount

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_GetElementText
; Description ...: Reads the text an element shows.
; Syntax ........: _WV2_GetElementText($iHandle, $sSelector[, $sAttribute])
; Parameters ....: $iHandle    - Handle returned by _WV2_Create.
;                  $sSelector  - A CSS selector, or an XPath when it starts with "/", "./" or "(".
;                  $sAttribute - Optional: read this attribute instead of the visible text. Pass "value"
;                               to read a field's current value, "href" or "src" for a link or image, and
;                               so on. Default "" reads the element's textContent.
; Return values .: Success: the text or attribute as a string, @error = 0.
;                  Not found: "" with @error = 0 and @extended = 1 (the element is simply not on the page).
;                  Failure: "", @error set to $WV2_ERR_* (bad handle, or the script could not run).
; Author ........: Numeric1
; Remarks .......: The crossing is done twice encoded, so a page text that holds a character the runtime
;                  cannot hand over as UTF-16 - an unpaired surrogate, which is half an emoji - still comes
;                  back instead of hanging the call until it times out. That is also why the empty string
;                  of a found element and the absence of one are different answers here.
;                  An attribute the element does not carry reads as the empty string, like a property that
;                  was never set; only a missing element is reported with @extended = 1.
; Related .......: _WV2_SetElementValue
; ===============================================================================================================================
Func _WV2_GetElementText($iHandle, $sSelector, $sAttribute = "")
	$__WV2_sLastFunc = "_WV2_GetElementText"
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, "")
	If Not __WV2_SelArg($sSelector, "_WV2_GetElementText") Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, "")
	Local $sJs = "(function(){var e=" & __WV2_DomExpr($sSelector) & ";" & _
			"if(!e)return JSON.stringify(null);" & _
			"var a=" & __WV2_JsString($sAttribute) & ";" & _
			"if(a===''){return JSON.stringify(e.textContent===null?'':e.textContent);}" & _
			"if(a==='value'){return JSON.stringify(e.value===undefined?'':String(e.value));}" & _
			"var v=e.getAttribute(a);return JSON.stringify(v===null?'':v);})()"
	Local $sOut = ""
	If Not _WV2_ExecuteScript($iHandle, $sJs, $sOut) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, "")
	; The value crosses twice encoded, and that is the whole trick of this function. Read straight, a page
	; text that holds an unpaired surrogate is answered by the runtime with nothing at all - the callback
	; never arrives and the call times out. Made into JSON text first, it is ASCII on the wire and comes
	; back whole; the price is two unquotes here, one for the string the script returned and one for the
	; JSON inside it. The bare word null is what a missing element returns, and a text that reads "null"
	; arrives between quotes, so the two are still told apart.
	Local $sJson = __WV2_Unquote($sOut)
	If $sJson = "null" Then Return SetError(0, 1, "")
	Return SetError(0, 0, __WV2_Unquote($sJson))
EndFunc   ;==>_WV2_GetElementText

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_SetElementValue
; Description ...: Types a value into a field and tells the page about it, so framework pages react.
; Syntax ........: _WV2_SetElementValue($iHandle, $sSelector, $sValue)
; Parameters ....: $iHandle   - Handle returned by _WV2_Create.
;                  $sSelector - A CSS selector, or an XPath when it starts with "/", "./" or "(".
;                  $sValue    - The text to put in the field; quotes and newlines are escaped for you.
; Return values .: Success: 1 when the field was found and set, @error = 0.
;                  Not found: 0 with @error = 0 and @extended = 1.
;                  Failure: 0, @error set to $WV2_ERR_* (bad handle, or the script could not run).
; Author ........: Numeric1
; Remarks .......: Setting input.value on its own does not fire the listeners a React/Vue/Angular page
;                  attaches, so this dispatches "input" and "change" as well, which is what usually turns
;                  a disabled submit button back on. A field that only wakes on a real keystroke is rare;
;                  if one ever ignores this, follow the set with a click.
;                  What is written is what the FIELD keeps: an input of type text or password has every
;                  newline taken out of it by the browser itself, and a textarea has CR folded into LF.
;                  Both are the page's rule, not this function's, and reading the value back is how to see
;                  it. The text crosses as escaped ASCII, so an emoji or a half of one arrives unchanged.
; Related .......: _WV2_GetElementText, _WV2_ClickElement
; ===============================================================================================================================
Func _WV2_SetElementValue($iHandle, $sSelector, $sValue)
	$__WV2_sLastFunc = "_WV2_SetElementValue"
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	If Not __WV2_SelArg($sSelector, "_WV2_SetElementValue") Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	Local $sJs = "(function(){var e=" & __WV2_DomExpr($sSelector) & ";" & _
			"if(!e)return 'nf';" & _
			"e.focus();e.value=" & __WV2_JsString($sValue) & ";" & _
			"e.dispatchEvent(new Event('input',{bubbles:true}));" & _
			"e.dispatchEvent(new Event('change',{bubbles:true}));return 'ok';})()"
	Local $sOut = ""
	If Not _WV2_ExecuteScript($iHandle, $sJs, $sOut) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	If __WV2_Unquote($sOut) = "ok" Then Return SetError(0, 0, 1)
	Return SetError(0, 1, 0)
EndFunc   ;==>_WV2_SetElementValue

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_ClickElement
; Description ...: Scrolls an element into view, focuses it and clicks it.
; Syntax ........: _WV2_ClickElement($iHandle, $sSelector)
; Parameters ....: $iHandle   - Handle returned by _WV2_Create.
;                  $sSelector - A CSS selector, or an XPath when it starts with "/", "./" or "(".
; Return values .: Success: 1 when the element was found and clicked, @error = 0.
;                  Not found: 0 with @error = 0 and @extended = 1.
;                  Failure: 0, @error set to $WV2_ERR_* (bad handle, or the script could not run).
; Author ........: Numeric1
; Remarks .......: This calls the DOM element.click(), which is the page's own click, not an OS mouse
;                  event at a screen point. It covers buttons, links, checkboxes and submit controls; it
;                  will not drive a control that listens for pointer coordinates rather than the click
;                  action.
; Related .......: _WV2_SetElementValue, _WV2_ElementExists
; ===============================================================================================================================
Func _WV2_ClickElement($iHandle, $sSelector)
	$__WV2_sLastFunc = "_WV2_ClickElement"
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	If Not __WV2_SelArg($sSelector, "_WV2_ClickElement") Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	Local $sJs = "(function(){var e=" & __WV2_DomExpr($sSelector) & ";" & _
			"if(!e)return 'nf';" & _
			"e.scrollIntoView({block:'center'});e.focus();e.click();return 'ok';})()"
	Local $sOut = ""
	If Not _WV2_ExecuteScript($iHandle, $sJs, $sOut) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	If __WV2_Unquote($sOut) = "ok" Then Return SetError(0, 0, 1)
	Return SetError(0, 1, 0)
EndFunc   ;==>_WV2_ClickElement

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_WaitForElement
; Description ...: Waits until an element that matches the selector appears on the page.
; Syntax ........: _WV2_WaitForElement($iHandle, $sSelector[, $iTimeoutMs])
; Parameters ....: $iHandle     - Handle returned by _WV2_Create.
;                  $sSelector   - A CSS selector, or an XPath when it starts with "/", "./" or "(".
;                  $iTimeoutMs  - Optional: how long to wait, in milliseconds. Default 5000.
; Return values .: Success: 1 when the element appeared in time, @error = 0.
;                  Timeout: 0 with @error = 0 and @extended = 1 (the page is alive, the element is not there).
;                  Failure: 0, @error set to $WV2_ERR_* (bad handle, or a script call failed outright).
; Author ........: Numeric1
; Remarks .......: The wait runs on the AutoIt side, not inside one long script, so $iTimeoutMs is not held
;                  to the 30 second ceiling _WV2_ExecuteScript puts on a single script - it can wait longer
;                  than a page load. Each poll is one cheap existence check, so a slow or busy machine only
;                  costs more polls, never a missed element.
; Related .......: _WV2_ElementExists, _WV2_WaitNavigation
; ===============================================================================================================================
Func _WV2_WaitForElement($iHandle, $sSelector, $iTimeoutMs = 5000)
	$__WV2_sLastFunc = "_WV2_WaitForElement"
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	If Not __WV2_SelArg($sSelector, "_WV2_WaitForElement") Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	If $iTimeoutMs < 0 Then $iTimeoutMs = 0
	Local $tWait = TimerInit(), $iExists
	While 1
		$iExists = _WV2_ElementExists($iHandle, $sSelector)
		If @Error Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
		If $iExists Then Return SetError(0, 0, 1)
		If TimerDiff($tWait) >= $iTimeoutMs Then Return SetError(0, 1, 0)
		Sleep(50)
	WEnd
EndFunc   ;==>_WV2_WaitForElement

; ===============================================================================================================================
; DPI awareness and the one line that explains a failure
;
; These two answer the questions the forum keeps asking: "why is the page blurry" and "why is it blank".
; The first has one cause on Windows - a process that is not DPI aware is drawn at 96 dpi and stretched by
; the system afterwards, and a web view stretched that way is unreadable text - and one call that has to
; happen before the first window exists. The second has no single cause, so this kit hands the caller the
; facts it would otherwise print by hand, in the order a reader needs them.
; ===============================================================================================================================

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_SetProcessDpiAware
; Description ...: Makes the process DPI aware, so a WebView2 renders text and vector at native resolution
;                  instead of a bitmap the system stretches.
; Syntax ........: _WV2_SetProcessDpiAware()
; Parameters ....: none
; Return values .: Success: 1, @error = 0 and @extended = the level the process runs at:
;                  3 per monitor aware v2 (Windows 10 1803 and later), 2 per monitor aware, 1 system aware,
;                  0 unaware or a level this Windows will not name.
;                  Failure: 0, @error = $WV2_ERR_CALL when no Windows request for the awareness was granted.
; Author ........: Numeric1
; Remarks .......: The awareness of a process is decided ONCE. The first request that is granted settles
;                  it, and Windows refuses every later request with ERROR_ACCESS_DENIED - which is not a
;                  failure of this function: the process is aware at the level that was settled, and that
;                  is what @extended reports, read back from the system rather than repeated from what was
;                  asked for. Measured on Windows 10 19045 x86 and x64: the first call returns 1 with
;                  @extended = 3, and the second and third return 1 with @extended = 3 as well. AutoIt3.exe
;                  carries no manifest of its own, so the interpreter starts unaware and the first call
;                  really is granted; a script compiled with the "DPI aware" option starts decided, and
;                  there the first call takes the read-back path.
;                  Reading DPI is not one of the things that decides it: GetProcessDpiAwareness,
;                  GetThreadDpiAwarenessContext and IsProcessDPIAware were all measured before the first
;                  ask and the ask still succeeded afterwards.
;                  The call belongs before the first window, before GUICreate and before _WV2_Create. That
;                  is not because a later request is refused - on 19045 a request made after a window had
;                  been shown was still granted, measured - but because a window that already exists keeps
;                  the mapping it was drawn with, and that half could not be measured here: the test
;                  display is at 96 dpi, where aware and unaware are the same picture and the same css
;                  pixel count. On a scaled display, WebView2_Dpi_SelfTest.au3 show_aware and show_plain
;                  are the two processes to compare.
;                  In a DPI aware process the coordinates GUICreate and _WV2_SetBounds take are physical
;                  pixels; in an unaware one Windows virtualises them, which is why the two cases should
;                  not be mixed inside one process.
; Related .......: _WV2_Create, _WV2_SetBounds, _WV2_GetLastErrorText
; ===============================================================================================================================
Func _WV2_SetProcessDpiAware()
	$__WV2_sLastFunc = "_WV2_SetProcessDpiAware"
	; The level is always written by a SetError of this function itself, never by a Return of a helper.
	; Measured on 3.3.16.1: a Return <func>() reaches the caller only when that helper is the frame that
	; ran SetError - two frames deep (this function calls a helper that returns SetError(...)) arrives with
	; @error = 0 and @extended = 0 whatever the helper asked for.
	Local $iLevel = -1
	; Per monitor v2 first: it is the level a WebView2 is designed for, and each window of the GUI then
	; keeps the scale of the monitor it is on. -4 is the pseudo handle user32 exports for the context.
	Local $iAsk = __WV2_DpiAsk("user32.dll", "SetProcessDpiAwarenessContext", "ptr", -4, "bool")
	If $iAsk = 1 Then
		$iLevel = 3
	ElseIf $iAsk = 2 Then
		$iLevel = __WV2_DpiRead()
	Else
		; Per monitor, the same promise for Windows 10 1703 and 1803 without v2. shcore answers in HRESULTs,
		; whose sign the helper turns back into the unsigned number the documentation writes.
		$iAsk = __WV2_DpiAsk("shcore.dll", "SetProcessDpiAwareness", "int", 2, "long")
		If $iAsk = 1 Then
			$iLevel = 2
		ElseIf $iAsk = 2 Then
			$iLevel = __WV2_DpiRead()
		Else
			; System aware, the oldest of the three and the one every Windows since Vista answers. It fixes
			; the blur on the monitor the process started on, and nothing else.
			$iAsk = __WV2_DpiAsk("user32.dll", "SetProcessDPIAware", "", 0, "bool")
			If $iAsk = 1 Then
				$iLevel = 1
			ElseIf $iAsk = 2 Then
				$iLevel = __WV2_DpiRead()
			EndIf
		EndIf
	EndIf
	If $iLevel <> -1 Then
		__WV2_DpiNote($iLevel)
		Return SetError(0, $iLevel, 1)
	EndIf
	; Nothing was granted and nothing had been decided before, so the process stays as Windows gave it.
	__WV2_SetErr($WV2_ERR_CALL, 0, "_WV2_SetProcessDpiAware")
	Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
EndFunc   ;==>_WV2_SetProcessDpiAware

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_GetLastErrorText
; Description ...: Builds one line that says what this kit knows about the machine, the views and the
;                  last failure - the line to print when a page shows nothing.
; Syntax ........: _WV2_GetLastErrorText([$iHandle])
; Parameters ....: $iHandle - Optional: handle returned by _WV2_Create, whose browser version, user data
;                               folder and readiness are then reported too. Default -1 leaves them out.
; Return values .: The string. @error is always 0: this function cannot fail, and an empty result never
;                  means anything went right.
; Author ........: Numeric1
; Remarks .......: Read only, and it changes nothing: the error it quotes is the one the last call left in
;                  @error and @extended, so call this before anything else has run. It never holds a
;                  secret - the user data folder is a path, and cookies, tokens and the page text are not
;                  looked at - which is why it is safe to paste into a forum post.
;                  The three facts that answer most "it is blank" reports are in the first half: whether
;                  the runtime was found, whether the view is ready, and which function failed with which
;                  HRESULT. The DPI level is there because a blurry page is the same class of report.
; Related .......: _WV2_GetLastErrorMessage, _WV2_SetProcessDpiAware, _WV2_GetBrowserVersion
; ===============================================================================================================================
Func _WV2_GetLastErrorText($iHandle = -1)
	; The runtime probe rewrites the three last-failure globals, so the failure is read first, put back
	; afterwards, and only then written into the line.
	Local $iErrSave = $__WV2_iLastError, $iHRSave = $__WV2_iLastHR, $sFnSave = $__WV2_sLastFunc
	Local $sRt = _WV2_GetRuntimePath()
	$__WV2_iLastError = $iErrSave
	$__WV2_iLastHR = $iHRSave
	$__WV2_sLastFunc = $sFnSave

	Local $s = "UDF " & $WV2_VERSION & " | AutoIt " & @AutoItVersion & " " & (@AutoItX64 ? "x64" : "x86") & _
			" | Windows " & @OSVersion & " build " & @OSBuild
	If $sRt <> "" Then
		Local $aVer = StringRegExp($sRt, "(\d+\.\d+\.\d+\.\d+)", 1)
		$s &= " | runtime " & (IsArray($aVer) ? $aVer[0] : "found")
	Else
		$s &= " | runtime NOT installed (this kit never downloads it)"
	EndIf
	$s &= " | dpi " & __WV2_DpiText($__WV2_iDpiLevel)
	Local $iViews = 0, $j
	For $j = 1 To $__WV2_MAX
		If $__WV2_aUsed[$j] Then $iViews += 1
	Next
	$s &= " | views alive " & $iViews
	$s &= " | last " & ($__WV2_iLastError = $WV2_ERR_NONE ? "call succeeded" : _WV2_GetLastErrorMessage())
	If $iHandle >= 1 And $iHandle <= $__WV2_MAX And $__WV2_aUsed[$iHandle] Then
		Local $sVer = $__WV2_sVersion[$iHandle]
		$s &= " | [" & $iHandle & "] ready " & ($__WV2_bReady[$iHandle] ? "yes" : "no") & _
				", browser " & ($sVer <> "" ? $sVer : "not read") & _
				", user data " & ($__WV2_sUser[$iHandle] <> "" ? $__WV2_sUser[$iHandle] : "chosen by the runtime")
	EndIf
	Return SetError(0, 0, $s)
EndFunc   ;==>_WV2_GetLastErrorText

; ===============================================================================================================================
; The one-call start
; ===============================================================================================================================

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_CountViews
; Description ...: Counts the views this process holds open right now.
; Syntax ........: _WV2_CountViews()
; Parameters ....: None.
; Return values .: Number of live views, 0 after the last _WV2_Destroy. Always @error = 0.
; Author ........: Numeric1
; Remarks .......: The number is the UDF's own table, not a Windows count: a view whose browser process
;                  died on its own is still counted until it is released. It is what a test checks to
;                  prove that nothing leaked, and what a tray application reads to decide whether a
;                  second window should open a view or show the one it already has.
; Related .......: _WV2_Destroy, _WV2_DestroyAll, _WV2_GetLastErrorText
; ===============================================================================================================================
Func _WV2_CountViews()
	Local $i, $n = 0
	For $i = 1 To $__WV2_MAX
		If $__WV2_aUsed[$i] Then $n += 1
	Next
	Return SetError(0, 0, $n)
EndFunc   ;==>_WV2_CountViews

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_Simple
; Description ...: Opens a window with a page already in it, in one call.
; Syntax ........: _WV2_Simple($sContent[, $iWidth = 900[, $iHeight = 620[, $sTitle = ""[, $sUserDataFolder
;                  = ""[, $iTimeoutMs = $WV2_CREATE_TIMEOUT]]]]])
; Parameters ....: $sContent - What to show, in whichever of the three forms it comes to hand: an HTML
;                               document (anything opening with "<"), an address (anything with "://" or
;                               starting with "file:", "http:", "https:", "about:", "data:", "voice:"), or
;                               the path of an HTML file on this disk.
;                  $iWidth, $iHeight - Size of the window in pixels.
;                  $sTitle - Window title. Leave it "" and the title of the page is used when it arrives.
;                  $sUserDataFolder - Profile folder, "" lets the UDF build a temporary one.
;                  $iTimeoutMs - Time allowed for the browser to come up.
; Return values .: Success: the view handle, ready to be read and driven by every other function of this
;                  UDF, with @error = 0 and @extended = 0 when the page arrived, 1 when it did not (the
;                  window is open and the view is alive; _WV2_GetLastErrorMessage says what refused).
;                  Failure: 0 with @error = $WV2_ERR_ARG (nothing to show, or text that is neither HTML,
;                  nor an address, nor a file that exists), $WV2_ERR_GUI (no window), or whatever
;                  _WV2_Create reported (no runtime, no browser, timeout).
; Author ........: Numeric1
; Remarks .......: This is the eight lines of Tools/samples/01_first_window.au3 folded into one, for a
;                  script that shows a page and does nothing else: the window, the view, the page, the
;                  wait, and the reveal only once there is something to see. Pair it with _WV2_Run, which
;                  carries the message loop and the clean close:
;                  Code Example:
;                  #Include "WebView2.au3"
;                  _WV2_Run(_WV2_Simple("<h1>Hello from the Edge engine</h1>"))
;                  What @extended answers is the navigation, not the server. Measured on browser
;                  157.0.4341.42: an address nothing on this machine answers (port 9 is open for nothing)
;                  still arrives, because the browser's own error page is a completed navigation, so
;                  @extended is 0 and _WV2_GetLastErrorMessage is empty. The 1 therefore means that no
;                  navigation completed in $iTimeoutMs - a timeout, a filter, a page that never started -
;                  which is the case a script should look at, and the window stays open while it does.
;                  A window built here is hidden while the browser starts, because the first start of the
;                  engine costs seconds on a cold machine and an empty frame is what a user calls a freeze.
;                  The same window is hidden again when its view is destroyed, by _WV2_Destroy,
;                  _WV2_DestroyAll or the end of the process: the close of a controller answers when the
;                  browser has let go, and a page still painted through that hold is what Windows reports
;                  as "not responding" - measured 14 150 ms on a window this UDF had left on screen. It is
;                  hidden, not deleted, so a script that wants the window back can still show it. A window
;                  you created yourself is never hidden by the UDF: it is yours.
;                  A script that adds its own controls, menus or tray icon creates its own window and calls
;                  _WV2_Create instead: _WV2_Simple owns neither the loop nor the window of a real GUI.
;                  The handle of the window is not given back; it is the parent of the view, so
;                  _WV2_SetBounds, _WV2_FitToParent and WinSetTitle all reach it, and _WV2_Run closes it.
; Related .......: _WV2_Run, _WV2_Create, _WV2_Navigate, _WV2_NavigateToString, _WV2_WaitNavigation
; ===============================================================================================================================
Func _WV2_Simple($sContent, $iWidth = 900, $iHeight = 620, $sTitle = "", $sUserDataFolder = "", $iTimeoutMs = $WV2_CREATE_TIMEOUT)
	$__WV2_sLastFunc = "_WV2_Simple"
	If Not IsString($sContent) Or $sContent = "" Then
		__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_Simple")
		Return SetError($__WV2_iLastError, 0, 0)
	EndIf

	; Decided on the text, never on a guess about the network: the three forms are distinguishable by what
	; they start with, and anything else has to be a file that is really there.
	Local $sTrim = StringStripWS($sContent, 3)
	Local $sLower = StringLower($sTrim), $iKind = 0
	If StringLeft($sLower, 1) = "<" Then
		$iKind = 1 ; HTML
	ElseIf StringLeft($sLower, 5) = "file:" Or StringLeft($sLower, 4) = "http" Or _
			StringLeft($sLower, 6) = "about:" Or StringLeft($sLower, 5) = "data:" Or _
			StringLeft($sLower, 6) = "voice:" Or StringInStr($sTrim, "://") Then
		$iKind = 2 ; address
	ElseIf FileExists($sTrim) Then
		$iKind = 2 ; a path on this disk, made into an address
		$sTrim = "file:///" & StringReplace(StringReplace(_PathFull($sTrim), "\", "/"), " ", "%20")
	Else
		__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_Simple")
		Return SetError($__WV2_iLastError, 0, 0)
	EndIf

	Local $hGui = GUICreate(($sTitle <> "" ? $sTitle : "WebView2"), $iWidth, $iHeight)
	If $hGui = 0 Then
		__WV2_SetErr($WV2_ERR_GUI, 0, "_WV2_Simple")
		Return SetError($__WV2_iLastError, 0, 0)
	EndIf

	Local $iHandle = _WV2_Create($hGui, 0, 0, -1, -1, $sUserDataFolder, $iTimeoutMs)
	If $iHandle = 0 Then
		; The create left nothing behind but this empty window, and a window with no browser in it is not
		; something the caller can use or even close meaningfully.
		GuiDelete($hGui)
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf

	; _WV2_Create leaves the view glued to the client area of a window that is not shown yet; the explicit
	; hide is for the case where the caller's own code showed it from a callback during the start.
	_WV2_SetVisible($iHandle, False)

	; The window is recorded as ours: it exists only because this function made it, and the teardown marks
	; it out of sight before the blocking work of the close. A window the script created itself is never
	; touched, it belongs to the script.
	$__WV2_bOwnWin[$iHandle] = 1

	Local $bNav
	If $iKind = 1 Then
		$bNav = _WV2_NavigateToString($iHandle, $sContent)
	Else
		$bNav = _WV2_Navigate($iHandle, $sTrim)
	EndIf
	Local $iNavErr = $__WV2_iLastError, $iNavHR = $__WV2_iLastHR

	Local $bLoaded = False
	If $bNav Then $bLoaded = _WV2_WaitNavigation($iHandle, $iTimeoutMs) <> 0

	; A page that arrived names its own window, unless the script already named it.
	If $sTitle = "" Then
		Local $sPage = ""
		_WV2_GetTitle($iHandle, $sPage)
		If $sPage <> "" Then WinSetTitle($hGui, "", $sPage)
	EndIf

	_WV2_SetVisible($iHandle, True)
	GUISetState(@SW_SHOW, $hGui)

	; The last-failure globals belong to the navigation, not to the reveal that followed it.
	$__WV2_iLastError = $bLoaded ? $WV2_ERR_NONE : $iNavErr
	$__WV2_iLastHR = $iNavHR
	Return SetError(0, $bLoaded ? 0 : 1, $iHandle)
EndFunc   ;==>_WV2_Simple

; #FUNCTION# ====================================================================================================================
; Name ..........: _WV2_Run
; Description ...: Waits for the window to be closed, then releases the browser properly.
; Syntax ........: _WV2_Run([$iHandle = 0])
; Parameters ....: $iHandle - View whose window is waited for. 0 (default) waits for whichever window of
;                               the script is closed.
; Return values .: Always 1 with @error = 0; the number of views released is in @extended.
; Author ........: Numeric1
; Remarks .......: The loop is the part a first script forgets, and forgetting it does not produce an
;                  error, it produces a window that stops painting. $GUI_EVENT_CLOSE is compared as -3
;                  here so that this file needs no include of its own; it is the same value
;                  GUIConstantsEx.au3 names.
;                  The close is in the order the runtime wants: the window is hidden first, then the views
;                  are released from inside the loop, because the same teardown costs 113 ms here and
;                  between 390 and 2 700 ms in an OnAutoItExitRegister handler (measured, see
;                  _WV2_DestroyAll). A script that registers its own exit handler keeps its window logic
;                  and calls _WV2_DestroyAll from its loop instead.
;                  With several windows, whichever close ends the wait and takes all the views with it -
;                  that is what a simple script wants. A GUI that must know which window went away, or
;                  keep the others alive, keeps its own GUIGetMsg loop.
; Related .......: _WV2_Simple, _WV2_DestroyAll, _WV2_Destroy
; ===============================================================================================================================
Func _WV2_Run($iHandle = 0)
	$__WV2_sLastFunc = "_WV2_Run"
	If $iHandle <> 0 And Not __WV2_Valid($iHandle) Then Return SetError($__WV2_iLastError, 0, 0)
	Local $hGui = 0
	If $iHandle <> 0 Then $hGui = $__WV2_hParent[$iHandle]
	While 1
		If GUIGetMsg() = -3 Then ExitLoop
		; The window loop is the pump this style of script has, so it is also the safe point the
		; handlers of this style are answered in. Nothing is waited for here, so nothing can be mixed.
		__WV2_DispatchQueued(0, $__WV2_CB_CAP)
	WEnd
	If $hGui <> 0 Then
		GUISetState(@SW_HIDE, $hGui)
	Else
		; Nothing was named: every window this process made goes out of sight before the browser starts
		; to leave, so the user never sees a page that has disappeared.
		Local $i
		For $i = 1 To $__WV2_MAX
			If $__WV2_aUsed[$i] And $__WV2_hParent[$i] <> 0 Then GUISetState(@SW_HIDE, $__WV2_hParent[$i])
		Next
	EndIf
	Local $iDone = _WV2_DestroyAll()
	Return SetError(0, $iDone, 1)
EndFunc   ;==>_WV2_Run


; ===============================================================================================================================
; Internal functions
; ===============================================================================================================================

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_OptLive
; Description ...: 1 when a browser process started by this process is still held, 0 when none is.
; Remarks .......: The ten option setters answer this through @extended, because the runtime reads the
;                  options object once, inside the create: after that, recording a value is honest work
;                  that reaches the NEXT environment, and a script that expected the running one to change
;                  has to be told. Counting views gives the same answer as counting environments here - the
;                  table of shared environments keeps an entry exactly while a view holds it - and is the
;                  cheaper question to ask.
; ===============================================================================================================================
Func __WV2_OptLive()
	Return _WV2_CountViews() > 0 ? 1 : 0
EndFunc   ;==>__WV2_OptLive

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_JsString
; Description ...: Writes an AutoIt string as a JavaScript string literal, quotes included, so the text
;                  cannot end the literal early or become code.
; Remarks .......: The escape table is the JSON one, which JavaScript accepts as a superset. Everything
;                  outside printable 7 bit ASCII goes out as \uXXXX - the controls, 0x7F, and every
;                  character at 0x80 or above. The reason is measured, not theorised: a script that CARRIES
;                  such a character, or a result that COMES BACK with an unpaired one, is answered by the
;                  runtime with a BSTR the encoder refuses, and no callback ever arrives, so the call hangs
;                  until it times out. Escaped, the same text is pure ASCII on the wire and every char
;                  reassembles on the far side; an astral character arrives as the two halves of its pair,
;                  which is what UTF-16 means anyway.
; ===============================================================================================================================
Func __WV2_JsString($sText)
	If Not IsString($sText) Then $sText = String($sText)
	Local $sOut = '"', $iAsc, $i
	For $i = 1 To StringLen($sText)
		$iAsc = AscW(StringMid($sText, $i, 1))
		Switch $iAsc
			Case 8
				$sOut &= '\b'
			Case 9
				$sOut &= '\t'
			Case 10
				$sOut &= '\n'
			Case 12
				$sOut &= '\f'
			Case 13
				$sOut &= '\r'
			Case 34
				$sOut &= '\"'
			Case 92
				$sOut &= '\\'
			Case Else
				; Written as a block, not as a ternary: Or binds looser than ? in AutoIt, and the test
				; then reads as one boolean whose "value" is a character.
				If $iAsc < 32 Or $iAsc >= 127 Then
					$sOut &= '\u' & Hex($iAsc, 4)
				Else
					$sOut &= StringMid($sText, $i, 1)
				EndIf
		EndSwitch
	Next
	Return $sOut & '"'
EndFunc   ;==>__WV2_JsString

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_Unquote
; Description ...: Reads back one JSON value as an AutoIt string. A quoted literal is decoded, and
;                  anything else (a number, true, null) is already the text the caller wants.
; Remarks .......: Only what _WV2_ExecuteScript answers for a script that returned a string reaches this;
;                  the bare "null" of a script that threw or returned nothing is NOT decoded here, because
;                  the callers compare the raw text before unquoting to tell the two apart.
; ===============================================================================================================================
Func __WV2_Unquote($sJson)
	If Not IsString($sJson) Then Return String($sJson)
	If StringLen($sJson) < 2 Or StringLeft($sJson, 1) <> '"' Or StringRight($sJson, 1) <> '"' Then Return $sJson
	Local $sOut = "", $i = 2, $iLen = StringLen($sJson) - 1, $c
	While $i <= $iLen
		$c = StringMid($sJson, $i, 1)
		If $c <> '\' Then
			$sOut &= $c
			$i += 1
		Else
			$i += 1
			$c = StringMid($sJson, $i, 1)
			Switch $c
				Case 'b'
					$sOut &= Chr(8)
				Case 'f'
					$sOut &= Chr(12)
				Case 'n'
					$sOut &= @LF
				Case 'r'
					$sOut &= @CR
				Case 't'
					$sOut &= @TAB
				Case 'u'
					$sOut &= ChrW(Number("0x" & StringMid($sJson, $i + 1, 4)))
					$i += 4
				Case Else
					; \" \\ \/ and any other escaped char stand for themselves.
					$sOut &= $c
			EndSwitch
			$i += 1
		EndIf
	WEnd
	Return $sOut
EndFunc   ;==>__WV2_Unquote

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_XPathSel / __WV2_DomExpr / __WV2_DomCountExpr
; Description ...: Decide from the text alone whether a selector is meant as XPath, and write the
;                  JavaScript that asks the page for that selector - one element, or how many match.
; Remarks .......: The four openings "/", "./", ".//" and "(" cannot be the start of a CSS selector, so
;                  the dialect is settled without asking the page and without a second round trip. A CSS
;                  selector that does not parse makes querySelector throw, the runtime answers "null" and
;                  the caller reads that as "not found" - the same answer a missing element gives, which
;                  is the only answer that keeps a wait loop waiting.
;                  Neither dialect reaches inside an iframe or past a shadow root: those belong to the
;                  script the caller writes with _WV2_ExecuteScript.
; ===============================================================================================================================
Func __WV2_XPathSel($sSelector)
	If Not IsString($sSelector) Or $sSelector = "" Then Return False
	If StringLeft($sSelector, 1) = "(" Or StringLeft($sSelector, 1) = "/" Then Return True
	Return StringLeft($sSelector, 2) = "./"
EndFunc   ;==>__WV2_XPathSel

Func __WV2_DomExpr($sSelector)
	Local $sJs = __WV2_JsString($sSelector)
	If __WV2_XPathSel($sSelector) Then _
			Return "(function(){var r=document.evaluate(" & $sJs & ",document,null,XPathResult.FIRST_ORDERED_NODE_TYPE,null);" & _
			"return r.singleNodeValue;})()"
	Return "document.querySelector(" & $sJs & ")"
EndFunc   ;==>__WV2_DomExpr

Func __WV2_DomCountExpr($sSelector)
	Local $sJs = __WV2_JsString($sSelector)
	If __WV2_XPathSel($sSelector) Then _
			Return "(function(){var r=document.evaluate(" & $sJs & ",document,null,XPathResult.ORDERED_NODE_ITERATOR_TYPE,null);" & _
			"var n=0;while(r.iterateNext())n++;return n;})()"
	Return "document.querySelectorAll(" & $sJs & ").length"
EndFunc   ;==>__WV2_DomCountExpr

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_SelArg
; Description ...: The one argument check every element helper shares: a selector has to be a non empty
;                  string, because nothing else in this kit can tell an empty selector from a page that
;                  holds nothing.
; ===============================================================================================================================
Func __WV2_SelArg($sSelector, $sFunc)
	If IsString($sSelector) And $sSelector <> "" Then Return True
	__WV2_SetErr($WV2_ERR_ARG, 0, $sFunc)
	Return False
EndFunc   ;==>__WV2_SelArg

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_DpiAsk / __WV2_DpiNote / __WV2_DpiRead / __WV2_DpiCtxLevel / __WV2_DpiText
; Description ...: The four entries Windows offers for the awareness of a process, asked in order, and the
;                  level the process actually runs at once one of them has answered.
; Remarks .......: DpiAsk sorts the answers into four, because the same refusal means two opposite things:
;                  1 granted, 2 refused BECAUSE THE AWARENESS WAS ALREADY DECIDED - by the manifest of the
;                  executable or by an earlier call, which is the state the caller wanted - 0 refused
;                  outright, -1 the entry point does not exist on this Windows. The two spellings of
;                  "already decided" are ERROR_ACCESS_DENIED (5) behind a BOOL and E_ACCESSDENIED
;                  (0x80070005) behind an HRESULT; an HRESULT reaches AutoIt signed, so it is made
;                  unsigned before it is compared.
;                  DpiRead is what "already decided" is answered with: asking the system, never repeating
;                  what was asked for. shcore names the three levels it knows for the handle NULL - the -4
;                  the context functions take is a different pseudo handle and shcore refuses it - and on a
;                  2 the thread context tells which of the two per-monitor levels the process runs at. -1
;                  means this Windows will not name the level, which the text says out loud.
; ===============================================================================================================================
Func __WV2_DpiAsk($sDll, $sFn, $sArgType, $iArg, $sRetType)
	; The refusal this helper reads lives in GetLastError, and AutoIt does not clear it: measured, a
	; SetLastError(4242) is still 4242 after a DllCall of SetProcessDPIAware that returned TRUE. Zeroing
	; here is what makes a 5 mean the call that follows rather than anything that ran earlier.
	DllCall("kernel32.dll", "none", "SetLastError", "dword", 0)
	Local $aCall
	If $sArgType = "" Then
		$aCall = DllCall($sDll, $sRetType, $sFn)
	Else
		$aCall = DllCall($sDll, $sRetType, $sFn, $sArgType, $iArg)
	EndIf
	If @Error Or Not IsArray($aCall) Then Return -1
	If $sRetType = "long" Then
		Local $iHR = $aCall[0]
		If $iHR < 0 Then $iHR += 4294967296
		If $iHR = 0 Then Return 1
		If $iHR = 0x80070005 Then Return 2
		Return 0
	EndIf
	If $aCall[0] <> 0 Then Return 1
	Local $aGl = DllCall("kernel32.dll", "dword", "GetLastError")
	Local $iGl = (IsArray($aGl) ? $aGl[0] : 0)
	If $iGl = 5 Then Return 2
	; 87 ERROR_INVALID_PARAMETER: this Windows knows the entry point but not the context asked for.
	If $iGl = 87 Then Return -1
	Return 0
EndFunc   ;==>__WV2_DpiAsk

Func __WV2_DpiNote($iLevel)
	$__WV2_iDpiLevel = $iLevel
	Return 1
EndFunc   ;==>__WV2_DpiNote

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_DpiCtxLevel
; Description ...: Names the awareness of the calling thread from its context, 3 v2, 2 per monitor,
;                  1 system, 0 unaware; -1 when this Windows will not answer.
; Remarks .......: -4, -3, -2 and -1 are the pseudo handles user32 exports for the four contexts, and
;                  AreDpiAwarenessContextsEqual is the only supported way of comparing them - the handles
;                  themselves are real pointers that change, so 0x00006010 for unaware on one run is not
;                  a fact worth testing. Measured on 19045: the unaware context compares equal to -1 and
;                  none of the other three.
; ===============================================================================================================================
Func __WV2_DpiCtxLevel()
	Local $aCtx = DllCall("user32.dll", "ptr", "GetThreadDpiAwarenessContext")
	If @Error Or Not IsArray($aCtx) Or $aCtx[0] = 0 Then Return -1
	Local Const $aLvl[4] = [3, 2, 1, 0]
	Local Const $aVal[4] = [-4, -3, -2, -1]
	For $i = 0 To 3
		Local $aEq = DllCall("user32.dll", "bool", "AreDpiAwarenessContextsEqual", "ptr", $aCtx[0], "ptr", $aVal[$i])
		If (Not @Error) And IsArray($aEq) And $aEq[0] <> 0 Then Return $aLvl[$i]
	Next
	Return -1
EndFunc   ;==>__WV2_DpiCtxLevel

Func __WV2_DpiRead()
	; The handle this entry point wants for the calling process is NULL. The -4 the context apis take is a
	; pseudo handle shcore refuses here with E_INVALIDARG (0x80070057), measured on 19045; passing it is
	; how a reader ends up guessing from IsProcessDPIAware, which cannot tell per-monitor v2 from system
	; aware and answers 1 for both.
	Local $aCall = DllCall("shcore.dll", "long", "GetProcessDpiAwareness", "ptr", 0, "int*", 0)
	If (Not @Error) And IsArray($aCall) And $aCall[0] = 0 Then
		If $aCall[2] < 2 Then Return $aCall[2]
		; 2 is PER_MONITOR_DPI_AWARE, which is the name shcore gives to two different levels.
		Return (__WV2_DpiCtxLevel() = 3 ? 3 : 2)
	EndIf
	; Windows 7, or a shcore that refused: since 1607 the thread context names all four levels on its own.
	Local $iCtx = __WV2_DpiCtxLevel()
	If $iCtx <> -1 Then Return $iCtx
	; Nothing else is left, and this pair of answers is still the truth: aware, or not.
	$aCall = DllCall("user32.dll", "bool", "IsProcessDPIAware")
	If @Error Or Not IsArray($aCall) Then Return -1
	Return ($aCall[0] <> 0 ? 1 : 0)
EndFunc   ;==>__WV2_DpiRead

Func __WV2_DpiText($iLevel)
	Switch $iLevel
		Case 3
			Return "3 per-monitor v2"
		Case 2
			Return "2 per-monitor"
		Case 1
			Return "1 system aware"
		Case 0
			Return "0 unaware"
	EndSwitch
	Return "-1 not settled (_WV2_SetProcessDpiAware before the first window)"
EndFunc   ;==>__WV2_DpiText

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_DllForVersion
; Description ...: Builds the path of EmbeddedBrowserWebView.dll for an installed version.
; ===============================================================================================================================
Func __WV2_ProgramFiles($b32)
	; The runtime installs side by side with Edge, which is 32 bit on most machines.
	Local $sVar = ($b32 ? "ProgramFiles(x86)" : "ProgramFiles")
	Local $sDir = EnvGet($sVar)
	If $sDir = "" Then $sDir = @ProgramFilesDir
	Return $sDir
EndFunc   ;==>__WV2_ProgramFiles

Func __WV2_DllForVersion($sVer)
	Local $i
	Local $sArch = (@AutoItX64 ? "x64" : "x86")
	For $i = 1 To 2
		Local $sRoot = __WV2_ProgramFiles($i = 1) & "\Microsoft\EdgeWebView\Application\" & $sVer & "\EBWebView\" & $sArch
		Local $sDll = $sRoot & "\" & $__WV2_DLL_NAME
		If FileExists($sDll) Then Return $sDll
	Next
	Return ""
EndFunc   ;==>__WV2_DllForVersion

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_CompareVersion
; Description ...: Compares two dotted versions numerically. Returns 1, -1 or 0.
; ===============================================================================================================================
Func __WV2_CompareVersion($sA, $sB)
	If $sB = "" Then Return 1
	Local $i
	Local $aA = StringSplit($sA, "."), $aB = StringSplit($sB, ".")
	For $i = 1 To 4
		If $i > $aA[0] Then Return -1
		If $i > $aB[0] Then Return 1
		If Number($aA[$i]) > Number($aB[$i]) Then Return 1
		If Number($aA[$i]) < Number($aB[$i]) Then Return -1
	Next
	Return 0
EndFunc   ;==>__WV2_CompareVersion

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_InitHeap
; Description ...: Reserves the memory holding every fake handler object and registers the callbacks
;                  that serve them, once per script.
;                  Each (instance, slot) block is five pointers: four vtable slots and the object
;                  cell that points back at them.
; ===============================================================================================================================
Func __WV2_InitHeap()
	If $__WV2_tHeap <> 0 Then Return
	$__WV2_iPtrSize = DllStructGetSize(DllStructCreate("ptr"))
	$__WV2_tHeap = DllStructCreate("ptr data[" & ($__WV2_MAX * $__WV2_SLOT_COUNT * $__WV2_PTRS_PER_BLOCK) & "]")
	$__WV2_pHeap = Number(DllStructGetPtr($__WV2_tHeap))
	$__WV2_hCbQI = DllCallbackRegister("__WV2_QI", "long", "ptr;ptr;ptr")
	$__WV2_hCbAddRef = DllCallbackRegister("__WV2_AddRef", "dword", "ptr")
	$__WV2_hCbRelease = DllCallbackRegister("__WV2_Release", "dword", "ptr")
	Local $i
	For $i = 1 To $__WV2_SLOT_COUNT
		$__WV2_hCbInv[$i] = DllCallbackRegister($__WV2_aInvFunc[$i], "long", $__WV2_aInvArgs[$i])
	Next
EndFunc   ;==>__WV2_InitHeap

Func __WV2_BlockBase($i, $iSlot)
	Return (($i - 1) * $__WV2_SLOT_COUNT + ($iSlot - 1)) * $__WV2_PTRS_PER_BLOCK
EndFunc   ;==>__WV2_BlockBase

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_BuildHandler
; Description ...: Lays out one fake COM object in the heap: four vtable slots and, right after them,
;                  the object cell that points back at the vtable.
; ===============================================================================================================================
Func __WV2_BuildHandler($i, $iSlot)
	Local $b = __WV2_BlockBase($i, $iSlot)
	DllStructSetData($__WV2_tHeap, "data", DllCallbackGetPtr($__WV2_hCbQI), $b + 1)
	DllStructSetData($__WV2_tHeap, "data", DllCallbackGetPtr($__WV2_hCbAddRef), $b + 2)
	DllStructSetData($__WV2_tHeap, "data", DllCallbackGetPtr($__WV2_hCbRelease), $b + 3)
	DllStructSetData($__WV2_tHeap, "data", DllCallbackGetPtr($__WV2_hCbInv[$iSlot]), $b + 4)
	; DllStructGetPtr only takes one index, so the object address is computed from the heap base.
	Local $pBase = DllStructGetPtr($__WV2_tHeap)
	DllStructSetData($__WV2_tHeap, "data", $pBase + $b * $__WV2_iPtrSize, $b + 5)
	$__WV2_pObj[$i][$iSlot] = $pBase + ($b + 4) * $__WV2_iPtrSize
EndFunc   ;==>__WV2_BuildHandler

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_BuildAllHandlers
; Description ...: Lays out the whole row of handler objects of one instance. Writing every slot of the
;                  block costs less than remembering which of them were built, and a view needs only a
;                  handful of them.
; ===============================================================================================================================
Func __WV2_BuildAllHandlers($i)
	Local $j
	For $j = 1 To $__WV2_SLOT_COUNT
		__WV2_BuildHandler($i, $j)
	Next
EndFunc   ;==>__WV2_BuildAllHandlers

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_FreeHandlers
; Description ...: Forgets the handler objects of an instance. The shared callbacks and the heap block
;                  itself stay alive: they are reused by the next _WV2_Create.
; ===============================================================================================================================
Func __WV2_FreeHandlers($i)
	Local $j
	For $j = 1 To $__WV2_SLOT_COUNT
		$__WV2_pObj[$i][$j] = 0
	Next
EndFunc   ;==>__WV2_FreeHandlers

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_OptStrOut / __WV2_OptBoolOut
; Description ...: Answers a get_ of the options object. A string leaves the way the runtime frees it:
;                  CoTaskMemAlloc and no BSTR header, and an option nobody set leaves as NULL, which is
;                  what the loader hands back for an unset property. A BOOL leaves as the four bytes the
;                  header declares.
; ===============================================================================================================================
Func __WV2_OptStrOut($pOut, $sText)
	If $pOut = 0 Then Return $__WV2_HR_E_FAIL
	If $sText = "" Then
		DllStructSetData(DllStructCreate("ptr", $pOut), 1, 0)
		Return 0
	EndIf
	; One wchar more than the text, for the terminator: the size asked of the allocator and the size the
	; reader walks are then the same number, whatever the bitness.
	Local $tSrc = DllStructCreate("wchar[" & (StringLen($sText) + 1) & "]")
	DllStructSetData($tSrc, 1, $sText)
	Local $aAlloc = DllCall("ole32.dll", "ptr", "CoTaskMemAlloc", "dword", DllStructGetSize($tSrc))
	If @Error Or Not IsArray($aAlloc) Or $aAlloc[0] = 0 Then Return $__WV2_HR_E_FAIL
	Local $tDst = DllStructCreate("wchar[" & (StringLen($sText) + 1) & "]", $aAlloc[0])
	DllStructSetData($tDst, 1, $sText)
	DllStructSetData(DllStructCreate("ptr", $pOut), 1, $aAlloc[0])
	Return 0
EndFunc   ;==>__WV2_OptStrOut

Func __WV2_OptBoolOut($pOut, $iValue)
	If $pOut = 0 Then Return $__WV2_HR_E_FAIL
	DllStructSetData(DllStructCreate("dword", $pOut), 1, ($iValue ? 1 : 0))
	Return 0
EndFunc   ;==>__WV2_OptBoolOut

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_OptQI / __WV2_OptAddRef / __WV2_OptRelease
; Description ...: IUnknown of the options object. Each cell answers for IUnknown and for the interface
;                  whose properties its own vtable carries, and the two interfaces whose properties are
;                  arrays are refused: the runtime asks for everything and reads only what it is given,
;                  which is what an environment built without a loader has always done.
; ===============================================================================================================================
Func __WV2_OptQI($pThis, $pRIID, $pOut)
	#forceref $pThis
	If $pOut = 0 Then Return $__WV2_HR_E_FAIL
	Local $sIID = __WV2_IIDString($pRIID)
	Local $k = 0
	Switch $sIID
		Case $WV2_IID_UNKNOWN, $WV2_IID_OPTB
			$k = 1
		Case $WV2_IID_OPT2
			$k = 2
		Case $WV2_IID_OPT3
			$k = 3
		Case $WV2_IID_OPT5
			$k = 4
		Case $WV2_IID_OPT6
			$k = 5
		Case $WV2_IID_OPT8
			$k = 6
	EndSwitch
	DllStructSetData(DllStructCreate("ptr", $pOut), 1, ($k ? $__WV2_pOpt[$k] : 0))
	If $k = 0 Then Return $__WV2_HR_E_NOINTERFACE
	Return 0
EndFunc   ;==>__WV2_OptQI

Func __WV2_OptAddRef($pThis)
	If $pThis = 0 Then Return 0
	Return 1
EndFunc   ;==>__WV2_OptAddRef

Func __WV2_OptRelease($pThis)
	If $pThis = 0 Then Return 0
	Return 0
EndFunc   ;==>__WV2_OptRelease

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: the nine properties of the options object
; Description ...: One pair of callbacks per property. The runtime only ever calls the getters of this
;                  object - it is handed over already filled - but the setters are there so the object is
;                  a full implementation of the interfaces it claims.
; ===============================================================================================================================
Func __WV2_OptGetAba($pThis, $pOut)
	#forceref $pThis
	Return __WV2_OptStrOut($pOut, $__WV2_sOptAba)
EndFunc   ;==>__WV2_OptGetAba

Func __WV2_OptPutAba($pThis, $sText)
	#forceref $pThis
	$__WV2_sOptAba = String($sText)
	Return 0
EndFunc   ;==>__WV2_OptPutAba

Func __WV2_OptGetLang($pThis, $pOut)
	#forceref $pThis
	Return __WV2_OptStrOut($pOut, $__WV2_sOptLang)
EndFunc   ;==>__WV2_OptGetLang

Func __WV2_OptPutLang($pThis, $sText)
	#forceref $pThis
	$__WV2_sOptLang = String($sText)
	Return 0
EndFunc   ;==>__WV2_OptPutLang

Func __WV2_OptGetTcbv($pThis, $pOut)
	#forceref $pThis
	Return __WV2_OptStrOut($pOut, $__WV2_sOptTcbv)
EndFunc   ;==>__WV2_OptGetTcbv

Func __WV2_OptPutTcbv($pThis, $sText)
	#forceref $pThis
	$__WV2_sOptTcbv = String($sText)
	Return 0
EndFunc   ;==>__WV2_OptPutTcbv

Func __WV2_OptGetSso($pThis, $pOut)
	#forceref $pThis
	Return __WV2_OptBoolOut($pOut, $__WV2_bOptSso)
EndFunc   ;==>__WV2_OptGetSso

Func __WV2_OptPutSso($pThis, $iValue)
	#forceref $pThis
	$__WV2_bOptSso = ($iValue ? True : False)
	Return 0
EndFunc   ;==>__WV2_OptPutSso

Func __WV2_OptGetExcl($pThis, $pOut)
	#forceref $pThis
	Return __WV2_OptBoolOut($pOut, $__WV2_bOptExcl)
EndFunc   ;==>__WV2_OptGetExcl

Func __WV2_OptPutExcl($pThis, $iValue)
	#forceref $pThis
	$__WV2_bOptExcl = ($iValue ? True : False)
	Return 0
EndFunc   ;==>__WV2_OptPutExcl

Func __WV2_OptGetCrash($pThis, $pOut)
	#forceref $pThis
	Return __WV2_OptBoolOut($pOut, $__WV2_bOptCrash)
EndFunc   ;==>__WV2_OptGetCrash

Func __WV2_OptPutCrash($pThis, $iValue)
	#forceref $pThis
	$__WV2_bOptCrash = ($iValue ? True : False)
	Return 0
EndFunc   ;==>__WV2_OptPutCrash

Func __WV2_OptGetTrack($pThis, $pOut)
	#forceref $pThis
	Return __WV2_OptBoolOut($pOut, $__WV2_bOptTrack)
EndFunc   ;==>__WV2_OptGetTrack

Func __WV2_OptPutTrack($pThis, $iValue)
	#forceref $pThis
	$__WV2_bOptTrack = ($iValue ? True : False)
	Return 0
EndFunc   ;==>__WV2_OptPutTrack

Func __WV2_OptGetExt($pThis, $pOut)
	#forceref $pThis
	Return __WV2_OptBoolOut($pOut, $__WV2_bOptExt)
EndFunc   ;==>__WV2_OptGetExt

Func __WV2_OptPutExt($pThis, $iValue)
	#forceref $pThis
	$__WV2_bOptExt = ($iValue ? True : False)
	Return 0
EndFunc   ;==>__WV2_OptPutExt

Func __WV2_OptGetScroll($pThis, $pOut)
	#forceref $pThis
	Return __WV2_OptBoolOut($pOut, $__WV2_iOptScroll)
EndFunc   ;==>__WV2_OptGetScroll

Func __WV2_OptPutScroll($pThis, $iValue)
	#forceref $pThis
	$__WV2_iOptScroll = Int($iValue)
	Return 0
EndFunc   ;==>__WV2_OptPutScroll

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_MkOptCell
; Description ...: Lays one interface of the options object: a vtable of the pointers handed over, and the
;                  cell that points back at it. Six of these make the object, one per interface it answers
;                  for - which is why the slot numbers of a property are always the numbers the header
;                  gives for the interface that declares it.
; ===============================================================================================================================
Func __WV2_MkOptCell($k, $aPtrs)
	Local $n = UBound($aPtrs)
	$__WV2_tOptVt[$k] = DllStructCreate("ptr[" & $n & "]")
	Local $i
	For $i = 0 To $n - 1
		DllStructSetData($__WV2_tOptVt[$k], 1, $aPtrs[$i], $i + 1)
	Next
	; A struct kept in a local variable is freed when the function returns, so the memory of the cell, like
	; that of the heap, lives in a global.
	$__WV2_tOptObj[$k] = DllStructCreate("ptr")
	DllStructSetData($__WV2_tOptObj[$k], 1, DllStructGetPtr($__WV2_tOptVt[$k]))
	$__WV2_pOpt[$k] = Number(DllStructGetPtr($__WV2_tOptObj[$k]))
EndFunc   ;==>__WV2_MkOptCell

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_BuildOptions
; Description ...: Builds the options object once per script and hands back the cell of the base interface,
;                  which is the pointer the environment factory takes. Returns 0 when the callbacks could
;                  not be registered.
; ===============================================================================================================================
Func __WV2_BuildOptions()
	If $__WV2_pOpt[1] <> 0 Then Return $__WV2_pOpt[1]
	If $__WV2_iPtrSize = 0 Then $__WV2_iPtrSize = DllStructGetSize(DllStructCreate("ptr"))

	$__WV2_hCbOptQI = DllCallbackRegister("__WV2_OptQI", "long", "ptr;ptr;ptr")
	$__WV2_hCbOptAddRef = DllCallbackRegister("__WV2_OptAddRef", "dword", "ptr")
	$__WV2_hCbOptRelease = DllCallbackRegister("__WV2_OptRelease", "dword", "ptr")
	Local $pQI = DllCallbackGetPtr($__WV2_hCbOptQI)
	Local $pAR = DllCallbackGetPtr($__WV2_hCbOptAddRef)
	Local $pRL = DllCallbackGetPtr($__WV2_hCbOptRelease)
	If $pQI = 0 Or $pAR = 0 Or $pRL = 0 Then Return 0

	; One handle per callback, all kept in a global: the runtime may read the object long after this
	; function returned, and a callback whose handle is gone is gone with it. Index 0 is never used, so the
	; nine getters and the nine setters sit in one array of nineteen.
	Local $sGet[10] = ["", "__WV2_OptGetAba", "__WV2_OptGetLang", "__WV2_OptGetTcbv", "__WV2_OptGetSso", _
			"__WV2_OptGetExcl", "__WV2_OptGetCrash", "__WV2_OptGetTrack", "__WV2_OptGetExt", "__WV2_OptGetScroll"]
	Local $sPut[10] = ["", "__WV2_OptPutAba", "__WV2_OptPutLang", "__WV2_OptPutTcbv", "__WV2_OptPutSso", _
			"__WV2_OptPutExcl", "__WV2_OptPutCrash", "__WV2_OptPutTrack", "__WV2_OptPutExt", "__WV2_OptPutScroll"]
	; The three string properties take a wstr, the five BOOL ones and the style one a dword - the same
	; difference the header makes between LPWSTR and BOOL in a propput.
	Local $bStr[10] = [False, True, True, True, False, False, False, False, False, False]
	Local $i
	For $i = 1 To 9
		$__WV2_hCbOpt[$i] = DllCallbackRegister($sGet[$i], "long", "ptr;ptr")
		$__WV2_hCbOpt[$i + 9] = DllCallbackRegister($sPut[$i], "long", "ptr;" & ($bStr[$i] ? "wstr" : "dword"))
		If $__WV2_hCbOpt[$i] = 0 Or $__WV2_hCbOpt[$i + 9] = 0 Then Return 0
	Next
	Local $pGet[10], $pPut[10]
	For $i = 1 To 9
		$pGet[$i] = DllCallbackGetPtr($__WV2_hCbOpt[$i])
		$pPut[$i] = DllCallbackGetPtr($__WV2_hCbOpt[$i + 9])
	Next

	; Six vtables, each with its own cell: the base interface carries its four pairs at slots 3 to 10, and
	; every newer interface the pair of the property it adds at slot 3.
	Local $aBase[11] = [$pQI, $pAR, $pRL, $pGet[1], $pPut[1], $pGet[2], $pPut[2], $pGet[3], $pPut[3], _
			$pGet[4], $pPut[4]]
	Local $aExcl[5] = [$pQI, $pAR, $pRL, $pGet[5], $pPut[5]]
	Local $aCrash[5] = [$pQI, $pAR, $pRL, $pGet[6], $pPut[6]]
	Local $aTrack[5] = [$pQI, $pAR, $pRL, $pGet[7], $pPut[7]]
	Local $aExt[5] = [$pQI, $pAR, $pRL, $pGet[8], $pPut[8]]
	Local $aScroll[5] = [$pQI, $pAR, $pRL, $pGet[9], $pPut[9]]
	__WV2_MkOptCell(1, $aBase)
	__WV2_MkOptCell(2, $aExcl)
	__WV2_MkOptCell(3, $aCrash)
	__WV2_MkOptCell(4, $aTrack)
	__WV2_MkOptCell(5, $aExt)
	__WV2_MkOptCell(6, $aScroll)
	Return $__WV2_pOpt[1]
EndFunc   ;==>__WV2_BuildOptions

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_OptionsForCreate
; Description ...: The options pointer for one create, or 0 when no option was ever asked for: a script
;                  that sets nothing keeps the call exactly as it has always been.
; Return values .: The pointer, 0 for "no options", or -1 when the object could not be built.
; ===============================================================================================================================
Func __WV2_OptionsForCreate($sDll)
	If Not $__WV2_bOptSet Then Return 0
	; Measured on 156.0.4314.58, x86 and x64: the internal factory this UDF calls refuses an options object
	; whose TargetCompatibleBrowserVersion is empty - 0x80070057, before the callback is ever reached. The
	; loader answers the same property with an empty string and turns it into a version itself, so the
	; version of the DLL being called is filled in here instead.
	If $__WV2_sOptTcbv = "" Then
		Local $aV = StringRegExp($sDll, "(\d+\.\d+\.\d+\.\d+)", 1)
		If IsArray($aV) Then $__WV2_sOptTcbv = $aV[0]
	EndIf
	Local $p = __WV2_BuildOptions()
	If $p = 0 Then Return -1
	Return $p
EndFunc   ;==>__WV2_OptionsForCreate

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_FindInst
; Description ...: Finds which instance and which handler slot a fake object pointer belongs to.
;                  @extended returns the slot.
; ===============================================================================================================================
Func __WV2_FindInst($pThis)
	; The fake objects all live in one block, so the address alone gives back the pair: blocks of
	; $__WV2_PTRS_PER_BLOCK pointers, $__WV2_SLOT_COUNT per instance, and the object cell is the
	; fifth pointer of its block. The arithmetic keeps this O(1) whatever the number of slots.
	; A Ptr cannot be divided in AutoIt: the division hands the pointer back untouched. The distance
	; is therefore turned into a plain number before it is divided.
	If $pThis = 0 Or $__WV2_pHeap = 0 Then Return SetError(1, 0, 0)
	Local $iDelta = Number($pThis) - Number($__WV2_pHeap)
	If $iDelta <= 0 Then Return SetError(1, 0, 0)
	If Mod($iDelta, $__WV2_iPtrSize) <> 0 Then Return SetError(1, 0, 0)
	Local $iOff = $iDelta / $__WV2_iPtrSize
	Local $iBlock = Int($iOff / $__WV2_PTRS_PER_BLOCK)
	If $iOff <> $iBlock * $__WV2_PTRS_PER_BLOCK + ($__WV2_PTRS_PER_BLOCK - 1) Then Return SetError(1, 0, 0)
	Local $i = Int($iBlock / $__WV2_SLOT_COUNT) + 1
	Local $j = Mod($iBlock, $__WV2_SLOT_COUNT) + 1
	If $i < 1 Or $i > $__WV2_MAX Or Not $__WV2_aUsed[$i] Then Return SetError(1, 0, 0)
	If $__WV2_pObj[$i][$j] <> $pThis Then Return SetError(1, 0, 0)
	Return SetError(0, $j, $i)
EndFunc   ;==>__WV2_FindInst

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_QI / __WV2_AddRef / __WV2_Release
; Description ...: IUnknown of the fake handler objects. Each object answers for IUnknown and for the
;                  handler interface of its own slot only, and both with the same pointer. AddRef and
;                  Release report counts of their own: these objects live in the UDF heap and are
;                  freed by __WV2_FreeHandlers, never by the runtime.
; ===============================================================================================================================
Func __WV2_QI($pThis, $pRIID, $pPPV)
	__WV2_FindInst($pThis)
	Local $bKnown = Not @Error
	Local $iSlot = @extended
	Local $sIID = __WV2_IIDString($pRIID)
	Local $pOut = 0
	If $bKnown And ($sIID = $WV2_IID_UNKNOWN Or $sIID = $__WV2_aInvIID[$iSlot]) Then $pOut = $pThis
	DllStructSetData(DllStructCreate("ptr", $pPPV), 1, $pOut)
	If $pOut = 0 Then Return $__WV2_HR_E_NOINTERFACE
	Return 0
EndFunc   ;==>__WV2_QI

Func __WV2_AddRef($pThis)
	If $pThis = 0 Then Return 0
	Return 1
EndFunc   ;==>__WV2_AddRef

Func __WV2_Release($pThis)
	If $pThis = 0 Then Return 0
	Return 0
EndFunc   ;==>__WV2_Release

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_VtFn
; Description ...: Address of one entry of the vtable of an interface pointer.
; Remarks .......: Slot 0 is QueryInterface and slot 2 Release, so the first method an interface itself
;                  declares sits at slot 3. Used for the methods no ObjCreateInterface tag carries.
; ===============================================================================================================================
Func __WV2_VtFn($pObj, $iSlot)
	If $pObj = 0 Or $iSlot < 0 Then Return 0
	If $__WV2_iPtrSize = 0 Then $__WV2_iPtrSize = DllStructGetSize(DllStructCreate("ptr"))
	Local $pVTable = DllStructGetData(DllStructCreate("ptr", $pObj), 1)
	If @Error Or $pVTable = 0 Then Return 0
	Local $pFn = DllStructGetData(DllStructCreate("ptr", $pVTable + $iSlot * $__WV2_iPtrSize), 1)
	If @Error Or $pFn = 0 Then Return 0
	Return $pFn
EndFunc   ;==>__WV2_VtFn

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_ReleaseExternal
; Description ...: Calls Release on an interface pointer owned by the operating system.
; Remarks .......: ObjCreateInterface cannot wrap the streams returned by ole32 here: doing so crashed
;                  the process. The vtable is read instead and Release is its third entry.
; ===============================================================================================================================
Func __WV2_ReleaseExternal($pObj)
	If $pObj = 0 Then Return 0
	Local $pFn = __WV2_VtFn($pObj, $__WV2_SLOT_IUnknown_Release)
	If $pFn = 0 Then Return 0
	Local $aRet = DllCallAddress("dword", $pFn, "ptr", $pObj)
	If @Error Or Not IsArray($aRet) Then Return 0
	Return $aRet[0]
EndFunc   ;==>__WV2_ReleaseExternal

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_AddRefExternal
; Description ...: Takes a reference of its own on an interface the runtime lends to a callback.
; Remarks .......: The object handed to an Invoke is borrowed: it lives only as long as the callback,
;                  unless a reference is taken. Every pointer kept past the callback goes through here.
; ===============================================================================================================================
Func __WV2_AddRefExternal($pObj)
	If $pObj = 0 Then Return 0
	Local $pFn = __WV2_VtFn($pObj, 1)
	If $pFn = 0 Then Return 0
	Local $aRet = DllCallAddress("dword", $pFn, "ptr", $pObj)
	If @Error Or Not IsArray($aRet) Then Return 0
	Return $aRet[0]
EndFunc   ;==>__WV2_AddRefExternal

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_QiView / __WV2_ViewIf
; Description ...: Asks the web view of an instance for a newer version of its own interface
;                  (ICoreWebView2_2 up to _28, and _13 for the profile of the theme lot).
;                  __WV2_ViewIf keeps the answer, so every version is
;                  asked for once and released with the view.
; Remarks .......: A wrapper made by ObjCreateInterface cannot be asked for another interface: the call
;                  is made on the raw pointer instead, which is why __WV2_InvCtl keeps it. The pointer
;                  returned by QueryInterface carries a reference of its own.
; ===============================================================================================================================
Func __WV2_QiView($i, $sIID)
	$__WV2_iLastError = $WV2_ERR_NONE
	$__WV2_iLastHR = 0
	If $__WV2_pWv[$i] = 0 Then
		__WV2_SetErr($WV2_ERR_NOT_READY, 0, "__WV2_QiView")
		Return 0
	EndIf
	Return __WV2_QiRaw($__WV2_pWv[$i], $sIID)
EndFunc   ;==>__WV2_QiView

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_QiRaw
; Description ...: Asks any interface pointer for another interface of the same object.
; Return values .: The new pointer, which carries a reference of its own, or 0 with $__WV2_iLastError and
;                  $__WV2_iLastHR set.
; ===============================================================================================================================
Func __WV2_QiRaw($pObj, $sIID)
	Local $pQI = __WV2_VtFn($pObj, $__WV2_SLOT_IUnknown_QueryInterface)
	If $pQI = 0 Then
		__WV2_SetErr($WV2_ERR_COM, 0, "__WV2_VtFn")
		Return 0
	EndIf
	; CLSIDFromString turns the text form of the IID into the sixteen bytes QueryInterface expects.
	; The structure has to stay alive until the call is over, so it lives here.
	Local $tIID = DllStructCreate("byte[16]")
	Local $aCS = DllCall("ole32.dll", "long", "CLSIDFromString", "wstr", $sIID, "ptr", DllStructGetPtr($tIID))
	If @Error Or Not IsArray($aCS) Or $aCS[0] <> 0 Then
		__WV2_SetErr($WV2_ERR_COM, (IsArray($aCS) ? $aCS[0] : 0), "CLSIDFromString")
		Return 0
	EndIf
	Local $tOut = DllStructCreate("ptr")
	Local $aRet = DllCallAddress("long", $pQI, "ptr", $pObj, "ptr", DllStructGetPtr($tIID), _
			"ptr", DllStructGetPtr($tOut))
	If @Error Or Not IsArray($aRet) Then
		__WV2_SetErr($WV2_ERR_COM, 0, "IUnknown::QueryInterface")
		Return 0
	EndIf
	; E_NOINTERFACE only says the installed runtime is older than the method asked for.
	If $aRet[0] <> 0 Then
		__WV2_SetErr($WV2_ERR_CALL, $aRet[0], "QueryInterface " & $sIID)
		Return 0
	EndIf
	Local $pIf = DllStructGetData($tOut, 1)
	If @Error Or $pIf = 0 Then
		__WV2_SetErr($WV2_ERR_COM, 0, "QueryInterface " & $sIID)
		Return 0
	EndIf
	Return $pIf
EndFunc   ;==>__WV2_QiRaw

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_EnvIf
; Description ...: Same for the environment: the two factories of this lot, CreatePrintSettings and
;                  CreateFindOptions, sit on versions of it the script never keeps.
; ===============================================================================================================================
Func __WV2_EnvIf($i, $sIID)
	$__WV2_iLastError = $WV2_ERR_NONE
	$__WV2_iLastHR = 0
	If $__WV2_pEnv[$i] = 0 Then
		__WV2_SetErr($WV2_ERR_NOT_READY, 0, "__WV2_EnvIf")
		Return 0
	EndIf
	Return __WV2_QiRaw($__WV2_pEnv[$i], $sIID)
EndFunc   ;==>__WV2_EnvIf

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_FindObj
; Description ...: The search object of a view, asked for on the first use and kept: get_Find hands out
;                  a pointer that carries a reference of its own, which __WV2_Teardown releases.
; ===============================================================================================================================
Func __WV2_FindObj($i)
	If $__WV2_pFind[$i] <> 0 Then Return $__WV2_pFind[$i]
	Local $p28 = __WV2_ViewIf($i, $__WV2_IF_28)
	If $p28 = 0 Then Return 0
	Local $p = __WV2_GetIface($p28, $__WV2_SLOT_ICoreWebView2_28_get_Find)
	If $p = 0 Then
		__WV2_SetErr($WV2_ERR_CALL, 0, "ICoreWebView2_28::get_Find")
		Return 0
	EndIf
	$__WV2_pFind[$i] = $p
	Return $p
EndFunc   ;==>__WV2_FindObj

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_ProfileObj
; Description ...: The profile of a view, asked for on the first use and kept: get_Profile hands out a
;                  pointer that carries a reference of its own, which __WV2_Teardown releases - the same
;                  arrangement as the search object above, and for the same reason.
; Remarks .......: ICoreWebView2_13 is the version that hands the profile out, so on a runtime older than
;                  that the QueryInterface of __WV2_ViewIf answers E_NOINTERFACE and every function of
;                  the theme lot reports it as $WV2_ERR_CALL rather than pretending the profile is empty.
; ===============================================================================================================================
Func __WV2_ProfileObj($i)
	If $__WV2_pProf[$i] <> 0 Then Return $__WV2_pProf[$i]
	Local $p13 = __WV2_ViewIf($i, $__WV2_IF_13)
	If $p13 = 0 Then Return 0
	Local $p = __WV2_GetIface($p13, $__WV2_SLOT_ICoreWebView2_13_get_Profile)
	If $p = 0 Then
		__WV2_SetErr($WV2_ERR_CALL, 0, "ICoreWebView2_13::get_Profile")
		Return 0
	EndIf
	$__WV2_pProf[$i] = $p
	Return $p
EndFunc   ;==>__WV2_ProfileObj

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_ExtProfile7 / __WV2_ExtList / __WV2_ExtById
; Description ...: The three steps the extension calls are built from. The profile pointer is the one the
;                  theme lot already caches, asked once more for the version that carries the two
;                  extension calls; the list is the object the GetBrowserExtensions handler answers with,
;                  and __WV2_ExtById walks it for the entry whose id matches, keeping the reference of the
;                  item it returns and releasing the rest.
; Remarks .......: A runtime older than the extension API refuses the QueryInterface of Profile7; that is
;                  reported as $WV2_ERR_EXT with the raw HRESULT, the same way the theme lot reports a
;                  profile it cannot reach, rather than answering with an empty list.
; ===============================================================================================================================
Func __WV2_ExtPath($sFolder)
	; The id of an unpacked extension is a hash of the path the browser was handed, and a trailing separator
	; belongs to that path: measured on runtime 157.0.4341.42, one folder answered
	;   ...\ext    -> fkljdihkncapakdkkgkagenkmioefdai
	;   ...\ext\   -> pbbkmllacbgiacdpokpgjclgmmgjhohm
	; so the two routes of this lot, which must agree on one extension, are given one spelling here. The case
	; of the drive letter is folded by the browser itself and needs nothing.
	While StringRight($sFolder, 1) = "\"
		$sFolder = StringTrimRight($sFolder, 1)
	WEnd
	Return $sFolder
EndFunc   ;==>__WV2_ExtPath

Func __WV2_ExtProfile7($iHandle)
	Local $pProf = __WV2_ProfileObj($iHandle)
	If $pProf = 0 Then Return 0
	Local $p7 = __WV2_QiRaw($pProf, $WV2_IID_PROFILE7)
	If $p7 = 0 Then __WV2_SetErr($WV2_ERR_EXT, $__WV2_iLastHR, "ICoreWebView2Profile7")
	Return $p7
EndFunc   ;==>__WV2_ExtProfile7

Func __WV2_ExtList($iHandle, $iTimeoutMs)
	Local $p7 = __WV2_ExtProfile7($iHandle)
	If $p7 = 0 Then Return 0
	Local $pFn = __WV2_VtFn($p7, $__WV2_SLOT_ICoreWebView2Profile7_GetBrowserExtensions)
	If $pFn = 0 Then
		__WV2_ReleaseExternal($p7)
		__WV2_SetErr($WV2_ERR_COM, 0, "__WV2_VtFn")
		Return 0
	EndIf
	__WV2_BeginOp($iHandle, $__WV2_H_EXTGET)
	Local $aCall = DllCallAddress("long", $pFn, "ptr", $p7, "ptr", $__WV2_pObj[$iHandle][$__WV2_H_EXTGET])
	Local $iCallErr = @Error
	__WV2_ReleaseExternal($p7)
	If $iCallErr Or Not IsArray($aCall) Then
		__WV2_SetErr($WV2_ERR_COM, 0, "ICoreWebView2Profile7::GetBrowserExtensions")
		Return 0
	EndIf
	If $aCall[0] <> 0 Then
		__WV2_SetErr($WV2_ERR_EXT, $aCall[0], "ICoreWebView2Profile7::GetBrowserExtensions")
		Return 0
	EndIf
	If Not __WV2_WaitOp($iHandle, $__WV2_H_EXTGET, $iTimeoutMs) Then Return 0
	Local $iDoneHR = $__WV2_iOpHR[$iHandle][$__WV2_H_EXTGET]
	Local $pList = $__WV2_pOpObj[$iHandle][$__WV2_H_EXTGET]
	$__WV2_pOpObj[$iHandle][$__WV2_H_EXTGET] = 0
	If $iDoneHR <> 0 Or $pList = 0 Then
		__WV2_ReleaseExternal($pList)
		__WV2_SetErr($WV2_ERR_EXT, $iDoneHR, "ICoreWebView2ProfileGetBrowserExtensionsCompletedHandler")
		Return 0
	EndIf
	Return $pList
EndFunc   ;==>__WV2_ExtList

Func __WV2_ExtById($iHandle, $sExtId, $iTimeoutMs)
	Local $pList = __WV2_ExtList($iHandle, $iTimeoutMs)
	If $pList = 0 Then Return 0
	Local $iCount = __WV2_IntProp($pList, $__WV2_SLOT_ICoreWebView2BrowserExtensionList_get_Count)
	If $iCount < 0 Then $iCount = 0
	Local $k
	For $k = 0 To $iCount - 1
		Local $pExt = __WV2_GetIfaceAt($pList, $__WV2_SLOT_ICoreWebView2BrowserExtensionList_GetValueAtIndex, $k)
		If $pExt = 0 Then ContinueLoop
		If __WV2_WStrProp($pExt, $__WV2_SLOT_ICoreWebView2BrowserExtension_get_Id) = $sExtId Then
			__WV2_ReleaseExternal($pList)
			Return $pExt
		EndIf
		__WV2_ReleaseExternal($pExt)
	Next
	__WV2_ReleaseExternal($pList)
	__WV2_SetErr($WV2_ERR_ARG, 0, "no extension of the profile carries this id")
	Return 0
EndFunc   ;==>__WV2_ExtById

Func __WV2_FindStep($iHandle, $iSlot, $sFunc)
	$__WV2_sLastFunc = $sFunc
	If Not __WV2_GuardCtl($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	If Not $__WV2_bFindOn[$iHandle] Then
		__WV2_SetErr($WV2_ERR_NOT_READY, 0, $sFunc)
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	EndIf
	Local $pFind = __WV2_FindObj($iHandle)
	If $pFind = 0 Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, 0)
	Return SetError($__WV2_iLastError, $__WV2_iLastHR, __WV2_Result(__WV2_CallNoArg($pFind, $iSlot), "ICoreWebView2Find"))
EndFunc   ;==>__WV2_FindStep

; The index of the active match is -1 once the search is over, so the value cannot be used to tell a
; failure from an answer: the HRESULT is what is looked at here.
Func __WV2_FindNumber($iHandle, $iSlot, $sFunc)
	$__WV2_sLastFunc = $sFunc
	If Not __WV2_GuardCtl($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	Local $pFind = __WV2_FindObj($iHandle)
	If $pFind = 0 Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	Local $pFn = __WV2_VtFn($pFind, $iSlot)
	If $pFn = 0 Then
		__WV2_SetErr($WV2_ERR_CALL, 0, "ICoreWebView2Find")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	EndIf
	Local $tOut = DllStructCreate("long")
	Local $aCall = DllCallAddress("long", $pFn, "ptr", $pFind, "ptr", DllStructGetPtr($tOut))
	If @Error Or Not IsArray($aCall) Then
		__WV2_SetErr($WV2_ERR_CALL, 0, "ICoreWebView2Find")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	EndIf
	If $aCall[0] <> 0 Then
		__WV2_SetErr($WV2_ERR_CALL, $aCall[0], "ICoreWebView2Find")
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	EndIf
	$__WV2_iLastError = $WV2_ERR_NONE
	$__WV2_iLastHR = 0
	Return SetError(0, 0, DllStructGetData($tOut, 1))
EndFunc   ;==>__WV2_FindNumber

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_CookieMgr
; Description ...: The cookie manager of a view. get_CookieManager answers with a reference of its own,
;                  which the caller releases once the call is over.
; ===============================================================================================================================
Func __WV2_CookieMgr($i)
	Local $p2 = __WV2_ViewIf($i, $__WV2_IF_2)
	If $p2 = 0 Then Return 0
	Local $p = __WV2_GetIface($p2, $__WV2_SLOT_ICoreWebView2_2_get_CookieManager)
	If $p = 0 Then __WV2_SetErr($WV2_ERR_CALL, 0, "ICoreWebView2_2::get_CookieManager")
	Return $p
EndFunc   ;==>__WV2_CookieMgr

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_PrintSet
; Description ...: Turns a settings handle into its object pointer, 0 when the handle is unknown.
; Remarks .......: The handle is only a slot number: an object released by _WV2_PrintSettingsDestroy
;                  leaves its slot at 0, so a stale handle answers 0 instead of touching freed memory.
; ===============================================================================================================================
Func __WV2_PrintSet($hSettings)
	If Not IsInt($hSettings) And Not IsNumber($hSettings) Then Return 0
	If $hSettings < 1 Or $hSettings > $WV2_PRINT_SETTINGS_MAX Then Return 0
	Return $__WV2_pPrintSet[$hSettings]
EndFunc   ;==>__WV2_PrintSet

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_StreamBytes
; Description ...: Reads a whole IStream into a Binary through the stream's own vtable.
; Remarks .......: The streams the runtime hands back (PDF, favicon) are not HGLOBAL streams, so
;                  GetHGlobalFromStream would refuse them: the size is found by seeking to the end and
;                  the bytes are read back from the start, chunk by chunk until the stream says it is
;                  empty or the size is reached.
; ===============================================================================================================================
Func __WV2_StreamBytes($pStream)
	If $pStream = 0 Then Return Binary("")
	Local $pSeek = __WV2_VtFn($pStream, $__WV2_SLOT_IStream_Seek)
	Local $pRead = __WV2_VtFn($pStream, $__WV2_SLOT_IStream_Read)
	If $pSeek = 0 Or $pRead = 0 Then Return Binary("")
	Local $aEnd = DllCallAddress("long", $pSeek, "ptr", $pStream, "int64", 0, "dword", $__WV2_SEEK_END, "uint64*", 0)
	If @Error Or Not IsArray($aEnd) Or $aEnd[0] <> 0 Then Return Binary("")
	Local $iSize = Number($aEnd[4])
	If $iSize <= 0 Then Return Binary("")
	Local $aBack = DllCallAddress("long", $pSeek, "ptr", $pStream, "int64", 0, "dword", $__WV2_SEEK_SET, "uint64*", 0)
	If @Error Or Not IsArray($aBack) Or $aBack[0] <> 0 Then Return Binary("")
	Local $bOut = Binary(""), $iGot = 0
	Local $tBuf = DllStructCreate("byte[" & $__WV2_STREAM_CHUNK & "]")
	While $iGot < $iSize
		Local $iWant = $iSize - $iGot
		If $iWant > $__WV2_STREAM_CHUNK Then $iWant = $__WV2_STREAM_CHUNK
		Local $aRead = DllCallAddress("long", $pRead, "ptr", $pStream, "ptr", DllStructGetPtr($tBuf), _
				"dword", $iWant, "dword*", 0)
		If @Error Or Not IsArray($aRead) Or $aRead[0] <> 0 Then Return Binary("")
		Local $iChunk = $aRead[4]
		If $iChunk <= 0 Then ExitLoop
		$bOut = $bOut & BinaryMid(DllStructGetData($tBuf, 1), 1, $iChunk)
		$iGot += $iChunk
	WEnd
	Return $bOut
EndFunc   ;==>__WV2_StreamBytes

Func __WV2_ViewIf($i, $iIf)
	If $__WV2_pWvIf[$i][$iIf] <> 0 Then Return $__WV2_pWvIf[$i][$iIf]
	Local $sIID = ""
	Switch $iIf
		Case $__WV2_IF_2
			$sIID = $WV2_IID_WV2
		Case $__WV2_IF_3
			$sIID = $WV2_IID_WV3
		Case $__WV2_IF_4
			$sIID = $WV2_IID_WV4
		Case $__WV2_IF_7
			$sIID = $WV2_IID_WV7
		Case $__WV2_IF_16
			$sIID = $WV2_IID_WV16
		Case $__WV2_IF_21
			$sIID = $WV2_IID_WV21
		Case $__WV2_IF_28
			$sIID = $WV2_IID_WV28
		Case $__WV2_IF_8
			$sIID = $WV2_IID_WV8
		Case $__WV2_IF_13
			$sIID = $WV2_IID_WV13
		Case Else
			__WV2_SetErr($WV2_ERR_ARG, 0, "__WV2_ViewIf")
			Return 0
	EndSwitch
	$__WV2_pWvIf[$i][$iIf] = __WV2_QiView($i, $sIID)
	Return $__WV2_pWvIf[$i][$iIf]
EndFunc   ;==>__WV2_ViewIf

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_CallNoArg / __WV2_CallBool / __WV2_CallWStr / __WV2_WStrProp
; Description ...: The four shapes a WebView2 method takes when it is called raw through its vtable
;                  entry: nothing, one BOOL, one text, or one text handed back.
; Return values .: The HRESULT of the call, or the text read for __WV2_WStrProp ("" when it failed).
; Remarks .......: A text coming back from the runtime was allocated with CoTaskMemAlloc, so
;                  __WV2_WStrProp copies it and frees it before returning.
; ===============================================================================================================================
Func __WV2_CallNoArg($pObj, $iSlot)
	Local $pFn = __WV2_VtFn($pObj, $iSlot)
	If $pFn = 0 Then Return $__WV2_HR_E_FAIL
	Local $aCall = DllCallAddress("long", $pFn, "ptr", $pObj)
	If @Error Or Not IsArray($aCall) Then Return $__WV2_HR_E_FAIL
	Return $aCall[0]
EndFunc   ;==>__WV2_CallNoArg

Func __WV2_CallBool($pObj, $iSlot, $iValue)
	Local $pFn = __WV2_VtFn($pObj, $iSlot)
	If $pFn = 0 Then Return $__WV2_HR_E_FAIL
	Local $aCall = DllCallAddress("long", $pFn, "ptr", $pObj, "int", $iValue ? 1 : 0)
	If @Error Or Not IsArray($aCall) Then Return $__WV2_HR_E_FAIL
	Return $aCall[0]
EndFunc   ;==>__WV2_CallBool

Func __WV2_CallWStr($pObj, $iSlot, $sText)
	Local $pFn = __WV2_VtFn($pObj, $iSlot)
	If $pFn = 0 Then Return $__WV2_HR_E_FAIL
	Local $aCall = DllCallAddress("long", $pFn, "ptr", $pObj, "wstr", $sText)
	If @Error Or Not IsArray($aCall) Then Return $__WV2_HR_E_FAIL
	Return $aCall[0]
EndFunc   ;==>__WV2_CallWStr

Func __WV2_WStrProp($pObj, $iSlot)
	Local $pFn = __WV2_VtFn($pObj, $iSlot)
	If $pFn = 0 Then Return ""
	Local $tOut = DllStructCreate("ptr")
	Local $aCall = DllCallAddress("long", $pFn, "ptr", $pObj, "ptr", DllStructGetPtr($tOut))
	If @Error Or Not IsArray($aCall) Or $aCall[0] <> 0 Then Return ""
	Local $pStr = DllStructGetData($tOut, 1)
	If $pStr = 0 Then Return ""
	Local $sText = __WV2_CopyWStr($pStr)
	DllCall("ole32.dll", "none", "CoTaskMemFree", "ptr", $pStr)
	Return $sText
EndFunc   ;==>__WV2_WStrProp

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_IntProp / __WV2_BoolProp / __WV2_DblProp / __WV2_GetIface
; Description ...: The other shapes a WebView2 property takes: an integer handed back, a BOOL handed
;                  back, a double handed back, and an interface pointer handed back.
; Return values .: The value read, or -1 (0 for __WV2_GetIface) when the call failed. None of the
;                  numbers read this way can legitimately be negative, so -1 is free to mean "no answer".
; Remarks .......: An interface pointer comes with a reference of its own: the caller releases it with
;                  __WV2_ReleaseExternal once it is done with it.
; ===============================================================================================================================
Func __WV2_IntProp($pObj, $iSlot)
	Local $pFn = __WV2_VtFn($pObj, $iSlot)
	If $pFn = 0 Then Return -1
	Local $tOut = DllStructCreate("long")
	Local $aCall = DllCallAddress("long", $pFn, "ptr", $pObj, "ptr", DllStructGetPtr($tOut))
	If @Error Or Not IsArray($aCall) Or $aCall[0] <> 0 Then Return -1
	Return DllStructGetData($tOut, 1)
EndFunc   ;==>__WV2_IntProp

Func __WV2_BoolProp($pObj, $iSlot)
	Local $iV = __WV2_IntProp($pObj, $iSlot)
	If $iV < 0 Then Return -1
	Return ($iV <> 0 ? 1 : 0)
EndFunc   ;==>__WV2_BoolProp

Func __WV2_DblProp($pObj, $iSlot)
	Local $pFn = __WV2_VtFn($pObj, $iSlot)
	If $pFn = 0 Then Return -1
	Local $tOut = DllStructCreate("double")
	Local $aCall = DllCallAddress("long", $pFn, "ptr", $pObj, "ptr", DllStructGetPtr($tOut))
	If @Error Or Not IsArray($aCall) Or $aCall[0] <> 0 Then Return -1
	Return DllStructGetData($tOut, 1)
EndFunc   ;==>__WV2_DblProp

; A download counts its bytes in an unsigned 64 bit integer: reading it as a long would wrap past
; two gigabytes, so it comes back as an Int64. -1 still means "no answer".
Func __WV2_I64Prop($pObj, $iSlot)
	Local $pFn = __WV2_VtFn($pObj, $iSlot)
	If $pFn = 0 Then Return -1
	Local $tOut = DllStructCreate("int64")
	Local $aCall = DllCallAddress("long", $pFn, "ptr", $pObj, "ptr", DllStructGetPtr($tOut))
	If @Error Or Not IsArray($aCall) Or $aCall[0] <> 0 Then Return -1
	Return DllStructGetData($tOut, 1)
EndFunc   ;==>__WV2_I64Prop

Func __WV2_GetIface($pObj, $iSlot)
	Local $pFn = __WV2_VtFn($pObj, $iSlot)
	If $pFn = 0 Then Return 0
	Local $tOut = DllStructCreate("ptr")
	Local $aCall = DllCallAddress("long", $pFn, "ptr", $pObj, "ptr", DllStructGetPtr($tOut))
	If @Error Or Not IsArray($aCall) Or $aCall[0] <> 0 Then Return 0
	Return DllStructGetData($tOut, 1)
EndFunc   ;==>__WV2_GetIface

Func __WV2_GetIfaceAt($pObj, $iSlot, $iIndex)
	Local $pFn = __WV2_VtFn($pObj, $iSlot)
	If $pFn = 0 Then Return 0
	Local $tOut = DllStructCreate("ptr")
	Local $aCall = DllCallAddress("long", $pFn, "ptr", $pObj, "uint", $iIndex, "ptr", DllStructGetPtr($tOut))
	If @Error Or Not IsArray($aCall) Or $aCall[0] <> 0 Then Return 0
	Return DllStructGetData($tOut, 1)
EndFunc   ;==>__WV2_GetIfaceAt

Func __WV2_CallLong($pObj, $iSlot, $iValue)
	Local $pFn = __WV2_VtFn($pObj, $iSlot)
	If $pFn = 0 Then Return $__WV2_HR_E_FAIL
	Local $aCall = DllCallAddress("long", $pFn, "ptr", $pObj, "long", $iValue)
	If @Error Or Not IsArray($aCall) Then Return $__WV2_HR_E_FAIL
	Return $aCall[0]
EndFunc   ;==>__WV2_CallLong

Func __WV2_CallDbl($pObj, $iSlot, $fValue)
	Local $pFn = __WV2_VtFn($pObj, $iSlot)
	If $pFn = 0 Then Return $__WV2_HR_E_FAIL
	Local $aCall = DllCallAddress("long", $pFn, "ptr", $pObj, "double", $fValue)
	If @Error Or Not IsArray($aCall) Then Return $__WV2_HR_E_FAIL
	Return $aCall[0]
EndFunc   ;==>__WV2_CallDbl

Func __WV2_FileName($sPath)
	Local $aMatch = StringRegExp($sPath, "([^\\/]+)$", 1)
	If @Error Or Not IsArray($aMatch) Then Return $sPath
	Return $aMatch[0]
EndFunc   ;==>__WV2_FileName

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_PutBounds
; Description ...: Sends the bounds to ICoreWebView2Controller::put_Bounds.
;                  The header declares the RECT by value, and on x86 that is what happens: four longs
;                  fit the tag of the wrapper. The 64 bit runtime does not read them that way - it takes
;                  the address of the sixteen bytes - and every other shape of that argument, four longs
;                  or the two halves of the struct, crashes the process. The address is therefore handed
;                  over through the vtable there, which is also the only way to check the outcome: the
;                  bounds read back with get_Bounds are the ones that were sent.
; Return values .: 1 the call succeeded, 0 with $__WV2_iLastError and $__WV2_iLastHR set.
; ===============================================================================================================================
Func __WV2_PutBounds($i, $iLeft, $iTop, $iRight, $iBottom)
	If Not @AutoItX64 Then Return __WV2_Result($__WV2_oCtl[$i].put_Bounds($iLeft, $iTop, $iRight, $iBottom), _
			"ICoreWebView2Controller::put_Bounds")

	Local $pFn = __WV2_VtFn($__WV2_pCtl[$i], $__WV2_SLOT_ICoreWebView2Controller_put_Bounds)
	If $pFn = 0 Then
		__WV2_SetErr($WV2_ERR_COM, 0, "__WV2_VtFn")
		Return 0
	EndIf
	Local $tRc = DllStructCreate("long l; long t; long r; long b")
	DllStructSetData($tRc, "l", $iLeft)
	DllStructSetData($tRc, "t", $iTop)
	DllStructSetData($tRc, "r", $iRight)
	DllStructSetData($tRc, "b", $iBottom)
	Local $aCall = DllCallAddress("long", $pFn, "ptr", $__WV2_pCtl[$i], "ptr", DllStructGetPtr($tRc))
	If @Error Or Not IsArray($aCall) Then
		__WV2_SetErr($WV2_ERR_COM, 0, "ICoreWebView2Controller::put_Bounds")
		Return 0
	EndIf
	Return __WV2_Result($aCall[0], "ICoreWebView2Controller::put_Bounds")
EndFunc   ;==>__WV2_PutBounds

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_BadByte
; Description ...: True when a value cannot be a colour channel: not a number, not a whole one, or
;                  outside 0 to 255.
; ===============================================================================================================================
Func __WV2_BadByte($v)
	If Not IsNumber($v) Then Return True
	If $v <> Int($v) Then Return True
	Return $v < 0 Or $v > 255
EndFunc   ;==>__WV2_BadByte

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_SetColor / __WV2_ReadColor
; Description ...: The two colour slots of ICoreWebView2Controller2, reached through the handle of the
;                  view. The controller is asked for ICoreWebView2Controller2 on every call and released
;                  again on it: unlike the profile, nothing is kept, because the two slots are the only
;                  thing that version has and no view is coloured twice a second.
; Remarks .......: COREWEBVIEW2_COLOR is four bytes - A, R, G and B in that order - and the header
;                  declares the argument of put_ by value. Four bytes are one register, so on both
;                  bitnesses the struct travels as one 32 bit integer whose low byte is the byte the
;                  header lists first; that is what __WV2_PackColor builds. It is deliberately not the
;                  sixteen byte RECT of __WV2_PutBounds, which the 64 bit runtime wants by address: a
;                  struct that fits a register is not a struct that needs memory, and the two calls are
;                  read back here on x86 and x64 before this sentence is trusted.
;                  get_ answers through a pointer into the four bytes, which the runtime writes.
; Return values .: 1 the call succeeded, 0 with $__WV2_iLastError and $__WV2_iLastHR set.
; ===============================================================================================================================
Func __WV2_PackColor($iA, $iR, $iG, $iB)
	Return BitOR($iA, BitShift($iR, -8), BitShift($iG, -16), BitShift($iB, -24))
EndFunc   ;==>__WV2_PackColor

Func __WV2_SetColor($iHandle, $iA, $iR, $iG, $iB)
	Local $pCtl2 = __WV2_QiRaw($__WV2_pCtl[$iHandle], $WV2_IID_CTL2)
	If $pCtl2 = 0 Then Return 0
	Local $pFn = __WV2_VtFn($pCtl2, $__WV2_SLOT_ICoreWebView2Controller2_put_DefaultBackgroundColor)
	If $pFn = 0 Then
		__WV2_SetErr($WV2_ERR_COM, 0, "__WV2_VtFn")
		__WV2_ReleaseExternal($pCtl2)
		Return 0
	EndIf
	Local $aCall = DllCallAddress("long", $pFn, "ptr", $pCtl2, "dword", __WV2_PackColor($iA, $iR, $iG, $iB))
	Local $iErr = @Error
	; Release overwrites @error, so the outcome of the call above is taken out of the way first.
	__WV2_ReleaseExternal($pCtl2)
	If $iErr Or Not IsArray($aCall) Then
		__WV2_SetErr($WV2_ERR_COM, 0, "ICoreWebView2Controller2::put_DefaultBackgroundColor")
		Return 0
	EndIf
	Return __WV2_Result($aCall[0], "ICoreWebView2Controller2::put_DefaultBackgroundColor")
EndFunc   ;==>__WV2_SetColor

Func __WV2_ReadColor($iHandle, ByRef $iA, ByRef $iR, ByRef $iG, ByRef $iB)
	$iA = 0
	$iR = 0
	$iG = 0
	$iB = 0
	Local $pCtl2 = __WV2_QiRaw($__WV2_pCtl[$iHandle], $WV2_IID_CTL2)
	If $pCtl2 = 0 Then Return 0
	Local $pFn = __WV2_VtFn($pCtl2, $__WV2_SLOT_ICoreWebView2Controller2_get_DefaultBackgroundColor)
	If $pFn = 0 Then
		__WV2_SetErr($WV2_ERR_COM, 0, "__WV2_VtFn")
		__WV2_ReleaseExternal($pCtl2)
		Return 0
	EndIf
	; The four bytes are read as the struct they are, in the order the header declares them: no shift,
	; no sign and no bitness to think about.
	Local $tColor = DllStructCreate("byte A; byte R; byte G; byte B")
	Local $aCall = DllCallAddress("long", $pFn, "ptr", $pCtl2, "ptr", DllStructGetPtr($tColor))
	Local $iErr = @Error
	__WV2_ReleaseExternal($pCtl2)
	If $iErr Or Not IsArray($aCall) Then
		__WV2_SetErr($WV2_ERR_COM, 0, "ICoreWebView2Controller2::get_DefaultBackgroundColor")
		Return 0
	EndIf
	If Not __WV2_Result($aCall[0], "ICoreWebView2Controller2::get_DefaultBackgroundColor") Then Return 0
	$iA = DllStructGetData($tColor, "A")
	$iR = DllStructGetData($tColor, "R")
	$iG = DllStructGetData($tColor, "G")
	$iB = DllStructGetData($tColor, "B")
	Return 1
EndFunc   ;==>__WV2_ReadColor

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_InvEnv
; Description ...: ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler::Invoke.
;                  Wraps the borrowed environment pointer, takes ownership of the reference the
;                  callback was handed, and immediately requests a controller.
; ===============================================================================================================================
Func __WV2_InvEnv($pThis, $pHr, $pObj)
	Local $i = __WV2_FindInst($pThis)
	If @Error Then Return 0
	$__WV2_iHR[$i] = Number($pHr)
	If $__WV2_iHR[$i] <> 0 Or $pObj = 0 Then
		$__WV2_bEnvErr[$i] = True
		Return 0
	EndIf
	$__WV2_oEnv[$i] = ObjCreateInterface($pObj, $WV2_IID_ENV, $__WV2_TAG_ENV, False)
	If @Error Or Not IsObj($__WV2_oEnv[$i]) Then
		$__WV2_iHR[$i] = 0
		$__WV2_bEnvErr[$i] = True
		Return 0
	EndIf
	$__WV2_oEnv[$i].AddRef()
	; Kept raw as well: CreateWebResourceResponse hands its response back through an out pointer, which
	; the wrapper tag cannot express, so the call goes through the vtable entry of the header.
	$__WV2_pEnv[$i] = Number($pObj)
	; Put in the table before the controller is asked for: a second view on this folder that starts
	; during the wait below then borrows this environment instead of making another one.
	__WV2_EnvShareNote($i, $__WV2_sUser[$i])
	$__WV2_iHR[$i] = $__WV2_oEnv[$i].CreateCoreWebView2Controller($__WV2_hParent[$i], $__WV2_pObj[$i][$__WV2_H_CTL])
	$__WV2_bEnv[$i] = True
	Return 0
EndFunc   ;==>__WV2_InvEnv

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_InvCtl
; Description ...: ICoreWebView2CreateCoreWebView2ControllerCompletedHandler::Invoke.
;                  Wraps the borrowed controller pointer, takes ownership of its reference and reads
;                  the web view, whose pointer already carries the reference owned by this instance.
; ===============================================================================================================================
Func __WV2_InvCtl($pThis, $pHr, $pObj)
	Local $i = __WV2_FindInst($pThis)
	If @Error Then Return 0
	$__WV2_iHR[$i] = Number($pHr)
	If $__WV2_iHR[$i] <> 0 Or $pObj = 0 Then
		$__WV2_bCtlErr[$i] = True
		Return 0
	EndIf
	$__WV2_oCtl[$i] = ObjCreateInterface($pObj, $WV2_IID_CTL, $__WV2_TAG_CTL, False)
	If @Error Or Not IsObj($__WV2_oCtl[$i]) Then
		$__WV2_iHR[$i] = 0
		$__WV2_bCtlErr[$i] = True
		Return 0
	EndIf
	; Kept raw as well: x64 put_Bounds needs a vtable call, which an ObjCreateInterface wrapper cannot express.
	$__WV2_pCtl[$i] = Number($pObj)
	$__WV2_oCtl[$i].AddRef()
	Local $pWv = 0
	$__WV2_iHR[$i] = $__WV2_oCtl[$i].get_CoreWebView2($pWv)
	If $__WV2_iHR[$i] <> 0 Or $pWv = 0 Then
		$__WV2_bCtlErr[$i] = True
		Return 0
	EndIf
	$__WV2_oWv[$i] = ObjCreateInterface($pWv, $WV2_IID_WV, $__WV2_TAG_WV, False)
	If @Error Or Not IsObj($__WV2_oWv[$i]) Then
		$__WV2_iHR[$i] = 0
		$__WV2_bCtlErr[$i] = True
		Return 0
	EndIf
	; The same pointer, kept raw: a method that only exists on a newer version of the interface is
	; reached by QueryInterface on it, which an ObjCreateInterface wrapper cannot do.
	$__WV2_pWv[$i] = Number($pWv)
	$__WV2_bCtl[$i] = True
	Return 0
EndFunc   ;==>__WV2_InvCtl

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_InvNavC
; Description ...: ICoreWebView2NavigationCompletedEventHandler::Invoke.
;                  Reads the outcome of the navigation from the borrowed arguments pointer, records it
;                  for _WV2_WaitNavigation and queues it for _WV2_GetEvent.
; ===============================================================================================================================
Func __WV2_InvNavC($pThis, $pSender, $pArgs)
	Local $i = __WV2_FindInst($pThis)
	If @Error Or $pSender = 0 Then Return 0 ; $pSender is the web view, already held by the instance
	$__WV2_bNavDone[$i] = True
	$__WV2_bNavOK[$i] = False
	$__WV2_iWebErr[$i] = 0
	Local $sUri = ""
	If $pArgs <> 0 Then
		Local $oArgs = ObjCreateInterface($pArgs, $WV2_IID_NAVARGS, $__WV2_TAG_NAVARGS, False)
		If Not @Error And IsObj($oArgs) Then
			Local $iOK = 0
			If $oArgs.get_IsSuccess($iOK) = 0 Then $__WV2_bNavOK[$i] = ($iOK <> 0)
			If Not $__WV2_bNavOK[$i] Then
				Local $iStatus = 0
				If $oArgs.get_WebErrorStatus($iStatus) = 0 Then $__WV2_iWebErr[$i] = $iStatus
			EndIf
		EndIf
		$oArgs = 0 ; non owning wrapper: the runtime keeps the arguments object alive
	EndIf
	Local $oWv = ObjCreateInterface($pSender, $WV2_IID_WV, $__WV2_TAG_WV, False)
	If Not @Error And IsObj($oWv) Then
		If $oWv.get_Source($sUri) <> 0 Then $sUri = ""
		$oWv = 0
	EndIf
	__WV2_PushEvent($i, $WV2_EVENT_NAVIGATION_COMPLETED, $sUri, $__WV2_bNavOK[$i] ? 1 : $__WV2_iWebErr[$i])
	Return 0
EndFunc   ;==>__WV2_InvNavC

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_InvNavS
; Description ...: ICoreWebView2NavigationStartingEventHandler::Invoke.
;                  Queues the target URI and applies the navigation filter of the instance: a URI that
;                  matches the filter is cancelled through put_Cancel before the callback returns.
; ===============================================================================================================================
Func __WV2_InvNavS($pThis, $pSender, $pArgs)
	#forceref $pSender
	Local $i = __WV2_FindInst($pThis)
	If @Error Then Return 0
	If $pArgs = 0 Then Return 0
	Local $oArgs = ObjCreateInterface($pArgs, $WV2_IID_NAVSARGS, $__WV2_TAG_NAVSARGS, False)
	If @Error Or Not IsObj($oArgs) Then Return 0
	Local $sUri = "", $iUser = 0
	$oArgs.get_Uri($sUri)
	$oArgs.get_IsUserInitiated($iUser)
	__WV2_PushEvent($i, $WV2_EVENT_NAVIGATION_STARTING, $sUri, $iUser <> 0 ? 1 : 0)
	If $__WV2_sNavFilter[$i] <> "" And StringRegExp($sUri, $__WV2_sNavFilter[$i]) Then $oArgs.put_Cancel(1)
	$oArgs = 0
	Return 0
EndFunc   ;==>__WV2_InvNavS

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_InvMsg
; Description ...: ICoreWebView2WebMessageReceivedEventHandler::Invoke.
;                  A page can post either a plain string or a JSON value; the plain form is tried
;                  first and $iValue tells which one was received (1 = string, 0 = JSON).
; ===============================================================================================================================
Func __WV2_InvMsg($pThis, $pSender, $pArgs)
	#forceref $pSender
	Local $i = __WV2_FindInst($pThis)
	If @Error Then Return 0
	If $pArgs = 0 Then Return 0
	Local $oArgs = ObjCreateInterface($pArgs, $WV2_IID_MSGARGS, $__WV2_TAG_MSGARGS, False)
	If @Error Or Not IsObj($oArgs) Then Return 0
	Local $sText = ""
	If $oArgs.TryGetWebMessageAsString($sText) = 0 And $sText <> "" Then
		__WV2_PushEvent($i, $WV2_EVENT_WEB_MESSAGE, $sText, 1)
	Else
		$sText = ""
		$oArgs.get_WebMessageAsJson($sText)
		__WV2_PushEvent($i, $WV2_EVENT_WEB_MESSAGE, $sText, 0)
	EndIf
	$oArgs = 0
	Return 0
EndFunc   ;==>__WV2_InvMsg

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_InvNew
; Description ...: ICoreWebView2NewWindowRequestedEventHandler::Invoke.
;                  The runtime would refuse to create a window it cannot show, so the request is
;                  cancelled here and its URI is queued: the host decides what to do with it.
; ===============================================================================================================================
Func __WV2_InvNew($pThis, $pSender, $pArgs)
	#forceref $pSender
	Local $i = __WV2_FindInst($pThis)
	If @Error Then Return 0
	If $pArgs = 0 Then Return 0
	Local $oArgs = ObjCreateInterface($pArgs, $WV2_IID_NEWARGS, $__WV2_TAG_NEWARGS, False)
	If @Error Or Not IsObj($oArgs) Then Return 0
	Local $sUri = ""
	$oArgs.get_Uri($sUri)
	$oArgs.put_Handled(1)
	__WV2_PushEvent($i, $WV2_EVENT_NEW_WINDOW, $sUri, 0)
	$oArgs = 0
	Return 0
EndFunc   ;==>__WV2_InvNew

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_InvTitle
; Description ...: ICoreWebView2DocumentTitleChangedEventHandler::Invoke.
;                  These callbacks carry no useful arguments object, so the title is read from the
;                  web view itself while the pointer is still alive.
; ===============================================================================================================================
Func __WV2_InvTitle($pThis, $pSender, $pArgs)
	#forceref $pArgs
	Local $i = __WV2_FindInst($pThis)
	If @Error Or $pSender = 0 Then Return 0
	Local $sTitle = ""
	Local $oWv = ObjCreateInterface($pSender, $WV2_IID_WV, $__WV2_TAG_WV, False)
	If Not @Error And IsObj($oWv) Then
		$oWv.get_DocumentTitle($sTitle)
		$oWv = 0
	EndIf
	__WV2_PushEvent($i, $WV2_EVENT_TITLE_CHANGED, $sTitle, 0)
	Return 0
EndFunc   ;==>__WV2_InvTitle

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_InvHist
; Description ...: ICoreWebView2HistoryChangedEventHandler::Invoke.
;                  $iValue is a bit mask: 1 when going back is possible, 2 when going forward is.
; ===============================================================================================================================
Func __WV2_InvHist($pThis, $pSender, $pArgs)
	#forceref $pArgs
	Local $i = __WV2_FindInst($pThis)
	If @Error Or $pSender = 0 Then Return 0
	Local $iValue = 0
	Local $oWv = ObjCreateInterface($pSender, $WV2_IID_WV, $__WV2_TAG_WV, False)
	If Not @Error And IsObj($oWv) Then
		Local $iB = 0, $iF = 0
		If $oWv.get_CanGoBack($iB) = 0 And $iB Then $iValue = 1
		If $oWv.get_CanGoForward($iF) = 0 And $iF Then $iValue = BitOR($iValue, 2)
		$oWv = 0
	EndIf
	__WV2_PushEvent($i, $WV2_EVENT_HISTORY_CHANGED, "", $iValue)
	Return 0
EndFunc   ;==>__WV2_InvHist

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_InvProc
; Description ...: ICoreWebView2ProcessFailedEventHandler::Invoke.
;                  $iValue holds the COREWEBVIEW2_PROCESS_FAILED_KIND value, a $WV2_PROCFAIL_* code.
; ===============================================================================================================================
Func __WV2_InvProc($pThis, $pSender, $pArgs)
	#forceref $pSender
	Local $i = __WV2_FindInst($pThis)
	If @Error Then Return 0
	If $pArgs = 0 Then Return 0
	Local $oArgs = ObjCreateInterface($pArgs, $WV2_IID_PROCARGS, $__WV2_TAG_PROCARGS, False)
	If @Error Or Not IsObj($oArgs) Then Return 0
	Local $iKind = 0
	$oArgs.get_ProcessFailedKind($iKind)
	$oArgs = 0
	__WV2_PushEvent($i, $WV2_EVENT_PROCESS_FAILED, "", $iKind)
	If $iKind = $WV2_PROCFAIL_BROWSER Then
		; Nothing answers after the browser process is gone: report every wait as finished.
		$__WV2_bNavDone[$i] = True
		$__WV2_bNavOK[$i] = False
	EndIf
	Return 0
EndFunc   ;==>__WV2_InvProc

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_InvExec / __WV2_InvAddScript
; Description ...: Invoke of the two handlers carrying a HRESULT and a wide string. The string is
;                  borrowed, so it is copied into the instance before returning.
; ===============================================================================================================================
Func __WV2_InvExec($pThis, $pHr, $pStr)
	Return __WV2_InvString($__WV2_H_EXEC, $pThis, $pHr, $pStr)
EndFunc   ;==>__WV2_InvExec

Func __WV2_InvAddScript($pThis, $pHr, $pStr)
	Return __WV2_InvString($__WV2_H_ADDSCRIPT, $pThis, $pHr, $pStr)
EndFunc   ;==>__WV2_InvAddScript

Func __WV2_InvString($iSlot, $pThis, $pHr, $pStr)
	Local $i = __WV2_FindInst($pThis)
	If @Error Then Return 0
	$__WV2_iOpHR[$i][$iSlot] = Number($pHr)
	$__WV2_sOpOut[$i][$iSlot] = __WV2_CopyWStr($pStr)
	$__WV2_bOpDone[$i][$iSlot] = True
	Return 0
EndFunc   ;==>__WV2_InvString

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_CopyWStr
; Description ...: Copies a UTF-16 string owned by the runtime into an AutoIt string. A pointer
;                  received as a callback argument is only valid while the callback runs, so nothing
;                  here may be deferred.
; ===============================================================================================================================
Func __WV2_CopyWStr($pStr)
	If $pStr = 0 Then Return ""
	Local $aL = DllCall("kernel32.dll", "dword", "lstrlenW", "ptr", $pStr)
	If @Error Or Not IsArray($aL) Or $aL[0] = 0 Then Return ""
	Local $tRaw = DllStructCreate("byte[" & ($aL[0] * 2) & "]", $pStr)
	If @Error Then Return ""
	Return BinaryToString(DllStructGetData($tRaw, 1), 2)
EndFunc   ;==>__WV2_CopyWStr

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_InvCap
; Description ...: ICoreWebView2CapturePreviewCompletedHandler::Invoke. Carries a HRESULT only.
; ===============================================================================================================================
Func __WV2_InvCap($pThis, $pHr)
	Local $i = __WV2_FindInst($pThis)
	If @Error Then Return 0
	$__WV2_iOpHR[$i][$__WV2_H_CAP] = Number($pHr)
	$__WV2_bOpDone[$i][$__WV2_H_CAP] = True
	Return 0
EndFunc   ;==>__WV2_InvCap

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_InvPrint
; Description ...: ICoreWebView2PrintToPdfCompletedHandler::Invoke. Carries a HRESULT and the answer of
;                  the print itself: the call can succeed while the page refuses to produce a file.
; ===============================================================================================================================
Func __WV2_InvPrint($pThis, $iHr, $iResult)
	Local $i = __WV2_FindInst($pThis)
	If @Error Then Return 0
	$__WV2_iOpHR[$i][$__WV2_H_PRINT] = $iHr
	$__WV2_sOpOut[$i][$__WV2_H_PRINT] = ($iResult ? "1" : "0")
	$__WV2_bOpDone[$i][$__WV2_H_PRINT] = True
	Return 0
EndFunc   ;==>__WV2_InvPrint

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_InvDl
; Description ...: ICoreWebView2DownloadStartingEventHandler::Invoke.
;                  Reads the URI of the download from the operation the arguments hand out, then applies
;                  the two rules of the instance: a URI matching the filter is refused through put_Cancel,
;                  any other download keeps the file name chosen by the runtime but is moved into the
;                  folder set with put_ResultFilePath. The outcome goes to the event queue.
; ===============================================================================================================================
Func __WV2_InvDl($pThis, $pSender, $pArgs)
	#forceref $pSender
	Local $i = __WV2_FindInst($pThis)
	If @Error Then Return 0
	If $pArgs = 0 Then Return 0

	; get_DownloadOperation answers with a pointer of its own, so it is read and released here.
	Local $pOp = 0
	Local $tOp = DllStructCreate("ptr")
	Local $pFnOp = __WV2_VtFn($pArgs, $__WV2_SLOT_ICoreWebView2DownloadStartingEventArgs_get_DownloadOperation)
	If $pFnOp <> 0 Then
		Local $aOp = DllCallAddress("long", $pFnOp, "ptr", $pArgs, "ptr", DllStructGetPtr($tOp))
		If (Not @Error) And IsArray($aOp) And $aOp[0] = 0 Then $pOp = DllStructGetData($tOp, 1)
	EndIf
	Local $sUri = ""
	If $pOp <> 0 Then $sUri = __WV2_WStrProp($pOp, $__WV2_SLOT_ICoreWebView2DownloadOperation_get_Uri)

	Local $bRefused = ($__WV2_sDlFilter[$i] <> "" And StringRegExp($sUri, $__WV2_sDlFilter[$i]))
	If $bRefused Then
		__WV2_CallBool($pArgs, $__WV2_SLOT_ICoreWebView2DownloadStartingEventArgs_put_Cancel, 1)
	ElseIf $__WV2_sDlFolder[$i] <> "" Then
		; ResultFilePath already holds the full path the runtime picked, file name included: the folder
		; of that path is replaced and nothing else.
		Local $sPath = __WV2_WStrProp($pArgs, $__WV2_SLOT_ICoreWebView2DownloadStartingEventArgs_get_ResultFilePath)
		If $sPath <> "" Then __WV2_CallWStr($pArgs, $__WV2_SLOT_ICoreWebView2DownloadStartingEventArgs_put_ResultFilePath, $__WV2_sDlFolder[$i] & "\" & __WV2_FileName($sPath))
	EndIf
	; An accepted download stays reachable through _WV2_GetDownload, pause, resume and cancel; the
	; reference read above is handed over instead of being released.
	Local $bKept = False
	If $pOp <> 0 And Not $bRefused Then $bKept = __WV2_DlRemember($i, $pOp)
	If $pOp <> 0 And Not $bKept Then __WV2_ReleaseExternal($pOp)

	__WV2_PushEvent($i, $WV2_EVENT_DOWNLOAD_STARTING, $sUri, $bRefused ? 1 : 0)
	Return 0
EndFunc   ;==>__WV2_InvDl

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_InvRes
; Description ...: ICoreWebView2WebResourceRequestedEventHandler::Invoke.
;                  Reads the URI, the method and the headers of the request, hands them to the function
;                  named by _WV2_SetResourceHandler and turns what it returns into the answer the page
;                  receives: nothing (the network decides), a response built here, or a failure.
; Remarks .......: Every pointer the runtime lends is read and released before the script runs, so the
;                  handler never holds a COM object it could outlive. The instance is marked busy for
;                  the duration of the call, which is what __WV2_Guard checks.
; ===============================================================================================================================
Func __WV2_InvRes($pThis, $pSender, $pArgs)
	#forceref $pSender
	Local $i = __WV2_FindInst($pThis)
	If @Error Then Return 0
	If $pArgs = 0 Or $__WV2_sResFunc[$i] = "" Then Return 0

	Local $sUri = "", $sMethod = "", $sHeaders = ""
	Local $tReq = DllStructCreate("ptr")
	Local $pFnReq = __WV2_VtFn($pArgs, $__WV2_SLOT_ICoreWebView2WebResourceRequestedEventArgs_get_Request)
	If $pFnReq <> 0 Then
		Local $aReq = DllCallAddress("long", $pFnReq, "ptr", $pArgs, "ptr", DllStructGetPtr($tReq))
		If (Not @Error) And IsArray($aReq) And $aReq[0] = 0 Then
			Local $pReq = DllStructGetData($tReq, 1)
			If $pReq <> 0 Then
				$sUri = __WV2_WStrProp($pReq, $__WV2_SLOT_ICoreWebView2WebResourceRequest_get_Uri)
				$sMethod = __WV2_WStrProp($pReq, $__WV2_SLOT_ICoreWebView2WebResourceRequest_get_Method)
				$sHeaders = __WV2_RequestHeaders($pReq)
				__WV2_ReleaseExternal($pReq)
			EndIf
		EndIf
	EndIf
	If $sUri = "" Then
		__WV2_PushEvent($i, $WV2_EVENT_RESOURCE_REQUESTED, "", 2)
		Return 0
	EndIf

	$__WV2_bInRes[$i] = True
	Local $vAnswer = Call($__WV2_sResFunc[$i], $i, $sUri, $sMethod, $sHeaders)
	Local $iCallErr = @Error
	$__WV2_bInRes[$i] = False

	; A function that could not be called and an answer that is not an array both leave the request to
	; the network; only a well formed answer takes it out of the hands of the runtime.
	If $iCallErr = 0 And IsArray($vAnswer) Then
		__WV2_PushEvent($i, $WV2_EVENT_RESOURCE_REQUESTED, $sUri, (__WV2_Respond($i, $pArgs, $vAnswer) ? 1 : 2))
	Else
		__WV2_PushEvent($i, $WV2_EVENT_RESOURCE_REQUESTED, $sUri, ($iCallErr = 0 ? 0 : 2))
	EndIf
	Return 0
EndFunc   ;==>__WV2_InvRes

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_DlRemember / __WV2_DlForget / __WV2_DlIndex
; Description ...: Keeps an accepted download operation reachable by index, with the two events that
;                  report its progress when they were asked for.
; Remarks .......: Eight operations are kept. When a ninth starts, the oldest one loses its slot and
;                  its reference: a finished download nobody asked about any more is worthless, while
;                  the numbers of the others stay what they were.
; ===============================================================================================================================
Func __WV2_DlRemember($i, $pOp)
	Local $j, $iFree = 0, $iOld = 1
	For $j = 1 To $WV2_DL_MAX
		If $__WV2_pDl[$i][$j] = 0 Then
			$iFree = $j
			ExitLoop
		EndIf
		If $__WV2_iDlSeq[$i][$j] < $__WV2_iDlSeq[$i][$iOld] Then $iOld = $j
	Next
	If $iFree = 0 Then
		$iFree = $iOld
		__WV2_DlForget($i, $iFree)
	EndIf
	$__WV2_iDlNext[$i] += 1
	$__WV2_iDlSeq[$i][$iFree] = $__WV2_iDlNext[$i]
	$__WV2_pDl[$i][$iFree] = $pOp
	$__WV2_iDlCount[$i] += 1
	If $__WV2_bDlWatch[$i] Then __WV2_DlSubscribe($i, $iFree)
	Return True
EndFunc   ;==>__WV2_DlRemember

Func __WV2_DlUnsubscribe($i, $j)
	Local $pOp = $__WV2_pDl[$i][$j]
	If $pOp = 0 Then Return
	If $__WV2_iDlStateTok[$i][$j] <> 0 Then
		DllCallAddress("long", __WV2_VtFn($pOp, $__WV2_SLOT_ICoreWebView2DownloadOperation_remove_StateChanged), _
				"ptr", $pOp, "int64", $__WV2_iDlStateTok[$i][$j])
		$__WV2_iDlStateTok[$i][$j] = 0
	EndIf
	If $__WV2_iDlProgTok[$i][$j] <> 0 Then
		DllCallAddress("long", __WV2_VtFn($pOp, $__WV2_SLOT_ICoreWebView2DownloadOperation_remove_BytesReceivedChanged), _
				"ptr", $pOp, "int64", $__WV2_iDlProgTok[$i][$j])
		$__WV2_iDlProgTok[$i][$j] = 0
	EndIf
EndFunc   ;==>__WV2_DlUnsubscribe

Func __WV2_DlForget($i, $j)
	Local $pOp = $__WV2_pDl[$i][$j]
	If $pOp = 0 Then Return
	__WV2_DlUnsubscribe($i, $j)
	__WV2_ReleaseExternal($pOp)
	$__WV2_pDl[$i][$j] = 0
	$__WV2_iDlSeq[$i][$j] = 0
	$__WV2_iDlCount[$i] -= 1
EndFunc   ;==>__WV2_DlForget

Func __WV2_DlSubscribe($i, $j)
	Local $pOp = $__WV2_pDl[$i][$j]
	If $pOp = 0 Then Return
	Local $tState = DllStructCreate("int64"), $tProg = DllStructCreate("int64")
	Local $pF1 = __WV2_VtFn($pOp, $__WV2_SLOT_ICoreWebView2DownloadOperation_add_StateChanged)
	If $pF1 <> 0 Then
		Local $a1 = DllCallAddress("long", $pF1, "ptr", $pOp, "ptr", $__WV2_pObj[$i][$__WV2_H_DLSTATE], "ptr", DllStructGetPtr($tState))
		If (Not @Error) And IsArray($a1) And $a1[0] = 0 Then $__WV2_iDlStateTok[$i][$j] = DllStructGetData($tState, 1)
	EndIf
	Local $pF2 = __WV2_VtFn($pOp, $__WV2_SLOT_ICoreWebView2DownloadOperation_add_BytesReceivedChanged)
	If $pF2 <> 0 Then
		Local $a2 = DllCallAddress("long", $pF2, "ptr", $pOp, "ptr", $__WV2_pObj[$i][$__WV2_H_DLPROG], "ptr", DllStructGetPtr($tProg))
		If (Not @Error) And IsArray($a2) And $a2[0] = 0 Then $__WV2_iDlProgTok[$i][$j] = DllStructGetData($tProg, 1)
	EndIf
EndFunc   ;==>__WV2_DlSubscribe

Func __WV2_DlIndex($i, $pOp)
	Local $j
	For $j = 1 To $WV2_DL_MAX
		If $__WV2_pDl[$i][$j] = $pOp And $pOp <> 0 Then Return $j
	Next
	Return 0
EndFunc   ;==>__WV2_DlIndex

; The operation behind a download index, 0 when that index holds nothing.
Func __WV2_DlAt($i, $iIndex)
	If Not IsNumber($iIndex) Then Return 0
	If $iIndex < 1 Or $iIndex > $WV2_DL_MAX Then Return 0
	Return $__WV2_pDl[$i][$iIndex]
EndFunc   ;==>__WV2_DlAt

Func __WV2_DlAction($iHandle, $iIndex, $iSlot, $sMethod)
	If Not __WV2_Guard($iHandle) Then Return False
	Local $pOp = __WV2_DlAt($iHandle, $iIndex)
	If $pOp = 0 Then
		__WV2_SetErr($WV2_ERR_ARG, 0, "_WV2_Download" & $sMethod)
		Return False
	EndIf
	Return __WV2_Result(__WV2_CallNoArg($pOp, $iSlot), "ICoreWebView2DownloadOperation::" & $sMethod)
EndFunc   ;==>__WV2_DlAction

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_InvFindIdx / __WV2_InvFindCnt / __WV2_InvFindStart
; Description ...: The three callbacks of ICoreWebView2Find. The two events queue what they read from
;                  the search object; the completion of Start only marks the operation done.
; ===============================================================================================================================
Func __WV2_InvFindIdx($pThis, $pSender, $pArgs)
	#forceref $pArgs
	Local $i = __WV2_FindInst($pThis)
	If @Error Then Return 0
	Local $iCount = __WV2_IntProp($pSender, $__WV2_SLOT_ICoreWebView2Find_get_MatchCount)
	Local $iActive = __WV2_IntProp($pSender, $__WV2_SLOT_ICoreWebView2Find_get_ActiveMatchIndex)
	__WV2_PushEvent($i, $WV2_EVENT_FIND, $iCount < 0 ? "" : $iCount, $iActive)
	Return 0
EndFunc   ;==>__WV2_InvFindIdx

Func __WV2_InvFindCnt($pThis, $pSender, $pArgs)
	#forceref $pArgs
	Local $i = __WV2_FindInst($pThis)
	If @Error Then Return 0
	Local $iCount = __WV2_IntProp($pSender, $__WV2_SLOT_ICoreWebView2Find_get_MatchCount)
	Local $iActive = __WV2_IntProp($pSender, $__WV2_SLOT_ICoreWebView2Find_get_ActiveMatchIndex)
	__WV2_PushEvent($i, $WV2_EVENT_FIND, $iCount < 0 ? "" : $iCount, $iActive)
	Return 0
EndFunc   ;==>__WV2_InvFindCnt

Func __WV2_InvFindStart($pThis, $hr)
	Local $i = __WV2_FindInst($pThis)
	If @Error Then Return 0
	$__WV2_iOpHR[$i][$__WV2_H_FINDSTART] = $hr
	$__WV2_bOpDone[$i][$__WV2_H_FINDSTART] = True
	Return 0
EndFunc   ;==>__WV2_InvFindStart

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_InvExecRes / __WV2_InvCookies / __WV2_InvPdfStream / __WV2_InvFavGet
; Description ...: The four asynchronous operations that answer with a COM object instead of a text.
;                  The pointer is stored in $__WV2_pOpObj, whose reference the caller then owns.
; ===============================================================================================================================
Func __WV2_InvExecRes($pThis, $hr, $pObj)
	Local $i = __WV2_FindInst($pThis)
	If @Error Then Return 0
	$__WV2_iOpHR[$i][$__WV2_H_EXECRES] = $hr
	__WV2_AddRefExternal($pObj)
	$__WV2_pOpObj[$i][$__WV2_H_EXECRES] = $pObj
	$__WV2_bOpDone[$i][$__WV2_H_EXECRES] = True
	Return 0
EndFunc   ;==>__WV2_InvExecRes

Func __WV2_InvCookies($pThis, $hr, $pObj)
	Local $i = __WV2_FindInst($pThis)
	If @Error Then Return 0
	$__WV2_iOpHR[$i][$__WV2_H_COOKIES] = $hr
	__WV2_AddRefExternal($pObj)
	$__WV2_pOpObj[$i][$__WV2_H_COOKIES] = $pObj
	$__WV2_bOpDone[$i][$__WV2_H_COOKIES] = True
	Return 0
EndFunc   ;==>__WV2_InvCookies

Func __WV2_InvPdfStream($pThis, $hr, $pObj)
	Local $i = __WV2_FindInst($pThis)
	If @Error Then Return 0
	$__WV2_iOpHR[$i][$__WV2_H_PDFSTREAM] = $hr
	__WV2_AddRefExternal($pObj)
	$__WV2_pOpObj[$i][$__WV2_H_PDFSTREAM] = $pObj
	$__WV2_bOpDone[$i][$__WV2_H_PDFSTREAM] = True
	Return 0
EndFunc   ;==>__WV2_InvPdfStream

Func __WV2_InvFavGet($pThis, $hr, $pObj)
	Local $i = __WV2_FindInst($pThis)
	If @Error Then Return 0
	$__WV2_iOpHR[$i][$__WV2_H_FAVICONGET] = $hr
	__WV2_AddRefExternal($pObj)
	$__WV2_pOpObj[$i][$__WV2_H_FAVICONGET] = $pObj
	$__WV2_bOpDone[$i][$__WV2_H_FAVICONGET] = True
	Return 0
EndFunc   ;==>__WV2_InvFavGet

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_InvProfile
; Description ...: ICoreWebView2Profile2::ClearBrowsingData completion: nothing to read, only the HRESULT.
; ===============================================================================================================================
Func __WV2_InvProfile($pThis, $hr)
	Local $i = __WV2_FindInst($pThis)
	If @Error Then Return 0
	$__WV2_iOpHR[$i][$__WV2_H_PROFILE] = $hr
	$__WV2_bOpDone[$i][$__WV2_H_PROFILE] = True
	Return 0
EndFunc   ;==>__WV2_InvProfile

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_InvExtAdd / __WV2_InvExtGet / __WV2_InvExtRemove / __WV2_InvExtEnable
; Description ...: The four completions of the extensions lot. Add and Get answer with a COM object - the
;                  extension that was just added, and the list the profile holds - so, like the cookie
;                  handler, they keep the borrowed reference in $__WV2_pOpObj: the public function reads
;                  the object and releases it. Remove and Enable have nothing to read but the HRESULT.
; ===============================================================================================================================
Func __WV2_InvExtAdd($pThis, $hr, $pObj)
	Local $i = __WV2_FindInst($pThis)
	If @Error Then Return 0
	$__WV2_iOpHR[$i][$__WV2_H_EXTADD] = $hr
	__WV2_AddRefExternal($pObj)
	$__WV2_pOpObj[$i][$__WV2_H_EXTADD] = $pObj
	$__WV2_bOpDone[$i][$__WV2_H_EXTADD] = True
	Return 0
EndFunc   ;==>__WV2_InvExtAdd

Func __WV2_InvExtGet($pThis, $hr, $pObj)
	Local $i = __WV2_FindInst($pThis)
	If @Error Then Return 0
	$__WV2_iOpHR[$i][$__WV2_H_EXTGET] = $hr
	__WV2_AddRefExternal($pObj)
	$__WV2_pOpObj[$i][$__WV2_H_EXTGET] = $pObj
	$__WV2_bOpDone[$i][$__WV2_H_EXTGET] = True
	Return 0
EndFunc   ;==>__WV2_InvExtGet

Func __WV2_InvExtRemove($pThis, $hr)
	Local $i = __WV2_FindInst($pThis)
	If @Error Then Return 0
	$__WV2_iOpHR[$i][$__WV2_H_EXTREMOVE] = $hr
	$__WV2_bOpDone[$i][$__WV2_H_EXTREMOVE] = True
	Return 0
EndFunc   ;==>__WV2_InvExtRemove

Func __WV2_InvExtEnable($pThis, $hr)
	Local $i = __WV2_FindInst($pThis)
	If @Error Then Return 0
	$__WV2_iOpHR[$i][$__WV2_H_EXTENABLE] = $hr
	$__WV2_bOpDone[$i][$__WV2_H_EXTENABLE] = True
	Return 0
EndFunc   ;==>__WV2_InvExtEnable

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_InvDlState / __WV2_InvDlProg
; Description ...: The two events of a remembered download. The operation is found back by its address,
;                  which is also its index in the list of the view.
; ===============================================================================================================================
Func __WV2_InvDlState($pThis, $pSender, $pArgs)
	#forceref $pArgs
	Local $i = __WV2_FindInst($pThis)
	If @Error Then Return 0
	Local $j = __WV2_DlIndex($i, $pSender)
	If $j = 0 Then Return 0
	Local $iState = __WV2_IntProp($pSender, $__WV2_SLOT_ICoreWebView2DownloadOperation_get_State)
	Local $sUri = __WV2_WStrProp($pSender, $__WV2_SLOT_ICoreWebView2DownloadOperation_get_Uri)
	__WV2_PushEvent($i, $WV2_EVENT_DOWNLOAD_STATE, $sUri, ($iState < 0 ? $WV2_DL_INTERRUPTED : $iState))
	Return 0
EndFunc   ;==>__WV2_InvDlState

Func __WV2_InvDlProg($pThis, $pSender, $pArgs)
	#forceref $pArgs
	Local $i = __WV2_FindInst($pThis)
	If @Error Then Return 0
	Local $j = __WV2_DlIndex($i, $pSender)
	If $j = 0 Then Return 0
	Local $iGot = __WV2_IntProp($pSender, $__WV2_SLOT_ICoreWebView2DownloadOperation_get_BytesReceived)
	Local $iTotal = __WV2_IntProp($pSender, $__WV2_SLOT_ICoreWebView2DownloadOperation_get_TotalBytesToReceive)
	__WV2_PushEvent($i, $WV2_EVENT_DOWNLOAD_PROGRESS, String($iGot) & "/" & String($iTotal), $j)
	Return 0
EndFunc   ;==>__WV2_InvDlProg

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_InvDialog
; Description ...: ICoreWebView2ScriptDialogOpeningEventHandler::Invoke. Hands the dialog to the
;                  function named by _WV2_SetDialogHandler and turns its answer into Accept or a
;                  dismissal: nothing else than calling Accept takes the dialog out of the hands of the
;                  runtime, which would otherwise put its own box in front of the page.
; Remarks .......: The page waits, so the handler runs while the runtime is inside its own callback:
;                  the instance is marked busy for the duration, which is what __WV2_Guard checks.
; ===============================================================================================================================
Func __WV2_InvDialog($pThis, $pSender, $pArgs)
	#forceref $pSender
	Local $i = __WV2_FindInst($pThis)
	If @Error Then Return 0
	If $pArgs = 0 Or $__WV2_sDlgFunc[$i] = "" Then Return 0

	Local $iKind = __WV2_IntProp($pArgs, $__WV2_SLOT_ICoreWebView2ScriptDialogOpeningEventArgs_get_Kind)
	Local $sMsg = __WV2_WStrProp($pArgs, $__WV2_SLOT_ICoreWebView2ScriptDialogOpeningEventArgs_get_Message)
	Local $sDefault = __WV2_WStrProp($pArgs, $__WV2_SLOT_ICoreWebView2ScriptDialogOpeningEventArgs_get_DefaultText)
	Local $sUri = __WV2_WStrProp($pArgs, $__WV2_SLOT_ICoreWebView2ScriptDialogOpeningEventArgs_get_Uri)

	$__WV2_bInCb[$i] = True
	Local $vAnswer = Call($__WV2_sDlgFunc[$i], $i, $iKind, $sMsg, $sDefault, $sUri)
	Local $iCallErr = @Error
	$__WV2_bInCb[$i] = False

	Local $bAccepted = False
	If $iCallErr = 0 Then
		If IsString($vAnswer) Then
			; A prompt answered with a string: the text goes back to the page, then the dialog is accepted.
			__WV2_CallWStr($pArgs, $__WV2_SLOT_ICoreWebView2ScriptDialogOpeningEventArgs_put_ResultText, $vAnswer)
			$bAccepted = (__WV2_CallNoArg($pArgs, $__WV2_SLOT_ICoreWebView2ScriptDialogOpeningEventArgs_Accept) = 0)
		ElseIf IsNumber($vAnswer) Or IsBool($vAnswer) Then
			If $vAnswer Then $bAccepted = (__WV2_CallNoArg($pArgs, $__WV2_SLOT_ICoreWebView2ScriptDialogOpeningEventArgs_Accept) = 0)
		EndIf
	EndIf
	__WV2_PushEvent($i, $WV2_EVENT_SCRIPT_DIALOG, $sMsg, ($bAccepted ? $iKind : $iKind + 16))
	Return 0
EndFunc   ;==>__WV2_InvDialog

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_InvAccel
; Description ...: ICoreWebView2AcceleratorKeyPressedEventHandler::Invoke. The function named by
;                  _WV2_SetAcceleratorHandler decides whether the page sees the key at all.
; ===============================================================================================================================
Func __WV2_InvAccel($pThis, $pSender, $pArgs)
	#forceref $pSender
	Local $i = __WV2_FindInst($pThis)
	If @Error Then Return 0
	If $pArgs = 0 Or $__WV2_sAccelFunc[$i] = "" Then Return 0
	Local $iKind = __WV2_IntProp($pArgs, $__WV2_SLOT_ICoreWebView2AcceleratorKeyPressedEventArgs_get_KeyEventKind)
	Local $iKey = __WV2_IntProp($pArgs, $__WV2_SLOT_ICoreWebView2AcceleratorKeyPressedEventArgs_get_VirtualKey)

	$__WV2_bInCb[$i] = True
	Local $vAnswer = Call($__WV2_sAccelFunc[$i], $i, $iKey, $iKind)
	Local $bHandled = (@Error = 0 And ($vAnswer = True Or (IsNumber($vAnswer) And $vAnswer <> 0)))
	$__WV2_bInCb[$i] = False

	If $bHandled Then __WV2_CallBool($pArgs, $__WV2_SLOT_ICoreWebView2AcceleratorKeyPressedEventArgs_put_Handled, 1)
	__WV2_PushEvent($i, $WV2_EVENT_ACCELERATOR, $iKey, $iKind)
	Return 0
EndFunc   ;==>__WV2_InvAccel

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_InvCtxMenu
; Description ...: ICoreWebView2ContextMenuRequestedEventHandler::Invoke. Reads the menu the runtime is
;                  about to show as an array, hands it to the function named by
;                  _WV2_SetContextMenuHandler, and applies the command id it answers with.
; ===============================================================================================================================
Func __WV2_InvCtxMenu($pThis, $pSender, $pArgs)
	#forceref $pSender
	Local $i = __WV2_FindInst($pThis)
	If @Error Then Return 0
	If $pArgs = 0 Or $__WV2_sCtxFunc[$i] = "" Then Return 0

	; get_Location answers with a POINT, two longs, filled in place.
	Local $iX = 0, $iY = 0
	Local $pFnLoc = __WV2_VtFn($pArgs, $__WV2_SLOT_ICoreWebView2ContextMenuRequestedEventArgs_get_Location)
	If $pFnLoc <> 0 Then
		Local $tLoc = DllStructCreate("long x;long y")
		Local $aLoc = DllCallAddress("long", $pFnLoc, "ptr", $pArgs, "ptr", DllStructGetPtr($tLoc))
		If (Not @Error) And IsArray($aLoc) And $aLoc[0] = 0 Then
			$iX = DllStructGetData($tLoc, "x")
			$iY = DllStructGetData($tLoc, "y")
		EndIf
	EndIf

	Local $aItems[1][5]
	$aItems[0][0] = 0
	Local $pColl = __WV2_GetIface($pArgs, $__WV2_SLOT_ICoreWebView2ContextMenuRequestedEventArgs_get_MenuItems)
	If $pColl <> 0 Then
		Local $iCount = __WV2_IntProp($pColl, $__WV2_SLOT_ICoreWebView2ContextMenuItemCollection_get_Count)
		If $iCount > 0 Then
			ReDim $aItems[$iCount + 1][5]
			$aItems[0][0] = $iCount
			Local $k
			For $k = 1 To $iCount
				Local $pItem = __WV2_GetIfaceAt($pColl, $__WV2_SLOT_ICoreWebView2ContextMenuItemCollection_GetValueAtIndex, $k - 1)
				If $pItem <> 0 Then
					$aItems[$k][0] = __WV2_WStrProp($pItem, $__WV2_SLOT_ICoreWebView2ContextMenuItem_get_Label)
					$aItems[$k][1] = __WV2_IntProp($pItem, $__WV2_SLOT_ICoreWebView2ContextMenuItem_get_CommandId)
					$aItems[$k][2] = __WV2_IntProp($pItem, $__WV2_SLOT_ICoreWebView2ContextMenuItem_get_Kind)
					$aItems[$k][3] = __WV2_BoolProp($pItem, $__WV2_SLOT_ICoreWebView2ContextMenuItem_get_IsEnabled)
					$aItems[$k][4] = __WV2_BoolProp($pItem, $__WV2_SLOT_ICoreWebView2ContextMenuItem_get_IsChecked)
					__WV2_ReleaseExternal($pItem)
				EndIf
			Next
		EndIf
		__WV2_ReleaseExternal($pColl)
	EndIf

	$__WV2_bInCb[$i] = True
	Local $vAnswer = Call($__WV2_sCtxFunc[$i], $i, $aItems, $iX, $iY)
	Local $iCallErr = @Error
	$__WV2_bInCb[$i] = False

	Local $iCmd = -1
	If $iCallErr = 0 And (IsNumber($vAnswer) Or IsString($vAnswer)) Then $iCmd = Int($vAnswer)
	If $iCmd >= 0 Then
		; Selecting a command and saying it was handled are two calls: without the second the runtime
		; still shows its own menu.
		If __WV2_CallLong($pArgs, $__WV2_SLOT_ICoreWebView2ContextMenuRequestedEventArgs_put_SelectedCommandId, $iCmd) = 0 Then _
				__WV2_CallBool($pArgs, $__WV2_SLOT_ICoreWebView2ContextMenuRequestedEventArgs_put_Handled, 1)
	EndIf
	__WV2_PushEvent($i, $WV2_EVENT_CONTEXT_MENU, "", $iCmd)
	Return 0
EndFunc   ;==>__WV2_InvCtxMenu

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_InvFavChanged / __WV2_InvCdpCall / __WV2_InvCdpEvt
; Description ...: The favicon change of the view, the completion of a DevTools call and the payload of
;                  a DevTools event.
; ===============================================================================================================================
Func __WV2_InvFavChanged($pThis, $pSender, $pArgs)
	#forceref $pArgs
	Local $i = __WV2_FindInst($pThis)
	If @Error Then Return 0
	Local $sUri = __WV2_WStrProp($pSender, $__WV2_SLOT_ICoreWebView2_15_get_FaviconUri)
	__WV2_PushEvent($i, $WV2_EVENT_FAVICON_CHANGED, $sUri, 0)
	Return 0
EndFunc   ;==>__WV2_InvFavChanged

Func __WV2_InvCdpCall($pThis, $hr, $pStr)
	Local $i = __WV2_FindInst($pThis)
	If @Error Then Return 0
	$__WV2_iOpHR[$i][$__WV2_H_CDPCALL] = $hr
	; The second argument is declared wstr, so AutoIt hands the text over already decoded. Comparing it
	; with 0 as the object answers do would read "{" as the number 0 and lose every answer.
	$__WV2_sOpOut[$i][$__WV2_H_CDPCALL] = String($pStr)
	$__WV2_bOpDone[$i][$__WV2_H_CDPCALL] = True
	Return 0
EndFunc   ;==>__WV2_InvCdpCall

Func __WV2_InvCdpEvt($pThis, $pSender, $pArgs)
	#forceref $pSender
	Local $i = __WV2_FindInst($pThis)
	If @Error Then Return 0
	If $pArgs = 0 Or $__WV2_sCdpEvent[$i] = "" Then Return 0
	Local $sJson = __WV2_WStrProp($pArgs, $__WV2_SLOT_ICoreWebView2DevToolsProtocolEventReceivedEventArgs_get_ParameterObjectAsJson)
	__WV2_PushEvent($i, $WV2_EVENT_DEVTOOLS, $sJson, 0)
	Return 0
EndFunc   ;==>__WV2_InvCdpEvt

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_InvAudio / __WV2_InvMuted
; Description ...: The two answers of ICoreWebView2_8. Neither carries an arguments object - the
;                  signature is Invoke(ICoreWebView2 *sender, IUnknown *args) with args always NULL -
;                  so the state that changed is read back off the sender, and the number goes into the
;                  queue as $iValue: 1 or 0 for $WV2_EVENT_PLAYING_AUDIO_CHANGED and $WV2_EVENT_MUTED_CHANGED.
; Remarks .......: The sender is asked for ICoreWebView2_8 before its vtable is touched: a slot number
;                  is only meaningful on an interface known to carry that many methods, and reading
;                  slot 87 of a pointer that stopped at 48 would run arbitrary code instead of failing.
;                  The QueryInterface cannot realistically fail here (the event was subscribed through
;                  _8, on this very object), but the cached _8 pointer of the view answers if it does.
; ===============================================================================================================================
Func __WV2_InvAudio($pThis, $pSender, $pArgs)
	#forceref $pArgs
	Local $i = __WV2_FindInst($pThis)
	If @Error Then Return 0
	Local $iPlaying = __WV2_AudioState($pSender, $i, $__WV2_SLOT_ICoreWebView2_8_get_IsDocumentPlayingAudio)
	__WV2_PushEvent($i, $WV2_EVENT_PLAYING_AUDIO_CHANGED, "", $iPlaying)
	Return 0
EndFunc   ;==>__WV2_InvAudio

Func __WV2_InvMuted($pThis, $pSender, $pArgs)
	#forceref $pArgs
	Local $i = __WV2_FindInst($pThis)
	If @Error Then Return 0
	Local $iMuted = __WV2_AudioState($pSender, $i, $__WV2_SLOT_ICoreWebView2_8_get_IsMuted)
	__WV2_PushEvent($i, $WV2_EVENT_MUTED_CHANGED, "", $iMuted)
	Return 0
EndFunc   ;==>__WV2_InvMuted

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_InvFullscreen
; Description ...: The answer of ICoreWebView2ContainsFullScreenElementChangedEventHandler. Like the
;                  two audio handlers it carries no arguments object - Invoke(ICoreWebView2 *sender,
;                  IUnknown *args), args always NULL - so the new state is read back off the sender
;                  and queued as $iValue: 1 or 0 for $WV2_EVENT_FULLSCREEN_CHANGED.
; Remarks .......: Slot 54 is get_ContainsFullScreenElement on the base interface, which every version
;                  of ICoreWebView2 repeats at the same absolute position, so the pointer the runtime
;                  hands back is read directly: no QueryInterface is needed here, unlike the _8 slots.
;                  The sender can still be NULL; the view pointer of the instance answers then.
; ===============================================================================================================================
Func __WV2_InvFullscreen($pThis, $pSender, $pArgs)
	#forceref $pArgs
	Local $i = __WV2_FindInst($pThis)
	If @Error Then Return 0
	Local $pWv = $pSender
	If $pWv = 0 Then $pWv = $__WV2_pWv[$i]
	If $pWv = 0 Then Return 0
	Local $iFull = __WV2_BoolProp($pWv, $__WV2_SLOT_ICoreWebView2_get_ContainsFullScreenElement)
	__WV2_PushEvent($i, $WV2_EVENT_FULLSCREEN_CHANGED, "", $iFull)
	Return 0
EndFunc   ;==>__WV2_InvFullscreen

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_AudioState
; Description ...: Reads one BOOL of ICoreWebView2_8, preferring the sender the runtime handed to the
;                  handler and falling back to the pointer the view already keeps.
; Return values .: 1 or 0, -1 when neither answer could be read.
; ===============================================================================================================================
Func __WV2_AudioState($pSender, $i, $iSlot)
	Local $p8 = 0
	Local $bOwned = False
	If $pSender <> 0 Then
		$p8 = __WV2_QiRaw($pSender, $WV2_IID_WV8)
		$bOwned = ($p8 <> 0)
	EndIf
	If $p8 = 0 Then $p8 = $__WV2_pWvIf[$i][$__WV2_IF_8]
	If $p8 = 0 Then Return -1
	Local $iValue = __WV2_BoolProp($p8, $iSlot)
	If $bOwned Then __WV2_ReleaseExternal($p8)
	Return $iValue
EndFunc   ;==>__WV2_AudioState

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_SenderSource
; Description ...: The uri the view is at, read off the sender pointer a handler was handed and falling
;                  back to the pointer the instance keeps when the runtime handed nothing.
; Remarks .......: Slot 4 is get_Source on the base layout, which every version of ICoreWebView2
;                  repeats at the same absolute position, so the sender is read directly: no
;                  QueryInterface, whatever the real version of the pointer is.
; ===============================================================================================================================
Func __WV2_SenderSource($pSender, $i)
	Local $pWv = $pSender
	If $pWv = 0 Then $pWv = $__WV2_pWv[$i]
	If $pWv = 0 Then Return ""
	Return __WV2_WStrProp($pWv, $__WV2_SLOT_ICoreWebView2_get_Source)
EndFunc   ;==>__WV2_SenderSource

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_InvCntLoad / __WV2_InvSrcChg / __WV2_InvDomContent / __WV2_InvWinClose
; Description ...: The four handlers of the life cycle of a document. Each queues what its arguments
;                  object reports, and none of them decides anything on the host's behalf.
;                  ContentLoading  - the runtime has committed to a document and its content is about
;                                    to replace what is on screen. $iValue = 1 when that content is one
;                                    of the runtime's own error pages, 0 when it is the document.
;                  SourceChanged   - the uri of the view moved. $iValue = 1 for a new document, 0 when
;                                    the same document only moved inside itself (a fragment, a push
;                                    state): the difference a host needs to decide whether to reload
;                                    its own state.
;                  DOMContentLoaded- the document is parsed and its script has run, but the subresources
;                                    may still be loading. $iValue = the navigation id, the number the
;                                    NavigationCompleted of the same navigation is filed under.
;                  WindowCloseRequested - the page called window.close(). Nothing is closed here: an
;                                    AutoIt window belongs to the script, not to the view, and a page
;                                    that could close the window that shows it would close a window the
;                                    host never agreed to open.
; Remarks .......: The three arguments objects are borrowed for the length of the callback, as every
;                  WebView2 handler's are, so everything worth keeping is read before the function
;                  returns. A BOOL that could not be read is queued as 0 and an unread navigation id as
;                  0: neither number can legitimately be negative, so the host never sees a value that
;                  looks like a real one. WindowCloseRequested carries no arguments object at all - the
;                  header types its second parameter as IUnknown *args and the runtime passes NULL.
; ===============================================================================================================================
Func __WV2_InvCntLoad($pThis, $pSender, $pArgs)
	Local $i = __WV2_FindInst($pThis)
	If @Error Then Return 0
	Local $iErr = ($pArgs <> 0 ? __WV2_BoolProp($pArgs, $__WV2_SLOT_ICoreWebView2ContentLoadingEventArgs_get_IsErrorPage) : -1)
	__WV2_PushEvent($i, $WV2_EVENT_CONTENT_LOADING, __WV2_SenderSource($pSender, $i), ($iErr > 0 ? 1 : 0))
	Return 0
EndFunc   ;==>__WV2_InvCntLoad

Func __WV2_InvSrcChg($pThis, $pSender, $pArgs)
	Local $i = __WV2_FindInst($pThis)
	If @Error Then Return 0
	Local $iNew = ($pArgs <> 0 ? __WV2_BoolProp($pArgs, $__WV2_SLOT_ICoreWebView2SourceChangedEventArgs_get_IsNewDocument) : -1)
	__WV2_PushEvent($i, $WV2_EVENT_SOURCE_CHANGED, __WV2_SenderSource($pSender, $i), ($iNew > 0 ? 1 : 0))
	Return 0
EndFunc   ;==>__WV2_InvSrcChg

Func __WV2_InvDomContent($pThis, $pSender, $pArgs)
	Local $i = __WV2_FindInst($pThis)
	If @Error Then Return 0
	Local $iNav = ($pArgs <> 0 ? __WV2_I64Prop($pArgs, $__WV2_SLOT_ICoreWebView2DOMContentLoadedEventArgs_get_NavigationId) : -1)
	If $iNav < 0 Then $iNav = 0
	__WV2_PushEvent($i, $WV2_EVENT_DOM_CONTENT_LOADED, __WV2_SenderSource($pSender, $i), $iNav)
	Return 0
EndFunc   ;==>__WV2_InvDomContent

Func __WV2_InvWinClose($pThis, $pSender, $pArgs)
	#forceref $pArgs
	Local $i = __WV2_FindInst($pThis)
	If @Error Then Return 0
	__WV2_PushEvent($i, $WV2_EVENT_WINDOW_CLOSE, __WV2_SenderSource($pSender, $i), 0)
	Return 0
EndFunc   ;==>__WV2_InvWinClose

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_InvPermission
; Description ...: ICoreWebView2PermissionRequestedEventHandler::Invoke. Reads which origin asks for
;                  which kind, applies the policy given by _WV2_SetPermissionPolicy and queues the
;                  request as $sData = origin, $iValue = a $WV2_PERM_* kind.
;                  $WV2_PERM_ALLOW and $WV2_PERM_DENY are answered here and now with put_State.
;                  $WV2_PERM_ASK takes a deferral instead, which keeps the request open until
;                  _WV2_PermissionRespond answers it from the queue. $WV2_PERM_DEFAULT touches nothing.
; Remarks .......: The answer has to be written while the handler runs, or a deferral has to be taken
;                  before it returns: after that the runtime has already decided. A WebView2 shows no
;                  prompt of its own - the application is the prompt - so a request nobody answered is
;                  left to the runtime, which documents it as not granted. That is why the policy is set
;                  before the page asks, not after the event is read.
; ===============================================================================================================================
Func __WV2_InvPermission($pThis, $pSender, $pArgs)
	#forceref $pSender
	Local $i = __WV2_FindInst($pThis)
	If @Error Then Return 0
	If $pArgs = 0 Then Return 0
	Local $sUri = __WV2_WStrProp($pArgs, $__WV2_SLOT_ICoreWebView2PermissionRequestedEventArgs_get_Uri)
	Local $iKind = __WV2_IntProp($pArgs, $__WV2_SLOT_ICoreWebView2PermissionRequestedEventArgs_get_PermissionKind)
	If $iKind < 0 Or $iKind > $__WV2_PERM_KIND_MAX Then $iKind = $WV2_PERM_UNKNOWN
	Local $iPol = $__WV2_iPermPol[$i][$iKind]
	If $iPol = $WV2_PERM_ALLOW Or $iPol = $WV2_PERM_DENY Then
		__WV2_CallLong($pArgs, $__WV2_SLOT_ICoreWebView2PermissionRequestedEventArgs_put_State, $iPol)
	ElseIf $iPol = $WV2_PERM_ASK Then
		; A request that cannot be held - no deferral, or a full table that refused to give one up - is
		; left to the runtime rather than answered blindly on the host's behalf.
		__WV2_PermHold($i, $pArgs, $sUri, $iKind)
	EndIf
	__WV2_PushEvent($i, $WV2_EVENT_PERMISSION_REQUESTED, $sUri, $iKind)
	Return 0
EndFunc   ;==>__WV2_InvPermission

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_PermHold / __WV2_PermForget / __WV2_PermSlot / __WV2_PermWait
; Description ...: The eight requests a view may keep waiting at one time. Hold takes the deferral the
;                  arguments offer, keeps a reference on both interfaces and records what was already
;                  read, because nothing of the arguments can be trusted once this callback has returned.
;                  Forget closes the deferral and lets the two references go.
; Remarks .......: A ninth request takes the slot of the oldest one, which ends unanswered - the same
;                  bargain the download table strikes, and the only one that keeps a page from stalling
;                  forever when the host stops reading its queue. $iIndex used by the public functions
;                  is the rank among the waiting requests, oldest first, so an answer given in the order
;                  the events were read is always right.
; ===============================================================================================================================
Func __WV2_PermHold($i, $pArgs, $sUri, $iKind)
	Local $tDef = DllStructCreate("ptr")
	Local $pFn = __WV2_VtFn($pArgs, $__WV2_SLOT_ICoreWebView2PermissionRequestedEventArgs_GetDeferral)
	If $pFn = 0 Then Return False
	Local $aDef = DllCallAddress("long", $pFn, "ptr", $pArgs, "ptr", DllStructGetPtr($tDef))
	If @Error Or Not IsArray($aDef) Or $aDef[0] <> 0 Then Return False
	Local $pDef = DllStructGetData($tDef, 1)
	If $pDef = 0 Then Return False
	If __WV2_AddRefExternal($pArgs) = 0 Then
		__WV2_ReleaseExternal($pDef)
		Return False
	EndIf
	Local $j, $iFree = 0, $iOld = 1
	For $j = 1 To $WV2_PERM_MAX
		If $__WV2_pPermArgs[$i][$j] = 0 Then
			$iFree = $j
			ExitLoop
		EndIf
		If $__WV2_iPermSeq[$i][$j] < $__WV2_iPermSeq[$i][$iOld] Then $iOld = $j
	Next
	If $iFree = 0 Then
		$iFree = $iOld
		__WV2_PermForget($i, $iFree)
	EndIf
	$__WV2_iPermNext[$i] += 1
	$__WV2_iPermSeq[$i][$iFree] = $__WV2_iPermNext[$i]
	$__WV2_pPermArgs[$i][$iFree] = $pArgs
	$__WV2_pPermDef[$i][$iFree] = $pDef
	$__WV2_sPermUri[$i][$iFree] = $sUri
	$__WV2_iPermKind[$i][$iFree] = $iKind
	Return True
EndFunc   ;==>__WV2_PermHold

Func __WV2_PermForget($i, $j)
	If $__WV2_pPermArgs[$i][$j] = 0 Then Return
	; The deferral is closed before the references go: a request left open on an object that is about to
	; die is the one thing the runtime cannot forget.
	Local $pDef = $__WV2_pPermDef[$i][$j]
	If $pDef <> 0 Then
		Local $pFn = __WV2_VtFn($pDef, $__WV2_SLOT_ICoreWebView2Deferral_Complete)
		If $pFn <> 0 Then DllCallAddress("long", $pFn, "ptr", $pDef)
		__WV2_ReleaseExternal($pDef)
	EndIf
	__WV2_ReleaseExternal($__WV2_pPermArgs[$i][$j])
	$__WV2_pPermArgs[$i][$j] = 0
	$__WV2_pPermDef[$i][$j] = 0
	$__WV2_sPermUri[$i][$j] = ""
	$__WV2_iPermKind[$i][$j] = 0
	$__WV2_iPermSeq[$i][$j] = 0
EndFunc   ;==>__WV2_PermForget

; How many requests wait, and which slot holds the one asked for by rank. A rank of 1 is the oldest.
Func __WV2_PermWait($i)
	Local $j, $iCount = 0
	For $j = 1 To $WV2_PERM_MAX
		If $__WV2_pPermArgs[$i][$j] <> 0 Then $iCount += 1
	Next
	Return $iCount
EndFunc   ;==>__WV2_PermWait

Func __WV2_PermSlot($i, $iOrdinal)
	If $iOrdinal < 1 Then Return 0
	Local $j, $k, $iRank
	For $j = 1 To $WV2_PERM_MAX
		If $__WV2_pPermArgs[$i][$j] = 0 Then ContinueLoop
		$iRank = 1
		For $k = 1 To $WV2_PERM_MAX
			If $k = $j Or $__WV2_pPermArgs[$i][$k] = 0 Then ContinueLoop
			If $__WV2_iPermSeq[$i][$k] < $__WV2_iPermSeq[$i][$j] Then $iRank += 1
		Next
		If $iRank = $iOrdinal Then Return $j
	Next
	Return 0
EndFunc   ;==>__WV2_PermSlot

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_RequestHeaders / __WV2_HeadersText
; Description ...: Reads the headers of a request as "Name: value" lines separated by @CRLF, the way
;                  they are written in the text of an HTTP request. The iterator hands one header at a
;                  time, in the order the runtime keeps them.
; Remarks .......: Both strings of a header come from CoTaskMemAlloc and are freed here; the iterator
;                  carries a reference of its own and is released when the walk is over.
; ===============================================================================================================================
Func __WV2_RequestHeaders($pReq)
	Local $tOut = DllStructCreate("ptr")
	Local $pFn = __WV2_VtFn($pReq, $__WV2_SLOT_ICoreWebView2WebResourceRequest_get_Headers)
	If $pFn = 0 Then Return ""
	Local $aCall = DllCallAddress("long", $pFn, "ptr", $pReq, "ptr", DllStructGetPtr($tOut))
	If @Error Or Not IsArray($aCall) Or $aCall[0] <> 0 Then Return ""
	Local $pHdrs = DllStructGetData($tOut, 1)
	If $pHdrs = 0 Then Return ""
	Local $sText = __WV2_HeadersText($pHdrs)
	__WV2_ReleaseExternal($pHdrs)
	Return $sText
EndFunc   ;==>__WV2_RequestHeaders

Func __WV2_HeadersText($pHdrs)
	Local $tOut = DllStructCreate("ptr")
	Local $pFn = __WV2_VtFn($pHdrs, $__WV2_SLOT_ICoreWebView2HttpRequestHeaders_GetIterator)
	If $pFn = 0 Then Return ""
	Local $aCall = DllCallAddress("long", $pFn, "ptr", $pHdrs, "ptr", DllStructGetPtr($tOut))
	If @Error Or Not IsArray($aCall) Or $aCall[0] <> 0 Then Return ""
	Local $pIt = DllStructGetData($tOut, 1)
	If $pIt = 0 Then Return ""

	Local $pFnHas = __WV2_VtFn($pIt, $__WV2_SLOT_ICoreWebView2HttpHeadersCollectionIterator_get_HasCurrentHeader)
	Local $pFnCur = __WV2_VtFn($pIt, $__WV2_SLOT_ICoreWebView2HttpHeadersCollectionIterator_GetCurrentHeader)
	Local $pFnNext = __WV2_VtFn($pIt, $__WV2_SLOT_ICoreWebView2HttpHeadersCollectionIterator_MoveNext)
	If $pFnHas = 0 Or $pFnCur = 0 Or $pFnNext = 0 Then
		__WV2_ReleaseExternal($pIt)
		Return ""
	EndIf

	Local $tHas = DllStructCreate("int")
	Local $tName = DllStructCreate("ptr")
	Local $tValue = DllStructCreate("ptr")
	Local $sOut = ""
	Local $bHas = __WV2_IteratorHas($pFnHas, $pIt, $tHas)
	While $bHas
		Local $aCur = DllCallAddress("long", $pFnCur, "ptr", $pIt, "ptr", DllStructGetPtr($tName), _
				"ptr", DllStructGetPtr($tValue))
		If (Not @Error) And IsArray($aCur) And $aCur[0] = 0 Then
			Local $pName = DllStructGetData($tName, 1)
			Local $pValue = DllStructGetData($tValue, 1)
			$sOut &= __WV2_CopyWStr($pName) & ": " & __WV2_CopyWStr($pValue) & @CRLF
			If $pName <> 0 Then DllCall("ole32.dll", "none", "CoTaskMemFree", "ptr", $pName)
			If $pValue <> 0 Then DllCall("ole32.dll", "none", "CoTaskMemFree", "ptr", $pValue)
		EndIf
		$bHas = __WV2_IteratorHas($pFnNext, $pIt, $tHas)
	WEnd
	__WV2_ReleaseExternal($pIt)
	Return $sOut
EndFunc   ;==>__WV2_HeadersText

Func __WV2_IteratorHas($pFn, $pIt, $tHas)
	Local $aCall = DllCallAddress("long", $pFn, "ptr", $pIt, "ptr", DllStructGetPtr($tHas))
	If @Error Or Not IsArray($aCall) Or $aCall[0] <> 0 Then Return False
	Return DllStructGetData($tHas, 1) <> 0
EndFunc   ;==>__WV2_IteratorHas

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_Respond
; Description ...: Turns the array returned by a resource handler into an
;                  ICoreWebView2WebResourceResponse and gives it to the arguments of the event.
; Parameters ....: $i - Instance, $pArgs - the event arguments, $vAnswer - the array of the handler:
;                  [status, reason, headers, body] with the body optional.
; Return values .: True when the browser took the response, False when the array was not usable or the
;                  runtime refused it; in both cases the request is then left to the network.
; ===============================================================================================================================
Func __WV2_Respond($i, $pArgs, $vAnswer)
	If UBound($vAnswer, 0) <> 1 Or UBound($vAnswer) < 3 Then Return False
	Local $iStatus = Int($vAnswer[0])
	If $iStatus < 100 Or $iStatus > 999 Then Return False
	Local $sReason = String($vAnswer[1])
	; A line break in the reason would be read as the end of the status line by the parser of the page.
	If StringInStr($sReason, @CR) Or StringInStr($sReason, @LF) Then Return False
	Local $sHeaders = String($vAnswer[2])
	Local $vBody = (UBound($vAnswer) > 3 ? $vAnswer[3] : "")
	Local $binBody = (IsBinary($vBody) ? $vBody : StringToBinary(String($vBody), 4))

	; A NULL stream is how the runtime is told there is no body at all.
	Local $pStream = __WV2_StreamFromBytes($binBody)
	Local $pFnResp = __WV2_VtFn($__WV2_pEnv[$i], $__WV2_SLOT_ICoreWebView2Environment_CreateWebResourceResponse)
	If $pFnResp = 0 Then
		If $pStream <> 0 Then __WV2_ReleaseExternal($pStream)
		Return False
	EndIf
	Local $tResp = DllStructCreate("ptr")
	Local $aResp = DllCallAddress("long", $pFnResp, "ptr", $__WV2_pEnv[$i], "ptr", $pStream, "int", $iStatus, _
			"wstr", $sReason, "wstr", $sHeaders, "ptr", DllStructGetPtr($tResp))
	; The response keeps its own reference to the stream, so ours goes as soon as the call is over.
	If $pStream <> 0 Then __WV2_ReleaseExternal($pStream)
	If @Error Or Not IsArray($aResp) Or $aResp[0] <> 0 Then Return False
	Local $pResp = DllStructGetData($tResp, 1)
	If $pResp = 0 Then Return False

	Local $pFn = __WV2_VtFn($pArgs, $__WV2_SLOT_ICoreWebView2WebResourceRequestedEventArgs_put_Response)
	If $pFn = 0 Then
		__WV2_ReleaseExternal($pResp)
		Return False
	EndIf
	Local $aCall = DllCallAddress("long", $pFn, "ptr", $pArgs, "ptr", $pResp)
	__WV2_ReleaseExternal($pResp)
	If @Error Or Not IsArray($aCall) Then Return False
	Return $aCall[0] = 0
EndFunc   ;==>__WV2_Respond

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_StreamFromBytes
; Description ...: Wraps a block of bytes in an IStream, the shape CreateWebResourceResponse wants for
;                  the body of a response.
; Return values .: The pointer of the stream, or 0 for an empty body (or when the block could not be
;                  allocated, in which case the request is left to the network).
; Remarks .......: The block is a moveable global memory block handed to CreateStreamOnHGlobal with
;                  fDeleteOnRelease = TRUE: releasing the stream frees it, so nothing has to be freed
;                  here, and a response the runtime drops mid-flight leaks nothing.
; ===============================================================================================================================
Func __WV2_StreamFromBytes($binBody)
	Local $iSize = BinaryLen($binBody)
	If $iSize = 0 Then Return 0
	; GMEM_MOVEABLE (0x0002) | GMEM_ZEROINIT (0x0040)
	Local $aMem = DllCall("kernel32.dll", "handle", "GlobalAlloc", "uint", 0x42, "ulong_ptr", $iSize)
	If @Error Or Not IsArray($aMem) Or $aMem[0] = 0 Then Return 0
	Local $pMem = DllCall("kernel32.dll", "ptr", "GlobalLock", "handle", $aMem[0])
	If @Error Or Not IsArray($pMem) Or $pMem[0] = 0 Then
		DllCall("kernel32.dll", "ptr", "GlobalFree", "handle", $aMem[0])
		Return 0
	EndIf
	Local $tBuf = DllStructCreate("byte[" & $iSize & "]", $pMem[0])
	DllStructSetData($tBuf, 1, $binBody)
	DllCall("kernel32.dll", "bool", "GlobalUnlock", "handle", $aMem[0])

	Local $tStream = DllStructCreate("ptr")
	Local $aCS = DllCall("ole32.dll", "long", "CreateStreamOnHGlobal", "handle", $aMem[0], "bool", True, _
			"ptr", DllStructGetPtr($tStream))
	If @Error Or Not IsArray($aCS) Then
		DllCall("kernel32.dll", "ptr", "GlobalFree", "handle", $aMem[0])
		Return 0
	EndIf
	If $aCS[0] <> 0 Then
		DllCall("kernel32.dll", "ptr", "GlobalFree", "handle", $aMem[0])
		Return 0
	EndIf
	Return DllStructGetData($tStream, 1)
EndFunc   ;==>__WV2_StreamFromBytes

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_Filter
; Description ...: Adds or removes one filter of the resource interception, after checking the pattern
;                  and the context once for the three public functions that reach it.
; ===============================================================================================================================
Func __WV2_Filter($i, $sPattern, $iContext, $bAdd)
	If Not IsString($sPattern) Or StringStripWS($sPattern, 3) = "" Then
		__WV2_SetErr($WV2_ERR_ARG, 0, "__WV2_Filter")
		Return False
	EndIf
	If Not IsNumber($iContext) Or $iContext < $WV2_RES_ALL Or $iContext > $WV2_RES_OTHER Then
		__WV2_SetErr($WV2_ERR_ARG, 0, "__WV2_Filter")
		Return False
	EndIf
	Local $iSlot = ($bAdd ? $__WV2_SLOT_ICoreWebView2_AddWebResourceRequestedFilter _
			: $__WV2_SLOT_ICoreWebView2_RemoveWebResourceRequestedFilter)
	Local $pFn = __WV2_VtFn($__WV2_pWv[$i], $iSlot)
	If $pFn = 0 Then
		__WV2_SetErr($WV2_ERR_COM, 0, "__WV2_Filter")
		Return False
	EndIf
	Local $aCall = DllCallAddress("long", $pFn, "ptr", $__WV2_pWv[$i], "wstr", $sPattern, "int", $iContext)
	If @Error Or Not IsArray($aCall) Then
		__WV2_SetErr($WV2_ERR_COM, 0, "ICoreWebView2::AddWebResourceRequestedFilter")
		Return False
	EndIf
	Return __WV2_Result($aCall[0], "ICoreWebView2::" & ($bAdd ? "Add" : "Remove") & "WebResourceRequestedFilter")
EndFunc   ;==>__WV2_Filter

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_PushEvent / __WV2_PopEvent / __WV2_PopEventOfType
; Description ...: Ring buffer of the events received by an instance. The buffer never blocks a
;                  callback: when it is full the oldest event is dropped and the drop counter
;                  returned through @extended by _WV2_GetEvent grows.
; ===============================================================================================================================
Func __WV2_PushEvent($i, $iType, $sData, $iValue)
	Local $iPos
	If $__WV2_iEvtCount[$i] < $__WV2_QCAP Then
		$iPos = Mod($__WV2_iEvtHead[$i] + $__WV2_iEvtCount[$i], $__WV2_QCAP)
		$__WV2_iEvtCount[$i] += 1
	Else
		$__WV2_iEvtDrop[$i] += 1
		$__WV2_iEvtHead[$i] = Mod($__WV2_iEvtHead[$i] + 1, $__WV2_QCAP)
		$iPos = Mod($__WV2_iEvtHead[$i] + $__WV2_QCAP - 1, $__WV2_QCAP)
	EndIf
	$__WV2_aEvtType[$i][$iPos] = $iType
	$__WV2_aEvtStr[$i][$iPos] = String($sData)
	$__WV2_aEvtNum[$i][$iPos] = Number($iValue)
EndFunc   ;==>__WV2_PushEvent

Func __WV2_PopEvent($i, ByRef $iType, ByRef $sData, ByRef $iValue)
	If $__WV2_iEvtCount[$i] = 0 Then Return False
	If $__WV2_iEvtCbCount[$i] = 0 Then
		; The usual case, and the one every script of the earlier builds lived in: nothing owns a
		; kind here, so the oldest entry is the host's and the head is taken as it always was.
		$iType = $__WV2_aEvtType[$i][$__WV2_iEvtHead[$i]]
		$sData = $__WV2_aEvtStr[$i][$__WV2_iEvtHead[$i]]
		$iValue = $__WV2_aEvtNum[$i][$__WV2_iEvtHead[$i]]
		$__WV2_aEvtStr[$i][$__WV2_iEvtHead[$i]] = ""
		$__WV2_iEvtHead[$i] = Mod($__WV2_iEvtHead[$i] + 1, $__WV2_QCAP)
		$__WV2_iEvtCount[$i] -= 1
		Return True
	EndIf
	; With a handler installed the two readers meet in one queue and the rule is ownership: an event
	; of a kind that has a name belongs to that name and is not what a by-hand read is owed. The
	; search stops at the first entry still the host's, which keeps the order of what is left.
	Local $k, $iT
	For $k = 0 To $__WV2_iEvtCount[$i] - 1
		$iT = $__WV2_aEvtType[$i][Mod($__WV2_iEvtHead[$i] + $k, $__WV2_QCAP)]
		If $__WV2_aEvtCb[$i][$iT] = "" Then
			$iType = $iT
			Return __WV2_PopEventOfType($i, $iT, $sData, $iValue)
		EndIf
	Next
	Return False
EndFunc   ;==>__WV2_PopEvent

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_PopEventOfType
; Description ...: Takes the oldest event of one type out of the queue and leaves the others in it.
; Remarks .......: The entries that were queued before the one taken move one slot back, so reading
;                  the queue afterwards still gives them in the order they arrived.
; ===============================================================================================================================
Func __WV2_PopEventOfType($i, $iWant, ByRef $sData, ByRef $iValue)
	Local $k, $iCount = $__WV2_iEvtCount[$i]
	Local $iOff = -1
	For $k = 0 To $iCount - 1
		If $__WV2_aEvtType[$i][Mod($__WV2_iEvtHead[$i] + $k, $__WV2_QCAP)] = $iWant Then
			$iOff = $k
			ExitLoop
		EndIf
	Next
	If $iOff < 0 Then Return False
	Local $iPos = Mod($__WV2_iEvtHead[$i] + $iOff, $__WV2_QCAP)
	$sData = $__WV2_aEvtStr[$i][$iPos]
	$iValue = $__WV2_aEvtNum[$i][$iPos]
	For $k = $iOff To 1 Step -1
		Local $iTo = Mod($__WV2_iEvtHead[$i] + $k, $__WV2_QCAP)
		Local $iFrom = Mod($__WV2_iEvtHead[$i] + $k - 1, $__WV2_QCAP)
		$__WV2_aEvtType[$i][$iTo] = $__WV2_aEvtType[$i][$iFrom]
		$__WV2_aEvtStr[$i][$iTo] = $__WV2_aEvtStr[$i][$iFrom]
		$__WV2_aEvtNum[$i][$iTo] = $__WV2_aEvtNum[$i][$iFrom]
	Next
	$__WV2_aEvtStr[$i][$__WV2_iEvtHead[$i]] = ""
	$__WV2_iEvtHead[$i] = Mod($__WV2_iEvtHead[$i] + 1, $__WV2_QCAP)
	$__WV2_iEvtCount[$i] = $iCount - 1
	Return True
EndFunc   ;==>__WV2_PopEventOfType

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_UnshiftEvent
; Description ...: Puts one event back at the head of the queue, where the pop took it from.
; Remarks .......: A name that is not a function of the script has to cost the host nothing, so the
;                  event it could not deliver keeps its place and stays readable by hand. The queue is
;                  a ring, so this is four writes, not a shift of everything behind it. A full queue
;                  cannot take it back: the push that filled it already counted a drop, and a second
;                  count invented here would move the number away from what really went missing.
; ===============================================================================================================================
Func __WV2_UnshiftEvent($i, $iType, $sData, $iValue)
	If $__WV2_iEvtCount[$i] >= $__WV2_QCAP Then Return False
	$__WV2_iEvtHead[$i] = Mod($__WV2_iEvtHead[$i] - 1 + $__WV2_QCAP, $__WV2_QCAP)
	$__WV2_iEvtCount[$i] += 1
	Local $iPos = $__WV2_iEvtHead[$i]
	$__WV2_aEvtType[$i][$iPos] = $iType
	$__WV2_aEvtStr[$i][$iPos] = String($sData)
	$__WV2_aEvtNum[$i][$iPos] = Number($iValue)
	Return True
EndFunc   ;==>__WV2_UnshiftEvent

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_DispatchQueued
; Description ...: Calls the functions that own the events waiting in one queue, or in every live one.
; Parameters ....: $iInst - Instance number, or 0 for every view still alive.
;                  $iCap  - Longest run of handlers this pass may start.
; Return values .: Number of handlers called. A call that could not be made leaves $WV2_ERR_CB as the
;                  last error and its event back at the head of the queue.
; Remarks .......: Nothing is pumped, so nothing can arrive while this runs: it works on what the sinks
;                  already put in the queues. Two guards, and both are the reason this function can be
;                  called from a wait loop. $__WV2_bDispatching keeps one pass from starting a second
;                  when the handler it calls reads the queue, which is what the handler is allowed to
;                  do; the in-callback test keeps this out of the four callbacks that owe the page an
;                  answer, where the UDF says no to everything else that would re-enter.
;                  The pass stops at the first event of a kind whose name is not a function, rather
;                  than trying the later ones: an event that arrived after it would be answered out of
;                  order, and a host that gets $WV2_ERR_CB has one wrong name to fix, not a scramble.
; ===============================================================================================================================
Func __WV2_DispatchQueued($iInst, $iCap)
	If $iCap < 1 Or $__WV2_bDispatching Then Return 0
	$__WV2_bDispatching = True
	; A pass starts clean: the refusal of a handler name is the only thing this can leave behind as an
	; error, and a notice from an earlier pass must not be read as the answer of this one.
	$__WV2_iLastError = $WV2_ERR_NONE
	$__WV2_iLastHR = 0
	Local $iCalled = 0, $i, $j, $k, $iType, $iPos, $sData, $iValue, $sName, $iErr
	For $i = 1 To $__WV2_MAX
		If ($iInst = 0 Or $i = $iInst) And $__WV2_aUsed[$i] And $__WV2_iEvtCbCount[$i] > 0 And _
				Not $__WV2_bInCb[$i] And Not $__WV2_bInRes[$i] Then
			While $iCalled < $iCap And $__WV2_iEvtCount[$i] > 0 And $__WV2_aUsed[$i] And _
					$__WV2_iEvtCbCount[$i] > 0
				$iPos = -1
				For $k = 0 To $__WV2_iEvtCount[$i] - 1
					$j = Mod($__WV2_iEvtHead[$i] + $k, $__WV2_QCAP)
					$iType = $__WV2_aEvtType[$i][$j]
					If $__WV2_aEvtCb[$i][$iType] <> "" Then
						$iPos = $k
						ExitLoop
					EndIf
				Next
				If $iPos < 0 Then ExitLoop
				$sName = $__WV2_aEvtCb[$i][$iType]
				__WV2_PopEventOfType($i, $iType, $sData, $iValue)
				Call($sName, $i, $iType, $sData, $iValue)
				$iErr = @error
				If $iErr <> 0 Then
					; The name is taken off the kind as the call is refused, so the event left back in
					; the queue is readable by hand from here on: a wrong name costs one notice and
					; nothing else. Leaving it installed would keep the kind owned by a function that
					; does not exist, and no by-hand read could reach the events any more. A handler that
					; released its own view is the one position where the slot is no longer this pass's to
					; rewrite: the walk stops on $__WV2_aUsed, and so must the write-back, because a view
					; created inside that same handler already owns the queue these lines would touch.
					If $__WV2_aUsed[$i] Then
						$__WV2_aEvtCb[$i][$iType] = ""
						$__WV2_iEvtCbCount[$i] -= 1
						__WV2_UnshiftEvent($i, $iType, $sData, $iValue)
					EndIf
					__WV2_SetErr($WV2_ERR_CB, 0, $sName)
					$__WV2_bDispatching = False
					Return $iCalled
				EndIf
				$iCalled += 1
			WEnd
		EndIf
	Next
	$__WV2_bDispatching = False
	Return $iCalled
EndFunc   ;==>__WV2_DispatchQueued

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_WaitOp
; Description ...: Pumps messages until an asynchronous operation answers, or the time is over.
; ===============================================================================================================================
Func __WV2_WaitOp($i, $iSlot, $iTimeoutMs)
	Local $tEnd = TimerInit()
	While Not $__WV2_bOpDone[$i][$iSlot]
		__WV2_Pump(20)
		If TimerDiff($tEnd) > $iTimeoutMs Then
			__WV2_SetErr($WV2_ERR_TIMEOUT, 0, "__WV2_WaitOp")
			Return False
		EndIf
	WEnd
	Return True
EndFunc   ;==>__WV2_WaitOp

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_BeginOp
; Description ...: Arms the state of an asynchronous operation before its method is called.
; ===============================================================================================================================
Func __WV2_BeginOp($i, $iSlot)
	If $__WV2_pOpObj[$i][$iSlot] <> 0 Then
		__WV2_ReleaseExternal($__WV2_pOpObj[$i][$iSlot])
		$__WV2_pOpObj[$i][$iSlot] = 0
	EndIf
	$__WV2_bOpDone[$i][$iSlot] = False
	$__WV2_iOpHR[$i][$iSlot] = 0
	$__WV2_sOpOut[$i][$iSlot] = ""
EndFunc   ;==>__WV2_BeginOp

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_AddRaw / __WV2_RemoveRaw
; Description ...: add_* and remove_* of an event whose interface the ObjCreateInterface tags do not
;                  cover: the same two calls as the wrappers, written once.
; Return values .: The HRESULT, -1 when the vtable entry could not be read or the call failed.
; ===============================================================================================================================
Func __WV2_AddRaw($pObj, $iSlot, $pHandler, ByRef $iTok)
	$iTok = 0
	Local $pFn = __WV2_VtFn($pObj, $iSlot)
	If $pFn = 0 Then Return $__WV2_HR_E_FAIL
	Local $tTok = DllStructCreate("int64")
	Local $aCall = DllCallAddress("long", $pFn, "ptr", $pObj, "ptr", $pHandler, "ptr", DllStructGetPtr($tTok))
	If @Error Or Not IsArray($aCall) Then Return $__WV2_HR_E_FAIL
	If $aCall[0] = 0 Then $iTok = DllStructGetData($tTok, 1)
	Return $aCall[0]
EndFunc   ;==>__WV2_AddRaw

Func __WV2_RemoveRaw($pObj, $iSlot, $iTok)
	If $pObj = 0 Or $iTok = 0 Then Return $__WV2_HR_E_FAIL
	Local $pFn = __WV2_VtFn($pObj, $iSlot)
	If $pFn = 0 Then Return $__WV2_HR_E_FAIL
	Local $aCall = DllCallAddress("long", $pFn, "ptr", $pObj, "int64", $iTok)
	If @Error Or Not IsArray($aCall) Then Return $__WV2_HR_E_FAIL
	Return $aCall[0]
EndFunc   ;==>__WV2_RemoveRaw

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_Attach / __WV2_Detach
; Description ...: Subscribe one handler slot of an instance to its WebView2 event and register the
;                  cookie returned by add_*, which is what remove_* needs. The method name cannot be
;                  built at run time, so each slot is written out.
; ===============================================================================================================================
Func __WV2_Attach($i, $iSlot)
	If $__WV2_iTok[$i][$iSlot] <> 0 Then Return True
	Local $iTok = 0
	Local $hr = 0
	Switch $iSlot
		Case $__WV2_H_NAVC
			$hr = $__WV2_oWv[$i].add_NavigationCompleted($__WV2_pObj[$i][$iSlot], $iTok)
		Case $__WV2_H_NAVS
			$hr = $__WV2_oWv[$i].add_NavigationStarting($__WV2_pObj[$i][$iSlot], $iTok)
		Case $__WV2_H_MSG
			$hr = $__WV2_oWv[$i].add_WebMessageReceived($__WV2_pObj[$i][$iSlot], $iTok)
		Case $__WV2_H_NEW
			$hr = $__WV2_oWv[$i].add_NewWindowRequested($__WV2_pObj[$i][$iSlot], $iTok)
		Case $__WV2_H_TITLE
			$hr = $__WV2_oWv[$i].add_DocumentTitleChanged($__WV2_pObj[$i][$iSlot], $iTok)
		Case $__WV2_H_HIST
			$hr = $__WV2_oWv[$i].add_HistoryChanged($__WV2_pObj[$i][$iSlot], $iTok)
		Case $__WV2_H_PROC
			$hr = $__WV2_oWv[$i].add_ProcessFailed($__WV2_pObj[$i][$iSlot], $iTok)
		Case $__WV2_H_DOWNLOAD
			; The download event is the only one that lives on a newer version of the interface, so it
			; is subscribed through the raw vtable entry of ICoreWebView2_4.
			Local $p4 = __WV2_ViewIf($i, $__WV2_IF_4)
			If $p4 = 0 Then Return False
			Local $pFn = __WV2_VtFn($p4, $__WV2_SLOT_ICoreWebView2_4_add_DownloadStarting)
			If $pFn = 0 Then
				__WV2_SetErr($WV2_ERR_COM, 0, "__WV2_VtFn")
				Return False
			EndIf
			Local $tTok = DllStructCreate("int64")
			Local $aCall = DllCallAddress("long", $pFn, "ptr", $p4, "ptr", $__WV2_pObj[$i][$iSlot], _
					"ptr", DllStructGetPtr($tTok))
			If @Error Or Not IsArray($aCall) Then
				__WV2_SetErr($WV2_ERR_COM, 0, "ICoreWebView2_4::add_DownloadStarting")
				Return False
			EndIf
			$hr = $aCall[0]
			$iTok = DllStructGetData($tTok, 1)
		Case $__WV2_H_RESOURCE
			; add_WebResourceRequested sits at slot 55, far past the last method the wrapper tag declares,
			; so the call goes through the raw vtable, exactly like the download event.
			Local $pFnRes = __WV2_VtFn($__WV2_pWv[$i], $__WV2_SLOT_ICoreWebView2_add_WebResourceRequested)
			If $pFnRes = 0 Then
				__WV2_SetErr($WV2_ERR_COM, 0, "__WV2_VtFn")
				Return False
			EndIf
			Local $tTokRes = DllStructCreate("int64")
			Local $aRes = DllCallAddress("long", $pFnRes, "ptr", $__WV2_pWv[$i], _
					"ptr", $__WV2_pObj[$i][$iSlot], "ptr", DllStructGetPtr($tTokRes))
			If @Error Or Not IsArray($aRes) Then
				__WV2_SetErr($WV2_ERR_COM, 0, "ICoreWebView2::add_WebResourceRequested")
				Return False
			EndIf
			$hr = $aRes[0]
			$iTok = DllStructGetData($tTokRes, 1)
		Case $__WV2_H_FINDIDX, $__WV2_H_FINDCNT
			; The two events of the search object live on ICoreWebView2Find, which is asked for on first
			; use. Asking here too lets a host subscribe before its first search, like every other event.
			If $__WV2_pFind[$i] = 0 Then
				If __WV2_FindObj($i) = 0 Then Return False
			EndIf
			Local $iFnFind = $__WV2_SLOT_ICoreWebView2Find_add_ActiveMatchIndexChanged
			If $iSlot = $__WV2_H_FINDCNT Then $iFnFind = $__WV2_SLOT_ICoreWebView2Find_add_MatchCountChanged
			$hr = __WV2_AddRaw($__WV2_pFind[$i], $iFnFind, $__WV2_pObj[$i][$iSlot], $iTok)
		Case $__WV2_H_DIALOG
			$hr = $__WV2_oWv[$i].add_ScriptDialogOpening($__WV2_pObj[$i][$iSlot], $iTok)
		Case $__WV2_H_ACCEL
			$hr = $__WV2_oCtl[$i].add_AcceleratorKeyPressed($__WV2_pObj[$i][$iSlot], $iTok)
		Case $__WV2_H_CTXMENU, $__WV2_H_FAVICON
			; ContextMenuRequested and FaviconChanged sit on ICoreWebView2_11 and _15, past the end of
			; the wrapper tag, so both go through the raw vtable of the _16 pointer.
			Local $p16 = __WV2_ViewIf($i, $__WV2_IF_16)
			If $p16 = 0 Then Return False
			Local $iFn = $__WV2_SLOT_ICoreWebView2_11_add_ContextMenuRequested
			If $iSlot = $__WV2_H_FAVICON Then $iFn = $__WV2_SLOT_ICoreWebView2_15_add_FaviconChanged
			$hr = __WV2_AddRaw($p16, $iFn, $__WV2_pObj[$i][$iSlot], $iTok)
		Case $__WV2_H_AUDIO, $__WV2_H_MUTED
			; Both audio events sit on ICoreWebView2_8, past the end of the wrapper tag, so they go through
			; the raw vtable of the _8 pointer. A runtime older than 97.0.1072.54 has no _8 at all: the
			; QueryInterface fails and the caller sees $WV2_ERR_CALL with E_NOINTERFACE in @extended.
			Local $p8 = __WV2_ViewIf($i, $__WV2_IF_8)
			If $p8 = 0 Then Return False
			Local $iFnAudio = $__WV2_SLOT_ICoreWebView2_8_add_IsDocumentPlayingAudioChanged
			If $iSlot = $__WV2_H_MUTED Then $iFnAudio = $__WV2_SLOT_ICoreWebView2_8_add_IsMutedChanged
			$hr = __WV2_AddRaw($p8, $iFnAudio, $__WV2_pObj[$i][$iSlot], $iTok)
		Case $__WV2_H_FULLSCREEN
			; ContainsFullScreenElementChanged is the base interface's own method, but it sits past
			; get_DocumentTitle (48), where the wrapper tag stops, so it goes through the raw vtable too.
			; Every ICoreWebView2 version repeats the base layout, so the plain view pointer carries slot
			; 52 whatever the runtime version - no QueryInterface, and no minimum runtime to name.
			$hr = __WV2_AddRaw($__WV2_pWv[$i], $__WV2_SLOT_ICoreWebView2_add_ContainsFullScreenElementChanged, _
					$__WV2_pObj[$i][$iSlot], $iTok)
		Case $__WV2_H_PERMISSION
			; add_PermissionRequested is slot 23, inside the wrapper tag, so the ordinary call answers.
			$hr = $__WV2_oWv[$i].add_PermissionRequested($__WV2_pObj[$i][$iSlot], $iTok)
		Case $__WV2_H_CNTLOAD, $__WV2_H_SRCCHG
			; The two events of the document itself are the oldest the interface declares: slot 9 and
			; slot 11, both inside the wrapper tag, so the ordinary call answers. They had been carried by
			; the tag from the first version of this UDF without a handler behind them; this is what the
			; first version left out, not what it got wrong.
			If $iSlot = $__WV2_H_CNTLOAD Then
				$hr = $__WV2_oWv[$i].add_ContentLoading($__WV2_pObj[$i][$iSlot], $iTok)
			Else
				$hr = $__WV2_oWv[$i].add_SourceChanged($__WV2_pObj[$i][$iSlot], $iTok)
			EndIf
		Case $__WV2_H_WINCLOSE
			; add_WindowCloseRequested is slot 59 of the base interface, past the end of the wrapper tag
			; (get_DocumentTitle, 48) but before add_WebResourceRequested's neighbours; the plain view
			; pointer carries it whatever the runtime version, so no QueryInterface is needed.
			$hr = __WV2_AddRaw($__WV2_pWv[$i], $__WV2_SLOT_ICoreWebView2_add_WindowCloseRequested, _
					$__WV2_pObj[$i][$iSlot], $iTok)
		Case $__WV2_H_DOMCONTENT
			; add_DOMContentLoaded is slot 64, the second method ICoreWebView2_2 adds of its own, so it
			; lives only on the _2 pointer. A runtime that old never existed: _2 arrived with
			; WebView2 75.0.721.0, and QueryInterface failing is the honest answer on anything older.
			Local $p2Ev = __WV2_ViewIf($i, $__WV2_IF_2)
			If $p2Ev = 0 Then Return False
			$hr = __WV2_AddRaw($p2Ev, $__WV2_SLOT_ICoreWebView2_2_add_DOMContentLoaded, _
					$__WV2_pObj[$i][$iSlot], $iTok)
		Case $__WV2_H_CDPEVT
			; The receiver comes from _WV2_SetDevToolsProtocolEvent and holds one event name.
			If $__WV2_pCdpRecv[$i] = 0 Then
				__WV2_SetErr($WV2_ERR_NOT_READY, 0, "ICoreWebView2::GetDevToolsProtocolEventReceiver")
				Return False
			EndIf
			$hr = __WV2_AddRaw($__WV2_pCdpRecv[$i], $__WV2_SLOT_ICoreWebView2DevToolsProtocolEventReceiver_add_DevToolsProtocolEventReceived, _
					$__WV2_pObj[$i][$iSlot], $iTok)
			If $hr = 0 Then $__WV2_iCdpTok[$i] = $iTok
		Case Else
			__WV2_SetErr($WV2_ERR_ARG, 0, "__WV2_Attach")
			Return False
	EndSwitch
	If $hr <> 0 Then
		__WV2_SetErr($WV2_ERR_CALL, $hr, "ICoreWebView2::add_" & __WV2_SlotName($iSlot))
		Return False
	EndIf
	$__WV2_iTok[$i][$iSlot] = $iTok
	; The count event of the search comes with the index event: a caller waiting on $WV2_EVENT_FIND
	; wants both, and the two are cheap.
	If $iSlot = $__WV2_H_FINDIDX Then __WV2_Attach($i, $__WV2_H_FINDCNT)
	Return True
EndFunc   ;==>__WV2_Attach

Func __WV2_Detach($i, $iSlot)
	If $__WV2_iTok[$i][$iSlot] = 0 Then Return
	Local $iTok = $__WV2_iTok[$i][$iSlot]
	Switch $iSlot
		Case $__WV2_H_NAVC
			$__WV2_oWv[$i].remove_NavigationCompleted($iTok)
		Case $__WV2_H_NAVS
			$__WV2_oWv[$i].remove_NavigationStarting($iTok)
		Case $__WV2_H_MSG
			$__WV2_oWv[$i].remove_WebMessageReceived($iTok)
		Case $__WV2_H_NEW
			$__WV2_oWv[$i].remove_NewWindowRequested($iTok)
		Case $__WV2_H_TITLE
			$__WV2_oWv[$i].remove_DocumentTitleChanged($iTok)
		Case $__WV2_H_HIST
			$__WV2_oWv[$i].remove_HistoryChanged($iTok)
		Case $__WV2_H_PROC
			$__WV2_oWv[$i].remove_ProcessFailed($iTok)
		Case $__WV2_H_DOWNLOAD
			; remove_DownloadStarting takes its token by value: one int64 pushed on the stack.
			Local $p4 = __WV2_ViewIf($i, $__WV2_IF_4)
			If $p4 <> 0 Then DllCallAddress("long", __WV2_VtFn($p4, $__WV2_SLOT_ICoreWebView2_4_remove_DownloadStarting), "ptr", $p4, "int64", $iTok)
		Case $__WV2_H_RESOURCE
			If $__WV2_pWv[$i] <> 0 Then _
					DllCallAddress("long", __WV2_VtFn($__WV2_pWv[$i], $__WV2_SLOT_ICoreWebView2_remove_WebResourceRequested), _
					"ptr", $__WV2_pWv[$i], "int64", $iTok)
		Case $__WV2_H_FINDIDX, $__WV2_H_FINDCNT
			Local $iFnFindOff = $__WV2_SLOT_ICoreWebView2Find_remove_ActiveMatchIndexChanged
			If $iSlot = $__WV2_H_FINDCNT Then $iFnFindOff = $__WV2_SLOT_ICoreWebView2Find_remove_MatchCountChanged
			__WV2_RemoveRaw($__WV2_pFind[$i], $iFnFindOff, $iTok)
		Case $__WV2_H_DIALOG
			If IsObj($__WV2_oWv[$i]) Then $__WV2_oWv[$i].remove_ScriptDialogOpening($iTok)
		Case $__WV2_H_ACCEL
			If IsObj($__WV2_oCtl[$i]) Then $__WV2_oCtl[$i].remove_AcceleratorKeyPressed($iTok)
		Case $__WV2_H_CTXMENU, $__WV2_H_FAVICON
			Local $iFnOff = $__WV2_SLOT_ICoreWebView2_11_remove_ContextMenuRequested
			If $iSlot = $__WV2_H_FAVICON Then $iFnOff = $__WV2_SLOT_ICoreWebView2_15_remove_FaviconChanged
			__WV2_RemoveRaw($__WV2_pWvIf[$i][$__WV2_IF_16], $iFnOff, $iTok)
		Case $__WV2_H_AUDIO, $__WV2_H_MUTED
			Local $iFnAudioOff = $__WV2_SLOT_ICoreWebView2_8_remove_IsDocumentPlayingAudioChanged
			If $iSlot = $__WV2_H_MUTED Then $iFnAudioOff = $__WV2_SLOT_ICoreWebView2_8_remove_IsMutedChanged
			__WV2_RemoveRaw($__WV2_pWvIf[$i][$__WV2_IF_8], $iFnAudioOff, $iTok)
		Case $__WV2_H_FULLSCREEN
			__WV2_RemoveRaw($__WV2_pWv[$i], $__WV2_SLOT_ICoreWebView2_remove_ContainsFullScreenElementChanged, $iTok)
		Case $__WV2_H_PERMISSION
			; A request still waiting on an answer when the view goes is abandoned with its two
			; references; the page simply never gets one.
			Local $j
			For $j = 1 To $WV2_PERM_MAX
				__WV2_PermForget($i, $j)
			Next
			If IsObj($__WV2_oWv[$i]) Then $__WV2_oWv[$i].remove_PermissionRequested($iTok)
		Case $__WV2_H_CNTLOAD, $__WV2_H_SRCCHG
			If IsObj($__WV2_oWv[$i]) Then
				If $iSlot = $__WV2_H_CNTLOAD Then
					$__WV2_oWv[$i].remove_ContentLoading($iTok)
				Else
					$__WV2_oWv[$i].remove_SourceChanged($iTok)
				EndIf
			EndIf
		Case $__WV2_H_WINCLOSE
			If $__WV2_pWv[$i] <> 0 Then __WV2_RemoveRaw($__WV2_pWv[$i], $__WV2_SLOT_ICoreWebView2_remove_WindowCloseRequested, $iTok)
		Case $__WV2_H_DOMCONTENT
			__WV2_RemoveRaw($__WV2_pWvIf[$i][$__WV2_IF_2], $__WV2_SLOT_ICoreWebView2_2_remove_DOMContentLoaded, $iTok)
		Case $__WV2_H_CDPEVT
			If $__WV2_pCdpRecv[$i] <> 0 Then
				__WV2_RemoveRaw($__WV2_pCdpRecv[$i], $__WV2_SLOT_ICoreWebView2DevToolsProtocolEventReceiver_remove_DevToolsProtocolEventReceived, $iTok)
				$__WV2_iCdpTok[$i] = 0
			EndIf
	EndSwitch
	$__WV2_iTok[$i][$iSlot] = 0
	; The two events of the search object are always subscribed together, so they go together.
	If $iSlot = $__WV2_H_FINDIDX And $__WV2_iTok[$i][$__WV2_H_FINDCNT] <> 0 Then _
			__WV2_Detach($i, $__WV2_H_FINDCNT)
EndFunc   ;==>__WV2_Detach

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_SetHandlerFunc / __WV2_HandlerName
; Description ...: The body the three script handlers share: refuse a malformed name, subscribe the
;                  event when a name is given, unsubscribe it and forget the name when "" is given.
; Remarks .......: Like the resource handler, the name is only checked for shape here: a name the
;                  script does not carry is seen by Call() at the first event, and treated there as
;                  "no answer", which leaves the runtime in charge.
; ===============================================================================================================================
Func __WV2_SetHandlerFunc($iHandle, $sFunc, $iSlot, $sName)
	If $iSlot <> $__WV2_H_DIALOG And $iSlot <> $__WV2_H_ACCEL And $iSlot <> $__WV2_H_CTXMENU Then
		__WV2_SetErr($WV2_ERR_ARG, 0, $sName)
		Return False
	EndIf
	If Not __WV2_Guard($iHandle) Then Return False
	$sFunc = StringStripWS(String($sFunc), 3)
	If $sFunc <> "" And Not StringRegExp($sFunc, "^(?i)[a-z_][a-z0-9_]*$") Then
		__WV2_SetErr($WV2_ERR_ARG, 0, $sName)
		Return False
	EndIf
	If $sFunc = "" Then
		__WV2_Detach($iHandle, $iSlot)
		__WV2_HandlerName($iHandle, $iSlot, "")
		If $iSlot = $__WV2_H_DIALOG Then __WV2_DialogSetting($iHandle, False)
		$__WV2_iLastError = $WV2_ERR_NONE
		$__WV2_iLastHR = 0
		Return True
	EndIf
	__WV2_HandlerName($iHandle, $iSlot, $sFunc)
	If Not __WV2_Attach($iHandle, $iSlot) Then
		__WV2_HandlerName($iHandle, $iSlot, "")
		Return False
	EndIf
	If $iSlot = $__WV2_H_DIALOG And Not __WV2_DialogSetting($iHandle, True) Then
		__WV2_Detach($iHandle, $iSlot)
		__WV2_HandlerName($iHandle, $iSlot, "")
		Return False
	EndIf
	$__WV2_iLastError = $WV2_ERR_NONE
	$__WV2_iLastHR = 0
	Return True
EndFunc   ;==>__WV2_SetHandlerFunc

Func __WV2_HandlerName($i, $iSlot, $sFunc)
	Switch $iSlot
		Case $__WV2_H_DIALOG
			$__WV2_sDlgFunc[$i] = $sFunc
		Case $__WV2_H_ACCEL
			$__WV2_sAccelFunc[$i] = $sFunc
		Case $__WV2_H_CTXMENU
			$__WV2_sCtxFunc[$i] = $sFunc
	EndSwitch
EndFunc   ;==>__WV2_HandlerName

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_DialogSetting
; Description ...: Turns AreDefaultScriptDialogsEnabled off while a dialog handler is installed and puts
;                  the value the host had back when the handler goes. The runtime only reads the setting
;                  when a document loads, and it raises the dialog event instead of drawing its own box
;                  only when the setting is off.
; ===============================================================================================================================
Func __WV2_DialogSetting($i, $bInstall)
	Local $oSettings = __WV2_Settings($i)
	If Not IsObj($oSettings) Then Return False
	If $bInstall Then
		If $__WV2_bDlgDefault[$i] >= 0 Then Return True
		Local $iValue = 0
		If Not __WV2_Result($oSettings.get_AreDefaultScriptDialogsEnabled($iValue), _
				"ICoreWebView2Settings::get_AreDefaultScriptDialogsEnabled") Then Return False
		$__WV2_bDlgDefault[$i] = ($iValue ? 1 : 0)
		; Already off: nothing to switch, nothing to put back either.
		If $__WV2_bDlgDefault[$i] = 0 Then Return True
		Return __WV2_Result($oSettings.put_AreDefaultScriptDialogsEnabled(0), _
				"ICoreWebView2Settings::put_AreDefaultScriptDialogsEnabled")
	EndIf
	If $__WV2_bDlgDefault[$i] < 0 Then Return True
	Local $iSaved = $__WV2_bDlgDefault[$i]
	$__WV2_bDlgDefault[$i] = -1
	If $iSaved = 0 Then Return True
	__WV2_Result($oSettings.put_AreDefaultScriptDialogsEnabled(1), _
			"ICoreWebView2Settings::put_AreDefaultScriptDialogsEnabled")
	Return True
EndFunc   ;==>__WV2_DialogSetting

Func __WV2_SlotName($iSlot)
	Switch $iSlot
		Case $__WV2_H_ENV
			Return "CreateCoreWebView2EnvironmentCompleted"
		Case $__WV2_H_CTL
			Return "CreateCoreWebView2ControllerCompleted"
		Case $__WV2_H_NAVC
			Return "NavigationCompleted"
		Case $__WV2_H_NAVS
			Return "NavigationStarting"
		Case $__WV2_H_MSG
			Return "WebMessageReceived"
		Case $__WV2_H_NEW
			Return "NewWindowRequested"
		Case $__WV2_H_TITLE
			Return "DocumentTitleChanged"
		Case $__WV2_H_HIST
			Return "HistoryChanged"
		Case $__WV2_H_PROC
			Return "ProcessFailed"
		Case $__WV2_H_EXEC
			Return "ExecuteScript"
		Case $__WV2_H_ADDSCRIPT
			Return "AddScriptToExecuteOnDocumentCreated"
		Case $__WV2_H_CAP
			Return "CapturePreview"
		Case $__WV2_H_PRINT
			Return "PrintToPdf"
		Case $__WV2_H_DOWNLOAD
			Return "DownloadStarting"
		Case $__WV2_H_RESOURCE
			Return "WebResourceRequested"
		Case $__WV2_H_FINDIDX
			Return "ActiveMatchIndexChanged"
		Case $__WV2_H_FINDCNT
			Return "MatchCountChanged"
		Case $__WV2_H_DIALOG
			Return "ScriptDialogOpening"
		Case $__WV2_H_ACCEL
			Return "AcceleratorKeyPressed"
		Case $__WV2_H_CTXMENU
			Return "ContextMenuRequested"
		Case $__WV2_H_FAVICON
			Return "FaviconChanged"
		Case $__WV2_H_CDPEVT
			Return "DevToolsProtocolEventReceived"
		Case $__WV2_H_AUDIO
			Return "IsDocumentPlayingAudioChanged"
		Case $__WV2_H_MUTED
			Return "IsMutedChanged"
		Case $__WV2_H_FULLSCREEN
			Return "ContainsFullScreenElementChanged"
		Case $__WV2_H_PERMISSION
			Return "PermissionRequested"
		Case $__WV2_H_CNTLOAD
			Return "ContentLoading"
		Case $__WV2_H_SRCCHG
			Return "SourceChanged"
		Case $__WV2_H_DOMCONTENT
			Return "DOMContentLoaded"
		Case $__WV2_H_WINCLOSE
			Return "WindowCloseRequested"
		Case Else
			Return "slot " & $iSlot
	EndSwitch
EndFunc   ;==>__WV2_SlotName

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_Settings
; Description ...: Reads and keeps the settings interface of an instance. get_Settings hands out a
;                  pointer that already carries the reference owned by this instance, so the wrapper
;                  is built without flag (no reference added) and __WV2_Teardown releases it once.
; ===============================================================================================================================
Func __WV2_Settings($i)
	If IsObj($__WV2_oSettings[$i]) Then Return $__WV2_oSettings[$i]
	Local $p = 0
	Local $hr = $__WV2_oWv[$i].get_Settings($p)
	If $hr <> 0 Then
		__WV2_SetErr($WV2_ERR_CALL, $hr, "ICoreWebView2::get_Settings")
		Return 0
	EndIf
	If $p = 0 Then
		__WV2_SetErr($WV2_ERR_COM, 0, "ICoreWebView2::get_Settings")
		Return 0
	EndIf
	$__WV2_oSettings[$i] = ObjCreateInterface($p, $WV2_IID_SETTINGS, $__WV2_TAG_SETTINGS, False)
	If @Error Or Not IsObj($__WV2_oSettings[$i]) Then
		$__WV2_oSettings[$i] = 0
		__WV2_SetErr($WV2_ERR_COM, 0, "ICoreWebView2Settings wrapper")
		Return 0
	EndIf
	Return $__WV2_oSettings[$i]
EndFunc   ;==>__WV2_Settings

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_Settings2
; Description ...: The version of the settings that carries the user agent, asked for on the call.
;                  get_Settings hands a fresh reference every time, so the pointer it gives is released as
;                  soon as Settings2 is in hand and the wrapper of the view keeps its own: what the caller
;                  gets is one reference, which it releases itself. Nothing is cached, because a view can
;                  be asked for its agent once and never again.
; Return values .: The pointer, or 0 with $__WV2_iLastError and $__WV2_iLastHR set - on a runtime older
;                  than the property, E_NOINTERFACE from the QueryInterface.
; ===============================================================================================================================
Func __WV2_Settings2($i)
	If Not IsObj($__WV2_oWv[$i]) Then
		__WV2_SetErr($WV2_ERR_NOT_READY, 0, "__WV2_Settings2")
		Return 0
	EndIf
	Local $pSet = 0
	Local $hr = $__WV2_oWv[$i].get_Settings($pSet)
	If $hr <> 0 Or $pSet = 0 Then
		__WV2_SetErr(($hr ? $WV2_ERR_CALL : $WV2_ERR_COM), $hr, "ICoreWebView2::get_Settings")
		Return 0
	EndIf
	Local $p2 = __WV2_QiRaw($pSet, $WV2_IID_SET2)
	__WV2_ReleaseExternal($pSet)
	Return $p2
EndFunc   ;==>__WV2_Settings2

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_EventSlot
; Description ...: Maps a $WV2_EVENT_* code onto the handler slot that carries it.
; ===============================================================================================================================
Func __WV2_EventSlot($iEvent)
	Switch $iEvent
		Case $WV2_EVENT_NAVIGATION_STARTING
			Return $__WV2_H_NAVS
		Case $WV2_EVENT_NAVIGATION_COMPLETED
			Return $__WV2_H_NAVC
		Case $WV2_EVENT_WEB_MESSAGE
			Return $__WV2_H_MSG
		Case $WV2_EVENT_NEW_WINDOW
			Return $__WV2_H_NEW
		Case $WV2_EVENT_TITLE_CHANGED
			Return $__WV2_H_TITLE
		Case $WV2_EVENT_HISTORY_CHANGED
			Return $__WV2_H_HIST
		Case $WV2_EVENT_PROCESS_FAILED
			Return $__WV2_H_PROC
		Case $WV2_EVENT_DOWNLOAD_STARTING
			Return $__WV2_H_DOWNLOAD
		Case $WV2_EVENT_RESOURCE_REQUESTED
			Return $__WV2_H_RESOURCE
		Case $WV2_EVENT_FIND
			Return $__WV2_H_FINDIDX
		Case $WV2_EVENT_DOWNLOAD_STATE
			Return $__WV2_H_DLSTATE
		Case $WV2_EVENT_DOWNLOAD_PROGRESS
			Return $__WV2_H_DLPROG
		Case $WV2_EVENT_SCRIPT_DIALOG
			Return $__WV2_H_DIALOG
		Case $WV2_EVENT_ACCELERATOR
			Return $__WV2_H_ACCEL
		Case $WV2_EVENT_CONTEXT_MENU
			Return $__WV2_H_CTXMENU
		Case $WV2_EVENT_FAVICON_CHANGED
			Return $__WV2_H_FAVICON
		Case $WV2_EVENT_DEVTOOLS
			Return $__WV2_H_CDPEVT
		Case $WV2_EVENT_PLAYING_AUDIO_CHANGED
			Return $__WV2_H_AUDIO
		Case $WV2_EVENT_MUTED_CHANGED
			Return $__WV2_H_MUTED
		Case $WV2_EVENT_FULLSCREEN_CHANGED
			Return $__WV2_H_FULLSCREEN
		Case $WV2_EVENT_PERMISSION_REQUESTED
			Return $__WV2_H_PERMISSION
		Case $WV2_EVENT_CONTENT_LOADING
			Return $__WV2_H_CNTLOAD
		Case $WV2_EVENT_SOURCE_CHANGED
			Return $__WV2_H_SRCCHG
		Case $WV2_EVENT_DOM_CONTENT_LOADED
			Return $__WV2_H_DOMCONTENT
		Case $WV2_EVENT_WINDOW_CLOSE
			Return $__WV2_H_WINCLOSE
	EndSwitch
	Return 0
EndFunc   ;==>__WV2_EventSlot

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_EventReady
; Description ...: Says whether an event can reach the queue: the handler is subscribed, or, for the
;                  events that hang off another object, that object carries the subscription anyway.
; ===============================================================================================================================
Func __WV2_EventReady($i, $iEvent)
	Switch $iEvent
		Case $WV2_EVENT_DOWNLOAD_STATE, $WV2_EVENT_DOWNLOAD_PROGRESS
			Return $__WV2_bDlWatch[$i]
		Case $WV2_EVENT_FIND
			Return ($__WV2_pFind[$i] <> 0 And $__WV2_iTok[$i][$__WV2_H_FINDIDX] <> 0)
	EndSwitch
	Local $iSlot = __WV2_EventSlot($iEvent)
	Return ($iSlot <> 0 And $__WV2_iTok[$i][$iSlot] <> 0)
EndFunc   ;==>__WV2_EventReady

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_WaitFor
; Description ...: Pumps messages until the environment and the controller are both in place.
; ===============================================================================================================================
Func __WV2_WaitFor($i, $iTimeoutMs)
	Local $tEnd = TimerInit()
	While 1
		If $__WV2_bCtl[$i] Then
			$__WV2_iLastError = $WV2_ERR_NONE
			$__WV2_iLastHR = 0
			Return True
		EndIf
		If $__WV2_bEnvErr[$i] Then
			__WV2_SetErr($WV2_ERR_ENV, $__WV2_iHR[$i], "ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler")
			Return False
		EndIf
		If $__WV2_bCtlErr[$i] Then
			__WV2_SetErr($WV2_ERR_CONTROLLER, $__WV2_iHR[$i], "ICoreWebView2CreateCoreWebView2ControllerCompletedHandler")
			Return False
		EndIf
		If TimerDiff($tEnd) > $iTimeoutMs Then
			__WV2_SetErr($WV2_ERR_TIMEOUT, $__WV2_iHR[$i], "_WV2_Create")
			Return False
		EndIf
		__WV2_Pump(20)
	WEnd
EndFunc   ;==>__WV2_WaitFor

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_Pump
; Description ...: Runs the message queue of the current thread for a while, the way a GUI loop does.
; ===============================================================================================================================
Func __WV2_Pump($iMs)
	Local Static $tMsg = DllStructCreate("ptr hwnd;uint message;ptr wParam;ptr lParam;dword time;long x;long y")
	Local $tEnd = TimerInit()
	While TimerDiff($tEnd) < $iMs
		Local $aPM = DllCall("user32.dll", "bool", "PeekMessageW", "ptr", DllStructGetPtr($tMsg), "ptr", 0, "dword", 0, "dword", 0, "dword", 1)
		If @Error Or Not $aPM[0] Then
			Sleep(2)
		Else
			DllCall("user32.dll", "bool", "TranslateMessage", "ptr", DllStructGetPtr($tMsg))
			DllCall("user32.dll", "lresult", "DispatchMessageW", "ptr", DllStructGetPtr($tMsg))
		EndIf
	WEnd
EndFunc   ;==>__WV2_Pump

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_PumpDrain
; Description ...: Pumps the thread queue until it goes quiet, with a hard cap.
; Parameters ....: $iCapMs   - longest this call may take.
;                  $iQuietMs - how long the queue must stay empty before the pump gives up on it.
; Return values .: 1 the queue went quiet, 0 the cap was reached with messages still arriving.
; Remarks .......: A fixed pump charges every caller the whole delay, even when the runtime has
;                  nothing left to say. Messages cannot be waited for without a bound, so the cap
;                  stays; the quiet spell is what normally ends the wait. A message that arrives
;                  after this pump is still answered: the handler slots this view owned were zeroed
;                  before it, so a late callback finds an empty slot instead of a freed object.
; ===============================================================================================================================
Func __WV2_PumpDrain($iCapMs, $iQuietMs)
	Local Static $tMsg = DllStructCreate("ptr hwnd;uint message;ptr wParam;ptr lParam;dword time;long x;long y")
	Local $tEnd = TimerInit(), $tQuiet = TimerInit()
	While TimerDiff($tEnd) < $iCapMs
		Local $aPM = DllCall("user32.dll", "bool", "PeekMessageW", "ptr", DllStructGetPtr($tMsg), "ptr", 0, "dword", 0, "dword", 0, "dword", 1)
		If @Error Or Not $aPM[0] Then
			If TimerDiff($tQuiet) >= $iQuietMs Then Return SetError(0, 0, 1)
			Sleep(2)
		Else
			$tQuiet = TimerInit()
			DllCall("user32.dll", "bool", "TranslateMessage", "ptr", DllStructGetPtr($tMsg))
			DllCall("user32.dll", "lresult", "DispatchMessageW", "ptr", DllStructGetPtr($tMsg))
		EndIf
	WEnd
	Return SetError(0, 0, 0)
EndFunc   ;==>__WV2_PumpDrain

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_Alloc / __WV2_Free / __WV2_Teardown
; Description ...: Instance table. A handle is a slot number, valid until _WV2_Destroy releases it.
; ===============================================================================================================================
Func __WV2_Alloc()
	Local $i, $j
	For $i = 1 To $__WV2_MAX
		If Not $__WV2_aUsed[$i] Then
			$__WV2_aUsed[$i] = 1
			$__WV2_oEnv[$i] = 0
			$__WV2_pEnv[$i] = 0
			$__WV2_oCtl[$i] = 0
			$__WV2_pCtl[$i] = 0
			$__WV2_oWv[$i] = 0
			$__WV2_pWv[$i] = 0
			For $j = 1 To $__WV2_IF_MAX
				$__WV2_pWvIf[$i][$j] = 0
			Next
			$__WV2_oSettings[$i] = 0
			$__WV2_hParent[$i] = 0
			$__WV2_iLeft[$i] = 0
			$__WV2_iTop[$i] = 0
			$__WV2_iRight[$i] = 0
			$__WV2_iBottom[$i] = 0
			$__WV2_bEnv[$i] = False
			$__WV2_bCtl[$i] = False
			$__WV2_bReady[$i] = False
			$__WV2_bEnvErr[$i] = False
			$__WV2_bCtlErr[$i] = False
			$__WV2_bNavDone[$i] = False
			$__WV2_bNavOK[$i] = False
			$__WV2_iWebErr[$i] = 0
			$__WV2_iHR[$i] = 0
			$__WV2_sUser[$i] = ""
			$__WV2_bTempUser[$i] = False
			$__WV2_sVersion[$i] = ""
			$__WV2_sNavFilter[$i] = ""
			$__WV2_sDlFilter[$i] = ""
			$__WV2_sDlFolder[$i] = ""
			$__WV2_sResFunc[$i] = ""
			$__WV2_sResFilter[$i] = ""
			$__WV2_iResCtx[$i] = $WV2_RES_ALL
			$__WV2_bInRes[$i] = False
			$__WV2_pFind[$i] = 0
			$__WV2_pProf[$i] = 0
			$__WV2_bFindOn[$i] = False
			$__WV2_sDlgFunc[$i] = ""
			$__WV2_bDlgDefault[$i] = -1
			$__WV2_sAccelFunc[$i] = ""
			$__WV2_sCtxFunc[$i] = ""
			$__WV2_sCdpEvent[$i] = ""
			$__WV2_iDlCount[$i] = 0
			$__WV2_iDlNext[$i] = 0
			$__WV2_bDlWatch[$i] = False
			$__WV2_bCdpOff[$i] = False
			$__WV2_bInCb[$i] = False
			$__WV2_pCdpRecv[$i] = 0
			$__WV2_iCdpTok[$i] = 0
			For $j = 1 To $WV2_DL_MAX
				$__WV2_pDl[$i][$j] = 0
				$__WV2_iDlSeq[$i][$j] = 0
				$__WV2_iDlStateTok[$i][$j] = 0
				$__WV2_iDlProgTok[$i][$j] = 0
			Next
			For $j = 0 To $__WV2_PERM_KIND_MAX
				$__WV2_iPermPol[$i][$j] = $WV2_PERM_DEFAULT
			Next
			For $j = 1 To $WV2_PERM_MAX
				$__WV2_pPermArgs[$i][$j] = 0
				$__WV2_pPermDef[$i][$j] = 0
				$__WV2_sPermUri[$i][$j] = ""
				$__WV2_iPermKind[$i][$j] = 0
				$__WV2_iPermSeq[$i][$j] = 0
			Next
			$__WV2_iPermNext[$i] = 0
			$__WV2_iEvtHead[$i] = 0
			$__WV2_iEvtCount[$i] = 0
			$__WV2_iEvtDrop[$i] = 0
			$__WV2_iEvtCbCount[$i] = 0
			For $j = 1 To $__WV2_EV_MAX
				$__WV2_aEvtCb[$i][$j] = ""
			Next
			For $j = 1 To $__WV2_SLOT_COUNT
				$__WV2_pObj[$i][$j] = 0
				$__WV2_iTok[$i][$j] = 0
				$__WV2_bOpDone[$i][$j] = False
				$__WV2_iOpHR[$i][$j] = 0
				$__WV2_sOpOut[$i][$j] = ""
				$__WV2_pOpObj[$i][$j] = 0
			Next
			Return $i
		EndIf
	Next
	Return 0
EndFunc   ;==>__WV2_Alloc

Func __WV2_Free($i)
	__WV2_FreeHandlers($i)
	; The profile folder is NOT deleted here. The browser process keeps it open for seconds after the
	; controller is closed, so a delete on this path only waits for files it cannot remove - fifteen
	; seconds of waiting, measured, and the folder survives anyway. It is queued for the next sweep,
	; which runs where nobody is watching the clock: at the end of _WV2_Create. The queue holds every
	; folder still waiting, not one per handle: a handle reused twice in a run can have two.
	If $__WV2_bTempUser[$i] And $__WV2_sUser[$i] <> "" And $__WV2_iPend < UBound($__WV2_aPend) Then
		$__WV2_aPend[$__WV2_iPend] = $__WV2_sUser[$i]
		$__WV2_tPend[$__WV2_iPend] = TimerInit()
		$__WV2_iPend += 1
	EndIf
	$__WV2_aUsed[$i] = 0
	$__WV2_bOwnWin[$i] = 0
	$__WV2_bReady[$i] = False
	$__WV2_bCtl[$i] = False
	$__WV2_bEnv[$i] = False
EndFunc   ;==>__WV2_Free

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_IsOurProfile
; Description ...: Tells whether a path is a profile folder this UDF built - and only one: a folder
;                  directly under the temporary directory, named AutoItWebView2_<pid>_<handle> plus
;                  an optional serial, all integers. Nothing else can be handed to the sweep, whatever
;                  a caller passes. The two-part form is the one the released builds used, so their
;                  rubbish is recognised too.
; ===============================================================================================================================
Func __WV2_IsOurProfile($sPath)
	If Not IsString($sPath) Or $sPath = "" Then Return False
	Local $sTemp = @TempDir
	If StringLeft($sPath, StringLen($sTemp) + 1) <> $sTemp & "\" Then Return False
	Local $sName = StringTrimLeft($sPath, StringLen($sTemp) + 1)
	If $sName = "" Or StringInStr($sName, "\") Then Return False ; one level only, never a subtree
	If StringLeft($sName, StringLen($__WV2_PROFILE_PREFIX)) <> $__WV2_PROFILE_PREFIX Then Return False
	Local $aP = StringSplit(StringTrimLeft($sName, StringLen($__WV2_PROFILE_PREFIX)), "_", 2)
	If @Error Or UBound($aP) < 2 Or UBound($aP) > 3 Then Return False
	Local $j
	For $j = 0 To UBound($aP) - 1
		If Not StringIsInt($aP[$j]) Then Return False
	Next
	If Number($aP[1]) < 1 Or Number($aP[1]) > $__WV2_MAX Then Return False
	Return True
EndFunc   ;==>__WV2_IsOurProfile

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_NukeWalk
; Description ...: Empties a folder tree from the bottom up, one attempt per entry. A locked file is
;                  left where it is and the caller notices through FileExists. Nothing is waited for:
;                  DirRemove retries twenty times against a folder the browser has not let go of,
;                  which is the fifteen seconds a close used to cost; RemoveDirectoryW answers at once.
; ===============================================================================================================================
Func __WV2_NukeWalk($sPath)
	Local $hF = FileFindFirstFile($sPath & "\*")
	If $hF = -1 Then Return
	Local $s, $sChild
	While 1
		$s = FileFindNextFile($hF)
		If @Error Then ExitLoop
		$sChild = $sPath & "\" & $s
		If @extended Then
			__WV2_NukeWalk($sChild)
			DllCall("kernel32.dll", "bool", "RemoveDirectoryW", "wstr", $sChild)
		Else
			; FileDelete answers 0 without an error on a read-only file, and a Chromium profile has a
			; few. Clearing the attributes is the second attempt, never the first, so the walk stays
			; at one call per file when there is nothing unusual.
			If Not FileDelete($sChild) Then
				FileSetAttrib($sChild, "-RASHNOT")
				FileDelete($sChild)
			EndIf
		EndIf
	WEnd
	FileClose($hF)
	DllCall("kernel32.dll", "bool", "RemoveDirectoryW", "wstr", $sPath)
EndFunc   ;==>__WV2_NukeWalk

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_ProfileNuke
; Description ...: Removes one profile folder of ours. Returns 1 when it is gone, 0 when something
;                  inside is still held by the browser - which is not an error, the next sweep tries
;                  again. Refuses any path that is not a profile folder of this UDF.
; ===============================================================================================================================
Func __WV2_ProfileNuke($sPath)
	If Not __WV2_IsOurProfile($sPath) Then Return SetError($WV2_ERR_ARG, 0, 0)
	If Not FileExists($sPath) Then Return SetError(0, 0, 1)
	__WV2_NukeWalk($sPath)
	Return SetError(0, 0, Not FileExists($sPath))
EndFunc   ;==>__WV2_ProfileNuke

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_SweepStale
; Description ...: Collects the profile folders the browser could not let go of in time: the ones this
;                  script released and queued, and - once, at the first create - the ones left by
;                  processes that no longer exist. Called from _WV2_Create after the view is up.
; Return values .: Number of folders removed. @error is always 0.
; ===============================================================================================================================
Func __WV2_SweepStale()
	Local $i, $j, $iGone = 0
	; Ours, released by _WV2_Destroy. The browser needs a couple of seconds of message loop to let go
	; of the folder, so a release younger than $__WV2_SWEEP_AGE is left in the queue: walking a locked
	; tree is not free, and the next sweep finds it open.
	$i = 0
	While $i < $__WV2_iPend
		If TimerDiff($__WV2_tPend[$i]) >= $__WV2_SWEEP_AGE And __WV2_ProfileNuke($__WV2_aPend[$i]) Then
			$iGone += 1
			For $j = $i To $__WV2_iPend - 2
				$__WV2_aPend[$j] = $__WV2_aPend[$j + 1]
				$__WV2_tPend[$j] = $__WV2_tPend[$j + 1]
			Next
			$__WV2_iPend -= 1
		Else
			$i += 1
		EndIf
	WEnd

	; The rubbish of the runs that ended before this one is worth one look per process, not one per
	; view: a clean temporary directory costs a millisecond to notice.
	If $__WV2_bSwept Then Return SetError(0, 0, $iGone)
	$__WV2_bSwept = True

	; One snapshot of the running processes. ProcessExists would rebuild that list for every folder,
	; and the folders are the cheap part. An empty list means the question could not be answered, and
	; then nothing is deleted: a live process must never lose the folder it is using.
	Local $aLive = ProcessList()
	If @Error Or $aLive[0][0] = 0 Then Return SetError(0, 0, $iGone)
	Local $sLive = ";"
	For $i = 1 To $aLive[0][0]
		$sLive &= $aLive[$i][1] & ";"
	Next

	Local $hF = FileFindFirstFile(@TempDir & "\" & $__WV2_PROFILE_PREFIX & "*")
	If $hF = -1 Then Return SetError(0, 0, $iGone)
	Local $s, $aP, $bDir
	While 1
		$s = FileFindNextFile($hF)
		If @Error Then ExitLoop
		$bDir = @extended
		If Not $bDir Then ContinueLoop ; a file of that name is nobody's rubbish
		If Not __WV2_IsOurProfile(@TempDir & "\" & $s) Then ContinueLoop
		$aP = StringSplit(StringTrimLeft($s, StringLen($__WV2_PROFILE_PREFIX)), "_", 2)
		If @Error Then ContinueLoop
		; Never touch the folder of a live process, ours included: another view is using it.
		If StringInStr($sLive, ";" & $aP[0] & ";") Then ContinueLoop
		If __WV2_ProfileNuke(@TempDir & "\" & $s) Then $iGone += 1
	WEnd
	FileClose($hF)
	Return SetError(0, 0, $iGone)
EndFunc   ;==>__WV2_SweepStale

Func __WV2_Teardown($i)
	Local $j
	; The window that _WV2_Simple made for this view goes out of sight first. The calls below do not
	; return until the browser has let go, and a page still painted while the thread holds is a page that
	; cannot answer. Asked from another process with the same question the shell asks - SendMessageTimeout
	; with SMTO_ABORTIFHUNG - a window this suite had left on screen held the answer off for 14 150 ms, and
	; WinList spelled its title "[WV2 refused (Ne repond pas)]". Hidden here, not deleted: a window the
	; script created itself is never touched, it is the script that decides when that one goes.
	If $__WV2_bOwnWin[$i] And $__WV2_hParent[$i] <> 0 Then GUISetState(@SW_HIDE, $__WV2_hParent[$i])
	; The resource handler is dropped first: a request still in flight must not reach a script that is
	; tearing the view down.
	$__WV2_sResFunc[$i] = ""
	For $j = 1 To $__WV2_SLOT_COUNT
		__WV2_Detach($i, $j)
	Next
	; The versions of the interface asked for through QueryInterface go first: they are references to
	; the same object as the view, and an interface must outlive the pointers taken from it.
	For $j = 1 To $__WV2_IF_MAX
		If $__WV2_pWvIf[$i][$j] <> 0 Then
			__WV2_ReleaseExternal($__WV2_pWvIf[$i][$j])
			$__WV2_pWvIf[$i][$j] = 0
		EndIf
	Next
	; The search object outlives the handlers that were just detached from it, then goes.
	If $__WV2_pFind[$i] <> 0 Then
		__WV2_ReleaseExternal($__WV2_pFind[$i])
		$__WV2_pFind[$i] = 0
	EndIf
	; The profile was taken from ICoreWebView2_13, which the loop just above has released: an interface
	; outlives the pointer it came from, so it goes in the same place as the search object.
	If $__WV2_pProf[$i] <> 0 Then
		__WV2_ReleaseExternal($__WV2_pProf[$i])
		$__WV2_pProf[$i] = 0
	EndIf
	If $__WV2_pCdpRecv[$i] <> 0 Then
		__WV2_ReleaseExternal($__WV2_pCdpRecv[$i])
		$__WV2_pCdpRecv[$i] = 0
	EndIf
	; Download operations keep a reference of their own, and so do the print settings made for this view.
	For $j = 1 To $WV2_DL_MAX
		If $__WV2_pDl[$i][$j] <> 0 Then __WV2_DlForget($i, $j)
	Next
	For $j = 1 To $WV2_PRINT_SETTINGS_MAX
		If $__WV2_pPrintSet[$j] <> 0 And $__WV2_iPrintInst[$j] = $i Then
			__WV2_ReleaseExternal($__WV2_pPrintSet[$j])
			$__WV2_pPrintSet[$j] = 0
			$__WV2_iPrintInst[$j] = 0
		EndIf
	Next
	For $j = 1 To $__WV2_SLOT_COUNT
		If $__WV2_pOpObj[$i][$j] <> 0 Then
			__WV2_ReleaseExternal($__WV2_pOpObj[$i][$j])
			$__WV2_pOpObj[$i][$j] = 0
		EndIf
	Next
	If IsObj($__WV2_oSettings[$i]) Then
		$__WV2_oSettings[$i].Release()
		$__WV2_oSettings[$i] = 0
	EndIf
	If IsObj($__WV2_oWv[$i]) Then $__WV2_oWv[$i].Release()
	$__WV2_oWv[$i] = 0
	$__WV2_pWv[$i] = 0
	If IsObj($__WV2_oCtl[$i]) Then
		$__WV2_iLastHR = $__WV2_oCtl[$i].Close()
		$__WV2_oCtl[$i].Release()
	EndIf
	$__WV2_oCtl[$i] = 0
	$__WV2_pCtl[$i] = 0
	__WV2_PumpDrain($__WV2_DRAIN_CAP, $__WV2_DRAIN_QUIET)
	__WV2_EnvShareRetire($i)
	If IsObj($__WV2_oEnv[$i]) Then $__WV2_oEnv[$i].Release()
	$__WV2_oEnv[$i] = 0
	$__WV2_pEnv[$i] = 0
	__WV2_PumpDrain($__WV2_DRAIN_CAP, $__WV2_DRAIN_QUIET)
EndFunc   ;==>__WV2_Teardown

Func __WV2_Fail($i)
	__WV2_Teardown($i)
	__WV2_Free($i)
EndFunc   ;==>__WV2_Fail

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_EnvShareFind / __WV2_EnvShareNote / __WV2_EnvShareRetire
; Description ...: The table of live environments, one entry per user data folder. Find answers the
;                  entry a new view can borrow, Note puts the environment of a folder in the table when
;                  the runtime hands it back, and Retire takes the entry out again when the last view
;                  of that folder goes. An entry only ever exists while at least one view holds a COM
;                  reference to the environment behind it, which is what keeps its pointer from ever
;                  going stale.
; ===============================================================================================================================
Func __WV2_EnvShareFind($sFolder)
	Local $i
	For $i = 1 To $__WV2_ENVSHARE
		If $__WV2_iEnvRefs[$i] > 0 And $__WV2_sEnvKey[$i] = StringUpper($sFolder) Then Return $i
	Next
	Return 0
EndFunc   ;==>__WV2_EnvShareFind

Func __WV2_EnvShareNote($i, $sFolder)
	Local $k = __WV2_EnvShareFind($sFolder)
	If $k <> 0 Then
		; Somebody got there first - two views started on one folder before either was answered. The
		; environment this one made stays its own and is released as such; the table keeps the one it
		; already held, and that is the one later views borrow.
		Return
	EndIf
	For $k = 1 To $__WV2_ENVSHARE
		If $__WV2_iEnvRefs[$k] = 0 Then
			$__WV2_sEnvKey[$k] = StringUpper($sFolder)
			$__WV2_pEnvShared[$k] = $__WV2_pEnv[$i]
			$__WV2_iEnvRefs[$k] = 1
			$__WV2_iEnvShare[$i] = $k
			Return
		EndIf
	Next
EndFunc   ;==>__WV2_EnvShareNote

Func __WV2_EnvShareRetire($i)
	Local $k = $__WV2_iEnvShare[$i]
	If $k = 0 Then Return
	$__WV2_iEnvShare[$i] = 0
	$__WV2_iEnvRefs[$k] -= 1
	If $__WV2_iEnvRefs[$k] <= 0 Then
		; The view that is going holds the last reference: after its own Release nobody is left to keep
		; the environment up, so the entry goes with it.
		$__WV2_sEnvKey[$k] = ""
		$__WV2_pEnvShared[$k] = 0
		$__WV2_iEnvRefs[$k] = 0
	EndIf
EndFunc   ;==>__WV2_EnvShareRetire

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_Valid / __WV2_Guard / __WV2_GuardCtl
; Description ...: Precondition checks. Each one leaves @error style state in the globals when it
;                  refuses, so every public function reports the same way.
; ===============================================================================================================================
Func __WV2_Valid($i)
	$__WV2_iLastError = $WV2_ERR_NONE
	$__WV2_iLastHR = 0
	If Not IsNumber($i) Or $i <> Int($i) Or $i < 1 Or $i > $__WV2_MAX Or Not $__WV2_aUsed[$i] Then
		$__WV2_iLastError = $WV2_ERR_HANDLE
		Return False
	EndIf
	Return True
EndFunc   ;==>__WV2_Valid

Func __WV2_Guard($i)
	If Not __WV2_Valid($i) Then Return False
	If $__WV2_bInRes[$i] Or $__WV2_bInCb[$i] Then
		; A resource, dialog, key or menu handler is walking the COM objects of the runtime right now.
		; Calling back into it from there - or pumping messages, which would deliver the next request
		; inside this one - is refused instead of being left to deadlock.
		$__WV2_iLastError = $WV2_ERR_BUSY
		Return False
	EndIf
	If Not $__WV2_bReady[$i] Then
		$__WV2_iLastError = $WV2_ERR_NOT_READY
		Return False
	EndIf
	Return True
EndFunc   ;==>__WV2_Guard

Func __WV2_GuardCtl($i)
	If Not __WV2_Guard($i) Then Return False
	If Not $__WV2_bCtl[$i] Then
		$__WV2_iLastError = $WV2_ERR_NOT_READY
		Return False
	EndIf
	Return True
EndFunc   ;==>__WV2_GuardCtl

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_BeginNavigation / __WV2_Result / __WV2_BoolMethod
; Description ...: Shared bodies of the thin wrappers around ICoreWebView2.
; Remarks .......: __WV2_Result only records the outcome, it cannot hand an @error to the caller of
;                  the public function that uses it: SetError applies to the function that calls it.
;                  Every public wrapper therefore ends with its own
;                  "Return SetError($__WV2_iLastError, $__WV2_iLastHR, ...)" read from these globals.
; ===============================================================================================================================
Func __WV2_BeginNavigation($i)
	$__WV2_bNavDone[$i] = False
	$__WV2_bNavOK[$i] = False
	$__WV2_iWebErr[$i] = 0
EndFunc   ;==>__WV2_BeginNavigation

Func __WV2_Result($hr, $sLabel)
	If $hr <> 0 Then
		__WV2_SetErr($WV2_ERR_CALL, $hr, $sLabel)
		Return 0
	EndIf
	$__WV2_iLastError = $WV2_ERR_NONE
	$__WV2_iLastHR = 0
	Return 1
EndFunc   ;==>__WV2_Result

Func __WV2_BoolMethod($iHandle, $sMethod, $sLabel)
	$__WV2_iLastError = $WV2_ERR_NONE
	$__WV2_iLastHR = 0
	If Not __WV2_Guard($iHandle) Then Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	Local $iV = 0
	Local $hr = 0
	If $sMethod = "get_CanGoBack" Then
		$hr = $__WV2_oWv[$iHandle].get_CanGoBack($iV)
	ElseIf $sMethod = "get_CanGoForward" Then
		$hr = $__WV2_oWv[$iHandle].get_CanGoForward($iV)
	Else
		__WV2_SetErr($WV2_ERR_ARG, 0, $sLabel)
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	EndIf
	If $hr <> 0 Then
		__WV2_SetErr($WV2_ERR_CALL, $hr, $sLabel)
		Return SetError($__WV2_iLastError, $__WV2_iLastHR, -1)
	EndIf
	$__WV2_iLastError = $WV2_ERR_NONE
	Return SetError(0, 0, $iV ? 1 : 0)
EndFunc   ;==>__WV2_BoolMethod

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_SetErr / __WV2_ErrText
; Description ...: Error reporting shared by every public function.
; ===============================================================================================================================
Func __WV2_SetErr($iErr, $iHR, $sFunc)
	$__WV2_iLastError = $iErr
	$__WV2_iLastHR = Number($iHR)
	$__WV2_sLastFunc = $sFunc
EndFunc   ;==>__WV2_SetErr

Func __WV2_ErrText($iErr)
	Switch $iErr
		Case $WV2_ERR_NONE
			Return "No error"
		Case $WV2_ERR_HANDLE
			Return "Invalid handle"
		Case $WV2_ERR_ARG
			Return "Invalid argument"
		Case $WV2_ERR_RUNTIME
			Return "WebView2 runtime not found"
		Case $WV2_ERR_COM
			Return "COM failure"
		Case $WV2_ERR_ENV
			Return "Environment creation failed"
		Case $WV2_ERR_CONTROLLER
			Return "Controller creation failed"
		Case $WV2_ERR_NOT_READY
			Return "Instance not ready"
		Case $WV2_ERR_CALL
			Return "Method call failed"
		Case $WV2_ERR_TIMEOUT
			Return "Timeout"
		Case $WV2_ERR_FULL
			Return "Too many instances"
		Case $WV2_ERR_FILE
			Return "File could not be written"
		Case $WV2_ERR_BUSY
			Return "Cannot re-enter a running callback"
		Case $WV2_ERR_GUI
			Return "Window could not be built"
		Case $WV2_ERR_CB
			Return "Event handler could not be called"
		Case $WV2_ERR_EXT
			Return "Extension support not available"
		Case Else
			Return "Unknown error"
	EndSwitch
EndFunc   ;==>__WV2_ErrText

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_ClientSize
; Description ...: Reads the client size of a window into the scratch globals.
; ===============================================================================================================================
Func __WV2_ClientSize($hWnd)
	Local Static $tRc = DllStructCreate("long left;long top;long right;long bottom")
	DllCall("user32.dll", "bool", "GetClientRect", "hwnd", $hWnd, "ptr", DllStructGetPtr($tRc))
	$__WV2_iClientW = DllStructGetData($tRc, "right") - DllStructGetData($tRc, "left")
	$__WV2_iClientH = DllStructGetData($tRc, "bottom") - DllStructGetData($tRc, "top")
	Return $__WV2_iClientW > 0 And $__WV2_iClientH > 0
EndFunc   ;==>__WV2_ClientSize

; #INTERNAL_USE_ONLY# ===========================================================================================================
; Name ..........: __WV2_IIDString
; Description ...: Reads a GUID at an address and formats it the AutoIt way, "{XXXXXXXX-XXXX-...}".
; ===============================================================================================================================
Func __WV2_IIDString($pIID)
	Return StringUpper("{" & __WV2_RevHex($pIID, 4) & "-" & __WV2_RevHex($pIID + 4, 2) & "-" & __WV2_RevHex($pIID + 6, 2) & "-" & _
			Hex(DllStructGetData(DllStructCreate("byte", $pIID + 8), 1), 2) & _
			Hex(DllStructGetData(DllStructCreate("byte", $pIID + 9), 1), 2) & "-" & _
			Hex(DllStructGetData(DllStructCreate("byte", $pIID + 10), 1), 2) & _
			Hex(DllStructGetData(DllStructCreate("byte", $pIID + 11), 1), 2) & _
			Hex(DllStructGetData(DllStructCreate("byte", $pIID + 12), 1), 2) & _
			Hex(DllStructGetData(DllStructCreate("byte", $pIID + 13), 1), 2) & _
			Hex(DllStructGetData(DllStructCreate("byte", $pIID + 14), 1), 2) & _
			Hex(DllStructGetData(DllStructCreate("byte", $pIID + 15), 1), 2) & "}")
EndFunc   ;==>__WV2_IIDString

Func __WV2_RevHex($p, $iN)
	Local $i
	Local $s = ""
	For $i = $iN - 1 To 0 Step -1
		$s &= Hex(DllStructGetData(DllStructCreate("byte", $p + $i), 1), 2)
	Next
	Return $s
EndFunc   ;==>__WV2_RevHex
