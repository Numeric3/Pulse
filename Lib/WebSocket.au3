;#INDEX# =======================================================================================================================
; Title .........: WebSocket.au3 - the one include of the WebSocket UDF (four layers)
; AutoIt Version : 3.3.16.1
; Language ......: English
; Description ...: Write #include <WebSocket.au3> and the whole UDF is in the process:
;                  layer 1 wsk.au3 (Winsock 2 non-blocking), layer 2 tls.au3 (Schannel TLS
;                  records, client and server), layer 3 wsp.au3 (the websocket.dll protocol
;                  component) and layer 4 ws.au3 (the caller API: _WS_Connect, _WS_Send,
;                  _WS_Pump, _WS_Listen, _WS_Accept, _WS_UpgradeHead, _WS_UpgradeAnswer,
;                  _WS_Close). This file decides nothing and contains no function: it only
;                  orders the four includes, so a caller never has to know their names.
; Remarks .......: Windows 8 or later, AutoIt 3.3.16.1, tested 32 and 64 bit. No DLL is
;                  shipped - the three system DLLs the layers name come with Windows. Each
;                  layer carries #include-once, so including this file next to a direct
;                  #include of one of them loads everything exactly once. Start from the
;                  examples folder: example_server.au3 and example_client.au3 call layer 4
;                  ONLY, which is the promise this file is there to keep.
; Copyright ....: Copyright (c) 2026 Numeric1
; Licence .......: MIT (see the LICENSE file in this folder)
; Author ........: Numeric1
; https .........:
;===============================================================================================================================

#include-once

#include "wsk.au3"
#include "tls.au3"
#include "wsp.au3"
#include "ws.au3"
