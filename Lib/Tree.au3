#include-once
; #INDEX# =======================================================================================================================
; Title .........: Tree UDF
; AutoIt Version : 3.3.16+
; Language ......: English
; Version ........: 0.2.0
; Modified .......: 2026-11-12
; Description ...: A tree of named nodes, held in flat integer arrays indexed by node id. No objects,
;                  no DLL, no recursion in the hot paths, one instance per script.
;                  Create or reset the tree, add children to any node, add a whole separator-delimited
;                  path in one call, ask for a parent, a child, a sibling, a depth, a path, a subtree
;                  size, find a node by name without scanning, move a subtree, delete a node with three
;                  different promises about its children, walk the tree in preorder through a callback,
;                  check the whole structure, and write or read it as a text file.
;                  Every relation is one array read: a parent costs about 0.2 us behind the API, and the
;                  API call itself is the 10 to 15 us of argument checks and SetError, which is why the
;                  $g_aTr* globals are public and documented as the fast path.
;                  Names are the one indexed relation, and the index is invalidated lazily: adding and
;                  deleting never touch a Map, so deleting a named subtree costs 65 us per node instead
;                  of the 121 us a MapRemove-per-delete version paid.
; Author ........: Numeric1
; Link ..........: https://www.autoitscript.com/forum/profile/118605-numeric1/
; License .......: MIT, Copyright (c) 2026 Numeric1.
; ===============================================================================================================================
; Requirements: AutoIt 3.3.16 or later. The UDF needs Map types and the 3.3.16 array semantics, and
; nothing else: no #include beyond AutoIt's own, no DLL call, no COM object, no registry key.
;
; Design basis, reproducible from Tree_CostProbe.log (AutoIt 3.3.16.1 x86, Windows 10.0.19045).
; Timings on this box move by 2x with memory pressure, so read them as orders of magnitude:
;   loop + Mod            < 1 us  (floor)
;   + array read          1 us    the baseline structure cost
;   + DllStructGetData    2 us    instead of the array read
;   + one internal call   2 us    an accessor is not free
;   + Random()            2 us
;   public API accessor  10-15 us per call (Tree_Bench.log): interpreter
;                        validation plus SetError, hence the raw-globals
;                        fast path documented in Tree_Example.au3
;   ReDim 1 -> 100001     0.21 ms, but resizing a full 100k array by one
;                        element costs 38.5 ms -> grow geometrically, never 1
;   Map cost per op, by key count 10k / 25k / 50k / 100k:
;        insert   2 /  2 /   5 /  21 us
;        read     2 /  3 /   8 /  28 us   (random key order)
;        remove  18 / 50 / 117 / 438 us   <- MapRemove is NOT constant time
;        MapKeys  under 1 us per key
;   emptying a 20k-key Map: reassignment 5.5 ms against a 509 ms MapRemove
;        loop; at 200k keys the same two ways measured 0.12 s against 339 s
;        (1.7 ms per key, measured once, six-minute run left out of the probe)
; => every structural link is a flat integer array indexed by node id;
; => the only Map is name -> id: it kills the O(N) name scan below ~25k named
;    nodes, and the delete path never touches it (lazy invalidation, verified
;    on lookup, rebuilt in one pass by _Tree_NameReindex);
; => above ~50k named nodes, Tree_UseNameIndex(False) is the faster setting.
;
; Design notes:
;   * One tree instance per script: the state is global. Tree_Create resets what is live.
;   * Node ids are recycled by Tree_Remove, so a stored id is only trustworthy until the next delete.
;   * The preorder index (order/pos/sub) is derived: it may be stale and is rebuilt in one O(N) pass by
;     Tree_Rebuild(). Subtree ranges are O(1) while it is clean, O(N) to refresh when it is not.
;   * The name index is the only Map. Mutations mark it stale instead of editing it; Tree_Find verifies
;     what it read and heals the key on the spot; _Tree_NameReindex rebuilds by reassignment.
;   * Not reentrant: Tree_Walk's callback and the $iFunc of any API must not call the routines that use
;     the shared scratch stack (Tree_Rebuild, Tree_Remove, Tree_SubtreeSize, Tree_Validate, Tree_Move).
;   * Every failure is reported by @error, with a $TREE_E_* code, and by @extended when there is a
;     number worth having (an id, a line, a count). Nothing is written to the console and no dialog.
; ===============================================================================================================================

; #CONSTANTS# ===================================================================================================================
; Version of this file, so a script can check what it is running against.
Global Const $TREE_VERSION = "0.2.0"

; Error codes returned through @error
Global Const $TREE_E_NONE = 0
Global Const $TREE_E_NODE = 1      ; unknown, dead or out-of-range node id
Global Const $TREE_E_PARENT = 2    ; parent link points at a dead node
Global Const $TREE_E_MEM = 3       ; capacity ceiling reached
Global Const $TREE_E_CYCLE = 4     ; cycle, or a move that would create one
Global Const $TREE_E_NOTEMPTY = 5  ; node has children, mode refused
Global Const $TREE_E_NAME = 6      ; name already used in the name index
Global Const $TREE_E_FILE = 7      ; export/import file problem
Global Const $TREE_E_STATE = 8     ; no tree created yet
Global Const $TREE_E_ARG = 9       ; bad argument, or link chain broken

; Ceilings. The id space is capped so a broken chain cannot spin forever, and
; the capacity arrays are counted, not guessed.
Global Const $g_iTrMaxSlots = 4000000 ; hard ceiling for the id space
Global Const $g_iTrNArrays = 13       ; arrays sized by capacity

; #VARIABLES# ===================================================================================================================
; The live structure, one array per relation, index = node id. These are public
; on purpose: inside a hot loop, reading them is the fast path, roughly a fifth
; of the price of the API call that answers the same question.
;   $g_aTrAlive[$i]   1 while the id owns a node
;   $g_aTrParent[$i]  parent id, 0 for the root
;   $g_aTrChild1[$i]  first child id, 0 when childless
;   $g_aTrTail[$i]    last child id, 0 when childless
;   $g_aTrNext[$i]    next sibling id, 0 at the end of the chain
;   $g_aTrPrev[$i]    previous sibling id, 0 at the start of the chain
;   $g_aTrNKid[$i]    child count
;   $g_aTrDepth[$i]   parents above the node, root 0
;   $g_aTrData[$i]    the payload slot, read and written untouched
;   $g_aTrName[$i]    the name, "" when anonymous
Global $g_aTrAlive[1], $g_aTrParent[1], $g_aTrChild1[1], $g_aTrTail[1]
Global $g_aTrNext[1], $g_aTrPrev[1], $g_aTrNKid[1], $g_aTrDepth[1]
Global $g_aTrData[1], $g_aTrName[1]
; The derived preorder index, which may be stale between two Tree_Rebuild() calls.
;   $g_aTrOrder[$k]   node id at preorder position k
;   $g_aTrPos[$i]     preorder position of a node, 0 when unknown
;   $g_aTrSub[$i]     subtree size of a node, valid only while the index is clean
Global $g_aTrOrder[1], $g_aTrPos[1], $g_aTrSub[1]
; The free id list (LIFO, so the id you just freed is the next one handed out)
; and the scratch stack the subtree walks share.
Global $g_aTrFree[129], $g_aTrStack[1]
; The name index: name -> id, the only Map, and the only thing that can be stale.
Global $g_mTrName[]
Global $g_bTrUseName = True
Global $g_iTrNameStale = 0   ; keys in the map that no longer own a node
; Counters and state.
Global $g_iTrCap = 0
Global $g_iTrCount = 0      ; highest id ever handed out
Global $g_iTrLive = 0       ; alive node count
Global $g_iTrFreeN = 0
Global $g_iTrRoot = 0
Global $g_iTrDirty = 0      ; structural changes since the last rebuild
Global $g_bTrClean = False  ; True = preorder index valid
Global $g_iTrMaxDepth = 0

; ================================================================== internals


; Rebuilds the name index from the nodes. Purging by reassignment is the only
; sane way to empty a Map (a Map assignment copies, measured: the source keeps
; its own keys): 5.5 ms against 509 ms for a MapRemove loop at 20k keys, and
; 0.12 s against 339 s at 200k. Never empty the index key by key.
Func _Tree_NameReindex()
	Local $aEmpty[], $k, $n = 0
	$g_mTrName = $aEmpty
	$g_iTrNameStale = 0
	If Not $g_bTrUseName Then Return 0
	For $k = 1 To $g_iTrCount
		If $g_aTrAlive[$k] = 1 And $g_aTrName[$k] <> "" Then
			$g_mTrName[$g_aTrName[$k]] = $k
			$n += 1
		EndIf
	Next
	Return $n
EndFunc   ;==>_Tree_NameReindex

; Amortises the rebuild: stale keys are only worth a full pass once they are a
; real fraction of the index, and the floor keeps small trees from paying it.
Func _Tree_NamePurgeCheck()
	If $g_iTrNameStale < 4096 Then Return 0
	If $g_iTrNameStale < 65536 And $g_iTrNameStale * 4 < $g_iTrLive Then Return 0
	_Tree_NameReindex()
	Return 1
EndFunc   ;==>_Tree_NamePurgeCheck

; The live owner of $sName, or 0. A key whose node is dead - or whose id was
; recycled onto another name - is dropped here, so the index heals as it is
; queried. Caller must have checked MapExists.
Func _Tree_NameLive($sName)
	Local $i = $g_mTrName[$sName]
	If _Tree_Ok($i) And $g_aTrName[$i] = $sName Then Return $i
	If $g_iTrNameStale > 0 Then $g_iTrNameStale -= 1
	MapRemove($g_mTrName, $sName)
	Return 0
EndFunc   ;==>_Tree_NameLive

; 1 = $sName is in use by a live node. Without the live check a stale key
; would block a name that is long dead.
Func _Tree_NameTaken($sName)
	If Not MapExists($g_mTrName, $sName) Then Return 0
	Return _Tree_NameLive($sName) <> 0 ? 1 : 0
EndFunc   ;==>_Tree_NameTaken

Func _Tree_Ok($iNode)
	Return ($iNode >= 1 And $iNode <= $g_iTrCap And $g_aTrAlive[$iNode] = 1)
EndFunc   ;==>_Tree_Ok

Func _Tree_ReDim($iNew)
	$g_iTrCap = $iNew
	ReDim $g_aTrAlive[$iNew + 1]
	ReDim $g_aTrParent[$iNew + 1]
	ReDim $g_aTrChild1[$iNew + 1]
	ReDim $g_aTrTail[$iNew + 1]
	ReDim $g_aTrNext[$iNew + 1]
	ReDim $g_aTrPrev[$iNew + 1]
	ReDim $g_aTrNKid[$iNew + 1]
	ReDim $g_aTrDepth[$iNew + 1]
	ReDim $g_aTrData[$iNew + 1]
	ReDim $g_aTrName[$iNew + 1]
	ReDim $g_aTrOrder[$iNew + 1]
	ReDim $g_aTrPos[$iNew + 1]
	ReDim $g_aTrSub[$iNew + 1]
	ReDim $g_aTrStack[$iNew + 1]
EndFunc   ;==>_Tree_ReDim

Func _Tree_Grow()
	Local $iNew = $g_iTrCap * 2
	If $iNew > $g_iTrMaxSlots Then $iNew = $g_iTrMaxSlots
	If $iNew <= $g_iTrCap Then Return 0
	_Tree_ReDim($iNew)
	Return 1
EndFunc   ;==>_Tree_Grow

Func _Tree_Alloc()
	Local $iId
	If $g_iTrFreeN > 0 Then
		$g_iTrFreeN -= 1
		$iId = $g_aTrFree[$g_iTrFreeN + 1]
		$g_aTrFree[$g_iTrFreeN + 1] = 0
		Return $iId
	EndIf
	If $g_iTrCount >= $g_iTrCap Then
		If Not _Tree_Grow() Then Return 0
	EndIf
	$g_iTrCount += 1
	Return $g_iTrCount
EndFunc   ;==>_Tree_Alloc

; Kills one node: clears every slot, drops its name key, recycles the id.
Func _Tree_Clear($iId)
	$g_aTrAlive[$iId] = 0
	$g_aTrParent[$iId] = 0
	$g_aTrChild1[$iId] = 0
	$g_aTrTail[$iId] = 0
	$g_aTrNext[$iId] = 0
	$g_aTrPrev[$iId] = 0
	$g_aTrNKid[$iId] = 0
	$g_aTrDepth[$iId] = 0
	$g_aTrData[$iId] = ""
	$g_aTrPos[$iId] = 0
	$g_aTrSub[$iId] = 0
	Local $sOld = $g_aTrName[$iId]
	$g_aTrName[$iId] = ""
	; No Map work here at all: the key stays in the index and is only counted.
	; MapRemove costs 18 us at 10k keys and 438 us at 100k (Tree_CostProbe.log),
	; and even the MapExists that would check ownership showed up as ~26 us per
	; deleted node in Tree_Bench_map.log. Tree_Find verifies and heals; the
	; counter is an upper bound, which only ever makes the rebuild fire early.
	If $g_bTrUseName And $sOld <> "" Then $g_iTrNameStale += 1
	$g_iTrLive -= 1
	If $g_iTrFreeN >= UBound($g_aTrFree) - 1 Then ReDim $g_aTrFree[(UBound($g_aTrFree) - 1) * 2 + 1]
	$g_iTrFreeN += 1
	$g_aTrFree[$g_iTrFreeN] = $iId
	If $g_bTrUseName Then _Tree_NamePurgeCheck()
EndFunc   ;==>_Tree_Clear

Func _Tree_Link($iNode, $iParent)
	$g_aTrParent[$iNode] = $iParent
	$g_aTrPrev[$iNode] = $g_aTrTail[$iParent]
	$g_aTrNext[$iNode] = 0
	If $g_aTrTail[$iParent] = 0 Then
		$g_aTrChild1[$iParent] = $iNode
	Else
		$g_aTrNext[$g_aTrTail[$iParent]] = $iNode
	EndIf
	$g_aTrTail[$iParent] = $iNode
	$g_aTrNKid[$iParent] += 1
EndFunc   ;==>_Tree_Link

Func _Tree_Unlink($iNode)
	Local $iP = $g_aTrParent[$iNode]
	If $iP = 0 Then Return 0
	If $g_aTrPrev[$iNode] <> 0 Then
		$g_aTrNext[$g_aTrPrev[$iNode]] = $g_aTrNext[$iNode]
	Else
		$g_aTrChild1[$iP] = $g_aTrNext[$iNode]
	EndIf
	If $g_aTrNext[$iNode] <> 0 Then
		$g_aTrPrev[$g_aTrNext[$iNode]] = $g_aTrPrev[$iNode]
	Else
		$g_aTrTail[$iP] = $g_aTrPrev[$iNode]
	EndIf
	$g_aTrNKid[$iP] -= 1
	$g_aTrPrev[$iNode] = 0
	$g_aTrNext[$iNode] = 0
	Return $iP
EndFunc   ;==>_Tree_Unlink

; Kills $iNode and its whole subtree, returns the number of nodes killed.
; Children are pushed before their parent is cleared, so the sibling chain is
; read while it is still intact. $bUseRange = the preorder index was valid when
; the caller started, so the subtree is a contiguous range. No allocation.
Func _Tree_ClearSubtree($iNode, $bUseRange)
	Local $n = 0, $iTop, $c, $k
	If $bUseRange And $g_aTrPos[$iNode] > 0 Then
		For $k = $g_aTrPos[$iNode] To $g_aTrPos[$iNode] + $g_aTrSub[$iNode] - 1
			$n += 1
			_Tree_Clear($g_aTrOrder[$k])
		Next
		Return $n
	EndIf
	$iTop = 1
	$g_aTrStack[1] = $iNode
	While $iTop > 0
		$c = $g_aTrStack[$iTop]
		$iTop -= 1
		$n += 1
		$k = $g_aTrChild1[$c]
		While $k <> 0
			$iTop += 1
			$g_aTrStack[$iTop] = $k
			$k = $g_aTrNext[$k]
		WEnd
		_Tree_Clear($c)
	WEnd
	Return $n
EndFunc   ;==>_Tree_ClearSubtree

; Recomputes stored depth for a node and all its descendants. O(subtree).
Func _Tree_FixDepth($iNode)
	Local $iTop = 1, $cur, $c
	$g_aTrDepth[$iNode] = $g_aTrDepth[$g_aTrParent[$iNode]] + 1
	If $g_aTrDepth[$iNode] > $g_iTrMaxDepth Then $g_iTrMaxDepth = $g_aTrDepth[$iNode]
	$g_aTrStack[1] = $iNode
	While $iTop > 0
		$cur = $g_aTrStack[$iTop]
		$iTop -= 1
		$c = $g_aTrChild1[$cur]
		While $c <> 0
			$g_aTrDepth[$c] = $g_aTrDepth[$cur] + 1
			If $g_aTrDepth[$c] > $g_iTrMaxDepth Then $g_iTrMaxDepth = $g_aTrDepth[$c]
			$iTop += 1
			$g_aTrStack[$iTop] = $c
			$c = $g_aTrNext[$c]
		WEnd
	WEnd
	Return 1
EndFunc   ;==>_Tree_FixDepth

; ============================ public API ============================

; #FUNCTION# ====================================================================================================================
; Name ..........: Tree_Create
; Description ...: Creates a fresh tree with one root node, or resets the tree that is live.
; Syntax ........: Tree_Create([$sRootName = "root"[, $iInitialCap = 1024]])
; Parameters ....: $sRootName - name of the root node; "" leaves the root anonymous.
; Parameters ....: $iInitialCap - how many nodes you expect to hold. Rounded up to the next power of two, minimum 2.
; Return values .: Success - the capacity actually allocated, @error = $TREE_E_NONE.
; Return values .: Failure - impossible, this call always builds a tree.
; Author ........: Numeric1
; Remarks .......: Every array is reallocated, so this is the one call that frees what the previous tree held; the ids
;                  of the old tree mean nothing afterwards. Giving the expected size is not decoration: 100 000 nodes
;                  built from a 1 024 capacity cost 6 119 ms against 4 677 ms when the capacity was declared up front
;                  (Tree_Bench_grow.log).
; Related .......: Tree_Add, Tree_Import, Tree_Info, Tree_Capacity
; ===============================================================================================================================
Func Tree_Create($sRootName = "root", $iInitialCap = 1024)
	If $iInitialCap < 2 Then $iInitialCap = 2
	Local $iCap = 1
	While $iCap < $iInitialCap And $iCap < $g_iTrMaxSlots
		$iCap *= 2
	WEnd
	$g_iTrCap = $iCap
	; ReDim keeps previous contents, so a reset needs brand new arrays
	Local $aTmp[$iCap + 1]
	$g_aTrAlive = $aTmp
	$g_aTrParent = $aTmp
	$g_aTrChild1 = $aTmp
	$g_aTrTail = $aTmp
	$g_aTrNext = $aTmp
	$g_aTrPrev = $aTmp
	$g_aTrNKid = $aTmp
	$g_aTrDepth = $aTmp
	$g_aTrData = $aTmp
	$g_aTrName = $aTmp
	$g_aTrOrder = $aTmp
	$g_aTrPos = $aTmp
	$g_aTrSub = $aTmp
	$g_aTrStack = $aTmp
	Local $aFree[129]
	$g_aTrFree = $aFree
	$g_iTrFreeN = 0
	$g_iTrCount = 1
	$g_iTrLive = 1
	$g_iTrRoot = 1
	$g_iTrDirty = 0
	$g_bTrClean = True
	$g_iTrMaxDepth = 0
	Local $aEmpty[]
	$g_mTrName = $aEmpty
	$g_iTrNameStale = 0
	$g_aTrAlive[1] = 1
	$g_aTrDepth[1] = 0
	$g_aTrOrder[1] = 1
	$g_aTrPos[1] = 1
	$g_aTrSub[1] = 1
	$g_aTrName[1] = ""
	$g_aTrData[1] = ""
	If $sRootName <> "" Then
		$g_aTrName[1] = $sRootName
		If $g_bTrUseName Then $g_mTrName[$sRootName] = 1
	EndIf
	Return SetError($TREE_E_NONE, 0, $iCap)
EndFunc   ;==>Tree_Create

; #FUNCTION# ====================================================================================================================
; Name ..........: Tree_Root
; Description ...: The id of the root node.
; Syntax ........: Tree_Root()
; Parameters ....: none
; Return values .: Success - the root id, always 1, @error = $TREE_E_NONE.
; Return values .: Failure - 0 with @error = $TREE_E_STATE when no tree has been created.
; Author ........: Numeric1
; Remarks .......: The root id never changes for the life of the tree, so storing it buys nothing; it is here because
;                  Tree_Add needs a parent and reading the constant 1 in your code explains nothing.
; Related .......: Tree_Create, Tree_Parent, Tree_Count
; ===============================================================================================================================
Func Tree_Root()
	If $g_iTrRoot = 0 Then Return SetError($TREE_E_STATE, 0, 0)
	Return SetError($TREE_E_NONE, 0, $g_iTrRoot)
EndFunc   ;==>Tree_Root

; #FUNCTION# ====================================================================================================================
; Name ..........: Tree_Count
; Description ...: How many nodes are alive in the tree.
; Syntax ........: Tree_Count()
; Parameters ....: none
; Return values .: Success - the live node count, the root included. No error is possible.
; Author ........: Numeric1
; Remarks .......: This is one integer read, $g_iTrLive. Deleted ids are still counted by $g_iTrCount, which is the
;                  highest id ever handed out, and the two numbers part as soon as something is removed.
; Related .......: Tree_Capacity, Tree_Info, Tree_Remove
; ===============================================================================================================================
Func Tree_Count()
	Return $g_iTrLive
EndFunc   ;==>Tree_Count

; #FUNCTION# ====================================================================================================================
; Name ..........: Tree_Capacity
; Description ...: The highest node id the arrays can hold without growing.
; Syntax ........: Tree_Capacity()
; Parameters ....: none
; Return values .: Success - capacity in nodes, the power of two Tree_Create settled on. No error is possible.
; Author ........: Numeric1
; Remarks .......: Growth happens inside Tree_Add and copies every array, measured at 38.5 ms for a full 100 000-element
;                  array; the ceiling is $g_iTrMaxSlots, above which Tree_Add answers $TREE_E_MEM.
; Related .......: Tree_Create, Tree_Add, Tree_Info, Tree_Count
; ===============================================================================================================================
Func Tree_Capacity()
	Return $g_iTrCap
EndFunc   ;==>Tree_Capacity

; #FUNCTION# ====================================================================================================================
; Name ..........: Tree_IsClean
; Description ...: Whether the derived preorder index still matches the structure.
; Syntax ........: Tree_IsClean()
; Parameters ....: none
; Return values .: Success - 1 when the index is valid, 0 when it is stale, @error = $TREE_E_NONE.
; Author ........: Numeric1
; Remarks .......: Any add, move or remove sets it to 0 and it stays 0 until Tree_Rebuild runs. While it is 0,
;                  Tree_SubtreeSize and the subtree path of Tree_Remove walk instead of reading, which is correct and
;                  slower; nothing in the UDF gives a wrong answer because the flag is 0.
; Related .......: Tree_Rebuild, Tree_SubtreeSize, Tree_Remove
; ===============================================================================================================================
Func Tree_IsClean()
	Return SetError($TREE_E_NONE, 0, $g_bTrClean ? 1 : 0)
EndFunc   ;==>Tree_IsClean

; #FUNCTION# ====================================================================================================================
; Name ..........: Tree_NameStale
; Description ...: How many keys the name index still holds for nodes that are gone or renamed.
; Syntax ........: Tree_NameStale()
; Parameters ....: none
; Return values .: Success - the stale key count, @error = $TREE_E_NONE. 0 after Tree_CompactNames.
; Author ........: Numeric1
; Remarks .......: An upper bound, not a diagnosis. A stale key is harmless: Tree_Find verifies what it reads and drops
;                  the key on the spot. The number exists so you can decide when to pay one rebuild pass instead of
;                  leaving the healing to the lookups.
; Related .......: Tree_CompactNames, Tree_Find, Tree_UseNameIndex
; ===============================================================================================================================
Func Tree_NameStale()
	Return SetError($TREE_E_NONE, 0, $g_iTrNameStale)
EndFunc   ;==>Tree_NameStale

; #FUNCTION# ====================================================================================================================
; Name ..........: Tree_CompactNames
; Description ...: Rebuilds the name index from the live nodes, dropping every stale key in one pass.
; Syntax ........: Tree_CompactNames()
; Parameters ....: none
; Return values .: Success - the number of live names now in the index, @error = $TREE_E_NONE.
; Return values .: Failure - 0 with @error = $TREE_E_STATE when no tree has been created, or with the index switched off
;                  returns 0 and $TREE_E_NONE.
; Author ........: Numeric1
; Remarks .......: Pays for itself after a bulk delete and before a long run of Tree_Find calls on a tree that lost many
;                  names. The purge is a reassignment, never a MapRemove loop: 5.5 ms against 509 ms for 20 000 keys
;                  (Tree_CostProbe.log).
; Related .......: Tree_NameStale, Tree_Find, Tree_UseNameIndex, Tree_Remove
; ===============================================================================================================================
Func Tree_CompactNames()
	If $g_iTrRoot = 0 Then Return SetError($TREE_E_STATE, 0, 0)
	If Not $g_bTrUseName Then Return SetError($TREE_E_NONE, 0, 0)
	Return SetError($TREE_E_NONE, 0, _Tree_NameReindex())
EndFunc   ;==>Tree_CompactNames

; #FUNCTION# ====================================================================================================================
; Name ..........: Tree_UseNameIndex
; Description ...: Turns the name index on or off.
; Syntax ........: Tree_UseNameIndex([$bEnable = True])
; Parameters ....: $bEnable - True keeps the index, False throws it away.
; Return values .: Success - the setting after the call (1 on, 0 off), @extended the setting before the call.
; Return values .: Failure - impossible.
; Author ........: Numeric1
; Remarks .......: With the index off, Tree_Find answers $TREE_E_ARG and any add or rename that carries a name refuses
;                  with $TREE_E_ARG; anonymous nodes are untouched. Above roughly 50 000 named nodes the index is the
;                  slower choice, because every Map operation grows with the key count - 21 us for an insert at 100 000
;                  keys against 2 us at 10 000 (Tree_CostProbe.log).
; Related .......: Tree_Find, Tree_Add, Tree_SetName, Tree_NameStale
; ===============================================================================================================================
Func Tree_UseNameIndex($bEnable = True)
	Local $bOld = $g_bTrUseName
	$g_bTrUseName = ($bEnable <> 0)
	If $g_bTrUseName = $bOld Then Return SetError($TREE_E_NONE, $bOld ? 1 : 0, $bOld ? 1 : 0)
	_Tree_NameReindex()
	Return SetError($TREE_E_NONE, $bOld ? 1 : 0, $g_bTrUseName ? 1 : 0)
EndFunc   ;==>Tree_UseNameIndex

; #FUNCTION# ====================================================================================================================
; Name ..........: Tree_Add
; Description ...: Appends one node under a parent and returns its id.
; Syntax ........: Tree_Add($iParent[, $vData = ""[, $sName = ""]])
; Parameters ....: $iParent - id of the node that will own the new one.
; Parameters ....: $vData - the payload. Any AutoIt value; the UDF never reads it and never converts it.
; Parameters ....: $sName - optional name, unique in the whole tree. "" makes the node anonymous.
; Return values .: Success - the new node id, @error = $TREE_E_NONE.
; Return values .: Failure - 0 with @error = $TREE_E_STATE (no tree), $TREE_E_NODE (bad parent), $TREE_E_NAME (the name
;                  is taken), $TREE_E_ARG (a name given while the index is off) or $TREE_E_MEM (ceiling reached).
; Author ........: Numeric1
; Remarks .......: Children keep insertion order; nothing is sorted anywhere in this UDF. The preorder index goes stale
;                  on every add. The name index is not edited on this path beyond one Map assignment, so the price of an
;                  add does not depend on how many names the tree holds.
; Related .......: Tree_AddPath, Tree_Remove, Tree_Move, Tree_NChildren, Tree_SetData
; ===============================================================================================================================
Func Tree_Add($iParent, $vData = "", $sName = "")
	If $g_iTrRoot = 0 Then Return SetError($TREE_E_STATE, 0, 0)
	If Not _Tree_Ok($iParent) Then Return SetError($TREE_E_NODE, 0, 0)
	If $sName <> "" Then
		If Not $g_bTrUseName Then Return SetError($TREE_E_ARG, 0, 0)
		If _Tree_NameTaken($sName) Then Return SetError($TREE_E_NAME, 0, 0)
	EndIf
	Local $iId = _Tree_Alloc()
	If $iId = 0 Then Return SetError($TREE_E_MEM, 0, 0)
	$g_aTrAlive[$iId] = 1
	$g_aTrNKid[$iId] = 0
	$g_aTrChild1[$iId] = 0
	$g_aTrTail[$iId] = 0
	$g_aTrData[$iId] = $vData
	$g_aTrName[$iId] = $sName
	$g_aTrPos[$iId] = 0
	$g_aTrSub[$iId] = 0
	$g_iTrLive += 1
	$g_aTrDepth[$iId] = $g_aTrDepth[$iParent] + 1
	If $g_aTrDepth[$iId] > $g_iTrMaxDepth Then $g_iTrMaxDepth = $g_aTrDepth[$iId]
	_Tree_Link($iId, $iParent)
	If $sName <> "" Then $g_mTrName[$sName] = $iId
	$g_iTrDirty += 1
	$g_bTrClean = False
	Return SetError($TREE_E_NONE, 0, $iId)
EndFunc   ;==>Tree_Add

; #FUNCTION# ====================================================================================================================
; Name ..........: Tree_AddPath
; Description ...: Walks a separator-delimited chain of names from the root, creating the segments that are missing.
; Syntax ........: Tree_AddPath($sPath[, $sSep = "\"[, $vData = ""]])
; Parameters ....: $sPath - the chain, as "home\carol\docs".
; Parameters ....: $sSep - the separator. A name that contains it cannot be reached through this call.
; Parameters ....: $vData - payload for the last segment only; the segments above stay empty.
; Return values .: Success - the id of the last segment, @extended = 1 when every segment already existed and nothing
;                  was created.
; Return values .: Failure - 0 with @error = $TREE_E_STATE, $TREE_E_ARG (empty path or separator), $TREE_E_NODE,
;                  $TREE_E_NAME, $TREE_E_MEM.
; Author ........: Numeric1
; Remarks .......: A segment is matched by name among the children of the current node, so the same name may live under
;                  two different parents; it is the whole chain that has to be unique, not each piece. Each missing
;                  segment is one Tree_Add, so the index goes stale exactly as it would for adds.
; Related .......: Tree_Add, Tree_PathTo, Tree_Find, Tree_Children
; ===============================================================================================================================
Func Tree_AddPath($sPath, $sSep = "\", $vData = "")
	If $g_iTrRoot = 0 Then Return SetError($TREE_E_STATE, 0, 0)
	If $sPath = "" Or $sSep = "" Then Return SetError($TREE_E_ARG, 0, 0)
	Local $a, $k, $iCur = $g_iTrRoot, $bExact = True
	$a = StringSplit($sPath, $sSep, 1)
	If @error Then
		; delimiter absent: the whole path is one segment
		$iCur = _Tree_Step($iCur, $sPath, $vData)
		If @error Then Return SetError(@error, @extended, 0)
		Return SetError($TREE_E_NONE, @extended = 0 ? 1 : 0, $iCur)
	EndIf
	For $k = 1 To $a[0]
		If $a[$k] = "" Then ContinueLoop
		Local $iFound = _Tree_Step($iCur, $a[$k], ($k = $a[0]) ? $vData : "")
		If @error Then Return SetError(@error, @extended, 0)
		If @extended Then $bExact = False
		$iCur = $iFound
	Next
	Return SetError($TREE_E_NONE, $bExact ? 1 : 0, $iCur)
EndFunc   ;==>Tree_AddPath

; One AddPath segment: returns the child id, @extended 1 when it was created.
Func _Tree_Step($iParent, $sName, $vData)
	Local $c = $g_aTrChild1[$iParent]
	While $c <> 0
		If $g_aTrName[$c] = $sName Then Return SetError($TREE_E_NONE, 0, $c)
		$c = $g_aTrNext[$c]
	WEnd
	Local $iNew = Tree_Add($iParent, $vData, $sName)
	If @error Then Return SetError(@error, @extended, 0)
	Return SetError($TREE_E_NONE, 1, $iNew)
EndFunc   ;==>_Tree_Step

; #FUNCTION# ====================================================================================================================
; Name ..........: Tree_SetData
; Description ...: Writes the payload slot of a node.
; Syntax ........: Tree_SetData($iNode, $vData)
; Parameters ....: $iNode - the node to write.
; Parameters ....: $vData - any value. The tree stores it untouched and never reads it.
; Return values .: Success - the value the node held before, @error = $TREE_E_NONE.
; Return values .: Failure - "" with @error = $TREE_E_NODE.
; Author ........: Numeric1
; Remarks .......: Nothing is indexed and nothing is marked stale: the payload is invisible to every structure in the
;                  UDF, which is why writing it costs one array assignment.
; Related .......: Tree_GetData, Tree_Add
; ===============================================================================================================================
Func Tree_SetData($iNode, $vData)
	If Not _Tree_Ok($iNode) Then Return SetError($TREE_E_NODE, 0, "")
	Local $vOld = $g_aTrData[$iNode]
	$g_aTrData[$iNode] = $vData
	Return SetError($TREE_E_NONE, 0, $vOld)
EndFunc   ;==>Tree_SetData

; #FUNCTION# ====================================================================================================================
; Name ..........: Tree_GetData
; Description ...: Reads the payload slot of a node.
; Syntax ........: Tree_GetData($iNode)
; Parameters ....: $iNode - the node to read.
; Return values .: Success - the value stored, @error = $TREE_E_NONE.
; Return values .: Failure - "" with @error = $TREE_E_NODE.
; Author ........: Numeric1
; Remarks .......: A node added without data holds "", so an empty answer is not proof that the payload was cleared.
; Related .......: Tree_SetData, Tree_Add
; ===============================================================================================================================
Func Tree_GetData($iNode)
	If Not _Tree_Ok($iNode) Then Return SetError($TREE_E_NODE, 0, "")
	Return SetError($TREE_E_NONE, 0, $g_aTrData[$iNode])
EndFunc   ;==>Tree_GetData

; #FUNCTION# ====================================================================================================================
; Name ..........: Tree_SetName
; Description ...: Names a node, renames it, or makes it anonymous.
; Syntax ........: Tree_SetName($iNode[, $sName = ""])
; Parameters ....: $iNode - the node to rename.
; Parameters ....: $sName - the new name, unique in the tree; "" makes the node anonymous.
; Return values .: Success - 1, @extended = 1 when the node already carried that name and nothing moved.
; Return values .: Failure - 0 with @error = $TREE_E_NODE, $TREE_E_NAME (the name belongs to another node, @extended
;                  then holds that node's id) or $TREE_E_ARG (a name given while the index is off).
; Author ........: Numeric1
; Remarks .......: The key the old name left behind is not removed here, it is counted as stale - that is the whole
;                  design of the index and the reason deleting a named subtree costs 65 us per node instead of the 121
;                  us the per-delete MapRemove version paid (Tree_Bench.log). See Tree_NameStale.
; Related .......: Tree_Name, Tree_Find, Tree_NameStale, Tree_CompactNames, Tree_Add
; ===============================================================================================================================
Func Tree_SetName($iNode, $sName)
	If Not _Tree_Ok($iNode) Then Return SetError($TREE_E_NODE, 0, 0)
	Local $sOld = $g_aTrName[$iNode], $iOwner
	If $sOld = $sName Then Return SetError($TREE_E_NONE, 1, 1)
	If $sName <> "" Then
		If Not $g_bTrUseName Then Return SetError($TREE_E_ARG, 0, 0)
		If MapExists($g_mTrName, $sName) Then
			$iOwner = _Tree_NameLive($sName)
			If $iOwner <> 0 Then Return SetError($TREE_E_NAME, $iOwner, 0)
		EndIf
		$g_aTrName[$iNode] = $sName
		If $sOld <> "" Then $g_iTrNameStale += 1
		$g_mTrName[$sName] = $iNode
	Else
		$g_aTrName[$iNode] = ""
		If $g_bTrUseName And $sOld <> "" Then $g_iTrNameStale += 1
	EndIf
	Return SetError($TREE_E_NONE, 0, 1)
EndFunc   ;==>Tree_SetName

; #FUNCTION# ====================================================================================================================
; Name ..........: Tree_Name
; Description ...: The name of a node, "" when the node is anonymous.
; Syntax ........: Tree_Name($iNode)
; Parameters ....: $iNode - the node to read.
; Return values .: Success - the name, @error = $TREE_E_NONE.
; Return values .: Failure - "" with @error = $TREE_E_NODE.
; Author ........: Numeric1
; Remarks .......: Names are compared case-sensitively, because the index is a Map keyed by the exact string. The root
;                  is a node like any other and can carry a name.
; Related .......: Tree_SetName, Tree_Find
; ===============================================================================================================================
Func Tree_Name($iNode)
	If Not _Tree_Ok($iNode) Then Return SetError($TREE_E_NODE, 0, "")
	Return SetError($TREE_E_NONE, 0, $g_aTrName[$iNode])
EndFunc   ;==>Tree_Name

; #FUNCTION# ====================================================================================================================
; Name ..........: Tree_Parent
; Description ...: The id of the parent of a node.
; Syntax ........: Tree_Parent($iNode)
; Parameters ....: $iNode - the node to ask about.
; Return values .: Success - the parent id, 0 for the root, @error = $TREE_E_NONE.
; Return values .: Failure - 0 with @error = $TREE_E_NODE.
; Author ........: Numeric1
; Remarks .......: One array read, $g_aTrParent[$iNode]. Inside a loop that touches every node, read that global: the
;                  API call around the same read costs about three times as much, 15.7 us against 5.4 us for 200 000
;                  reads of 20 000 nodes (Tree_Bench.log).
; Related .......: Tree_Children, Tree_FirstChild, Tree_PathTo, Tree_IsAncestor, Tree_Depth
; ===============================================================================================================================
Func Tree_Parent($iNode)
	If Not _Tree_Ok($iNode) Then Return SetError($TREE_E_NODE, 0, 0)
	Return SetError($TREE_E_NONE, 0, $g_aTrParent[$iNode])
EndFunc   ;==>Tree_Parent

; #FUNCTION# ====================================================================================================================
; Name ..........: Tree_Depth
; Description ...: How many parents stand above a node; the root is 0.
; Syntax ........: Tree_Depth($iNode)
; Parameters ....: $iNode - the node to measure.
; Return values .: Success - the depth, @error = $TREE_E_NONE.
; Return values .: Failure - -1 with @error = $TREE_E_NODE.
; Author ........: Numeric1
; Remarks .......: Stored, not computed. Tree_Move recomputes the depth of the whole moved subtree as it re-parents, so
;                  the stored value stays exact after a re-parent; the deepest node seen so far is
;                  Tree_Info("maxdepth").
; Related .......: Tree_PathTo, Tree_IsAncestor, Tree_Info
; ===============================================================================================================================
Func Tree_Depth($iNode)
	If Not _Tree_Ok($iNode) Then Return SetError($TREE_E_NODE, 0, -1)
	; stored depth is exact for a node whose subtree has not been re-parented;
	; after a move it is recomputed eagerly, so the array is authoritative
	Return SetError($TREE_E_NONE, 0, $g_aTrDepth[$iNode])
EndFunc   ;==>Tree_Depth

; #FUNCTION# ====================================================================================================================
; Name ..........: Tree_NChildren
; Description ...: How many children a node has.
; Syntax ........: Tree_NChildren($iNode)
; Parameters ....: $iNode - the node to measure.
; Return values .: Success - the child count, 0 for a leaf, @error = $TREE_E_NONE.
; Return values .: Failure - -1 with @error = $TREE_E_NODE.
; Author ........: Numeric1
; Remarks .......: Stored per node, so the answer does not depend on how wide the node is. Use Tree_Children when you
;                  want the ids as well.
; Related .......: Tree_Children, Tree_FirstChild, Tree_Add
; ===============================================================================================================================
Func Tree_NChildren($iNode)
	If Not _Tree_Ok($iNode) Then Return SetError($TREE_E_NODE, 0, -1)
	Return SetError($TREE_E_NONE, 0, $g_aTrNKid[$iNode])
EndFunc   ;==>Tree_NChildren

; #FUNCTION# ====================================================================================================================
; Name ..........: Tree_Children
; Description ...: Fills a 1-based array with the children of a node, in insertion order.
; Syntax ........: Tree_Children($iNode, ByRef $aOut)
; Parameters ....: $iNode - the node to read.
; Parameters ....: $aOut - array variable passed by reference; resized to count + 1 and filled from index 1.
; Return values .: Success - the number of children written, @error = $TREE_E_NONE.
; Return values .: Failure - 0 with @error = $TREE_E_NODE, or $TREE_E_ARG when the sibling chain and the stored count
;                  disagreed (@extended = what the chain gave), or $TREE_E_CYCLE when the chain is longer than the tree.
; Author ........: Numeric1
; Remarks .......: $aOut[0] is not the count - the count is the return value. The chain is walked twice: once to prove
;                  its length, once to write it, so a corrupted structure cannot hang the caller or overflow the array.
; Related .......: Tree_NChildren, Tree_FirstChild, Tree_NextSibling, Tree_SubtreeSize
; ===============================================================================================================================
Func Tree_Children($iNode, ByRef $aOut)
	If Not _Tree_Ok($iNode) Then Return SetError($TREE_E_NODE, 0, 0)
	Local $n = $g_aTrNKid[$iNode], $i = 0, $c = $g_aTrChild1[$iNode]
	While $c <> 0
		$i += 1
		$c = $g_aTrNext[$c]
		; a corrupted chain must not hang the caller
		If $i > $n And $i > $g_iTrLive Then Return SetError($TREE_E_CYCLE, $i, 0)
	WEnd
	If $i <> $n Then Return SetError($TREE_E_ARG, $i, 0)
	If Not IsArray($aOut) Or UBound($aOut) <> $n + 1 Then ReDim $aOut[$n + 1]
	$c = $g_aTrChild1[$iNode]
	$i = 0
	While $c <> 0
		$i += 1
		$aOut[$i] = $c
		$c = $g_aTrNext[$c]
	WEnd
	Return SetError($TREE_E_NONE, 0, $n)
EndFunc   ;==>Tree_Children

; #FUNCTION# ====================================================================================================================
; Name ..........: Tree_FirstChild
; Description ...: The first child of a node, the head of its sibling chain.
; Syntax ........: Tree_FirstChild($iNode)
; Parameters ....: $iNode - the node to read.
; Return values .: Success - the child id, 0 when the node is childless, @error = $TREE_E_NONE.
; Return values .: Failure - 0 with @error = $TREE_E_NODE.
; Author ........: Numeric1
; Remarks .......: Pair it with Tree_NextSibling or $g_aTrNext to walk a node's children without allocating an array -
;                  the shape Tree_Walk and Tree_Rebuild use internally.
; Related .......: Tree_NextSibling, Tree_Children, Tree_NChildren
; ===============================================================================================================================
Func Tree_FirstChild($iNode)
	If Not _Tree_Ok($iNode) Then Return SetError($TREE_E_NODE, 0, 0)
	Return SetError($TREE_E_NONE, 0, $g_aTrChild1[$iNode])
EndFunc   ;==>Tree_FirstChild

; #FUNCTION# ====================================================================================================================
; Name ..........: Tree_NextSibling
; Description ...: The next child of the same parent.
; Syntax ........: Tree_NextSibling($iNode)
; Parameters ....: $iNode - the node to read.
; Return values .: Success - the sibling id, 0 at the end of the chain, @error = $TREE_E_NONE.
; Return values .: Failure - 0 with @error = $TREE_E_NODE.
; Author ........: Numeric1
; Remarks .......: The root has no siblings. The order is insertion order, not sorted order; sorting is yours, on the
;                  array Tree_Children fills.
; Related .......: Tree_FirstChild, Tree_Children
; ===============================================================================================================================
Func Tree_NextSibling($iNode)
	If Not _Tree_Ok($iNode) Then Return SetError($TREE_E_NODE, 0, 0)
	Return SetError($TREE_E_NONE, 0, $g_aTrNext[$iNode])
EndFunc   ;==>Tree_NextSibling

; #FUNCTION# ====================================================================================================================
; Name ..........: Tree_IsAncestor
; Description ...: Whether one node stands above another in the tree.
; Syntax ........: Tree_IsAncestor($iAnc, $iNode[, $bIncludeSelf = False])
; Parameters ....: $iAnc - the node suspected of being above.
; Parameters ....: $iNode - the node to test.
; Parameters ....: $bIncludeSelf - True answers 1 when both ids name the same node.
; Return values .: Success - 1 or 0, @error = $TREE_E_NONE.
; Return values .: Failure - 0 with @error = $TREE_E_NODE when either id is unknown.
; Author ........: Numeric1
; Remarks .......: Climbs the parent chain from $iNode, so the price is the depth of that node, not the size of the
;                  tree. Tree_Move uses the same climb to refuse a move that would create a cycle.
; Related .......: Tree_Parent, Tree_PathTo, Tree_Move, Tree_AddPath
; ===============================================================================================================================
Func Tree_IsAncestor($iAnc, $iNode, $bIncludeSelf = False)
	If Not _Tree_Ok($iAnc) Or Not _Tree_Ok($iNode) Then Return SetError($TREE_E_NODE, 0, 0)
	Local $c = $iNode
	If Not $bIncludeSelf Then $c = $g_aTrParent[$c]
	While $c <> 0
		If $c = $iAnc Then Return SetError($TREE_E_NONE, 0, 1)
		$c = $g_aTrParent[$c]
	WEnd
	Return SetError($TREE_E_NONE, 0, 0)
EndFunc   ;==>Tree_IsAncestor

; #FUNCTION# ====================================================================================================================
; Name ..........: Tree_Find
; Description ...: The node that carries a name.
; Syntax ........: Tree_Find($sName)
; Parameters ....: $sName - the exact name; the comparison is case-sensitive.
; Return values .: Success - the node id, @error = $TREE_E_NONE.
; Return values .: Failure - 0 with @error = $TREE_E_NODE (no such name), $TREE_E_ARG (empty name, or the index is
;                  switched off) or $TREE_E_STATE (no tree).
; Author ........: Numeric1
; Remarks .......: A Map read, not a scan: 34.7 us for one name among 20 000 nodes, against 54.8 ms for the scan-every-
;                  node idiom on the same machine and run (Tree_Bench.log). The answer is verified against the node
;                  before it is handed back, so a key left by a delete or a rename reads as absent and is dropped on the
;                  spot - that verification is the second half of the lazy index.
; Related .......: Tree_Name, Tree_SetName, Tree_NameStale, Tree_CompactNames, Tree_UseNameIndex
; ===============================================================================================================================
Func Tree_Find($sName)
	If $g_iTrRoot = 0 Then Return SetError($TREE_E_STATE, 0, 0)
	If $sName = "" Then Return SetError($TREE_E_ARG, 0, 0)
	If Not $g_bTrUseName Then Return SetError($TREE_E_ARG, 0, 0)
	If Not MapExists($g_mTrName, $sName) Then Return SetError($TREE_E_NODE, 0, 0)
	Local $i = _Tree_NameLive($sName)
	If $i = 0 Then Return SetError($TREE_E_NODE, 0, 0)
	Return SetError($TREE_E_NONE, 0, $i)
EndFunc   ;==>Tree_Find

; #FUNCTION# ====================================================================================================================
; Name ..........: Tree_Remove
; Description ...: Deletes a node, with three different promises about its children.
; Syntax ........: Tree_Remove($iNode[, $iMode = 0])
; Parameters ....: $iNode - the node to delete; the root cannot be.
; Parameters ....: $iMode - 0 refuses when the node has at least one child, 1 promotes the direct children to the
;                  grandparent in order, 2 deletes the node and its whole subtree.
; Return values .: Success - the number of nodes removed, @error = $TREE_E_NONE.
; Return values .: Failure - 0 with @error = $TREE_E_STATE, $TREE_E_NODE, $TREE_E_ARG (the root, or a mode outside 0 to
;                  2) or $TREE_E_NOTEMPTY (@extended = the child count that made mode 0 refuse).
; Author ........: Numeric1
; Remarks .......: Freed ids go back to a LIFO list and are usually the next ones Tree_Add hands out, so a stored id is
;                  only trustworthy until the next delete. Empty a tree with Tree_Create, never by removing the root.
;                  The name index is not edited on this path: the keys of the dead nodes become stale, which is what
;                  keeps the delete at 65 us per node.
; Related .......: Tree_Move, Tree_SubtreeSize, Tree_NameStale, Tree_CompactNames, Tree_Create
; ===============================================================================================================================
Func Tree_Remove($iNode, $iMode = 0)
	If $g_iTrRoot = 0 Then Return SetError($TREE_E_STATE, 0, 0)
	If Not _Tree_Ok($iNode) Then Return SetError($TREE_E_NODE, 0, 0)
	If $iNode = $g_iTrRoot Then Return SetError($TREE_E_ARG, 0, 0)
	Local $n = 1, $k, $c
	If $iMode = 0 And $g_aTrNKid[$iNode] > 0 Then Return SetError($TREE_E_NOTEMPTY, $g_aTrNKid[$iNode], 0)
	If $iMode <> 0 And $iMode <> 1 And $iMode <> 2 Then Return SetError($TREE_E_ARG, 0, 0)
	Local $bUseRange = $g_bTrClean
	$g_bTrClean = False
	$g_iTrDirty += 1
	If $iMode = 0 Then
		_Tree_Unlink($iNode)
		_Tree_Clear($iNode)
	ElseIf $iMode = 1 Then
		Local $iG = $g_aTrParent[$iNode]
		Local $aKid[$g_aTrNKid[$iNode] + 1], $nKid = 0
		$c = $g_aTrChild1[$iNode]
		While $c <> 0
			$nKid += 1
			$aKid[$nKid] = $c
			$c = $g_aTrNext[$c]
		WEnd
		; every unlink rewires the sibling chain and decrements the child count,
		; so $iNode ends up childless without touching its slots first
		For $k = 1 To $nKid
			_Tree_Unlink($aKid[$k])
			_Tree_Link($aKid[$k], $iG)
		Next
		For $k = 1 To $nKid
			_Tree_FixDepth($aKid[$k])
		Next
		_Tree_Unlink($iNode)
		_Tree_Clear($iNode)
	ElseIf $iMode = 2 Then
		_Tree_Unlink($iNode)
		$n = _Tree_ClearSubtree($iNode, $bUseRange)
	EndIf
	Return SetError($TREE_E_NONE, 0, $n)
EndFunc   ;==>Tree_Remove

; #FUNCTION# ====================================================================================================================
; Name ..........: Tree_Move
; Description ...: Re-parents a node and its whole subtree.
; Syntax ........: Tree_Move($iNode, $iNewParent)
; Parameters ....: $iNode - the node to move; the root cannot be.
; Parameters ....: $iNewParent - the node that will own it. Anywhere in the tree is allowed, including a descendant's
;                  sibling - but not a descendant itself.
; Return values .: Success - 1, @extended = 1 when the node was already a child of that parent and nothing moved.
; Return values .: Failure - 0 with @error = $TREE_E_STATE, $TREE_E_NODE, $TREE_E_ARG (the root) or $TREE_E_CYCLE (the
;                  target is the node itself or one of its descendants).
; Author ........: Numeric1
; Remarks .......: The depth of every node in the moved subtree is recomputed on the spot, which is the O(subtree) part
;                  of the call; the preorder index is left stale for one Tree_Rebuild to fix. Moving a big subtree is
;                  therefore not free, and the stored depth of the moved nodes is exact immediately.
; Related .......: Tree_Add, Tree_Remove, Tree_IsAncestor, Tree_Rebuild, Tree_Depth
; ===============================================================================================================================
Func Tree_Move($iNode, $iNewParent)
	If $g_iTrRoot = 0 Then Return SetError($TREE_E_STATE, 0, 0)
	If Not _Tree_Ok($iNode) Or Not _Tree_Ok($iNewParent) Then Return SetError($TREE_E_NODE, 0, 0)
	If $iNode = $g_iTrRoot Then Return SetError($TREE_E_ARG, 0, 0)
	If $iNode = $iNewParent Then Return SetError($TREE_E_CYCLE, 0, 0)
	If $g_aTrParent[$iNode] = $iNewParent Then Return SetError($TREE_E_NONE, 1, 1)
	Local $c = $iNewParent
	While $c <> 0
		If $c = $iNode Then Return SetError($TREE_E_CYCLE, 0, 0)
		$c = $g_aTrParent[$c]
	WEnd
	$g_bTrClean = False
	$g_iTrDirty += 1
	_Tree_Unlink($iNode)
	_Tree_Link($iNode, $iNewParent)
	_Tree_FixDepth($iNode)
	Return SetError($TREE_E_NONE, 0, 1)
EndFunc   ;==>Tree_Move

; #FUNCTION# ====================================================================================================================
; Name ..........: Tree_SubtreeSize
; Description ...: How many nodes are under a node, counting the node itself.
; Syntax ........: Tree_SubtreeSize($iNode)
; Parameters ....: $iNode - the root of the subtree to count.
; Return values .: Success - the count, @extended telling how it was obtained: 1 = read from a clean index in O(1), 2 =
;                  the subtree was walked because the index is stale.
; Return values .: Failure - 0 with @error = $TREE_E_NODE.
; Author ........: Numeric1
; Remarks .......: Measured 14.8 us per query against 125 us for the recursive count of the object idiom, on a clean
;                  index (Tree_Bench.log). The walk uses the shared scratch stack, which is why this call must not be
;                  made from a Tree_Walk callback.
; Related .......: Tree_IsClean, Tree_Rebuild, Tree_Remove, Tree_Children
; ===============================================================================================================================
Func Tree_SubtreeSize($iNode)
	If Not _Tree_Ok($iNode) Then Return SetError($TREE_E_NODE, 0, 0)
	If $g_bTrClean Then Return SetError($TREE_E_NONE, 1, $g_aTrSub[$iNode])
	Local $i = 0, $iTop = 1, $c, $cur
	$g_aTrStack[1] = $iNode
	While $iTop > 0
		$cur = $g_aTrStack[$iTop]
		$iTop -= 1
		$i += 1
		$c = $g_aTrChild1[$cur]
		While $c <> 0
			$iTop += 1
			$g_aTrStack[$iTop] = $c
			$c = $g_aTrNext[$c]
		WEnd
	WEnd
	Return SetError($TREE_E_NONE, 2, $i)
EndFunc   ;==>Tree_SubtreeSize

; #FUNCTION# ====================================================================================================================
; Name ..........: Tree_Rebuild
; Description ...: Recomputes the derived preorder index in one pass over the tree.
; Syntax ........: Tree_Rebuild()
; Parameters ....: none
; Return values .: Success - the number of reachable nodes, @error = $TREE_E_NONE.
; Return values .: Failure - 0 with @error = $TREE_E_STATE when no tree has been created.
; Author ........: Numeric1
; Remarks .......: Fills $g_aTrOrder, $g_aTrPos and $g_aTrSub and clears the dirty counter. It walks with the left-
;                  child/next-sibling cursor, so it needs no scratch stack and no memory proportional to the widest
;                  node. About 14 us per node measured; the mistake to avoid is calling it after every single change
;                  instead of once at the end of a batch.
; Related .......: Tree_IsClean, Tree_SubtreeSize, Tree_Add, Tree_Move, Tree_Remove
; ===============================================================================================================================
Func Tree_Rebuild()
	If $g_iTrRoot = 0 Then Return SetError($TREE_E_STATE, 0, 0)
	If UBound($g_aTrOrder) < $g_iTrCap + 1 Then _Tree_ReDim($g_iTrCap)
	Local $i = 0, $k, $cur = $g_iTrRoot, $c
	$g_iTrMaxDepth = 0
	While $cur <> 0
		$i += 1
		$g_aTrOrder[$i] = $cur
		$g_aTrPos[$cur] = $i
		$g_aTrSub[$cur] = 1
		If $g_aTrDepth[$cur] > $g_iTrMaxDepth Then $g_iTrMaxDepth = $g_aTrDepth[$cur]
		$c = $g_aTrChild1[$cur]
		If $c <> 0 Then
			$cur = $c
		Else
			While $cur <> 0 And $g_aTrNext[$cur] = 0
				$cur = $g_aTrParent[$cur]
			WEnd
			If $cur <> 0 Then $cur = $g_aTrNext[$cur]
		EndIf
	WEnd
	For $k = $i To 1 Step -1
		$cur = $g_aTrOrder[$k]
		$c = $g_aTrChild1[$cur]
		While $c <> 0
			$g_aTrSub[$cur] += $g_aTrSub[$c]
			$c = $g_aTrNext[$c]
		WEnd
	Next
	$g_bTrClean = True
	$g_iTrDirty = 0
	Return SetError($TREE_E_NONE, 0, $i)
EndFunc   ;==>Tree_Rebuild

; #FUNCTION# ====================================================================================================================
; Name ..........: Tree_Walk
; Description ...: Visits every node of a subtree in preorder through a callback.
; Syntax ........: Tree_Walk($iFunc[, $iNode = 0])
; Parameters ....: $iFunc - name of a top-level function, called as $iFunc($iNode). AutoIt cannot call a function
;                  declared inside another one.
; Parameters ....: $iNode - subtree to walk; 0 walks the whole tree from the root.
; Return values .: Success - the number of nodes visited, @error = $TREE_E_NONE.
; Return values .: Failure - 0 with @error = $TREE_E_STATE, $TREE_E_NODE or $TREE_E_ARG (the callback could not be
;                  called at all). When the callback returns a negative number the walk stops early and returns that
;                  value with @extended = the nodes visited, @error still $TREE_E_NONE.
; Author ........: Numeric1
; Remarks .......: Children are visited in insertion order. The walk does not use the preorder index, so it is correct
;                  on a stale index and costs nothing extra. A callback that changes the shape - Tree_Rebuild,
;                  Tree_Remove, Tree_SubtreeSize, Tree_Validate, Tree_Move - shares the scratch stack with the walk and
;                  corrupts it: keep callbacks read-only.
; Related .......: Tree_Children, Tree_FirstChild, Tree_NextSibling, Tree_SubtreeSize
; ===============================================================================================================================
Func Tree_Walk($iFunc, $iNode = 0)
	If $g_iTrRoot = 0 Then Return SetError($TREE_E_STATE, 0, 0)
	If $iNode = 0 Then $iNode = $g_iTrRoot
	If Not _Tree_Ok($iNode) Then Return SetError($TREE_E_NODE, 0, 0)
	If Not IsString($iFunc) Or $iFunc = "" Then Return SetError($TREE_E_ARG, 0, 0)
	Local $i = 0, $cur = $iNode, $c, $r
	While $cur <> 0
		$i += 1
		$r = Call($iFunc, $cur)
		If @error Then Return SetError($TREE_E_ARG, $i, 0)
		If $r < 0 Then Return SetError($TREE_E_NONE, $i, $r)
		$c = $g_aTrChild1[$cur]
		If $c <> 0 Then
			$cur = $c
		Else
			While $cur <> $iNode And $cur <> 0 And $g_aTrNext[$cur] = 0
				$cur = $g_aTrParent[$cur]
			WEnd
			If $cur = $iNode Or $cur = 0 Then ExitLoop
			$cur = $g_aTrNext[$cur]
		EndIf
	WEnd
	Return SetError($TREE_E_NONE, 0, $i)
EndFunc   ;==>Tree_Walk

; #FUNCTION# ====================================================================================================================
; Name ..........: Tree_PathTo
; Description ...: The nodes from the root down to a node, written to a 1-based array.
; Syntax ........: Tree_PathTo($iNode, ByRef $aOut)
; Parameters ....: $iNode - the node to trace.
; Parameters ....: $aOut - array variable passed by reference; resized to steps + 1, $aOut[1] the root, $aOut[$n] the
;                  node itself.
; Return values .: Success - the number of steps written, @error = $TREE_E_NONE.
; Return values .: Failure - 0 with @error = $TREE_E_NODE.
; Author ........: Numeric1
; Remarks .......: The reverse of Tree_AddPath: this one reads a chain of names, that one writes it. Climbs the parent
;                  chain, so the cost is the depth of the node.
; Related .......: Tree_AddPath, Tree_Parent, Tree_Depth, Tree_IsAncestor
; ===============================================================================================================================
Func Tree_PathTo($iNode, ByRef $aOut)
	If Not _Tree_Ok($iNode) Then Return SetError($TREE_E_NODE, 0, 0)
	Local $n = 0, $k, $c = $iNode
	While $c <> 0
		$n += 1
		$c = $g_aTrParent[$c]
	WEnd
	If Not IsArray($aOut) Or UBound($aOut) <> $n + 1 Then ReDim $aOut[$n + 1]
	$c = $iNode
	For $k = $n To 1 Step -1
		$aOut[$k] = $c
		$c = $g_aTrParent[$c]
	Next
	Return SetError($TREE_E_NONE, 0, $n)
EndFunc   ;==>Tree_PathTo

; #FUNCTION# ====================================================================================================================
; Name ..........: Tree_Info
; Description ...: One number describing the state of the tree, asked by name.
; Syntax ........: Tree_Info($sKey)
; Parameters ....: $sKey - one of "count", "ids", "capacity", "free", "dirty", "clean", "root", "maxdepth", "arrays",
;                  "cells".
; Return values .: Success - the value asked for, @error = $TREE_E_NONE.
; Return values .: Failure - -1 with @error = $TREE_E_ARG for a key this build does not know.
; Author ........: Numeric1
; Remarks .......: "count" is the live nodes, "ids" the highest id ever handed out, "free" the ids waiting to be
;                  recycled, "dirty" the structural changes since the last rebuild, "cells" the number of array slots
;                  the capacity costs, which is how the memory figures in Tree_Bench.au3 are obtained. It is a Select on
;                  a string, so it belongs in a report line, not in a loop.
; Related .......: Tree_Count, Tree_Capacity, Tree_IsClean, Tree_NameStale
; ===============================================================================================================================
Func Tree_Info($sKey)
	; keys: count ids capacity free dirty clean root maxdepth arrays cells
	Select
		Case $sKey = "count"
			Return $g_iTrLive
		Case $sKey = "ids"
			Return $g_iTrCount
		Case $sKey = "capacity"
			Return $g_iTrCap
		Case $sKey = "free"
			Return $g_iTrFreeN
		Case $sKey = "dirty"
			Return $g_iTrDirty
		Case $sKey = "clean"
			Return $g_bTrClean ? 1 : 0
		Case $sKey = "root"
			Return $g_iTrRoot
		Case $sKey = "maxdepth"
			Return $g_iTrMaxDepth
		Case $sKey = "arrays"
			Return $g_iTrNArrays
		Case $sKey = "cells"
			Return ($g_iTrCap + 1) * $g_iTrNArrays
		Case Else
			Return SetError($TREE_E_ARG, 0, -1)
	EndSelect
EndFunc   ;==>Tree_Info

; #FUNCTION# ====================================================================================================================
; Name ..........: Tree_Validate
; Description ...: Full structural check of the tree: every link, every count, the index, the name Map.
; Syntax ........: Tree_Validate()
; Parameters ....: none
; Return values .: Success - 1 with @error = $TREE_E_NONE when the structure is sound.
; Return values .: Failure - 0 with @error set to the $TREE_E_* code that describes the fault and @extended set to the
;                  offending node id (or, for the name index, a key count). $TREE_E_STATE when no tree exists.
; Author ........: Numeric1
; Remarks .......: Checks that every live node is reachable from the root, that parent and child agree both ways, that
;                  the sibling chain matches the stored child count, that depths are the parent's plus one, that the
;                  preorder arrays agree while the index is clean, and that every live name is in the Map and points
;                  back at its node. It does not mutate the tree. O(N) except the name pass, so it is a test-harness
;                  call, not a per-operation one.
; Related .......: Tree_IsClean, Tree_Rebuild, Tree_NameStale
; ===============================================================================================================================
Func Tree_Validate()
	If $g_iTrRoot = 0 Then Return SetError($TREE_E_STATE, 0, 0)
	Local $iTop = 1, $i = 0, $cur, $c, $s, $k, $n = 0, $iMap = 0, $sKey
	Local $aSeen[$g_iTrCap + 1]
	$g_aTrStack[1] = $g_iTrRoot
	While $iTop > 0
		$cur = $g_aTrStack[$iTop]
		$iTop -= 1
		If $cur < 1 Or $cur > $g_iTrCap Or $g_aTrAlive[$cur] <> 1 Then Return SetError($TREE_E_NODE, $cur, 0)
		If $aSeen[$cur] <> 0 Then Return SetError($TREE_E_CYCLE, $cur, 0)
		$aSeen[$cur] = 1
		$i += 1
		If $cur = $g_iTrRoot Then
			If $g_aTrParent[$cur] <> 0 Then Return SetError($TREE_E_CYCLE, $cur, 0)
			If $g_aTrDepth[$cur] <> 0 Then Return SetError($TREE_E_ARG, $cur, 0)
		Else
			$c = $g_aTrParent[$cur]
			If $c < 1 Or $c > $g_iTrCap Or $g_aTrAlive[$c] <> 1 Then Return SetError($TREE_E_PARENT, $cur, 0)
			If $g_aTrDepth[$cur] <> $g_aTrDepth[$c] + 1 Then Return SetError($TREE_E_ARG, $cur, 0)
		EndIf
		$s = 0
		$c = $g_aTrChild1[$cur]
		While $c <> 0
			$s += 1
			If $s > $g_iTrLive Then Return SetError($TREE_E_CYCLE, $cur, 0)
			If $g_aTrParent[$c] <> $cur Then Return SetError($TREE_E_PARENT, $c, 0)
			If $g_aTrPrev[$c] <> 0 And $g_aTrNext[$g_aTrPrev[$c]] <> $c Then Return SetError($TREE_E_ARG, $c, 0)
			If $g_aTrNext[$c] <> 0 And $g_aTrPrev[$g_aTrNext[$c]] <> $c Then Return SetError($TREE_E_ARG, $c, 0)
			$iTop += 1
			$g_aTrStack[$iTop] = $c
			$c = $g_aTrNext[$c]
		WEnd
		If $s <> $g_aTrNKid[$cur] Then Return SetError($TREE_E_NOTEMPTY, $cur, 0)
		If $s = 0 Then
			If $g_aTrChild1[$cur] <> 0 Or $g_aTrTail[$cur] <> 0 Then Return SetError($TREE_E_ARG, $cur, 0)
		Else
			If $g_aTrNext[$g_aTrChild1[$cur]] = 0 And $g_aTrChild1[$cur] <> $g_aTrTail[$cur] Then Return SetError($TREE_E_ARG, $cur, 0)
			If $g_aTrPrev[$g_aTrTail[$cur]] = 0 And $g_aTrTail[$cur] <> $g_aTrChild1[$cur] Then Return SetError($TREE_E_ARG, $cur, 0)
			If $g_aTrNext[$g_aTrTail[$cur]] <> 0 Then Return SetError($TREE_E_ARG, $cur, 0)
		EndIf
	WEnd
	If $i <> $g_iTrLive Then Return SetError($TREE_E_NODE, $i, 0)
	For $k = 1 To $g_iTrCount
		If $g_aTrAlive[$k] <> 1 Then ContinueLoop
		If $aSeen[$k] = 0 Then Return SetError($TREE_E_NODE, $k, 0)
		If $g_aTrName[$k] <> "" Then $n += 1
	Next
	If $g_bTrUseName Then
		For $sKey In $g_mTrName
			$iMap += 1
		Next
		; Every live name must be in the index. Keys left over from dead or
		; renamed nodes are a normal state, so the map may be larger than the
		; live count; $g_iTrNameStale is the upper bound on that slack.
		If $iMap < $n Then Return SetError($TREE_E_ARG, $iMap, 0)
		For $k = 1 To $g_iTrCount
			If $g_aTrAlive[$k] = 1 And $g_aTrName[$k] <> "" Then
				If Not MapExists($g_mTrName, $g_aTrName[$k]) Then Return SetError($TREE_E_ARG, $k, 0)
				If $g_mTrName[$g_aTrName[$k]] <> $k Then Return SetError($TREE_E_ARG, $k, 0)
			EndIf
		Next
		If $iMap - $n > $g_iTrNameStale Then Return SetError($TREE_E_ARG, $iMap, 0)
	ElseIf $iMap <> 0 Or $g_iTrNameStale <> 0 Then
		Return SetError($TREE_E_ARG, $g_iTrNameStale, 0)
	EndIf
	If $g_bTrClean Then
		For $k = $i To 1 Step -1
			$c = $g_aTrOrder[$k]
			If $g_aTrPos[$c] <> $k Then Return SetError($TREE_E_ARG, $c, 0)
			$s = 1
			Local $d = $g_aTrChild1[$c]
			While $d <> 0
				$s += $g_aTrSub[$d]
				$d = $g_aTrNext[$d]
			WEnd
			If $s <> $g_aTrSub[$c] Then Return SetError($TREE_E_NOTEMPTY, $c, 0)
		Next
	EndIf
	Return SetError($TREE_E_NONE, 0, 1)
EndFunc   ;==>Tree_Validate

; #FUNCTION# ====================================================================================================================
; Name ..........: Tree_Export
; Description ...: Writes the whole tree to a text file, one line per node in preorder.
; Syntax ........: Tree_Export($sFile)
; Parameters ....: $sFile - path to write; the file is replaced, not appended.
; Return values .: Success - the number of nodes written, @error = $TREE_E_NONE.
; Return values .: Failure - 0 with @error = $TREE_E_STATE (no tree) or $TREE_E_FILE (@extended = 1 when the file opened
;                  but the write failed).
; Author ........: Numeric1
; Remarks .......: The format is a TREE1 magic line then id, parent (-1 for the root), name and data separated by tabs,
;                  in preorder, so a reader needs no index to rebuild the shape. Names and payloads are flattened: a
;                  value containing a tab or a line break is written with spaces, which is why a round trip is not byte-
;                  exact for such payloads. Tree_Rebuild runs first, so exporting costs one pass.
; Related .......: Tree_Import, Tree_Walk, Tree_Rebuild
; ===============================================================================================================================
Func Tree_Export($sFile)
	If $g_iTrRoot = 0 Then Return SetError($TREE_E_STATE, 0, 0)
	Local $iN = Tree_Rebuild()
	If @error Then Return SetError(@error, 0, 0)
	Local $s = "TREE1" & @LF, $n, $p, $k
	For $k = 1 To $iN
		$n = $g_aTrOrder[$k]
		$p = $g_aTrParent[$n]
		$s &= $n & @TAB & ($p = 0 ? -1 : $p) & @TAB & _Tree_Sanitize($g_aTrName[$n]) & @TAB & _Tree_Sanitize($g_aTrData[$n]) & @LF
	Next
	Local $h = FileOpen($sFile, 2)
	If $h = -1 Then Return SetError($TREE_E_FILE, 0, 0)
	Local $b = FileWrite($h, $s)
	Local $iErr = @error
	FileClose($h)
	If $b = 0 Or $iErr Then Return SetError($TREE_E_FILE, 1, 0)
	Return SetError($TREE_E_NONE, 0, $iN)
EndFunc   ;==>Tree_Export

Func _Tree_Sanitize($v)
	If IsString($v) Then
		Local $s = StringReplace($v, @CR, " ")
		$s = StringReplace($s, @LF, " ")
		$s = StringReplace($s, @TAB, " ")
		Return $s
	EndIf
	Return String($v)
EndFunc   ;==>_Tree_Sanitize

; #FUNCTION# ====================================================================================================================
; Name ..........: Tree_Import
; Description ...: Rebuilds the tree from a file Tree_Export wrote.
; Syntax ........: Tree_Import($sFile)
; Parameters ....: $sFile - path to read.
; Return values .: Success - the number of nodes loaded, the root excluded, @error = $TREE_E_NONE.
; Return values .: Failure - 0 with @error = $TREE_E_FILE and @extended = the offending line number, or 0 when the fault
;                  is not on a line (missing file, empty file, wrong magic, no root).
; Author ........: Numeric1
; Remarks .......: The file is parsed and validated in a first pass and the live tree is only touched once it is known
;                  good, so a rejected file leaves your tree exactly as it was. Ids are reassigned by Tree_Add in
;                  preorder, which keeps the child order; the tree that was live before the call is replaced, because
;                  the root line recreates the tree. A payload that was flattened on the way out stays flattened.
; Related .......: Tree_Export, Tree_Create, Tree_Add
; ===============================================================================================================================
Func Tree_Import($sFile)
	If FileExists($sFile) = 0 Then Return SetError($TREE_E_FILE, 0, 0)
	Local $sAll = FileRead($sFile)
	If @error Or $sAll = "" Then Return SetError($TREE_E_FILE, 0, 0)
	$sAll = StringStripCR($sAll)
	Local $aLines = StringSplit($sAll, @LF, 1)
	If $aLines[0] < 2 Then Return SetError($TREE_E_FILE, 0, 0)
	If $aLines[1] <> "TREE1" Then Return SetError($TREE_E_FILE, 1, 0)
	Local $k, $f, $n = 0, $bRoot = False, $iOldPar, $iOld
	; pass 1 : parse and validate, nothing is written to the tree yet
	Local $aOld[$aLines[0] + 1], $aPar[$aLines[0] + 1], $aName[$aLines[0] + 1], $aData[$aLines[0] + 1]
	Local $mSeen[], $mXlate[], $mNames[]
	For $k = 2 To $aLines[0]
		If $aLines[$k] = "" Then ContinueLoop
		$f = StringSplit($aLines[$k], @TAB, 1)
		If $f[0] < 4 Then Return SetError($TREE_E_FILE, $k, 0)
		$iOld = Number($f[1])
		$iOldPar = Number($f[2])
		If $iOld < 1 Or MapExists($mSeen, $iOld) Then Return SetError($TREE_E_FILE, $k, 0)
		$mSeen[$iOld] = 1
		$n += 1
		$aOld[$n] = $iOld
		$aName[$n] = $f[3]
		$aData[$n] = $f[4]
		If $iOldPar = -1 Then
			; the root line must be the first node of a preorder dump
			If $bRoot Or $n <> 1 Then Return SetError($TREE_E_FILE, $k, 0)
			$bRoot = True
			$aPar[$n] = 0
		Else
			If Not $bRoot Then Return SetError($TREE_E_FILE, $k, 0)
			If $iOldPar < 1 Or Not MapExists($mSeen, $iOldPar) Then Return SetError($TREE_E_FILE, $k, 0)
			$aPar[$n] = $iOldPar
		EndIf
		If $f[3] <> "" Then
			If MapExists($mNames, $f[3]) Then Return SetError($TREE_E_FILE, $k, 0)
			$mNames[$f[3]] = 1
		EndIf
	Next
	If Not $bRoot Then Return SetError($TREE_E_FILE, 0, 0)
	; pass 2 : the file is known good, rebuild
	Tree_Create("")
	$mXlate[$aOld[1]] = 1
	If $aName[1] <> "" Then Tree_SetName(1, $aName[1])
	$g_aTrData[1] = $aData[1]
	For $k = 2 To $n
		Local $iNew = Tree_Add($mXlate[$aPar[$k]], $aData[$k], $aName[$k])
		If @error Then Return SetError($TREE_E_FILE, $k, 0)
		$mXlate[$aOld[$k]] = $iNew
	Next
	Return SetError($TREE_E_NONE, 0, $n - 1)
EndFunc   ;==>Tree_Import
