/* Pulse - the view side. The host (Pulse.au3) pushes JSON strings through
   window.chrome.webview.postMessage; nothing here ever reaches the network.
   Messages are the ones documented in docs/PROTOCOL.md:
     {"k":"evs","a":[[time,lvl,name,src,ms,txt],...]}  a batch of rows
     {"k":"stat", total, rate, srcs, nodes, dead, q, journal, conns, file, bytes, port}
     {"k":"tree","a":[name,count,level]}               the whole visible tree
     {"k":"srcs","a":[[name,pid,count,err],...]}
     {"k":"arch","a":[[path,size],...]}                streams inside the archive
     {"k":"clear"}
*/
(function () {
	"use strict";

	var MAX_ROWS = 800;
	var rows = [];
	var shown = 0;
	var levels = { info: 1, ok: 1, warn: 1, error: 1, debug: 0 };
	var filter = "";
	var bNeedDraw = false;

	var elRows = document.getElementById("rows");
	var elTree = document.getElementById("tree");
	var elSrc = document.querySelector("#src tbody");
	var elArch = document.getElementById("arch");
	var elFilter = document.getElementById("filter");
	var elChips = document.getElementById("chips");

	function pad2(n) { return n < 10 ? "0" + n : "" + n; }

	function passes(r) {
		if (!levels[r[1]]) return false;
		if (!filter) return true;
		var s = filter;
		return String(r[2]).toLowerCase().indexOf(s) >= 0 ||
			String(r[3]).toLowerCase().indexOf(s) >= 0 ||
			String(r[5]).toLowerCase().indexOf(s) >= 0;
	}

	function rowHtml(r) {
		return '<div class="row ' + esc(r[1]) + '"><span class="t">' + esc(r[0]) +
			'</span><span class="lv">' + esc(r[1]) +
			'</span><span class="nm">' + esc(r[2]) +
			'</span><span class="src">' + esc(r[3]) +
			'</span><span class="ms">' + (r[4] === "" ? "" : esc(r[4]) + "ms") +
			'</span><span class="tx">' + esc(r[5]) + (r[6] ? ' <span class="cut">[cut]</span>' : "") +
			"</span></div>";
	}

	/* Redraws are coalesced to one animation frame, and retained history is capped
	   so a busy stream cannot grow the page without bound. */
	function draw() {
		bNeedDraw = false;
		var html = "", i, n = 0;
		var start = Math.max(0, rows.length - MAX_ROWS);
		for (i = rows.length - 1; i >= start && n < MAX_ROWS; i--) {
			if (!passes(rows[i])) continue;
			html += rowHtml(rows[i]);
			n++;
		}
		shown = n;
		elRows.innerHTML = html;
		document.getElementById("stream-count").textContent =
			n + " of " + rows.length + " rows";
	}

	function queueDraw() {
		if (!bNeedDraw) { bNeedDraw = true; requestAnimationFrame(draw); }
	}

	function append(r) { rows.push(r); }

	function setText(id, v) { document.getElementById(id).textContent = v; }

	function onEvs(a) {
		var i, r;
		for (i = 0; i < a.length; i++) {
			r = a[i];
			append([r[0], r[1], r[2], r[3], r[4], r[5], r[6]]);
		}
		if (rows.length > MAX_ROWS * 2) {
			rows = rows.slice(-MAX_ROWS);
		}
		queueDraw();
	}

	function onStat(s) {
		setText("s-total", s.total);
		setText("s-rate", s.rate);
		setText("s-src", s.srcs);
		setText("s-tree", s.nodes);
		setText("s-dead", s.dead);
		setText("s-cfb", s.file ? (s.bytes / 1024).toFixed(0) + " KB" : "idle");
		var live = document.getElementById("live");
		live.className = "dot " + (s.conns > 0 ? "on" : (s.listening ? "" : "off"));
		document.getElementById("lasterr").textContent = s.err ? String(s.err) : "";
		setText("endpoint", "ws://127.0.0.1:" + s.port + "/stream  \u00b7  one flat JSON object per text frame");
	}

	function onTree(a) {
		var html = "", i, d, nm, cnt, cls;
		for (i = 0; i < a.length; i += 3) {
			nm = a[i]; cnt = a[i + 1];
			d = nm.split(".").length - 1;
			cls = esc(a[i + 2]);
			html += '<div class="node ' + cls + '" data-name="' + esc(nm) +
				'" style="padding-left:' + (12 + d * 14) + 'px">' +
				'<span class="' + (cnt ? "leaf" : "br") + '">' + esc(nm.split(".").pop()) + "</span>" +
				'<span class="cnt">' + esc(cnt) + "</span></div>";
		}
		elTree.innerHTML = html;
	}

	function onSrcs(a) {
		var html = "", i;
		for (i = 0; i < a.length; i++) {
			html += "<tr><td class=\"name\">" + esc(a[i][0]) + "</td><td>" + esc(a[i][1]) +
				"</td><td class=\"r\">" + esc(a[i][2]) + "</td><td class=\"r\">" + esc(a[i][3]) + "</td></tr>";
		}
		elSrc.innerHTML = html;
	}

	function onArch(a) {
		var html = "", i;
		for (i = 0; i < a.length; i++) {
			html += "<div><b>" + esc(a[i][0]) + "</b><span>" + esc(a[i][1]) + "</span></div>";
		}
		elArch.innerHTML = html || "<div>no streams yet</div>";
	}

	function esc(s) {
		return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").
			replace(/>/g, "&gt;").replace(/"/g, "&quot;");
	}

	/* The chips are the only controls: level visibility. The filter box is a
	   plain substring match on name, source and text. */
	function buildChips() {
		var order = ["info", "ok", "warn", "error", "debug"], i, c;
		for (i = 0; i < order.length; i++) {
			c = document.createElement("span");
			c.className = "chip " + order[i] + (levels[order[i]] ? " on" : "");
			c.textContent = order[i];
			c.onclick = (function (k) {
				return function () {
					levels[k] = levels[k] ? 0 : 1;
					this.className = "chip " + k + (levels[k] ? " on" : "");
					draw();
				};
			})(order[i]);
			elChips.appendChild(c);
		}
	}

	elFilter.oninput = function () {
		filter = this.value.toLowerCase();
		draw();
	};

	elTree.onclick = function (e) {
		var n = e.target;
		while (n && n !== this && !n.getAttribute("data-name")) n = n.parentNode;
		if (!n || n === this) return;
		elFilter.value = n.getAttribute("data-name");
		filter = elFilter.value.toLowerCase();
		draw();
	};

	buildChips();
	draw();

	window.chrome.webview.addEventListener("message", function (e) {
		var m;
		try { m = e.data; } catch (x) { return; }
		if (!m || typeof m !== "object") return;
		switch (m.k) {
			case "evs": onEvs(m.a || []); break;
			case "stat": onStat(m); break;
			case "tree": onTree(m.a || []); break;
			case "srcs": onSrcs(m.a || []); break;
			case "arch": onArch(m.a || []); break;
			case "clear": rows = []; draw(); break;
			case "log": append([m.t || "", "info", "Pulse.Console", "console", "", String(m.a), 0]); queueDraw(); break;
		}
	});

	/* Tell the host the page is ready; it answers with the current state. */
	window.chrome.webview.postMessage({ k: "ready" });
})();
