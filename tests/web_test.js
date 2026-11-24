"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const source = fs.readFileSync(path.join(__dirname, "..", "Web", "app.js"), "utf8");
let passed = 0;
let failed = 0;

function check(name, body) {
	try {
		body();
		passed += 1;
		console.log("  ok    " + name);
	} catch (error) {
		failed += 1;
		console.log("  FAIL  " + name + ": " + error.message);
	}
}

class Element {
	constructor(id) {
		this.id = id || "";
		this.className = "";
		this.textContent = "";
		this.innerHTML = "";
		this.value = "";
		this.children = [];
		this.parentNode = null;
		this.attributes = {};
	}

	appendChild(child) {
		child.parentNode = this;
		this.children.push(child);
		return child;
	}

	getAttribute(name) {
		return Object.prototype.hasOwnProperty.call(this.attributes, name) ? this.attributes[name] : null;
	}

	setAttribute(name, value) {
		this.attributes[name] = String(value);
	}
}

function loadPage() {
	const ids = [
		"rows", "tree", "arch", "filter", "chips", "live", "lasterr", "endpoint", "stream-count",
		"s-total", "s-rate", "s-src", "s-tree", "s-dead", "s-cfb"
	];
	const elements = {};
	for (const id of ids) elements[id] = new Element(id);
	const sourceBody = new Element("source-body");
	let messageHandler;
	const posted = [];
	const document = {
		getElementById(id) { return elements[id] || null; },
		querySelector(selector) {
			if (selector === "#src tbody") return sourceBody;
			throw new Error("unexpected selector " + selector);
		},
		createElement() { return new Element(); }
	};
	const window = {
		chrome: {
			webview: {
				addEventListener(type, handler) {
					if (type === "message") messageHandler = handler;
				},
				postMessage(message) { posted.push(message); }
			}
		}
	};
	vm.runInNewContext(source, {
		window,
		document,
		requestAnimationFrame(callback) { callback(); }
	}, { filename: "Web/app.js" });
	return {
		elements,
		sourceBody,
		posted,
		send(message) {
			assert.strictEqual(typeof messageHandler, "function");
			messageHandler({ data: message });
		}
	};
}

function rowCount(page) {
	return (page.elements.rows.innerHTML.match(/class="row /g) || []).length;
}

check("the page announces ready once", () => {
	const page = loadPage();
	assert.strictEqual(page.posted.length, 1);
	assert.strictEqual(page.posted[0].k, "ready");
});

check("every dynamic stream cell is HTML-escaped", () => {
	const page = loadPage();
	page.send({ k: "evs", a: [[
		"<t>", "error", '"><img src=x onerror=alert(1)>', "<svg onload=alert(1)>",
		'"><b>12</b>', '<script>alert("x")</script> & done', 1
	]] });
	const html = page.elements.rows.innerHTML;
	assert.ok(!html.includes("<img"));
	assert.ok(!html.includes("<svg"));
	assert.ok(!html.includes("<script"));
	assert.ok(!html.includes("<b>12</b>"));
	assert.ok(html.includes("&lt;img"));
	assert.ok(html.includes("&lt;script&gt;"));
	assert.ok(html.includes("&amp; done"));
	assert.ok(html.includes("&quot;"));
	assert.ok(html.includes("[cut]"));
});

check("name, source and text filters ignore case", () => {
	const page = loadPage();
	page.send({ k: "evs", a: [["12:00:00.000", "info", "Build.MixedCase", "AgentOne", "", "NeedleTEXT", 0]] });
	for (const query of ["BUILD.MIXED", "agentone", "needletext"]) {
		page.elements.filter.value = query;
		page.elements.filter.oninput();
		assert.strictEqual(rowCount(page), 1, query);
	}
	page.elements.filter.value = "missing";
	page.elements.filter.oninput();
	assert.strictEqual(rowCount(page), 0);
});

check("level chips hide and restore debug rows", () => {
	const page = loadPage();
	page.send({ k: "evs", a: [
		["12:00:00.000", "debug", "Debug.Row", "Agent", "", "debug", 0],
		["12:00:01.000", "info", "Info.Row", "Agent", "", "info", 0]
	] });
	assert.strictEqual(rowCount(page), 1);
	const chip = page.elements.chips.children.find((child) => child.textContent === "debug");
	assert.ok(chip);
	chip.onclick();
	assert.strictEqual(rowCount(page), 2);
	chip.onclick();
	assert.strictEqual(rowCount(page), 1);
});

check("status uses err and the actual listening port", () => {
	const page = loadPage();
	page.send({
		k: "stat", total: 4, rate: 2.5, srcs: 2, nodes: 3, dead: 0,
		conns: 2, listening: 1, bytes: 2048, file: "session.cfb", port: 49999,
		err: '<img src=x onerror="alert(1)">', error: "wrong field"
	});
	assert.strictEqual(page.elements.lasterr.textContent, '<img src=x onerror="alert(1)">');
	assert.ok(page.elements.endpoint.textContent.includes("127.0.0.1:49999/stream"));
	assert.ok(!page.elements.endpoint.textContent.includes("48411"));
	assert.strictEqual(page.elements.live.className, "dot on");
	page.send({ k: "stat", conns: 0, listening: 0, port: 49999, err: "" });
	assert.strictEqual(page.elements.live.className, "dot off");
	assert.strictEqual(page.elements.lasterr.textContent, "");
});

check("source names and PID text are HTML-escaped", () => {
	const page = loadPage();
	page.send({ k: "srcs", a: [['<img src=x>', '"><svg onload=alert(1)>', 2, 1]] });
	const html = page.sourceBody.innerHTML;
	assert.ok(!html.includes("<img"));
	assert.ok(!html.includes("<svg"));
	assert.ok(html.includes("&lt;img"));
	assert.ok(html.includes("&lt;svg"));
	assert.ok(html.includes("&quot;"));
});

check("tree names, levels and counts are HTML-escaped", () => {
	const page = loadPage();
	page.send({ k: "tree", a: ['<img src=x>.Branch', 2, 'error" onclick="alert(1)'] });
	const html = page.elements.tree.innerHTML;
	assert.ok(!html.includes("<img"));
	assert.ok(html.includes("&lt;img"));
	assert.ok(html.includes("error&quot; onclick=&quot;alert(1)"));
	assert.ok(html.includes('data-name="&lt;img src=x&gt;.Branch"'));
});

check("archive names and sizes are HTML-escaped", () => {
	const page = loadPage();
	page.send({ k: "arch", a: [['<script>alert(1)</script>', '<img src=x>']] });
	const html = page.elements.arch.innerHTML;
	assert.ok(!html.includes("<script"));
	assert.ok(!html.includes("<img"));
	assert.ok(html.includes("&lt;script&gt;"));
	assert.ok(html.includes("&lt;img"));
});

check("clear and unrelated messages are safe", () => {
	const page = loadPage();
	page.send({ k: "evs", a: [["12:00:00.000", "info", "Row", "Agent", "", "text", 0]] });
	assert.strictEqual(rowCount(page), 1);
	page.send({ k: "clear" });
	assert.strictEqual(rowCount(page), 0);
	assert.strictEqual(page.elements["stream-count"].textContent, "0 of 0 rows");
	for (const message of [null, "not an object", {}, { k: "unknown" }]) page.send(message);
	assert.strictEqual(rowCount(page), 0);
});

check("retained and rendered history stays capped at 800 rows", () => {
	const page = loadPage();
	const rows = [];
	for (let i = 0; i < 1700; i += 1) {
		rows.push(["12:00:00.000", "info", "Bulk.Row." + i, "Agent", "", "text", 0]);
	}
	page.send({ k: "evs", a: rows });
	assert.strictEqual(rowCount(page), 800);
	assert.strictEqual(page.elements["stream-count"].textContent, "800 of 800 rows");
	assert.ok(page.elements.rows.innerHTML.includes("Bulk.Row.1699"));
	assert.ok(!page.elements.rows.innerHTML.includes("Bulk.Row.899"));
});

console.log("RESULT ok=" + passed + " fail=" + failed);
process.exitCode = failed ? 1 : 0;
