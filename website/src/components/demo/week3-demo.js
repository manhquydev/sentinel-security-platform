/**
 * Week 3 interactive demo: static fixtures only.
 * Security: all dynamic strings via textContent / createTextNode (no innerHTML).
 */

const BASE = '/demo/week-03';

/** Failure codes documented by agent/week3_analysis.py (sample + known set). */
const FAILURE_ALLOWLIST = new Set([
	'malformed-input',
	'empty-input',
	'metadata-mismatch',
	'invalid-record',
	'knowledge-unavailable',
	'live-preflight-failed',
	'model-output-invalid',
	'artifact-publication-failed',
]);

/**
 * @param {string} text
 * @returns {unknown[]}
 */
function parseJsonl(text) {
	const lines = text.split(/\r?\n/).filter((l) => l.trim().length > 0);
	return lines.map((line, i) => {
		try {
			return JSON.parse(line);
		} catch {
			throw new Error(`JSONL dòng ${i + 1} không hợp lệ`);
		}
	});
}

/**
 * @param {ParentNode} el
 */
function clear(el) {
	while (el.firstChild) el.removeChild(el.firstChild);
}

/**
 * @param {string} tag
 * @param {string} [className]
 * @param {string} [text]
 */
function el(tag, className, text) {
	const node = document.createElement(tag);
	if (className) node.className = className;
	if (text != null) node.textContent = text;
	return node;
}

/**
 * @param {HTMLElement} root
 * @param {string} label
 * @param {string} value
 * @param {'code' | 'model' | 'prose'} ownership
 * @param {boolean} [mono]
 */
function field(root, label, value, ownership, mono = false) {
	const wrap = el('div', 'w3-field');
	const lab = el('div', 'w3-field__label');
	lab.appendChild(document.createTextNode(label + ' '));
	let badgeClass = 'w3-badge w3-badge--code';
	let badgeText = 'Sự kiện do code';
	if (ownership === 'model') {
		badgeClass = 'w3-badge w3-badge--model';
		badgeText = 'Confidence do model';
	} else if (ownership === 'prose') {
		badgeClass = 'w3-badge w3-badge--prose';
		badgeText = 'Prose do code';
	}
	lab.appendChild(el('span', badgeClass, badgeText));
	wrap.appendChild(lab);
	const val = el('div', mono ? 'w3-field__value w3-field__value--mono' : 'w3-field__value', value);
	wrap.appendChild(val);
	root.appendChild(wrap);
}

/**
 * @param {unknown[]} aggregate
 * @param {unknown[]} findings
 */
function buildGroupRows(aggregate, findings) {
	return findings.map((raw) => {
		const f = /** @type {Record<string, unknown>} */ (raw);
		const sources = Array.isArray(f.source_ids) ? f.source_ids.map(String) : [];
		const matched = aggregate.filter((aRaw) => {
			const a = /** @type {Record<string, unknown>} */ (aRaw);
			const sid = String(a.source_id ?? '');
			return sid.length > 0 && sources.includes(sid);
		});
		const n = matched.length > 0 ? matched.length : sources.length > 0 ? sources.length : 1;
		const titles = matched.map((aRaw) => {
			const a = /** @type {Record<string, unknown>} */ (aRaw);
			return String(a.title ?? a.name ?? a.tool ?? 'row');
		});
		return {
			name: String(f.name ?? 'Finding'),
			tool: String(f.tool ?? ''),
			from: n,
			to: 1,
			grouped: n > 1,
			sourceTitles: titles,
			sourceIds: sources,
		};
	});
}

/**
 * @param {HTMLElement} mount
 */
export async function mountWeek3Demo(mount) {
	const status = mount.querySelector('[data-w3-status]');
	const counter = mount.querySelector('[data-w3-counter]');
	const stepper = mount.querySelector('[data-w3-stepper]');
	const groupEl = mount.querySelector('[data-w3-group]');
	const listEl = mount.querySelector('[data-w3-list]');
	const detailEl = mount.querySelector('[data-w3-detail]');
	const modeHappy = mount.querySelector('[data-w3-mode="happy"]');
	const modeFail = mount.querySelector('[data-w3-mode="fail"]');

	if (
		!status ||
		!counter ||
		!stepper ||
		!groupEl ||
		!listEl ||
		!detailEl ||
		!modeHappy ||
		!modeFail
	) {
		console.error('Week3Demo: missing mount nodes');
		return;
	}

	/** @type {'happy' | 'fail'} */
	let mode = 'happy';
	/** @type {unknown[]} */
	let findings = [];
	/** @type {unknown[]} */
	let aggregate = [];
	/** @type {Record<string, unknown> | null} */
	let meta = null;
	/** @type {Record<string, unknown> | null} */
	let failClosed = null;
	/** @type {ReturnType<typeof buildGroupRows>} */
	let groupRows = [];
	let selected = 0;

	function setStatus(msg) {
		status.textContent = msg;
	}

	function renderStepper(activeIndex) {
		clear(stepper);
		const steps =
			/** @type {string[]} */ (
				meta && Array.isArray(meta.stepper)
					? meta.stepper
					: [
							'Nạp aggregate + manifest',
							'Nhóm cảnh báo (4 → 3)',
							'Confidence (model only)',
							'Báo cáo VI (code renderer)',
						]
			);
		steps.forEach((label, i) => {
			const li = el('li', i === 2 ? 'w3-step w3-step--model' : 'w3-step');
			li.dataset.active = String(i === activeIndex);
			li.appendChild(el('span', 'w3-step__n', `Bước ${i + 1}`));
			li.appendChild(document.createTextNode(label));
			stepper.appendChild(li);
		});
	}

	function renderCounter() {
		counter.textContent = `${aggregate.length} dòng aggregate → ${findings.length} finding`;
	}

	function renderGroupMap(showEmpty) {
		clear(groupEl);
		const h = el('h2', '', 'Nhóm cảnh báo (4 → 3)');
		groupEl.appendChild(h);

		if (showEmpty) {
			groupEl.appendChild(
				el(
					'p',
					'w3-field__value',
					'Fail-closed: không có report. Bước nhóm không publish finding.',
				),
			);
			return;
		}

		const intro = el(
			'p',
			'w3-muted',
			`${aggregate.length} dòng aggregate (máy quét) được gộp còn ${findings.length} finding. Dòng trùng title/location/tool gộp source_ids.`,
		);
		groupEl.appendChild(intro);

		const before = el('div', 'w3-group__col');
		before.appendChild(el('h3', 'w3-group__h', `Trước: aggregate (${aggregate.length})`));
		const beforeList = el('ul', 'w3-group__list');
		aggregate.forEach((raw, i) => {
			const a = /** @type {Record<string, unknown>} */ (raw);
			const li = el('li', 'w3-group__item');
			li.appendChild(
				el(
					'span',
					'w3-group__item-title',
					`${i + 1}. ${String(a.title ?? a.name ?? 'row')} · ${String(a.tool ?? '')}`,
				),
			);
			li.appendChild(
				el('span', 'w3-group__item-meta', String(a.location ?? a.source_id ?? '')),
			);
			beforeList.appendChild(li);
		});
		before.appendChild(beforeList);

		const after = el('div', 'w3-group__col');
		after.appendChild(el('h3', 'w3-group__h', `Sau: findings (${findings.length})`));
		const afterList = el('ul', 'w3-group__list');
		groupRows.forEach((row, i) => {
			const li = el('li', row.grouped ? 'w3-group__item w3-group__item--merged' : 'w3-group__item');
			const title = el('span', 'w3-group__item-title', `${i + 1}. ${row.name} · ${row.tool}`);
			li.appendChild(title);
			if (row.grouped) {
				li.appendChild(
					el(
						'span',
						'w3-group__chip',
						`Gộp ${row.from} → 1 (source_ids: ${row.sourceIds.length})`,
					),
				);
			} else {
				li.appendChild(el('span', 'w3-group__item-meta', '1 → 1 (không trùng)'));
			}
			afterList.appendChild(li);
		});
		after.appendChild(afterList);

		const grid = el('div', 'w3-group__grid');
		grid.appendChild(before);
		grid.appendChild(after);
		groupEl.appendChild(grid);
	}

	/**
	 * @param {Record<string, unknown>} finding
	 */
	function renderDetail(finding) {
		clear(detailEl);
		detailEl.classList.remove('w3-error');
		const h = el('h2', '', 'Chi tiết finding');
		detailEl.appendChild(h);

		const name = String(finding.name ?? '');
		const severity = String(finding.severity ?? '');
		const location = String(finding.location ?? '');
		const tool = String(finding.tool ?? '');
		const scanner = String(finding.scanner ?? '');
		const evidence = Array.isArray(finding.scanner_evidence)
			? finding.scanner_evidence.map(String).join(', ')
			: String(finding.scanner_evidence ?? '');
		const explanation = String(finding.explanation ?? '');
		const remediation = String(finding.remediation ?? '');
		const confidence = String(finding.confidence ?? '');
		const corpus = String(finding.corpus_digest ?? '');
		const retrieval = String(finding.retrieval_digest ?? '');
		const provenance = Array.isArray(finding.knowledge_provenance)
			? finding.knowledge_provenance.map(String).join('\n')
			: String(finding.knowledge_provenance ?? '');
		const sources = Array.isArray(finding.source_ids)
			? finding.source_ids.map(String).join('\n')
			: String(finding.source_ids ?? '');

		field(detailEl, 'Tên', name, 'code');
		field(detailEl, 'Mức độ', severity, 'code');
		field(detailEl, 'Vị trí', location, 'code', true);
		field(detailEl, 'Công cụ / scanner', `${tool} / ${scanner}`, 'code', true);
		field(detailEl, 'Bằng chứng máy quét', evidence, 'code', true);
		field(detailEl, 'Giải thích (VI)', explanation, 'prose');
		field(detailEl, 'Khắc phục (VI)', remediation, 'prose');
		field(detailEl, 'Độ tin cậy', confidence, 'model', true);

		const details = document.createElement('details');
		details.className = 'w3-tech';
		const summary = document.createElement('summary');
		summary.textContent = 'Bằng chứng kỹ thuật (digests · provenance · source_ids)';
		details.appendChild(summary);
		const techBody = el('div', 'w3-tech__body');
		field(techBody, 'corpus_digest', corpus, 'code', true);
		field(techBody, 'retrieval_digest', retrieval, 'code', true);
		field(techBody, 'knowledge_provenance', provenance, 'code', true);
		field(techBody, 'source_ids', sources, 'code', true);
		details.appendChild(techBody);
		detailEl.appendChild(details);

		const legend = el('div', 'w3-legend');
		legend.appendChild(el('span', 'w3-badge w3-badge--code', 'Sự kiện do code'));
		legend.appendChild(document.createTextNode(' · '));
		legend.appendChild(el('span', 'w3-badge w3-badge--prose', 'Prose do code'));
		legend.appendChild(document.createTextNode(' · '));
		legend.appendChild(el('span', 'w3-badge w3-badge--model', 'Confidence do model'));
		legend.appendChild(
			document.createTextNode(
				'. LLM không invent endpoint/vuln; code ghi sự kiện + prose VI.',
			),
		);
		detailEl.appendChild(legend);
	}

	function renderFail() {
		clear(listEl);
		clear(detailEl);
		detailEl.classList.add('w3-error');

		const empty = el('li', 'w3-list-empty');
		empty.appendChild(el('strong', '', '0 finding'));
		empty.appendChild(
			el(
				'p',
				'w3-muted',
				'Agent fail-closed: không publish report. Không invent finding từ input hỏng.',
			),
		);
		if (failClosed && failClosed.failure != null) {
			empty.appendChild(
				el('span', 'w3-group__chip w3-group__chip--danger', String(failClosed.failure)),
			);
		}
		listEl.appendChild(empty);

		const h = el('h2', '', 'Fail-closed');
		detailEl.appendChild(h);
		const ui =
			meta && typeof meta.fail_closed_ui_vi === 'string'
				? meta.fail_closed_ui_vi
				: 'Agent fail-closed: không ghi report. Mã lỗi CLI:';
		detailEl.appendChild(el('p', 'w3-field__value', ui));

		if (
			!failClosed ||
			failClosed.status !== 'failed' ||
			typeof failClosed.failure !== 'string'
		) {
			detailEl.appendChild(
				el(
					'p',
					'w3-field__value',
					'Chưa tải được fail-closed hợp lệ. Không hiển thị mã lỗi giả.',
				),
			);
			renderGroupMap(true);
			renderStepper(0);
			counter.textContent = '0 finding (fail-closed)';
			setStatus('Chế độ fail-closed: fixture lỗi');
			return;
		}

		const code = el('p', '');
		code.appendChild(document.createTextNode('status='));
		code.appendChild(el('code', '', String(failClosed.status)));
		code.appendChild(document.createTextNode(' · failure='));
		code.appendChild(el('code', '', String(failClosed.failure)));
		detailEl.appendChild(code);
		detailEl.appendChild(
			el(
				'p',
				'w3-field__value',
				'Hợp đồng CLI (agent/week3_analysis.py): {"status":"failed","failure":"<code>"}. Sample một mã; monorepo còn empty-input, metadata-mismatch, …',
			),
		);

		renderGroupMap(true);
		renderStepper(0);
		counter.textContent = '0 finding (fail-closed)';
		setStatus('Fail-closed sample: không sinh finding');
	}

	function renderHappy() {
		detailEl.classList.remove('w3-error');
		clear(listEl);
		findings.forEach((raw, i) => {
			const finding = /** @type {Record<string, unknown>} */ (raw);
			const li = el('li', '');
			const btn = el('button', '', '');
			btn.type = 'button';
			btn.setAttribute('aria-pressed', String(i === selected));
			const name = String(finding.name ?? `Finding ${i + 1}`);
			btn.appendChild(el('span', 'w3-list__name', name));
			const row = groupRows[i];
			const metaLine = row?.grouped
				? `${String(finding.severity ?? '')} · ${String(finding.tool ?? '')} · gộp ${row.from}→1`
				: `${String(finding.severity ?? '')} · ${String(finding.tool ?? '')}`;
			btn.appendChild(el('span', 'w3-list__meta', metaLine));
			btn.addEventListener('click', () => {
				selected = i;
				renderHappy();
			});
			li.appendChild(btn);
			listEl.appendChild(li);
		});
		if (findings[selected]) {
			renderDetail(/** @type {Record<string, unknown>} */ (findings[selected]));
		}
		renderGroupMap(false);
		renderStepper(3);
		renderCounter();
		setStatus('Chạy thành công: sample report week3-analysis/v1');
	}

	function applyMode() {
		modeHappy.setAttribute('aria-pressed', String(mode === 'happy'));
		modeFail.setAttribute('aria-pressed', String(mode === 'fail'));
		if (mode === 'fail') renderFail();
		else renderHappy();
	}

	function setTogglesEnabled(enabled) {
		modeHappy.disabled = !enabled;
		modeFail.disabled = !enabled;
	}
	setTogglesEnabled(false);

	modeHappy.addEventListener('click', () => {
		if (modeHappy.disabled) return;
		mode = 'happy';
		applyMode();
	});
	modeFail.addEventListener('click', () => {
		if (modeFail.disabled) return;
		mode = 'fail';
		applyMode();
	});

	listEl.addEventListener('keydown', (ev) => {
		if (mode !== 'happy' || findings.length === 0) return;
		if (ev.key === 'ArrowDown') {
			ev.preventDefault();
			selected = Math.min(findings.length - 1, selected + 1);
			renderHappy();
			listEl.querySelectorAll('button')[selected]?.focus();
		} else if (ev.key === 'ArrowUp') {
			ev.preventDefault();
			selected = Math.max(0, selected - 1);
			renderHappy();
			listEl.querySelectorAll('button')[selected]?.focus();
		}
	});

	try {
		setStatus('Đang tải fixtures…');
		const paths = [
			['meta.json', `${BASE}/meta.json`],
			['aggregate.jsonl', `${BASE}/aggregate.jsonl`],
			['manifest.json', `${BASE}/manifest.json`],
			['report.jsonl', `${BASE}/report.jsonl`],
			['fail-closed.json', `${BASE}/fail-closed.json`],
		];
		/** @type {Record<string, string>} */
		const bodies = {};
		await Promise.all(
			paths.map(async ([name, url]) => {
				const res = await fetch(url);
				if (!res.ok) throw new Error(`HTTP ${res.status} khi tải ${url}`);
				bodies[name] = await res.text();
			}),
		);

		meta = JSON.parse(bodies['meta.json']);
		const maxBytes =
			typeof meta.max_fixture_bytes === 'number' ? meta.max_fixture_bytes : 65536;
		for (const [name, body] of Object.entries(bodies)) {
			if (body.length > maxBytes) {
				throw new Error(`Fixture ${name} vượt max_fixture_bytes (${maxBytes})`);
			}
		}

		failClosed = JSON.parse(bodies['fail-closed.json']);
		if (
			!failClosed ||
			typeof failClosed !== 'object' ||
			failClosed.status !== 'failed' ||
			typeof failClosed.failure !== 'string' ||
			!FAILURE_ALLOWLIST.has(failClosed.failure)
		) {
			throw new Error(
				'fail-closed.json phải {"status":"failed","failure":"<allowlisted code>"}',
			);
		}
		JSON.parse(bodies['manifest.json']);
		aggregate = parseJsonl(bodies['aggregate.jsonl']);
		findings = parseJsonl(bodies['report.jsonl']);
		groupRows = buildGroupRows(aggregate, findings);

		const expectA = typeof meta.aggregate_count === 'number' ? meta.aggregate_count : 4;
		const expectF = typeof meta.finding_count === 'number' ? meta.finding_count : 3;
		if (aggregate.length !== expectA || findings.length !== expectF) {
			throw new Error(
				`Fixture count lệch meta: aggregate ${aggregate.length}/${expectA}, findings ${findings.length}/${expectF}`,
			);
		}

		if (meta.sha256 && typeof meta.sha256 === 'object' && crypto?.subtle) {
			const pins = /** @type {Record<string, string>} */ (meta.sha256);
			for (const key of ['aggregate.jsonl', 'report.jsonl', 'manifest.json']) {
				const expected = pins[key];
				const body = bodies[key];
				if (!expected || !body) continue;
				const buf = new TextEncoder().encode(body);
				const dig = await crypto.subtle.digest('SHA-256', buf);
				const hex = [...new Uint8Array(dig)].map((b) => b.toString(16).padStart(2, '0')).join('');
				if (hex !== expected) {
					throw new Error(`sha256 lệch ${key}: fixture không khớp meta.sha256 pin`);
				}
			}
		}

		setTogglesEnabled(true);
		applyMode();
	} catch (err) {
		const msg = err instanceof Error ? err.message : String(err);
		setTogglesEnabled(false);
		setStatus(`Lỗi: ${msg}`);
		clear(detailEl);
		detailEl.classList.add('w3-error');
		detailEl.appendChild(el('h2', '', 'Không tải được demo'));
		detailEl.appendChild(el('p', 'w3-field__value', msg));
	}
}
