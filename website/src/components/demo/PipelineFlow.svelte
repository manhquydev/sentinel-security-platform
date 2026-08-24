<script>
	import {
		SvelteFlow,
		Background,
		BackgroundVariant,
		Controls,
	} from '@xyflow/svelte';
	import '@xyflow/svelte/dist/style.css';
	import StageNode from './StageNode.svelte';

	const STAGES = [
		{
			short: 'Quét',
			stage: 'var(--sl-color-text-accent)',
			badge: 'Máy quét · lab',
			tone: 'neutral',
			ev: 'Máy quét Juice Shop trong lab, không ra internet.\nChe mật khẩu rồi đưa kết quả vào DefectDojo.\nBản ghi thật chỉ có bước này (4 lỗ hổng Trivy).',
		},
		{
			short: 'Phân tích',
			stage: 'var(--sl-color-purple-high, #a78bfa)',
			badge: 'Bám dữ liệu máy quét',
			tone: 'model',
			ev: 'AI chỉ chọn mức tin cậy.\nCâu giải thích do chương trình viết từ dữ liệu máy quét.\nChưa có bản ghi bước này.',
		},
		{
			short: 'Đề xuất',
			stage: 'var(--sl-color-text-accent)',
			badge: 'Danh sách có sẵn',
			tone: 'neutral',
			ev: 'Request lấy từ danh sách đã chuẩn bị.\nKhông tự bịa đường dẫn từ tên lỗ hổng.\nChưa có bản ghi bước này.',
		},
		{
			short: 'Duyệt',
			stage: 'var(--sl-color-orange-high)',
			badge: 'Người phải bấm',
			tone: 'warn',
			ev: 'Đồng ý thì mới gửi.\nTừ chối thì không gửi gì.\nChưa có bản ghi bước này.',
		},
		{
			short: 'Cổng',
			stage: 'var(--sl-color-green-high)',
			badge: 'Kong',
			tone: 'neutral',
			ev: 'Đi qua cổng: có khóa và danh sách cho phép.\nKhông đưa nguyên nội dung phản hồi vào AI.\nChưa có bản ghi bước này.',
		},
		{
			short: 'Chặn độc',
			stage: 'var(--sl-color-red-high)',
			badge: 'Giữ lại chỉ dẫn lạ',
			tone: 'good',
			ev: 'Nội dung từ app không được tin.\nCâu “đổi mục tiêu” bị giữ lại, agent không đổi việc.\nChưa có bản ghi bước này.',
		},
		{
			short: 'Che dữ liệu',
			stage: 'var(--sl-color-red-high)',
			badge: 'Che trước khi lưu',
			tone: 'good',
			ev: 'Email / token / mật khẩu thành nhãn [đã che].\nBài kiểm tra trên máy: 10/10 — không lên DefectDojo.',
		},
	];

	const nodeTypes = { stage: StageNode };

	function buildNodes(active) {
		return STAGES.map((s, i) => ({
			id: String(i),
			type: 'stage',
			position: { x: i * 220, y: 48 },
			data: {
				step: String(i + 1),
				label: s.short,
				color: s.stage,
				tone: s.tone,
				selected: i === active,
			},
			sourcePosition: 'right',
			targetPosition: 'left',
			draggable: false,
			deletable: false,
		}));
	}

	function buildEdges(active, motion) {
		return STAGES.slice(1).map((_, i) => ({
			id: 'e' + i,
			source: String(i),
			target: String(i + 1),
			animated: motion && i === Math.max(0, active - 1),
			style: i < active ? 'stroke-width:2.4' : 'stroke-width:1.4;opacity:0.55',
		}));
	}

	let sel = $state(0);
	let playing = $state(false);
	let motion = $state(true);
	let colorMode = $state('dark');
	let nodes = $state.raw(buildNodes(0));
	let edges = $state.raw(buildEdges(0, true));

	$effect(() => {
		const t = document.documentElement.dataset.theme;
		colorMode = t === 'light' ? 'light' : 'dark';
		motion = !window.matchMedia('(prefers-reduced-motion: reduce)').matches;
	});

	function apply(i) {
		sel = i;
		nodes = buildNodes(i);
		edges = buildEdges(i, motion);
	}

	function pick(i) {
		playing = false;
		apply(i);
	}

	$effect(() => {
		if (!playing || !motion) return;
		const t = setInterval(() => apply((sel + 1) % STAGES.length), 2200);
		return () => clearInterval(t);
	});
</script>

<div class="pf not-content">
	<p class="pf-hint">
		Kéo nền để xem. Lăn chuột để phóng to. Nút góc phải để <kbd>thu vừa lại</kbd>.
	</p>
	<div class="pf-canvas">
		<SvelteFlow
			bind:nodes
			bind:edges
			{nodeTypes}
			{colorMode}
			fitView
			fitViewOptions={{ padding: 0.28, maxZoom: 1.05 }}
			minZoom={0.4}
			maxZoom={1.8}
			nodesDraggable={false}
			nodesConnectable={false}
			elementsSelectable={true}
			deleteKey={null}
			zoomOnDoubleClick={false}
			zoomOnScroll={true}
			zoomOnPinch={true}
			panOnDrag={true}
			panOnScroll={false}
			preventScrolling={false}
			onnodeclick={(e) => pick(Number(e.node.id))}
		>
			<Background variant={BackgroundVariant.Dots} gap={18} />
			<Controls
				showLock={false}
				showZoom={true}
				showFitView={true}
				position="bottom-right"
				aria-label="Phóng, thu, vừa khung"
			/>
		</SvelteFlow>
	</div>

	<div class="pf-bar">
		<button type="button" class="pf-play" onclick={() => (playing = !playing)}>
			{playing ? 'Dừng' : 'Chạy thử'}
		</button>
		<div class="pf-tabs" role="tablist" aria-label="Chọn giai đoạn">
			{#each STAGES as s, i}
				<button
					type="button"
					role="tab"
					aria-selected={sel === i}
					aria-controls="pf-panel"
					id={`pf-tab-${i}`}
					class="pf-tab"
					class:active={sel === i}
					style={`--stage:${s.stage}`}
					onclick={() => pick(i)}
				>
					{i + 1} · {s.short}
				</button>
			{/each}
		</div>
	</div>

	<div
		class="pf-panel"
		id="pf-panel"
		role="tabpanel"
		aria-labelledby={`pf-tab-${sel}`}
		style={`--stage:${STAGES[sel].stage}`}
	>
		<span class="pf-badge" data-tone={STAGES[sel].tone}>{STAGES[sel].badge}</span>
		<pre class="pf-ev">{STAGES[sel].ev}</pre>
	</div>
</div>

<style>
	.pf {
		display: flex;
		flex-direction: column;
		gap: 0.7rem;
	}
	.pf-hint {
		margin: 0;
		font-size: 0.85rem;
		color: var(--sl-color-gray-2);
	}
	.pf-hint kbd {
		font-size: 0.78rem;
		padding: 0.05rem 0.35rem;
		border: 1px solid var(--sl-color-hairline, #555);
		border-radius: 4px;
	}
	.pf-canvas {
		height: min(48vh, 460px);
		min-height: 340px;
		border: 1px solid var(--sl-color-hairline, var(--sl-color-gray-5));
		border-radius: 14px;
		overflow: hidden;
		background: var(--sl-color-gray-6);
	}
	.pf-bar {
		display: flex;
		flex-wrap: wrap;
		gap: 0.55rem;
		align-items: center;
	}
	.pf-play {
		appearance: none;
		border: 1px solid var(--sl-color-text-accent);
		background: color-mix(in srgb, var(--sl-color-text-accent) 16%, var(--sl-color-gray-6));
		color: var(--sl-color-white);
		font: inherit;
		font-size: 0.85rem;
		font-weight: 700;
		padding: 0.4rem 0.8rem;
		border-radius: 8px;
		cursor: pointer;
	}
	.pf-tabs {
		display: flex;
		flex-wrap: wrap;
		gap: 0.35rem;
		flex: 1;
	}
	.pf-tab {
		appearance: none;
		border: 1px solid var(--sl-color-hairline, var(--sl-color-gray-5));
		border-left: 3px solid var(--stage);
		background: var(--sl-color-gray-6);
		color: var(--sl-color-gray-2);
		font: inherit;
		font-size: 0.85rem;
		padding: 0.4rem 0.75rem;
		border-radius: 7px;
		cursor: pointer;
	}
	.pf-tab.active {
		color: var(--sl-color-white);
		background: color-mix(in srgb, var(--stage) 18%, var(--sl-color-gray-6));
		font-weight: 700;
	}
	.pf-panel {
		border: 1px solid var(--sl-color-hairline, var(--sl-color-gray-5));
		border-left: 4px solid var(--stage);
		border-radius: 10px;
		background: var(--sl-color-gray-6);
		padding: 0.85rem 1rem;
	}
	.pf-badge {
		display: inline-block;
		font-size: 0.75rem;
		font-weight: 700;
		padding: 0.22rem 0.6rem;
		border-radius: 999px;
		margin-bottom: 0.5rem;
		border: 1px solid var(--tone, var(--sl-color-gray-3));
		color: var(--tone, var(--sl-color-gray-1));
		background: color-mix(in srgb, var(--tone, var(--sl-color-gray-3)) 14%, var(--sl-color-gray-6));
	}
	.pf-badge[data-tone='good'] {
		--tone: var(--sl-color-green-high);
	}
	.pf-badge[data-tone='warn'] {
		--tone: var(--sl-color-orange-high);
	}
	.pf-badge[data-tone='model'] {
		--tone: var(--sl-color-purple-high, #a78bfa);
	}
	.pf-ev {
		margin: 0;
		font-family: var(--sl-font, inherit);
		font-size: 0.92rem;
		line-height: 1.55;
		white-space: pre-wrap;
		color: var(--sl-color-gray-1);
	}
	.pf-canvas :global(.svelte-flow__controls) {
		border: 1px solid var(--sl-color-hairline, #555);
		border-radius: 8px;
		overflow: hidden;
		box-shadow: none;
	}
	.pf-canvas :global(.svelte-flow__controls-button) {
		width: 28px;
		height: 28px;
		border-bottom-color: var(--sl-color-hairline, #555);
	}
</style>
