<script>
	import { SvelteFlow, Background, BackgroundVariant } from '@xyflow/svelte';
	import '@xyflow/svelte/dist/style.css';

	const STAGES = [
		{
			label: '1 · Quét',
			stage: 'var(--sl-color-text-accent)',
			badge: 'DAST · Medium',
			tone: 'neutral',
			ev: 'nuclei · DAST\nMissing Security Header\npath:/rest/products · template-id=header',
		},
		{
			label: '2 · Agent',
			stage: 'var(--sl-color-purple-high, #a78bfa)',
			badge: 'model: chỉ confidence',
			tone: 'model',
			ev: 'report.jsonl (week3-analysis/v1)\nconfidence = medium  ← model\nexplanation/remediation = code-rendered\nknowledge: OWASP secure-headers',
		},
		{
			label: '3 · Đề xuất',
			stage: 'var(--sl-color-text-accent)',
			badge: 'catalog cố định',
			tone: 'neutral',
			ev: 'get-baseline (predeclared)\nGET …/rest/products/search?q=apple\nfinding.location ≠ path/query/body',
		},
		{
			label: '4 · HITL',
			stage: 'var(--sl-color-orange-high)',
			badge: 'cần phê duyệt',
			tone: 'warn',
			ev: 'Approve → gửi (action_sent=true)\nReject → fail-closed:\n  action_sent=false, request_count=0\n  (không mint, không gửi)',
		},
		{
			label: '5 · Kong',
			stage: 'var(--sl-color-green-high)',
			badge: 'chỉ digest',
			tone: 'neutral',
			ev: 'Kong TLS 127.0.0.1:18443\nACL + OAuth2 + API-key (Kong strip)\nchỉ digest → KHÔNG raw body vào LLM',
		},
		{
			label: '6 · Guard IPI',
			stage: 'var(--sl-color-red-high)',
			badge: 'QUARANTINED',
			tone: 'good',
			ev: 'response = untrusted data\n"Ignore the prior objective…"\n→ [quarantined: objective-change]\n→ agent không đổi mục tiêu',
		},
		{
			label: '7 · Che PII',
			stage: 'var(--sl-color-red-high)',
			badge: 'REDACTED',
			tone: 'good',
			ev: 'email=alice@example.test pan=4532…\n→ email=[redacted:pii:email]\n→ pan=[redacted:pii:card]\n(che trước LLM/log)',
		},
	];

	function nodeStyle(stage) {
		return (
			'border:1px solid var(--sl-color-hairline,#ccc);' +
			'border-left:4px solid ' +
			stage +
			';border-radius:10px;padding:8px 12px;font-size:12px;font-weight:600;min-width:104px;text-align:center;'
		);
	}

	let nodes = $state.raw(
		STAGES.map((s, i) => ({
			id: String(i),
			position: { x: i * 168, y: 0 },
			data: { label: s.label },
			sourcePosition: 'right',
			targetPosition: 'left',
			draggable: false,
			style: nodeStyle(s.stage),
		})),
	);
	let edges = $state.raw(
		STAGES.slice(1).map((_, i) => ({
			id: 'e' + i,
			source: String(i),
			target: String(i + 1),
			animated: true,
		})),
	);

	let sel = $state(0);
	let colorMode = $state('dark');
	$effect(() => {
		const t = document.documentElement.dataset.theme;
		colorMode = t === 'light' ? 'light' : 'dark';
	});

	function pick(i) {
		sel = i;
	}
</script>

<div class="pf not-content">
	<div class="pf-canvas">
		<SvelteFlow
			bind:nodes
			bind:edges
			{colorMode}
			fitView
			nodesDraggable={false}
			nodesConnectable={false}
			zoomOnScroll={false}
			panOnScroll={false}
			panOnDrag={false}
			preventScrolling={false}
			onnodeclick={(e) => pick(Number(e.node.id))}
		>
			<Background variant={BackgroundVariant.Dots} gap={16} />
		</SvelteFlow>
	</div>

	<div class="pf-tabs" role="tablist" aria-label="Chọn giai đoạn">
		{#each STAGES as s, i}
			<button
				type="button"
				role="tab"
				aria-selected={sel === i}
				class="pf-tab"
				class:active={sel === i}
				style={`--stage:${s.stage}`}
				onclick={() => pick(i)}
			>
				{s.label}
			</button>
		{/each}
	</div>

	<div class="pf-panel" style={`--stage:${STAGES[sel].stage}`}>
		<span class="pf-badge" data-tone={STAGES[sel].tone}>{STAGES[sel].badge}</span>
		<pre class="pf-ev">{STAGES[sel].ev}</pre>
	</div>
</div>

<style>
	.pf {
		display: flex;
		flex-direction: column;
		gap: 0.6rem;
	}
	.pf-canvas {
		height: 200px;
		border: 1px solid var(--sl-color-hairline, var(--sl-color-gray-5));
		border-radius: 12px;
		overflow: hidden;
		background: var(--sl-color-gray-6);
	}
	.pf-tabs {
		display: flex;
		flex-wrap: wrap;
		gap: 0.35rem;
	}
	.pf-tab {
		appearance: none;
		border: 1px solid var(--sl-color-hairline, var(--sl-color-gray-5));
		border-left: 3px solid var(--stage);
		background: var(--sl-color-gray-6);
		color: var(--sl-color-gray-2);
		font: inherit;
		font-size: 0.72rem;
		padding: 0.25rem 0.55rem;
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
		padding: 0.7rem 0.9rem;
	}
	.pf-badge {
		display: inline-block;
		font-size: 0.72rem;
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
		font-family: var(--sl-font-mono);
		font-size: 0.82rem;
		line-height: 1.5;
		white-space: pre-wrap;
		color: var(--sl-color-gray-1);
	}
</style>
