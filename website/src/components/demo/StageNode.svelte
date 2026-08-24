<script>
	import { Handle, Position } from '@xyflow/svelte';

	let { data } = $props();
	const label = $derived(String(data?.label ?? ''));
	const color = $derived(String(data?.color ?? 'var(--sl-color-text-accent)'));
	const on = $derived(Boolean(data?.selected));
	const step = $derived(String(data?.step ?? ''));
</script>

<div class="sn" class:on style={`--c:${color}`} data-tone={data?.tone ?? 'neutral'}>
	<Handle type="target" position={Position.Left} class="sn-h" />
	<span class="sn-step">{step}</span>
	<span class="sn-label">{label}</span>
	<Handle type="source" position={Position.Right} class="sn-h" />
</div>

<style>
	.sn {
		display: flex;
		align-items: center;
		gap: 0.55rem;
		min-width: 168px;
		padding: 0.85rem 1.05rem;
		border-radius: 14px;
		border: 1px solid color-mix(in srgb, var(--c) 45%, var(--sl-color-hairline, #444));
		background: color-mix(in srgb, var(--c) 12%, var(--sl-color-gray-6));
		box-shadow: 0 0 0 0 transparent;
		transition:
			transform 220ms ease,
			box-shadow 220ms ease,
			border-color 220ms ease;
		cursor: pointer;
	}
	.sn.on {
		transform: translateY(-2px) scale(1.04);
		border-color: var(--c);
		box-shadow:
			0 0 0 3px color-mix(in srgb, var(--c) 35%, transparent),
			0 10px 28px color-mix(in srgb, var(--c) 22%, transparent);
	}
	@media (prefers-reduced-motion: reduce) {
		.sn,
		.sn.on {
			transition: none;
			transform: none;
		}
	}
	.sn-step {
		font-size: 0.72rem;
		font-weight: 800;
		letter-spacing: 0.04em;
		color: var(--c);
		min-width: 1.1rem;
	}
	.sn-label {
		font-size: 0.98rem;
		font-weight: 700;
		color: var(--sl-color-white);
	}
	:global(.sn-h) {
		width: 8px !important;
		height: 8px !important;
		background: var(--c) !important;
		border: none !important;
	}
</style>
