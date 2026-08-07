// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

// https://astro.build/config
export default defineConfig({
	site: 'https://vinsoc.manhquy.id.vn',
	integrations: [
		starlight({
			title: 'Sentinel Docs',
			description: 'Weekly mentor reports and product docs for Project Sentinel',
			social: [
				{
					icon: 'github',
					label: 'GitHub',
					href: 'https://github.com/manhquydev/sentinel-security-platform',
				},
			],
			sidebar: [
				{
					label: 'Báo cáo tuần',
					items: [
						{ label: 'Mục lục', slug: 'reports' },
						{ label: 'Tuần 1 — Baseline scan', slug: 'reports/week-01' },
						{ label: 'Tuần 2 — Normalize + knowledge', slug: 'reports/week-02' },
						{ label: 'Tuần 3 — Analysis agent', slug: 'reports/week-03' },
					],
				},
			],
		}),
	],
});
