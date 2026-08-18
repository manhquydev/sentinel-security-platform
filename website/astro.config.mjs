// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

// https://astro.config
export default defineConfig({
	site: 'https://vinsoc.manhquy.id.vn',
	integrations: [
		starlight({
			title: 'Sentinel: Báo cáo tuần',
			description:
				'Báo cáo tuần đồ án Project Sentinel (VINSOC × VINUNI). TTS Nguyễn Mạnh Quý.',
			defaultLocale: 'root',
			locales: {
				root: {
					label: 'Tiếng Việt',
					lang: 'vi',
				},
			},
			social: [
				{
					icon: 'github',
					label: 'GitHub',
					href: 'https://github.com/manhquydev/sentinel-security-platform',
				},
			],
			components: {
				Footer: './src/components/Footer.astro',
			},
			sidebar: [
				{
					label: 'Báo cáo tuần',
					items: [
						{ label: 'Mục lục', slug: 'reports' },
						{ label: 'Tuần 1: Quét bảo mật nền', slug: 'reports/week-01' },
						{ label: 'Tuần 2: Chuẩn hóa và kho tri thức', slug: 'reports/week-02' },
						{ label: 'Tuần 3: Agent phân tích bảo mật', slug: 'reports/week-03' },
						{ label: 'Tuần 4: API Gateway và request an toàn', slug: 'reports/week-04' },
						{ label: 'Tuần 5: IPI, HITL và che dữ liệu', slug: 'reports/week-05' },
						{ label: 'Tuần 6: Tích hợp, đánh giá và demo', slug: 'reports/week-06' },
					],
				},
				{
					label: 'Demo',
					items: [
						{ label: 'Hub demo', link: '/demo/' },
						{ label: 'Demo Tuần 3', link: '/demo/week-03/' },
					],
				},
				{
					label: 'Nguồn Markdown',
					items: [
						{ label: 'llms.txt', link: '/llms.txt' },
						{ label: 'Mục lục (Markdown)', slug: 'reports/index/markdown' },
						{ label: 'Tuần 1 (Markdown)', slug: 'reports/week-01/markdown' },
						{ label: 'Tuần 2 (Markdown)', slug: 'reports/week-02/markdown' },
						{ label: 'Tuần 3 (Markdown)', slug: 'reports/week-03/markdown' },
						{ label: 'Tuần 4 (Markdown)', slug: 'reports/week-04/markdown' },
						{ label: 'Tuần 5 (Markdown)', slug: 'reports/week-05/markdown' },
						{ label: 'Tuần 6 (Markdown)', slug: 'reports/week-06/markdown' },
					],
				},
			],
		}),
	],
});
