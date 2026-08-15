/**
 * Thin asset proxy: ensure text responses declare UTF-8.
 * Without charset, browsers often decode as ISO-8859-1 and break Vietnamese.
 * Demo fixtures under /demo/ revalidate promptly (fixture refresh after deploy).
 */
const TEXT_EXT = new Map([
	[".txt", "text/plain; charset=utf-8"],
	[".md", "text/markdown; charset=utf-8"],
	[".markdown", "text/markdown; charset=utf-8"],
	[".csv", "text/csv; charset=utf-8"],
	[".json", "application/json; charset=utf-8"],
	// NDJSON / JSON Lines for demo fixtures
	[".jsonl", "application/x-ndjson; charset=utf-8"],
	[".xml", "application/xml; charset=utf-8"],
	[".css", "text/css; charset=utf-8"],
	[".js", "text/javascript; charset=utf-8"],
	[".mjs", "text/javascript; charset=utf-8"],
	[".svg", "image/svg+xml; charset=utf-8"],
	[".html", "text/html; charset=utf-8"],
	[".htm", "text/html; charset=utf-8"],
]);

function textContentType(pathname) {
	const lower = pathname.toLowerCase();
	for (const [ext, type] of TEXT_EXT) {
		if (lower.endsWith(ext)) return type;
	}
	return null;
}

export default {
	async fetch(request, env) {
		const response = await env.ASSETS.fetch(request);
		const url = new URL(request.url);
		const path = url.pathname.toLowerCase();
		const headers = new Headers(response.headers);

		const desired = textContentType(url.pathname);
		if (desired) {
			headers.set("Content-Type", desired);
		}

		// Revalidate text docs and all demo fixtures quickly.
		if (
			path.endsWith(".txt") ||
			path.endsWith(".md") ||
			path.endsWith(".markdown") ||
			path.startsWith("/demo/")
		) {
			headers.set("Cache-Control", "public, max-age=0, must-revalidate");
		}

		// Reduce MIME sniffing risk for interactive demo pages/assets.
		if (path.startsWith("/demo/") || desired) {
			headers.set("X-Content-Type-Options", "nosniff");
		}

		if (!desired && !path.startsWith("/demo/")) {
			return response;
		}

		return new Response(response.body, {
			status: response.status,
			statusText: response.statusText,
			headers,
		});
	},
};
