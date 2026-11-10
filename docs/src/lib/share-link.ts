export type ShareKind = 'url' | 'file' | 'port';

export interface ShareInput {
	kind: ShareKind;
	target: string;
	path: string;
}

const WINDOWS_PATH = /^[A-Za-z]:[\\/]/;
const UNC_PATH = /^\\\\/;

export function classifyShareInput(raw: string): ShareInput {
	const trimmed = raw.trim();
	if (trimmed === '') {
		return { kind: 'port', target: '', path: '' };
	}

	if (/^https?:\/\//i.test(trimmed)) {
		const target = urlToExposeTarget(trimmed);
		return { kind: 'url', target, path: '' };
	}

	if (/^file:\/\//i.test(trimmed)) {
		const path = fileURLToPath(trimmed);
		return { kind: 'file', target: '', path };
	}

	if (WINDOWS_PATH.test(trimmed) || UNC_PATH.test(trimmed) || trimmed.startsWith('/')) {
		return { kind: 'file', target: '', path: trimmed };
	}

	return { kind: 'port', target: trimmed, path: '' };
}

function urlToExposeTarget(raw: string): string {
	try {
		const parsed = new URL(raw);
		if (parsed.hostname === '') return '';
		return parsed.port ? `${parsed.hostname}:${parsed.port}` : parsed.hostname;
	} catch {
		return '';
	}
}

function fileURLToPath(raw: string): string {
	try {
		const parsed = new URL(raw);
		let path = decodeURIComponent(parsed.pathname);
		if (/^\/[A-Za-z]:[\\/]/.test(path)) {
			path = path.slice(1);
		}
		return path;
	} catch {
		return raw.replace(/^file:\/\//i, '');
	}
}
