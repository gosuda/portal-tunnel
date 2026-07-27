import { resolveExposeName } from './expose-name';
import type { ShareKind } from './share-link';

/** Hardcoded relay origin for the static docs site */
export const RELAY_ORIGIN = 'https://portal.suda.me';

export type TunnelCommandOS = 'unix' | 'windows';

export interface TunnelCommandOptions {
	currentOrigin: string;
	target: string;
	name: string;
	nameSeed: string;
	relayUrls: string[];
	discovery: boolean;
	thumbnailURL: string;
	enableUDP?: boolean;
	udpPort?: string;
	os: TunnelCommandOS;
	/** How the share input was classified; defaults to 'port'. */
	shareKind?: ShareKind;
	/** Local path passed to `--serve` when shareKind is 'file'. */
	servePath?: string;
}

export function buildTunnelDisplayCommand(opts: TunnelCommandOptions): string {
	const { installLine, exposeHead, exposeOptions } = buildTunnelCommandParts(opts);
	return joinTunnelDisplayCommand(installLine, exposeHead, exposeOptions);
}

export function buildTunnelPreviewURL(
	origin: string,
	name: string,
	target: string,
	nameSeed: string
): string {
	const baseHost = getRelayOriginHost(origin);
	const subdomain = resolveExposeName(name, target, nameSeed);
	return `https://${subdomain}.${baseHost}`;
}

function buildTunnelCommandParts({
	currentOrigin,
	discovery,
	enableUDP = false,
	name,
	nameSeed,
	os,
	relayUrls,
	target,
	thumbnailURL,
	udpPort = '',
	shareKind = 'port',
	servePath = ''
}: TunnelCommandOptions): {
	installLine: string;
	exposeHead: string;
	exposeOptions: string[];
} {
	const isFile = shareKind === 'file';
	const targetValue = target.trim() === '' ? '3000' : target.trim();
	const nameSeedTarget = isFile ? servePath : targetValue;
	const nameValue = resolveExposeName(name, nameSeedTarget, nameSeed);
	const relayURLValue = relayUrls.length > 0 ? relayUrls.join(',') : currentOrigin;
	const leadingArgs = isFile
		? ['--serve', formatToken(servePath, os)]
		: [formatToken(targetValue, os)];

	// Inlined install paths — no apiPaths dependency
	const installScriptURL = new URL('/api/install.sh', currentOrigin).toString();
	const installPowerShellURL = new URL('/api/install.ps1', currentOrigin).toString();

	const exposeArgs: string[] = [];
	exposeArgs.push(`--name ${formatToken(nameValue, os)}`);
	if (relayUrls.length > 0) {
		exposeArgs.push(`--relays ${formatToken(relayURLValue, os)}`);
	}
	if (!discovery) {
		exposeArgs.push('--discovery=false');
	}

	const normalizedThumbnailURL = normalizeAbsoluteHTTPURL(thumbnailURL);
	if (normalizedThumbnailURL !== '') {
		exposeArgs.push(`--thumbnail ${formatToken(normalizedThumbnailURL, os)}`);
	}
	if (enableUDP) {
		exposeArgs.push('--udp');
		const normalizedUDPPort = udpPort.trim();
		if (normalizedUDPPort !== '') {
			exposeArgs.push(`--udp-addr ${formatToken(normalizedUDPPort, os)}`);
		}
	}

	if (os === 'windows') {
		return {
			installLine: [
				`$ProgressPreference = 'SilentlyContinue'`,
				`irm ${formatToken(installPowerShellURL, os)} | iex`
			].join('\n'),
			exposeHead: 'portal expose',
			exposeOptions: [...leadingArgs, ...exposeArgs]
		};
	}

	const curlFlags = isLocalRelayOrigin(currentOrigin) ? '-ksSL' : '-sSL';
	return {
		installLine: `curl ${curlFlags} ${formatToken(installScriptURL, os)} | bash`,
		exposeHead: 'portal expose',
		exposeOptions: [...leadingArgs, ...exposeArgs]
	};
}

function normalizeAbsoluteHTTPURL(raw: string): string {
	const trimmed = raw.trim();
	if (trimmed === '') return '';
	try {
		const parsed = new URL(trimmed);
		if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return '';
		return parsed.toString();
	} catch { return ''; }
}

function getRelayOriginHost(origin: string): string {
	try {
		return new URL(origin).hostname.trim().toLowerCase();
	} catch { return ''; }
}

function isLocalRelayOrigin(origin: string): boolean {
	try {
		const hostname = new URL(origin).hostname.trim().toLowerCase();
		return (
			hostname === 'localhost' ||
			hostname === '127.0.0.1' ||
			hostname === '::1' ||
			hostname.endsWith('.localhost')
		);
	} catch { return false; }
}

function quoteShellValue(value: string): string {
	return "'" + value.replace(/'/g, `'"'"'`) + "'";
}

function quotePowerShellValue(value: string): string {
	return `'${value.replace(/'/g, "''")}'`;
}

function formatToken(value: string, os: TunnelCommandOS): string {
	if (/^[A-Za-z0-9:/.=_-]+$/.test(value)) return value;
	return os === 'windows' ? quotePowerShellValue(value) : quoteShellValue(value);
}

function joinTunnelCommand(
	installLine: string,
	exposeHead: string,
	exposeOptions: string[]
): string {
	return [installLine, [exposeHead, ...exposeOptions].join(' ')].join('\n');
}

function joinTunnelDisplayCommand(
	installLine: string,
	exposeHead: string,
	exposeOptions: string[]
): string {
	const relayIndex = exposeOptions.findIndex((option) => option.startsWith('--relays '));
	if (relayIndex < 0) return joinTunnelCommand(installLine, exposeHead, exposeOptions);
	const exposeLines = [
		[exposeHead, ...exposeOptions.slice(0, relayIndex)].join(' '),
		exposeOptions.slice(relayIndex).join(' ')
	];
	return [installLine, exposeLines.join('\n')].join('\n');
}
