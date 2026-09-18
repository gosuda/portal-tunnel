import { resolveExposeName } from './expose-name';
import type { ShareInput } from './share-link';

export type TunnelCommandOS = 'unix' | 'windows';

export function buildTunnelCommand(
	share: ShareInput,
	name: string,
	nameSeed: string,
	os: TunnelCommandOS
) {
	const target = share.kind === 'file' ? share.path : share.target || '3000';
	const nameValue = resolveExposeName(name, share.seedTarget, nameSeed);
	const args = share.kind === 'file' ? ['--serve', target] : [target];
	args.push('--name', nameValue);
	const run = 'portal expose ' + args.map((value) => {
		if (/^[A-Za-z0-9:/.=_-]+$/.test(value)) return value;
		return os === 'windows'
			? "'" + value.replace(/'/g, "''") + "'"
			: "'" + value.replace(/'/g, `'"'"'`) + "'";
	}).join(' ');
	const release = 'https://github.com/gosuda/portal-tunnel/releases/latest/download';
	const install = os === 'windows'
		? `$ProgressPreference = 'SilentlyContinue'\nirm ${release}/install.ps1 | iex`
		: `curl -fsSL ${release}/install.sh | bash`;
	return { install, run };
}
