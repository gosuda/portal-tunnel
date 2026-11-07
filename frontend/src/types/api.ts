export interface APIErrorPayload {
  code: string;
  message: string;
}

export type APIEnvelope<T> =
  | {
      ok: true;
      data: T;
      error?: never;
    }
  | {
      ok: false;
      error: APIErrorPayload;
      data?: unknown;
    };

export type ApprovalMode = "auto" | "manual";

export interface LeaseMetadata {
  description?: string;
  owner?: string;
  thumbnail?: string;
  tags?: string[];
  hide?: boolean;
}

export interface Lease {
  name?: string;
  address: string;
  expires_at: string;
  first_seen_at: string;
  last_seen_at: string;
  hostname: string;
  canonical_hostname: string;
  udp_enabled?: boolean;
  udp_addr?: string;
  tcp_enabled?: boolean;
  tcp_addr?: string;
  metadata: LeaseMetadata;
  ready: number;
}

export interface PolicyLease extends Lease {
  identity_key: string;
  bps: number;
  client_ip: string;
  reported_ip?: string;
  is_approved: boolean;
  is_banned: boolean;
  is_denied: boolean;
}

export interface PublicStateResponse {
  leases?: Lease[];
  reputation?: ReputationSummary[];
}

export interface PolicyPortSettings {
  enabled: boolean;
  max_leases: number;
}

export interface PolicyStateResponse {
  policy: PolicySettings;
  leases?: PolicyLease[];
}

export interface PolicySettings {
  approval_mode: ApprovalMode;
  udp: PolicyPortSettings;
  tcp_port: PolicyPortSettings;
}

export interface AdminAuthStatusResponse {
  authenticated: boolean;
}

export interface AdminAuthLoginRequest {
  token: string;
}

export interface AdminAuthLoginResponse {
  access_token?: string;
}

export interface ENSStatus {
  enabled: boolean;
  verified: boolean;
  provider?: string;
  address?: string;
  dnssec_state?: string;
  ds_record?: string;
  message?: string;
  last_error?: string;
}

export interface X402FacilitatorInfo {
  enabled: boolean;
  url?: string;
  network?: string;
  network_name?: string;
  supported_url?: string;
  pay_to?: string;
}

export interface DomainResponse {
  protocol_version: string;
  release_version: string;
  ens: ENSStatus;
  x402: X402FacilitatorInfo;
}

export interface RelayDescriptor {
  api_https_addr?: string;
}

export interface IncompatibleRelayEntry {
  url: string;
  protocol_version?: string;
  last_seen_at?: string;
}

export interface DiscoveryResponse {
  relays?: RelayDescriptor[];
  incompatible_relays?: IncompatibleRelayEntry[];
  protocol_version?: string;
  release_version?: string;
  relay_release_versions?: Record<string, string>;
}

export type ReputationVote = "up" | "down";
export type ReputationVoteAction = ReputationVote | "clear";

// Every reputation response carries viewer_vote; anonymous viewers carry "".
export type ViewerVote = ReputationVote | "";

export interface ReputationSummary {
  hostname: string;
  up: number;
  down: number;
  total: number;
  viewer_vote?: ViewerVote;
}

export interface ReputationVoteRequest {
  hostname: string;
  vote: ReputationVoteAction;
}

// The vote response is the same aggregate as a directory row, hostname included.
export type ReputationVoteResponse = ReputationSummary;

export interface LeasePolicyUpdate {
  identity_key: string;
  bps?: number;
  is_approved?: boolean;
  is_banned?: boolean;
  is_denied?: boolean;
}

export const COMMENT_MAX_LENGTH = 2000;

export interface AppComment {
  id: string;
  text: string;
  created_at: string;
  up?: number;
  down?: number;
  viewer_vote?: ViewerVote;
  can_delete?: boolean;
}

export interface VoteCommentRequest {
  hostname: string;
  id: string;
  vote: ReputationVoteAction;
}

export interface CommentListResponse {
  comments: AppComment[];
}
