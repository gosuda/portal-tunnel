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
  expires_at: string;
  first_seen_at: string;
  last_seen_at: string;
  hostname: string;
  udp_enabled?: boolean;
  udp_addr?: string;
  tcp_enabled?: boolean;
  tcp_addr?: string;
  metadata: LeaseMetadata;
  ready: number;
}

export interface PolicyLease extends Lease {
  identity_key: string;
  address: string;
  bps: number;
  client_ip: string;
  reported_ip?: string;
  is_approved: boolean;
  is_banned: boolean;
  is_denied: boolean;
  is_ip_banned: boolean;
}

export interface PublicStateResponse {
  leases?: Lease[];
  landing_page_enabled: boolean;
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
  landing_page_enabled: boolean;
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

export interface DiscoveryResponse {
  relays?: RelayDescriptor[];
}

export interface LeasePolicyUpdate {
  identity_key: string;
  bps?: number;
  is_approved?: boolean;
  is_banned?: boolean;
  is_denied?: boolean;
}

export interface IPPolicyUpdate {
  ip: string;
  is_banned: boolean;
}
