import type { ReputationSummary } from "@/types/api";

// Core server shape used across list, card, and detail views.
// Shares the reputation field with the list view; detail builds its own
// ServerDetailState that mirrors this shape for routing state.
export interface BaseServer {
  id: string;
  name: string;
  description: string;
  tags: string[];
  thumbnail: string;
  owner: string;
  online: boolean;
  dns: string;
  link: string;
  tcpAddr?: string;
  udpAddr?: string;
  lastUpdated?: string;
  firstSeen?: string;
  paymentEnabled?: boolean;
  paymentLabel?: string;
  reputation?: ReputationSummary;
}
