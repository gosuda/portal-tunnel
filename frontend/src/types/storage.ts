export const STORAGE_KEY_IS_PUSH = "isPush";
export const REPUTATION_ACK_PREFIX = "portalReputationWarningAck:";

export function buildReputationAckKey(serverId: string): string {
  return `${REPUTATION_ACK_PREFIX}${serverId}`;
}
