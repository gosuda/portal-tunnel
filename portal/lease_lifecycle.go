package portal

import (
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func (r *leaseRegistry) Touch(key types.ServiceIdentityKey, sourceAddr netip.Addr, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()

	record := r.recordByKey(key, now)
	if record == nil {
		return
	}
	record.LastSeenAt = now
	if sourceAddr.IsValid() {
		record.sourceAddr = sourceAddr
	}
}

func (r *leaseRegistry) collectCleanupExpiredLocked(now time.Time) []*leaseRecord {
	var expired []*leaseRecord
	for i := 0; i < len(r.records); {
		record := r.records[i]
		if record != nil && record.isExpired(now) {
			expired = append(expired, record)
			if record.reverse != nil {
				r.bps.ResetIdentityLimiter(record.ServiceKey())
			}
			r.deleteRecord(i)
			continue
		}
		i++
	}
	return expired
}

func (r *leaseRegistry) pruneLifecycleBlockedLocked(now time.Time) {
	for key, blocked := range r.blocked {
		if now.Sub(blocked.pushedAt) <= defaultRegisterChallengeTTL {
			continue
		}
		if r.recordByKey(key, now) == nil {
			delete(r.blocked, key)
		}
	}
}

func (r *leaseRegistry) cleanupExpired(now time.Time) []*leaseRecord {
	r.mu.Lock()
	expired := r.collectCleanupExpiredLocked(now)
	r.pruneLifecycleBlockedLocked(now)
	r.mu.Unlock()

	for _, record := range expired {
		r.closeRecord(record)
	}
	return expired
}

func (r *leaseRegistry) includePublicLeaseLocked(record *leaseRecord, now time.Time) bool {
	if record == nil || !record.isPublicEntry() || record.isExpired(now) {
		return false
	}
	if record.Metadata.Hide {
		return false
	}
	if record.reverse == nil {
		return true
	}
	if !r.isRoutableLocked(record.ServiceKey()) {
		return false
	}
	since := time.Duration(0)
	if !record.LastSeenAt.IsZero() {
		since = max(now.Sub(record.LastSeenAt), 0)
	}
	if record.reverse.ReadyCount() == 0 && since >= 3*time.Minute {
		return false
	}
	return true
}

func (r *leaseRegistry) collectPublicLeasesLocked(now time.Time) []types.Lease {
	leases := make([]types.Lease, 0, len(r.records))
	for _, record := range r.records {
		if !r.includePublicLeaseLocked(record, now) {
			continue
		}
		leases = append(leases, r.publicLease(record))
	}
	return leases
}

func (r *leaseRegistry) PublicLeases(now time.Time) []types.Lease {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.collectPublicLeasesLocked(now)
}

func (r *leaseRegistry) PolicyLeases(now time.Time) []types.PolicyLease {
	r.mu.RLock()
	defer r.mu.RUnlock()

	leases := make([]types.PolicyLease, 0, len(r.records))
	for _, record := range r.records {
		if record == nil || record.reverse == nil || record.isExpired(now) {
			continue
		}
		clientIP := "<unknown>"
		if record.sourceAddr.IsValid() {
			clientIP = record.sourceAddr.String()
		}
		identityKey := record.ServiceKey()
		serializedIdentityKey := identityKey.String()
		leases = append(leases, types.PolicyLease{
			Lease:       r.publicLease(record),
			IdentityKey: serializedIdentityKey,
			BPS:         r.bps.IdentityBPS(identityKey),
			ClientIP:    clientIP,
			ReportedIP:  record.ReportedIP,
		})
	}
	return leases
}

func (r *leaseRegistry) stats(now time.Time) (activeLeases, activeUDPFlows int64) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, record := range r.records {
		if record == nil || record.reverse == nil || record.isExpired(now) {
			continue
		}
		activeLeases++
		if record.datagram != nil {
			activeUDPFlows += record.datagram.ActiveFlowCount()
		}
	}
	return activeLeases, activeUDPFlows
}

func (r *leaseRegistry) deleteRecord(i int) {
	if record := r.records[i]; record != nil {
		r.cache.Detach(record.cacheLeaseLocked())
	}
	if record := r.records[i]; record != nil && r.overlay != nil {
		r.overlay.ForgetLease(record.id)
	}
	last := len(r.records) - 1
	r.records[i] = r.records[last]
	r.records[last] = nil
	r.records = r.records[:last]
}

func (r *leaseRegistry) publicLease(record *leaseRecord) types.Lease {
	lease := types.Lease{
		Namespace:               record.Namespace,
		LegacyCanonicalHostname: record.LegacyCanonicalHostname,
		Name:                    record.Name,
		Address:                 record.Address,
		ExpiresAt:               record.ExpiresAt,
		FirstSeenAt:             record.FirstSeenAt,
		LastSeenAt:              record.LastSeenAt,
		Hostname:                record.Hostname,
		CanonicalHostname:       record.CanonicalHostname,
		UDPEnabled:              record.datagram != nil,
		TCPEnabled:              record.tcpPort > 0,
		Metadata:                record.Metadata.Copy(),
	}
	if record.tcpPort > 0 {
		lease.TCPAddr = fmt.Sprintf("%s:%d", record.CanonicalHostname, record.tcpPort)
	}
	if record.datagram != nil {
		lease.UDPAddr = fmt.Sprintf("%s:%d", record.CanonicalHostname, record.datagram.UDPPort())
	}
	if record.reverse != nil {
		lease.Ready = record.reverse.ReadyCount()
	}
	return lease
}

func (r *leaseRegistry) closeRecord(record *leaseRecord) {
	if record == nil {
		return
	}
	record.Close()
	r.mu.Lock()
	defer r.mu.Unlock()
	if record.datagram != nil {
		r.udpPorts.release(record.datagram.UDPPort(), record)
	}
	if record.tcpPort > 0 {
		r.tcpPorts.release(record.tcpPort, record)
	}
}

func (r *leaseRegistry) rollbackRecord(record *leaseRecord) {
	if record == nil {
		return
	}
	record.Close()
	r.mu.Lock()
	defer r.mu.Unlock()
	if record.datagram != nil {
		r.udpPorts.rollback(record.datagram.UDPPort(), record)
	}
	if record.tcpPort > 0 {
		r.tcpPorts.rollback(record.tcpPort, record)
	}
}

var errPortExhausted = errors.New("no ports available")

type portReservation struct {
	port      int
	expiresAt time.Time
}

type portAllocation struct {
	record      *leaseRecord
	reservation portReservation
}

// portPool is registry-owned reservation metadata; all access holds leaseRegistry.mu.
type portPool struct {
	available []int
	inUse     map[int]portAllocation
	reserved  map[types.ServiceIdentityKey]portReservation
	grace     time.Duration
}

func newPortPool(min, max int, grace time.Duration) portPool {
	if min <= 0 || max <= 0 || min > max {
		return portPool{
			inUse:    make(map[int]portAllocation),
			reserved: make(map[types.ServiceIdentityKey]portReservation),
			grace:    grace,
		}
	}

	available := make([]int, 0, max-min+1)
	for port := min; port <= max; port++ {
		available = append(available, port)
	}
	return portPool{
		available: available,
		inUse:     make(map[int]portAllocation),
		reserved:  make(map[types.ServiceIdentityKey]portReservation),
		grace:     grace,
	}
}

func (a *portPool) allocate(record *leaseRecord) (int, error) {
	a.cleanupExpired(time.Now())

	key := record.ServiceKey()
	if res, ok := a.reserved[key]; ok {
		delete(a.reserved, key)
		a.inUse[res.port] = portAllocation{record: record, reservation: res}
		return res.port, nil
	}

	if len(a.available) == 0 {
		return 0, errPortExhausted
	}

	port := a.available[0]
	a.available = a.available[1:]
	a.inUse[port] = portAllocation{record: record}
	return port, nil
}

func (a *portPool) rollback(port int, record *leaseRecord) {
	allocation, ok := a.inUse[port]
	if !ok || allocation.record != record {
		return
	}
	delete(a.inUse, port)
	key := record.ServiceKey()
	if res := allocation.reservation; res.port != 0 && time.Now().Before(res.expiresAt) {
		if _, exists := a.reserved[key]; !exists {
			a.reserved[key] = res
			return
		}
	}
	a.available = append(a.available, port)
}

func (a *portPool) release(port int, record *leaseRecord) {
	owner, ok := a.inUse[port]
	if !ok || owner.record != record {
		return
	}
	delete(a.inUse, port)
	key := record.ServiceKey()

	if prev, exists := a.reserved[key]; exists {
		a.available = append(a.available, prev.port)
	}

	a.reserved[key] = portReservation{
		port:      port,
		expiresAt: time.Now().Add(a.grace),
	}
	a.cleanupExpired(time.Now())
}

func (a *portPool) cleanupExpired(now time.Time) {
	for key, res := range a.reserved {
		if now.After(res.expiresAt) {
			delete(a.reserved, key)
			a.available = append(a.available, res.port)
		}
	}
}
