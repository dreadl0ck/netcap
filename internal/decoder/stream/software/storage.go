package software

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/dreadl0ck/netcap/internal/aggregate"
	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/exploit"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/vulnerability"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

var softwareLocks [64]sync.Mutex
var storedSoftwareCount atomic.Int64

func softwareState() *aggregate.Store {
	if decoderconfig.Instance == nil {
		return nil
	}
	return decoderconfig.Instance.AggregateStore
}

func softwareIdentity(s *types.Software) string {
	id := s.Product + "/" + s.Version
	if s.SourceName == "Passive WebTech" {
		id += "/" + s.Notes + "/" + strings.Join(s.Flows, ",")
	}
	if s.ObservedHost != "" {
		id += "/" + s.ObservedHost + "/" + s.ObservationRole
	}
	return id
}

func softwareLock(id string) *sync.Mutex {
	h := fnv.New64a()
	_, _ = h.Write([]byte(id))
	return &softwareLocks[h.Sum64()%uint64(len(softwareLocks))]
}

type storedSoftware struct {
	record *types.Software
	counts [4]uint64
}

func softwareLists(s *types.Software) [4]*[]string {
	return [4]*[]string{&s.Flows, &s.CommunityIDs, &s.DeviceProfiles, &s.DPIResults}
}

func softwareFieldPrefix(id string, field int) string {
	return fmt.Sprintf("software/fields/%s/%d/", base64.RawURLEncoding.EncodeToString([]byte(id)), field)
}

func decodeSoftware(wire []byte) (storedSoftware, error) {
	s := storedSoftware{record: &types.Software{}}
	if len(wire) < 33 || wire[0] != 1 {
		return s, fmt.Errorf("invalid stored Software record")
	}
	for i := range s.counts {
		s.counts[i] = binary.LittleEndian.Uint64(wire[1+i*8:])
	}
	return s, proto.Unmarshal(wire[33:], s.record)
}

func putSoftwareBase(tx *aggregate.Tx, id string, s storedSoftware) error {
	base := proto.Clone(s.record).(*types.Software)
	for _, list := range softwareLists(base) {
		*list = nil
	}
	wire := make([]byte, 33)
	wire[0] = 1
	for i, count := range s.counts {
		binary.LittleEndian.PutUint64(wire[1+i*8:], count)
	}
	data, err := proto.Marshal(base)
	if err != nil {
		return err
	}
	return tx.Put("software/base/"+id, append(wire, data...))
}

func loadSoftwareLists(tx *aggregate.Tx, id string, s *types.Software) error {
	for field, list := range softwareLists(s) {
		*list = nil
		if err := tx.Each(softwareFieldPrefix(id, field)+"order/", func(_ string, value []byte) error {
			*list = append(*list, string(value))
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}

func replaceSoftwareLists(tx *aggregate.Tx, id string, s *storedSoftware) error {
	for field, list := range softwareLists(s.record) {
		prefix := softwareFieldPrefix(id, field)
		if err := tx.Delete(prefix); err != nil {
			return err
		}
		s.counts[field] = 0
		for _, value := range *list {
			if err := appendSoftwareValue(tx, prefix, &s.counts[field], value, false); err != nil {
				return err
			}
		}
	}
	return nil
}

func appendSoftwareValue(tx *aggregate.Tx, prefix string, count *uint64, value string, unique bool) error {
	seen := prefix + "seen/" + base64.RawURLEncoding.EncodeToString([]byte(value))
	if unique {
		if _, found, err := tx.Get(seen); err != nil || found {
			return err
		}
	}
	if *count == ^uint64(0) {
		return fmt.Errorf("Software list counter exhausted")
	}
	if err := tx.Put(fmt.Sprintf("%sorder/%016x", prefix, *count), []byte(value)); err != nil {
		return err
	}
	*count++
	return tx.Put(seen, []byte{1})
}

// WriteHTTPSoftware appends observed flow memberships without decoding old lists.
func WriteHTTPSoftware(items []*AtomicSoftware, flow, communityID string) {
	if softwareState() != nil {
		writeStoredSoftwareBatch(items, nil, &softwareMembership{flow: flow, communityID: communityID})
		return
	}
	WriteSoftware(items, func(s *AtomicSoftware) {
		s.Lock()
		defer s.Unlock()
		if !slices.Contains(s.Flows, flow) {
			s.Flows = append(s.Flows, flow)
		}
		if communityID != "" && !slices.Contains(s.CommunityIDs, communityID) {
			s.CommunityIDs = append(s.CommunityIDs, communityID)
		}
	})
}

type softwareMembership struct{ flow, communityID string }

// StorePassiveSoftware retains observations that do not authorize CVE lookups.
func StorePassiveSoftware(records []*types.Software) int {
	Store.operations.RLock()
	defer Store.operations.RUnlock()
	created := 0
	for _, record := range records {
		if record == nil {
			continue
		}
		candidate := proto.Clone(record).(*types.Software)
		id := softwareIdentity(candidate)
		if state := softwareState(); state != nil {
			added, err := storeSoftwareObservation(state, id, candidate, nil, nil)
			if err != nil {
				return created
			}
			if added {
				created++
			}
			continue
		}
		Store.Lock()
		if _, found := Store.Items[id]; !found {
			Store.Items[id] = &AtomicSoftware{Software: candidate}
			created++
		}
		Store.Unlock()
	}
	return created
}

func writeStoredSoftwareBatch(items []*AtomicSoftware, update func(*AtomicSoftware), membership *softwareMembership) {
	Store.operations.RLock()
	defer Store.operations.RUnlock()
	state := softwareState()
	for _, input := range items {
		if input == nil {
			continue
		}
		input.Lock()
		if input.Software == nil {
			input.Unlock()
			continue
		}
		candidate := proto.Clone(input.Software).(*types.Software)
		input.Unlock()
		id := softwareIdentity(candidate)
		if len(candidate.Version) > 15 && candidate.SourceName != "Passive WebTech" {
			candidate.Version = candidate.Version[:15] + "..."
		}
		created, err := storeSoftwareObservation(state, id, candidate, update, membership)
		if err != nil {
			return
		}
		if !created || candidate.SourceName == "Passive WebTech" {
			continue
		}
		// Lookups can call writers that reenter Software; no row/store lock is held.
		vulnerability.VulnerabilitiesLookup(candidate)
		exploit.ExploitsLookup(candidate)
		if err := mergeSoftwareAssessment(state, id, candidate); err != nil {
			return
		}
	}
}

func mergeSoftwareAssessment(state *aggregate.Store, id string, candidate *types.Software) error {
	lock := softwareLock(id)
	lock.Lock()
	defer lock.Unlock()
	return state.Do(func(tx *aggregate.Tx) error {
		wire, found, err := tx.Get("software/base/" + id)
		if err != nil || !found {
			return err
		}
		s, err := decodeSoftware(wire)
		if err != nil {
			return err
		}
		s.record.VulnerabilityAssessment = candidate.VulnerabilityAssessment
		s.record.HasKnownVulnerabilities = s.record.HasKnownVulnerabilities || candidate.HasKnownVulnerabilities
		return putSoftwareBase(tx, id, s)
	})
}

func storeSoftwareObservation(state *aggregate.Store, id string, candidate *types.Software, update func(*AtomicSoftware), membership *softwareMembership) (bool, error) {
	lock := softwareLock(id)
	lock.Lock()
	defer lock.Unlock()
	s := storedSoftware{record: candidate}
	var found bool
	err := state.Do(func(tx *aggregate.Tx) error {
		wire, exists, err := tx.Get("software/base/" + id)
		found = exists
		if err != nil || !exists {
			return err
		}
		s, err = decodeSoftware(wire)
		if err == nil && update != nil {
			err = loadSoftwareLists(tx, id, s.record)
		}
		return err
	})
	if err != nil {
		return false, err
	}
	if found && update == nil && membership == nil {
		return false, nil
	}
	if found && update != nil {
		update(&AtomicSoftware{Software: s.record})
	}
	err = state.Do(func(tx *aggregate.Tx) error {
		if !found || update != nil {
			if err := replaceSoftwareLists(tx, id, &s); err != nil {
				return err
			}
		} else if membership != nil {
			if err := appendSoftwareValue(tx, softwareFieldPrefix(id, 0), &s.counts[0], membership.flow, true); err != nil {
				return err
			}
			if membership.communityID != "" {
				if err := appendSoftwareValue(tx, softwareFieldPrefix(id, 1), &s.counts[1], membership.communityID, true); err != nil {
					return err
				}
			}
		}
		return putSoftwareBase(tx, id, s)
	})
	if err == nil && !found {
		storedSoftwareCount.Add(1)
	}
	return !found, err
}

func walkStoredSoftware(fn func(*types.Software) error) error {
	state := softwareState()
	last := ""
	for {
		var key string
		var wire []byte
		var found bool
		err := state.Do(func(tx *aggregate.Tx) error {
			var err error
			key, wire, found, err = tx.Next("software/base/", last)
			return err
		})
		if err != nil || !found {
			return err
		}
		s, err := decodeSoftware(wire)
		if err != nil {
			return err
		}
		id := strings.TrimPrefix(key, "software/base/")
		if err := state.Do(func(tx *aggregate.Tx) error { return loadSoftwareLists(tx, id, s.record) }); err != nil {
			return err
		}
		if err := fn(s.record); err != nil {
			return err
		}
		last = key
	}
}
