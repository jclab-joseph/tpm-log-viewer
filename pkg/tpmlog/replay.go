package tpmlog

import (
	"fmt"
	"sort"
)

// PCRValue 는 리플레이로 재계산한 PCR 값이다.
type PCRValue struct {
	PCRIndex uint32
	Alg      AlgorithmID
	Value    []byte
	// Extends 는 이 PCR 에 실제로 확장된 이벤트 수다(EV_NO_ACTION 제외).
	Extends int
}

// ReplayPCRs 는 로그의 다이제스트를 순서대로 확장해 PCR 최종값을 계산한다.
// TPM 에서 읽은 실제 PCR 값과 비교하면 로그의 무결성을 확인할 수 있다.
//
// EV_NO_ACTION 이벤트는 확장되지 않는다(스펙에 따라 로그 정보 전달용).
// PCR 0 의 초기값은 StartupLocality 이벤트가 있으면 그에 맞춰 설정한다.
func (l *Log) ReplayPCRs(alg AlgorithmID) ([]PCRValue, error) {
	h, ok := alg.Hash()
	if !ok {
		return nil, fmt.Errorf("replay not supported for %s", alg)
	}
	size := h.Size()

	values := map[uint32][]byte{}
	counts := map[uint32]int{}

	for i := range l.Events {
		ev := &l.Events[i]
		if ev.Type == EvNoAction {
			// StartupLocality 는 PCR 0 초기값에만 영향을 준다.
			if sl, ok := ev.Decoded().(StartupLocality); ok && sl.Locality != 0 {
				if _, seen := values[ev.PCRIndex]; !seen {
					init := make([]byte, size)
					init[size-1] = sl.Locality
					values[ev.PCRIndex] = init
				}
			}
			continue
		}
		d, ok := ev.Digest(alg)
		if !ok {
			continue
		}
		if len(d.Value) != size {
			return nil, fmt.Errorf("event #%d: %s digest is %d bytes, expected %d", ev.Sequence, alg, len(d.Value), size)
		}
		cur, seen := values[ev.PCRIndex]
		if !seen {
			cur = make([]byte, size)
		}
		hasher := h.New()
		hasher.Write(cur)
		hasher.Write(d.Value)
		values[ev.PCRIndex] = hasher.Sum(nil)
		counts[ev.PCRIndex]++
	}

	out := make([]PCRValue, 0, len(values))
	for pcr, v := range values {
		out = append(out, PCRValue{PCRIndex: pcr, Alg: alg, Value: v, Extends: counts[pcr]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PCRIndex < out[j].PCRIndex })
	return out, nil
}
