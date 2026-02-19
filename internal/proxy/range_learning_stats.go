package proxy

import "sync/atomic"

type rangeLearningStats struct {
	skipCount           uint64
	downgradeCount      uint64
	recoverCount        uint64
	probeTotal          uint64
	probeSuccess        uint64
	probeFailure        uint64
	pseudoRangeCount    uint64
	reasonUnsupported   uint64
	reasonUnsatisfiable uint64
}

func newRangeLearningStats() *rangeLearningStats {
	return &rangeLearningStats{}
}

func (s *rangeLearningStats) snapshot() map[string]interface{} {
	if s == nil {
		return map[string]interface{}{}
	}
	return map[string]interface{}{
		"skip_count":           atomic.LoadUint64(&s.skipCount),
		"downgrade_count":      atomic.LoadUint64(&s.downgradeCount),
		"recover_count":        atomic.LoadUint64(&s.recoverCount),
		"probe_total":          atomic.LoadUint64(&s.probeTotal),
		"probe_success":        atomic.LoadUint64(&s.probeSuccess),
		"probe_failure":        atomic.LoadUint64(&s.probeFailure),
		"pseudo_range_count":   atomic.LoadUint64(&s.pseudoRangeCount),
		"reason_unsupported":   atomic.LoadUint64(&s.reasonUnsupported),
		"reason_unsatisfiable": atomic.LoadUint64(&s.reasonUnsatisfiable),
	}
}
