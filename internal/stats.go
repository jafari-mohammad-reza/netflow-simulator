package internal

import "runtime"

func ReadUsage() (routines int, heapusage float64) {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	numGoroutines := runtime.NumGoroutine()

	return numGoroutines, float64(mem.Alloc)
}
