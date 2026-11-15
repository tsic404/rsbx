package fusefs

// HashForTest exposes the cache key derivation to black-box tests.
func HashForTest(p string) string { return hash(p) }
