// Copyright (c) 2026, Janoš Guljaš <janos@resenje.org>
// All rights reserved.

package sajberpank

// Export internal functions for black-box testing (e.g. package sajberpank_test).
var (
	NewKeyEnvelope          = newKeyEnvelope
	NewKeyEnvelopeWithSuite = newKeyEnvelopeWithSuite
)
