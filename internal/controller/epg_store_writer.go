package controller

import "github.com/ontai-dev/guardian/internal/epg"

// EPGStoreWriter is the write-side interface for the PermissionService EPG store.
// EPGReconciler calls Update after each successful EPG computation. The concrete
// implementation (InMemoryEPGStore) lives in internal/permissionservice; it is
// wired by main.go so that the controller package does not import permissionservice.
type EPGStoreWriter interface {
	Update(result epg.EPGComputationResult)
}
