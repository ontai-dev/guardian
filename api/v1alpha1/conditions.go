package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SetCondition finds an existing condition of the given type in the slice and
// updates it in-place, or appends a new condition if none exists.
//
// LastTransitionTime is updated only when the Status value changes, following
// the standard Kubernetes condition update pattern. This prevents spurious
// status updates when conditions are repeatedly reconciled with no change.
//
// Parameters:
//   - conditions: pointer to the conditions slice to update (modified in-place)
//   - conditionType: the Type field of the condition to set
//   - status: the new Status value (True, False, or Unknown)
//   - reason: a CamelCase reason code (must be non-empty)
//   - message: human-readable message (may be empty)
//   - observedGeneration: the CR generation that was observed when this was set
func SetCondition(
	conditions *[]metav1.Condition,
	conditionType string,
	status metav1.ConditionStatus,
	reason string,
	message string,
	observedGeneration int64,
) {
	now := metav1.Now()
	existing := FindCondition(*conditions, conditionType)
	if existing == nil {
		*conditions = append(*conditions, metav1.Condition{
			Type:               conditionType,
			Status:             status,
			Reason:             reason,
			Message:            message,
			ObservedGeneration: observedGeneration,
			LastTransitionTime: now,
		})
		return
	}
	// Only advance LastTransitionTime when the Status value actually changes.
	if existing.Status != status {
		existing.LastTransitionTime = now
	}
	existing.Status = status
	existing.Reason = reason
	existing.Message = message
	existing.ObservedGeneration = observedGeneration
}

// FindCondition returns a pointer to the first condition in the slice with the
// given Type, or nil if no such condition exists.
//
// The returned pointer is into the original slice — callers may modify the
// condition via the pointer. Do not hold the pointer across slice growth.
func FindCondition(conditions []metav1.Condition, conditionType string) *metav1.Condition {
	for i := range conditions {
		if conditions[i].Type == conditionType {
			return &conditions[i]
		}
	}
	return nil
}
