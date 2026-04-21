// Package database_test covers RunWithRetry startup behaviour.
//
// These tests verify the degraded-hold contract: when CNPG is unreachable,
// RunWithRetry sets the CNPGUnreachable condition on the Guardian singleton CR
// and retries indefinitely without crashing. It exits only when the context
// is cancelled or CNPG becomes reachable.
//
// guardian-schema.md §3 Step 1, §16.
package database_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/ontai-dev/guardian/api/v1alpha1"
	"github.com/ontai-dev/guardian/internal/database"
)

// buildStartupScheme returns a scheme with all types needed for RunWithRetry tests.
func buildStartupScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	_ = securityv1alpha1.AddToScheme(s)
	return s
}

// guardianSingleton builds a minimal Guardian singleton CR used in startup tests.
func guardianSingleton() *securityv1alpha1.Guardian {
	return &securityv1alpha1.Guardian{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "guardian",
			Namespace: "seam-system",
		},
	}
}

// TestRunWithRetry_ContextCancellationStopsRetry verifies that RunWithRetry does
// not crash when CNPG is permanently unreachable — it holds in degraded state and
// exits cleanly when the context is cancelled. This satisfies the "no crash" contract
// from guardian-schema.md §3 Step 1.
func TestRunWithRetry_ContextCancellationStopsRetry(t *testing.T) {
	orig := database.OpenFunc
	defer func() { database.OpenFunc = orig }()

	attempts := 0
	database.OpenFunc = func(_ database.ConnConfig) (*sql.DB, error) {
		attempts++
		return nil, fmt.Errorf("connection refused: test injection")
	}

	// A 60ms context ensures the function exits before the 30s retry interval.
	// The select in RunWithRetry unblocks immediately on ctx.Done().
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()

	_, err := database.RunWithRetry(ctx, func() (database.ConnConfig, error) {
		return database.ConnConfig{}, nil
	}, nil)

	if err == nil {
		t.Fatal("expected RunWithRetry to return an error when context is cancelled")
	}
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Errorf("expected context error; got: %v", err)
	}
	if attempts == 0 {
		t.Error("expected at least one OpenFunc attempt before context cancellation")
	}
}

// TestRunWithRetry_CNPGUnreachableSetsCondition verifies that when CNPG is unreachable,
// RunWithRetry sets the CNPGUnreachable=True condition on the Guardian singleton CR.
// This is the primary observability signal for the degraded-hold state.
// guardian-schema.md §3 Step 1, §16.
func TestRunWithRetry_CNPGUnreachableSetsCondition(t *testing.T) {
	orig := database.OpenFunc
	defer func() { database.OpenFunc = orig }()

	database.OpenFunc = func(_ database.ConnConfig) (*sql.DB, error) {
		return nil, fmt.Errorf("connection refused: test injection")
	}

	// Build a fake kube client with the Guardian singleton pre-populated.
	s := buildStartupScheme()
	singleton := guardianSingleton()
	fakeKube := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(singleton).
		WithStatusSubresource(singleton).
		Build()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()

	// kube is non-nil so condition writes are attempted.
	database.RunWithRetry(ctx, func() (database.ConnConfig, error) { //nolint:errcheck
		return database.ConnConfig{}, nil
	}, fakeKube)

	// Re-fetch the Guardian singleton and verify the condition was set.
	g := &securityv1alpha1.Guardian{}
	if err := fakeKube.Get(context.Background(),
		client.ObjectKey{Name: "guardian", Namespace: "seam-system"}, g); err != nil {
		t.Fatalf("could not get Guardian singleton after RunWithRetry: %v", err)
	}

	cond := securityv1alpha1.FindCondition(g.Status.Conditions, database.ConditionTypeCNPGUnreachable)
	if cond == nil {
		t.Fatal("CNPGUnreachable condition was not set on Guardian singleton")
	}
	if cond.Status != metav1.ConditionTrue {
		t.Errorf("expected CNPGUnreachable=True; got %s", cond.Status)
	}
	if cond.Reason != database.ReasonCNPGRetrying {
		t.Errorf("expected reason %q; got %q", database.ReasonCNPGRetrying, cond.Reason)
	}
}
