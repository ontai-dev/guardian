package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	securityv1alpha1 "github.com/ontai-dev/guardian/api/v1alpha1"
)

const (
	// CNPGRetryInterval is the interval between CNPG reachability retries
	// when Guardian is in degraded hold. guardian-schema.md §3 Step 1.
	CNPGRetryInterval = 30 * time.Second

	// ConditionTypeCNPGUnreachable is the condition set on the Guardian singleton
	// CR when CNPG is not reachable at startup. guardian-schema.md §3.
	ConditionTypeCNPGUnreachable = "CNPGUnreachable"

	// ReasonCNPGRetrying is the reason string used while Guardian is retrying.
	ReasonCNPGRetrying = "CNPGRetrying"

	// ReasonCNPGReady is the reason string set when CNPG becomes reachable.
	ReasonCNPGReady = "CNPGReady"
)

// OpenFunc is the function signature for opening a database connection.
// It is a variable so tests can inject a fake that never dials a real database.
var OpenFunc = func(cfg ConnConfig) (*sql.DB, error) {
	return Open(cfg)
}

// RunWithRetry attempts to open a CNPG connection, run migrations, and return
// the connected DB. If CNPG is unreachable, it sets the CNPGUnreachable condition
// on the Guardian singleton CR and retries every CNPGRetryInterval until ctx is
// cancelled or the connection succeeds. It does not crash — it holds in degraded
// state per guardian-schema.md §3 Step 1.
//
// configFn is called on every retry attempt so that a rotated CNPG credential
// (secret updated by CNPG after a pod restart) is picked up without requiring
// a guardian restart. kube is used only for condition writes; if nil (tests),
// condition writes are skipped.
func RunWithRetry(ctx context.Context, configFn func() (ConnConfig, error), kube client.Client) (DB, error) {
	logger := log.FromContext(ctx).WithName("cnpg-startup")

	for {
		cfg, cfgErr := configFn()
		if cfgErr != nil {
			logger.Error(cfgErr, "CNPG config unresolvable; entering degraded hold")
			if kube != nil {
				msg := fmt.Sprintf("CNPG config unresolvable: %v. Retrying every %s.", cfgErr, CNPGRetryInterval)
				_ = setCNPGCondition(ctx, kube, metav1.ConditionTrue, ReasonCNPGRetrying, msg)
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(CNPGRetryInterval):
			}
			continue
		}
		db, err := OpenFunc(cfg)
		if err == nil {
			runner := NewMigrationRunner(db)
			if migErr := runner.Run(ctx); migErr == nil {
				if kube != nil {
					_ = setCNPGCondition(ctx, kube, metav1.ConditionFalse,
						ReasonCNPGReady, "CNPG is reachable and migrations are applied.")
				}
				logger.Info("CNPG connected and migrations applied")
				return db, nil
			} else {
				logger.Error(migErr, "migration runner failed; will retry")
				err = fmt.Errorf("migration runner: %w", migErr)
				db.Close()
			}
		} else {
			logger.Error(err, "CNPG unreachable; entering degraded hold")
		}

		// Set CNPGUnreachable condition on the Guardian singleton CR.
		if kube != nil {
			msg := fmt.Sprintf("CNPG unreachable: %v. Retrying every %s.", err, CNPGRetryInterval)
			_ = setCNPGCondition(ctx, kube, metav1.ConditionTrue, ReasonCNPGRetrying, msg)
		}

		// Wait before retrying. Return if ctx is cancelled.
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(CNPGRetryInterval):
		}
	}
}

// setCNPGCondition writes the CNPGUnreachable condition to the Guardian singleton CR.
// Errors are logged and ignored — condition writes are best-effort during startup.
func setCNPGCondition(ctx context.Context, kube client.Client,
	status metav1.ConditionStatus, reason, message string) error {

	logger := log.FromContext(ctx)

	g := &securityv1alpha1.Guardian{}
	if err := kube.Get(ctx, client.ObjectKey{
		Name:      "guardian",
		Namespace: "seam-system",
	}, g); err != nil {
		logger.Error(err, "setCNPGCondition: could not get Guardian singleton")
		return err
	}

	patchBase := client.MergeFrom(g.DeepCopy())
	securityv1alpha1.SetCondition(
		&g.Status.Conditions,
		ConditionTypeCNPGUnreachable,
		status,
		reason,
		message,
		g.Generation,
	)
	if err := kube.Status().Patch(ctx, g, patchBase); err != nil {
		logger.Error(err, "setCNPGCondition: failed to patch Guardian status")
		return err
	}
	return nil
}
