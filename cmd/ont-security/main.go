// Binary guardian is the controller-runtime manager entry point for the
// guardian operator.
//
// GUARDIAN_ROLE is read at the very start of main, before any initialisation.
// An absent or invalid GUARDIAN_ROLE causes an immediate structured exit.
// guardian-schema.md §15.
//
// Controller sets are role-gated:
//   - Both roles: RBACPolicy, RBACProfile, IdentityProvider, IdentityBinding,
//     Bootstrap, PermissionService gRPC.
//   - role=management adds: PermissionSet, EPG, AuditSink.
//   - role=tenant adds: AuditForwarder.
//
// The CNPG migration runner (WS2 session/41) runs before controller registration
// when role=management. guardian-schema.md §3, §16.
package main

import (
	"flag"
	"os"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	ctrlwebhook "sigs.k8s.io/controller-runtime/pkg/webhook"

	securityv1alpha1 "github.com/ontai-dev/guardian/api/v1alpha1"
	"github.com/ontai-dev/guardian/internal/controller"
	"github.com/ontai-dev/guardian/internal/database"
	"github.com/ontai-dev/guardian/internal/permissionservice"
	"github.com/ontai-dev/guardian/internal/role"
	"github.com/ontai-dev/guardian/internal/webhook"
)

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(securityv1alpha1.AddToScheme(scheme))
}

func main() {
	// Read GUARDIAN_ROLE before any other initialisation.
	// An absent or invalid value causes an immediate structured exit.
	// guardian-schema.md §15.
	guardianRole := role.ReadFromEnv()

	var (
		metricsAddr          string
		healthProbeAddr      string
		enableLeaderElection bool
		webhookPort          int
		grpcAddr             string
	)

	// METRICS_ADDR overrides the metrics bind address. Defaults to :8080.
	// ServiceMonitor CRDs for Prometheus Operator scrape configuration are
	// deferred to a post-e2e observability session.
	metricsDefault := ":8080"
	if v := os.Getenv("METRICS_ADDR"); v != "" {
		metricsDefault = v
	}
	flag.StringVar(&metricsAddr, "metrics-bind-address", metricsDefault,
		"The address the metrics endpoint binds to. Overridden by METRICS_ADDR env var.")
	flag.StringVar(&healthProbeAddr, "health-probe-bind-address", ":8081",
		"The address the health and readiness probes bind to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", true,
		"Enable leader election for controller manager. "+
			"Ensures only one instance is active at a time.")
	flag.IntVar(&webhookPort, "webhook-port", 9443,
		"The port the admission webhook server binds to.")
	flag.StringVar(&grpcAddr, "grpc-address", ":9090",
		"The address the PermissionService gRPC endpoint binds to.")

	opts := zap.Options{}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))
	setupLog := ctrl.Log.WithName("setup")
	setupLog.Info("guardian starting", "role", string(guardianRole))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                  scheme,
		Metrics:                 metricsserver.Options{BindAddress: metricsAddr},
		HealthProbeBindAddress:  healthProbeAddr,
		LeaderElection:          enableLeaderElection,
		LeaderElectionID:        "guardian-leader",
		LeaderElectionNamespace: "seam-system",
		WebhookServer: ctrlwebhook.NewServer(ctrlwebhook.Options{
			Port: webhookPort,
		}),
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	// Create the in-memory EPG store shared between EPGReconciler and PermissionService.
	epgStore := permissionservice.NewInMemoryEPGStore()

	// For role=management: run the CNPG migration runner before controller registration.
	// If CNPG is unreachable, this blocks in a degraded hold loop (30s retry) until
	// CNPG becomes reachable. guardian-schema.md §3 Step 1, §16.
	var auditDB database.DB
	if guardianRole == role.RoleManagement {
		cfg, err := database.ConnConfigFromSecret(ctrl.SetupSignalHandler(), mgr.GetClient())
		if err != nil {
			// CNPG_SECRET_NAME / CNPG_SECRET_NAMESPACE not set is a hard failure.
			setupLog.Error(err, "cannot resolve CNPG connection config")
			os.Exit(1)
		}
		db, err := database.RunWithRetry(ctrl.SetupSignalHandler(), cfg, mgr.GetClient())
		if err != nil {
			// ctx cancelled — clean shutdown.
			setupLog.Error(err, "CNPG startup aborted")
			os.Exit(1)
		}
		auditDB = db
	}

	// Register controllers shared by both roles.
	if err := setupSharedControllers(mgr); err != nil {
		setupLog.Error(err, "unable to set up shared controllers")
		os.Exit(1)
	}

	// Register role-specific controllers.
	if err := setupRoleControllers(mgr, guardianRole, epgStore, auditDB); err != nil {
		setupLog.Error(err, "unable to set up role controllers", "role", string(guardianRole))
		os.Exit(1)
	}

	// Start the PermissionService gRPC server in the background.
	// Runs in both roles. guardian-schema.md §15.
	svc := permissionservice.NewService(epgStore)
	go func() {
		if err := permissionservice.ListenAndServe(grpcAddr, svc); err != nil {
			setupLog.Error(err, "PermissionService gRPC server failed")
		}
	}()

	// CS-INV-001: admission webhook is the enforcement mechanism.
	// CS-INV-006: leader election enforced by the manager.
	// INV-020: bootstrap RBAC window starts open here.
	modeGate := webhook.NewWebhookModeGate()
	enforcementRegistry := webhook.NewNamespaceEnforcementRegistry()

	if err := (&controller.BootstrapController{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("bootstrap-controller"),
		Gate:     modeGate,
		Registry: enforcementRegistry,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Bootstrap")
		os.Exit(1)
	}

	// WS3: verify seam-system carries seam.ontai.dev/webhook-mode=exempt.
	// guardian-schema.md §4, INV-020.
	if err := webhook.CheckBootstrapLabels(ctrl.SetupSignalHandler(), mgr.GetClient()); err != nil {
		setupLog.Error(err, "bootstrap label check failed; refusing to register admission webhook",
			"label", webhook.WebhookModeLabelKey,
			"expected", string(webhook.NamespaceModeExempt),
		)
		os.Exit(1)
	}

	bootstrapWindow := webhook.NewBootstrapWindow()
	webhookServer := webhook.NewAdmissionWebhookServer(mgr)
	baseResolver := &webhook.KubeNamespaceModeResolver{Client: mgr.GetClient()}
	namespaceModeResolver := webhook.NewGuardedNamespaceModeResolver(baseResolver, modeGate, enforcementRegistry)
	if err := webhookServer.Register(bootstrapWindow, namespaceModeResolver); err != nil {
		setupLog.Error(err, "unable to register admission webhook")
		os.Exit(1)
	}
	webhookServer.RegisterLineage()

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting guardian manager", "role", string(guardianRole))
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

// setupSharedControllers registers the controllers that run in both roles.
// guardian-schema.md §15.
func setupSharedControllers(mgr ctrl.Manager) error {
	if err := (&controller.RBACPolicyReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("rbacpolicy-controller"),
	}).SetupWithManager(mgr); err != nil {
		return err
	}

	if err := (&controller.RBACProfileReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("rbacprofile-controller"),
	}).SetupWithManager(mgr); err != nil {
		return err
	}

	if err := (&controller.IdentityBindingReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("identitybinding-controller"),
	}).SetupWithManager(mgr); err != nil {
		return err
	}

	if err := (&controller.IdentityProviderReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("identityprovider-controller"),
	}).SetupWithManager(mgr); err != nil {
		return err
	}

	// PermissionSnapshotReconciler: runs under both roles.
	// Both management and tenant need freshness tracking. guardian-schema.md §7.
	if err := (&controller.PermissionSnapshotReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("permissionsnapshot-controller"),
	}).SetupWithManager(mgr); err != nil {
		return err
	}

	return nil
}

// setupRoleControllers registers the controllers specific to the given role.
// guardian-schema.md §15.
func setupRoleControllers(mgr ctrl.Manager, r role.Role, epgStore *permissionservice.InMemoryEPGStore, auditDB database.DB) error {
	switch r {
	case role.RoleManagement:
		return setupManagementControllers(mgr, epgStore, auditDB)
	case role.RoleTenant:
		return setupTenantControllers(mgr)
	default:
		// ParseRole already prevents this path; guard defensively.
		return nil
	}
}

// setupManagementControllers registers controllers that run only when role=management.
// guardian-schema.md §15.
func setupManagementControllers(mgr ctrl.Manager, epgStore *permissionservice.InMemoryEPGStore, auditDB database.DB) error {
	if err := (&controller.PermissionSetReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("permissionset-controller"),
	}).SetupWithManager(mgr); err != nil {
		return err
	}

	if err := (&controller.EPGReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("epg-controller"),
		Store:    epgStore,
	}).SetupWithManager(mgr); err != nil {
		return err
	}

	// AuditSinkReconciler: full implementation in WS3 session/41.
	// Wrap the raw DB in an SQLAuditStore that implements database.AuditDatabase.
	var auditStore database.AuditDatabase
	if auditDB != nil {
		auditStore = database.NewSQLAuditStore(auditDB)
	}
	if err := (&controller.AuditSinkReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("auditsink-controller"),
		DB:       auditStore,
	}).SetupWithManager(mgr); err != nil {
		return err
	}

	return nil
}

// setupTenantControllers registers controllers that run only when role=tenant.
// guardian-schema.md §15.
func setupTenantControllers(mgr ctrl.Manager) error {
	clusterID := os.Getenv("CLUSTER_ID")

	// AuditForwarderController: full implementation in WS4 session/41.
	auditCh := make(chan controller.AuditForwarderEvent, 256)
	if err := (&controller.AuditForwarderController{
		Client:    mgr.GetClient(),
		Scheme:    mgr.GetScheme(),
		Recorder:  mgr.GetEventRecorderFor("auditforwarder-controller"),
		EventCh:   auditCh,
		ClusterID: clusterID,
	}).SetupWithManager(mgr); err != nil {
		return err
	}

	return nil
}
