package database

import (
	"context"
	"fmt"
	"os"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// CNPGSecretNameEnv is the environment variable holding the name of the CNPG
// connection Secret. The Secret must exist in CNPGSecretNamespaceEnv namespace.
// guardian-schema.md §16.
const CNPGSecretNameEnv = "CNPG_SECRET_NAME"

// CNPGSecretNamespaceEnv is the environment variable holding the namespace of
// the CNPG connection Secret.
const CNPGSecretNamespaceEnv = "CNPG_SECRET_NAMESPACE"

// ConnConfigFromSecret reads the CNPG connection Secret identified by the
// CNPG_SECRET_NAME and CNPG_SECRET_NAMESPACE environment variables and builds
// a ConnConfig from its data fields (host, port, dbname, user, password).
func ConnConfigFromSecret(ctx context.Context, kube client.Client) (ConnConfig, error) {
	name := os.Getenv(CNPGSecretNameEnv)
	namespace := os.Getenv(CNPGSecretNamespaceEnv)
	if name == "" || namespace == "" {
		return ConnConfig{}, fmt.Errorf("%s and %s must be set for role=management",
			CNPGSecretNameEnv, CNPGSecretNamespaceEnv)
	}

	secret := &corev1.Secret{}
	if err := kube.Get(ctx, client.ObjectKey{Name: name, Namespace: namespace}, secret); err != nil {
		return ConnConfig{}, fmt.Errorf("get CNPG secret %s/%s: %w", namespace, name, err)
	}

	get := func(field string) (string, error) {
		val, ok := secret.Data[field]
		if !ok || len(val) == 0 {
			return "", fmt.Errorf("CNPG secret %s/%s missing field %q", namespace, name, field)
		}
		return string(val), nil
	}

	host, err := get(SecretFieldHost)
	if err != nil {
		return ConnConfig{}, err
	}
	port, err := get(SecretFieldPort)
	if err != nil {
		return ConnConfig{}, err
	}
	dbname, err := get(SecretFieldDBName)
	if err != nil {
		return ConnConfig{}, err
	}
	user, err := get(SecretFieldUser)
	if err != nil {
		return ConnConfig{}, err
	}
	password, err := get(SecretFieldPassword)
	if err != nil {
		return ConnConfig{}, err
	}

	return ConnConfig{
		Host:     host,
		Port:     port,
		DBName:   dbname,
		User:     user,
		Password: password,
	}, nil
}
