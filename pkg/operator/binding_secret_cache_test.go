/*
SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and valkey-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package operator_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/sap/valkey-operator/pkg/operator"
)

// Binding only needs named Secret reads and updates in the Valkey namespace.
// Those permissions must suffice without permission to enumerate Secrets in any
// namespace. A real HTTP boundary allows only that named GET/PUT; the production
// manager client must complete both operations without starting a Secret informer.
// This isolates the controller-runtime cache boundary, rather than mocking its
// client or asserting which Go types the operator returns.
func TestBindingSecretAccessDoesNotRequireSecretListWatch(t *testing.T) {
	const secretPath = "/api/v1/namespaces/binding/secrets/valkey-binding"
	stored := &corev1.Secret{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"},
		ObjectMeta: metav1.ObjectMeta{Namespace: "binding", Name: "valkey-binding", ResourceVersion: "1"},
		Data:       map[string][]byte{"password": []byte("test-fixture")},
	}
	var mu sync.Mutex
	var denied []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != secretPath || (r.Method != http.MethodGet && r.Method != http.MethodPut) || r.URL.Query().Get("watch") != "" {
			denied = append(denied, r.Method+" "+r.URL.Path)
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(&metav1.Status{
				TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Status"},
				Status:   metav1.StatusFailure, Reason: metav1.StatusReasonForbidden, Code: http.StatusForbidden,
				Message: "only named Secret get/update in namespace binding is allowed",
			})
			return
		}
		if r.Method == http.MethodPut {
			var updated corev1.Secret
			if err := json.NewDecoder(r.Body).Decode(&updated); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			stored = updated.DeepCopy()
			stored.ResourceVersion = "2"
		}
		_ = json.NewEncoder(w).Encode(stored)
	}))
	defer server.Close()

	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, apiextensionsv1.AddToScheme, apiregistrationv1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	operator.InitScheme(scheme)
	mapper := meta.NewDefaultRESTMapper([]schema.GroupVersion{corev1.SchemeGroupVersion})
	mapper.Add(corev1.SchemeGroupVersion.WithKind("Secret"), meta.RESTScopeNamespace)
	config := &rest.Config{Host: server.URL, ContentConfig: rest.ContentConfig{ContentType: "application/json"}}
	direct, err := client.New(config, client.Options{Scheme: scheme, Mapper: mapper})
	if err != nil {
		t.Fatal(err)
	}
	controlCtx, cancelControl := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelControl()
	key := types.NamespacedName{Namespace: "binding", Name: "valkey-binding"}
	if err := direct.Get(controlCtx, key, &corev1.Secret{}); err != nil {
		t.Fatalf("named Secret GET must be allowed by the HTTP boundary: %v", err)
	}
	if err := direct.List(controlCtx, &corev1.SecretList{}); !apierrors.IsForbidden(err) {
		t.Fatal("HTTP boundary must forbid global Secret LIST")
	}
	if err := direct.Get(controlCtx, types.NamespacedName{Namespace: "other", Name: key.Name}, &corev1.Secret{}); !apierrors.IsForbidden(err) {
		t.Fatal("HTTP boundary must forbid Secret access in another namespace")
	}
	mu.Lock()
	denied = nil
	mu.Unlock()

	mgr, err := ctrl.NewManager(config, ctrl.Options{
		Scheme:         scheme,
		MapperProvider: func(*rest.Config, *http.Client) (meta.RESTMapper, error) { return mapper, nil },
		Client: client.Options{Cache: &client.CacheOptions{
			DisableFor: append(operator.GetUncacheableTypes(), &apiextensionsv1.CustomResourceDefinition{}, &apiregistrationv1.APIService{}),
		}},
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
	})
	if err != nil {
		t.Fatal(err)
	}
	managerCtx, cancelManager := context.WithCancel(context.Background())
	managerDone := make(chan error, 1)
	go func() { managerDone <- mgr.Start(managerCtx) }()
	defer func() {
		cancelManager()
		select {
		case err := <-managerDone:
			if err != nil {
				t.Errorf("manager shutdown: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("manager did not stop within deadline")
		}
	}()
	operationCtx, cancelOperation := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelOperation()
	if !mgr.GetCache().WaitForCacheSync(operationCtx) {
		t.Fatal("manager cache did not start within deadline")
	}
	secret := &corev1.Secret{}
	if err := mgr.GetClient().Get(operationCtx, key, secret); err != nil {
		mu.Lock()
		requests := append([]string(nil), denied...)
		mu.Unlock()
		t.Fatalf("named Secret GET must work without list/watch permissions: %v; denied HTTP requests: %v", err, requests)
	}
	secret.Data["password"] = []byte("updated-fixture")
	if err := mgr.GetClient().Update(operationCtx, secret); err != nil {
		t.Fatalf("named Secret update must work without list/watch permissions: %v", err)
	}
	persisted := &corev1.Secret{}
	if err := direct.Get(operationCtx, key, persisted); err != nil {
		t.Fatalf("read updated Secret: %v", err)
	}
	if !bytes.Equal(persisted.Data["password"], []byte("updated-fixture")) {
		t.Error("named Secret update was not persisted")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(denied) != 0 {
		t.Errorf("binding Secret access attempted requests outside named get/update: %v", denied)
	}
}
