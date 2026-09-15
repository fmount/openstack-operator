package openstack

import (
	"context"
	"fmt"
	"strings"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openstack-k8s-operators/lib-common/modules/common/condition"
	"github.com/openstack-k8s-operators/lib-common/modules/common/configmap"
	"github.com/openstack-k8s-operators/lib-common/modules/common/helper"
	"github.com/openstack-k8s-operators/lib-common/modules/common/util"
	corev1 "github.com/openstack-k8s-operators/openstack-operator/api/core/v1beta1"
	k8s_corev1 "k8s.io/api/core/v1"
	k8s_errors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
)

// Let's map the httpd config with the TLSProfile gathered from the APIServer
var tlsVersionToSSLProtocol = map[configv1.TLSProtocolVersion]string{
	configv1.VersionTLS10: "all -SSLv2 -SSLv3",
	configv1.VersionTLS11: "all -SSLv2 -SSLv3 -TLSv1",
	configv1.VersionTLS12: "all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1",
	configv1.VersionTLS13: "all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1 -TLSv1.2",
}

// ReconcileTLSProfile reads the OpenShift APIServer TLS security profile and
// publishes the resolved SSLCipherSuite and SSLProtocol values in the
// util.TLSProfileConfigMap ConfigMap.
//
// lib-common merges that ConfigMap underneath the ConfigOptions of every
// Template it renders, so service operators inherit the cluster TLS settings
// NOTE: openstack-operator owns the object's whole lifecycle; lib-common only
// consumes it, and renders built-in defaults when it is not present.
func ReconcileTLSProfile(ctx context.Context, instance *corev1.OpenStackControlPlane, helper *helper.Helper) (ctrl.Result, error) {
	Log := GetLogger(ctx)

	apiServer := &configv1.APIServer{}
	if err := helper.GetClient().Get(ctx, types.NamespacedName{Name: "cluster"}, apiServer); err != nil {
		if k8s_errors.IsNotFound(err) || meta.IsNoMatchError(err) {
			Log.Info("APIServer CR not found, skipping TLS profile resolution (defaults will apply)")

			// The cluster APIServer CR is not found or not available. Drop
			// any ConfigMap published earlier and fall back to the built-in
			// defaults. If there's a pre-existing leftover, it would keep pinning
			// services to a profile the cluster no longer declares
			if err := configmap.DeleteConfigMapWithName(
				ctx, helper, util.TLSProfileConfigMap, instance.Namespace,
			); err != nil {
				instance.Status.Conditions.Set(condition.FalseCondition(
					corev1.OpenStackControlPlaneTLSProfileReadyCondition,
					condition.ErrorReason,
					condition.SeverityWarning,
					corev1.OpenStackControlPlaneTLSProfileReadyErrorMessage,
					err.Error()))
				return ctrl.Result{}, err
			}

			instance.Status.Conditions.MarkTrue(
				corev1.OpenStackControlPlaneTLSProfileReadyCondition,
				corev1.OpenStackControlPlaneTLSProfileReadyMessage)
			return ctrl.Result{}, nil
		}
		instance.Status.Conditions.Set(condition.FalseCondition(
			corev1.OpenStackControlPlaneTLSProfileReadyCondition,
			condition.ErrorReason,
			condition.SeverityWarning,
			corev1.OpenStackControlPlaneTLSProfileReadyErrorMessage,
			err.Error()))
		return ctrl.Result{}, err
	}

	cipherSuite, sslProtocol, err := resolveTLSProfile(apiServer.Spec.TLSSecurityProfile)
	if err != nil {
		instance.Status.Conditions.Set(condition.FalseCondition(
			corev1.OpenStackControlPlaneTLSProfileReadyCondition,
			condition.ErrorReason,
			condition.SeverityWarning,
			corev1.OpenStackControlPlaneTLSProfileReadyErrorMessage,
			err.Error()))
		return ctrl.Result{}, err
	}

	Log.Info("Resolved TLS profile from APIServer", "SSLCipherSuite", cipherSuite, "SSLProtocol", sslProtocol)

	// Write the retrieved data to a ConfigMap controlled by openstack-operator
	// This is used to push/inject a global configuration to the underlying
	// openstack services
	cm := &k8s_corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      util.TLSProfileConfigMap,
			Namespace: instance.Namespace,
		},
		Data: map[string]string{
			"SSLCipherSuite": cipherSuite,
			"SSLProtocol":    sslProtocol,
		},
	}

	// The control plane is set as controller owner, so the ConfigMap is
	// garbage-collected when the control plane is deleted.
	if _, _, err := configmap.CreateOrPatchRawConfigMap(ctx, helper, instance, cm, false); err != nil {
		instance.Status.Conditions.Set(condition.FalseCondition(
			corev1.OpenStackControlPlaneTLSProfileReadyCondition,
			condition.ErrorReason,
			condition.SeverityWarning,
			corev1.OpenStackControlPlaneTLSProfileReadyErrorMessage,
			err.Error()))
		return ctrl.Result{}, err
	}

	instance.Status.Conditions.MarkTrue(
		corev1.OpenStackControlPlaneTLSProfileReadyCondition,
		corev1.OpenStackControlPlaneTLSProfileReadyMessage)

	return ctrl.Result{}, nil
}

// resolveTLSProfile resolves a TLSSecurityProfile into Apache httpd directives.
// If the profile is nil, the OpenShift default (Intermediate) is used.
func resolveTLSProfile(profile *configv1.TLSSecurityProfile) (cipherSuite string, sslProtocol string, err error) {
	// pick the spec the cluster asked for: a Custom profile carries its own,
	// the named ones come from the table OpenShift ships
	var spec *configv1.TLSProfileSpec
	switch {
	case profile == nil:
		spec = configv1.TLSProfiles[configv1.TLSProfileIntermediateType]

	case profile.Type == configv1.TLSProfileCustomType:
		if profile.Custom == nil {
			return "", "", fmt.Errorf("custom TLS profile type specified but no custom profile provided")
		}
		spec = &profile.Custom.TLSProfileSpec

	default:
		var ok bool
		spec, ok = configv1.TLSProfiles[profile.Type]
		if !ok {
			return "", "", fmt.Errorf("unknown TLS profile type: %s", profile.Type)
		}
	}

	// render it as the pair of httpd directives ssl.conf templates in
	sslProtocol, ok := tlsVersionToSSLProtocol[spec.MinTLSVersion]
	if !ok {
		return "", "", fmt.Errorf("unsupported minimum TLS version: %s", spec.MinTLSVersion)
	}

	return strings.Join(spec.Ciphers, ":"), sslProtocol, nil
}
