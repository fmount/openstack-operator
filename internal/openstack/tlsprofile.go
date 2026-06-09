package openstack

import (
	"context"
	"fmt"
	"strings"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openstack-k8s-operators/lib-common/modules/common/condition"
	"github.com/openstack-k8s-operators/lib-common/modules/common/helper"
	"github.com/openstack-k8s-operators/lib-common/modules/common/secret"
	"github.com/openstack-k8s-operators/lib-common/modules/common/util"
	corev1 "github.com/openstack-k8s-operators/openstack-operator/api/core/v1beta1"
	k8s_errors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
)

const (
	tlsProfileSecretName = "openstack-ssl-profile"
)

var tlsVersionToSSLProtocol = map[configv1.TLSProtocolVersion]string{
	configv1.VersionTLS10: "all -SSLv2 -SSLv3",
	configv1.VersionTLS11: "all -SSLv2 -SSLv3 -TLSv1",
	configv1.VersionTLS12: "all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1",
	configv1.VersionTLS13: "all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1 -TLSv1.2",
}

// ReconcileTLSProfile reads the OpenShift APIServer TLS security profile and
// creates a Secret with the resolved SSLCipherSuite and SSLProtocol values
// for consumption by lib-common's ssl.conf template.
func ReconcileTLSProfile(ctx context.Context, instance *corev1.OpenStackControlPlane, helper *helper.Helper) (ctrl.Result, error) {
	Log := GetLogger(ctx)

	apiServer := &configv1.APIServer{}
	if err := helper.GetClient().Get(ctx, types.NamespacedName{Name: "cluster"}, apiServer); err != nil {
		if k8s_errors.IsNotFound(err) || meta.IsNoMatchError(err) {
			Log.Info("APIServer CR not found, skipping TLS profile resolution (defaults will apply)")
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

	tmpl := []util.Template{
		{
			Name:         tlsProfileSecretName,
			Namespace:    instance.Namespace,
			Type:         util.TemplateTypeNone,
			InstanceType: instance.Kind,
			CustomData: map[string]string{
				"SSLCipherSuite": cipherSuite,
				"SSLProtocol":    sslProtocol,
			},
			SkipSetOwner: true,
		},
	}

	if err := secret.EnsureSecrets(ctx, helper, instance, tmpl, nil); err != nil {
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
	if profile == nil {
		return resolveProfileSpec(configv1.TLSProfiles[configv1.TLSProfileIntermediateType])
	}

	if profile.Type == configv1.TLSProfileCustomType {
		if profile.Custom == nil {
			return "", "", fmt.Errorf("custom TLS profile type specified but no custom profile provided")
		}
		return resolveProfileSpec(&profile.Custom.TLSProfileSpec)
	}

	spec, ok := configv1.TLSProfiles[profile.Type]
	if !ok {
		return "", "", fmt.Errorf("unknown TLS profile type: %s", profile.Type)
	}
	return resolveProfileSpec(spec)
}

func resolveProfileSpec(spec *configv1.TLSProfileSpec) (string, string, error) {
	cipherSuite := strings.Join(spec.Ciphers, ":")

	sslProtocol, ok := tlsVersionToSSLProtocol[spec.MinTLSVersion]
	if !ok {
		return "", "", fmt.Errorf("unsupported minimum TLS version: %s", spec.MinTLSVersion)
	}

	return cipherSuite, sslProtocol, nil
}
