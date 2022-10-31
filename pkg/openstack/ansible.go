package openstack

import (
	"context"
	"fmt"

	//"github.com/openstack-k8s-operators/lib-common/modules/common/condition"
	"github.com/openstack-k8s-operators/lib-common/modules/common/helper"

	ansibleeev1 "github.com/openstack-k8s-operators/ansibleee-operator/api/v1alpha1"
	corev1beta1 "github.com/openstack-k8s-operators/openstack-operator/apis/core/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// ReconcileGlance -
func ReconcileAnsible(ctx context.Context, instance *corev1beta1.OpenStackControlPlane, helper *helper.Helper) (ctrl.Result, error) {
	ansible := &ansibleeev1.AnsibleEE{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ansibleee",
			Namespace: instance.Namespace,
		},
	}

	helper.GetLogger().Info("Reconciling ansible", "ansible.Namespace", instance.Namespace, "ansible.Name", "ansibleee")
	// Run ansibleee jobs only when the ctlplane is ready
	if instance.IsReady() {
		op, _ := controllerutil.CreateOrPatch(ctx, helper.GetClient(), ansible, func() error {
			instance.Spec.AnsibleTemplate.DeepCopyInto(&ansible.Spec)
			err := controllerutil.SetControllerReference(helper.GetBeforeObject(), ansible, helper.GetScheme())
			if err != nil {
				return err
			}
			return nil
		})

		if op != controllerutil.OperationResultNone {
			helper.GetLogger().Info(fmt.Sprintf("ansible %s - %s", ansible.Name, op))
		}
	}

	return ctrl.Result{}, nil

}
