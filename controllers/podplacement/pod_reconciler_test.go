package podplacement

import (
	"fmt"

	"k8s.io/apimachinery/pkg/util/sets"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"

	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/openshift/multiarch-tuning-operator/pkg/utils"

	. "github.com/openshift/multiarch-tuning-operator/pkg/testing/builder"
	. "github.com/openshift/multiarch-tuning-operator/pkg/testing/framework"
	"github.com/openshift/multiarch-tuning-operator/pkg/testing/image/fake/registry"
)

var _ = Describe("Controllers/Podplacement/PodReconciler", func() {
	When("Handling Single-container Pods", func() {
		Context("with different image types", func() {
			DescribeTable("handles correctly", func(imageType string, supportedArchitectures ...string) {
				pod := NewPod().
					WithContainersImages(fmt.Sprintf("%s/%s/%s:latest", registryAddress,
						registry.PublicRepo, registry.ComputeNameByMediaType(imageType))).
					WithGenerateName("test-pod-").
					WithNamespace("test-namespace").
					Build()
				err := k8sClient.Create(ctx, &pod)
				Expect(err).NotTo(HaveOccurred(), "failed to create pod", err)
				// Test the removal of the scheduling gate. However, since the pod is mutated and the reconciler
				// removes the scheduling gate concurrently, we cannot ensure that the scheduling gate is added
				// and that the following Eventually works on a pod with the scheduling gate.
				// Waiting for the pod to be mutated is not enough, as the pod could be mutated and the reconciler
				// could have removed the scheduling gate before our check.
				Eventually(func(g Gomega) {
					// Get pod from the API server
					err := k8sClient.Get(ctx, crclient.ObjectKeyFromObject(&pod), &pod)
					g.Expect(err).NotTo(HaveOccurred(), "failed to get pod", err)
					g.Expect(pod.Spec.SchedulingGates).NotTo(ContainElement(corev1.PodSchedulingGate{
						Name: utils.SchedulingGateName,
					}), "scheduling gate not removed")
					g.Expect(pod.Labels).To(HaveKeyWithValue(utils.SchedulingGateLabel, utils.SchedulingGateLabelValueRemoved),
						"scheduling gate annotation not found")
				}).Should(Succeed(), "failed to remove scheduling gate from pod")
				Eventually(func(g Gomega) {
					g.Expect(pod).To(HaveEquivalentNodeAffinity(
						&corev1.NodeAffinity{
							RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
								NodeSelectorTerms: []corev1.NodeSelectorTerm{
									{
										MatchExpressions: []corev1.NodeSelectorRequirement{
											{
												Key:      utils.ArchLabel,
												Operator: corev1.NodeSelectorOpIn,
												Values:   supportedArchitectures,
											},
										},
									},
								},
							},
						}), "unexpected node affinity")
				}).Should(Succeed(), "failed to set node affinity to pod")
			},
				Entry("OCI Index Images", imgspecv1.MediaTypeImageIndex, utils.ArchitectureAmd64, utils.ArchitectureArm64),
				Entry("Docker images", imgspecv1.MediaTypeImageManifest, utils.ArchitecturePpc64le),
			)
		})

		Context("with different pull secrets", func() {
			It("handles images with global pull secrets correctly", func() {
				// TODO: Test logic for handling a Pod with one container and image using global pull secret
			})

			It("handles images with local pull secrets correctly", func() {
				// TODO: Test logic for handling a Pod with one container and image using local pull secret
			})
		})
	})
	When("Reconciling a pod", func() {
		Context("with cache enabled and an image that changes after the first time it is used", func() {
			FIt("does not query the remote registry until the cache expires", func() {
				imageName := registry.ComputeNameByMediaType(imgspecv1.MediaTypeImageIndex, "custom-image-that-will-change-supported-architectures")

				By("Pushing a custom image to the registry")
				supportedArchitectures := sets.New(utils.ArchitectureArm64, utils.ArchitectureAmd64)
				err := registry.PushMockImage(ctx,
					&registry.MockImage{
						Architectures: supportedArchitectures,
						Repository:    registry.PublicRepo,
						Name:          imageName,
						MediaType:     imgspecv1.MediaTypeImageIndex,
						Tag:           "latest",
					})
				By("Creating a pod with the custom image [the cache will be populated with info about that image and its supported architectures]")
				pod := NewPod().
					WithContainersImages(fmt.Sprintf("%s/%s/%s:latest", registryAddress,
						registry.PublicRepo, imageName)).
					WithGenerateName("test-pod-").
					WithNamespace("test-namespace").
					Build()
				err = k8sClient.Create(ctx, &pod)
				Expect(err).NotTo(HaveOccurred(), "failed to create pod", err)
				By("Waiting for the pod to be mutated and the scheduling gate to be removed")
				Eventually(func(g Gomega) {
					// Get pod from the API server
					err := k8sClient.Get(ctx, crclient.ObjectKeyFromObject(&pod), &pod)
					g.Expect(err).NotTo(HaveOccurred(), "failed to get pod", err)
					g.Expect(pod.Spec.SchedulingGates).NotTo(ContainElement(corev1.PodSchedulingGate{
						Name: utils.SchedulingGateName,
					}), "scheduling gate not removed")
					g.Expect(pod.Labels).To(HaveKeyWithValue(utils.SchedulingGateLabel, utils.SchedulingGateLabelValueRemoved),
						"scheduling gate annotation not found")
				}).Should(Succeed(), "failed to remove scheduling gate from pod")
				By("Checking that the pod has the correct node affinity")
				Expect(pod).To(HaveEquivalentNodeAffinity(
					&corev1.NodeAffinity{
						RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
							NodeSelectorTerms: []corev1.NodeSelectorTerm{
								{
									MatchExpressions: []corev1.NodeSelectorRequirement{
										{
											Key:      utils.ArchLabel,
											Operator: corev1.NodeSelectorOpIn,
											Values:   sets.List(supportedArchitectures),
										},
									},
								},
							},
						},
					}), "unexpected node affinity")
				By("Replace the image with a new one having a different set of supported architectures [the cache will not be invalidated]")
				supportedArchitectures = sets.New(utils.ArchitectureArm64, utils.ArchitectureAmd64, utils.ArchitecturePpc64le)
				err = registry.PushMockImage(ctx,
					&registry.MockImage{
						Repository:    registry.PublicRepo,
						Name:          imageName,
						Architectures: supportedArchitectures,
						MediaType:     imgspecv1.MediaTypeImageIndex,
						Tag:           "latest",
					})
				Expect(err).NotTo(HaveOccurred(), "failed push custom image to registry, err")
				By("Creating a new pod with the custom image [the cache will be used to set the node affinity]")
				pod = NewPod().
					WithContainersImages(fmt.Sprintf("%s/%s/%s:latest", registryAddress,
						registry.PublicRepo, imageName)).
					WithGenerateName("test-pod-").
					WithNamespace("test-namespace").
					Build()
				err = k8sClient.Create(ctx, &pod)
				Expect(err).NotTo(HaveOccurred(), "failed to create pod", err)
				By("Waiting for the pod to be mutated and the scheduling gate to be removed")
				Eventually(func(g Gomega) {
					// Get pod from the API server
					err := k8sClient.Get(ctx, crclient.ObjectKeyFromObject(&pod), &pod)
					g.Expect(err).NotTo(HaveOccurred(), "failed to get pod", err)
					g.Expect(pod.Spec.SchedulingGates).NotTo(ContainElement(corev1.PodSchedulingGate{
						Name: utils.SchedulingGateName,
					}), "scheduling gate not removed")
					g.Expect(pod.Labels).To(HaveKeyWithValue(utils.SchedulingGateLabel, utils.SchedulingGateLabelValueRemoved),
						"scheduling gate annotation not found")
				}).Should(Succeed(), "failed to remove scheduling gate from pod")
				By("Checking that the pod has the wrong, cached, node affinity [this proves we are not querying the remote registry]")
				Expect(pod).To(HaveEquivalentNodeAffinity(
					&corev1.NodeAffinity{
						RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
							NodeSelectorTerms: []corev1.NodeSelectorTerm{
								{
									MatchExpressions: []corev1.NodeSelectorRequirement{
										{
											Key:      utils.ArchLabel,
											Operator: corev1.NodeSelectorOpIn,
											Values:   []string{utils.ArchitectureArm64, utils.ArchitectureAmd64},
										},
									},
								},
							},
						},
					}), "unexpected node affinity")
				Expect(err).NotTo(HaveOccurred(), "failed to create pod", err)

			})
		})
	})
	When("Handling Multi-container Pods", func() {
		Context("with different image types and different auth credentials sources", func() {
			It("handles node affinity as the intersection of the compatible architectures of each multi-arch image", func() {
				// TODO: Test logic for handling a Pod with multiple multi-arch image-based containers
			})

			It("handles node affinity of multi-arch images and single-arch image setting the only one possible", func() {
				// TODO: Test logic for handling a Pod with multiple multi-arch image-based containers
			})

		})
	})

	When("Handling Pod with Operator Bundle Images", func() {
		Context("with different image types", func() {
			DescribeTable("handles correctly", func(bundleImageType string, secondImageType string, supportedArchitectures ...string) {
				pod := NewPod().
					WithContainersImages(fmt.Sprintf("%s/%s/%s:latest", registryAddress,
						registry.PublicRepo, registry.ComputeNameByMediaType(bundleImageType, "bundle"))).
					WithContainersImages(fmt.Sprintf("%s/%s/%s:latest", registryAddress,
						registry.PublicRepo, registry.ComputeNameByMediaType(secondImageType, "ppc64le-s390x"))).
					WithGenerateName("test-pod-").
					WithNamespace("test-namespace").Build()
				err := k8sClient.Create(ctx, &pod)
				Expect(err).NotTo(HaveOccurred(), "failed to create pod", err)
				// Test the removal of the scheduling gate. However, since the pod is mutated and the reconciler
				// removes the scheduling gate concurrently, we cannot ensure that the scheduling gate is added
				// and that the following Eventually works on a pod with the scheduling gate.
				// Waiting for the pod to be mutated is not enough, as the pod could be mutated and the reconciler
				// could have removed the scheduling gate before our check.
				Eventually(func(g Gomega) {
					// Get pod from the API server
					err := k8sClient.Get(ctx, crclient.ObjectKeyFromObject(&pod), &pod)
					g.Expect(err).NotTo(HaveOccurred(), "failed to get pod", err)
					g.Expect(pod.Spec.SchedulingGates).NotTo(ContainElement(corev1.PodSchedulingGate{
						Name: utils.SchedulingGateName,
					}), "scheduling gate not removed")
					g.Expect(pod.Labels).To(HaveKeyWithValue(utils.SchedulingGateLabel, utils.SchedulingGateLabelValueRemoved),
						"scheduling gate annotation not found")
				}).Should(Succeed(), "failed to remove scheduling gate from pod")
				Eventually(func(g Gomega) {
					if len(supportedArchitectures) == 0 {
						g.Expect(pod.Spec.Affinity.NodeAffinity).To(BeNil(), "unexpected node affinity")
						return
					}
					g.Expect(pod).To(HaveEquivalentNodeAffinity(
						&corev1.NodeAffinity{
							RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
								NodeSelectorTerms: []corev1.NodeSelectorTerm{
									{
										MatchExpressions: []corev1.NodeSelectorRequirement{
											{
												Key:      utils.ArchLabel,
												Operator: corev1.NodeSelectorOpIn,
												Values:   supportedArchitectures,
											},
										},
									},
								},
							},
						}), "unexpected node affinity")
				}).Should(Succeed(), "failed to set node affinity to pod")
			},
				Entry("OCI Index bundles + OCI index image", imgspecv1.MediaTypeImageIndex, imgspecv1.MediaTypeImageIndex, utils.ArchitecturePpc64le, utils.ArchitectureS390x),
				Entry("Docker manifest bundles + OCI index image", imgspecv1.MediaTypeImageManifest, imgspecv1.MediaTypeImageIndex, utils.ArchitecturePpc64le, utils.ArchitectureS390x),
			)
		})
	})
})
