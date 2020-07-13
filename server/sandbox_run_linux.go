// +build linux

package server

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	cnitypes "github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/current"
	"github.com/containers/libpod/pkg/annotations"
	selinux "github.com/containers/libpod/pkg/selinux"
	"github.com/containers/storage"
	"github.com/cri-o/cri-o/internal/config/node"
	"github.com/cri-o/cri-o/internal/lib"
	libsandbox "github.com/cri-o/cri-o/internal/lib/sandbox"
	"github.com/cri-o/cri-o/internal/log"
	oci "github.com/cri-o/cri-o/internal/oci"
	criostore "github.com/cri-o/cri-o/internal/storage"
	libconfig "github.com/cri-o/cri-o/pkg/config"
	"github.com/cri-o/cri-o/pkg/sandbox"
	"github.com/cri-o/cri-o/utils"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	spec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/opencontainers/runtime-tools/generate"
	"github.com/opencontainers/selinux/go-selinux/label"
	"github.com/pkg/errors"
	"golang.org/x/net/context"
	"golang.org/x/sys/unix"
	pb "k8s.io/cri-api/pkg/apis/runtime/v1alpha2"
	"k8s.io/kubernetes/pkg/kubelet/leaky"
	"k8s.io/kubernetes/pkg/kubelet/types"
)

// sets the name of the sandbox pod and container
func (s *Server) setNames(sbox sandbox.Sandbox, ctx context.Context) (err error) {
	if err = sbox.SetNameAndID(); err != nil {
		return errors.Wrap(err, "setting pod sandbox name and id")
	}

	if _, err = s.ReservePodName(sbox.ID(), sbox.Name()); err != nil {
		return errors.Wrap(err, "reserving pod sandbox name")
	}

	defer func() {
		if err != nil {
			log.Infof(ctx, "runSandbox: releasing pod sandbox name: %s", sbox.Name())
			s.ReleasePodName(sbox.Name())
		}
	}()

	containerName, err := s.ReserveSandboxContainerIDAndName(sbox.Config())
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			log.Infof(ctx, "runSandbox: releasing container name: %s", containerName)
			s.ReleaseContainerName(containerName)
		}
	}()
	return nil
}

// generates spec
func (s *Server) generateSpec() (g generate.Generator, err error) {
	g, err = generate.New("linux")
	if err != nil {
		return g, err
	}
	g.HostSpecific = true
	g.ClearProcessRlimits()

	for _, u := range s.config.Ulimits() {
		g.AddProcessRlimits(u.Name, u.Hard, u.Soft)
	}
	return g, nil
}

// set sandbox defaults
func (s *Server) setSandboxDefaults(g generate.Generator, podContainer criostore.ContainerInfo) (err error) {
	g.SetRootReadonly(true)

	pauseCommand, err := PauseCommand(s.Config(), podContainer.Config)
	if err != nil {
		return err
	}
	g.SetProcessArgs(pauseCommand)
	return nil
}

// sets DNS options
func (s *Server) setDNSOptions(sbox sandbox.Sandbox, podContainer criostore.ContainerInfo, pathsToChown []string, g generate.Generator, mountLabel string, resolvPath string) (err error) {
	if sbox.Config().GetDnsConfig() != nil {
		dnsServers := sbox.Config().GetDnsConfig().Servers
		dnsSearches := sbox.Config().GetDnsConfig().Searches
		dnsOptions := sbox.Config().GetDnsConfig().Options
		resolvPath = fmt.Sprintf("%s/resolv.conf", podContainer.RunDir)
		err = parseDNSOptions(dnsServers, dnsSearches, dnsOptions, resolvPath)
		if err != nil {
			err1 := removeFile(resolvPath)
			if err1 != nil {
				err = err1
				return fmt.Errorf("%v; failed to remove %s: %v", err, resolvPath, err1)
			}
			return err
		}
		if err := label.Relabel(resolvPath, mountLabel, false); err != nil && errors.Cause(err) != unix.ENOTSUP {
			return err
		}
		mnt := spec.Mount{
			Type:        "bind",
			Source:      resolvPath,
			Destination: "/etc/resolv.conf",
			Options:     []string{"ro", "bind", "nodev", "nosuid", "noexec"},
		}
		pathsToChown = append(pathsToChown, resolvPath)
		g.AddMount(mnt)
	}
	return nil
}

// sets log directory
func (s *Server) setLogDir(logDir string, sbox sandbox.Sandbox) (err error) {
	// set log directory
	if logDir == "" {
		logDir = filepath.Join(s.config.LogDir, sbox.ID())
	}
	if err := os.MkdirAll(logDir, 0700); err != nil {
		return err
	}

	// This should always be absolute from k8s.
	if !filepath.IsAbs(logDir) {
		return fmt.Errorf("requested logDir for sbox id %s is a relative path: %s", sbox.ID(), logDir)
	}
	return nil
}

// creates shm mount
func (s *Server) createShmMount(sbox sandbox.Sandbox, hostIPC bool, shmPath string, podContainer criostore.ContainerInfo, pathsToChown []string, mountLabel string, ctx context.Context) (mnt spec.Mount, err error) {
	if hostIPC {
		shmPath = libsandbox.DevShmPath
	} else {
		shmPath, err = setupShm(podContainer.RunDir, mountLabel)
		if err != nil {
			return spec.Mount{}, err
		}
		pathsToChown = append(pathsToChown, shmPath)
		defer func() {
			if err != nil {
				log.Infof(ctx, "runSandbox: unmounting shmPath for sandbox %s", sbox.ID())
				if err2 := unix.Unmount(shmPath, unix.MNT_DETACH); err2 != nil {
					log.Warnf(ctx, "failed to unmount shm for pod: %v", err2)
				}
			}
		}()
	}

	mnt = spec.Mount{
		Type:        "bind",
		Source:      shmPath,
		Destination: libsandbox.DevShmPath,
		Options:     []string{"rw", "bind"},
	}
	return mnt, nil
}

// adds spec annotations
func (s *Server) addAnnotations(g generate.Generator, metadataJSON []byte, labelsJSON []byte, kubeAnnotationsJSON []byte, logPath string, sboxName string, namespace string, sboxID string, pauseImage string, shmPath string, privileged bool, runtimeHandler string, resolvPath string, hostname string, nsOptsJSON []byte, kubeName string, portMappingsJSON []byte, cgroupPath string, cgroupParent string, kubeAnnotations map[string]string, labels map[string]string, created time.Time, mountPoint string, podContainer criostore.ContainerInfo) {

	g.AddAnnotation(annotations.Metadata, string(metadataJSON))
	g.AddAnnotation(annotations.Labels, string(labelsJSON))
	g.AddAnnotation(annotations.Annotations, string(kubeAnnotationsJSON))
	g.AddAnnotation(annotations.LogPath, logPath)
	g.AddAnnotation(annotations.Name, sboxName)
	g.AddAnnotation(annotations.Namespace, namespace)
	g.AddAnnotation(annotations.ContainerType, annotations.ContainerTypeSandbox)
	g.AddAnnotation(annotations.SandboxID, sboxID)
	g.AddAnnotation(annotations.Image, pauseImage)
	g.AddAnnotation(annotations.ContainerName, containerName)
	g.AddAnnotation(annotations.ContainerID, sboxID)
	g.AddAnnotation(annotations.ShmPath, shmPath)
	g.AddAnnotation(annotations.PrivilegedRuntime, fmt.Sprintf("%v", privileged))
	g.AddAnnotation(annotations.RuntimeHandler, runtimeHandler)
	g.AddAnnotation(annotations.ResolvPath, resolvPath)
	g.AddAnnotation(annotations.HostName, hostname)
	g.AddAnnotation(annotations.NamespaceOptions, string(nsOptsJSON))
	g.AddAnnotation(annotations.KubeName, kubeName)
	g.AddAnnotation(annotations.HostNetwork, fmt.Sprintf("%v", hostNetwork))
	g.AddAnnotation(annotations.ContainerManager, lib.ContainerManagerCRIO)
	g.AddAnnotation(annotations.Created, created.Format(time.RFC3339Nano))
	g.AddAnnotation(annotations.PortMappings, string(portMappingsJSON))
	g.AddAnnotation(annotations.CgroupParent, cgroupParent)
	g.AddAnnotation(annotations.MountPoint, mountPoint)

	if podContainer.Config.Config.StopSignal != "" {
		// this key is defined in image-spec conversion document at https://github.com/opencontainers/image-spec/pull/492/files#diff-8aafbe2c3690162540381b8cdb157112R57
		g.AddAnnotation("org.opencontainers.image.stopSignal", podContainer.Config.Config.StopSignal)
	}

	if s.config.CgroupManager().IsSystemd() && node.SystemdHasCollectMode() {
		g.AddAnnotation("org.systemd.property.CollectMode", "'inactive-or-failed'")
	}

	if cgroupPath != "" {
		g.SetLinuxCgroupsPath(cgroupPath)
	}

	for k, v := range kubeAnnotations {
		g.AddAnnotation(k, v)
	}
	for k, v := range labels {
		g.AddAnnotation(k, v)
	}

}

// sets the ID mappings for the spec
func (s *Server) setIDMappings(g generate.Generator) (err error) {

	if s.defaultIDMappings != nil && !s.defaultIDMappings.Empty() {
		if err := g.AddOrReplaceLinuxNamespace(string(spec.UserNamespace), ""); err != nil {
			return errors.Wrap(err, "add or replace linux namespace")
		}
		for _, uidmap := range s.defaultIDMappings.UIDs() {
			g.AddLinuxUIDMapping(uint32(uidmap.HostID), uint32(uidmap.ContainerID), uint32(uidmap.Size))
		}
		for _, gidmap := range s.defaultIDMappings.GIDs() {
			g.AddLinuxGIDMapping(uint32(gidmap.HostID), uint32(gidmap.ContainerID), uint32(gidmap.Size))
		}
	}
	return nil
}

// adds the sandbox to the server
func (s *Server) addSandboxToServer(sb *libsandbox.Sandbox, sbox sandbox.Sandbox, ctx context.Context) (err error) {
	if err := s.addSandbox(sb); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			log.Infof(ctx, "runSandbox: removing pod sandbox %s", sbox.ID())
			if err := s.removeSandbox(sbox.ID()); err != nil {
				log.Warnf(ctx, "could not remove pod sandbox: %v", err)
			}
		}
	}()

	if err := s.PodIDIndex().Add(sbox.ID()); err != nil {
		return err
	}

	defer func() {
		if err != nil {
			log.Infof(ctx, "runSandbox: deleting pod ID %s from idIndex", sbox.ID())
			if err := s.PodIDIndex().Delete(sbox.ID()); err != nil {
				log.Warnf(ctx, "couldn't delete pod id %s from idIndex", sbox.ID())
			}
		}
	}()

	return nil
}

// check for duplicate name
func (s *Server) duplicateNameCheck(sbox sandbox.Sandbox, ctx context.Context) (err error) {

	if errors.Cause(err) == storage.ErrDuplicateName {
		return fmt.Errorf("pod sandbox with name %q already exists", sbox.Name())
	}
	if err != nil {
		return fmt.Errorf("error creating pod sandbox with name %q: %v", sbox.Name(), err)
	}
	defer func() {
		if err != nil {
			log.Infof(ctx, "runSandbox: removing pod sandbox from storage: %s", sbox.ID())
			if err2 := s.StorageRuntimeServer().RemovePodSandbox(sbox.ID()); err2 != nil {
				log.Warnf(ctx, "couldn't cleanup pod sandbox %q: %v", sbox.ID(), err2)
			}
		}
	}()
	return nil
}

// set up namespaces
func (s *Server) namespaceSetup(ctx context.Context, hostIPC bool, hostPID bool, hostNetwork bool, sb *libsandbox.Sandbox, sbox sandbox.Sandbox, g generate.Generator) (err error) {
	// set up namespaces
	cleanupFuncs, err := s.configureGeneratorForSandboxNamespaces(hostNetwork, hostIPC, hostPID, sb, g)
	// We want to cleanup after ourselves if we are managing any namespaces and fail in this function.
	defer func() {
		if err != nil {
			log.Infof(ctx, "runSandbox: cleaning up namespaces after failing to run sandbox %s", sbox.ID())
			for idx := range cleanupFuncs {
				if err2 := cleanupFuncs[idx](); err2 != nil {
					log.Debugf(ctx, err2.Error())
				}
			}
		}
	}()
	if err != nil {
		return err
	}
	return nil
}

func (s *Server) getMountPoint(sbox sandbox.Sandbox, sb *libsandbox.Sandbox, ctx context.Context) (mountPoint string, err error) {
	mountPoint, err = s.StorageRuntimeServer().StartContainer(sbox.ID())
	if err != nil {
		return "", fmt.Errorf("failed to mount container %s in pod sandbox %s(%s): %v", containerName, sb.Name(), sbox.ID(), err)
	}
	defer func() {
		if err != nil {
			log.Infof(ctx, "runSandbox: stopping storage container for sandbox %s", sbox.ID())
			if err2 := s.StorageRuntimeServer().StopContainer(sbox.ID()); err2 != nil {
				log.Warnf(ctx, "couldn't stop storage container: %v: %v", sbox.ID(), err2)
			}
		}
	}()
	return mountPoint, nil
}

func (s *Server) runPodSandbox(ctx context.Context, req *pb.RunPodSandboxRequest) (resp *pb.RunPodSandboxResponse, err error) {

	s.updateLock.RLock()
	defer s.updateLock.RUnlock()

	sbox := sandbox.New(ctx)
	if err := sbox.SetConfig(req.GetConfig()); err != nil {
		return nil, errors.Wrap(err, "setting sandbox config")
	}

	// sandbox constants
	created := time.Now()
	kubeName := sbox.Config().GetMetadata().GetName()
	namespace := sbox.Config().GetMetadata().GetNamespace()
	attempt := sbox.Config().GetMetadata().GetAttempt()
	securityContext := sbox.Config().GetLinux().GetSecurityContext()
	selinuxConfig := securityContext.GetSelinuxOptions()
	privileged := s.privilegedSandbox(req)
	metadata := sbox.Config().GetMetadata()
	labels := sbox.Config().GetLabels()
	kubeAnnotations := sbox.Config().GetAnnotations()
	logDir := sbox.Config().GetLogDirectory()
	logPath := filepath.Join(logDir, sbox.ID()+".log")
	capabilities := &pb.Capability{}
	hostIPC := securityContext.GetNamespaceOptions().GetIpc() == pb.NamespaceMode_NODE
	hostPID := securityContext.GetNamespaceOptions().GetPid() == pb.NamespaceMode_NODE
	hostNetwork := securityContext.GetNamespaceOptions().GetNetwork() == pb.NamespaceMode_NODE
	portMappings := convertPortMappings(sbox.Config().GetPortMappings())
	saveOptions := generate.ExportOptions{}

	pathsToChown := []string{}

	var labelOptions []string
	var resolvPath string
	var shmPath string

	// marshal metadata json
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return nil, err
	}

	// marshal labels json
	labelsJSON, err := json.Marshal(labels)
	if err != nil {
		return nil, err
	}

	// marshal annotations json
	kubeAnnotationsJSON, err := json.Marshal(kubeAnnotations)
	if err != nil {
		return nil, err
	}

	// marshals json for namespace options
	nsOptsJSON, err := json.Marshal(securityContext.GetNamespaceOptions())
	if err != nil {
		return nil, err
	}

	// marshals json for portmappings
	portMappingsJSON, err := json.Marshal(portMappings)
	if err != nil {
		return nil, err
	}

	log.Infof(ctx, "Running pod sandbox: %s%s", translateLabelsToDescription(sbox.Config().GetLabels()), leaky.PodInfraContainerName)

	//sets the names of the sandbox and container
	err = s.setNames(sbox, ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to set name of sandbox")
	}

	podContainer, err := s.StorageRuntimeServer().CreatePodSandbox(s.config.SystemContext,
		sbox.Name(), sbox.ID(),
		s.config.PauseImage,
		s.config.PauseImageAuthFile,
		"",
		containerName,
		kubeName,
		sbox.Config().GetMetadata().GetUid(),
		namespace,
		attempt,
		s.defaultIDMappings,
		labelOptions,
		privileged,
	)

	mountLabel := podContainer.MountLabel
	processLabel := podContainer.ProcessLabel

	// checks for duplicate names
	err = s.duplicateNameCheck(sbox, ctx)
	if err != nil {
		return nil, err
	}

	// creates a spec Generator with the default spec.
	g, err := s.generateSpec()
	if err != nil {
		return nil, err
	}

	// setup defaults for the pod sandbox
	err = s.setSandboxDefaults(g, podContainer)
	if err != nil {
		return nil, err
	}

	// set DNS options
	s.setDNSOptions(sbox, podContainer, pathsToChown, g, mountLabel, resolvPath)

	// validate labels
	if err := validateLabels(labels); err != nil {
		return nil, err
	}

	// if selinux is set, set label options with the selinux config
	if selinuxConfig != nil {
		labelOptions = getLabelOptions(selinuxConfig)
	}

	// Add special container name label for the infra container
	if labels != nil {
		labels[types.KubernetesContainerNameLabel] = leaky.PodInfraContainerName
	}

	// set log directory
	err = s.setLogDir(logDir, sbox)
	if err != nil {
		return nil, err
	}

	// Add capabilities from crio.conf if default_capabilities is defined
	if s.config.DefaultCapabilities != nil {
		g.ClearProcessCapabilities()
		capabilities.AddCapabilities = append(capabilities.AddCapabilities, s.config.DefaultCapabilities...)
	}
	if err := setupCapabilities(&g, capabilities); err != nil {
		return nil, err
	}

	// Don't use SELinux separation with Host Pid or IPC Namespace or privileged.
	if hostPID || hostIPC {
		processLabel, mountLabel = "", ""
	}
	g.SetProcessSelinuxLabel(processLabel)
	g.SetLinuxMountLabel(mountLabel)

	// Remove the default /dev/shm mount to ensure we overwrite it
	g.RemoveMount(libsandbox.DevShmPath)

	// create shm mount for the pod containers.
	mnt, err := s.createShmMount(sbox, hostIPC, shmPath, podContainer, pathsToChown, mountLabel, ctx)
	if err != nil {
		return nil, err
	}

	// bind mount the pod shm
	g.AddMount(mnt)

	// set the sandbox mount label
	err = s.setPodSandboxMountLabel(sbox.ID(), mountLabel)
	if err != nil {
		return nil, err
	}

	// set the container id index
	if err := s.CtrIDIndex().Add(sbox.ID()); err != nil {
		return nil, err
	}

	defer func() {
		if err != nil {
			log.Infof(ctx, "runSandbox: deleting container ID from idIndex for sandbox %s", sbox.ID())
			if err2 := s.CtrIDIndex().Delete(sbox.ID()); err2 != nil {
				log.Warnf(ctx, "couldn't delete ctr id %s from idIndex", sbox.ID())
			}
		}
	}()

	// Handle https://issues.k8s.io/44043
	if err := utils.EnsureValidLogPath(logPath); err != nil {
		return nil, err
	}

	//set hostname
	hostname, err := getHostname(sbox.ID(), sbox.Config().Hostname, hostNetwork)
	if err != nil {
		return nil, err
	}
	g.SetHostname(hostname)

	// validate the runtime handler
	runtimeHandler, err := s.runtimeHandler(req)
	if err != nil {
		return nil, err
	}

	// set cgroup parent
	cgroupParent, cgroupPath, err := s.config.CgroupManager().SandboxCgroupPath(sbox.Config().GetLinux().GetCgroupParent(), sbox.ID())
	if err != nil {
		return nil, err
	}

	// create a new sandbox
	sb, err := libsandbox.New(sbox.ID(), namespace, sbox.Name(), kubeName, logDir, labels, kubeAnnotations, processLabel, mountLabel, metadata, shmPath, cgroupParent, privileged, runtimeHandler, resolvPath, hostname, portMappings, hostNetwork)
	if err != nil {
		return nil, err
	}

	// set the mount point
	mountPoint, err := s.getMountPoint(sbox, sb, ctx)
	if err != nil {
		return nil, err
	}

	// add spec annotations
	s.addAnnotations(g, metadataJSON, labelsJSON, kubeAnnotationsJSON, logPath, sbox.Name(), namespace, sbox.ID(), s.config.PauseImage, shmPath, privileged, runtimeHandler, resolvPath, hostname, nsOptsJSON, kubeName, portMappingsJSON, cgroupParent, cgroupPath, kubeAnnotations, labels, created, mountPoint, podContainer)

	// sets the id mappings for the spec
	err = s.setIDMappings(g)
	if err != nil {
		return nil, err
	}

	// add sandbox to the server
	s.addSandboxToServer(sb, sbox, ctx)

	// Add default sysctls given in crio.conf
	s.configureGeneratorForSysctls(ctx, g, hostNetwork, hostIPC)
	// extract linux sysctls from annotations and pass down to oci runtime
	// Will override any duplicate default systcl from crio.conf
	for key, value := range sbox.Config().GetLinux().GetSysctls() {
		g.AddLinuxSysctl(key, value)
	}

	// Set OOM score adjust of the infra container to be very low
	// so it doesn't get killed.
	g.SetProcessOOMScoreAdj(PodInfraOOMAdj)
	g.SetLinuxResourcesCPUShares(PodInfraCPUshares)

	// sets up namespace and handles tearing down if there's an error
	s.namespaceSetup(ctx, hostIPC, hostPID, hostNetwork, sb, sbox, g)

	if s.Config().Seccomp().IsDisabled() {
		g.Config.Linux.Seccomp = nil
	}

	hostnamePath := fmt.Sprintf("%s/hostname", podContainer.RunDir)
	if err := ioutil.WriteFile(hostnamePath, []byte(hostname+"\n"), 0644); err != nil {
		return nil, err
	}
	if err := label.Relabel(hostnamePath, mountLabel, false); err != nil && errors.Cause(err) != unix.ENOTSUP {
		return nil, err
	}
	mnt = spec.Mount{
		Type:        "bind",
		Source:      hostnamePath,
		Destination: "/etc/hostname",
		Options:     []string{"ro", "bind", "nodev", "nosuid", "noexec"},
	}
	pathsToChown = append(pathsToChown, hostnamePath)
	g.AddMount(mnt)
	g.AddAnnotation(annotations.HostnamePath, hostnamePath)
	sb.AddHostnamePath(hostnamePath)

	container, err := oci.NewContainer(sbox.ID(), containerName, podContainer.RunDir, logPath, labels, g.Config.Annotations, kubeAnnotations, s.config.PauseImage, "", "", nil, sbox.ID(), false, false, false, runtimeHandler, podContainer.Dir, created, podContainer.Config.Config.StopSignal)
	if err != nil {
		return nil, err
	}

	runtimeType, err := s.Runtime().ContainerRuntimeType(container)
	if err != nil {
		return nil, err
	}
	// If using kata runtime, the process label should be set to container_kvm_t
	// Keep in mind that kata does *not* apply any process label to containers within the VM
	// Note: the requirement here is that the name used for the runtime class has "kata" in it
	// or the runtime_type is set to "vm"
	if runtimeType == libconfig.RuntimeTypeVM || strings.Contains(strings.ToLower(runtimeHandler), "kata") {
		processLabel, err = selinux.SELinuxKVMLabel(processLabel)
		if err != nil {
			return nil, err
		}
		g.SetProcessSelinuxLabel(processLabel)
	}

	container.SetMountPoint(mountPoint)

	container.SetIDMappings(s.defaultIDMappings)

	if s.defaultIDMappings != nil && !s.defaultIDMappings.Empty() {
		if securityContext.GetNamespaceOptions().GetIpc() == pb.NamespaceMode_NODE {
			g.RemoveMount("/dev/mqueue")
			mqueue := spec.Mount{
				Type:        "bind",
				Source:      "/dev/mqueue",
				Destination: "/dev/mqueue",
				Options:     []string{"rw", "rbind", "nodev", "nosuid", "noexec"},
			}
			g.AddMount(mqueue)
		}
		if hostNetwork {
			g.RemoveMount("/sys")
			g.RemoveMount("/sys/cgroup")
			sysMnt := spec.Mount{
				Destination: "/sys",
				Type:        "bind",
				Source:      "/sys",
				Options:     []string{"nosuid", "noexec", "nodev", "ro", "rbind"},
			}
			g.AddMount(sysMnt)
		}
		if securityContext.GetNamespaceOptions().GetPid() == pb.NamespaceMode_NODE {
			g.RemoveMount("/proc")
			proc := spec.Mount{
				Type:        "bind",
				Source:      "/proc",
				Destination: "/proc",
				Options:     []string{"rw", "rbind", "nodev", "nosuid", "noexec"},
			}
			g.AddMount(proc)
		}
	}
	g.SetRootPath(mountPoint)

	if os.Getenv("_CRIO_ROOTLESS") != "" {
		makeOCIConfigurationRootless(&g)
	}

	container.SetSpec(g.Config)

	if err := sb.SetInfraContainer(container); err != nil {
		return nil, err
	}

	var ips []string
	var result cnitypes.Result

	if s.config.ManageNSLifecycle {
		ips, result, err = s.networkStart(ctx, sb)
		if err != nil {
			return nil, err
		}
		if result != nil {
			resultCurrent, err := current.NewResultFromResult(result)
			if err != nil {
				return nil, err
			}
			cniResultJSON, err := json.Marshal(resultCurrent)
			if err != nil {
				return nil, err
			}
			g.AddAnnotation(annotations.CNIResult, string(cniResultJSON))
		}
		defer func() {
			if err != nil {
				log.Infof(ctx, "runSandbox: in manageNSLifecycle, stopping network for sandbox %s", sb.ID())
				if err2 := s.networkStop(ctx, sb); err2 != nil {
					log.Errorf(ctx, "error stopping network on cleanup: %v", err2)
				}
			}
		}()
	}

	for idx, ip := range ips {
		g.AddAnnotation(fmt.Sprintf("%s.%d", annotations.IP, idx), ip)
	}
	sb.AddIPs(ips)
	sb.SetNamespaceOptions(securityContext.GetNamespaceOptions())

	spp := securityContext.GetSeccompProfilePath()
	g.AddAnnotation(annotations.SeccompProfilePath, spp)
	sb.SetSeccompProfilePath(spp)
	if !privileged {
		if err := s.setupSeccomp(ctx, &g, spp); err != nil {
			return nil, err
		}
	}

	err = g.SaveToFile(filepath.Join(podContainer.Dir, "config.json"), saveOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to save template configuration for pod sandbox %s(%s): %v", sb.Name(), sbox.ID(), err)
	}
	if err = g.SaveToFile(filepath.Join(podContainer.RunDir, "config.json"), saveOptions); err != nil {
		return nil, fmt.Errorf("failed to write runtime configuration for pod sandbox %s(%s): %v", sb.Name(), sbox.ID(), err)
	}

	s.addInfraContainer(container)
	defer func() {
		if err != nil {
			log.Infof(ctx, "runSandbox: removing infra container %s", container.ID())
			s.removeInfraContainer(container)
		}
	}()

	if s.defaultIDMappings != nil && !s.defaultIDMappings.Empty() {
		rootPair := s.defaultIDMappings.RootPair()
		for _, path := range pathsToChown {
			if err := os.Chown(path, rootPair.UID, rootPair.GID); err != nil {
				return nil, errors.Wrapf(err, "cannot chown %s to %d:%d", path, rootPair.UID, rootPair.GID)
			}
		}
	}

	if err := s.createContainerPlatform(container, sb.CgroupParent()); err != nil {
		return nil, err
	}

	if err := s.Runtime().StartContainer(container); err != nil {
		return nil, err
	}

	defer func() {
		if err != nil {
			// Clean-up steps from RemovePodSanbox
			log.Infof(ctx, "runSandbox: stopping container %s", container.ID())
			if err2 := s.Runtime().StopContainer(ctx, container, int64(10)); err2 != nil {
				log.Warnf(ctx, "failed to stop container %s: %v", container.Name(), err2)
			}
			if err2 := s.Runtime().WaitContainerStateStopped(ctx, container); err2 != nil {
				log.Warnf(ctx, "failed to get container 'stopped' status %s in pod sandbox %s: %v", container.Name(), sb.ID(), err2)
			}
			log.Infof(ctx, "runSandbox: deleting container %s", container.ID())
			if err2 := s.Runtime().DeleteContainer(container); err2 != nil {
				log.Warnf(ctx, "failed to delete container %s in pod sandbox %s: %v", container.Name(), sb.ID(), err2)
			}
			log.Infof(ctx, "runSandbox: writing container %s state to disk", container.ID())
			if err2 := s.ContainerStateToDisk(container); err2 != nil {
				log.Warnf(ctx, "failed to write container state %s in pod sandbox %s: %v", container.Name(), sb.ID(), err2)
			}
		}
	}()

	if err := s.ContainerStateToDisk(container); err != nil {
		log.Warnf(ctx, "unable to write containers %s state to disk: %v", container.ID(), err)
	}

	if !s.config.ManageNSLifecycle {
		ips, _, err = s.networkStart(ctx, sb)
		if err != nil {
			return nil, err
		}
		defer func() {
			if err != nil {
				log.Infof(ctx, "runSandbox: in not manageNSLifecycle, stopping network for sandbox %s", sb.ID())
				if err2 := s.networkStop(ctx, sb); err2 != nil {
					log.Errorf(ctx, "error stopping network on cleanup: %v", err2)
				}
			}
		}()
	}
	sb.AddIPs(ips)

	sb.SetCreated()

	if ctx.Err() == context.Canceled || ctx.Err() == context.DeadlineExceeded {
		log.Infof(ctx, "runSandbox: context was either canceled or the deadline was exceeded: %v", ctx.Err())
		return nil, ctx.Err()
	}

	log.Infof(ctx, "Ran pod sandbox %s with infra container: %s", container.ID(), container.Description())
	resp = &pb.RunPodSandboxResponse{PodSandboxId: sbox.ID()}
	return resp, nil
}

func setupShm(podSandboxRunDir, mountLabel string) (shmPath string, err error) {
	shmPath = filepath.Join(podSandboxRunDir, "shm")
	if err := os.Mkdir(shmPath, 0700); err != nil {
		return "", err
	}
	shmOptions := "mode=1777,size=" + strconv.Itoa(libsandbox.DefaultShmSize)
	if err = unix.Mount("shm", shmPath, "tmpfs", unix.MS_NOEXEC|unix.MS_NOSUID|unix.MS_NODEV,
		label.FormatMountLabel(shmOptions, mountLabel)); err != nil {
		return "", fmt.Errorf("failed to mount shm tmpfs for pod: %v", err)
	}
	return shmPath, nil
}

// PauseCommand returns the pause command for the provided image configuration.
func PauseCommand(cfg *libconfig.Config, image *v1.Image) ([]string, error) {
	if cfg == nil {
		return nil, fmt.Errorf("provided configuration is nil")
	}

	// This has been explicitly set by the user, since the configuration
	// default is `/pause`
	if cfg.PauseCommand == "" {
		if image == nil ||
			(len(image.Config.Entrypoint) == 0 && len(image.Config.Cmd) == 0) {
			return nil, fmt.Errorf(
				"unable to run pause image %q: %s",
				cfg.PauseImage,
				"neither Cmd nor Entrypoint specified",
			)
		}
		cmd := []string{}
		cmd = append(cmd, image.Config.Entrypoint...)
		cmd = append(cmd, image.Config.Cmd...)
		return cmd, nil
	}
	return []string{cfg.PauseCommand}, nil
}

func (s *Server) configureGeneratorForSysctls(ctx context.Context, g generate.Generator, hostNetwork, hostIPC bool) {
	sysctls, err := s.config.RuntimeConfig.Sysctls()
	if err != nil {
		log.Warnf(ctx, "sysctls invalid: %v", err)
	}

	for _, sysctl := range sysctls {
		if err := sysctl.Validate(hostNetwork, hostIPC); err != nil {
			log.Warnf(ctx, "skipping invalid sysctl %s: %v", sysctl, err)
			continue
		}
		g.AddLinuxSysctl(sysctl.Key(), sysctl.Value())
	}
}

// configureGeneratorForSandboxNamespaces set the linux namespaces for the generator, based on whether the pod is sharing namespaces with the host,
// as well as whether CRI-O should be managing the namespace lifecycle.
// it returns a slice of cleanup funcs, all of which are the respective NamespaceRemove() for the sandbox.
// The caller should defer the cleanup funcs if there is an error, to make sure each namespace we are managing is properly cleaned up.
func (s *Server) configureGeneratorForSandboxNamespaces(hostNetwork, hostIPC, hostPID bool, sb *libsandbox.Sandbox, g generate.Generator) (cleanupFuncs []func() error, err error) {
	managedNamespaces := make([]libsandbox.NSType, 0, 3)
	if hostNetwork {
		err = g.RemoveLinuxNamespace(string(spec.NetworkNamespace))
		if err != nil {
			return
		}
	} else if s.config.ManageNSLifecycle {
		managedNamespaces = append(managedNamespaces, libsandbox.NETNS)
	}

	if hostIPC {
		err = g.RemoveLinuxNamespace(string(spec.IPCNamespace))
		if err != nil {
			return
		}
	} else if s.config.ManageNSLifecycle {
		managedNamespaces = append(managedNamespaces, libsandbox.IPCNS)
	}

	// Since we need a process to hold open the PID namespace, CRI-O can't manage the NS lifecycle
	if hostPID {
		err = g.RemoveLinuxNamespace(string(spec.PIDNamespace))
		if err != nil {
			return
		}
	}

	// There's no option to set hostUTS
	if s.config.ManageNSLifecycle {
		managedNamespaces = append(managedNamespaces, libsandbox.UTSNS)

		// now that we've configured the namespaces we're sharing, tell sandbox to configure them
		managedNamespaces, err := sb.CreateManagedNamespaces(managedNamespaces, &s.config)
		if err != nil {
			return nil, err
		}

		cleanupFuncs = append(cleanupFuncs, sb.RemoveManagedNamespaces)

		if err := configureGeneratorGivenNamespacePaths(managedNamespaces, g); err != nil {
			return cleanupFuncs, err
		}
	}

	return cleanupFuncs, err
}

// configureGeneratorGivenNamespacePaths takes a map of nsType -> nsPath. It configures the generator
// to add or replace the defaults to these paths
func configureGeneratorGivenNamespacePaths(managedNamespaces []*libsandbox.ManagedNamespace, g generate.Generator) error {
	typeToSpec := map[libsandbox.NSType]spec.LinuxNamespaceType{
		libsandbox.IPCNS:  spec.IPCNamespace,
		libsandbox.NETNS:  spec.NetworkNamespace,
		libsandbox.UTSNS:  spec.UTSNamespace,
		libsandbox.USERNS: spec.UserNamespace,
	}

	for _, ns := range managedNamespaces {
		// allow for empty paths, as this namespace just shouldn't be configured
		if ns.Path() == "" {
			continue
		}
		nsForSpec := typeToSpec[ns.Type()]
		if nsForSpec == "" {
			return errors.Errorf("Invalid namespace type %s", nsForSpec)
		}
		err := g.AddOrReplaceLinuxNamespace(string(nsForSpec), ns.Path())
		if err != nil {
			return err
		}
	}
	return nil
}
