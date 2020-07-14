package specgen

import (
	"github.com/cri-o/cri-o/internal/log"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/opencontainers/runtime-tools/generate"
	"golang.org/x/net/context"
)

var spec *generate.Generator

func SetSpec(s *generate.Generator) {
	spec = s
}

func GetSpec() *generate.Generator {
	return spec
}

func SetLinuxDevice(ctx context.Context, path string, deviceType string, major int64, minor int64, uid *uint32, gid *uint32) {
	rd := specs.LinuxDevice{
		Path:  path,
		Type:  deviceType,
		Major: major,
		Minor: minor,
		UID:   uid,
		GID:   gid,
	}
	if major == 0 && minor == 0 {
		log.Infof(ctx, "symlink device found, skipping")
		return
	}
	spec.AddDevice(rd)
}

func AddLinuxDeviceCgroup(allow bool, deviceType string, major *int64, minor *int64, access string) {
	spec.Config.Linux.Resources.Devices = append(spec.Config.Linux.Resources.Devices,
		specs.LinuxDeviceCgroup{
			Allow:  allow,
			Type:   deviceType,
			Major:  major,
			Minor:  minor,
			Access: access,
		})
}

func SetLinuxDeviceCgroup(allow bool, access string) {
	spec.Config.Linux.Resources.Devices =
		[]specs.LinuxDeviceCgroup{
			{
				Allow:  allow,
				Access: access,
			},
		}
}
