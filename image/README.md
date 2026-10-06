# The agentos image

A Linux distribution built for agents: [Fedora bootc](https://docs.fedoraproject.org/en-US/bootc/) with the agentos runtime built in. The whole OS is one container image ([Containerfile](Containerfile)). It updates atomically (`bootc upgrade`) and rolls back the same way (`bootc rollback`), so the OS itself gets the guarantee agentos gives files: nothing half-applied.

What's in it on top of Fedora bootc 42:

- `/usr/bin/agent`, the same binary CI tests
- git, curl, python3 and util-linux, which agents and agentos reach for
- `agentd` as a systemd user service: `systemctl --user enable --now agentd`
- a login message that explains the basics

Fedora doesn't restrict unprivileged user namespaces and its kernel has Landlock, so `agent doctor` passes out of the box, with no AppArmor profile to install.

## Build it

```bash
podman build -f image/Containerfile -t localhost/agentos .
```

CI builds it on every push and runs the whole end-to-end suite inside it (job `image`).

## Boot it

Make a disk image with [bootc-image-builder](https://github.com/osbuild/bootc-image-builder). First put your SSH key in [disk.toml](disk.toml), then:

```bash
sudo podman run --rm --privileged --pull=newer \
  --security-opt label=type:unconfined_t \
  -v ./image/disk.toml:/config.toml:ro -v ./output:/output \
  -v /var/lib/containers/storage:/var/lib/containers/storage \
  quay.io/centos-bootc/bootc-image-builder:latest \
  --type qcow2 --rootfs xfs localhost/agentos:latest
```

Boot `output/qcow2/disk.qcow2` in QEMU, UTM or a cloud. `--type raw`, `ami` and `anaconda-iso` work too. Or let CI do it: Actions → ci → **Run workflow** builds a qcow2 artifact. It adds a user `agent` with your key if the repository secret `AGENTOS_SSH_KEY` is set.

## Move an existing machine onto it

On any bootc system (Fedora bootc, or Fedora Atomic such as Silverblue), once the image is in a registry you control:

```bash
sudo bootc switch ghcr.io/<you>/agentos:latest
```

CI doesn't publish the image anywhere. Pushing it to a registry is your call.
