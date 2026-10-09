# The agentos image

A Linux distribution built for agents: [Fedora bootc](https://docs.fedoraproject.org/en-US/bootc/) with the agentos runtime built in. The whole OS is one container image ([Containerfile](Containerfile)). It updates atomically (`bootc upgrade`) and rolls back the same way (`bootc rollback`), so the OS itself gets the guarantee agentos gives files: nothing half-applied.

What's in it on top of Fedora bootc 42:

- `/usr/bin/agent`, the same binary CI tests
- git, curl, python3 and util-linux, which agents and agentos reach for
- `agentd` as a systemd user service ([the same unit the packages ship](../packaging/agentd.service)): `systemctl --user enable --now agentd`
- cloud-init, so a cloud's user data (users, SSH keys) is applied at first boot
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

Boot `output/qcow2/disk.qcow2` in QEMU, UTM or a cloud. Or let CI do it: Actions → disk → **Run workflow** builds a disk and uploads it as an artifact. Pick the type:

| type | output | for |
|---|---|---|
| `qcow2` (default) | `disk.qcow2` | QEMU, KVM, OpenStack. CI also boots it, logs in over SSH and runs the whole end-to-end suite inside it |
| `raw` | `disk.raw` | writing to a drive or a cloud's raw import |
| `ami` | `disk.raw` | AWS: import it as a snapshot and register an AMI, or run bootc-image-builder yourself with its `--aws-*` options to upload directly |
| `vmdk` | `disk.vmdk` | VMware |
| `anaconda-iso` | `install.iso` | installing onto hardware |

Only the qcow2 is booted in CI; the others are built, not tried. The disk has a user `agent` with your key if the repository secret `AGENTOS_SSH_KEY` is set, and a `ci` user for the boot test, whose private key is thrown away. On a cloud, cloud-init adds the users and keys you give it as user data.

## Move an existing machine onto it

On any bootc system (Fedora bootc, or Fedora Atomic such as Silverblue), once the image is in a registry you control:

```bash
sudo bootc switch ghcr.io/<you>/agentos:latest
```

Then `sudo bootc upgrade` follows it, and `sudo bootc rollback` goes back. To have a machine update itself, `sudo systemctl enable --now bootc-fetch-apply-updates.timer` (it fetches the image you're tracking and reboots into it).

CI doesn't publish the image anywhere. Pushing it to a registry is your call: `podman build -f image/Containerfile -t ghcr.io/<you>/agentos:latest .` and `podman push ghcr.io/<you>/agentos:latest` do it by hand.
