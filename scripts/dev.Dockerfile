# The dev container: Rust, plus the programs some of the end-to-end sections
# use (a section skips itself when its program isn't there):
#   Xvfb and xdotool   a task's screen (--display), watched and driven from the console
#   dbus and busctl    D-Bus services as MCP servers ([mcp.NAME] dbus = ...)
FROM rust:1.94-bookworm
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends xvfb x11-utils xdotool xauth dbus dbus-daemon dbus-bin systemd \
 && rm -rf /var/lib/apt/lists/*
