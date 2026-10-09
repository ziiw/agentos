//! A screen of its own for a task: `--display`.
//!
//! For agents that drive a graphical program (a browser, a desktop app), the
//! task gets a private virtual X display. The X server (Xvfb) runs outside
//! the sandbox, started by the supervisor; the sandbox gets its one socket
//! and a cookie, nothing else of the host's display. The server's framebuffer
//! is a file in the task, so you can watch the screen at any moment
//! (`agent screen`) without going through the agent, and the last picture is
//! kept when the task ends.
//!
//! ```text
//! supervisor ── starts ──▶ Xvfb :N  (socket /tmp/.X11-unix/XN, cookie in the task)
//!      │                      │ framebuffer: <task>/fb/Xvfb_screen0 (XWD, live)
//!      ▼                      ▼
//!   sandbox: DISPLAY=:0 ── /tmp/.X11-unix/X0 → /run/agentos/x11.sock (the socket)
//! ```

use anyhow::{Context, Result, bail};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// What a screen is unless you say otherwise.
pub const DEFAULT_SIZE: &str = "1280x800";
/// Where the server's framebuffer lands, under the task's folder.
const FRAMEBUFFER: &str = "fb/Xvfb_screen0";
/// Kept in the task when it ends.
pub const FINAL: &str = "screen.png";
/// Which display a running task's screen is, and how big.
const INFO: &str = "display.json";

/// A task's screen, as recorded when it started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Info {
    pub number: u32,
    pub width: u32,
    pub height: u32,
}

pub fn info(dir: &Path) -> Option<Info> {
    let v: serde_json::Value = serde_json::from_slice(&fs::read(dir.join(INFO)).ok()?).ok()?;
    let field = |k: &str| v[k].as_u64().and_then(|n| u32::try_from(n).ok());
    Some(Info { number: field("number")?, width: field("width")?, height: field("height")? })
}

/// Whether the task's screen is up right now.
pub fn is_up(dir: &Path) -> bool {
    dir.join(FRAMEBUFFER).is_file()
}

/// Acts on a task's screen as a person would: a click, a key, some typing
/// (`xdotool`, run against the task's display with its cookie).
pub fn act(dir: &Path, action: &Input) -> Result<()> {
    let info = info(dir).context("this task has no screen")?;
    let xdotool = crate::profiles::find_on_path("xdotool").context("acting on the screen needs xdotool (apt install xdotool, dnf install xdotool)")?;
    let mut cmd = Command::new(xdotool);
    match action {
        Input::Click { x, y, button } => {
            if *x >= info.width || *y >= info.height {
                bail!("({x}, {y}) is outside the {}x{} screen", info.width, info.height);
            }
            if !(1..=5).contains(button) {
                bail!("mouse buttons are 1 to 5");
            }
            cmd.args(["mousemove", "--sync", &x.to_string(), &y.to_string(), "click", &button.to_string()]);
        }
        Input::Key(key) => {
            if key.is_empty() || key.len() > 40 || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '+') {
                bail!("a key is a name like Return, Tab, ctrl+c or F5");
            }
            cmd.args(["key", "--clearmodifiers", key]);
        }
        Input::Type(text) => {
            if text.is_empty() || text.chars().count() > 500 || text.contains('\0') {
                bail!("type between 1 and 500 characters at a time");
            }
            cmd.args(["type", "--delay", "8", "--clearmodifiers", "--", text]);
        }
    }
    let out = cmd
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("DISPLAY", format!(":{}", info.number))
        .env("XAUTHORITY", dir.join("xauth"))
        .stdin(Stdio::null())
        .output()
        .context("run xdotool")?;
    if !out.status.success() {
        bail!("xdotool: {}", String::from_utf8_lossy(&out.stderr).lines().next().unwrap_or("failed"));
    }
    Ok(())
}

/// What a person does at a screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Input {
    Click { x: u32, y: u32, button: u32 },
    Key(String),
    Type(String),
}

/// `1280x800`: wide enough to be useful, small enough that a screenshot is cheap.
pub fn parse_size(s: &str) -> Result<(u32, u32)> {
    let (w, h) = s.trim().split_once(['x', 'X']).context("a screen size is WIDTHxHEIGHT, like 1280x800")?;
    let (w, h): (u32, u32) = (w.parse().context("the width isn't a number")?, h.parse().context("the height isn't a number")?);
    if !(320..=7680).contains(&w) || !(200..=4320).contains(&h) {
        bail!("a screen is between 320x200 and 7680x4320, not {w}x{h}");
    }
    Ok((w, h))
}

/// Xvfb, if it's installed.
pub fn xvfb() -> Option<PathBuf> {
    crate::profiles::find_on_path("Xvfb")
}

/// An X authority file with one cookie that any client of this display may
/// use (family "wild": it matches whatever the sandbox's hostname is).
fn write_cookie(path: &Path) -> Result<()> {
    let mut cookie = [0u8; 16];
    fs::File::open("/dev/urandom")?.read_exact(&mut cookie)?;
    let (name, mut entry) = (b"MIT-MAGIC-COOKIE-1", Vec::new());
    entry.extend(0xffffu16.to_be_bytes()); // family: wild
    entry.extend(0u16.to_be_bytes()); // address: any
    entry.extend(0u16.to_be_bytes()); // display number: any
    entry.extend((name.len() as u16).to_be_bytes());
    entry.extend(name);
    entry.extend((cookie.len() as u16).to_be_bytes());
    entry.extend(cookie);
    let mut file = fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;
    file.write_all(&entry)?;
    Ok(())
}

/// A running virtual screen.
pub struct Display {
    child: Child,
    dir: PathBuf,
    /// The X display number (`:N`) on this machine.
    pub number: u32,
    /// The server's socket, on this machine.
    pub socket: PathBuf,
    /// The cookie the sandbox presents.
    pub xauth: PathBuf,
    pub size: (u32, u32),
    /// Keeps the latest picture that had something on it: when the agent's last
    /// program exits and the sandbox is torn down, the screen goes black.
    watcher: Option<(JoinHandle<()>, Arc<AtomicBool>)>,
    latest: Arc<Mutex<Option<Vec<u8>>>>,
}

impl Display {
    /// Starts Xvfb for the task whose folder is `dir`.
    pub fn start(dir: &Path, size: (u32, u32)) -> Result<Display> {
        let xvfb = xvfb().context(
            "--display needs Xvfb, which isn't installed (Debian, Ubuntu: apt install xvfb; Fedora: dnf install xorg-x11-server-Xvfb)",
        )?;
        fs::create_dir_all(dir.join("fb"))?;
        let xauth = dir.join("xauth");
        write_cookie(&xauth)?;
        let log = fs::File::create(dir.join("xvfb.log"))?;
        let mut cmd = Command::new(xvfb);
        cmd.args(["-screen", "0", &format!("{}x{}x24", size.0, size.1)])
            // No network, and no abstract socket either: the one door is the socket file, and the cookie.
            .args(["-nolisten", "tcp", "-nolisten", "local"])
            // Shared memory can't cross into the sandbox's own IPC namespace; clients fall back to the protocol.
            .args(["-extension", "MIT-SHM", "-noreset", "-displayfd", "1"])
            .arg("-auth")
            .arg(&xauth)
            .arg("-fbdir")
            .arg(dir.join("fb"))
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(log)
            // Ctrl-C at your terminal is for the supervisor, which then ends the screen itself.
            .process_group(0);
        // If the supervisor is killed outright, the screen goes with it.
        unsafe {
            cmd.pre_exec(|| {
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM);
                Ok(())
            });
        }
        let mut child = cmd.spawn().context("start Xvfb")?;
        let number = match wait_for_number(&mut child) {
            Ok(n) => n,
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                let why = fs::read_to_string(dir.join("xvfb.log")).unwrap_or_default();
                let why = why.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or_default().to_string();
                bail!("Xvfb didn't start: {e:#}{}", if why.is_empty() { String::new() } else { format!(" ({why})") });
            }
        };
        let socket = PathBuf::from(format!("/tmp/.X11-unix/X{number}"));
        // For whoever acts on this screen from another process (the console).
        fs::write(dir.join(INFO), serde_json::json!({ "number": number, "width": size.0, "height": size.1 }).to_string())?;
        Ok(Display { child, dir: dir.to_path_buf(), number, socket, xauth, size, watcher: None, latest: Arc::default() })
    }

    /// Starts keeping the latest picture with something on it. A thread, so only
    /// once the sandbox has been forked.
    pub fn watch(&mut self) {
        let (stop, latest, framebuffer) = (Arc::new(AtomicBool::new(false)), self.latest.clone(), self.dir.join(FRAMEBUFFER));
        let flag = stop.clone();
        let thread = std::thread::spawn(move || {
            while !flag.load(Ordering::SeqCst) {
                if let Ok(data) = fs::read(&framebuffer) {
                    if !is_blank(&data) {
                        if let Ok(mut slot) = latest.lock() {
                            *slot = Some(data);
                        }
                    }
                }
                std::thread::sleep(Duration::from_millis(250));
            }
        });
        self.watcher = Some((thread, stop));
    }

    /// What the screen shows now, as a PNG (at most `max_width` wide, if given).
    pub fn screenshot(&self, max_width: Option<u32>) -> Result<Vec<u8>> {
        screenshot_file(&self.dir.join(FRAMEBUFFER), max_width)
    }

    /// Keeps the last picture in the task and ends the screen. The picture is the
    /// latest one with something on it (the screen is blank again by the time the
    /// sandbox is gone), else however the screen is now.
    pub fn finish(mut self) -> Option<Vec<u8>> {
        if let Some((thread, stop)) = self.watcher.take() {
            stop.store(true, Ordering::SeqCst);
            let _ = thread.join();
        }
        let sampled = self.latest.lock().ok().and_then(|mut slot| slot.take());
        let last = sampled.and_then(|data| parse_xwd(&data).ok().map(|image| image.png())).or_else(|| self.screenshot(None).ok());
        if let Some(png) = &last {
            let _ = fs::write(self.dir.join(FINAL), png);
        }
        unsafe { libc::kill(self.child.id() as i32, libc::SIGTERM) };
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_file(&self.xauth);
        let _ = fs::remove_file(&self.socket);
        last
    }
}

impl Drop for Display {
    /// However a task ends (even on an error), the screen doesn't outlive it.
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Xvfb writes the number of the display it took to the pipe once it's ready.
fn wait_for_number(child: &mut Child) -> Result<u32> {
    use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
    let stdout = child.stdout.take().context("no pipe to Xvfb")?;
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(status) = child.try_wait()? {
            bail!("it exited ({status})");
        }
        let mut fds = [PollFd::new(stdout.as_fd(), PollFlags::POLLIN | PollFlags::POLLHUP)];
        if poll(&mut fds, PollTimeout::from(100u16))? > 0 {
            let mut line = String::new();
            BufReader::new(stdout).read_line(&mut line)?;
            return line.trim().parse().with_context(|| format!("it said {:?}, not a display number", line.trim()));
        }
        if Instant::now() > deadline {
            bail!("it wasn't ready after 15 seconds");
        }
    }
}

/// A PNG of a server's framebuffer file.
pub fn screenshot_file(framebuffer: &Path, max_width: Option<u32>) -> Result<Vec<u8>> {
    let data = fs::read(framebuffer).with_context(|| format!("read {}", framebuffer.display()))?;
    let mut image = parse_xwd(&data)?;
    if let Some(w) = max_width.filter(|w| *w < image.width) {
        image = image.scaled_to_width(w);
    }
    Ok(image.png())
}

/// Where the pixels start in an XWD dump, if it looks like one.
fn pixels_start(data: &[u8]) -> Option<usize> {
    let field = |i: usize| data.get(4 * i..4 * i + 4).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize);
    let start = field(0)?.checked_add(field(19)?.checked_mul(12)?)?;
    (start <= data.len()).then_some(start)
}

/// Nothing drawn at all: a fresh screen is all zeros.
fn is_blank(data: &[u8]) -> bool {
    pixels_start(data).is_some_and(|start| data[start..].iter().all(|b| *b == 0))
}

/// A picture, 8 bits a channel.
#[derive(Debug)]
pub struct Image {
    pub width: u32,
    pub height: u32,
    /// Row by row, R G B.
    pub rgb: Vec<u8>,
}

/// An `xwd` file, as Xvfb keeps its framebuffer (TrueColor, 24 or 32 bits a pixel).
pub fn parse_xwd(data: &[u8]) -> Result<Image> {
    if data.len() < 100 {
        bail!("not a screen dump: too short");
    }
    let field = |i: usize| u32::from_be_bytes([data[4 * i], data[4 * i + 1], data[4 * i + 2], data[4 * i + 3]]);
    let (header_size, version, format) = (field(0) as usize, field(1), field(2));
    let (width, height, byte_order, bpp, per_line) = (field(4), field(5), field(7), field(11), field(12) as usize);
    let (red, green, blue, ncolors) = (field(14), field(15), field(16), field(19) as usize);
    if version != 7 || format != 2 {
        bail!("not an XWD screen dump (version {version}, format {format})");
    }
    if !(1..=16384).contains(&width) || !(1..=16384).contains(&height) {
        bail!("a {width}x{height} screen? that isn't right");
    }
    if bpp != 32 && bpp != 24 {
        bail!("{bpp} bits a pixel isn't supported (24 or 32)");
    }
    let bytes = (bpp / 8) as usize;
    if per_line < width as usize * bytes {
        bail!("rows are shorter than their pixels");
    }
    let start = header_size + ncolors * 12;
    if data.len() < start + per_line * height as usize {
        bail!("the dump is shorter than its header says");
    }
    // Where each channel lives in a pixel, and how far to bring it to 8 bits.
    let channel = |mask: u32| -> (u32, u32, u32) {
        let shift = mask.trailing_zeros();
        let bits = (mask >> shift).trailing_ones();
        (mask, shift, bits)
    };
    let channels = [channel(red), channel(green), channel(blue)];
    if channels.iter().any(|(m, _, bits)| *m == 0 || *bits == 0 || *bits > 8) {
        bail!("unexpected colour masks {red:#x} {green:#x} {blue:#x}");
    }
    let mut rgb = Vec::with_capacity(width as usize * height as usize * 3);
    for y in 0..height as usize {
        let row = &data[start + y * per_line..start + y * per_line + width as usize * bytes];
        for px in row.chunks_exact(bytes) {
            let mut p = [0u8; 4];
            if byte_order == 0 {
                p[..bytes].copy_from_slice(px);
            } else {
                p[4 - bytes..].copy_from_slice(px);
            }
            let value = if byte_order == 0 { u32::from_le_bytes(p) } else { u32::from_be_bytes(p) };
            for (mask, shift, bits) in channels {
                let v = (value & mask) >> shift;
                rgb.push(if bits == 8 { v as u8 } else { (v * 255 / ((1 << bits) - 1)) as u8 });
            }
        }
    }
    Ok(Image { width, height, rgb })
}

impl Image {
    /// Nearest-neighbour, keeping the shape: cheap, and fine for watching.
    pub fn scaled_to_width(&self, width: u32) -> Image {
        let width = width.clamp(1, self.width);
        let height = ((self.height as u64 * width as u64) / self.width as u64).max(1) as u32;
        let mut rgb = Vec::with_capacity(width as usize * height as usize * 3);
        for y in 0..height as u64 {
            let sy = (y * self.height as u64 / height as u64) as usize;
            for x in 0..width as u64 {
                let sx = (x * self.width as u64 / width as u64) as usize;
                let i = (sy * self.width as usize + sx) * 3;
                rgb.extend_from_slice(&self.rgb[i..i + 3]);
            }
        }
        Image { width, height, rgb }
    }

    /// As a PNG: each row filtered the way that leaves it with the smallest
    /// numbers, then deflated. A desktop is mostly flat colour, so this is
    /// a few percent of the raw size, which is what a phone watching it over a
    /// connection (or a console polling it every second) needs.
    pub fn png(&self) -> Vec<u8> {
        let stride = self.width as usize * 3;
        let mut raw = Vec::with_capacity(self.rgb.len() + self.height as usize);
        let blank = vec![0u8; stride];
        let mut prev: &[u8] = &blank;
        let (mut best, mut trial) = (Vec::with_capacity(stride), Vec::with_capacity(stride));
        for row in self.rgb.chunks_exact(stride) {
            let mut lowest = (u64::MAX, 0);
            for kind in 0..=4u8 {
                filter(kind, row, prev, &mut trial);
                // The usual guess: the smaller the numbers (as signed bytes), the better it deflates.
                let cost: u64 = trial.iter().map(|b| (*b as i8).unsigned_abs() as u64).sum();
                if cost < lowest.0 {
                    lowest = (cost, kind);
                    std::mem::swap(&mut best, &mut trial);
                }
            }
            raw.push(lowest.1);
            raw.extend_from_slice(&best);
            prev = row;
        }
        let z = miniz_oxide::deflate::compress_to_vec_zlib(&raw, DEFLATE_LEVEL);

        let mut ihdr = Vec::new();
        ihdr.extend(self.width.to_be_bytes());
        ihdr.extend(self.height.to_be_bytes());
        ihdr.extend([8, 2, 0, 0, 0]); // 8 bits, RGB, deflate, adaptive filtering, no interlace
        let mut out = b"\x89PNG\r\n\x1a\n".to_vec();
        for (kind, body) in [(b"IHDR", ihdr.as_slice()), (b"IDAT", z.as_slice()), (b"IEND", &[][..])] {
            out.extend((body.len() as u32).to_be_bytes());
            let start = out.len();
            out.extend(kind);
            out.extend(body);
            let crc = crc32(&out[start..]);
            out.extend(crc.to_be_bytes());
        }
        out
    }
}

/// How hard to deflate: 1 is quick and leaves most of the gain on screens.
const DEFLATE_LEVEL: u8 = 2;

/// One of PNG's five row filters over RGB pixels (3 bytes each), into `out`.
fn filter(kind: u8, row: &[u8], prev: &[u8], out: &mut Vec<u8>) {
    out.clear();
    for (i, x) in row.iter().enumerate() {
        let a = if i >= 3 { row[i - 3] } else { 0 };
        let b = prev[i];
        let c = if i >= 3 { prev[i - 3] } else { 0 };
        out.push(x.wrapping_sub(match kind {
            0 => 0,
            1 => a,
            2 => b,
            3 => ((a as u16 + b as u16) / 2) as u8,
            _ => paeth(a, b, c),
        }));
    }
}

fn paeth(a: u8, b: u8, c: u8) -> u8 {
    let (a, b, c) = (a as i16, b as i16, c as i16);
    let p = a + b - c;
    let (pa, pb, pc) = ((p - a).abs(), (p - b).abs(), (p - c).abs());
    if pa <= pb && pa <= pc {
        a as u8
    } else if pb <= pc {
        b as u8
    } else {
        c as u8
    }
}

const CRC_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut n = 0;
    while n < 256 {
        let mut c = n as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { 0xedb8_8320 ^ (c >> 1) } else { c >> 1 };
            k += 1;
        }
        table[n] = c;
        n += 1;
    }
    table
};

fn crc32(data: &[u8]) -> u32 {
    !data.iter().fold(!0u32, |c, b| CRC_TABLE[((c ^ *b as u32) & 0xff) as usize] ^ (c >> 8))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// An XWD dump as Xvfb writes it: TrueColor, 32 bits a pixel, little-endian pixels.
    fn xwd(width: u32, height: u32, pixels: &[[u8; 4]]) -> Vec<u8> {
        let name = b"Xvfb test:0.0\0";
        let header_size = 100 + name.len() as u32;
        let fields: [u32; 25] = [
            header_size, 7, 2, 24, width, height, 0, 0, 32, 0, 32, 32, width * 4, 4, 0xff0000, 0xff00, 0xff, 8, 256, 256, width, height, 0, 0, 0,
        ];
        let mut out: Vec<u8> = fields.iter().flat_map(|f| f.to_be_bytes()).collect();
        out.extend(name);
        out.extend(vec![0u8; 256 * 12]);
        out.extend(pixels.iter().flatten());
        out
    }

    #[test]
    fn a_framebuffer_dump_becomes_rgb() {
        // B G R X, as a little-endian 0x00RRGGBB pixel is stored.
        let dump = xwd(3, 2, &[[0, 0, 255, 0], [0, 255, 0, 0], [255, 0, 0, 0], [0, 128, 255, 0], [10, 20, 30, 0], [0, 0, 0, 0]]);
        let image = parse_xwd(&dump).unwrap();
        assert_eq!((image.width, image.height), (3, 2));
        assert_eq!(image.rgb, [255, 0, 0, 0, 255, 0, 0, 0, 255, 255, 128, 0, 30, 20, 10, 0, 0, 0]);
        for broken in [&dump[..60], &dump[..dump.len() - 4]] {
            assert!(parse_xwd(broken).is_err());
        }
        let mut wrong = dump.clone();
        wrong[4..8].copy_from_slice(&3u32.to_be_bytes()); // not version 7
        assert!(parse_xwd(&wrong).unwrap_err().to_string().contains("not an XWD"));
    }

    /// Reads a PNG back: (width, height, the pixels, the filters undone), and the filter each row used.
    fn unpng(png: &[u8]) -> (u32, u32, Vec<u8>, Vec<u8>) {
        assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n");
        let (mut i, mut idat, mut dims) = (8, Vec::new(), (0, 0));
        let mut kinds = Vec::new();
        while i < png.len() {
            let len = u32::from_be_bytes(png[i..i + 4].try_into().unwrap()) as usize;
            let kind = &png[i + 4..i + 8];
            let body = &png[i + 8..i + 8 + len];
            let crc = u32::from_be_bytes(png[i + 8 + len..i + 12 + len].try_into().unwrap());
            assert_eq!(crc, crc32(&png[i + 4..i + 8 + len]), "the checksum of {}", String::from_utf8_lossy(kind));
            match kind {
                b"IHDR" => dims = (u32::from_be_bytes(body[..4].try_into().unwrap()), u32::from_be_bytes(body[4..8].try_into().unwrap())),
                b"IDAT" => idat.extend(body),
                _ => {}
            }
            kinds.push(String::from_utf8_lossy(kind).into_owned());
            i += 12 + len;
        }
        assert_eq!(kinds, ["IHDR", "IDAT", "IEND"]);
        let raw = miniz_oxide::inflate::decompress_to_vec_zlib(&idat).expect("a zlib stream");
        let stride = dims.0 as usize * 3;
        assert_eq!(raw.len(), (stride + 1) * dims.1 as usize);
        let (mut pixels, mut used, mut prev) = (Vec::new(), Vec::new(), vec![0u8; stride]);
        for line in raw.chunks(stride + 1) {
            used.push(line[0]);
            let mut row = vec![0u8; stride];
            for i in 0..stride {
                let a = if i >= 3 { row[i - 3] } else { 0 };
                let b = prev[i];
                let c = if i >= 3 { prev[i - 3] } else { 0 };
                let predicted = match line[0] {
                    0 => 0,
                    1 => a,
                    2 => b,
                    3 => ((a as u16 + b as u16) / 2) as u8,
                    4 => paeth(a, b, c),
                    other => panic!("filter {other}"),
                };
                row[i] = line[1 + i].wrapping_add(predicted);
            }
            pixels.extend(&row);
            prev = row;
        }
        (dims.0, dims.1, pixels, used)
    }

    #[test]
    fn a_png_reads_back_as_the_picture_it_was() {
        let image = Image { width: 3, height: 2, rgb: (0..18).collect() };
        let (w, h, pixels, _) = unpng(&image.png());
        assert_eq!((w, h, pixels), (3, 2, (0..18).collect::<Vec<u8>>()));
        // A bigger one with patterns (rows that want different filters), and noise.
        let mut noise = 0x2545_f491u32;
        let rgb: Vec<u8> = (0..200 * 150 * 3)
            .map(|i| match (i / 600) % 3 {
                0 => (i % 251) as u8,
                1 => 90,
                _ => {
                    noise ^= noise << 13;
                    noise ^= noise >> 17;
                    noise ^= noise << 5;
                    noise as u8
                }
            })
            .collect();
        let big = Image { width: 200, height: 150, rgb };
        let (w, h, pixels, _) = unpng(&big.png());
        assert_eq!((w, h, pixels == big.rgb), (200, 150, true));
        // No picture, no rows: still a PNG.
        let nothing = Image { width: 1, height: 1, rgb: vec![9, 8, 7] };
        assert_eq!(unpng(&nothing.png()).2, [9, 8, 7]);
        // Known value of the checksum.
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }

    #[test]
    fn every_filter_can_be_undone() {
        // Rows that are neither flat nor smooth, so no filter can pass for another.
        let (mut above, mut row, mut state) = (vec![0u8; 30], vec![0u8; 30], 7u32);
        for _ in 0..2 {
            for byte in above.iter_mut().chain(row.iter_mut()) {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                *byte = (state >> 24) as u8;
            }
        }
        for kind in 0..=4u8 {
            let mut out = Vec::new();
            filter(kind, &row, &above, &mut out);
            let mut back = vec![0u8; row.len()];
            for i in 0..row.len() {
                let a = if i >= 3 { back[i - 3] } else { 0 };
                let b = above[i];
                let c = if i >= 3 { above[i - 3] } else { 0 };
                let predicted = match kind {
                    0 => 0,
                    1 => a,
                    2 => b,
                    3 => ((a as u16 + b as u16) / 2) as u8,
                    _ => paeth(a, b, c),
                };
                back[i] = out[i].wrapping_add(predicted);
            }
            assert_eq!(back, row, "filter {kind}");
        }
    }

    #[test]
    fn a_desktop_is_a_few_percent_of_its_size() {
        // A grey desktop with a lighter window and a gradient bar: flat areas, edges and one smooth ramp.
        let (w, h) = (1280u32, 800u32);
        let mut rgb = Vec::with_capacity((w * h * 3) as usize);
        for y in 0..h {
            for x in 0..w {
                let pixel = match (x, y) {
                    (200..900, 150..600) => [235, 235, 235],
                    (0..1280, 770..800) => [(x / 5) as u8, 80, 160],
                    _ => [40, 44, 52],
                };
                rgb.extend(pixel);
            }
        }
        let image = Image { width: w, height: h, rgb };
        let png = image.png();
        assert!(png.len() < image.rgb.len() / 50, "{} bytes for {}", png.len(), image.rgb.len());
        let (_, _, pixels, used) = unpng(&png);
        assert!(pixels == image.rgb);
        // The gradient row wants Sub; flat rows are fine with anything cheap.
        assert!(used.iter().any(|k| *k != 0), "some rows are filtered: {used:?}");
        let started = std::time::Instant::now();
        let _ = image.png();
        assert!(started.elapsed() < std::time::Duration::from_secs(2), "a frame takes {:?}", started.elapsed());
    }

    #[test]
    fn a_screen_with_nothing_on_it_is_blank() {
        let blank = xwd(2, 2, &[[0; 4]; 4]);
        assert!(is_blank(&blank));
        assert!(!is_blank(&xwd(2, 2, &[[0; 4], [0; 4], [0, 0, 0, 1], [0; 4]])));
        assert!(!is_blank(b"not a dump"), "unreadable isn't a blank screen to keep");
    }

    #[test]
    fn a_smaller_picture_keeps_its_shape() {
        let image = Image { width: 4, height: 2, rgb: (0..24).collect() };
        let half = image.scaled_to_width(2);
        assert_eq!((half.width, half.height, half.rgb.len()), (2, 1, 6));
        assert_eq!(half.rgb, [0, 1, 2, 6, 7, 8]);
        assert_eq!(image.scaled_to_width(100).width, 4, "never bigger than it was");
    }

    #[test]
    fn sizes() {
        assert_eq!(parse_size("1280x800").unwrap(), (1280, 800));
        assert_eq!(parse_size(" 1920X1080 ").unwrap(), (1920, 1080));
        for bad in ["1280", "axb", "100x100", "9000x9000", "1280x", ""] {
            assert!(parse_size(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_cookie_is_one_wild_entry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("xauth");
        write_cookie(&path).unwrap();
        let data = fs::read(&path).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(&data[..6], [0xff, 0xff, 0, 0, 0, 0], "any family, any address, any display");
        assert_eq!(&data[6..8], [0, 18]);
        assert_eq!(&data[8..26], b"MIT-MAGIC-COOKIE-1");
        assert_eq!(&data[26..28], [0, 16]);
        assert_eq!(data.len(), 28 + 16);
        let again = dir.path().join("again");
        write_cookie(&again).unwrap();
        assert_ne!(fs::read(&again).unwrap()[28..], data[28..], "a new cookie each time");
    }
}
