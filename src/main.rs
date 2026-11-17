use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    net::{SocketAddr, TcpStream},
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::{Child, Command},
    time::sleep,
};

#[derive(Parser)]
#[command(version, about = "Argus reverse relay client (Rust)")]
struct Cli {
    #[arg(long, global = true)]
    state_dir: Option<PathBuf>,
    #[command(subcommand)]
    command: Action,
}
#[derive(Subcommand)]
enum Action {
    Enroll {
        #[arg(long)]
        center: String,
        #[arg(long)]
        token: String,
        #[arg(long, default_value_t = false)]
        run: bool,
        #[arg(long, default_value = "chisel")]
        chisel: String,
    },
    Join {
        #[arg(long)]
        center: String,
        #[arg(long)]
        pair: String,
        #[arg(long, default_value_t = false)]
        run: bool,
        #[arg(long, default_value = "chisel")]
        chisel: String,
    },
    Run {
        #[arg(long)]
        pair: String,
        #[arg(long, default_value = "chisel")]
        chisel: String,
    },
    Sync {
        #[arg(long)]
        pair: String,
    },
    Check {
        #[arg(long)]
        pair: String,
    },
    List,
    InstallService {
        #[arg(long)]
        pair: String,
        #[arg(long, default_value = "chisel")]
        chisel: String,
        #[arg(long, default_value_t = false)]
        system: bool,
    },
    ProxyCapture {
        #[arg(long)]
        pair: String,
    },
    Watchdog {
        #[arg(long)]
        pair: String,
        #[arg(long, default_value_t = false)]
        check_only: bool,
    },
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
struct Service {
    name: String,
    local_port: u16,
    relay_port: u16,
    protocol: String,
}
#[derive(Clone, Serialize, Deserialize)]
struct WatchdogSpec {
    service: String,
    script: String,
    sha256: String,
    cooldown_secs: u64,
}
#[derive(Clone, Serialize, Deserialize)]
struct Enrollment {
    center: String,
    pair: String,
    username: String,
    password: String,
    fingerprint: String,
    revision: u64,
    services: Vec<Service>,
    interval_secs: u64,
    #[serde(default)]
    transport_proxy: Option<String>,
    #[serde(default)]
    watchdogs: Vec<WatchdogSpec>,
}
fn state_root(arg: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = arg {
        return Ok(path);
    }
    #[cfg(windows)]
    let home = std::env::var_os("USERPROFILE");
    #[cfg(not(windows))]
    let home = std::env::var_os("HOME");
    home.map(|h| PathBuf::from(h).join(".argus-client"))
        .context("home directory unknown: pass --state-dir")
}
fn safe(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 48
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
fn file(dir: &Path, pair: &str) -> Result<PathBuf> {
    if !safe(pair) {
        bail!("invalid pair");
    }
    Ok(dir.join(format!("{pair}.json")))
}
fn save(dir: &Path, e: &Enrollment) -> Result<()> {
    fs::create_dir_all(dir)?;
    // Validate and persist centrally injected scripts before writing the new
    // configuration revision. A compromised/malformed manifest fails closed.
    let scripts = dir.join("watchdogs");
    fs::create_dir_all(&scripts)?;
    for w in &e.watchdogs {
        if !safe(&w.service)
            || !e.services.iter().any(|s| s.name == w.service)
            || w.script.len() > 16384
        {
            bail!("invalid watchdog script service");
        }
        let got = format!("{:x}", Sha256::digest(w.script.as_bytes()));
        if got != w.sha256 {
            bail!("watchdog script checksum mismatch");
        }
        let script_file = scripts.join(format!("{}-{}.sh", e.pair, w.service));
        let tmp_script = script_file.with_extension("sh.new");
        fs::write(&tmp_script, &w.script)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&tmp_script, fs::Permissions::from_mode(0o700))?;
        }
        #[cfg(windows)]
        if script_file.exists() {
            fs::remove_file(&script_file)?;
        }
        fs::rename(tmp_script, script_file)?;
    }
    let target = file(dir, &e.pair)?;
    let tmp = target.with_extension("json.new");
    fs::write(&tmp, serde_json::to_vec_pretty(e)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(windows)]
    if target.exists() {
        fs::remove_file(&target)?;
    }
    fs::rename(tmp, target)?;
    Ok(())
}
fn load(dir: &Path, pair: &str) -> Result<Enrollment> {
    Ok(serde_json::from_slice(
        &fs::read(file(dir, pair)?).context("pair not enrolled")?,
    )?)
}
fn check_url(url: &str) -> Result<()> {
    if url.starts_with("https://")
        || url.starts_with("http://127.0.0.1")
        || url.starts_with("http://localhost")
    {
        Ok(())
    } else {
        bail!("center must be HTTPS (loopback HTTP is permitted for tests)")
    }
}
async fn enroll(dir: &Path, center: String, token: String) -> Result<Enrollment> {
    check_url(&center)?;
    if token.len() < 32 || !token.bytes().all(|c| c.is_ascii_hexdigit()) {
        bail!("invalid enrollment token format");
    }
    let url = format!("{}/api/enroll/{token}", center.trim_end_matches('/'));
    let response = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()?
        .post(&url)
        .send()
        .await?;
    if !response.status().is_success() {
        bail!("enrollment rejected: HTTP {}", response.status());
    }
    let mut e: Enrollment = response.json().await?;
    // Snapshot provider proxy once so a later VM process restart does not
    // require a secret-bearing VM environment variable for reverse transport.
    e.transport_proxy = std::env::var("HTTPS_PROXY")
        .ok()
        .filter(|x| !x.is_empty())
        .or_else(|| std::env::var("https_proxy").ok().filter(|x| !x.is_empty()));
    if e.fingerprint.trim().is_empty() || e.services.is_empty() || !safe(&e.pair) {
        bail!("malformed enrollment or absent host pin");
    }
    if !e
        .center
        .trim_end_matches('/')
        .eq(center.trim_end_matches('/'))
    {
        bail!("unexpected center URL");
    }
    save(dir, &e)?;
    println!(
        "ARGUS_ENROLLED={} REVISION={} SERVICES={}",
        e.pair,
        e.revision,
        e.services.len()
    );
    Ok(e)
}
async fn join(dir: &Path, center: String, pair: String) -> Result<Enrollment> {
    check_url(&center)?;
    if !safe(&pair) {
        bail!("invalid pair name");
    }
    if file(dir, &pair)?.exists() {
        bail!("already enrolled in this state directory");
    }
    let mut secret = [0_u8; 32];
    rand::thread_rng().fill_bytes(&mut secret);
    let nonce = hex::encode(secret);
    let proof = format!("{:x}", Sha256::digest(nonce.as_bytes()));
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()?;
    let base = center.trim_end_matches('/');
    let resp = http
        .post(format!("{base}/api/join/request/{pair}"))
        .json(&serde_json::json!({"proof":proof}))
        .send()
        .await?;
    if !resp.status().is_success() {
        bail!("join request rejected: HTTP {}", resp.status());
    }
    println!(
        "ARGUS_JOIN_PENDING={} PROOF={} APPROVAL_REQUIRED=true",
        pair, proof
    );
    // Only a public SHA-256 proof is printed. The 256-bit nonce never leaves
    // this process except in its HTTPS claim request to the designated Center.
    for _ in 0..180 {
        let resp = http
            .post(format!("{base}/api/join/claim/{pair}"))
            .json(&serde_json::json!({"nonce":nonce}))
            .send()
            .await?;
        if resp.status() == reqwest::StatusCode::ACCEPTED {
            sleep(Duration::from_secs(5)).await;
            continue;
        }
        if !resp.status().is_success() {
            bail!("join claim rejected: HTTP {}", resp.status());
        }
        let mut e: Enrollment = resp.json().await?;
        e.transport_proxy = std::env::var("HTTPS_PROXY")
            .ok()
            .filter(|x| !x.is_empty())
            .or_else(|| std::env::var("https_proxy").ok().filter(|x| !x.is_empty()));
        if e.pair != pair
            || e.center.trim_end_matches('/') != base
            || e.fingerprint.trim().is_empty()
            || e.services.is_empty()
        {
            bail!("invalid join identity or missing transport pin");
        }
        save(dir, &e)?;
        println!(
            "ARGUS_JOIN_SUCCEEDED={} REVISION={} SERVICES={}",
            pair,
            e.revision,
            e.services.len()
        );
        return Ok(e);
    }
    bail!("join approval timed out after 15 minutes")
}
async fn sync(dir: &Path, pair: &str, verbose: bool) -> Result<bool> {
    let old = load(dir, pair)?;
    check_url(&old.center)?;
    let url = format!("{}/api/sync/{}", old.center.trim_end_matches('/'), old.pair);
    let response = reqwest::Client::builder()
        .timeout(Duration::from_secs(12))
        .build()?
        .get(&url)
        .bearer_auth(&old.password)
        .send()
        .await?;
    if !response.status().is_success() {
        bail!("sync rejected HTTP {}", response.status());
    }
    let mut updated: Enrollment = response.json().await?;
    // Client-specific proxy is never overwritten by the center's sync payload.
    updated.transport_proxy = old.transport_proxy.clone();
    if updated.pair != old.pair
        || updated.username != old.username
        || updated.password != old.password
        || updated.fingerprint != old.fingerprint
        || updated.center != old.center
    {
        bail!("identity changed unexpectedly; refusing config update");
    }
    if updated.revision < old.revision {
        bail!("configuration revision rollback rejected");
    }
    let changed = updated.revision > old.revision || updated.services != old.services;
    if changed {
        save(dir, &updated)?;
    }
    if verbose {
        println!(
            "SYNC={} REVISION={} CHANGED={}",
            pair, updated.revision, changed
        );
    }
    Ok(changed)
}
fn local_ok(port: u16) -> bool {
    TcpStream::connect_timeout(
        &SocketAddr::from(([127, 0, 0, 1], port)),
        Duration::from_secs(2),
    )
    .is_ok()
}
fn report(dir: &Path, pair: &str) -> Result<()> {
    let e = load(dir, pair)?;
    println!(
        "PAIR={} CENTER={} REVISION={} PINNED_HOST_KEY=true",
        e.pair, e.center, e.revision
    );
    for s in e.services {
        println!(
            "SERVICE={} PORT={} LOOPBACK_TCP={}",
            s.name,
            s.local_port,
            local_ok(s.local_port)
        );
    }
    Ok(())
}
async fn start_chisel(e: &Enrollment, binary: &str) -> Result<Child> {
    let url = format!("{}/_wire/{}", e.center.trim_end_matches('/'), e.pair);
    let mut cmd = Command::new(binary);
    cmd.arg("client");
    if let Some(proxy) = &e.transport_proxy {
        cmd.arg("--proxy").arg(proxy);
    }
    cmd.arg("--fingerprint")
        .arg(&e.fingerprint)
        .arg("--keepalive")
        .arg("25s")
        .arg("--max-retry-interval")
        .arg("10s")
        .arg(&url);
    for svc in &e.services {
        cmd.arg(format!(
            "R:127.0.0.1:{}:127.0.0.1:{}",
            svc.relay_port, svc.local_port
        ));
    }
    // Chisel reads AUTH from child environment; no process arguments or persistent
    // VM environment setting contain the relay password.
    cmd.env("AUTH", format!("{}:{}", e.username, e.password))
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = cmd
        .spawn()
        .with_context(|| format!("start Chisel executable {binary}"))?;
    if let Some(stderr) = child.stderr.take() {
        let name = e.pair.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if line.contains("client: Connected") {
                    println!("ARGUS_TRANSPORT_CONNECTED={name}");
                } else if line.contains("client: Disconnected") {
                    eprintln!("ARGUS_TRANSPORT_DISCONNECTED={name}");
                } else if line.contains("client: Connection error") {
                    eprintln!("ARGUS_TRANSPORT_RETRY={name}");
                }
                // Deliberately never print an unfiltered Chisel line: its
                // proxy URL may contain credentials on transport errors.
            }
        });
    }
    Ok(child)
}
async fn run(dir: &Path, pair: &str, chisel: &str) -> Result<()> {
    let mut e = load(dir, pair)?;
    let mut child = start_chisel(&e, chisel).await?;
    let mut misses = std::collections::BTreeMap::<String, u32>::new();
    println!("ARGUS_CLIENT_RUNNING={} REVISION={}", pair, e.revision);
    loop {
        tokio::select! {
            result=child.wait()=>{
                eprintln!("ARGUS_TRANSPORT_EXIT={} STATUS={:?}",pair,result.ok());
                sleep(Duration::from_secs(3)).await;
                e=load(dir,pair)?;
                child=start_chisel(&e,chisel).await?;
            }
            _=sleep(Duration::from_secs(e.interval_secs.clamp(5,300)))=>{
                if let Err(err)=sync(dir,pair,false).await {eprintln!("ARGUS_SYNC_WARNING={err:#}");}
                let next=load(dir,pair)?;
                if next.revision!=e.revision {
                    let _=child.kill().await;
                    e=next;
                    child=start_chisel(&e,chisel).await?;
                    println!("ARGUS_RELOADED={} REVISION={}",pair,e.revision);
                }
                for service in &e.services {
                    if !local_ok(service.local_port) {
                        eprintln!("ARGUS_SERVICE_UNHEALTHY={} PORT={}",service.name,service.local_port);
                        let count=misses.entry(service.name.clone()).or_insert(0);
                        *count=count.saturating_add(1);
                        if *count>=2 {if let Err(err)=restore_one(dir,&e,service).await {eprintln!("ARGUS_WATCHDOG_ERROR={}:{}",service.name,err);}}
                    } else {misses.remove(&service.name);}
                }
            }
        }
    }
}
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
async fn restore_one(dir: &Path, e: &Enrollment, service: &Service) -> Result<()> {
    let Some(w) = e.watchdogs.iter().find(|w| w.service == service.name) else {
        eprintln!("ARGUS_WATCHDOG_UNCONFIGURED={}", service.name);
        return Ok(());
    };
    let stamp = dir
        .join("watchdogs")
        .join(format!("{}-{}.last", e.pair, service.name));
    let last = fs::read_to_string(&stamp)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or_default();
    if now_secs().saturating_sub(last) < w.cooldown_secs {
        eprintln!("ARGUS_WATCHDOG_COOLDOWN={}", service.name);
        return Ok(());
    }
    fs::write(&stamp, now_secs().to_string())?;
    let script = dir
        .join("watchdogs")
        .join(format!("{}-{}.sh", e.pair, service.name));
    let mut child = Command::new("bash")
        .arg(&script)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("launch watchdog {}", service.name))?;
    let done = tokio::time::timeout(Duration::from_secs(45), child.wait()).await;
    match done {
        Ok(Ok(status)) if status.success() => {
            for _ in 0..5 {
                if local_ok(service.local_port) {
                    println!("ARGUS_WATCHDOG_RESTORED={}", service.name);
                    return Ok(());
                }
                sleep(Duration::from_secs(1)).await;
            }
            eprintln!(
                "ARGUS_WATCHDOG_SCRIPT_FINISHED_BUT_UNHEALTHY={}",
                service.name
            );
        }
        Ok(Ok(_)) => eprintln!("ARGUS_WATCHDOG_SCRIPT_FAILED={}", service.name),
        Ok(Err(_)) => eprintln!("ARGUS_WATCHDOG_WAIT_FAILED={}", service.name),
        Err(_) => {
            let _ = child.kill().await;
            eprintln!("ARGUS_WATCHDOG_TIMED_OUT={}", service.name);
        }
    };
    Ok(())
}
async fn watchdog_check(dir: &Path, pair: &str, execute: bool) -> Result<()> {
    let e = load(dir, pair)?;
    for service in &e.services {
        let ok = local_ok(service.local_port);
        let configured = e.watchdogs.iter().any(|w| w.service == service.name);
        println!(
            "ARGUS_WATCHDOG_CHECK={} HEALTHY={} CONFIGURED={}",
            service.name, ok, configured
        );
        if execute && !ok && configured {
            restore_one(dir, &e, service).await?;
        }
    }
    Ok(())
}

fn systemd_arg(value: &str) -> String {
    // Quote paths for systemd ExecStart, escape specifiers and double-quotes.
    format!(
        "\"{}\"",
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
    )
}
fn systemd_unit(pair: &str, binary: &Path, state: &Path, chisel: &str, system: bool) -> String {
    let target = if system {
        "multi-user.target"
    } else {
        "default.target"
    };
    format!(
        "[Unit]\nDescription=Argus Client {pair}\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nUMask=0077\nExecStart={} --state-dir {} run --pair {} --chisel {}\nRestart=always\nRestartSec=5\n\n[Install]\nWantedBy={}\n",
        systemd_arg(&binary.to_string_lossy()),systemd_arg(&state.to_string_lossy()),pair,systemd_arg(chisel),target
    )
}
fn install_service(dir: &Path, pair: &str, chisel: &str, system: bool) -> Result<()> {
    let _ = load(dir, pair)?;
    let binary = std::env::current_exe()?;
    let state = fs::canonicalize(dir)?;
    #[cfg(target_os = "linux")]
    {
        let units = if system {
            PathBuf::from("/etc/systemd/system")
        } else {
            let home = std::env::var_os("HOME").context("HOME unavailable")?;
            PathBuf::from(home).join(".config/systemd/user")
        };
        fs::create_dir_all(&units)?;
        let unit = units.join(format!("argus-client-{pair}.service"));
        // Pair is validated by load; execution is generated only from local
        // absolute executable paths. Systemd handles restart on failure.
        let content = systemd_unit(pair, &binary, &state, chisel, system);
        fs::write(&unit, content)?;
        let mut reload = std::process::Command::new("systemctl");
        if !system {
            reload.arg("--user");
        }
        let reload = reload.arg("daemon-reload").status()?;
        if !reload.success() {
            bail!("systemd reload failed");
        }
        let mut start = std::process::Command::new("systemctl");
        if !system {
            start.arg("--user");
        }
        let start = start
            .args(["enable", "--now", &format!("argus-client-{pair}.service")])
            .status()?;
        if !start.success() {
            bail!("systemd enable failed");
        }
        println!("ARGUS_AUTOSTART_INSTALLED={}", unit.display());
    }
    #[cfg(windows)]
    {
        if system {
            bail!("--system is supported on Linux only");
        }
        let task = format!("Argus-Client-{pair}");
        let command = format!(
            "\\\"{}\\\" --state-dir \\\"{}\\\" run --pair {} --chisel \\\"{}\\\"",
            binary.display(),
            state.display(),
            pair,
            chisel
        );
        let result = std::process::Command::new("schtasks")
            .args([
                "/Create", "/F", "/SC", "ONLOGON", "/TN", &task, "/TR", &command,
            ])
            .status()?;
        if !result.success() {
            bail!("scheduled task creation failed");
        }
        println!(
            "ARGUS_AUTOSTART_INSTALLED={} (runs when user logs on)",
            task
        );
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    bail!("autostart not implemented on this OS");
    Ok(())
}
#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let dir = state_root(cli.state_dir)?;
    match cli.command {
        Action::Enroll {
            center,
            token,
            run: run_now,
            chisel,
        } => {
            let e = enroll(&dir, center, token).await?;
            if run_now {
                run(&dir, &e.pair, &chisel).await?;
            }
            Ok(())
        }
        Action::Join {
            center,
            pair,
            run: run_now,
            chisel,
        } => {
            let e = join(&dir, center, pair).await?;
            if run_now {
                run(&dir, &e.pair, &chisel).await?;
            }
            Ok(())
        }
        Action::Run { pair, chisel } => run(&dir, &pair, &chisel).await,
        Action::Sync { pair } => {
            sync(&dir, &pair, true).await?;
            Ok(())
        }
        Action::Check { pair } => report(&dir, &pair),
        Action::List => {
            if dir.is_dir() {
                for entry in fs::read_dir(&dir)? {
                    let path = entry?.path();
                    if path.extension().and_then(|s| s.to_str()) == Some("json") {
                        if let Ok(e) = serde_json::from_slice::<Enrollment>(&fs::read(&path)?) {
                            println!(
                                "PAIR={} REVISION={} CENTER={}",
                                e.pair, e.revision, e.center
                            );
                        }
                    }
                }
            }
            Ok(())
        }
        Action::InstallService {
            pair,
            chisel,
            system,
        } => install_service(&dir, &pair, &chisel, system),
        Action::Watchdog { pair, check_only } => watchdog_check(&dir, &pair, !check_only).await,
        Action::ProxyCapture { pair } => {
            let mut e = load(&dir, &pair)?;
            let proxy = std::env::var("HTTPS_PROXY")
                .ok()
                .filter(|x| !x.is_empty())
                .or_else(|| std::env::var("https_proxy").ok().filter(|x| !x.is_empty()));
            if let Some(proxy) = proxy {
                e.transport_proxy = Some(proxy);
                save(&dir, &e)?;
                println!("PROXY_CAPTURED={} STORED_LOCALLY=true", pair);
                Ok(())
            } else {
                bail!("HTTPS_PROXY is unset; cannot capture a proxy")
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reject_path_in_pair() {
        assert!(!safe("../foo"));
        assert!(safe("codex-1"));
    }
    #[test]
    fn reject_unencrypted_external_center() {
        assert!(check_url("http://10.0.0.1:1888").is_err());
        assert!(check_url("https://example.com").is_ok());
    }
    #[test]
    fn system_service_has_boot_target_and_no_vm_env() {
        let unit = systemd_unit(
            "muse",
            Path::new("/home/hatch/argus/bin/argus-client"),
            Path::new("/home/hatch/argus/state"),
            "/home/hatch/argus/bin/chisel",
            true,
        );
        assert!(unit.contains("WantedBy=multi-user.target"));
        assert!(
            unit.lines().count() > 10,
            "systemd unit requires actual line breaks"
        );
        assert!(unit.contains("Restart=always"));
        assert!(unit.contains("UMask=0077"));
        assert!(!unit.contains("EnvironmentFile"));
        assert!(unit.contains("--pair muse"));
    }
}
