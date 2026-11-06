//! [`HostApi`] for one plugin's code: what its imports reach in the IDE.
//! Capabilities were checked by the runtime before any of this runs.

use super::{PluginEvent, PluginEventSink};
use ide_core::ipc_path::to_ipc;
use ide_core::{CancellationToken, TextEdit};
use ide_extension::Package;
use ide_language::ProgramPin;
use ide_plugin::{
    EventKind, HostApi, HostError, HttpRequest, HttpResponse, NotificationLevel, ProcessChunk, ProcessCommand,
    ProcessOutput, RepositoryStatus, StatusItem,
};
use parking_lot::{Mutex, RwLock};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command as StdCommand, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Largest storage of one plugin (keys + values).
const MAX_STORAGE: usize = 1 << 20;
const MAX_KEY: usize = 256;
/// Most status bar items per plugin.
const MAX_STATUS_ITEMS: usize = 8;

/// What plugins see of the open projects; provided by the app
/// ([`super::PluginHost::set_workspace`]), over [`crate::Host`] on the desktop.
pub trait PluginWorkspace: Send + Sync {
    /// Roots of the open projects.
    fn projects(&self) -> Vec<PathBuf>;
    /// Unsaved text of the open document at `path`.
    fn buffer_text(&self, path: &Path) -> Option<String>;
    /// Whether the editor holds changes for `path` that are not on disk yet;
    /// writing such a file would lose them.
    fn buffer_dirty(&self, _path: &Path) -> bool {
        false
    }
    /// Up to `limit` files of the project index below `root` whose root-relative path satisfies
    /// `matches`; `None` when no index covers `root` yet (the caller walks the disk instead).
    fn indexed_files(&self, _root: &Path, _matches: &dyn Fn(&Path) -> bool, _limit: usize) -> Option<Vec<PathBuf>> {
        None
    }
    /// Version and text of the open document at `path`.
    fn document(&self, path: &Path) -> Option<(u64, String)>;
    /// Applies `edits` to the open document at `path` if it is still at
    /// `version`, as one change (one undo step in the editor).
    fn apply_edits(&self, path: &Path, version: u64, edits: &[TextEdit]) -> Result<u64, HostError>;
    /// Code from the project may run (git hooks and config on fetch).
    fn trusted(&self, root: &Path) -> bool;
    /// Root of the project open in `window`.
    fn project_of(&self, window: &str) -> Option<PathBuf>;
    /// Shows `items` as producer `source`'s diagnostics of `path` (replacing earlier ones).
    fn publish_diagnostics(&self, source: &str, path: &Path, items: Vec<ide_core::Diagnostic>)
    -> Result<(), HostError>;
    /// The user's values of `plugin`'s settings: the project's at `root`
    /// (over global), or global.
    fn plugin_settings(&self, _plugin: &str, _root: Option<&Path>) -> serde_json::Map<String, serde_json::Value> {
        serde_json::Map::new()
    }
}

/// Where plugin secrets live (the OS keychain on the desktop). Plugins can
/// only ask whether one is set; values go out only inside `net` requests.
pub trait SecretStore: Send + Sync {
    fn get(&self, plugin: &str, name: &str) -> Option<String>;
    /// Sets, or (`None`) deletes.
    fn set(&self, plugin: &str, name: &str, value: Option<&str>) -> Result<(), String>;
}

/// Fallback [`SecretStore`]: one file per plugin, readable only by the user.
pub struct FileSecretStore {
    pub dir: PathBuf,
}

impl FileSecretStore {
    fn file(&self, plugin: &str) -> PathBuf {
        self.dir.join(plugin).join("secrets.json")
    }

    fn load(&self, plugin: &str) -> BTreeMap<String, String> {
        std::fs::read(self.file(plugin)).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
    }
}

impl SecretStore for FileSecretStore {
    fn get(&self, plugin: &str, name: &str) -> Option<String> {
        self.load(plugin).remove(name)
    }

    fn set(&self, plugin: &str, name: &str, value: Option<&str>) -> Result<(), String> {
        let mut map = self.load(plugin);
        match value {
            Some(v) => map.insert(name.to_owned(), v.to_owned()),
            None => map.remove(name),
        };
        let file = self.file(plugin);
        std::fs::create_dir_all(file.parent().expect("has parent")).map_err(|e| e.to_string())?;
        let bytes = serde_json::to_vec(&map).map_err(|e| e.to_string())?;
        let tmp = file.with_extension("tmp");
        std::fs::write(&tmp, bytes).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
        std::fs::rename(&tmp, &file).map_err(|e| e.to_string())
    }
}

/// Largest response body a plugin receives.
const MAX_RESPONSE: usize = 8 << 20;
/// Largest stdout / stderr kept from a process.
const MAX_OUTPUT: usize = 4 << 20;
/// Most processes one plugin keeps running at once.
const MAX_PROCESSES: usize = 8;
/// Most output one stream of a handle holds until the plugin reads it.
const MAX_PENDING: usize = 1 << 20;
/// Most files `find-files` walks before giving up.
const MAX_WALK: usize = 200_000;

/// Runtime for plugin HTTP requests (actor threads block on it).
pub(super) fn net_runtime() -> &'static tokio::runtime::Runtime {
    static RT: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("plugin-net")
            .enable_all()
            .build()
            .expect("plugin network runtime")
    })
}

/// Replaces `{{secret:<name>}}` in `value` with the plugin's secrets.
fn fill_secrets(value: &str, lookup: impl Fn(&str) -> Option<String>) -> Result<String, HostError> {
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(i) = rest.find("{{secret:") {
        out.push_str(&rest[..i]);
        let after = &rest[i + "{{secret:".len()..];
        let end = after.find("}}").ok_or_else(|| HostError::Invalid("unterminated {{secret:…}}".into()))?;
        let name = &after[..end];
        let secret = lookup(name).ok_or_else(|| HostError::NotFound(format!("secret {name:?} is not set")))?;
        out.push_str(&secret);
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    Ok(out)
}

/// A plugin task shown in the UI.
struct TaskEntry {
    plugin: String,
    cancel: CancellationToken,
    cancelled: bool,
}

/// A process a plugin started and has not released (API 1.7 `process.start`).
/// Two reader threads copy its output into bounded buffers; the handle lives
/// as long as the plugin instance that started it.
struct Proc {
    state: Mutex<ProcState>,
}

struct ProcState {
    child: Child,
    stdin: Option<ChildStdin>,
    /// What it printed and the plugin hasn't read yet.
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    /// Its exit status once it ended (a code, or -1 when a signal ended it).
    status: Option<i32>,
    /// Reader threads still copying its pipes into the buffers above.
    readers: usize,
}

/// Which pipe a reader thread drains.
#[derive(Clone, Copy)]
enum Stream {
    Out,
    Err,
}

impl Proc {
    /// Copies `pipe` into the matching buffer until it closes, keeping the last
    /// [`MAX_PENDING`] bytes, then notes that the reader finished.
    fn read(self: &Arc<Self>, mut pipe: impl Read + Send + 'static, stream: Stream) {
        self.state.lock().readers += 1;
        let this = Arc::clone(self);
        std::thread::spawn(move || {
            let mut buf = [0u8; 8 << 10];
            loop {
                match pipe.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        let mut state = this.state.lock();
                        let out = match stream {
                            Stream::Out => &mut state.stdout,
                            Stream::Err => &mut state.stderr,
                        };
                        out.extend_from_slice(&buf[..n]);
                        let over = out.len().saturating_sub(MAX_PENDING);
                        if over > 0 {
                            out.drain(..over);
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            }
            this.state.lock().readers -= 1;
        });
    }

    /// Notes its exit status if it ended (dropping its stdin then).
    fn reap(&self) -> Result<(), HostError> {
        let mut state = self.state.lock();
        if state.status.is_none() {
            match state.child.try_wait() {
                Ok(Some(status)) => {
                    state.status = Some(status.code().unwrap_or(-1));
                    state.stdin = None;
                }
                Ok(None) => {}
                Err(e) => return Err(failed(e)),
            }
        }
        Ok(())
    }

    /// Ends it and reaps it, so its status is known right away; killing twice
    /// does nothing.
    fn kill(&self) {
        let mut state = self.state.lock();
        state.stdin = None;
        if state.status.is_none() {
            let _ = state.child.kill();
            if let Ok(status) = state.child.wait() {
                state.status = Some(status.code().unwrap_or(-1));
            }
        }
    }

    /// What it printed since the last call, each stream at most `max` bytes.
    fn chunk(&self, max: usize) -> ProcessChunk {
        let mut state = self.state.lock();
        ProcessChunk {
            stdout: take_text(&mut state.stdout, max),
            stderr: take_text(&mut state.stderr, max),
            status: state.status,
        }
    }
}

/// Takes up to `max` bytes from the front of `buf` as text without splitting a
/// character: bytes of an incomplete sequence stay queued for the next call.
fn take_text(buf: &mut Vec<u8>, max: usize) -> String {
    if buf.is_empty() {
        return String::new();
    }
    let mut end = max.max(1).min(buf.len());
    if end < buf.len() {
        while end > 0 && (buf[end] & 0xC0) == 0x80 {
            end -= 1;
        }
        if end == 0 {
            // The limit falls inside the first character: hand that one over
            // rather than nothing at all, or the plugin would read forever.
            end = 1;
            while end < buf.len() && (buf[end] & 0xC0) == 0x80 {
                end += 1;
            }
        }
    }
    let head: Vec<u8> = buf.drain(..end).collect();
    String::from_utf8_lossy(&head).into_owned()
}

/// State shared by the host and every plugin's [`PluginApi`].
pub(super) struct Shared {
    pub sink: Arc<dyn PluginEventSink>,
    pub workspace: RwLock<Option<Arc<dyn PluginWorkspace>>>,
    /// `<plugins>/.data`: one directory per plugin id.
    pub data_dir: PathBuf,
    tasks: Mutex<HashMap<u64, TaskEntry>>,
    next_task: AtomicU64,
    /// (plugin, handle id) → the processes it started and hasn't released.
    processes: Mutex<HashMap<(String, u64), Arc<Proc>>>,
    next_process: AtomicU64,
    /// (plugin, item id) → item, for windows opened later.
    status: Mutex<BTreeMap<(String, String), StatusItem>>,
    /// plugin → kinds subscribed at run time (kept across idle reclaim).
    pub subscriptions: Mutex<HashMap<String, BTreeSet<EventKind>>>,
    /// plugin → files it shows problems for, withdrawn when it stops.
    diagnostics: Mutex<HashMap<String, BTreeSet<PathBuf>>>,
    pub secrets: RwLock<Arc<dyn SecretStore>>,
    /// (plugin, `process:` capability) → the approved program.
    pub pins: Arc<RwLock<HashMap<(String, String), ProgramPin>>>,
    /// Validated UI declarations (settings schemas, declared views).
    pub ui: Arc<ide_extension::UiStore>,
}

impl Shared {
    pub fn new(
        sink: Arc<dyn PluginEventSink>,
        data_dir: PathBuf,
        pins: Arc<RwLock<HashMap<(String, String), ProgramPin>>>,
        ui: Arc<ide_extension::UiStore>,
    ) -> Arc<Self> {
        Arc::new(Self {
            ui,
            sink,
            workspace: RwLock::new(None),
            secrets: RwLock::new(Arc::new(FileSecretStore { dir: data_dir.clone() })),
            pins,
            data_dir,
            tasks: Mutex::default(),
            next_task: AtomicU64::new(1),
            processes: Mutex::default(),
            next_process: AtomicU64::new(1),
            status: Mutex::default(),
            subscriptions: Mutex::default(),
            diagnostics: Mutex::default(),
        })
    }

    fn workspace(&self) -> Option<Arc<dyn PluginWorkspace>> {
        self.workspace.read().clone()
    }

    pub fn project_of(&self, window: &str) -> Option<PathBuf> {
        self.workspace()?.project_of(window)
    }

    /// Shows `plugin`'s problems of `path`, remembering the file until they are
    /// cleared (by the plugin, or when it stops).
    fn publish_diagnostics(
        &self,
        plugin: &str,
        path: &Path,
        items: Vec<ide_core::Diagnostic>,
    ) -> Result<(), HostError> {
        let workspace = self.workspace().ok_or_else(|| HostError::NotFound("no project is open".into()))?;
        let empty = items.is_empty();
        workspace.publish_diagnostics(plugin, path, items)?;
        let mut published = self.diagnostics.lock();
        if empty {
            if let Some(paths) = published.get_mut(plugin) {
                paths.remove(path);
                if paths.is_empty() {
                    published.remove(plugin);
                }
            }
        } else {
            published.entry(plugin.to_owned()).or_default().insert(path.to_path_buf());
        }
        Ok(())
    }

    pub fn status_items(&self) -> Vec<(String, String, StatusItem)> {
        self.status.lock().iter().map(|((p, id), item)| (p.clone(), id.clone(), item.clone())).collect()
    }

    /// Withdraws a plugin's run-time state (it stopped or failed). Its
    /// subscriptions go only with `subscriptions`, as they survive restarts.
    pub fn clear_plugin(&self, plugin: &str, subscriptions: bool) {
        self.kill_processes(plugin);
        let removed: Vec<String> = {
            let mut status = self.status.lock();
            let ids: Vec<String> = status.keys().filter(|(p, _)| p == plugin).map(|(_, id)| id.clone()).collect();
            for id in &ids {
                status.remove(&(plugin.to_owned(), id.clone()));
            }
            ids
        };
        for id in removed {
            self.sink.emit(None, PluginEvent::StatusItemChanged { plugin_id: plugin.to_owned(), id, item: None });
        }
        let tasks: Vec<u64> = self.tasks.lock().iter().filter(|(_, t)| t.plugin == plugin).map(|(id, _)| *id).collect();
        for id in tasks {
            self.end_task(id);
        }
        // Its problems go with it (an idle reclaim keeps them: it isn't cleared then).
        let paths = self.diagnostics.lock().remove(plugin).unwrap_or_default();
        if let Some(workspace) = self.workspace() {
            for path in paths {
                let _ = workspace.publish_diagnostics(plugin, &path, Vec::new());
            }
        }
        if subscriptions && self.subscriptions.lock().remove(plugin).is_some() {
            self.sink.emit(None, PluginEvent::SubscriptionsChanged);
        }
    }

    /// Ends every process `plugin` started: its handles go with its instance
    /// (it stopped, was disabled, or was reclaimed while idle).
    pub fn kill_processes(&self, plugin: &str) {
        let mine: Vec<Arc<Proc>> = {
            let mut processes = self.processes.lock();
            let keys: Vec<(String, u64)> = processes.keys().filter(|(p, _)| p == plugin).cloned().collect();
            keys.iter().filter_map(|k| processes.remove(k)).collect()
        };
        for proc in mine {
            proc.kill();
        }
    }

    /// The user cancelled a task in the UI.
    pub fn cancel_task(&self, id: u64) -> bool {
        let mut tasks = self.tasks.lock();
        let Some(t) = tasks.get_mut(&id) else { return false };
        t.cancelled = true;
        t.cancel.cancel();
        true
    }

    fn end_task(&self, id: u64) {
        if let Some(t) = self.tasks.lock().remove(&id) {
            self.sink.emit(None, PluginEvent::TaskEnded { plugin_id: t.plugin, task_id: id.to_string() });
        }
    }

    pub fn storage_file(&self, plugin: &str) -> PathBuf {
        self.data_dir.join(plugin).join("storage.json")
    }
}

pub(super) struct PluginApi {
    pub pkg: Package,
    pub shared: Arc<Shared>,
}

impl PluginApi {
    fn id(&self) -> &str {
        self.pkg.id()
    }

    fn load_storage(&self) -> Result<BTreeMap<String, String>, HostError> {
        match std::fs::read(self.shared.storage_file(self.id())) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| HostError::Failed(format!("storage: {e}"))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
            Err(e) => Err(HostError::Failed(format!("storage: {e}"))),
        }
    }

    fn save_storage(&self, map: &BTreeMap<String, String>) -> Result<(), HostError> {
        let file = self.shared.storage_file(self.id());
        let bytes = serde_json::to_vec(map).map_err(|e| HostError::Failed(e.to_string()))?;
        let io = |e: std::io::Error| HostError::Failed(format!("storage: {e}"));
        std::fs::create_dir_all(file.parent().expect("has parent")).map_err(io)?;
        let tmp = file.with_extension("tmp");
        std::fs::write(&tmp, bytes).and_then(|()| std::fs::rename(&tmp, &file)).map_err(io)
    }

    /// The program approved for the (already checked) `process:` grant,
    /// verified right before it starts.
    fn approved_program(&self, program: &str) -> Result<PathBuf, HostError> {
        let cap = format!("process:{program}");
        // Granted without a pinned file: the program wasn't found when it was
        // allowed, and installing it later approves nothing by itself.
        let pin = self.shared.pins.read().get(&(self.id().to_owned(), cap.clone())).cloned().ok_or_else(|| {
            HostError::Failed(format!(
                "{cap}: `{program}` was not found on PATH when this permission was allowed. \
                 Restarting doesn't approve a program installed later: once `{program}` is on PATH, \
                 clear {cap} in Settings › Plugins and select it again"
            ))
        })?;
        pin.verify().map(Path::to_path_buf).map_err(|e| HostError::Denied(format!("{cap}: {e}")))
    }

    /// Where `cmd` runs: the project root it names, else the plugin's data
    /// directory (created as needed).
    fn spawn_dir(&self, cwd: Option<&Path>) -> PathBuf {
        let dir = cwd.map(Path::to_path_buf).unwrap_or_else(|| self.shared.data_dir.join(self.id()));
        let _ = std::fs::create_dir_all(&dir);
        dir
    }

    /// The process handle `id`, if this plugin started it and it is still open.
    fn process(&self, id: u64) -> Result<Arc<Proc>, HostError> {
        self.shared.processes.lock().get(&(self.id().to_owned(), id)).cloned().ok_or_else(|| {
            HostError::NotFound(format!("no process {id}: it was released, or belongs to another plugin"))
        })
    }
}

fn failed(e: impl std::fmt::Display) -> HostError {
    HostError::Failed(e.to_string())
}

impl HostApi for PluginApi {
    fn notify(&self, client: Option<&str>, level: NotificationLevel, title: String, body: String) {
        self.shared
            .sink
            .emit(client, PluginEvent::Notification { plugin_id: self.id().to_owned(), level, title, body });
    }

    fn copy_to_clipboard(&self, client: Option<&str>, text: String) -> Result<(), HostError> {
        let client = from_window(client, "copy to the clipboard")?;
        self.shared.sink.emit(Some(client), PluginEvent::CopyToClipboard { plugin_id: self.id().to_owned(), text });
        Ok(())
    }

    fn open_url(&self, client: Option<&str>, url: String) -> Result<(), HostError> {
        let client = from_window(client, "open a URL")?;
        self.shared.sink.emit(Some(client), PluginEvent::OpenUrl { plugin_id: self.id().to_owned(), url });
        Ok(())
    }

    fn status_item(&self, id: &str, item: Option<StatusItem>) {
        let key = (self.id().to_owned(), id.to_owned());
        {
            let mut status = self.shared.status.lock();
            match &item {
                Some(item) => {
                    let count = status.keys().filter(|(p, _)| p == self.id()).count();
                    if !status.contains_key(&key) && count >= MAX_STATUS_ITEMS {
                        tracing::warn!(plugin = %self.id(), "more than {MAX_STATUS_ITEMS} status items; {id:?} ignored");
                        return;
                    }
                    if status.get(&key) == Some(item) {
                        return;
                    }
                    status.insert(key, item.clone());
                }
                None => {
                    if status.remove(&key).is_none() {
                        return;
                    }
                }
            }
        }
        self.shared
            .sink
            .emit(None, PluginEvent::StatusItemChanged { plugin_id: self.id().to_owned(), id: id.to_owned(), item });
    }

    fn projects(&self) -> Vec<PathBuf> {
        self.shared.workspace().map(|w| w.projects()).unwrap_or_default()
    }

    fn buffer_text(&self, path: &Path) -> Option<String> {
        self.shared.workspace()?.buffer_text(path)
    }

    fn document(&self, path: &Path) -> Option<(u64, String)> {
        self.shared.workspace()?.document(path)
    }

    fn apply_edits(
        &self,
        _client: Option<&str>,
        path: &Path,
        version: u64,
        edits: Vec<TextEdit>,
    ) -> Result<u64, HostError> {
        let workspace = self.shared.workspace().ok_or_else(|| HostError::NotFound("no project is open".into()))?;
        workspace.apply_edits(path, version, &edits)
    }

    fn storage_get(&self, key: &str) -> Result<Option<String>, HostError> {
        Ok(self.load_storage()?.get(key).cloned())
    }

    fn storage_set(&self, key: &str, value: Option<String>) -> Result<(), HostError> {
        if key.is_empty() || key.len() > MAX_KEY {
            return Err(HostError::Invalid(format!("keys are 1–{MAX_KEY} bytes")));
        }
        let mut map = self.load_storage()?;
        let changed = match value {
            Some(v) => map.insert(key.to_owned(), v.clone()).as_ref() != Some(&v),
            None => map.remove(key).is_some(),
        };
        if !changed {
            return Ok(());
        }
        let size: usize = map.iter().map(|(k, v)| k.len() + v.len()).sum();
        if size > MAX_STORAGE {
            return Err(HostError::Invalid(format!("storage is limited to {} KiB", MAX_STORAGE >> 10)));
        }
        self.save_storage(&map)
    }

    fn storage_keys(&self, prefix: &str) -> Result<Vec<String>, HostError> {
        Ok(self.load_storage()?.into_keys().filter(|k| k.starts_with(prefix)).collect())
    }

    fn vcs_status(&self, root: &Path) -> Result<Option<RepositoryStatus>, HostError> {
        let Some(repo) = ide_vcs::Repo::discover(root).map_err(failed)? else { return Ok(None) };
        let info = repo.branch_info().map_err(failed)?;
        let changed = repo.status().map_err(failed)?.len();
        Ok(Some(RepositoryStatus {
            root: to_ipc(repo.root()),
            branch: info.head,
            commit: info.head_commit,
            upstream: info.upstream,
            ahead: info.ahead,
            behind: info.behind,
            operation: info.operation,
            changed_files: u32::try_from(changed).unwrap_or(u32::MAX),
        }))
    }

    fn vcs_remotes(&self, root: &Path) -> Result<Vec<(String, String)>, HostError> {
        let Some(repo) = ide_vcs::Repo::discover(root).map_err(failed)? else { return Ok(Vec::new()) };
        let remotes = repo.remotes().map_err(failed)?;
        Ok(remotes.into_iter().map(|r| (r.name, without_credentials(&r.url))).collect())
    }

    fn vcs_fetch(&self, root: &Path, cancel: &CancellationToken) -> Result<(), HostError> {
        let workspace = self.shared.workspace();
        if !workspace.is_some_and(|w| w.trusted(root)) {
            return Err(HostError::Failed("the project is in Restricted Mode: git does not run there".into()));
        }
        let Some(repo) = ide_vcs::Repo::discover(root).map_err(failed)? else {
            return Err(HostError::NotFound("the project is not in a git repository".into()));
        };
        match repo.fetch(cancel, &|_| {}) {
            Ok(()) => Ok(()),
            Err(_) if cancel.is_cancelled() => Err(HostError::Cancelled),
            Err(e) => Err(failed(e.message)),
        }
    }

    fn find_files(&self, root: &Path, glob: &str, limit: usize) -> Result<Vec<String>, HostError> {
        let matcher = globset::GlobBuilder::new(glob)
            .literal_separator(true)
            .build()
            .map_err(|e| HostError::Invalid(format!("{glob:?}: {e}")))?
            .compile_matcher();
        // Hidden files and folders are left out, as in the walk below — unless the pattern names
        // one (`.idea/libraries/*.xml`): a project's own metadata lives in a hidden folder, and a
        // plugin that cannot read it cannot see what the project is made of.
        let visible = |rel: &Path| !rel.iter().any(|c| c.to_str().is_some_and(|c| c.starts_with('.')));
        let named = |segment: &&str| segment.starts_with('.');
        let names_hidden = glob.split(['/', '\\']).any(|segment| named(&segment));
        // The project index already lists the files: walking a large tree on every call can take
        // longer than an editor provider's deadline (the plugin is then stopped as crashed). It
        // leaves hidden folders out, so a pattern that names one has to walk the disk.
        if !names_hidden
            && let Some(files) = self
                .shared
                .workspace()
                .and_then(|w| w.indexed_files(root, &|rel| visible(rel) && matcher.is_match(rel), limit))
        {
            let mut out: Vec<String> = files.iter().map(|p| to_ipc(p)).collect();
            out.sort();
            return Ok(out);
        }
        let mut out = Vec::new();
        // A pattern that names a hidden folder is a request for that folder, so the ignore rules
        // that keep a `.idea` out of a walk do not apply to it either.
        let mut walk = ignore::WalkBuilder::new(root);
        walk.hidden(!names_hidden);
        if names_hidden {
            walk.git_ignore(false).git_global(false).git_exclude(false).ignore(false);
        }
        for (n, entry) in walk.build().flatten().enumerate() {
            if n >= MAX_WALK || out.len() >= limit {
                break;
            }
            if !entry.file_type().is_some_and(|t| t.is_file()) {
                continue;
            }
            let Ok(rel) = entry.path().strip_prefix(root) else { continue };
            if matcher.is_match(rel) {
                out.push(to_ipc(entry.path()));
            }
        }
        out.sort();
        Ok(out)
    }

    fn publish_diagnostics(&self, path: &Path, items: Vec<ide_core::Diagnostic>) -> Result<(), HostError> {
        self.shared.publish_diagnostics(self.id(), path, items)
    }

    fn fetch(&self, request: HttpRequest, cancel: &CancellationToken) -> Result<HttpResponse, HostError> {
        let secrets = self.shared.secrets.read().clone();
        let id = self.id().to_owned();
        let mut headers = reqwest::header::HeaderMap::new();
        for (name, value) in &request.headers {
            let value = fill_secrets(value, |n| secrets.get(&id, n))?;
            let name = reqwest::header::HeaderName::from_bytes(name.as_bytes())
                .map_err(|e| HostError::Invalid(format!("header {name:?}: {e}")))?;
            let mut value = reqwest::header::HeaderValue::from_str(&value)
                .map_err(|e| HostError::Invalid(format!("header {name}: {e}")))?;
            value.set_sensitive(true);
            headers.append(name, value);
        }
        let method = reqwest::Method::from_bytes(request.method.to_ascii_uppercase().as_bytes())
            .map_err(|_| HostError::Invalid(format!("method {:?}", request.method)))?;
        let client = ide_http::client::shared().map_err(|e| HostError::Failed(e.message))?;
        // A redirect to another host is refused after the fact (the shared
        // client follows redirects).
        let builder = client.request(method, &request.url).headers(headers).timeout(request.timeout);
        let builder = match request.body {
            Some(body) => builder.body(body),
            None => builder,
        };
        let cancel = cancel.clone();
        let host = ide_plugin::net_host(&request.url).map_err(HostError::Invalid)?;
        net_runtime().block_on(async move {
            let send = async {
                let response = builder.send().await.map_err(|e| HostError::Failed(e.to_string()))?;
                if ide_plugin::net_host(response.url().as_str()).ok().as_deref() != Some(host.as_str()) {
                    return Err(HostError::Denied(format!(
                        "net:{} (redirected)",
                        response.url().host_str().unwrap_or("?")
                    )));
                }
                let status = response.status().as_u16();
                let headers = response
                    .headers()
                    .iter()
                    .map(|(k, v)| (k.as_str().to_owned(), String::from_utf8_lossy(v.as_bytes()).into_owned()))
                    .collect();
                let mut body = Vec::new();
                let mut response = response;
                while let Some(chunk) = response.chunk().await.map_err(|e| HostError::Failed(e.to_string()))? {
                    if body.len() + chunk.len() > MAX_RESPONSE {
                        return Err(HostError::Failed("response larger than 8 MiB".into()));
                    }
                    body.extend_from_slice(&chunk);
                }
                Ok(HttpResponse { status, headers, body })
            };
            tokio::select! {
                r = send => r,
                () = cancel.cancelled() => Err(HostError::Cancelled),
            }
        })
    }

    fn secret_is_set(&self, name: &str) -> bool {
        self.shared.secrets.read().get(self.id(), name).is_some()
    }

    fn run_process(
        &self,
        cmd: ProcessCommand,
        cwd: Option<&Path>,
        stdin: Option<String>,
        cancel: &CancellationToken,
        timeout: Duration,
    ) -> Result<ProcessOutput, HostError> {
        let binary = self.approved_program(&cmd.program)?;
        let cwd = self.spawn_dir(cwd);
        let mut child = StdCommand::new(&binary)
            .args(&cmd.args)
            .envs(cmd.env.iter().map(|(name, value)| (name, value)))
            .current_dir(&cwd)
            .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| HostError::Failed(format!("{}: {e}", binary.display())))?;
        if let (Some(input), Some(mut pipe)) = (stdin, child.stdin.take()) {
            std::thread::spawn(move || {
                use std::io::Write;
                let _ = pipe.write_all(input.as_bytes());
            });
        }
        let read = |pipe: Option<Box<dyn Read + Send>>| {
            std::thread::spawn(move || {
                let mut out = Vec::new();
                if let Some(p) = pipe {
                    let _ = p.take(MAX_OUTPUT as u64).read_to_end(&mut out);
                }
                String::from_utf8_lossy(&out).into_owned()
            })
        };
        let stdout = read(child.stdout.take().map(|p| Box::new(p) as Box<dyn Read + Send>));
        let stderr = read(child.stderr.take().map(|p| Box::new(p) as Box<dyn Read + Send>));
        let deadline = Instant::now() + timeout;
        let status = loop {
            if let Some(status) = child.try_wait().map_err(|e| HostError::Failed(e.to_string()))? {
                break status;
            }
            if cancel.is_cancelled() || Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(if cancel.is_cancelled() {
                    HostError::Cancelled
                } else {
                    HostError::Failed(format!("{} timed out after {timeout:?}", cmd.program))
                });
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        Ok(ProcessOutput {
            status: status.code(),
            stdout: stdout.join().unwrap_or_default(),
            stderr: stderr.join().unwrap_or_default(),
        })
    }

    fn start_process(&self, cmd: ProcessCommand, cwd: Option<&Path>) -> Result<u64, HostError> {
        let binary = self.approved_program(&cmd.program)?;
        let cwd = self.spawn_dir(cwd);
        {
            let processes = self.shared.processes.lock();
            let running = processes.keys().filter(|(plugin, _)| plugin == self.id()).count();
            if running >= MAX_PROCESSES {
                return Err(HostError::Invalid(format!(
                    "at most {MAX_PROCESSES} processes may run at once: release one first"
                )));
            }
        }
        let mut child = StdCommand::new(&binary)
            .args(&cmd.args)
            .envs(cmd.env.iter().map(|(name, value)| (name, value)))
            .current_dir(&cwd)
            // Always piped: `write` may come later, and a plugin that never
            // writes closes it (or loses it when it releases the handle).
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| HostError::Failed(format!("{}: {e}", binary.display())))?;
        let (stdout, stderr) = (child.stdout.take(), child.stderr.take());
        let proc = Arc::new(Proc {
            state: Mutex::new(ProcState {
                stdin: child.stdin.take(),
                child,
                stdout: Vec::new(),
                stderr: Vec::new(),
                status: None,
                readers: 0,
            }),
        });
        if let Some(pipe) = stdout {
            proc.read(pipe, Stream::Out);
        }
        if let Some(pipe) = stderr {
            proc.read(pipe, Stream::Err);
        }
        let id = self.shared.next_process.fetch_add(1, Ordering::Relaxed);
        self.shared.processes.lock().insert((self.id().to_owned(), id), proc);
        Ok(id)
    }

    fn poll_process(&self, id: u64, max: usize) -> Result<ProcessChunk, HostError> {
        let proc = self.process(id)?;
        proc.reap()?;
        Ok(proc.chunk(max))
    }

    fn write_process(&self, id: u64, text: &str) -> Result<(), HostError> {
        let proc = self.process(id)?;
        let mut state = proc.state.lock();
        if state.status.is_some() {
            return Err(HostError::Failed("the process already ended".into()));
        }
        let Some(pipe) = state.stdin.as_mut() else {
            return Err(HostError::Failed("its stdin is closed".into()));
        };
        use std::io::Write;
        pipe.write_all(text.as_bytes())
            .and_then(|()| pipe.flush())
            .map_err(|e| HostError::Failed(format!("stdin: {e}")))
    }

    fn close_process_stdin(&self, id: u64) -> Result<(), HostError> {
        let proc = self.process(id)?;
        proc.state.lock().stdin = None;
        Ok(())
    }

    fn kill_process(&self, id: u64) -> Result<(), HostError> {
        self.process(id)?.kill();
        Ok(())
    }

    fn wait_process(
        &self,
        id: u64,
        max: usize,
        timeout: Duration,
        cancel: &CancellationToken,
    ) -> Result<ProcessChunk, HostError> {
        let proc = self.process(id)?;
        let deadline = Instant::now() + timeout;
        loop {
            proc.reap()?;
            let (ended, readers) = {
                let state = proc.state.lock();
                (state.status.is_some(), state.readers)
            };
            // Its output is only complete once its pipes reached the end too.
            if ended && readers == 0 {
                break;
            }
            if cancel.is_cancelled() {
                return Err(HostError::Cancelled);
            }
            if Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Ok(proc.chunk(max))
    }

    fn release_process(&self, id: u64) -> Result<(), HostError> {
        let proc = self.shared.processes.lock().remove(&(self.id().to_owned(), id));
        let Some(proc) = proc else {
            return Err(HostError::NotFound(format!("no process {id}")));
        };
        // Releasing it while it runs ends it: the plugin can't reach it again.
        proc.kill();
        Ok(())
    }

    fn subscribe(&self, kind: EventKind, on: bool) {
        let changed = {
            let mut subs = self.shared.subscriptions.lock();
            let set = subs.entry(self.id().to_owned()).or_default();
            if on { set.insert(kind) } else { set.remove(&kind) }
        };
        if changed {
            self.shared.sink.emit(None, PluginEvent::SubscriptionsChanged);
        }
    }

    fn task_begin(&self, client: Option<&str>, title: String, cancellable: bool, cancel: CancellationToken) -> u64 {
        let id = self.shared.next_task.fetch_add(1, Ordering::Relaxed);
        self.shared.tasks.lock().insert(id, TaskEntry { plugin: self.id().to_owned(), cancel, cancelled: false });
        self.shared.sink.emit(
            client,
            PluginEvent::TaskStarted { plugin_id: self.id().to_owned(), task_id: id.to_string(), title, cancellable },
        );
        id
    }

    fn task_report(&self, id: u64, done: u32, total: Option<u32>, message: Option<String>) {
        if !self.shared.tasks.lock().contains_key(&id) {
            return;
        }
        self.shared.sink.emit(
            None,
            PluginEvent::TaskProgress {
                plugin_id: self.id().to_owned(),
                task_id: id.to_string(),
                done,
                total,
                message,
            },
        );
    }

    fn task_cancelled(&self, id: u64) -> bool {
        self.shared.tasks.lock().get(&id).is_some_and(|t| t.cancelled)
    }

    fn task_end(&self, id: u64) {
        self.shared.end_task(id);
    }

    fn refresh_view(&self, view: &str) {
        self.shared
            .sink
            .emit(None, PluginEvent::ViewChanged { plugin_id: self.id().to_owned(), view: view.to_owned() });
    }

    fn post_view_message(&self, view: &str, message: String) -> Result<(), HostError> {
        let declared = [super::ui_points::VIEWS, super::ui_points::CUSTOM_EDITORS]
            .iter()
            .any(|point| self.shared.ui.items(point, Some(self.id())).iter().any(|i| i.key == view));
        if !declared {
            return Err(HostError::NotFound(format!("the plugin declares no view {view:?}")));
        }
        let event = PluginEvent::ViewMessage { plugin_id: self.id().to_owned(), view: view.to_owned(), message };
        self.shared.sink.emit(None, event);
        Ok(())
    }

    fn open_terminal(
        &self,
        client: Option<&str>,
        title: String,
        program: &str,
        args: Vec<String>,
        cwd: Option<&Path>,
    ) -> Result<(), HostError> {
        let binary = self.approved_program(program)?;
        let cwd = cwd.map(Path::to_path_buf).unwrap_or_else(|| self.shared.data_dir.join(self.id()));
        let _ = std::fs::create_dir_all(&cwd);
        let event = PluginEvent::OpenTerminal {
            plugin_id: self.id().to_owned(),
            title,
            program: binary.into(),
            args,
            cwd: cwd.into(),
        };
        self.shared.sink.emit(client, event);
        Ok(())
    }

    fn open_location(&self, client: Option<&str>, path: &Path, line: u32, column: u32) -> Result<(), HostError> {
        let event = PluginEvent::OpenLocation {
            plugin_id: self.id().to_owned(),
            path: path.to_path_buf().into(),
            line,
            column,
        };
        self.shared.sink.emit(client, event);
        Ok(())
    }

    fn setting(&self, root: Option<&Path>, key: &str) -> Option<String> {
        let schema: Vec<super::ui_points::SettingSchema> = self
            .shared
            .ui
            .items(super::ui_points::SETTINGS, Some(self.id()))
            .into_iter()
            .find_map(|i| serde_json::from_value(i.decl.get("properties")?.clone()).ok())?;
        let setting = schema.into_iter().find(|s| s.key == key)?;
        let user = self.shared.workspace().map(|w| w.plugin_settings(self.id(), root)).unwrap_or_default();
        let value = user.get(key).filter(|v| setting.accepts(v)).cloned().unwrap_or(setting.default);
        serde_json::to_string(&value).ok()
    }

    fn read_text_file(&self, real: &Path, max: usize) -> Result<String, HostError> {
        // Unsaved editor contents win, as they do for project files.
        if let Some(text) = self.shared.workspace().and_then(|w| w.buffer_text(real)) {
            return Ok(text);
        }
        let meta = std::fs::metadata(real).map_err(|e| not_a_file(real, e))?;
        if !meta.is_file() {
            return Err(HostError::Invalid(format!("{}: not a file", real.display())));
        }
        if meta.len() > max as u64 {
            return Err(too_large(real, max));
        }
        let loaded = ide_vfs::load_text(real).map_err(failed)?;
        if loaded.binary {
            return Err(HostError::Invalid(format!("{}: not text; read it as bytes", real.display())));
        }
        Ok(loaded.text)
    }

    fn read_bytes_file(&self, real: &Path, max: usize) -> Result<Vec<u8>, HostError> {
        use std::io::Read;
        let file = std::fs::File::open(real).map_err(|e| not_a_file(real, e))?;
        let mut bytes = Vec::new();
        // One byte over the limit, so a file that grew after the metadata check
        // is still refused instead of truncated.
        file.take(max as u64 + 1).read_to_end(&mut bytes).map_err(failed)?;
        if bytes.len() > max {
            return Err(too_large(real, max));
        }
        Ok(bytes)
    }

    fn path_kind(&self, real: &Path) -> Result<ide_plugin::PathKind, HostError> {
        let meta =
            std::fs::metadata(real).map_err(|_| HostError::NotFound(format!("{}: no such file", real.display())))?;
        Ok(if meta.is_dir() { ide_plugin::PathKind::Directory } else { ide_plugin::PathKind::File })
    }

    fn list_dir(&self, real: &Path, max: usize) -> Result<Vec<ide_plugin::DirEntryInfo>, HostError> {
        let meta = std::fs::metadata(real).map_err(|e| not_a_file(real, e))?;
        if !meta.is_dir() {
            return Err(HostError::Invalid(format!("{}: not a directory", real.display())));
        }
        let read = std::fs::read_dir(real).map_err(|e| not_a_file(real, e))?;
        let mut entries = Vec::new();
        for entry in read.flatten() {
            if entries.len() == max {
                break;
            }
            let directory = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
            entries
                .push(ide_plugin::DirEntryInfo { name: entry.file_name().to_string_lossy().into_owned(), directory });
        }
        // Sorted, so a plugin's pick of "the first jar" doesn't depend on the disk.
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(entries)
    }

    fn write_text_file(&self, real: &Path, text: &str, max: usize) -> Result<(), HostError> {
        if text.len() > max {
            return Err(too_much_to_write(real, max));
        }
        check_unsaved(self.shared.workspace(), real)?;
        // Write back in the file's own encoding, so a GBK properties file stays
        // one; a file that is not there yet becomes UTF-8.
        let (encoding, has_bom) = match ide_vfs::load_text(real) {
            Ok(loaded) if loaded.binary => {
                return Err(HostError::Invalid(format!("{}: not text; write it as bytes", real.display())));
            }
            Ok(loaded) => (loaded.encoding, loaded.has_bom),
            Err(_) => ("utf-8".to_string(), false),
        };
        ide_vfs::save_text(real, text, &encoding, has_bom).map_err(|e| not_writable(real, e))?;
        Ok(())
    }

    fn write_bytes_file(&self, real: &Path, bytes: &[u8], max: usize) -> Result<(), HostError> {
        if bytes.len() > max {
            return Err(too_much_to_write(real, max));
        }
        check_unsaved(self.shared.workspace(), real)?;
        ide_vfs::write_atomic(real, bytes).map_err(|e| not_writable(real, e))?;
        Ok(())
    }

    fn write_project_file(&self, real: &Path, bytes: &[u8], max: usize) -> Result<(), HostError> {
        if bytes.len() > max {
            return Err(too_much_to_write(real, max));
        }
        // A Run configuration lives in `.openidea/`, which may not exist yet.
        if let Some(parent) = real.parent() {
            std::fs::create_dir_all(parent).map_err(|e| HostError::Failed(format!("{}: {e}", parent.display())))?;
        }
        check_unsaved(self.shared.workspace(), real)?;
        ide_vfs::write_atomic(real, bytes).map_err(|e| not_writable(real, e))?;
        Ok(())
    }
}

/// A file that is not there, or cannot be read, as the plugin sees it.
fn not_a_file(path: &Path, e: std::io::Error) -> HostError {
    match e.kind() {
        std::io::ErrorKind::NotFound => HostError::NotFound(format!("{}: no such file", path.display())),
        std::io::ErrorKind::PermissionDenied => HostError::Denied(format!("{}: {}", path.display(), "not readable")),
        _ => failed(e),
    }
}

fn too_large(path: &Path, max: usize) -> HostError {
    HostError::Invalid(format!("{}: file is larger than {} MiB", path.display(), max >> 20))
}

/// Refuses to replace a file the editor holds unsaved changes for: the write
/// would lose them.
fn check_unsaved(workspace: Option<Arc<dyn PluginWorkspace>>, path: &Path) -> Result<(), HostError> {
    match workspace {
        Some(workspace) if workspace.buffer_dirty(path) => Err(HostError::Invalid(format!(
            "{}: the editor has unsaved changes for it; save them first",
            path.display()
        ))),
        _ => Ok(()),
    }
}

fn too_much_to_write(path: &Path, max: usize) -> HostError {
    HostError::Invalid(format!("{}: more than {} MiB to write", path.display(), max >> 20))
}

/// A write that did not land, as the plugin sees it.
fn not_writable(path: &Path, e: ide_core::error::IdeError) -> HostError {
    let message = format!("{}: {}", path.display(), e.message);
    match e.kind {
        ide_core::error::ErrorKind::NotFound => HostError::NotFound(message),
        ide_core::error::ErrorKind::PermissionDenied => HostError::Denied(message),
        ide_core::error::ErrorKind::InvalidInput => HostError::Invalid(message),
        _ => HostError::Failed(message),
    }
}

/// [`PluginWorkspace`] over the desktop host's open projects.
pub struct HostWorkspace(pub std::sync::Weak<crate::Host>);

impl HostWorkspace {
    fn projects(&self) -> Vec<Arc<crate::project::Project>> {
        self.0.upgrade().map(|h| h.projects()).unwrap_or_default()
    }

    /// The project holding an open document at `path`, and its id.
    fn open_document(&self, path: &Path) -> Option<(Arc<crate::project::Project>, ide_core::DocId)> {
        self.projects().into_iter().find_map(|p| p.documents.by_path(path).map(|doc| (p, doc)))
    }
}

impl PluginWorkspace for HostWorkspace {
    fn projects(&self) -> Vec<PathBuf> {
        let mut roots: Vec<PathBuf> = HostWorkspace::projects(self).iter().map(|p| p.root.clone()).collect();
        roots.sort();
        roots.dedup();
        roots
    }

    fn buffer_text(&self, path: &Path) -> Option<String> {
        HostWorkspace::projects(self).iter().find_map(|p| p.documents.text_of(path))
    }

    fn buffer_dirty(&self, path: &Path) -> bool {
        let Some((project, doc)) = self.open_document(path) else { return false };
        project.documents.is_dirty(doc).unwrap_or(false)
    }

    fn indexed_files(&self, root: &Path, matches: &dyn Fn(&Path) -> bool, limit: usize) -> Option<Vec<PathBuf>> {
        // The index of the project rooted at `root` (a workspace member's files are in its own).
        let project = HostWorkspace::projects(self).into_iter().find(|p| p.root == root)?;
        project.index.files_matching(root, matches, limit)
    }

    fn document(&self, path: &Path) -> Option<(u64, String)> {
        let (project, doc) = self.open_document(path)?;
        let snap = project.documents.snapshot(doc).ok()?;
        Some((u64::from(snap.version), snap.text))
    }

    fn apply_edits(&self, path: &Path, version: u64, edits: &[TextEdit]) -> Result<u64, HostError> {
        let (project, doc) =
            self.open_document(path).ok_or_else(|| HostError::NotFound(format!("{} is not open", path.display())))?;
        let version = u32::try_from(version).map_err(|_| HostError::Stale)?;
        match project.documents.apply_edits_at(doc, version, edits) {
            Ok(Some(v)) => Ok(u64::from(v)),
            Ok(None) => Err(HostError::Stale),
            Err(e) if e.kind == ide_core::error::ErrorKind::InvalidInput => Err(HostError::Invalid(e.message)),
            Err(e) => Err(HostError::Failed(e.message)),
        }
    }

    fn trusted(&self, root: &Path) -> bool {
        HostWorkspace::projects(self).iter().any(|p| p.root == root && p.is_trusted())
    }

    fn project_of(&self, window: &str) -> Option<PathBuf> {
        self.0.upgrade()?.project(window).ok().map(|p| p.root.clone())
    }

    fn publish_diagnostics(
        &self,
        source: &str,
        path: &Path,
        items: Vec<ide_core::Diagnostic>,
    ) -> Result<(), HostError> {
        let projects = HostWorkspace::projects(self);
        let project = projects
            .iter()
            .filter(|p| path.starts_with(&p.root))
            .max_by_key(|p| p.root.as_os_str().len())
            .ok_or_else(|| HostError::Invalid(format!("{} is not in an open project", path.display())))?;
        project.sink.emit(ide_core::IdeEvent::Diagnostics {
            path: path.to_path_buf().into(),
            source: format!("plugin:{source}"),
            items,
        });
        Ok(())
    }

    fn plugin_settings(&self, plugin: &str, root: Option<&Path>) -> serde_json::Map<String, serde_json::Value> {
        let Some(host) = self.0.upgrade() else { return serde_json::Map::new() };
        let settings = match root.and_then(|r| host.projects().into_iter().find(|p| p.root == r)) {
            Some(p) => p.settings.effective(),
            None => host.global_settings.effective(),
        };
        settings.plugins.get(plugin).cloned().unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn api(dir: &Path, pins: Arc<RwLock<HashMap<(String, String), ProgramPin>>>) -> PluginApi {
        let manifest = ide_extension::Manifest::parse(
            "id = \"acme.lint\"\nname = \"Lint\"\nversion = \"1.0.0\"\nengines.openidea = \"^1.0\"\n",
        )
        .unwrap();
        let sink: Arc<dyn PluginEventSink> = Arc::new(|_: Option<&str>, _: PluginEvent| {});
        let shared = Shared::new(sink, dir.join(".data"), pins, ide_extension::UiStore::new());
        PluginApi { pkg: Package::new(manifest, dir.to_path_buf()), shared }
    }

    #[test]
    fn repository_and_search_paths_match_ipc_events() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(std::process::Command::new("git").args(["init", "-q"]).arg(tmp.path()).status().unwrap().success());
        let root = tmp.path().canonicalize().unwrap();
        std::fs::create_dir(root.join("src")).unwrap();
        let file = root.join("src/Example.java");
        std::fs::write(&file, "class Example {}\n").unwrap();
        let api = api(&root, Arc::default());
        assert_eq!(api.find_files(&root, "**/*.java", 8).unwrap(), [to_ipc(&file)]);
        assert_eq!(api.vcs_status(&root).unwrap().unwrap().root, to_ipc(&root));
    }

    /// A project index that lists `files` (root-relative), whatever is on disk.
    struct Indexed(PathBuf, Vec<&'static str>);
    impl PluginWorkspace for Indexed {
        fn projects(&self) -> Vec<PathBuf> {
            vec![self.0.clone()]
        }
        fn buffer_text(&self, _: &Path) -> Option<String> {
            None
        }
        fn document(&self, _: &Path) -> Option<(u64, String)> {
            None
        }
        fn apply_edits(&self, _: &Path, _: u64, _: &[TextEdit]) -> Result<u64, HostError> {
            Err(HostError::Stale)
        }
        fn trusted(&self, _: &Path) -> bool {
            true
        }
        fn project_of(&self, _: &str) -> Option<PathBuf> {
            None
        }
        fn publish_diagnostics(&self, _: &str, _: &Path, _: Vec<ide_core::Diagnostic>) -> Result<(), HostError> {
            Ok(())
        }
        fn indexed_files(&self, root: &Path, matches: &dyn Fn(&Path) -> bool, limit: usize) -> Option<Vec<PathBuf>> {
            (root == self.0).then(|| {
                self.1.iter().map(Path::new).filter(|rel| matches(rel)).take(limit).map(|rel| root.join(rel)).collect()
            })
        }
    }

    #[test]
    fn find_files_uses_the_project_index_when_there_is_one() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        let api = api(&root, Arc::default());
        *api.shared.workspace.write() = Some(Arc::new(Indexed(
            root.clone(),
            vec!["src/b/UserMapper.xml", "src/a/OrderMapper.xml", ".idea/workspace.xml", "pom.xml"],
        )));
        // Listed by the index, not walked: none of these exist on disk.
        assert_eq!(
            api.find_files(&root, "**/*Mapper.xml", 10).unwrap(),
            [to_ipc(&root.join("src/a/OrderMapper.xml")), to_ipc(&root.join("src/b/UserMapper.xml"))]
        );
        assert_eq!(api.find_files(&root, "**/*.xml", 10).unwrap().len(), 3, "hidden folders are left out");
        assert_eq!(api.find_files(&root, "**/*.xml", 1).unwrap().len(), 1);
        // Another root: no index covers it, so the disk is walked.
        let other = root.join("other");
        std::fs::create_dir_all(&other).unwrap();
        std::fs::write(other.join("a.xml"), "").unwrap();
        assert_eq!(api.find_files(&other, "*.xml", 10).unwrap(), [to_ipc(&other.join("a.xml"))]);
    }

    #[test]
    fn find_files_can_name_a_hidden_folder() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        std::fs::create_dir_all(root.join(".idea/libraries")).unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join(".idea/libraries/Module_Public_Library.xml"), "").unwrap();
        std::fs::write(root.join("src/App.java"), "").unwrap();
        let api = api(&root, Arc::default());
        // Not named: hidden folders stay out, as before.
        assert!(api.find_files(&root, "**/*.xml", 10).unwrap().is_empty());
        assert_eq!(
            api.find_files(&root, ".idea/libraries/*.xml", 10).unwrap(),
            [to_ipc(&root.join(".idea/libraries/Module_Public_Library.xml"))]
        );
    }

    #[test]
    fn programs_run_only_as_approved() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("lint");
        std::fs::write(&bin, "#!/bin/sh\n").unwrap();
        let pins: Arc<RwLock<HashMap<(String, String), ProgramPin>>> = Arc::default();
        let api = api(tmp.path(), pins.clone());

        // Allowed while the program was missing: say how to fix it rather than "not granted".
        let err = api.approved_program("lint").unwrap_err().to_string();
        assert!(
            err.contains("was not found on PATH when this permission was allowed")
                && err.contains("clear process:lint in Settings › Plugins and select it again"),
            "{err}"
        );

        pins.write().insert(("acme.lint".into(), "process:lint".into()), ProgramPin::approve(&bin).unwrap());
        assert_eq!(api.approved_program("lint").unwrap(), bin);

        std::fs::write(&bin, "#!/bin/sh\necho replaced\n").unwrap();
        assert!(
            matches!(api.approved_program("lint"), Err(HostError::Denied(e)) if e.contains("changed since it was approved"))
        );
    }

    #[test]
    fn take_text_splits_on_character_boundaries() {
        // 1 + 2 + 3 bytes: 'a', 'é', '€'.
        let mut buf = "aé€".as_bytes().to_vec();
        assert_eq!(take_text(&mut buf, 2), "a", "the limit falls inside 'é', which waits");
        assert_eq!(take_text(&mut buf, 2), "é");
        assert_eq!(take_text(&mut buf, 1), "€", "a limit inside one character hands it over whole");
        assert_eq!(take_text(&mut buf, 10), "");
        assert!(buf.is_empty());
        // A zero limit still moves the front forward: a plugin polling with one
        // must not read the same bytes forever.
        let mut buf = b"abc".to_vec();
        assert_eq!(take_text(&mut buf, 0), "a");
        assert_eq!(take_text(&mut buf, 0), "b");
    }

    /// The `git` on PATH. The process tests need a program that reads stdin and
    /// reports its environment, and every machine running them has git.
    fn git_on_path() -> Option<PathBuf> {
        let name = if cfg!(windows) { "git.exe" } else { "git" };
        std::env::split_paths(&std::env::var_os("PATH")?).map(|dir| dir.join(name)).find(|file| file.is_file())
    }

    /// An api of a plugin allowed to run `git` (pinned, as allowing it would).
    fn api_running(dir: &Path, git: &Path) -> PluginApi {
        let pins: Arc<RwLock<HashMap<(String, String), ProgramPin>>> = Arc::default();
        pins.write().insert(("acme.lint".to_owned(), "process:git".to_owned()), ProgramPin::approve(git).unwrap());
        api(dir, pins)
    }

    fn git_cmd(args: &[&str]) -> ProcessCommand {
        ProcessCommand { program: "git".into(), args: args.iter().map(|a| (*a).to_owned()).collect(), env: Vec::new() }
    }

    #[test]
    fn a_run_passes_its_environment_to_the_program() {
        let Some(git) = git_on_path() else { return };
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        let api = api_running(&root, &git);
        let mut cmd = git_cmd(&["var", "GIT_AUTHOR_IDENT"]);
        cmd.env = vec![
            ("GIT_AUTHOR_NAME".into(), "Openidea Bot".into()),
            ("GIT_AUTHOR_EMAIL".into(), "bot@example.com".into()),
            ("GIT_AUTHOR_DATE".into(), "2005-04-07T22:13:13 +0200".into()),
        ];
        let out = api.run_process(cmd, None, None, &CancellationToken::new(), Duration::from_secs(60)).unwrap();
        assert_eq!(out.status, Some(0), "{}{}", out.stdout, out.stderr);
        // Only the passed variables can name this author: whatever the machine's
        // git config says, it is not "Openidea Bot".
        assert!(out.stdout.starts_with("Openidea Bot <bot@example.com>"), "{}", out.stdout);
    }

    #[test]
    fn a_kept_running_program_streams_reads_and_reports_its_end() {
        let Some(git) = git_on_path() else { return };
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        let api = api_running(&root, &git);
        let id = api.start_process(git_cmd(&["hash-object", "--stdin"]), None).unwrap();

        // It is waiting for stdin: nothing printed yet, no status yet.
        let chunk = api.poll_process(id, 4096).unwrap();
        assert!(chunk.stdout.is_empty() && chunk.stderr.is_empty() && chunk.status.is_none(), "{chunk:?}");

        api.write_process(id, "hello\n").unwrap();
        api.close_process_stdin(id).unwrap();
        let chunk = api.wait_process(id, 4096, Duration::from_secs(60), &CancellationToken::new()).unwrap();
        assert_eq!(chunk.status, Some(0), "{chunk:?}");
        assert_eq!(chunk.stdout.trim().len(), 40, "a sha1 in hex: {}", chunk.stdout);
        assert!(chunk.stdout.trim().chars().all(|c| c.is_ascii_hexdigit()), "{}", chunk.stdout);

        // Writing after it ended reports the problem instead of losing the bytes.
        assert!(api.write_process(id, "more\n").is_err());
        // Releasing takes the handle away for good.
        api.release_process(id).unwrap();
        assert!(matches!(api.poll_process(id, 16), Err(HostError::NotFound(_))));
        assert!(matches!(api.release_process(id), Err(HostError::NotFound(_))));
    }

    #[test]
    fn handles_are_capped_and_killing_frees_them_when_released() {
        let Some(git) = git_on_path() else { return };
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        let api = api_running(&root, &git);
        let mut ids: Vec<u64> = (0..MAX_PROCESSES)
            .map(|_| api.start_process(git_cmd(&["hash-object", "--stdin"]), None).unwrap())
            .collect();
        let err = api.start_process(git_cmd(&["hash-object", "--stdin"]), None).unwrap_err();
        assert!(matches!(&err, HostError::Invalid(m) if m.contains("at most 8 processes")), "{err}");

        // Killing ends it right away, so its status is known rather than pending.
        api.kill_process(ids[0]).unwrap();
        let chunk = api.poll_process(ids[0], 64).unwrap();
        assert!(chunk.status.is_some(), "{chunk:?}");
        // Its slot is free once it is released, not when it dies.
        assert!(api.start_process(git_cmd(&["hash-object", "--stdin"]), None).is_err());
        api.release_process(ids.remove(0)).unwrap();
        ids.push(api.start_process(git_cmd(&["hash-object", "--stdin"]), None).unwrap());

        for id in ids {
            api.release_process(id).unwrap();
        }
    }

    #[test]
    fn stopping_a_plugin_kills_what_it_started() {
        let Some(git) = git_on_path() else { return };
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        let api = api_running(&root, &git);
        let id = api.start_process(git_cmd(&["hash-object", "--stdin"]), None).unwrap();
        api.shared.kill_processes("acme.lint");
        assert!(matches!(api.poll_process(id, 16), Err(HostError::NotFound(_))), "the handle is gone");
        assert!(
            api.start_process(git_cmd(&["hash-object", "--stdin"]), None).is_ok(),
            "nothing is left holding a slot"
        );
        // Another plugin's processes are not touched.
        assert!(api.shared.processes.lock().keys().all(|(plugin, _)| plugin == "acme.lint"));
    }
}

/// The window a user action invoked the plugin from: browser tabs and clipboard writes
/// follow what the user did, never background work (which would reach every window).
fn from_window<'a>(client: Option<&'a str>, what: &str) -> Result<&'a str, HostError> {
    client.ok_or_else(|| HostError::Invalid(format!("can only {what} from a command the user invoked")))
}

/// `url` without the `user:password@` a remote may carry (`https://user:token@host/…`):
/// `vcs.read` must not hand out credentials. scp-style `git@host:path` has no password.
fn without_credentials(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else { return url.to_owned() };
    let authority_end = rest.find('/').unwrap_or(rest.len());
    match rest[..authority_end].rfind('@') {
        Some(at) => format!("{scheme}://{}", &rest[at + 1..]),
        None => url.to_owned(),
    }
}

#[cfg(test)]
mod credential_tests {
    use super::*;

    #[test]
    fn remote_urls_lose_their_credentials() {
        for (url, expected) in [
            ("https://user:ghp_token@github.com/o/r.git", "https://github.com/o/r.git"),
            ("https://token@gitlab.com/o/r", "https://gitlab.com/o/r"),
            ("ssh://git@host:2222/o/r.git", "ssh://host:2222/o/r.git"),
            ("https://github.com/o/r.git", "https://github.com/o/r.git"),
            ("https://github.com/o/r@v1", "https://github.com/o/r@v1"),
            ("git@github.com:o/r.git", "git@github.com:o/r.git"),
            ("/srv/git/r.git", "/srv/git/r.git"),
        ] {
            assert_eq!(without_credentials(url), expected, "{url}");
        }
        assert!(matches!(from_window(None, "open a URL"), Err(HostError::Invalid(_))));
        assert_eq!(from_window(Some("main"), "open a URL").unwrap(), "main");
    }
}
