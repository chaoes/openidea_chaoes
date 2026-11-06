//! The host side of the `openidea:plugin@1.0.0` world: bindings, resource
//! types and the implementation of every import. Capabilities are checked
//! here; a missing one returns `error::denied` (the plugin can degrade).

use crate::runtime::{StoreData, clip};
use crate::sandbox;
use crate::types::{
    EditorContext, EventKind, HostError, HttpRequest, NotificationLevel, ProcessChunk, ProcessCommand, StatusItem,
    net_host,
};
use ide_core::ipc_path::to_ipc;
use ide_extension::Capability;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use wasmtime::component::Resource;

pub(crate) mod bindings {
    wasmtime::component::bindgen!({
        world: "plugin",
        path: "../../wit",
        imports: { default: trappable },
        with: {
            "openidea:plugin/workspace.project": super::ProjectRes,
            "openidea:plugin/editor.text-editor": super::EditorRes,
            "openidea:plugin/invocation.invocation": super::InvocationRes,
            "openidea:plugin/tasks.task": super::TaskRes,
        },
    });
}

/// The optional `syntax-provider` export, bound on its own when present.
pub(crate) mod syntax_bindings {
    wasmtime::component::bindgen!({
        world: "plugin-syntax",
        path: "../../wit",
        imports: { default: trappable },
        with: {
            "openidea:plugin/types": super::bindings::openidea::plugin::types,
            "openidea:plugin/log": super::bindings::openidea::plugin::log,
            "openidea:plugin/ui": super::bindings::openidea::plugin::ui,
            "openidea:plugin/storage": super::bindings::openidea::plugin::storage,
            "openidea:plugin/workspace": super::bindings::openidea::plugin::workspace,
            "openidea:plugin/editor": super::bindings::openidea::plugin::editor,
            "openidea:plugin/invocation": super::bindings::openidea::plugin::invocation,
            "openidea:plugin/vcs": super::bindings::openidea::plugin::vcs,
            "openidea:plugin/events": super::bindings::openidea::plugin::events,
            "openidea:plugin/tasks": super::bindings::openidea::plugin::tasks,
            "openidea:plugin/diagnostics": super::bindings::openidea::plugin::diagnostics,
            "openidea:plugin/net": super::bindings::openidea::plugin::net,
            "openidea:plugin/secrets": super::bindings::openidea::plugin::secrets,
            "openidea:plugin/process": super::bindings::openidea::plugin::process,
            "openidea:plugin/fs": super::bindings::openidea::plugin::fs,
            "openidea:plugin/views": super::bindings::openidea::plugin::views,
            "openidea:plugin/settings": super::bindings::openidea::plugin::settings,
        },
    });
}

/// The optional `providers` export.
pub(crate) mod providers_bindings {
    wasmtime::component::bindgen!({
        world: "plugin-providers",
        path: "../../wit",
        imports: { default: trappable },
        with: {
            "openidea:plugin/types": super::bindings::openidea::plugin::types,
            "openidea:plugin/log": super::bindings::openidea::plugin::log,
            "openidea:plugin/ui": super::bindings::openidea::plugin::ui,
            "openidea:plugin/storage": super::bindings::openidea::plugin::storage,
            "openidea:plugin/workspace": super::bindings::openidea::plugin::workspace,
            "openidea:plugin/editor": super::bindings::openidea::plugin::editor,
            "openidea:plugin/invocation": super::bindings::openidea::plugin::invocation,
            "openidea:plugin/vcs": super::bindings::openidea::plugin::vcs,
            "openidea:plugin/events": super::bindings::openidea::plugin::events,
            "openidea:plugin/tasks": super::bindings::openidea::plugin::tasks,
            "openidea:plugin/diagnostics": super::bindings::openidea::plugin::diagnostics,
            "openidea:plugin/net": super::bindings::openidea::plugin::net,
            "openidea:plugin/secrets": super::bindings::openidea::plugin::secrets,
            "openidea:plugin/process": super::bindings::openidea::plugin::process,
            "openidea:plugin/fs": super::bindings::openidea::plugin::fs,
            "openidea:plugin/views": super::bindings::openidea::plugin::views,
            "openidea:plugin/settings": super::bindings::openidea::plugin::settings,
        },
    });
}

/// The optional `view-provider` export.
pub(crate) mod views_bindings {
    wasmtime::component::bindgen!({
        world: "plugin-views",
        path: "../../wit",
        imports: { default: trappable },
        with: {
            "openidea:plugin/types": super::bindings::openidea::plugin::types,
            "openidea:plugin/log": super::bindings::openidea::plugin::log,
            "openidea:plugin/ui": super::bindings::openidea::plugin::ui,
            "openidea:plugin/storage": super::bindings::openidea::plugin::storage,
            "openidea:plugin/workspace": super::bindings::openidea::plugin::workspace,
            "openidea:plugin/editor": super::bindings::openidea::plugin::editor,
            "openidea:plugin/invocation": super::bindings::openidea::plugin::invocation,
            "openidea:plugin/vcs": super::bindings::openidea::plugin::vcs,
            "openidea:plugin/events": super::bindings::openidea::plugin::events,
            "openidea:plugin/tasks": super::bindings::openidea::plugin::tasks,
            "openidea:plugin/diagnostics": super::bindings::openidea::plugin::diagnostics,
            "openidea:plugin/net": super::bindings::openidea::plugin::net,
            "openidea:plugin/secrets": super::bindings::openidea::plugin::secrets,
            "openidea:plugin/process": super::bindings::openidea::plugin::process,
            "openidea:plugin/fs": super::bindings::openidea::plugin::fs,
            "openidea:plugin/views": super::bindings::openidea::plugin::views,
            "openidea:plugin/settings": super::bindings::openidea::plugin::settings,
        },
    });
}

use bindings::openidea::plugin::{
    diagnostics, editor, events, fs, invocation, log, net, process, secrets, settings, storage, tasks, types as wit,
    ui, vcs, views, workspace,
};

/// A project handle: its root.
pub struct ProjectRes {
    root: PathBuf,
}

/// The invoking window's focused editor.
pub struct EditorRes {
    ctx: EditorContext,
}

/// The current call's invocation (read from [`StoreData`]).
pub struct InvocationRes;

pub struct TaskRes {
    id: u64,
}

const MAX_EDITS: usize = 10_000;
const MAX_DIAGNOSTICS: usize = 5_000;
const MAX_REQUEST_BODY: usize = 8 << 20;
const MAX_FIND: u32 = 10_000;
const MAX_STATUS_TEXT: usize = 128;
/// Bounds of `process.command`: what a plugin may ask to run.
const MAX_ARGS: usize = 256;
const MAX_ARG_BYTES: usize = 4096;
const MAX_ENV: usize = 64;
const MAX_ENV_NAME: usize = 256;
const MAX_ENV_VALUE: usize = 4096;
/// Most output one `poll` / `wait` hands out, per stream.
const MAX_CHUNK: usize = 1 << 20;
/// Most text one `write` puts into a process's stdin.
const MAX_STDIN_BYTES: usize = 1 << 20;

type Fallible<T> = wasmtime::Result<Result<T, wit::Error>>;

pub(crate) fn to_wit(e: HostError) -> wit::Error {
    match e {
        HostError::Denied(c) => wit::Error::Denied(c),
        HostError::Stale => wit::Error::Stale,
        HostError::NotFound(m) => wit::Error::NotFound(m),
        HostError::Invalid(m) => wit::Error::Invalid(m),
        HostError::Cancelled => wit::Error::Cancelled,
        HostError::Failed(m) => wit::Error::Failed(m),
    }
}

/// A guest's `error` as text (`denied: net:example.com`, `stale`, …).
impl From<wit::Error> for crate::runtime::GuestError {
    fn from(e: wit::Error) -> Self {
        let clip = |m: String| clip(m, crate::runtime::MAX_TITLE * 16);
        match e {
            wit::Error::Denied(c) => Self::Denied(clip(c)),
            wit::Error::Stale => Self::Stale,
            wit::Error::NotFound(m) => Self::NotFound(clip(m)),
            wit::Error::Invalid(m) => Self::Invalid(clip(m)),
            wit::Error::Cancelled => Self::Cancelled,
            wit::Error::Failed(m) => Self::Failed(clip(m)),
        }
    }
}

fn pos(p: wit::Position) -> ide_core::Pos {
    ide_core::Pos::new(p.line, p.character)
}

fn range_to_wit(r: &ide_core::Range) -> wit::Range {
    wit::Range {
        start: wit::Position { line: r.start.line, character: r.start.col },
        end: wit::Position { line: r.end.line, character: r.end.col },
    }
}

impl StoreData {
    fn require(&self, cap: Capability) -> Result<(), wit::Error> {
        if self.granted.iter().any(|g| g.covers(&cap)) { Ok(()) } else { Err(wit::Error::Denied(cap.to_string())) }
    }

    /// `path` as the real path an `fs.read:…` grant covers, or what the plugin
    /// should be told instead (`denied` naming the capability to declare).
    fn granted_file(&self, path: &str) -> Result<PathBuf, wit::Error> {
        sandbox::resolve_granted(&self.granted, path).map_err(Into::into)
    }

    /// The same for `fs.write:…`: a file that does not exist yet is resolved
    /// through the directory it would be created in.
    fn writable_file(&self, path: &str) -> Result<PathBuf, wit::Error> {
        sandbox::resolve_writable(&self.granted, path).map_err(Into::into)
    }

    fn client(&self) -> Option<&str> {
        self.invocation.client.as_deref()
    }

    fn push<T: Send + 'static>(&mut self, value: T) -> wasmtime::Result<Resource<T>> {
        Ok(self.table.push(value)?)
    }

    pub(crate) fn new_invocation(&mut self) -> wasmtime::Result<Resource<InvocationRes>> {
        self.push(InvocationRes)
    }

    pub(crate) fn drop_invocation(&mut self, res: Resource<InvocationRes>) {
        let _ = self.table.delete(res);
    }
}

impl wit::Host for StoreData {}

impl log::Host for StoreData {
    fn log(&mut self, level: wit::LogLevel, message: String) -> wasmtime::Result<()> {
        let id = &self.plugin_id;
        let message = clip(message, crate::runtime::MAX_TEXT);
        match level {
            wit::LogLevel::Trace => tracing::trace!(plugin = %id, "{message}"),
            wit::LogLevel::Debug => tracing::debug!(plugin = %id, "{message}"),
            wit::LogLevel::Info => tracing::info!(plugin = %id, "{message}"),
            wit::LogLevel::Warn => tracing::warn!(plugin = %id, "{message}"),
            wit::LogLevel::Error => tracing::error!(plugin = %id, "{message}"),
        }
        Ok(())
    }
}

impl ui::Host for StoreData {
    fn show_notification(
        &mut self,
        level: wit::NotificationLevel,
        title: String,
        body: String,
    ) -> wasmtime::Result<()> {
        let level = match level {
            wit::NotificationLevel::Info => NotificationLevel::Info,
            wit::NotificationLevel::Warning => NotificationLevel::Warning,
            wit::NotificationLevel::Error => NotificationLevel::Error,
        };
        let max = crate::runtime::MAX_TITLE;
        self.host.notify(self.client(), level, clip(title, max), clip(body, 16 << 10));
        Ok(())
    }

    fn set_status_item(&mut self, id: String, item: ui::StatusItem) -> wasmtime::Result<()> {
        let item = StatusItem {
            text: clip(item.text, MAX_STATUS_TEXT),
            tooltip: item.tooltip.map(|t| clip(t, 1024)),
            command: item.command.map(|c| clip(c, 128)),
        };
        self.host.status_item(&clip(id, 64), Some(item));
        Ok(())
    }

    fn remove_status_item(&mut self, id: String) -> wasmtime::Result<()> {
        self.host.status_item(&clip(id, 64), None);
        Ok(())
    }

    fn copy_to_clipboard(&mut self, text: String) -> Fallible<()> {
        if let Err(e) = self.require(Capability::Clipboard) {
            return Ok(Err(e));
        }
        let client = self.invocation.client.clone();
        Ok(self.host.copy_to_clipboard(client.as_deref(), clip(text, crate::runtime::MAX_TEXT)).map_err(to_wit))
    }

    fn open_url(&mut self, url: String) -> Fallible<()> {
        let trimmed = url.trim();
        let valid = (trimmed.starts_with("https://") || trimmed.starts_with("http://")) && trimmed.len() <= 8192;
        if !valid {
            return Ok(Err(wit::Error::Invalid(format!("{url:?}: expected an http:// or https:// URL"))));
        }
        let client = self.invocation.client.clone();
        Ok(self.host.open_url(client.as_deref(), trimmed.to_owned()).map_err(to_wit))
    }
}

impl storage::Host for StoreData {
    fn get(&mut self, key: String) -> Fallible<Option<String>> {
        if let Err(e) = self.require(Capability::Storage) {
            return Ok(Err(e));
        }
        Ok(self.host.storage_get(&key).map_err(to_wit))
    }

    fn set(&mut self, key: String, value: String) -> Fallible<()> {
        if let Err(e) = self.require(Capability::Storage) {
            return Ok(Err(e));
        }
        Ok(self.host.storage_set(&key, Some(value)).map_err(to_wit))
    }

    fn delete(&mut self, key: String) -> Fallible<()> {
        if let Err(e) = self.require(Capability::Storage) {
            return Ok(Err(e));
        }
        Ok(self.host.storage_set(&key, None).map_err(to_wit))
    }

    fn keys(&mut self, prefix: String) -> Fallible<Vec<String>> {
        if let Err(e) = self.require(Capability::Storage) {
            return Ok(Err(e));
        }
        Ok(self.host.storage_keys(&prefix).map_err(to_wit))
    }
}

impl workspace::Host for StoreData {
    fn projects(&mut self) -> Fallible<Vec<Resource<ProjectRes>>> {
        if let Err(e) = self.require(Capability::ProjectRead) {
            return Ok(Err(e));
        }
        let mut out = Vec::new();
        for root in self.host.projects() {
            out.push(self.push(ProjectRes { root })?);
        }
        Ok(Ok(out))
    }
}

impl workspace::HostProject for StoreData {
    fn root(&mut self, this: Resource<ProjectRes>) -> Fallible<String> {
        if let Err(e) = self.require(Capability::ProjectRead) {
            return Ok(Err(e));
        }
        // Paths reach plugins in IPC form (`/` on Windows), as the UI's event paths do, so they compare as text.
        Ok(Ok(to_ipc(&self.table.get(&this)?.root)))
    }

    fn read_file(&mut self, this: Resource<ProjectRes>, path: String) -> Fallible<String> {
        if let Err(e) = self.require(Capability::ProjectRead) {
            return Ok(Err(e));
        }
        let root = self.table.get(&this)?.root.clone();
        let real = match sandbox::resolve_in_root(&root, &path) {
            Ok(real) => real,
            Err(e) => return Ok(Err(wit::Error::Invalid(e))),
        };
        if let Some(text) = self.host.buffer_text(&real) {
            return Ok(Ok(text));
        }
        Ok(sandbox::read_text(&real).map_err(wit::Error::Failed))
    }

    fn find_files(&mut self, this: Resource<ProjectRes>, glob: String, limit: u32) -> Fallible<Vec<String>> {
        if let Err(e) = self.require(Capability::ProjectRead) {
            return Ok(Err(e));
        }
        let root = self.table.get(&this)?.root.clone();
        Ok(self.host.find_files(&root, &glob, limit.min(MAX_FIND) as usize).map_err(to_wit))
    }

    fn write_file(&mut self, this: Resource<ProjectRes>, path: String, bytes: Vec<u8>) -> Fallible<()> {
        if let Err(e) = self.require(Capability::ProjectWrite) {
            return Ok(Err(e));
        }
        let root = self.table.get(&this)?.root.clone();
        let real = match sandbox::resolve_writable_in_root(&root, &path) {
            Ok(real) => real,
            Err(e) => return Ok(Err(wit::Error::Invalid(e))),
        };
        Ok(self.host.write_project_file(&real, &bytes, sandbox::MAX_WRITE_BYTES).map_err(to_wit))
    }

    fn drop(&mut self, rep: Resource<ProjectRes>) -> wasmtime::Result<()> {
        self.table.delete(rep)?;
        Ok(())
    }
}

impl editor::Host for StoreData {}

impl editor::HostTextEditor for StoreData {
    fn path(&mut self, this: Resource<EditorRes>) -> wasmtime::Result<String> {
        Ok(to_ipc(&self.table.get(&this)?.ctx.path))
    }

    fn language(&mut self, this: Resource<EditorRes>) -> wasmtime::Result<String> {
        Ok(self.table.get(&this)?.ctx.language.clone())
    }

    fn document(&mut self, this: Resource<EditorRes>) -> Fallible<editor::Document> {
        if let Err(e) = self.require(Capability::EditorRead) {
            return Ok(Err(e));
        }
        let path = self.table.get(&this)?.ctx.path.clone();
        Ok(match self.host.document(&path) {
            Some((version, text)) => Ok(editor::Document { version, text }),
            None => Err(wit::Error::NotFound(format!("{} is not open", path.display()))),
        })
    }

    fn selections(&mut self, this: Resource<EditorRes>) -> Fallible<Vec<wit::Range>> {
        if let Err(e) = self.require(Capability::EditorRead) {
            return Ok(Err(e));
        }
        Ok(Ok(self.table.get(&this)?.ctx.selections.iter().map(range_to_wit).collect()))
    }

    fn apply_edits(&mut self, this: Resource<EditorRes>, version: u64, edits: Vec<wit::TextEdit>) -> Fallible<u64> {
        if let Err(e) = self.require(Capability::EditorWrite) {
            return Ok(Err(e));
        }
        if edits.len() > MAX_EDITS {
            return Ok(Err(wit::Error::Invalid(format!("more than {MAX_EDITS} edits"))));
        }
        let total: usize = edits.iter().map(|e| e.text.len()).sum();
        if total > crate::runtime::MAX_TEXT * 8 {
            return Ok(Err(wit::Error::Invalid("edits too large".into())));
        }
        let path = self.table.get(&this)?.ctx.path.clone();
        let edits: Vec<ide_core::TextEdit> = edits
            .into_iter()
            .map(|e| ide_core::TextEdit {
                range: ide_core::Range::new(pos(e.range.start), pos(e.range.end)),
                new_text: e.text,
            })
            .collect();
        let client = self.invocation.client.clone();
        Ok(self.host.apply_edits(client.as_deref(), &path, version, edits).map_err(to_wit))
    }

    fn drop(&mut self, rep: Resource<EditorRes>) -> wasmtime::Result<()> {
        self.table.delete(rep)?;
        Ok(())
    }
}

impl invocation::Host for StoreData {}

impl invocation::HostInvocation for StoreData {
    fn project(&mut self, _this: Resource<InvocationRes>) -> wasmtime::Result<Option<Resource<ProjectRes>>> {
        match self.invocation.workspace_root.clone() {
            Some(root) => Ok(Some(self.push(ProjectRes { root })?)),
            None => Ok(None),
        }
    }

    fn editor(&mut self, _this: Resource<InvocationRes>) -> wasmtime::Result<Option<Resource<EditorRes>>> {
        match self.invocation.editor.clone() {
            Some(ctx) => Ok(Some(self.push(EditorRes { ctx })?)),
            None => Ok(None),
        }
    }

    fn drop(&mut self, rep: Resource<InvocationRes>) -> wasmtime::Result<()> {
        // Owned by the host for the duration of the call.
        let _ = rep;
        Ok(())
    }
}

impl vcs::Host for StoreData {
    fn status(&mut self, project: Resource<ProjectRes>) -> Fallible<Option<vcs::RepositoryStatus>> {
        if let Err(e) = self.require(Capability::VcsRead) {
            return Ok(Err(e));
        }
        let root = self.table.get(&project)?.root.clone();
        Ok(self
            .host
            .vcs_status(&root)
            .map(|s| {
                s.map(|s| vcs::RepositoryStatus {
                    root: s.root,
                    branch: s.branch,
                    commit: s.commit,
                    upstream: s.upstream,
                    ahead: s.ahead,
                    behind: s.behind,
                    operation: s.operation,
                    changed_files: s.changed_files,
                })
            })
            .map_err(to_wit))
    }

    fn fetch(&mut self, project: Resource<ProjectRes>) -> Fallible<()> {
        if let Err(e) = self.require(Capability::VcsWrite) {
            return Ok(Err(e));
        }
        let root = self.table.get(&project)?.root.clone();
        let token = self.cancel.token();
        Ok(self.host.vcs_fetch(&root, &token).map_err(to_wit))
    }

    fn remotes(&mut self, project: Resource<ProjectRes>) -> Fallible<Vec<(String, String)>> {
        if let Err(e) = self.require(Capability::VcsRead) {
            return Ok(Err(e));
        }
        let root = self.table.get(&project)?.root.clone();
        Ok(self.host.vcs_remotes(&root).map_err(to_wit))
    }
}

impl events::Host for StoreData {
    fn subscribe(&mut self, kind: String) -> Fallible<()> {
        let Some(kind) = EventKind::parse(&kind) else {
            return Ok(Err(wit::Error::Invalid(format!("no event kind {kind:?} in this OpenIDEA"))));
        };
        if let Some(cap) = kind.capability()
            && let Err(e) = self.require(cap)
        {
            return Ok(Err(e));
        }
        self.host.subscribe(kind, true);
        Ok(Ok(()))
    }

    fn unsubscribe(&mut self, kind: String) -> wasmtime::Result<()> {
        if let Some(kind) = EventKind::parse(&kind) {
            self.host.subscribe(kind, false);
        }
        Ok(())
    }
}

impl tasks::Host for StoreData {
    fn begin(&mut self, title: String, cancellable: bool) -> wasmtime::Result<Resource<TaskRes>> {
        let token = self.cancel.token();
        let id = self.host.task_begin(self.client(), clip(title, crate::runtime::MAX_TITLE), cancellable, token);
        self.open_tasks.push(id);
        // The call may now run for the background budget.
        let extended = self.call_started + self.limits.background;
        if extended > self.deadline {
            self.deadline = extended;
            self.timeout = self.limits.background;
        }
        self.push(TaskRes { id })
    }
}

impl tasks::HostTask for StoreData {
    fn report(
        &mut self,
        this: Resource<TaskRes>,
        done: u32,
        total: Option<u32>,
        message: Option<String>,
    ) -> wasmtime::Result<()> {
        let id = self.table.get(&this)?.id;
        let now = Instant::now();
        // At most ~10 updates per second reach the UI.
        if self.last_report.is_none_or(|t| now.duration_since(t).as_millis() >= 100) || total.is_some_and(|t| done >= t)
        {
            self.last_report = Some(now);
            self.host.task_report(id, done, total, message.map(|m| clip(m, 256)));
        }
        Ok(())
    }

    fn is_cancelled(&mut self, this: Resource<TaskRes>) -> wasmtime::Result<bool> {
        let id = self.table.get(&this)?.id;
        Ok(self.cancel.token().is_cancelled() || self.host.task_cancelled(id))
    }

    fn drop(&mut self, rep: Resource<TaskRes>) -> wasmtime::Result<()> {
        let id = self.table.delete(rep)?.id;
        self.open_tasks.retain(|t| *t != id);
        self.host.task_end(id);
        Ok(())
    }
}

impl StoreData {
    /// What is left of the running call's wall-clock budget (host operations
    /// can't be interrupted by the epoch callback, so they get this as timeout).
    fn remaining(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }

    /// Checks the `process:` grant and the shape of a [`process::Command`]: what
    /// a plugin asks to run is bounded here, before anything is spawned.
    fn command(
        &self,
        program: String,
        args: Vec<String>,
        env: Vec<(String, String)>,
    ) -> Result<ProcessCommand, wit::Error> {
        self.require(Capability::Process(program.clone()))?;
        if args.len() > MAX_ARGS || args.iter().any(|a| a.len() > MAX_ARG_BYTES) {
            return Err(wit::Error::Invalid(format!("at most {MAX_ARGS} arguments of at most {MAX_ARG_BYTES} bytes")));
        }
        if env.len() > MAX_ENV {
            return Err(wit::Error::Invalid(format!("at most {MAX_ENV} environment variables")));
        }
        for (name, value) in &env {
            if name.is_empty() || name.len() > MAX_ENV_NAME || name.contains(['=', '\0']) {
                return Err(wit::Error::Invalid(format!("{name:?} is not an environment variable name")));
            }
            if value.len() > MAX_ENV_VALUE || value.contains('\0') {
                return Err(wit::Error::Invalid(format!("the value of {name:?} is too long or holds a NUL")));
            }
        }
        Ok(ProcessCommand { program, args, env })
    }
}

impl diagnostics::Host for StoreData {
    fn publish(&mut self, path: String, items: Vec<diagnostics::Diagnostic>) -> Fallible<()> {
        if let Err(e) = self.require(Capability::ProjectRead) {
            return Ok(Err(e));
        }
        let source = self.plugin_id.clone();
        let items = items
            .into_iter()
            .take(MAX_DIAGNOSTICS)
            .map(|d| ide_core::Diagnostic {
                range: ide_core::Range::new(pos(d.range.start), pos(d.range.end)),
                severity: match d.severity {
                    diagnostics::Severity::Error => ide_core::Severity::Error,
                    diagnostics::Severity::Warning => ide_core::Severity::Warning,
                    diagnostics::Severity::Info => ide_core::Severity::Info,
                    diagnostics::Severity::Hint => ide_core::Severity::Hint,
                },
                message: clip(d.message, 4096),
                source: Some(d.source.map_or_else(|| source.clone(), |s| clip(s, 128))),
                code: d.code.map(|c| clip(c, 128)),
                unnecessary: d.tags.iter().any(|t| t == "unnecessary"),
                deprecated: d.tags.iter().any(|t| t == "deprecated"),
                server: Some(source.clone()),
            })
            .collect();
        Ok(self.host.publish_diagnostics(Path::new(&path), items).map_err(to_wit))
    }
}

impl net::Host for StoreData {
    fn fetch(&mut self, req: net::Request) -> Fallible<net::Response> {
        let host = match net_host(&req.url) {
            Ok(h) => h,
            Err(e) => return Ok(Err(wit::Error::Invalid(e))),
        };
        if let Err(e) = self.require(Capability::Net(host)) {
            return Ok(Err(e));
        }
        if req.headers.iter().any(|h| h.value.contains("{{secret:"))
            && let Err(e) = self.require(Capability::Secrets)
        {
            return Ok(Err(e));
        }
        if req.body.as_ref().is_some_and(|b| b.len() > MAX_REQUEST_BODY) {
            return Ok(Err(wit::Error::Invalid("request body larger than 8 MiB".into())));
        }
        let wanted = Duration::from_millis(u64::from(req.timeout_ms.unwrap_or(30_000)));
        let request = HttpRequest {
            method: req.method,
            url: req.url,
            headers: req.headers.into_iter().map(|h| (h.name, h.value)).collect(),
            body: req.body,
            timeout: wanted.min(self.remaining()),
        };
        let token = self.cancel.token();
        Ok(self
            .host
            .fetch(request, &token)
            .map(|r| net::Response {
                status: r.status,
                headers: r.headers.into_iter().map(|(name, value)| net::Header { name, value }).collect(),
                body: r.body,
            })
            .map_err(to_wit))
    }
}

impl secrets::Host for StoreData {
    fn is_set(&mut self, name: String) -> wasmtime::Result<bool> {
        Ok(self.granted.iter().any(|g| g.covers(&Capability::Secrets)) && self.host.secret_is_set(&name))
    }
}

impl process::Host for StoreData {
    fn run(
        &mut self,
        program: String,
        args: Vec<String>,
        cwd: Option<Resource<ProjectRes>>,
        stdin: Option<String>,
    ) -> Fallible<process::Output> {
        if let Err(e) = self.require(Capability::Process(program.clone())) {
            return Ok(Err(e));
        }
        let cmd = ProcessCommand { program, args, env: Vec::new() };
        let cwd = match &cwd {
            Some(p) => Some(self.table.get(p)?.root.clone()),
            None => None,
        };
        let token = self.cancel.token();
        let timeout = self.remaining();
        Ok(self
            .host
            .run_process(cmd, cwd.as_deref(), stdin, &token, timeout)
            .map(|o| process::Output { status: o.status, stdout: o.stdout, stderr: o.stderr })
            .map_err(to_wit))
    }

    fn run_command(
        &mut self,
        cmd: process::Command,
        cwd: Option<Resource<ProjectRes>>,
        stdin: Option<String>,
    ) -> Fallible<process::Output> {
        let cmd = match self.command(cmd.program, cmd.args, cmd.env) {
            Ok(cmd) => cmd,
            Err(e) => return Ok(Err(e)),
        };
        let cwd = match &cwd {
            Some(p) => Some(self.table.get(p)?.root.clone()),
            None => None,
        };
        let token = self.cancel.token();
        let timeout = self.remaining();
        Ok(self
            .host
            .run_process(cmd, cwd.as_deref(), stdin, &token, timeout)
            .map(|o| process::Output { status: o.status, stdout: o.stdout, stderr: o.stderr })
            .map_err(to_wit))
    }

    fn start(&mut self, cmd: process::Command, cwd: Option<Resource<ProjectRes>>) -> Fallible<u64> {
        let cmd = match self.command(cmd.program, cmd.args, cmd.env) {
            Ok(cmd) => cmd,
            Err(e) => return Ok(Err(e)),
        };
        let cwd = match &cwd {
            Some(p) => Some(self.table.get(p)?.root.clone()),
            None => None,
        };
        Ok(self.host.start_process(cmd, cwd.as_deref()).map_err(to_wit))
    }

    fn poll(&mut self, id: u64, max_bytes: u32) -> Fallible<process::Chunk> {
        let max = chunk_bytes(max_bytes);
        Ok(self.host.poll_process(id, max).map(to_chunk).map_err(to_wit))
    }

    fn write(&mut self, id: u64, text: String) -> Fallible<()> {
        if text.len() > MAX_STDIN_BYTES {
            return Ok(Err(wit::Error::Invalid(format!("writes are limited to {MAX_STDIN_BYTES} bytes"))));
        }
        Ok(self.host.write_process(id, &text).map_err(to_wit))
    }

    fn close_stdin(&mut self, id: u64) -> Fallible<()> {
        Ok(self.host.close_process_stdin(id).map_err(to_wit))
    }

    fn kill(&mut self, id: u64) -> Fallible<()> {
        Ok(self.host.kill_process(id).map_err(to_wit))
    }

    fn wait(&mut self, id: u64, timeout_ms: u32) -> Fallible<process::Chunk> {
        let timeout = Duration::from_millis(u64::from(timeout_ms)).min(self.remaining());
        let token = self.cancel.token();
        Ok(self.host.wait_process(id, MAX_CHUNK, timeout, &token).map(to_chunk).map_err(to_wit))
    }

    fn release(&mut self, id: u64) -> Fallible<()> {
        Ok(self.host.release_process(id).map_err(to_wit))
    }
}

/// `max-bytes` of `poll`, bounded: the host never hands out more at once.
fn chunk_bytes(max_bytes: u32) -> usize {
    (max_bytes as usize).min(MAX_CHUNK)
}

fn to_chunk(c: ProcessChunk) -> process::Chunk {
    process::Chunk { stdout: c.stdout, stderr: c.stderr, status: c.status }
}

impl views::Host for StoreData {
    fn refresh(&mut self, view: String) -> wasmtime::Result<()> {
        self.host.refresh_view(&clip(view, 64));
        Ok(())
    }

    fn post_message(&mut self, view: String, message: String) -> Fallible<()> {
        if message.len() > MAX_VIEW_MESSAGE {
            return Ok(Err(wit::Error::Invalid(format!("messages are limited to {MAX_VIEW_MESSAGE} bytes"))));
        }
        Ok(self.host.post_view_message(&clip(view, 64), message).map_err(to_wit))
    }

    fn open_terminal(&mut self, title: String, program: String, args: Vec<String>) -> Fallible<()> {
        if let Err(e) = self.require(Capability::Process(program.clone())) {
            return Ok(Err(e));
        }
        if args.len() > 256 || args.iter().any(|a| a.len() > 4096) {
            return Ok(Err(wit::Error::Invalid("too many or too long arguments".into())));
        }
        let cwd = self.invocation.workspace_root.clone();
        let client = self.invocation.client.clone();
        let title = clip(title, crate::runtime::MAX_TITLE);
        Ok(self.host.open_terminal(client.as_deref(), title, &program, args, cwd.as_deref()).map_err(to_wit))
    }

    fn open_location(&mut self, path: String, line: u32, column: u32) -> Fallible<()> {
        if let Err(e) = self.require(Capability::ProjectRead) {
            return Ok(Err(e));
        }
        let Some(root) = self.invocation.workspace_root.clone() else {
            return Ok(Err(wit::Error::Invalid("no project is open in this window".into())));
        };
        let real = match sandbox::resolve_in_root(&root, &path) {
            Ok(real) => real,
            Err(e) => return Ok(Err(wit::Error::Invalid(e))),
        };
        let client = self.invocation.client.clone();
        Ok(self.host.open_location(client.as_deref(), &real, line, column).map_err(to_wit))
    }
}

impl settings::Host for StoreData {
    fn get(&mut self, key: String) -> wasmtime::Result<Option<String>> {
        let root = self.invocation.workspace_root.clone();
        Ok(self.host.setting(root.as_deref(), &clip(key, 128)))
    }
}

impl views_bindings::openidea::plugin::view_types::Host for StoreData {}

/// A refused `fs` call as the plugin sees it: `denied` carries the capability
/// string, so the plugin can say exactly what its manifest lacks.
impl From<sandbox::Refusal> for wit::Error {
    fn from(refusal: sandbox::Refusal) -> Self {
        match refusal {
            sandbox::Refusal::Denied(cap) => Self::Denied(cap),
            sandbox::Refusal::Invalid(message) => Self::Invalid(message),
        }
    }
}

/// Files outside the windows' projects, gated by `fs.read:<path>` and
/// `fs.write:<path>` grants.
impl fs::Host for StoreData {
    fn read_text(&mut self, path: String) -> Fallible<String> {
        let real = match self.granted_file(&path) {
            Ok(real) => real,
            Err(e) => return Ok(Err(e)),
        };
        let max = sandbox::MAX_READ_BYTES as usize;
        Ok(self.host.read_text_file(&real, max).map_err(to_wit))
    }

    fn read_bytes(&mut self, path: String) -> Fallible<Vec<u8>> {
        let real = match self.granted_file(&path) {
            Ok(real) => real,
            Err(e) => return Ok(Err(e)),
        };
        let max = sandbox::MAX_READ_BYTES as usize;
        Ok(self.host.read_bytes_file(&real, max).map_err(to_wit))
    }

    fn stat(&mut self, path: String) -> Fallible<fs::FileKind> {
        let real = match self.granted_file(&path) {
            Ok(real) => real,
            Err(e) => return Ok(Err(e)),
        };
        Ok(self.host.path_kind(&real).map_err(to_wit).map(|kind| match kind {
            crate::types::PathKind::File => fs::FileKind::File,
            crate::types::PathKind::Directory => fs::FileKind::Directory,
        }))
    }

    fn read_dir(&mut self, path: String) -> Fallible<Vec<fs::DirEntry>> {
        let real = match self.granted_file(&path) {
            Ok(real) => real,
            Err(e) => return Ok(Err(e)),
        };
        Ok(self.host.list_dir(&real, sandbox::MAX_LIST_ENTRIES).map_err(to_wit).map(|entries| {
            entries
                .into_iter()
                .map(|entry| fs::DirEntry {
                    name: entry.name,
                    kind: if entry.directory { fs::FileKind::Directory } else { fs::FileKind::File },
                })
                .collect()
        }))
    }

    fn write_text(&mut self, path: String, text: String) -> Fallible<()> {
        let real = match self.writable_file(&path) {
            Ok(real) => real,
            Err(e) => return Ok(Err(e)),
        };
        let max = sandbox::MAX_WRITE_BYTES;
        Ok(self.host.write_text_file(&real, &text, max).map_err(to_wit))
    }

    fn write_bytes(&mut self, path: String, bytes: Vec<u8>) -> Fallible<()> {
        let real = match self.writable_file(&path) {
            Ok(real) => real,
            Err(e) => return Ok(Err(e)),
        };
        let max = sandbox::MAX_WRITE_BYTES;
        Ok(self.host.write_bytes_file(&real, &bytes, max).map_err(to_wit))
    }
}

/// Largest message between a plugin and its view's frame.
const MAX_VIEW_MESSAGE: usize = 1 << 20;

pub(crate) mod indexing_bindings {
    wasmtime::component::bindgen!({
        world: "indexing", path: "../../wit",
        with: { "openidea:plugin/types": super::bindings::openidea::plugin::types },
    });
}
