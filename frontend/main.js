/**
 * AegisLab - Electron main process
 * ===================================
 * Responsibilities:
 *   1. Spawn the Python (FastAPI/uvicorn) security engine as a child process
 *      on app startup, and kill it cleanly on quit.
 *   2. Open the dashboard window pointing at index.html.
 *   3. Provide a couple of native conveniences (save-file dialog for reports,
 *      opening the generated PDF/JSON in the OS default app) via IPC.
 */

const { app, BrowserWindow, ipcMain, dialog, shell } = require("electron");
const path = require("path");
const { spawn } = require("child_process");
const fs = require("fs");
const http = require("http");
const { autoUpdater } = require("electron-updater");

const BACKEND_PORT = 8765;
// In dev, backend/ is a sibling of frontend/ on real disk. In a packaged
// build, frontend/ ends up inside app.asar (a read-only archive) but
// backend/ is shipped separately via "extraResources" (see package.json)
// into process.resourcesPath/backend, so it stays a normal, spawnable
// directory of .py files instead of being trapped in the archive.
const BACKEND_DIR = app.isPackaged
  ? path.join(process.resourcesPath, "backend")
  : path.join(__dirname, "..", "backend");

let mainWindow;
let backendProcess;

function candidatePythonCommands() {
  // Build an ordered list of candidates and let the first one that actually
  // exists on disk (or resolves on PATH) win. This means AegisLab no longer
  // hard-fails just because the user launched it without activating conda
  // first, as long as SOME usable Python interpreter is findable.
  const candidates = [];

  if (process.env.AEGISLAB_PYTHON) candidates.push(process.env.AEGISLAB_PYTHON);

  // A project-local virtualenv, if one was created (e.g. python -m venv .venv)
  const venvPython = process.platform === "win32"
    ? path.join(BACKEND_DIR, "..", ".venv", "Scripts", "python.exe")
    : path.join(BACKEND_DIR, "..", ".venv", "bin", "python3");
  candidates.push(venvPython);

  // A conda env named 'aegislab', resolved without requiring activation
  const condaBase = process.env.CONDA_ROOT || process.env.CONDA_PREFIX_BASE;
  if (condaBase) {
    candidates.push(
      process.platform === "win32"
        ? path.join(condaBase, "envs", "aegislab", "python.exe")
        : path.join(condaBase, "envs", "aegislab", "bin", "python3")
    );
  }

  // Whatever is already active / on PATH (covers an already-activated conda env)
  candidates.push(process.platform === "win32" ? "python" : "python3");
  candidates.push("python");
  if (process.platform === "win32") candidates.push("py");

  // De-dupe while preserving order
  return [...new Set(candidates.filter(Boolean))];
}

function pathLooksUsable(cmd) {
  // Absolute/relative paths: only usable if the file is actually there.
  // Bare command names (no path separators) are left to PATH resolution.
  if (cmd.includes(path.sep) || cmd.includes("/")) {
    return fs.existsSync(cmd);
  }
  return true;
}

// Polls http://127.0.0.1:BACKEND_PORT/api/health until it responds or times
// out. This is the ONLY thing that counts as "backend started" — process
// output is not trustworthy on its own (a Python traceback also prints to
// stderr, and uvicorn's normal startup banner also prints to stderr, so the
// old code treated a crash and a success identically).
function waitForBackendHealth(timeoutMs = 12000, intervalMs = 300) {
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolve) => {
    const tick = () => {
      const req = http.get({ host: "127.0.0.1", port: BACKEND_PORT, path: "/api/health", timeout: 1500 }, (res) => {
        res.resume();
        if (res.statusCode === 200) return resolve(true);
        if (Date.now() > deadline) return resolve(false);
        setTimeout(tick, intervalMs);
      });
      req.on("error", () => {
        if (Date.now() > deadline) return resolve(false);
        setTimeout(tick, intervalMs);
      });
      req.on("timeout", () => req.destroy());
    };
    tick();
  });
}

function startBackend(attempt = 0, candidates = null) {
  const list = candidates || candidatePythonCommands().filter(pathLooksUsable);
  const triedLog = [];

  if (attempt >= list.length) {
    dialog.showErrorBox(
      "AegisLab — Backend Failed to Start",
      `Could not start the security engine with any available Python interpreter.\n\n` +
      `Tried:\n${triedLog.length ? triedLog.join("\n") : (list.map((c) => "  • " + c).join("\n") || "  (no candidates found)")}\n\n` +
      `Fix options:\n` +
      `  1. Run scripts/start_app.sh (macOS/Linux) or scripts/start_app.bat (Windows) from a\n` +
      `     terminal first — these set up a local Python environment and install dependencies\n` +
      `     automatically, and print the exact error if something goes wrong.\n` +
      `  2. Or set AEGISLAB_PYTHON to the full path of a Python 3.11+ executable that has\n` +
      `     backend/requirements.txt installed, then relaunch.\n\n` +
      `A detailed log was written to: ${backendLogPath()}`
    );
    return;
  }

  const pythonCmd = list[attempt];
  const logStream = fs.createWriteStream(backendLogPath(), { flags: "a" });
  logStream.write(`\n--- launch attempt with "${pythonCmd}" at ${new Date().toISOString()} ---\n`);

  let proc;
  try {
    proc = spawn(
      pythonCmd,
      ["-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", String(BACKEND_PORT)],
      { cwd: BACKEND_DIR, env: process.env }
    );
  } catch (err) {
    logStream.write(`spawn() threw synchronously: ${err.message}\n`);
    startBackend(attempt + 1, list);
    return;
  }

  backendProcess = proc;
  let settled = false;
  let stderrTail = "";

  proc.stdout.on("data", (data) => logStream.write(data));
  proc.stderr.on("data", (data) => {
    logStream.write(data);
    stderrTail = (stderrTail + data.toString()).slice(-2000);
  });
  proc.on("error", (err) => {
    // e.g. ENOENT: this interpreter path doesn't actually exist / isn't executable
    logStream.write(`process error: ${err.message}\n`);
    if (!settled) {
      settled = true;
      startBackend(attempt + 1, list);
    }
  });
  proc.on("close", (code) => {
    logStream.write(`process exited with code ${code}\n`);
    if (!settled && code !== 0) {
      // Crashed before we could confirm health (missing deps, import error,
      // port already in use, etc). Move on to the next candidate.
      settled = true;
      startBackend(attempt + 1, list);
    }
  });

  waitForBackendHealth().then((healthy) => {
    if (settled) return; // already handled by a process error/close above
    settled = true;
    if (healthy) {
      console.log(`[backend] confirmed healthy on interpreter: ${pythonCmd}`);
    } else {
      logStream.write(`health check timed out. Last stderr:\n${stderrTail}\n`);
      try { proc.kill(); } catch (_) {}
      startBackend(attempt + 1, list);
    }
  });
}

function backendLogPath() {
  return path.join(app.getPath("userData"), "backend.log");
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1440,
    height: 900,
    minWidth: 1100,
    minHeight: 700,
    backgroundColor: "#0b1320",
    title: "AegisLab",
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  mainWindow.loadFile(path.join(__dirname, "index.html"));
}

// ---------------------------------------------------------------------------
// Crash / error logging (Sprint 5 Day 7) — the Electron-side half of this.
// backend/main.py handles Python-side unhandled exceptions with its own
// rotating log; this covers the two things that can go wrong in the
// Electron shell itself: the main process crashing, and the renderer
// (the actual UI window) crashing or hitting an uncaught JS error.
// ---------------------------------------------------------------------------
function appLogPath() {
  return path.join(app.getPath("userData"), "app_crash.log");
}

function logAppEvent(label, detail) {
  try {
    fs.appendFileSync(appLogPath(), `\n[${new Date().toISOString()}] ${label}\n${detail}\n`);
  } catch (_) {
    // If we can't even write the log, there's nothing more useful to do here.
  }
}

process.on("uncaughtException", (err) => {
  logAppEvent("main-process uncaughtException", err.stack || String(err));
});
process.on("unhandledRejection", (reason) => {
  logAppEvent("main-process unhandledRejection", reason && reason.stack ? reason.stack : String(reason));
});

app.whenReady().then(() => {
  startBackend();
  createWindow();
  checkForUpdates();

  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });

  // Renderer process actually crashed (not just a JS error — an OOM, GPU
  // crash, etc). Log it and offer to reload rather than leaving a dead window.
  app.on("render-process-gone", (_event, webContents, details) => {
    logAppEvent("render-process-gone", JSON.stringify(details));
    dialog
      .showMessageBox(mainWindow, {
        type: "error",
        title: "AegisLab — Window Crashed",
        message: `The AegisLab window stopped responding (reason: ${details.reason}).`,
        detail: `A log was written to: ${appLogPath()}`,
        buttons: ["Reload", "Close"],
      })
      .then(({ response }) => {
        if (response === 0) mainWindow.reload();
        else app.quit();
      });
  });
});

// Renderer-side (index.html/renderer.js) uncaught errors get forwarded here
// via preload.js's logError, so they end up in the same log file instead of
// silently vanishing into DevTools console output nobody's looking at.
ipcMain.handle("log-renderer-error", async (_event, { message, stack }) => {
  logAppEvent("renderer uncaught error", `${message}\n${stack || ""}`);
  return true;
});

// ---------------------------------------------------------------------------
// Auto-update (Sprint 6 Day 3) — checks GitHub Releases (see package.json's
// "publish" config) for a newer version, downloads it silently in the
// background, and prompts once it's actually ready to install. Only runs in
// a packaged build: in dev there's no update feed to check against, and
// electron-updater logs a (harmless but noisy) error if it tries.
// ---------------------------------------------------------------------------
function checkForUpdates() {
  if (!app.isPackaged) return;

  autoUpdater.autoDownload = true;
  autoUpdater.on("error", (err) => logAppEvent("autoUpdater error", err.stack || String(err)));
  autoUpdater.on("update-available", (info) => logAppEvent("update-available", info.version));
  autoUpdater.on("update-downloaded", (info) => {
    logAppEvent("update-downloaded", info.version);
    dialog
      .showMessageBox(mainWindow, {
        type: "info",
        title: "AegisLab — Update Ready",
        message: `AegisLab ${info.version} has been downloaded.`,
        detail: "Restart now to install it, or it'll install automatically the next time you quit.",
        buttons: ["Restart Now", "Later"],
      })
      .then(({ response }) => {
        if (response === 0) autoUpdater.quitAndInstall();
      });
  });

  autoUpdater.checkForUpdates().catch((err) => {
    // No network, no GitHub releases published yet, etc — not fatal, just
    // means the user keeps running their current version.
    logAppEvent("checkForUpdates failed", err.stack || String(err));
  });
}

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});

app.on("before-quit", () => {
  if (backendProcess) {
    backendProcess.kill();
  }
});

// ---- IPC: native save dialog + "open report" ----
ipcMain.handle("save-report", async (_event, { defaultName, sourcePath }) => {
  const { canceled, filePath } = await dialog.showSaveDialog(mainWindow, {
    defaultPath: defaultName,
  });
  if (canceled || !filePath) return { saved: false };
  fs.copyFileSync(sourcePath, filePath);
  return { saved: true, path: filePath };
});

ipcMain.handle("open-path", async (_event, targetPath) => {
  shell.openPath(targetPath);
  return true;
});

ipcMain.handle("get-backend-url", async () => `http://127.0.0.1:${BACKEND_PORT}`);

// ---- IPC: open a billing URL (Stripe Checkout / customer portal) in the
// system browser. Deliberately allow-listed to Stripe's own domains plus
// our own localhost backend (for the success/cancel landing pages) so this
// can't be repurposed into an arbitrary "open any URL" primitive. ----
const ALLOWED_EXTERNAL_HOSTS = [/(^|\.)stripe\.com$/i, /(^|\.)github\.com$/i, /^127\.0\.0\.1$/, /^localhost$/i];
ipcMain.handle("open-external", async (_event, url) => {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return { opened: false, reason: "invalid URL" };
  }
  if (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && parsed.hostname === "127.0.0.1")) {
    return { opened: false, reason: "disallowed protocol" };
  }
  if (!ALLOWED_EXTERNAL_HOSTS.some((re) => re.test(parsed.hostname))) {
    return { opened: false, reason: "disallowed host" };
  }
  await shell.openExternal(url);
  return { opened: true };
});
