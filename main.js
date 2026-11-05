const { app, BrowserWindow, dialog, shell, screen, ipcMain } = require("electron");
const path = require("path");
const { spawn } = require("child_process");
const http = require("http");

let backend = null;
let mainWindow = null;
let backendLog = "";
ipcMain.handle("save-web-discovery-pdf", async (event, filename) => {
    try {
        const win = BrowserWindow.fromWebContents(event.sender);

        if (!win) {
            throw new Error("Application window not found.");
        }

        const safeName = String(filename || "WebDiscovery")
            .replace(/[^a-zA-Z0-9._-]/g, "_")
            .replace(/_+/g, "_");

        const { canceled, filePath } = await dialog.showSaveDialog(win, {
            title: "Save Web Discovery PDF",
            defaultPath: path.join(
                app.getPath("downloads"),
                safeName.endsWith(".pdf") ? safeName : safeName + ".pdf"
            ),
            filters: [
                { name: "PDF Documents", extensions: ["pdf"] }
            ]
        });

        if (canceled || !filePath) {
            return { success: false, canceled: true };
        }

        const pdfBuffer = await win.webContents.printToPDF({
            printBackground: true,
            preferCSSPageSize: true
        });

        await require("fs").promises.writeFile(filePath, pdfBuffer);

        return {
            success: true,
            filePath: filePath
        };

    } catch (error) {
        console.error("PDF export error:", error);

        return {
            success: false,
            error: error.message
        };
    }
});

function pythonCommand() {
  const fs = require("fs");

  if (app.isPackaged) {
    const backendPath = path.join(process.resourcesPath, "backend", "app.py");
    if (!fs.existsSync(backendPath)) {
      throw new Error("Packaged Python backend is missing: " + backendPath);
    }
    return { cmd: "python3", args: [backendPath] };
  }

  const devVenv = path.join(__dirname, ".venv", "bin", "python");
  return {
    cmd: fs.existsSync(devVenv) ? devVenv : "python3",
    args: [path.join(__dirname, "backend", "app.py")]
  };
}

function waitForBackend(timeoutMs = 12000) {
  return new Promise((resolve, reject) => {
    const start = Date.now();
    const attempt = () => {
      const req = http.get("http://127.0.0.1:8765/api/health", res => {
        res.resume();
        if (res.statusCode === 200) return resolve();
        retry();
      });
      req.on("error", retry);
      req.setTimeout(800, () => req.destroy());

      function retry() {
        if (Date.now() - start > timeoutMs) {
          return reject(new Error("Python backend did not start.\n" + backendLog));
        }
        setTimeout(attempt, 250);
      }
    };
    attempt();
  });
}

function startBackend() {
  const py = pythonCommand();
  const childEnv = {
    ...process.env,
    PYTHONUNBUFFERED: "1",
    RECONSUITE_REPORTS: path.join(app.getPath("documents"), "ReconSuite", "recon-reports")
  };

  if (app.isPackaged) {
    childEnv.RECONSUITE_ENV_FILE = path.join(
      app.getPath("home"), ".config", "reconsuite-lite", ".env"
    );
  } else {
    delete childEnv.RECONSUITE_ENV_FILE;
  }

  backend = spawn(py.cmd, py.args, {
    cwd: app.isPackaged ? process.resourcesPath : __dirname,
    env: childEnv,
    stdio: ["ignore", "pipe", "pipe"]
  });

  backend.stdout.on("data", d => {
    backendLog += d.toString();
    if (backendLog.length > 12000) backendLog = backendLog.slice(-12000);
  });
  backend.stderr.on("data", d => {
    backendLog += d.toString();
    if (backendLog.length > 12000) backendLog = backendLog.slice(-12000);
  });
  backend.on("exit", code => {
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send("backend-exit", code);
    }
  });
}

/*
 * Electron-only dashboard sizing. This CSS is injected into the Electron
 * renderer after the page loads; browser frontend files remain untouched.
 */
async function applyElectronWorkspaceLayout(win) {
  const css = `
    :root { color-scheme: dark; }

    html, body {
      width: 100% !important;
      height: 100% !important;
      min-height: 0 !important;
      overflow: hidden !important;
    }

    body { margin: 0 !important; }

    .app-shell {
      width: 100% !important;
      height: 100vh !important;
      min-height: 0 !important;
      max-height: 100vh !important;
      overflow: hidden !important;
      display: flex !important;
      flex-direction: column !important;
    }

    .topbar {
      flex: 0 0 82px !important;
      height: 82px !important;
      min-height: 82px !important;
      padding-top: 8px !important;
      padding-bottom: 8px !important;
    }

    .layout {
      flex: 1 1 auto !important;
      height: 0 !important;
      min-height: 0 !important;
      overflow: hidden !important;
      display: grid !important;
      grid-template-columns: 190px minmax(0, 1fr) 245px !important;
      align-items: stretch !important;
      gap: 9px !important;
      padding: 8px !important;
    }

    .sidebar, .main-content, .rightbar {
      min-width: 0 !important;
      min-height: 0 !important;
      height: 100% !important;
      overflow: hidden !important;
    }

    .sidebar {
      display: flex !important;
      flex-direction: column !important;
    }

    .nav-list { flex: 0 0 auto !important; }

    /* Sidebar: show only the latest scan history entry */
    .history-list {
        flex: 0 0 auto !important;
        max-height: 64px !important;
        overflow: hidden !important;
        overscroll-behavior: none !important;
    }

    /* Hide all history entries except the first (newest) */
    #historyList > :nth-child(n + 2) {
        display: none !important;
    }

    /* Completely remove the history scrollbar */
    .history-list::-webkit-scrollbar,
    #historyList::-webkit-scrollbar {
        display: none !important;
        width: 0 !important;
        height: 0 !important;
    }

    /* Show only the three most recent scan-history rows in the sidebar. */
    #historyList > :nth-child(n + 4) {
      display: none !important;
    }

    .side-foot {
      margin-top: auto !important;
      flex: 0 0 auto !important;
    }

    .main-content {
      display: flex !important;
      flex-direction: column !important;
      overflow: hidden !important;
    }

    .target-card, .tool-grid, .metric-grid {
      flex: 0 0 auto !important;
    }

    .results-card {
      flex: 1 1 auto !important;
      min-height: 0 !important;
      overflow: hidden !important;
      display: flex !important;
      flex-direction: column !important;
    }

    #resultsPanel {
      flex: 1 1 auto !important;
      min-height: 0 !important;
      overflow: hidden !important;
      display: flex !important;
      flex-direction: column !important;
    }

    .table-wrap {
      flex: 1 1 auto !important;
      min-height: 0 !important;
      max-height: none !important;
      overflow: auto !important;
      overscroll-behavior: contain !important;
    }

    .rightbar {
      display: flex !important;
      flex-direction: column !important;
      gap: 9px !important;
    }

    .progress-card {
      flex: 0 0 auto !important;
    }

    .activity-card {
      flex: 1 1 auto !important;
      min-height: 0 !important;
      overflow: hidden !important;
      display: flex !important;
      flex-direction: column !important;
    }

    .activity-card .right-heading {
      flex: 0 0 auto !important;
    }

    #rightLog, .right-log {
      flex: 1 1 auto !important;
      min-height: 0 !important;
      max-height: none !important;
      overflow-y: auto !important;
      overflow-x: hidden !important;
      overscroll-behavior: contain !important;
      scrollbar-gutter: stable !important;
    }

    .quick-card { display: none !important; }

    /* Compact laptop spacing while retaining the browser dashboard's design. */
    .target-card { padding-top: 10px !important; padding-bottom: 8px !important; }
    .tool-card { min-height: 92px !important; }
    .metric-card { min-height: 66px !important; }

    @media (max-width: 1100px) {
      .layout {
        grid-template-columns: 165px minmax(0, 1fr) 220px !important;
        gap: 7px !important;
        padding: 6px !important;
      }
      .brand { min-width: 190px !important; }
      .topbar { gap: 10px !important; }
      .top-context strong { font-size: 14px !important; }
      .top-context span { white-space: normal !important; }
    }
  `;

  await win.webContents.insertCSS(css);
}

async function createWindow() {
  const { width: workWidth, height: workHeight } = screen.getPrimaryDisplay().workAreaSize;

  mainWindow = new BrowserWindow({
    width: Math.min(1640, workWidth),
    height: Math.min(1000, workHeight),
    minWidth: Math.min(900, workWidth),
    minHeight: Math.min(600, workHeight),
    show: false,
    autoHideMenuBar: true,
    backgroundColor: "#09111a",
    title: "ReconSuite Lite",
    webPreferences: {
        preload: path.join(__dirname, "preload.js"),
        contextIsolation: true,
        nodeIntegration: false,
        sandbox: true
    }
  });

  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith("http://127.0.0.1:8765/")) {
      return { action: "allow" };
    }
    if (url.startsWith("https://")) shell.openExternal(url);
    return { action: "deny" };
  });

  await mainWindow.loadURL("http://127.0.0.1:8765/");
  await applyElectronWorkspaceLayout(mainWindow);
  mainWindow.maximize();
  mainWindow.show();

  mainWindow.on("closed", () => {
    mainWindow = null;
  });
}

app.whenReady().then(async () => {
  startBackend();
  try {
    await waitForBackend();
    await createWindow();
  } catch (err) {
    dialog.showErrorBox("ReconSuite backend error", String(err.message || err));
    app.quit();
  }

  app.on("activate", async () => {
    if (BrowserWindow.getAllWindows().length === 0) await createWindow();
  });
});

app.on("before-quit", () => {
  if (backend && !backend.killed) backend.kill("SIGTERM");
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});
