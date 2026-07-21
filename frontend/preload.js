const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("aegis", {
  getBackendUrl: () => ipcRenderer.invoke("get-backend-url"),
  saveReport: (defaultName, sourcePath) =>
    ipcRenderer.invoke("save-report", { defaultName, sourcePath }),
  openPath: (targetPath) => ipcRenderer.invoke("open-path", targetPath),
  openExternal: (url) => ipcRenderer.invoke("open-external", url),
  logError: (message, stack) => ipcRenderer.invoke("log-renderer-error", { message, stack }),
});
