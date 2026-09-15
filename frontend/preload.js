const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("aegis", {
  getBackendUrl: () => ipcRenderer.invoke("get-backend-url"),
  saveReport: (defaultName, sourcePath) =>
    ipcRenderer.invoke("save-report", { defaultName, sourcePath }),
  openPath: (targetPath) => ipcRenderer.invoke("open-path", targetPath),
  openExternal: (url) => ipcRenderer.invoke("open-external", url),
  logError: (message, stack) => ipcRenderer.invoke("log-renderer-error", { message, stack }),
  // GitHub "Connect account" OAuth
  connectGithub: () => ipcRenderer.invoke("connect-github"),
  onGithubOauthCallback: (callback) => {
    ipcRenderer.on("github-oauth-callback", (_event, data) => callback(data));
  },
  saveGithubToken: (tokenData) => ipcRenderer.invoke("github-token-save", tokenData),
  loadGithubToken: () => ipcRenderer.invoke("github-token-load"),
  clearGithubToken: () => ipcRenderer.invoke("github-token-clear"),
});
