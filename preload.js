const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("reconsuite", {
    saveWebDiscoveryPdf: (filename) =>
        ipcRenderer.invoke("save-web-discovery-pdf", filename)
});

