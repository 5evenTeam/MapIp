import { contextBridge, ipcRenderer } from 'electron'

contextBridge.exposeInMainWorld('api', {
  getCore: () => ipcRenderer.invoke('get-core'),
})
