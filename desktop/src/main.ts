import { app, BrowserWindow, ipcMain, shell } from 'electron'
import { spawn } from 'node:child_process'
import { join } from 'node:path'
import { existsSync } from 'node:fs'

let mainWindow: BrowserWindow | null = null
let coreProc: ReturnType<typeof spawn> | null = null
let coreUrl: string | null = null
let coreToken: string | null = null

function findCore() {
  const candidates = [
    join(process.resourcesPath || '', 'mapip.exe'),
    join(process.cwd(), 'mapip.exe'),
    join(process.cwd(), '../mapip.exe'),
    join(__dirname, 'mapip.exe'),
    join(__dirname, '../mapip.exe'),
  ]
  for (const c of candidates) {
    if (c && existsSync(c)) return c
  }
  return 'mapip'
}

function startCore() {
  const exe = findCore()
  coreProc = spawn(exe, ['serve', '--addr', '127.0.0.1:8765'], {
    detached: false,
  })
  coreProc.stdout?.on('data', (d) => {
    const s = d.toString()
    if (s.includes('listening on http://')) {
      const m = s.match(/http:\/\/127\.0\.0\.1:\d+/)
      if (m) coreUrl = m[0]
    }
    if (s.includes('token:')) {
      const m = s.match(/token:\s*([a-f0-9]+)/)
      if (m) coreToken = m[1]
    }
  })
  coreProc.stderr?.on('data', (e) => {
    console.error('[mapip-core]', e.toString())
  })
  coreProc.on('exit', () => {
    coreProc = null
  })
}

async function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    title: 'MapIp — Network Host Mapper (NOT geolocation)',
    webPreferences: {
      preload: join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
    },
  })

  await mainWindow.loadFile(join(__dirname, 'renderer', 'index.html'))
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url)
    return { action: 'deny' }
  })
}

app.whenReady().then(() => {
  startCore()
  createWindow()
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow()
  })
})

app.on('window-all-closed', () => {
  if (coreProc) {
    coreProc.kill()
  }
  if (process.platform !== 'darwin') app.quit()
})

ipcMain.handle('get-core', () => ({ url: coreUrl, token: coreToken }))
