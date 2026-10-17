import { app, BrowserWindow, ipcMain, shell, dialog } from 'electron'
import { spawn } from 'node:child_process'
import { join } from 'node:path'
import { existsSync } from 'node:fs'

let mainWindow: BrowserWindow | null = null
let coreProc: ReturnType<typeof spawn> | null = null
let coreUrl: string | null = null
let coreToken: string | null = null
let coreReady = false

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

function startCore(): Promise<{ url: string; token: string }> {
  return new Promise((resolve, reject) => {
    const exe = findCore()
    coreProc = spawn(exe, ['serve', '--addr', '127.0.0.1:0'], { detached: false })

    const timeout = setTimeout(() => {
      reject(new Error('core did not start within 15 seconds'))
    }, 15000)

    coreProc.stdout?.on('data', (d) => {
      const s = d.toString()
      const urlMatch = s.match(/listening on (http:\/\/127\.0\.0\.1:\d+)/)
      const tokenMatch = s.match(/token:\s*([a-f0-9]+)/)
      if (urlMatch) coreUrl = urlMatch[1]
      if (tokenMatch) coreToken = tokenMatch[1]
      if (coreUrl && coreToken) {
        clearTimeout(timeout)
        coreReady = true
        resolve({ url: coreUrl, token: coreToken })
      }
    })

    coreProc.stderr?.on('data', (e) => {
      console.error('[mapip-core]', e.toString())
    })

    coreProc.on('exit', (code) => {
      if (!coreReady) {
        clearTimeout(timeout)
        reject(new Error(`core exited early with code ${code}`))
      }
    })

    coreProc.on('error', (err) => {
      clearTimeout(timeout)
      reject(err)
    })
  })
}

async function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 860,
    minWidth: 900,
    minHeight: 600,
    title: 'MapIp — Network Host Mapper (NOT geolocation)',
    backgroundColor: '#0b0f14',
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

app.whenReady().then(async () => {
  try {
    await startCore()
  } catch (err) {
    dialog.showErrorBox(
      'MapIp could not start its scanning engine',
      String(err) + '\n\nMake sure mapip.exe is installed alongside the application.',
    )
    app.quit()
    return
  }
  await createWindow()
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow()
  })
})

app.on('window-all-closed', () => {
  if (coreProc) {
    try {
      coreProc.kill()
    } catch {
    }
  }
  if (process.platform !== 'darwin') app.quit()
})

ipcMain.handle('get-core', () => ({ url: coreUrl, token: coreToken }))
