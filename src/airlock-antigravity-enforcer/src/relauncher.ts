import * as vscode from "vscode";
import * as http from "http";
import * as os from "os";
import * as fs from "fs";
import * as path from "path";
import { execSync, spawn } from "child_process";

const BASE_CDP_PORT = 9000;
const CDP_FLAG = `--remote-debugging-port=${BASE_CDP_PORT}`;

/**
 * Handles relaunching the IDE with CDP enabled.
 * Adapted from AUTO-ALL's relauncher.js — cross-platform support.
 */
export class Relauncher {
    private readonly _platform = os.platform();

    constructor(private readonly _out: vscode.OutputChannel) { }

    // ── Public API ─────────────────────────────────────────────────

    async isCdpRunning(port: number = BASE_CDP_PORT): Promise<boolean> {
        return new Promise((resolve) => {
            const req = http.get(`http://127.0.0.1:${port}/json`, (res) => {
                resolve(res.statusCode === 200);
            });
            req.on("error", () => resolve(false));
            req.setTimeout(2000, () => { req.destroy(); resolve(false); });
        });
    }

    /**
     * Prompt the user and relaunch with CDP if needed.
     * Returns the user's choice.
     */
    async promptAndRelaunch(): Promise<"relaunched" | "cancelled"> {
        const choice = await vscode.window.showInformationMessage(
            "Airlock: CDP is not available. The IDE needs to be launched with remote debugging enabled for Airlock to detect agent actions. Relaunch now?",
            { modal: false },
            "Relaunch with CDP"
        );

        this._log(`User chose: ${choice ?? "dismissed"}`);

        if (choice === "Relaunch with CDP") {
            const result = await this.relaunchWithCdp();
            return result.success ? "relaunched" : "cancelled";
        }
        return "cancelled";
    }

    async relaunchWithCdp(): Promise<{ success: boolean; message: string }> {
        this._log("Starting relaunch flow...");

        if (await this.isCdpRunning()) {
            return { success: true, message: "CDP already available" };
        }

        const shortcuts = await this._findShortcuts();
        if (shortcuts.length === 0) {
            return { success: false, message: "No IDE shortcuts found." };
        }

        const primary = shortcuts.find(
            (s) => s.type === "startmenu" || s.type === "wrapper" || s.type === "user"
        ) ?? shortcuts[0];

        // Ensure shortcut has CDP flag
        await this._ensureFlag(primary);

        // Relaunch
        const workspaces = vscode.workspace.workspaceFolders?.map((f) => f.uri.fsPath) ?? [];
        return await this._relaunch(primary, workspaces);
    }

    // ── Shortcut discovery ─────────────────────────────────────────

    private async _findShortcuts(): Promise<Shortcut[]> {
        if (this._platform === "win32") { return this._findWindowsShortcuts(); }
        if (this._platform === "darwin") { return this._findMacShortcuts(); }
        return this._findLinuxShortcuts();
    }

    private async _findWindowsShortcuts(): Promise<Shortcut[]> {
        const shortcuts: Shortcut[] = [];
        const ideName = this._getIdeName();
        const paths = [
            path.join(process.env.APPDATA ?? "", "Microsoft", "Windows", "Start Menu", "Programs", ideName, `${ideName}.lnk`),
            path.join(process.env.USERPROFILE ?? "", "Desktop", `${ideName}.lnk`),
        ];
        for (const p of paths) {
            if (fs.existsSync(p)) {
                const info = await this._readWinShortcut(p);
                shortcuts.push({
                    path: p,
                    hasFlag: info.hasFlag,
                    type: p.includes("Start Menu") ? "startmenu" : "desktop",
                    target: info.target,
                    args: info.args,
                });
            }
        }
        return shortcuts;
    }

    private _findMacShortcuts(): Shortcut[] {
        const ideName = this._getIdeName();
        const shortcuts: Shortcut[] = [];
        const wrapper = path.join(os.homedir(), ".local", "bin", `${ideName.toLowerCase()}-cdp`);
        if (fs.existsSync(wrapper)) {
            const content = fs.readFileSync(wrapper, "utf8");
            shortcuts.push({ path: wrapper, hasFlag: content.includes("--remote-debugging-port"), type: "wrapper" });
        }
        const app = `/Applications/${ideName}.app`;
        if (fs.existsSync(app)) {
            shortcuts.push({ path: app, hasFlag: false, type: "app" });
        }
        return shortcuts;
    }

    private _findLinuxShortcuts(): Shortcut[] {
        const ideName = this._getIdeName().toLowerCase();
        const shortcuts: Shortcut[] = [];
        const locations = [
            path.join(os.homedir(), ".local", "share", "applications", `${ideName}.desktop`),
            `/usr/share/applications/${ideName}.desktop`,
        ];
        for (const p of locations) {
            if (fs.existsSync(p)) {
                const content = fs.readFileSync(p, "utf8");
                const execMatch = content.match(/^Exec=(.*)$/m);
                shortcuts.push({
                    path: p,
                    hasFlag: (execMatch?.[1] ?? "").includes("--remote-debugging-port"),
                    type: p.includes(".local") ? "user" : "system",
                    execLine: execMatch?.[1],
                });
            }
        }
        return shortcuts;
    }

    // ── Shortcut modification ──────────────────────────────────────

    private async _ensureFlag(shortcut: Shortcut): Promise<void> {
        if (shortcut.hasFlag) { return; }
        if (this._platform === "win32") {
            await this._modifyWinShortcut(shortcut.path);
        } else if (this._platform === "darwin") {
            await this._createMacWrapper();
        } else {
            this._modifyLinuxDesktop(shortcut.path);
        }
        shortcut.hasFlag = true;
    }

    private async _readWinShortcut(shortcutPath: string): Promise<{ args: string; target: string; hasFlag: boolean }> {
        const scriptPath = path.join(os.tmpdir(), "airlock_read_shortcut.ps1");
        try {
            const ps = `
$ErrorActionPreference = "Stop"
try {
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut('${shortcutPath.replace(/'/g, "''")}')
    Write-Output "ARGS:$($shortcut.Arguments)"
    Write-Output "TARGET:$($shortcut.TargetPath)"
} catch { Write-Output "ERROR:$($_.Exception.Message)" }`;
            fs.writeFileSync(scriptPath, ps, "utf8");
            const result = execSync(`powershell -ExecutionPolicy Bypass -File "${scriptPath}"`, { encoding: "utf8", timeout: 10000 });
            const lines = result.split("\n").map((l) => l.trim());
            const args = (lines.find((l) => l.startsWith("ARGS:")) ?? "ARGS:").substring(5);
            const target = (lines.find((l) => l.startsWith("TARGET:")) ?? "TARGET:").substring(7);
            return { args, target, hasFlag: args.includes("--remote-debugging-port") };
        } catch {
            return { args: "", target: "", hasFlag: false };
        } finally {
            try { fs.unlinkSync(scriptPath); } catch { /* ignore */ }
        }
    }

    private async _modifyWinShortcut(shortcutPath: string): Promise<void> {
        const scriptPath = path.join(os.tmpdir(), "airlock_modify_shortcut.ps1");
        try {
            const ps = `
$ErrorActionPreference = "Stop"
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut('${shortcutPath.replace(/'/g, "''")}')
$shortcut.Arguments = "--remote-debugging-port=${BASE_CDP_PORT} " + $shortcut.Arguments
$shortcut.Save()`;
            fs.writeFileSync(scriptPath, ps, "utf8");
            execSync(`powershell -ExecutionPolicy Bypass -File "${scriptPath}"`, { encoding: "utf8", timeout: 10000 });
            this._log(`Modified shortcut: ${shortcutPath}`);
        } catch (e: unknown) {
            this._log(`Failed to modify shortcut: ${e instanceof Error ? e.message : String(e)}`);
        } finally {
            try { fs.unlinkSync(scriptPath); } catch { /* ignore */ }
        }
    }

    private async _createMacWrapper(): Promise<void> {
        const ideName = this._getIdeName();
        const wrapperDir = path.join(os.homedir(), ".local", "bin");
        const wrapperPath = path.join(wrapperDir, `${ideName.toLowerCase()}-cdp`);
        fs.mkdirSync(wrapperDir, { recursive: true });
        const content = `#!/bin/bash\nopen -a "/Applications/${ideName}.app" --args ${CDP_FLAG} "$@"\n`;
        fs.writeFileSync(wrapperPath, content, { mode: 0o755 });
        this._log(`Created macOS wrapper: ${wrapperPath}`);
    }

    private _modifyLinuxDesktop(desktopPath: string): void {
        let content = fs.readFileSync(desktopPath, "utf8");
        if (!content.includes("--remote-debugging-port")) {
            content = content.replace(/^(Exec=)(.*)$/m, `$1$2 ${CDP_FLAG}`);
            const target = desktopPath.includes(".local")
                ? desktopPath
                : path.join(os.homedir(), ".local", "share", "applications", path.basename(desktopPath));
            fs.mkdirSync(path.dirname(target), { recursive: true });
            fs.writeFileSync(target, content);
            this._log(`Modified .desktop: ${target}`);
        }
    }

    // ── Relaunch ───────────────────────────────────────────────────

    private async _relaunch(shortcut: Shortcut, workspaces: string[]): Promise<{ success: boolean; message: string }> {
        const folderArgs = workspaces.map((f) => `"${f}"`).join(" ");
        try {
            if (this._platform === "win32") {
                const target = shortcut.target ?? "";
                const cmd = target
                    ? `start "" "${target}" ${CDP_FLAG} ${folderArgs}`
                    : `start "" "${shortcut.path}" ${folderArgs}`;
                const batch = `@echo off\ntimeout /t 5 /nobreak >nul\n${cmd}\ndel "%~f0" & exit\n`;
                const batchPath = path.join(os.tmpdir(), `airlock_relaunch_${Date.now()}.bat`);
                fs.writeFileSync(batchPath, batch, "utf8");
                const child = spawn("explorer.exe", [batchPath], { detached: true, stdio: "ignore", windowsHide: true });
                child.unref();
            } else if (this._platform === "darwin") {
                const cmd = shortcut.type === "wrapper"
                    ? `"${shortcut.path}" ${folderArgs}`
                    : `open -a "${shortcut.path}" --args ${CDP_FLAG} ${folderArgs}`;
                const script = `#!/bin/bash\nsleep 2\n${cmd}\n`;
                const scriptPath = path.join(os.tmpdir(), "airlock_relaunch.sh");
                fs.writeFileSync(scriptPath, script, { mode: 0o755 });
                const child = spawn("/bin/bash", [scriptPath], { detached: true, stdio: "ignore" });
                child.unref();
            } else {
                const cmd = shortcut.execLine
                    ? `${shortcut.execLine.replace(/%[fFuUdDnNickvm]/g, "").trim()} ${folderArgs}`
                    : `${this._getIdeName().toLowerCase()} ${CDP_FLAG} ${folderArgs}`;
                const script = `#!/bin/bash\nsleep 2\n${cmd}\n`;
                const scriptPath = path.join(os.tmpdir(), "airlock_relaunch.sh");
                fs.writeFileSync(scriptPath, script, { mode: 0o755 });
                const child = spawn("/bin/bash", [scriptPath], { detached: true, stdio: "ignore" });
                child.unref();
            }

            // Quit current instance after a delay
            setTimeout(() => {
                void vscode.commands.executeCommand("workbench.action.quit");
            }, 1500);

            return { success: true, message: "Relaunching with CDP..." };
        } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { success: false, message: msg };
        }
    }

    private _getIdeName(): string {
        const appName = vscode.env.appName ?? "";
        if (appName.toLowerCase().includes("cursor")) return "Cursor";
        if (appName.toLowerCase().includes("antigravity")) return "Antigravity";
        return "Code";
    }

    private _log(msg: string): void {
        this._out.appendLine(`[Airlock Relauncher] ${msg}`);
    }
}

interface Shortcut {
    path: string;
    hasFlag: boolean;
    type: string;
    target?: string;
    args?: string;
    execLine?: string;
}

export { BASE_CDP_PORT };
