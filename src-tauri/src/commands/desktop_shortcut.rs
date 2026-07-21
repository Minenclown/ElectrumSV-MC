// commands/desktop_shortcut.rs — Create desktop shortcut (cross-platform)
//
// On first launch, the frontend can call this to offer creating a desktop
// shortcut. OS is auto-detected:
//   Linux:   ~/.local/share/applications/electrumsv-mc.desktop
//   Windows: %USERPROFILE%\Desktop\ElectrumSV-Mc.lnk (via PowerShell)
//   macOS:   not supported (use .app bundle instead)

use serde::Serialize;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize)]
pub struct ShortcutResult {
    pub created: bool,
    pub path: Option<String>,
    pub message: String,
}

fn detect_os() -> &'static str {
    #[cfg(target_os = "linux")]
    { "linux" }
    #[cfg(target_os = "windows")]
    { "windows" }
    #[cfg(target_os = "macos")]
    { "macos" }
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    { "unknown" }
}

fn desktop_dir() -> Option<PathBuf> {
    // 1. Try XDG_DESKTOP_DIR env var
    if let Ok(xdg) = std::env::var("XDG_DESKTOP_DIR") {
        let p = PathBuf::from(&xdg);
        if p.exists() {
            return Some(p);
        }
    }
    // 2. Try reading ~/.config/user-dirs.dirs (localized desktop dir)
    if let Ok(home) = std::env::var("HOME") {
        let user_dirs = PathBuf::from(&home).join(".config/user-dirs.dirs");
        if let Ok(content) = std::fs::read_to_string(&user_dirs) {
            for line in content.lines() {
                if line.starts_with("XDG_DESKTOP_DIR=") {
                    let val = line.trim_start_matches("XDG_DESKTOP_DIR=").trim().trim_matches('"');
                    let expanded = val.replace("$HOME", &home);
                    let p = PathBuf::from(&expanded);
                    if p.exists() {
                        return Some(p);
                    }
                }
            }
        }
        // 3. Fallback: ~/Desktop
        let desktop = PathBuf::from(&home).join("Desktop");
        if desktop.exists() {
            return Some(desktop);
        }
        // 4. Fallback: ~/Schreibtisch (German locale)
        let schreibtisch = PathBuf::from(&home).join("Schreibtisch");
        if schreibtisch.exists() {
            return Some(schreibtisch);
        }
    }
    None
}

fn create_linux_desktop_shortcut(exec_path: &str) -> Result<String, String> {
    // Install to ~/.local/share/applications/ (XDG menu) and symlink on Desktop
    let home = std::env::var("HOME").map_err(|_| "HOME not set")?;
    let apps_dir = PathBuf::from(&home).join(".local/share/applications");
    std::fs::create_dir_all(&apps_dir)
        .map_err(|e| format!("failed to create applications dir: {}", e))?;

    let desktop_file = apps_dir.join("electrumsv-mc.desktop");
    let icon_dir = PathBuf::from(&home).join(".local/share/icons/hicolor/256x256/apps");
    let icon_file = icon_dir.join("electrumsv-mc.png");

    // Install the same branded icon used by the Tauri bundle. This keeps the
    // application menu and desktop shortcut consistent with the favicon/app icon.
    std::fs::create_dir_all(&icon_dir)
        .map_err(|e| format!("failed to create icon dir: {}", e))?;
    std::fs::write(&icon_file, include_bytes!("../../icons/256x256.png"))
        .map_err(|e| format!("failed to install application icon: {}", e))?;

    let icon_path = icon_file.to_string_lossy().to_string();

    let icon_line = if icon_path.is_empty() {
        String::new()
    } else {
        format!("Icon={}\n", icon_path)
    };

    let contents = format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Name=ElectrumSV-Mc\n\
         Comment=Bitcoin SV Wallet\n\
         Exec={exec}\n\
         {icon_line}\
         Terminal=false\n\
         Categories=Finance;Network;\n\
         StartupWMClass=ElectrumSV-Mc\n",
        exec = exec_path,
        icon_line = icon_line,
    );

    std::fs::write(&desktop_file, &contents)
        .map_err(|e| format!("failed to write .desktop file: {}", e))?;

    // Make executable
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&desktop_file)
            .map_err(|e| format!("failed to stat .desktop: {}", e))?
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&desktop_file, perms)
            .map_err(|e| format!("failed to chmod .desktop: {}", e))?;
    }

    // Also place a copy/symlink on the Desktop if it exists
    if let Some(desktop) = desktop_dir() {
        let desktop_link = desktop.join("ElectrumSV-Mc.desktop");
        let _ = std::fs::copy(&desktop_file, &desktop_link);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(
                &desktop_link,
                std::fs::Permissions::from_mode(0o755),
            );
        }
    }

    Ok(desktop_file.to_string_lossy().to_string())
}

fn create_windows_shortcut(exec_path: &str) -> Result<String, String> {
    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOMEPATH"))
        .map_err(|_| "USERPROFILE/HOMEPATH not set")?;
    let desktop = PathBuf::from(&home).join("Desktop");
    if !desktop.exists() {
        return Err("Desktop directory not found".into());
    }

    let lnk_path = desktop.join("ElectrumSV-Mc.lnk");

    // Use PowerShell to create the .lnk shortcut
    let script = format!(
        "$ws = New-Object -ComObject WScript.Shell; \
         $s = $ws.CreateShortcut('{}'); \
         $s.TargetPath = '{}'; \
         $s.Description = 'Bitcoin SV Wallet'; \
         $s.Save()",
        lnk_path.to_string_lossy().replace('\'', "''"),
        exec_path.replace('\'', "''"),
    );

    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", &script])
        .output()
        .map_err(|e| format!("failed to run PowerShell: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "PowerShell failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    Ok(lnk_path.to_string_lossy().to_string())
}

#[tauri::command]
pub fn create_desktop_shortcut() -> Result<ShortcutResult, String> {
    let os = detect_os();

    // Get the current executable path
    let exec_path = std::env::current_exe()
        .map_err(|e| format!("failed to get executable path: {}", e))?
        .to_string_lossy()
        .to_string();

    match os {
        "linux" => match create_linux_desktop_shortcut(&exec_path) {
            Ok(path) => {
                let msg = format!("Desktop shortcut created: {}", path);
                Ok(ShortcutResult { created: true, path: Some(path), message: msg })
            }
            Err(e) => Ok(ShortcutResult { created: false, path: None, message: e }),
        },
        "windows" => match create_windows_shortcut(&exec_path) {
            Ok(path) => {
                let msg = format!("Desktop shortcut created: {}", path);
                Ok(ShortcutResult { created: true, path: Some(path), message: msg })
            }
            Err(e) => Ok(ShortcutResult { created: false, path: None, message: e }),
        },
        "macos" => Ok(ShortcutResult {
            created: false,
            path: None,
            message: "macOS: use the .app bundle instead".into(),
        }),
        _ => Ok(ShortcutResult {
            created: false,
            path: None,
            message: "unsupported OS".into(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_os_returns_known() {
        let os = detect_os();
        assert!(matches!(os, "linux" | "windows" | "macos" | "unknown"));
    }

    #[test]
    fn test_desktop_dir_returns_some_or_none() {
        // Just verify it doesn't panic
        let _ = desktop_dir();
    }
}