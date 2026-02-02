// Copyright (C) 2026  Галимзянов Г.Р.
//
// This file is part of time-to-table
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/


use std::path::PathBuf;

/// Проверяет что путь находится в разрешённой директории
fn is_path_allowed(path: &PathBuf) -> bool {
    let allowed_dirs: Vec<PathBuf> = [
        dirs::download_dir(),
        dirs::document_dir(),
        dirs::desktop_dir(),
    ]
    .into_iter()
    .flatten()
    .collect();

    // Канонизируем путь для защиты от ../ атак
    let canonical = match path.canonicalize() {
        Ok(p) => p,
        Err(_) => {
            // Если файл ещё не существует, проверяем родительскую директорию
            if let Some(parent) = path.parent() {
                match parent.canonicalize() {
                    Ok(p) => p,
                    Err(_) => return false,
                }
            } else {
                return false;
            }
        }
    };

    allowed_dirs.iter().any(|dir| {
        if let Ok(canonical_dir) = dir.canonicalize() {
            canonical.starts_with(&canonical_dir)
        } else {
            false
        }
    })
}

/// Безопасная запись файла с проверкой пути
#[tauri::command]
fn save_file_secure(path: String, content: String) -> Result<String, String> {
    let path_buf = PathBuf::from(&path);
    
    if !is_path_allowed(&path_buf) {
        return Err("Сохранение разрешено только в папки: Загрузки, Документы или Рабочий стол".into());
    }
    
    std::fs::write(&path_buf, &content)
        .map_err(|e| format!("Ошибка записи: {}", e))?;
    
    Ok(path)
}

/// Безопасное чтение файла с проверкой пути
#[tauri::command]
fn read_file_secure(path: String) -> Result<String, String> {
    let path_buf = PathBuf::from(&path);
    
    if !is_path_allowed(&path_buf) {
        return Err("Чтение разрешено только из папок: Загрузки, Документы или Рабочий стол".into());
    }
    
    std::fs::read_to_string(&path_buf)
        .map_err(|e| format!("Ошибка чтения: {}", e))
}

/// Возвращает список разрешённых директорий
#[tauri::command]
fn get_allowed_dirs() -> Vec<String> {
    [
        dirs::download_dir(),
        dirs::document_dir(), 
        dirs::desktop_dir(),
    ]
    .into_iter()
    .flatten()
    .map(|p| p.to_string_lossy().to_string())
    .collect()
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .invoke_handler(tauri::generate_handler![
            save_file_secure,
            read_file_secure,
            get_allowed_dirs
        ])
        .setup(|_app| {
            // DevTools только в debug режиме
            #[cfg(debug_assertions)]
            {
                
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
