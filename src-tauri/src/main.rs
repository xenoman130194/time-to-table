// Copyright (C) 2026  Галимзянов Г.Р.
//
// This file is part of time-to-table
// SPDX-License-Identifier: GPL-3.0-or-later

// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    time_sap_lib::run()
}
