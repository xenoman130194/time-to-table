// This file is part of time-to-table //
// SPDX-License-Identifier: GPL-3.0-or-later //

"use strict";

// === TAURI API ===
let tauriDialog = null;
let tauriFs = null;
let tauriInvoke = null;

// Инициализация Tauri API после загрузки
async function initTauriApi() {
    if (globalThis.__TAURI__) {
        try {
            // В Tauri v2 модули доступны через __TAURI__
            tauriDialog = globalThis.__TAURI__.dialog;
            tauriFs = globalThis.__TAURI__.fs;
            tauriInvoke = globalThis.__TAURI__.core.invoke;
            // Avoid logging runtime capabilities to reduce potential sensitive output
            console.debug?.('Tauri API available');
        } catch (e) {
            console.error('Tauri API init error:', e);
        }
    } else {
        // Intentionally do not log environment details in production
    }
}

// Безопасная запись файла через Rust команду
async function saveFileSecure(path, content) {
    if (tauriInvoke) {
        return await tauriInvoke('save_file_secure', { path, content });
    }
    throw new Error('Tauri not available');
}

// Безопасное чтение файла через Rust команду
async function readFileSecure(path) {
    if (tauriInvoke) {
        return await tauriInvoke('read_file_secure', { path });
    }
    throw new Error('Tauri not available');
}

// Вызываем при загрузке с задержкой для гарантии загрузки Tauri
globalThis.addEventListener('DOMContentLoaded', () => {
    setTimeout(initTauriApi, 100);
    try {
        // Генерируем CSRF токен для интерактивных форм (локально)
        const token = generateCsrfToken();
        const meta = document.getElementById('csrfMeta');
        if (meta) meta.setAttribute('content', token);
    } catch (e) {
        console.debug?.('DOMContentLoaded CSRF set failed:', e?.message);
    }
});

// === ФУНКЦИИ БЕЗОПАСНОСТИ ===
function sanitizeInput(str, maxLength = 500) {
    if (typeof str !== 'string') return '';
    return str.substring(0, maxLength).trim();
}

// Returns a hex string of `bytes` random bytes using crypto.getRandomValues when available.
// Falls back to crypto.randomUUID() (without dashes) or a timestamp+counter hex string —
// critically: does NOT use Math.random().
function secureRandomHex(bytes = 8) {
    try {
        if (globalThis.crypto?.getRandomValues) {
            const arr = new Uint8Array(bytes);
            globalThis.crypto.getRandomValues(arr);
            return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
        }
        if (globalThis.crypto?.randomUUID) {
            return globalThis.crypto.randomUUID().replaceAll('-', '');
        }
    } catch (e) {
        console.debug?.('secureRandomHex crypto error:', e?.message);
    }
    // Last-resort fallback: timestamp + performance + counter (predictable but no Math.random)
    secureRandomHex._counter = (secureRandomHex._counter || 0) + 1;
    const nowHex = Date.now().toString(16);
    const perfHex = performance?.now ? Math.floor(performance.now()).toString(16) : '0';
    return nowHex + perfHex + secureRandomHex._counter.toString(16);
}

// Асинхронная локальная блокировка для операций с localStorage, чтобы уменьшить гонки
// Использует неблокирующий backoff, избегая busy-wait.
async function acquireStorageLock(lockKey = 'z7_lock', ttl = 3000) {
    const id = secureRandomHex(8);
    const deadline = Date.now() + ttl;
    let attempt = 0;
    while (Date.now() < deadline) {
        try {
            const cur = localStorage.getItem(lockKey);
            if (!cur) {
                localStorage.setItem(lockKey, JSON.stringify({ id, ts: Date.now() }));
                const stored = JSON.parse(localStorage.getItem(lockKey) || '{}');
                if (stored.id === id) return id;
            } else {
                const parsed = JSON.parse(cur);
                if (Date.now() - (parsed.ts || 0) > ttl) {
                    // stale lock, try to take it
                    localStorage.setItem(lockKey, JSON.stringify({ id, ts: Date.now() }));
                    const stored = JSON.parse(localStorage.getItem(lockKey) || '{}');
                    if (stored.id === id) return id;
                }
            }
        } catch (e) {
            console.debug?.('acquireStorageLock attempt error:', e?.message);
        }
        // non-blocking sleep with small exponential backoff
        await new Promise(resolve => setTimeout(resolve, 20 + Math.min(200, attempt * 10)));
        attempt++;
    }
    return null;
}

function releaseStorageLock(lockKey = 'z7_lock', id) {
    try {
        const cur = localStorage.getItem(lockKey);
        if (!cur) return;
        const parsed = JSON.parse(cur);
        if (parsed.id === id) localStorage.removeItem(lockKey);
    } catch (e) {
        console.debug?.('releaseStorageLock error:', e?.message);
    }
}

async function safeLocalStorageSet(key, value) {
    const id = await acquireStorageLock();
    try {
        localStorage.setItem(key, value);
    } catch (e) {
        console.error('localStorage set error:', e);
    } finally {
        if (id) releaseStorageLock('z7_lock', id);
    }
}

async function safeLocalStorageRemove(key) {
    const id = await acquireStorageLock();
    try {
        localStorage.removeItem(key);
    } catch (e) {
        console.error('localStorage remove error:', e);
    } finally {
        if (id) releaseStorageLock('z7_lock', id);
    }
}

function generateCsrfToken() {
    try {
        const arr = new Uint8Array(32);
        if (globalThis.crypto?.getRandomValues) {
            globalThis.crypto.getRandomValues(arr);
            return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
        }
    } catch (e) {
        console.debug?.('generateCsrfToken crypto failed:', e?.message);
    }
    // Fallback to secureRandomHex (never uses Math.random)
    return secureRandomHex(16) + Date.now().toString(36);
}

// Защита от Excel-инъекций: если текст начинается с символов формулы,
// добавляем ведущую апостроф-кавычку, чтобы Excel воспринимал это как текст.
function excelSanitizeCell(str) {
    if (typeof str !== 'string') return '';
    if (str.length === 0) return '';
    const first = str[0];
    if (['=', '+', '-', '@'].includes(first)) return "'" + str;
    return str;
}

function validateNumber(value, min, max) {
    const num = Number.parseInt(value, 10);
    if (Number.isNaN(num)) return min;
    return Math.max(min, Math.min(max, num));
}

function validateCardData(steps) {
    if (!Array.isArray(steps)) return false;
    return steps.every(s => 
        typeof s.name === 'string' && s.name.length <= 500 &&
        !Number.isNaN(Number.parseFloat(s.dur)) &&
        typeof s.unit === 'string' && ['min', 'hour'].includes(s.unit) &&
        typeof s.hasBreak === 'boolean' &&
        !Number.isNaN(Number.parseFloat(s.breakVal)) &&
        typeof s.breakUnit === 'string' && ['min', 'hour'].includes(s.breakUnit)
    );
}

// Безопасный парсинг JSON с защитой от prototype pollution
function safeJsonParse(jsonString) {
    try {
        const parsed = JSON.parse(jsonString);
        return sanitizeObject(parsed);
    } catch (e) {
        console.error('JSON parse error:', e);
        return null;
    }
}

// Очистка объекта от опасных свойств (prototype pollution protection)
function sanitizeObject(obj) {
    if (obj === null || typeof obj !== 'object') {
        return obj;
    }
    
    if (Array.isArray(obj)) {
        return obj.map(sanitizeObject);
    }
    
    const clean = {};
    for (const key of Object.keys(obj)) {
        // Блокируем prototype pollution атаки
        if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
            console.warn('Blocked potentially dangerous key:', key);
            continue;
        }
        clean[key] = sanitizeObject(obj[key]);
    }
    return clean;
}

function validateImportData(obj) {
    if (typeof obj !== 'object' || obj === null) return false;
    return Object.entries(obj).every(([key, value]) => {
        if (!key.startsWith('z7_card_')) return false;
        // Дополнительная проверка на опасные ключи
        if (key.includes('__proto__') || key.includes('constructor')) return false;
        try {
            const parsed = JSON.parse(value);
            return validateCardData(parsed);
        } catch (e) {
            return false;
        }
    });
}

function formatDurationToTime(val, unit) {
    let sec = 0;
    if (unit === 'min') sec = val * 60;
    else if (unit === 'hour') sec = val * 3600;
    else sec = val;
    
    const h = Math.floor(sec / 3600);
    const m = Math.floor((sec % 3600) / 60);
    const s = Math.floor(sec % 60);
    
    return [h, m, s].map(v => String(v).padStart(2, '0')).join(':');
}

// === ИНИЦИАЛИЗАЦИЯ ===
const startDateInput = document.getElementById('startDate');
// Устанавливаем текущую локальную дату (без проблем с UTC)
const today = new Date();
const yyyy = today.getFullYear();
const mm = String(today.getMonth() + 1).padStart(2, '0');
const dd = String(today.getDate()).padStart(2, '0');
startDateInput.value = `${yyyy}-${mm}-${dd}`;

const startTimeInput = document.getElementById('startTime');
const container = document.getElementById('fieldsContainer');

// Синхронизация единиц времени: все операции используют единицу первой операции
function syncTimeUnits() {
    const firstUnitSelect = container.querySelector('.op-block:first-child .op-unit');
    if (!firstUnitSelect) return;
    
    const selectedUnit = firstUnitSelect.value;
    const allUnitSelects = container.querySelectorAll('.op-block .op-unit');
    
    allUnitSelects.forEach((select, idx) => {
        if (idx > 0) { // Пропускаем первую операцию
            select.value = selectedUnit;
        }
    });
}

function createEl(tag, props = {}, text = '') {
    const el = document.createElement(tag);
    for (const [key, value] of Object.entries(props)) {
        if (key.startsWith('on')) continue;
        if (key === 'className') el.className = value;
        else if (key === 'style') el.style.cssText = value;
        else el.setAttribute(key, value);
    }
    if (text) el.textContent = text;
    return el;
}

function escapeXml(unsafe) {
    return (unsafe || "").toString()
        .replaceAll('&', "&amp;")
        .replaceAll('<', "&lt;")
        .replaceAll('>', "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&apos;");
}

function formatXmlDate(date) {
    if (!date || Number.isNaN(date.getTime())) return "1900-01-01T00:00:00.000";
    const y = date.getFullYear();
    const m = String(date.getMonth() + 1).padStart(2, '0');
    const d = String(date.getDate()).padStart(2, '0');
    return `${y}-${m}-${d}T00:00:00.000`;
}

function formatXmlTime(date) {
    if (!date || Number.isNaN(date.getTime())) return "1899-12-31T00:00:00.000";
    const h = String(date.getHours()).padStart(2, '0');
    const min = String(date.getMinutes()).padStart(2, '0');
    const s = String(date.getSeconds()).padStart(2, '0');
    return `1899-12-31T${h}:${min}:${s}.000`;
}

// === ФУНКЦИИ ДЛЯ СОХРАНЕНИЯ И ЗАГРУЗКИ ИСТОРИИ ===
async function saveHistoryToStorage() {
    try {
        const historyList = document.getElementById('historyList');
        const entries = historyList.querySelectorAll('.history-entry');
        const historyData = Array.from(entries).map(entry => entry.dataset.jsonData);
        await safeLocalStorageSet('z7_history_session', JSON.stringify(historyData));
    } catch (e) {
        console.error('Ошибка при сохранении истории:', e);
    }
}

function restoreHistoryFromStorage() {
    try {
        const historyJson = localStorage.getItem('z7_history_session');
        if (!historyJson) return;
        
        const historyList = document.getElementById('historyList');
        historyList.textContent = '';
        
        const historyData = safeJsonParse(historyJson);
        if (!Array.isArray(historyData)) return;
        
        historyData.forEach(jsonStr => {
            try {
                const data = safeJsonParse(jsonStr);
                if (!data) return;
                const entryDiv = createEl('div', { className: 'history-entry' });
                entryDiv.dataset.jsonData = jsonStr;

                const header = createEl('div', { className: 'history-header' });
                const leftSpan = createEl('span');
                const bName = createEl('b', {}, data.title);
                leftSpan.append(bName);

                const rightSpan = createEl('span', { style: 'display:flex; align-items:center;' });
                const infoText = createEl('span', { style: 'font-size:12px' }, ` Строк: ${data.rows.length}`);
                const delBtn = createEl('button', { className: 'btn-sm btn-del-history' }, 'Удалить');
                delBtn.onclick = async () => {
                    if (confirm('Удалить эту запись из истории?')) {
                        entryDiv.remove();
                        await saveHistoryToStorage();
                        updateFirstPauseVisibility();
                    }
                };
                rightSpan.append(infoText, delBtn);
                header.append(leftSpan, rightSpan);
                
                const table = createEl('table', { style: 'width:100%; border:1px solid #ccc;' });
                const thead = createEl('thead');
                const trHead = createEl('tr', { style: 'background:#eee;' });
                
                // Определяем единицу измерения для заголовка
                let restoreHeaderUnit = "";
                const restoreUniqueUnits = [...new Set(data.rows.map(r => r.unit || 'min'))];
                if (restoreUniqueUnits.length === 1) {
                    if (restoreUniqueUnits[0] === 'min') restoreHeaderUnit = " (мин)";
                    else if (restoreUniqueUnits[0] === 'hour') restoreHeaderUnit = " (час)";
                }
                
                ['№', 'Операция', 'Исполнитель', 'Обед?', 'Перерыв', `Длительность${restoreHeaderUnit}`, 'Дата Начала', 'Время Начала', 'Дата конца', 'Время конца'].forEach(text => {
                    trHead.append(createEl('th', {}, text));
                });
                thead.append(trHead);

                const tbody = createEl('tbody');
                data.rows.forEach(r => {
                    const tr = createEl('tr');
                    tr.append(
                        createEl('td', {}, r.opIdx),
                        createEl('td', { style: 'text-align:left;' }, r.name),
                        createEl('td', {}, r.worker),
                        createEl('td', {}, r.crossedLunch ? '🍽️' : ''),
                        createEl('td', { style: 'color: #555;' }, r.pauseText || ''),
                        createEl('td', {}, r.durText),
                        createEl('td', {}, r.startDate),
                        createEl('td', {}, r.startTime),
                        createEl('td', {}, r.endDate),
                        createEl('td', {}, r.endTime)
                    );
                    tbody.append(tr);
                });
                table.append(thead, tbody);

                const z7Table = createEl('table', { className: 'history-z7', style: 'width:100%; border-collapse:collapse;' });
                const z7Head = createEl('thead');
                const thZ7 = createEl('th', { className: 'z7-header-common', colspan: '10' }, 'Z7');
                const z7HeadTr = createEl('tr');
                z7HeadTr.append(thZ7);
                z7Head.append(z7HeadTr);
                
                const z7Body = createEl('tbody');
                const z7Tr = createEl('tr');
                const z7Td = createEl('td');
                data.z7.forEach(line => z7Td.append(createEl('div', { className: 'z7-line-item' }, line)));
                z7Tr.append(z7Td);
                z7Body.append(z7Tr);
                z7Table.append(z7Head, z7Body);
                
                entryDiv.append(header, table, createEl('div', { style: 'height:10px' }), z7Table);
                historyList.append(entryDiv);
            } catch (e) {
                console.error('Ошибка при восстановлении записи:', e);
            }
        });
    } catch (e) {
        console.error('Ошибка при загрузке истории:', e);
    }
    updateStartTimeFromHistory();
}

async function clearHistoryData() {
    let confirmed = false;
    
    // Используем Tauri диалог если доступен
    if (tauriDialog?.confirm) {
        try {
            confirmed = await tauriDialog.confirm('Вы уверены? Это удалит всю историю расчетов.', {
                title: 'Подтверждение',
                kind: 'warning'
            });
        } catch (e) {
            console.error('Tauri confirm error:', e);
            confirmed = globalThis.confirm('Вы уверены? Это удалит всю историю расчетов.');
        }
    } else {
        confirmed = globalThis.confirm('Вы уверены? Это удалит всю историю расчетов.');
    }
    
    if (confirmed) {
        try {
            const historyList = document.getElementById('historyList');
            historyList.textContent = '';
            await safeLocalStorageRemove('z7_history_session');
            if (tauriDialog && tauriDialog.message) {
                try { tauriDialog.message('История удалена', { title: 'Информация' }); } catch(e){}
            }
            
            document.getElementById('startTime').value = "08:00:00";
            
            updateStartTimeFromHistory();
            updateFirstPauseVisibility();
        } catch (e) {
            console.error('Ошибка при очистке истории:', e);
            alert('Ошибка при очистке истории');
        }
    }
}

// Функция для управления видимостью чекбокса паузы первого блока
function updateFirstPauseVisibility() {
    const firstOpBlock = document.querySelector('.op-block');
    if (!firstOpBlock) return;
    
    const toggleDiv = firstOpBlock.querySelector('.order-pause-toggle')?.parentElement;
    if (!toggleDiv) return;
    
    const isChainMode = document.getElementById('chainMode').checked;
    const historyList = document.getElementById('historyList');
    const isFirstCalculation = historyList.children.length === 0;
    
    // Показать паузу ТОЛЬКО если: режим цепочки включен И история НЕ пуста
    if (isChainMode && !isFirstCalculation) {
        toggleDiv.style.display = 'flex';
    } else {
        toggleDiv.style.display = 'none';
    }
}

function renderFields() {
    const targetCount = validateNumber(document.getElementById('totalOps').value, 1, 50);
    document.getElementById('totalOps').value = targetCount;
    
    // Валидация отрицательных значений для #workerCount
    let workerCount = Number.parseInt(document.getElementById('workerCount').value);
    if (workerCount < 1) {
        document.getElementById('workerCount').value = 1;
    }
    
    const currentBlocks = Array.from(container.children);
    const currentCount = currentBlocks.length;
    
    if (targetCount > currentCount) {
        for (let i = currentCount; i < targetCount; i++) {
            createOperationBlock(i + 1);
        }
    } else if (targetCount < currentCount) {
        for (let i = currentCount - 1; i >= targetCount; i--) {
            container.removeChild(currentBlocks[i]);
        }
    }
}

function createOperationBlock(index) {
    const block = createEl('div', { className: 'op-block' });
    const nameInp = createEl('input', {
        className: 'op-header-input',
        value: `Операция №${index}`,
        type: 'text',
        placeholder: 'Название операции'
    });
    
    const controls = createEl('div', { className: 'op-controls' });
    
    // Блок времени работы
    const workGroup = createEl('div', { className: 'time-group' });
    workGroup.append(createEl('label', {}, 'Время:'));
    const workInput = createEl('input', {
        type: 'number',
        className: 'op-duration',
        step: '1',
        min: '0',
        value: '10'
    });
    // Валидация отрицательных значений для op-duration
    workInput.addEventListener('change', (e) => {
        let value = Number.parseFloat(e.target.value);
        if (value < 0) {
            e.target.value = 0;
        }
    });
    workGroup.append(workInput);
    const workUnit = createEl('select', {
        className: 'op-unit',
        style: 'width:70px; background:transparent; border:none;'
    });
    workUnit.append(
        new Option('мин', 'min'),
        new Option('час', 'hour')
    );
    
    // Для всех операций кроме первой - disabled и синхронизация с первой
    if (index !== 1) {
        workUnit.disabled = true;
        // Синхронизируем с первой операцией
        const firstUnitSelect = container.querySelector('.op-block:first-child .op-unit');
        if (firstUnitSelect) {
            workUnit.value = firstUnitSelect.value;
        }
    } else {
        // Для первой операции - обработчик синхронизации
        workUnit.addEventListener('change', syncTimeUnits);
    }
    workGroup.append(workUnit);
    
    // Блок паузы между заказами (только для первой операции)
    const breakGroup = createEl('div', { className: 'time-group break-container' });
    breakGroup.append(createEl('label', {}, 'Пауза:'));
    const breakInput = createEl('input', {
        type: 'number',
        className: 'op-break-val',
        value: '0',
        step: '1',
        min: '0'
    });
    // Валидация отрицательных значений для op-break-val
    breakInput.addEventListener('change', (e) => {
        let value = Number.parseFloat(e.target.value);
        if (value < 0) {
            e.target.value = 0;
        }
    });
    breakGroup.append(breakInput);
    const breakUnit = createEl('select', {
        className: 'op-break-unit',
        style: 'width:70px; background:transparent; border:none;'
    });
    breakUnit.append(
        new Option('мин', 'min'),
        new Option('час', 'hour')
    );
    breakGroup.append(breakUnit);
    
    // Чекбокс для паузы между заказами
    const toggleDiv = createEl('div', { style: 'display:flex; align-items:center;' });
    const chk = createEl('input', {
        type: 'checkbox',
        className: 'order-pause-toggle',
        style: 'margin:0;'
    });
    toggleDiv.append(chk, createEl('label', { style: 'margin-left:4px; cursor:pointer;' }, 'Пауза перед началом (перерыв)'));
    
    // Скрыть паузу для всех блоков кроме первого
    if (index !== 1) {
        toggleDiv.style.display = 'none';
    }
    
    const updateBreakVis = () => {
        breakGroup.style.display = chk.checked ? 'flex' : 'none';
        toggleDiv.style.opacity = chk.checked ? '0.5' : '1';
    };
    
    chk.addEventListener('change', updateBreakVis);
    toggleDiv.querySelector('label').addEventListener('click', () => {
        chk.checked = !chk.checked;
        updateBreakVis();
    });
    
    controls.append(toggleDiv, breakGroup, workGroup);
    block.append(nameInp, controls);
    container.append(block);
    updateBreakVis();
    
    // Обновить видимость паузы первого блока после создания нового блока
    updateFirstPauseVisibility();
}

async function generateTable() {
    const tableResult = document.getElementById('tableResult');
    const z7Result = document.getElementById('z7Result');
    tableResult.textContent = '';
    z7Result.textContent = '';

    const startD = document.getElementById('startDate').value;
    const startT = document.getElementById('startTime').value;
    const workerCount = validateNumber(document.getElementById('workerCount').value, 1, 20);
    const timeMode = document.getElementById('timeMode').value;
    const lunchStartInput = document.getElementById('lunchStart').value;
    const lunchStartInput2 = document.getElementById('lunchStart2').value;
    const lunchDurMin = validateNumber(document.getElementById('lunchDur').value, 0, 480);
    const isChain = document.getElementById('chainMode').checked;
    
    if (!startD || !startT) {
        alert("Пожалуйста, укажите дату и время начала.");
        return;
    }

    // Проверяем, это первый расчет или нет
    const historyList = document.getElementById('historyList');
    const isFirstCalculation = historyList.children.length === 0;

    let [y, m, d] = startD.split('-').map(Number);
    let [th, tm, ts] = startT.split(':').map(Number);
    ts = ts || 0;
    let globalTime = new Date(y, m - 1, d, th, tm, ts);
    
    // Получаем параметры паузы (для первой операции)
    const firstOpBlock = document.querySelector('.op-block');
    let pauseText = "";
    let pauseExcelVal = 0; // в днях (для Excel)
    
    let pauseAppliedMs = 0;

    if (firstOpBlock) {
        const pauseChk = firstOpBlock.querySelector('.order-pause-toggle');
            if (pauseChk?.checked && !isFirstCalculation) {
            const pauseDur = Math.max(0, Number.parseFloat(firstOpBlock.querySelector('.op-break-val').value) || 0);
            const pauseUnit = firstOpBlock.querySelector('.op-break-unit').value;
            
            // Если пауза выставлена (даже 0), мы её будем отображать для первой операции, 
            // если считаем, что наличие галочки = наличие паузы. 
            // Но пользователь просил "если паузы нет - ячейка пустая". 
            // Будем считать, что если > 0, то отображаем.
            if (pauseDur > 0) {
               pauseText = formatDurationToTime(pauseDur, pauseUnit);
               
               let pauseSec = 0;
               if (pauseUnit === 'min') pauseSec = pauseDur * 60;
               else if (pauseUnit === 'hour') pauseSec = pauseDur * 3600;
               else pauseSec = pauseDur * 60; 

               pauseAppliedMs = pauseSec * 1000;
               pauseExcelVal = pauseSec / 86400.0;
            }
        }
    }

    // Применяем паузу к глобальному времени
    globalTime = new Date(globalTime.getTime() + pauseAppliedMs);
    
    // --- 
    
    // --- Настройка обедов (JS) ---
    let [lh, lm] = lunchStartInput.split(':').map(Number);
    let lunchStartTime = new Date(y, m - 1, d, lh, lm, 0);
    let lunchEndTime = new Date(lunchStartTime.getTime() + lunchDurMin * 60000);

    // Второй обед
    let [lh2, lm2] = lunchStartInput2.split(':').map(Number);
    let lunch2StartTime = new Date(y, m - 1, d, lh2, lm2, 0);
    // Если второй обед раньше старта (напр 00:00 vs 08:00), считаем что он на след. день
    // (Это простая эвристика, "ночной обед")
    if (lunch2StartTime < globalTime) {
        lunch2StartTime.setDate(lunch2StartTime.getDate() + 1);
    }
    let lunch2EndTime = new Date(lunch2StartTime.getTime() + lunchDurMin * 60000);

    const ops = document.querySelectorAll('.op-block');
    if (ops.length === 0) return;

    const operationNames = [];
    const dataMain = [];
    const fmtTime = (date) => date.toLocaleTimeString('ru', {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    });
    const fmtDate = (date) => date.toLocaleDateString('ru');

    ops.forEach((block, opIndex) => {
        const name = sanitizeInput(block.querySelector('.op-header-input').value, 200);
        operationNames.push(name);
        const dur = Math.max(0, Number.parseFloat(block.querySelector('.op-duration').value) || 0);
        const unit = block.querySelector('.op-unit').value;
        
        let durationMs = 0;
        if (unit === 'hour') durationMs = dur * 3600 * 1000;
        else if (unit === 'min') durationMs = dur * 60 * 1000;
        else durationMs = dur * 60 * 1000;

        let displayDurVal = dur;
        if (timeMode === 'total' && workerCount > 1) {
            durationMs = durationMs / workerCount;
            displayDurVal = displayDurVal / workerCount;
        }

        let opStart = new Date(globalTime);
        let opEnd = new Date(opStart.getTime() + durationMs);
        let crossedLunch = false;

        // Логика проверки двух обедов
        let lunches = [
            { s: lunchStartTime, e: lunchEndTime },
            { s: lunch2StartTime, e: lunch2EndTime }
        ].sort((a, b) => a.s - b.s);

        for (let l of lunches) {
            // 1. Если начало операции попадает внутрь обеда -> сдвигаем старт
            if (opStart >= l.s && opStart < l.e) {
                opStart = new Date(l.e);
                opEnd = new Date(opStart.getTime() + durationMs);
                crossedLunch = true;
            }
            
            // 2. Если операция накрывает начало обеда (началась до, заканчивается после)
            if (opStart < l.s && opEnd > l.s) {
                let lDur = l.e.getTime() - l.s.getTime();
                opEnd = new Date(opEnd.getTime() + lDur);
                crossedLunch = true;
            }
        }

        let displayDurText = new Intl.NumberFormat('ru-RU', {
            minimumFractionDigits: Number.isInteger(displayDurVal) ? 0 : 2,
            maximumFractionDigits: 2
        }).format(displayDurVal);

        for (let w = 1; w <= workerCount; w++) {
            // Пауза применяется ко всем исполнителям первой операции
            const rowPauseText = (opIndex === 0) ? pauseText : "";
            const rowPauseExcel = (opIndex === 0) ? pauseExcelVal : 0;

            dataMain.push({
                opIdx: opIndex + 1,
                name: name,
                worker: getWorkerLabel(w),
                workerIndex: w, // сохраняем числовой индекс для Excel формул
                durVal: displayDurVal,
                durText: displayDurText,
                startObj: new Date(opStart),
                endObj: new Date(opEnd),
                startDate: fmtDate(opStart),
                startTime: fmtTime(opStart),
                endDate: fmtDate(opEnd),
                endTime: fmtTime(opEnd),
                crossedLunch: crossedLunch,
                pauseText: rowPauseText,
                pauseExcelVal: rowPauseExcel,
                unit: unit // сохраняем единицу измерения
            });
        }
        globalTime = opEnd;
    });

    if (isChain) {
        const yyyy = globalTime.getFullYear();
        const mm = String(globalTime.getMonth() + 1).padStart(2, '0');
        const dd = String(globalTime.getDate()).padStart(2, '0');
        startDateInput.value = `${yyyy}-${mm}-${dd}`;
        
        const hh = String(globalTime.getHours()).padStart(2, '0');
        const min = String(globalTime.getMinutes()).padStart(2, '0');
        const sec = String(globalTime.getSeconds()).padStart(2, '0');
        startTimeInput.value = `${hh}:${min}:${sec}`;
    }

    const createSubTable = (headers, flexGrow = 1) => {
        const wrapper = createEl('div', {
            className: 'split-table-wrapper',
            style: `flex-grow:${flexGrow};`
        });
        const table = createEl('table');
        const thead = createEl('thead');
        const trHead = createEl('tr');
        headers.forEach(h => trHead.append(createEl('th', {}, h)));
        thead.append(trHead);
        const tbody = createEl('tbody');
        table.append(thead, tbody);
        wrapper.append(table);
        return { wrapper, tbody };
    };

    const tblOps = createSubTable(['№', 'Операция', 'Исполнитель', 'Обед?', 'Перерыв'], 2);
    
    // Определяем единицу измерения для заголовка Длительность
    let headerUnit = "";
    const uniqueUnits = [...new Set(dataMain.map(r => r.unit || 'min'))];
    if (uniqueUnits.length === 1) {
        if (uniqueUnits[0] === 'min') headerUnit = " (мин)";
        else if (uniqueUnits[0] === 'hour') headerUnit = " (час)";
    }
    
    const tblDur = createSubTable([`Длительность${headerUnit}`], 1);
    const tblTime = createSubTable(['Дата Начала', 'Время Начала', 'Дата конца', 'Время конца'], 3);

    dataMain.forEach((row) => {
        const trOps = createEl('tr');
        trOps.append(
            createEl('td', {}, row.opIdx),
            createEl('td', { style: 'text-align:left; font-weight:600;' }, row.name),
            createEl('td', {}, row.worker),
            createEl('td', { style: 'font-size: 24px; line-height: 1; padding: 4px 12px;' }, row.crossedLunch ? '🍽️' : ''),
            createEl('td', { style: 'color: #555;' }, row.pauseText || '')
        );
        tblOps.tbody.append(trOps);

        const trDur = createEl('tr');
        trDur.append(createEl('td', {}, row.durText));
        tblDur.tbody.append(trDur);

        const trTime = createEl('tr');
        trTime.append(
            createEl('td', {}, row.startDate),
            createEl('td', {}, row.startTime),
            createEl('td', {}, row.endDate),
            createEl('td', {}, row.endTime)
        );
        tblTime.tbody.append(trTime);
    });

    tableResult.append(tblOps.wrapper, tblDur.wrapper, tblTime.wrapper);

    const statusText = sanitizeInput(document.getElementById('statusBefore').value, 300) || "замечаний нет";
    const extraWorks = sanitizeInput(document.getElementById('workExtra').value, 300) || "нет";
    const devRec = sanitizeInput(document.getElementById('devRec').value, 300) || "нет";
    const rizVal = sanitizeInput(document.getElementById('resIz').value, 100) || "";
    const kVal = sanitizeInput(document.getElementById('coefK').value, 100) || "";
    const worksText = operationNames.join(', ');
    const rizDisplay = rizVal ? `${rizVal} МОм` : "";

    const z7Lines = [
        `1. состояние объекта ремонта до начала работ: ${statusText}`,
        `2. выполненные работы в рамках планового объёма работ: ${worksText}`,
        `3. выполненные работы в рамках дополнительного объёма работ: ${extraWorks}`,
        `4. результаты испытаний, тестов, замеров, инспекций: Rиз= ${rizDisplay} K= ${kVal}.`,
        `5. отклонения от ТК и рекомендации по корректировке ТК: ${devRec}`
    ];
    
    const z7Div = createEl('div', { className: 'z7-report-wrapper' });
    const z7Table = createEl('table', { className: 'z7-table' });
    const z7Head = createEl('thead');
    const thZ7 = createEl('th', { className: 'z7-header-common', colspan: '9' }, 'Z7');
    const z7HeadTr = createEl('tr');
    z7HeadTr.append(thZ7);
    z7Head.append(z7HeadTr);

    const z7Body = createEl('tbody');
    const tr = createEl('tr', { className: 'z7-row' });
    const z7Td = createEl('td');
    z7Lines.forEach(line => z7Td.append(createEl('div', { className: 'z7-line-item' }, line)));
    tr.append(z7Td);
    z7Body.append(tr);
    z7Table.append(z7Head, z7Body);
    z7Div.append(z7Table);
    z7Result.append(z7Div);

    const select = document.getElementById('techCardSelect');
    const cardName = select.value === 'manual' ? 'Ручной ввод' : select.options[select.selectedIndex].text;
    
    const lunchConfig = { h: lh, m: lm, h2: lh2, m2: lm2, dur: lunchDurMin };
    
    // orderPauseConfig сохраняем для совместимости, но данные уже в строках
    const orderPauseConfig = { dur: 0, unit: 'min', isApplied: !isFirstCalculation }; // Dummy values as actual are in rows
    await addToHistoryTable(dataMain, cardName, z7Lines, lunchConfig, isChain, orderPauseConfig);
}

async function addToHistoryTable(data, cardName, z7LinesArray, lunchConfig, isChain, orderPauseConfig) {
    try {
        const historyList = document.getElementById('historyList');
        const timestamp = new Date().toLocaleString('ru');
        
        const entryDiv = createEl('div', { className: 'history-entry' });
        entryDiv.dataset.jsonData = JSON.stringify({
            title: `${cardName} (${timestamp})`,
            rows: data,
            z7: z7LinesArray,
            lunch: lunchConfig,
            chain: isChain,
            orderPause: orderPauseConfig
        });

        const header = createEl('div', { className: 'history-header' });
        const leftSpan = createEl('span');
        const bName = createEl('b', {}, cardName);
        leftSpan.append(bName, document.createTextNode(` (${timestamp})`));

        const rightSpan = createEl('span', { style: 'display:flex; align-items:center;' });
        const infoText = createEl('span', { style: 'font-size:12px' }, ` Строк: ${data.length}`);
        const delBtn = createEl('button', { className: 'btn-sm btn-del-history' }, 'Удалить');
        delBtn.onclick = async () => {
            if (confirm('Удалить эту запись из истории?')) {
                entryDiv.remove();
                await saveHistoryToStorage();
                updateFirstPauseVisibility();
            }
        };
        rightSpan.append(infoText, delBtn);
        header.append(leftSpan, rightSpan);
        
        const table = createEl('table', { style: 'width:100%; border:1px solid #ccc;' });
        const thead = createEl('thead');
        const trHead = createEl('tr', { style: 'background:#eee;' });
        
        // Определяем единицу измерения для заголовка
        let histHeaderUnit = "";
        const histUniqueUnits = [...new Set(data.map(r => r.unit || 'min'))];
        if (histUniqueUnits.length === 1) {
            if (histUniqueUnits[0] === 'min') histHeaderUnit = " (мин)";
            else if (histUniqueUnits[0] === 'hour') histHeaderUnit = " (час)";
        }
        
        ['№', 'Операция', 'Исполнитель', 'Обед?', 'Перерыв', `Длительность${histHeaderUnit}`, 'Дата Начала', 'Время Начала', 'Дата конца', 'Время конца'].forEach(text => {
            trHead.append(createEl('th', {}, text));
        });
        thead.append(trHead);

        const tbody = createEl('tbody');
        data.forEach(r => {
            const tr = createEl('tr');
            tr.append(
                createEl('td', {}, r.opIdx),
                createEl('td', { style: 'text-align:left;' }, r.name),
                createEl('td', {}, r.worker),
                createEl('td', {}, r.crossedLunch ? '🍽️' : ''),
                createEl('td', { style: 'color: #555;' }, r.pauseText || ''),
                createEl('td', {}, r.durText),
                createEl('td', {}, r.startDate),
                createEl('td', {}, r.startTime),
                createEl('td', {}, r.endDate),
                createEl('td', {}, r.endTime)
            );
            tbody.append(tr);
        });
        table.append(thead, tbody);

        const z7Table = createEl('table', { className: 'history-z7', style: 'width:100%; border-collapse:collapse;' });
        const z7Head = createEl('thead');
        const thZ7 = createEl('th', { className: 'z7-header-common', colspan: '10' }, 'Z7');
        const z7HeadTr = createEl('tr');
        z7HeadTr.append(thZ7);
        z7Head.append(z7HeadTr);
        
        const z7Body = createEl('tbody');
        const z7Tr = createEl('tr');
        const z7Td = createEl('td');
        z7LinesArray.forEach(line => z7Td.append(createEl('div', { className: 'z7-line-item' }, line)));
        z7Tr.append(z7Td);
        z7Body.append(z7Tr);
        z7Table.append(z7Head, z7Body);
        
        entryDiv.append(header, table, createEl('div', { style: 'height:10px' }), z7Table);
        historyList.prepend(entryDiv);
        
        // Сохраняем историю в localStorage
        await saveHistoryToStorage();
        updateStartTimeFromHistory();
        updateFirstPauseVisibility();
    } catch (e) {
        console.error(e);
        alert("Ошибка добавления в историю: " + e.message);
    }
}

function updateStartTimeFromHistory() {
    const isChainMode = document.getElementById('chainMode').checked;
    const historyList = document.getElementById('historyList');
    const startTimeInput = document.getElementById('startTime');
    const startDateInput = document.getElementById('startDate');
    
    if (!isChainMode || historyList.children.length === 0) {
        // Если режим цепочки отключен или история пуста, поле активно
        startTimeInput.disabled = false;
        startDateInput.disabled = false;
        return;
    }
    
    // Получаем последнюю запись из истории
    const lastEntry = historyList.firstElementChild;
    if (!lastEntry || !lastEntry.dataset.jsonData) {
        startTimeInput.disabled = false;
        startDateInput.disabled = false;
        return;
    }
    
    try {
        const data = safeJsonParse(lastEntry.dataset.jsonData);
        if (!data || !data.rows || data.rows.length === 0) {
            startTimeInput.disabled = false;
            startDateInput.disabled = false;
            return;
        }
        
        // Получаем время окончания последней операции
        const lastRow = data.rows[data.rows.length - 1];
        
        if (lastRow.endObj) {
            const dt = new Date(lastRow.endObj);
            const y = dt.getFullYear();
            const m = String(dt.getMonth() + 1).padStart(2, '0');
            const d = String(dt.getDate()).padStart(2, '0');
            startDateInput.value = `${y}-${m}-${d}`;

            const hh = String(dt.getHours()).padStart(2, '0');
            const mm = String(dt.getMinutes()).padStart(2, '0');
            const ss = String(dt.getSeconds()).padStart(2, '0');
            startTimeInput.value = `${hh}:${mm}:${ss}`;
        } else {
            startTimeInput.value = lastRow.endTime; 
        }
        
        startTimeInput.disabled = true;
        startDateInput.disabled = true;
    } catch (e) {
        console.error('Ошибка при обновлении времени начала:', e);
        startTimeInput.disabled = false;
        startDateInput.disabled = false;
    }
}

// === ЭКСПОРТ В EXCEL ===
function setupExcelExport() {
    document.getElementById('clearHistoryBtn').addEventListener('click', clearHistoryData);
    document.getElementById('exportExcelBtn').addEventListener('click', exportToExcel);
}

async function exportToExcel() {
    const historyList = document.getElementById('historyList');
    const entries = historyList.querySelectorAll('.history-entry');
    
    if (entries.length === 0) {
        if (tauriDialog?.message) {
            await tauriDialog.message('История пуста!', { title: 'Информация' });
        } else {
            alert("История пуста!");
        }
        return;
    }

    let xmlBody = '';
    let previousEntryData = null;
    const entriesArray = Array.from(entries).reverse();

    entriesArray.forEach(entry => {
        const data = safeJsonParse(entry.dataset.jsonData);
        if (!data) return;
        const lh = data.lunch.h || 0;
        const lm = data.lunch.m || 0;
        const lh2 = (data.lunch.h2 !== undefined) ? data.lunch.h2 : 0;
        const lm2 = (data.lunch.m2 !== undefined) ? data.lunch.m2 : 0;
        const ld = data.lunch.dur || 60;
        const isChain = data.chain;
        
        // Определяем единицу измерения для заголовка
        let headerUnit = "";
        const uniqueUnits = [...new Set(data.rows.map(r => r.unit || 'min'))];
        if (uniqueUnits.length === 1) {
            if (uniqueUnits[0] === 'min') headerUnit = " (мин)";
            else if (uniqueUnits[0] === 'hour') headerUnit = " (час)";
        } else if (uniqueUnits.length > 1) {
            // Если смешанные, можно не выводить или вывести (мин/час)
            // Но лучше оставить пользователю понимание, что единицы разные
            headerUnit = ""; 
        }

        xmlBody += `
        <Row>
            <Cell ss:Index="2" ss:MergeAcross="9" ss:StyleID="sTitle"><Data ss:Type="String">${escapeXml(excelSanitizeCell(data.title))}</Data></Cell>
        </Row>
        <Row>
            <Cell ss:Index="2" ss:StyleID="sHeader"><Data ss:Type="String">№</Data></Cell>
            <Cell ss:StyleID="sHeader"><Data ss:Type="String">Операция</Data></Cell>
            <Cell ss:StyleID="sHeader"><Data ss:Type="String">Исполнитель</Data></Cell>
            <Cell ss:StyleID="sHeader"><Data ss:Type="String">Обед?</Data></Cell>
            <Cell ss:StyleID="sHeader"><Data ss:Type="String">Перерыв</Data></Cell>
            <Cell ss:StyleID="sHeader"><Data ss:Type="String">Длительность${headerUnit}</Data></Cell>
            <Cell ss:StyleID="sHeader"><Data ss:Type="String">Дата Начала</Data></Cell>
            <Cell ss:StyleID="sHeader"><Data ss:Type="String">Время Начала</Data></Cell>
            <Cell ss:StyleID="sHeader"><Data ss:Type="String">Дата конца</Data></Cell>
            <Cell ss:StyleID="sHeader"><Data ss:Type="String">Время конца</Data></Cell>
        </Row>
        `;

        data.rows.forEach((r, idx) => {
            const startXml = formatXmlDate(new Date(r.startObj));
            const endXml = formatXmlDate(new Date(r.endObj));
            const startTimeXml = formatXmlTime(new Date(r.startObj));
            const pauseVal = typeof r.pauseExcelVal === 'number' ? r.pauseExcelVal : 0;
            
            // Делитель для формул времени
            const unitDiv = (r.unit === 'hour') ? 24.0 : 1440.0;
            
            let startTimeCell;
            let durCell;
            const prevRowOpIdx = (idx > 0) ? data.rows[idx - 1].opIdx : -1;
            
            if (r.opIdx === prevRowOpIdx) {
                durCell = `<Cell ss:StyleID="sDurLocked" ss:Formula="=R[-1]C"><Data ss:Type="Number">${r.durVal}</Data></Cell>`;
            } else {
                durCell = `<Cell ss:StyleID="sDurEditable"><Data ss:Type="Number">${r.durVal}</Data></Cell>`;
            }

            // Ячейка паузы. 
            // Op 1 Worker 1: Редактируемая.
            // Op 1 Worker > 1: Защищена, копия значения сверху.
            // Op > 1: Защищена, пустая.
            let pauseCell;
            if (r.opIdx === 1) {
                if (r.workerIndex === 1) {
                    pauseCell = `<Cell ss:StyleID="sTimeEditable"><Data ss:Type="Number">${pauseVal}</Data></Cell>`;
                } else {
                    pauseCell = `<Cell ss:StyleID="sTimeLocked" ss:Formula="=R[-1]C"><Data ss:Type="Number">${pauseVal}</Data></Cell>`;
                }
            } else {
                pauseCell = `<Cell ss:StyleID="sTimeLocked"></Cell>`;
            }

            if (idx === 0) {
                if (isChain && previousEntryData) {
                    // offset = 5 (заголовок Z7 + разделители) + (z7.length * 2) т.к. после каждой строки Z7 пустая строка
                    const offset = 5 + (previousEntryData.z7.length * 2);
                    // Формула: (Конец пред. таблицы) + (Пауза этой строки)
                    // Если пауза пустая, Excel воспримет как 0, формула не сломается
                    startTimeCell = `<Cell ss:StyleID="sTimeLocked" ss:Formula="=MOD(R[-${offset}]C[2] + RC[-3],1)"><Data ss:Type="DateTime">${startTimeXml}</Data></Cell>`;
                } else {
                    // Если первая таблица или не цепочка - время фиксировано
                    startTimeCell = `<Cell ss:StyleID="sTimeEditable"><Data ss:Type="DateTime">${startTimeXml}</Data></Cell>`;
                }
            } else {
                if (r.opIdx === prevRowOpIdx) {
                    startTimeCell = `<Cell ss:StyleID="sTimeLocked" ss:Formula="=R[-1]C"><Data ss:Type="DateTime">${startTimeXml}</Data></Cell>`;
                } else {
                    // Начало операции (кроме первой) ссылается на конец предыдущей. 
                    startTimeCell = `<Cell ss:StyleID="sTimeLocked" ss:Formula="=MOD(R[-1]C[2],1)"><Data ss:Type="DateTime">${startTimeXml}</Data></Cell>`;
                }
            }

            const l1Val = `TIME(${lh},${lm},0)`;
            const l1End = `(TIME(${lh},${lm},0)+TIME(0,${ld},0))`;
            const lDurVal = `TIME(0,${ld},0)`;
            
            // Проверяем, задан ли второй обед (не 00:00)
            const hasLunch2 = !(lh2 === 0 && lm2 === 0);
            const l2Val = `TIME(${lh2},${lm2},0)`;
            const l2End = `(TIME(${lh2},${lm2},0)+TIME(0,${ld},0))`;
            
            // --- ICONS (RC[4] = Start, RC[2] = Dur) ---
            // Условие 1: начало < конец_обеда И конец_операции > начало_обеда
            const icC1 = `AND(RC[4] < ${l1End}, (RC[4]+(RC[2]/${unitDiv})) > ${l1Val})`;
            const icShift1 = `IF(${icC1}, ${lDurVal}, 0)`;
            
            let formulaIcon;
            if (hasLunch2) {
                // Условие 2: для второго обеда (с учётом сдвига от первого)
                const icC2 = `AND((RC[4] + ${icShift1}) < ${l2End}, (RC[4]+(RC[2]/${unitDiv}) + ${icShift1}) > ${l2Val})`;
                formulaIcon = `=IF(OR(${icC1}, ${icC2}), "🍽️", "")`;
            } else {
                // Второй обед не задан - проверяем только первый
                formulaIcon = `=IF(${icC1}, "🍽️", "")`;
            }

            // --- END TIME (RC[-2] = Start, RC[-4] = Dur) ---
            const enC1 = `AND(RC[-2] < ${l1End}, (RC[-2]+(RC[-4]/${unitDiv})) > ${l1Val})`;
            const enShift1 = `IF(${enC1}, ${lDurVal}, 0)`;
            
            let formulaEnd;
            if (hasLunch2) {
                const enC2 = `AND((RC[-2] + ${enShift1}) < ${l2End}, (RC[-2]+(RC[-4]/${unitDiv}) + ${enShift1}) > ${l2Val})`;
                const enShift2 = `IF(${enC2}, ${lDurVal}, 0)`;
                formulaEnd = `=MOD(RC[-2]+(RC[-4]/${unitDiv}) + ${enShift1} + ${enShift2}, 1)`;
            } else {
                // Второй обед не задан - учитываем только первый
                formulaEnd = `=MOD(RC[-2]+(RC[-4]/${unitDiv}) + ${enShift1}, 1)`;
            }

            xmlBody += `
            <Row>
                <Cell ss:Index="2" ss:StyleID="sBorderLocked"><Data ss:Type="Number">${r.opIdx}</Data></Cell>
                <Cell ss:StyleID="sBorderLeftLocked"><Data ss:Type="String">${escapeXml(excelSanitizeCell(r.name))}</Data></Cell>
                <Cell ss:StyleID="sBorderLocked"><Data ss:Type="String">${escapeXml(excelSanitizeCell(String(r.worker)))}</Data></Cell>
                <Cell ss:StyleID="sIconLocked" ss:Formula="${escapeXml(formulaIcon)}"><Data ss:Type="String">${r.crossedLunch ? '🍽️' : ''}</Data></Cell>
                ${pauseCell}
                ${durCell}
                <Cell ss:StyleID="sDateLocked"><Data ss:Type="DateTime">${startXml}</Data></Cell>
                ${startTimeCell}
                <Cell ss:StyleID="sDateLocked"><Data ss:Type="DateTime">${endXml}</Data></Cell>
                <Cell ss:StyleID="sTimeLocked" ss:Formula="${escapeXml(formulaEnd)}"><Data ss:Type="DateTime">${startTimeXml}</Data></Cell>
            </Row>
            `;
        });

        xmlBody += `
        <Row>
            <Cell ss:Index="2" ss:MergeAcross="9" ss:StyleID="sTitle"><Data ss:Type="String">Z7</Data></Cell>
        </Row>
        `;

        data.z7.forEach(line => {
            xmlBody += `
            <Row>
                <Cell ss:Index="2" ss:MergeAcross="9" ss:StyleID="sBorderLeftLocked"><Data ss:Type="String">${escapeXml(excelSanitizeCell(line))}</Data></Cell>
            </Row>
            <Row>
                <Cell ss:Index="2" ss:MergeAcross="9" ss:StyleID="sBorderLeftLocked"><Data ss:Type="String"></Data></Cell>
            </Row>
            `;
        });

        xmlBody += `<Row></Row>`;
        previousEntryData = data;
    });

    const xmlContent = buildExcelXml(xmlBody);
    downloadExcelFile(xmlContent);
}

function buildExcelXml(xmlBody) {
    return `<?xml version="1.0" encoding="UTF-8"?>
<?mso-application progid="Excel.Sheet"?>
<Workbook xmlns="urn:schemas-microsoft-com:office:spreadsheet"
 xmlns:o="urn:schemas-microsoft-com:office:office"
 xmlns:x="urn:schemas-microsoft-com:office:excel"
 xmlns:ss="urn:schemas-microsoft-com:office:spreadsheet">
 <Styles>
  <Style ss:ID="Default" ss:Name="Normal">
   <Alignment ss:Vertical="Center"/>
   <Borders/>
   <Font ss:FontName="Arial"/>
   <Interior/>
   <Protection ss:Protected="1"/>
  </Style>
  <Style ss:ID="sHeader">
   <Alignment ss:Horizontal="Center" ss:Vertical="Center"/>
   <Borders>
    <Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="1"/>
    <Border ss:Position="Left" ss:LineStyle="Continuous" ss:Weight="1"/>
    <Border ss:Position="Right" ss:LineStyle="Continuous" ss:Weight="1"/>
    <Border ss:Position="Top" ss:LineStyle="Continuous" ss:Weight="1"/>
   </Borders>
   <Font ss:Color="#FFFFFF" ss:Bold="1"/>
   <Interior ss:Color="#374151" ss:Pattern="Solid"/>
   <Protection ss:Protected="1"/>
  </Style>
  <Style ss:ID="sTitle">
   <Alignment ss:Horizontal="Center" ss:Vertical="Center"/>
   <Borders>
    <Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="1"/>
    <Border ss:Position="Left" ss:LineStyle="Continuous" ss:Weight="1"/>
    <Border ss:Position="Right" ss:LineStyle="Continuous" ss:Weight="1"/>
    <Border ss:Position="Top" ss:LineStyle="Continuous" ss:Weight="1"/>
   </Borders>
   <Font ss:Color="#FFFFFF" ss:Bold="1"/>
   <Interior ss:Color="#374151" ss:Pattern="Solid"/>
   <Protection ss:Protected="1"/>
  </Style>
  <Style ss:ID="sTextLocked">
   <Alignment ss:Vertical="Center"/>
   <Protection ss:Protected="1"/>
  </Style>
  <Style ss:ID="sBorderLocked">
   <Alignment ss:Horizontal="Center" ss:Vertical="Center"/>
   <Borders><Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Left" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Right" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Top" ss:LineStyle="Continuous" ss:Weight="1"/></Borders>
   <Interior ss:Color="#F4CCCC" ss:Pattern="Solid"/>
   <Protection ss:Protected="1"/>
  </Style>
  <Style ss:ID="sBorderLeftLocked">
   <Alignment ss:Horizontal="Left" ss:Vertical="Center" ss:WrapText="1"/>
   <Borders><Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Left" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Right" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Top" ss:LineStyle="Continuous" ss:Weight="1"/></Borders>
   <Interior ss:Color="#F4CCCC" ss:Pattern="Solid"/>
   <Protection ss:Protected="1"/>
  </Style>
  <Style ss:ID="sDurLocked">
   <Alignment ss:Horizontal="Center" ss:Vertical="Center"/>
   <Borders><Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Left" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Right" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Top" ss:LineStyle="Continuous" ss:Weight="1"/></Borders>
   <Interior ss:Color="#F4CCCC" ss:Pattern="Solid"/>
   <Protection ss:Protected="1"/>
  </Style>
  <Style ss:ID="sTimeLocked">
   <Alignment ss:Horizontal="Center" ss:Vertical="Center"/>
   <Borders><Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Left" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Right" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Top" ss:LineStyle="Continuous" ss:Weight="1"/></Borders>
   <NumberFormat ss:Format="h:mm:ss"/>
   <Interior ss:Color="#F4CCCC" ss:Pattern="Solid"/>
   <Protection ss:Protected="1"/>
  </Style>
  <Style ss:ID="sDateLocked">
   <Alignment ss:Horizontal="Center" ss:Vertical="Center"/>
   <Borders><Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Left" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Right" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Top" ss:LineStyle="Continuous" ss:Weight="1"/></Borders>
   <NumberFormat ss:Format="dd.mm.yyyy"/>
   <Interior ss:Color="#F4CCCC" ss:Pattern="Solid"/>
   <Protection ss:Protected="1"/>
  </Style>
  <Style ss:ID="sIconLocked">
   <Alignment ss:Horizontal="Center" ss:Vertical="Center"/>
   <Borders><Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Left" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Right" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Top" ss:LineStyle="Continuous" ss:Weight="1"/></Borders>
   <Font ss:Size="14"/>
   <Interior ss:Color="#F4CCCC" ss:Pattern="Solid"/>
   <Protection ss:Protected="1"/>
  </Style>
  <Style ss:ID="sDurEditable">
   <Alignment ss:Horizontal="Center" ss:Vertical="Center"/>
   <Borders><Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Left" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Right" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Top" ss:LineStyle="Continuous" ss:Weight="1"/></Borders>
   <Interior ss:Color="#FFFFFF" ss:Pattern="Solid"/>
   <Protection ss:Protected="0"/>
  </Style>
  <Style ss:ID="sTimeEditable">
   <Alignment ss:Horizontal="Center" ss:Vertical="Center"/>
   <Borders><Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Left" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Right" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Top" ss:LineStyle="Continuous" ss:Weight="1"/></Borders>
   <NumberFormat ss:Format="h:mm:ss"/>
   <Interior ss:Color="#FFFFFF" ss:Pattern="Solid"/>
   <Protection ss:Protected="0"/>
  </Style>
 </Styles>
 <Worksheet ss:Name="Sheet1" ss:Protected="1" x:Password="">
  <Table>
   <Column ss:Width="20" ss:StyleID="sTextLocked"/> <!-- Margin -->
   <Column ss:Width="30" ss:StyleID="sTextLocked"/> <!-- № -->
   <Column ss:Width="200" ss:StyleID="sTextLocked"/> <!-- Operation -->
   <Column ss:Width="80" ss:StyleID="sTextLocked"/> <!-- Worker -->
   <Column ss:Width="50" ss:StyleID="sTextLocked"/> <!-- Lunch? -->
   <Column ss:Width="70" ss:StyleID="sTextLocked"/> <!-- Pause (New) -->
   <Column ss:Width="130" ss:StyleID="sTextLocked"/> <!-- Duration -->
   <Column ss:Width="80" ss:StyleID="sTextLocked"/> <!-- Start D -->
   <Column ss:Width="80" ss:StyleID="sTextLocked"/> <!-- Start T -->
   <Column ss:Width="80" ss:StyleID="sTextLocked"/> <!-- End D -->
   <Column ss:Width="80" ss:StyleID="sTextLocked"/> <!-- End T -->
   ${xmlBody}
  </Table>
  <WorksheetOptions xmlns="urn:schemas-microsoft-com:office:excel">
   <FitToPage/>
   <Print>
    <ValidPrinterInfo/>
    <HorizontalResolution>600</HorizontalResolution>
    <VerticalResolution>600</VerticalResolution>
   </Print>
   <Selected/>
   <Panes>
    <Pane>
     <Number>3</Number>
     <ActiveRow>1</ActiveRow>
    </Pane>
   </Panes>
   <ProtectObjects>True</ProtectObjects>
   <ProtectScenarios>True</ProtectScenarios>
   <ProtectedCells>True</ProtectedCells>
   <Protection>
    <Password></Password>
   </Protection>
  </WorksheetOptions>
 </Worksheet>
</Workbook>`;
}

async function downloadExcelFile(xmlContent) {
    const fileName = `История_Расчетов_${new Date().toLocaleDateString('ru-RU').replaceAll('.', '-')}.xls`;
    
    // Пробуем использовать Tauri API
    if (tauriDialog?.save && tauriInvoke) {
        try {
            const filePath = await tauriDialog.save({
                defaultPath: fileName,
                filters: [{ name: 'Excel', extensions: ['xls'] }]
            });
            
            if (filePath) {
                await saveFileSecure(filePath, xmlContent);
                if (tauriDialog?.message) {
                    await tauriDialog.message('Файл успешно сохранён!', { title: 'Успех' });
                } else {
                    alert('Файл успешно сохранён!');
                }
            }
            return;
        } catch (e) {
            console.error('Ошибка сохранения:', e);
            if (tauriDialog?.message) {
                await tauriDialog.message(String(e), { title: 'Ошибка', kind: 'error' });
            } else {
                alert('Ошибка: ' + e);
            }
            return;
        }
    }
    
    // Fallback на браузерный метод
    const blob = new Blob([xmlContent], { type: 'application/vnd.ms-excel' });
    const link = document.createElement('a');
    const url = URL.createObjectURL(blob);
    link.href = url;
    link.download = fileName;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// === УПРАВЛЕНИЕ ТЕХКАРТАМИ ===
function getCardData() {
    return Array.from(document.querySelectorAll('.op-block')).map(b => ({
        name: sanitizeInput(b.querySelector('.op-header-input').value, 200),
        dur: Math.max(0, Number.parseFloat(b.querySelector('.op-duration').value) || 0),
        unit: b.querySelector('.op-unit').value,
        hasBreak: b.querySelector('.order-pause-toggle').checked,
        breakVal: Math.max(0, Number.parseFloat(b.querySelector('.op-break-val').value) || 0),
        breakUnit: b.querySelector('.op-break-unit').value
    }));
}

function setCardData(steps) {
    if (!validateCardData(steps)) {
        alert('Ошибка: некорректные данные шаблона');
        return;
    }

    document.getElementById('totalOps').value = Math.min(steps.length, 50);
    container.textContent = '';
    renderFields();

    const blocks = document.querySelectorAll('.op-block');
    
    // Сначала устанавливаем единицу для первой операции
    if (steps[0] && blocks[0]) {
        blocks[0].querySelector('.op-unit').value = steps[0].unit;
    }
    
    steps.forEach((s, i) => {
        if (!blocks[i]) return;
        blocks[i].querySelector('.op-header-input').value = sanitizeInput(s.name, 200);
        blocks[i].querySelector('.op-duration').value = Math.max(0, Number.parseFloat(s.dur) || 0);
        // Для всех операций кроме первой единица будет синхронизирована
        if (i === 0) {
            blocks[i].querySelector('.op-unit').value = s.unit;
        }

        if (s.hasBreak) {
            const chk = blocks[i].querySelector('.order-pause-toggle');
            chk.checked = true;
            chk.dispatchEvent(new Event('change'));
            blocks[i].querySelector('.op-break-val').value = Math.max(0, Number.parseFloat(s.breakVal) || 0);
            blocks[i].querySelector('.op-break-unit').value = s.breakUnit || 'min';
        }
    });
    
    // Синхронизируем единицы времени всех операций с первой
    syncTimeUnits();
}

function loadTechCards() {
    const userGroup = document.getElementById('userCards');
    userGroup.textContent = '';
    Object.keys(localStorage)
        .filter(k => k.startsWith('z7_card_'))
        .forEach(k => {
            userGroup.append(createEl('option', { value: k }, k.replace('z7_card_', '')));
        });
}

// === ПРИВЯЗКА СОБЫТИЙ ===
document.getElementById('chainMode').addEventListener('change', () => {
    updateStartTimeFromHistory();
    updateFirstPauseVisibility();
});
document.getElementById('totalOps').addEventListener('change', renderFields);
document.getElementById('totalOps').addEventListener('keyup', renderFields);
document.getElementById('generateBtn').addEventListener('click', generateTable);

document.getElementById('clearBtn').addEventListener('click', async () => {
    let confirmed = false;
    
    if (tauriDialog?.confirm) {
        try {
            confirmed = await tauriDialog.confirm('Очистить все поля?', {
                title: 'Подтверждение',
                kind: 'warning'
            });
        } catch (e) {
            confirmed = globalThis.confirm('Очистить все поля?');
        }
    } else {
        confirmed = globalThis.confirm('Очистить все поля?');
    }
    
    if (confirmed) {
        container.textContent = '';
        document.getElementById('totalOps').value = 1;
        renderFields();
    }
});

document.getElementById('saveCardBtn').addEventListener('click', async () => {
    let name = null;
    
    // Tauri v2 не имеет встроенного prompt, используем fallback на globalThis.prompt
    // но оборачиваем в try-catch для безопасности
    try {
        name = globalThis.prompt("Название шаблона (техкарты):");
    } catch (e) {
        console.error('Prompt error:', e);
        return;
    }
    
    if (!name) return;

    name = sanitizeInput(name, 100);
    if (name.length === 0) {
        if (tauriDialog?.message) {
            await tauriDialog.message('Название не может быть пустым', { title: 'Ошибка', kind: 'error' });
        } else {
            alert('Название не может быть пусто');
        }
        return;
    }

    await safeLocalStorageSet('z7_card_' + name, JSON.stringify(getCardData()));
    loadTechCards();
    
    // Уведомление об успешном сохранении
    if (tauriDialog?.message) {
        await tauriDialog.message(`Шаблон "${name}" сохранён`, { title: 'Успешно' });
    }
});

document.getElementById('deleteCardBtn').addEventListener('click', async () => {
    const sel = document.getElementById('techCardSelect');
    if (sel.value === 'manual') return;

    let confirmed = false;
    
    if (tauriDialog?.confirm) {
        try {
            confirmed = await tauriDialog.confirm('Удалить шаблон?', {
                title: 'Подтверждение',
                kind: 'warning'
            });
        } catch (e) {
            confirmed = globalThis.confirm('Удалить?');
        }
    } else {
        confirmed = globalThis.confirm('Удалить?');
    }
    
    if (confirmed) {
        await safeLocalStorageRemove(sel.value);
        loadTechCards();
        sel.value = 'manual';
    }
});

document.getElementById('techCardSelect').addEventListener('change', (e) => {
    if (e.target.value !== 'manual') {
        try {
            const data = safeJsonParse(localStorage.getItem(e.target.value));
            if (data) {
                setCardData(data);
            }
        } catch (err) {
            console.error('Ошибка загрузки шаблона:', err);
        }
    }
});

document.getElementById('exportBtn').addEventListener('click', async () => {
    const obj = {};
    Object.keys(localStorage)
        .filter(k => k.startsWith('z7_card_'))
        .forEach(k => {
            obj[k] = localStorage.getItem(k);
        });

    const jsonContent = JSON.stringify(obj, null, 2);
    const fileName = `z7_backup_${new Date().toISOString().slice(0, 10)}.json`;
    
    // Пробуем использовать Tauri API
    if (tauriDialog?.save && tauriInvoke) {
        try {
            const filePath = await tauriDialog.save({
                defaultPath: fileName,
                filters: [{ name: 'JSON', extensions: ['json'] }]
            });
            
            if (filePath) {
                await saveFileSecure(filePath, jsonContent);
                if (tauriDialog?.message) {
                    await tauriDialog.message('Файл успешно сохранён!', { title: 'Успех' });
                } else {
                    alert('Файл успешно сохранён!');
                }
            }
            return;
        } catch (e) {
            console.error('Ошибка сохранения:', e);
            if (tauriDialog.message) {
                await tauriDialog.message(String(e), { title: 'Ошибка', kind: 'error' });
            } else {
                alert('Ошибка: ' + e);
            }
            return;
        }
    }
    
    // Fallback на браузерный метод
    const a = document.createElement('a');
    const url = URL.createObjectURL(new Blob([jsonContent], { type: "application/json" }));
    a.href = url;
    a.download = fileName;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
});

document.getElementById('importBtn').addEventListener('click', () => {
    document.getElementById('fileInput').click();
});

document.getElementById('fileInput').addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (!file) return;
    
    // Проверка размера файла (макс 1 МБ)
    const MAX_FILE_SIZE = 1024 * 1024;
    if (file.size > MAX_FILE_SIZE) {
        alert('Ошибка: файл слишком большой (макс. 1 МБ)');
        e.target.value = '';
        return;
    }
    
    const reader = new FileReader();
    reader.onload = async (ev) => {
        try {
            const d = safeJsonParse(ev.target.result);
            if (!d || !validateImportData(d)) {
                alert('Ошибка: файл содержит некорректные данные');
                return;
            }

            for (const k of Object.keys(d)) {
                if (k.startsWith('z7_card_')) {
                    await safeLocalStorageSet(k, d[k]);
                }
            }

            loadTechCards();
            alert("Готово!");
        } catch (e) {
            alert("Ошибка при импорте: " + e.message);
        }
    };
    reader.readAsText(file);
    e.target.value = ''; // Сброс input для повторного выбора того же файла
});

// === ИНИЦИАЛИЗАЦИЯ ===
loadTechCards();
renderFields();
setupExcelExport();
restoreHistoryFromStorage();
updateFirstPauseVisibility();

// === МОДАЛЬНОЕ ОКНО "О ПРОГРАММЕ" ===
let aboutTextCache = null;

async function loadAboutText() {
    if (aboutTextCache) return aboutTextCache;
    try {
        const response = await fetch('about.txt');
        if (!response.ok) throw new Error('Failed to load about.txt');
        aboutTextCache = await response.text();
        return aboutTextCache;
    } catch (e) {
        console.error('Error loading about text:', e);
        return 'Ошибка загрузки информации о программе.';
    }
}

document.getElementById('aboutBtn').addEventListener('click', async () => {
    const modal = document.getElementById('aboutModal');
    const modalBody = document.getElementById('aboutModalBody');
    
    modalBody.textContent = 'Загрузка...';
    modal.classList.add('active');
    
    const text = await loadAboutText();
    modalBody.textContent = text;
});

document.getElementById('closeAboutModal').addEventListener('click', () => {
    document.getElementById('aboutModal').classList.remove('active');
});

document.getElementById('aboutModal').addEventListener('click', (e) => {
    if (e.target.id === 'aboutModal') {
        document.getElementById('aboutModal').classList.remove('active');
    }
});

// Закрытие по Escape
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        const modal = document.getElementById('aboutModal');
        if (modal && modal.classList.contains('active')) {
            modal.classList.remove('active');
        }
        const workersModal = document.getElementById('workersModal');
        if (workersModal && workersModal.classList.contains('active')) {
            workersModal.classList.remove('active');
        }
    }
});

// === МОДАЛЬНОЕ ОКНО НОМЕРОВ ИСПОЛНИТЕЛЕЙ ===
let workerIds = []; // Массив 8-значных номеров исполнителей

function getWorkerLabel(index) {
    // index начинается с 1
    if (workerIds[index - 1] && workerIds[index - 1].trim()) {
        return workerIds[index - 1].trim();
    }
    return String(index); // По умолчанию порядковый номер
}

function renderWorkersInputList() {
    const container = document.getElementById('workersInputList');
    const count = parseInt(document.getElementById('workerCount').value) || 1;
    container.innerHTML = '';
    
    for (let i = 1; i <= count; i++) {
        const row = createEl('div', { className: 'worker-input-row' });
        const label = createEl('label', {}, `Исполнитель ${i}:`);
        const input = createEl('input', {
            type: 'text',
            maxLength: '8',
            placeholder: '00000000',
            pattern: '[0-9]{8}'
        });
        input.value = workerIds[i - 1] || '';
        input.dataset.workerIndex = i - 1;
        
        // Разрешаем только цифры
        input.addEventListener('input', (e) => {
            e.target.value = e.target.value.replace(/[^0-9]/g, '').substring(0, 8);
        });
        
        row.append(label, input);
        container.append(row);
    }
}

function saveWorkerIds() {
    const inputs = document.querySelectorAll('#workersInputList input');
    workerIds = [];
    inputs.forEach((input, idx) => {
        const val = input.value.trim();
        // Если номер введён, проверяем что он 8-значный
        if (val && val.length === 8) {
            workerIds[idx] = val;
        } else if (val && val.length > 0 && val.length < 8) {
            // Дополняем нулями слева до 8 цифр
            workerIds[idx] = val.padStart(8, '0');
        } else {
            workerIds[idx] = '';
        }
    });
    document.getElementById('workersModal').classList.remove('active');
}

function resetWorkerIds() {
    workerIds = [];
    renderWorkersInputList();
}

document.getElementById('setWorkersBtn').addEventListener('click', () => {
    renderWorkersInputList();
    document.getElementById('workersModal').classList.add('active');
});

document.getElementById('closeWorkersModal').addEventListener('click', () => {
    document.getElementById('workersModal').classList.remove('active');
});

document.getElementById('workersModal').addEventListener('click', (e) => {
    if (e.target.id === 'workersModal') {
        document.getElementById('workersModal').classList.remove('active');
    }
});

document.getElementById('saveWorkersBtn').addEventListener('click', saveWorkerIds);
document.getElementById('resetWorkersBtn').addEventListener('click', resetWorkerIds);

// При изменении количества исполнителей обновляем модальное окно (если открыто)
document.getElementById('workerCount').addEventListener('change', () => {
    const modal = document.getElementById('workersModal');
    if (modal && modal.classList.contains('active')) {
        renderWorkersInputList();
    }
});
