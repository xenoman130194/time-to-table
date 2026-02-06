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

// Строгая санитизация для названий/описаний: допускаем буквы (лат/кириллица), цифры, запятую, точку, символ № и пробел
function sanitizeStrict(str, maxLength = 500) {
    if (typeof str !== 'string') return '';
    // Разрешаем: A-Z a-z, Cyrillic 00-F? (use 00-FF earlier) — use common Cyrillic range \u0400-\u04FF
    // цифры, запятая, точка, символ №, пробел
    const cleaned = String(str).replaceAll(/[^A-Za-z\u0400-\u04FF0-9,.№ ]+/g, '');
    return cleaned.substring(0, maxLength);
}

// Удаляет ведущий порядковый префикс вида "1) ", "2) " и т.п.
function stripOrdinalPrefix(str) {
    if (typeof str !== 'string') return '';
    return str.replace(/^\s*\d+\)\s*/, '');
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

// Санитизация числового ввода: допускаем до 5 цифр в целой части и до 2 цифр в дробной
function sanitizeDecimalInput(raw) {
    if (raw === null || raw === undefined) return '';
    let s = String(raw);
    // Оставляем только цифры и разделители . и ,
    s = s.replaceAll(/[^0-9.,]/g, '');
    // Найдём первый разделитель
    const m = s.match(/[.,]/);
    if (!m) {
        // Только целая часть, обрезаем до 5 цифр
        return s.slice(0, 5);
    }
    const sep = m[0];
    const idx = s.indexOf(sep);
    let intPart = s.slice(0, idx).replaceAll(/[.,]/g, '').slice(0, 5);
    let fracPart = s.slice(idx + 1).replaceAll(/[.,]/g, '').slice(0, 2);
    // Если дробная часть ещё пустая — возвращаем с точкой, чтобы пользователь мог продолжить вводить
    if (fracPart.length === 0) return intPart + '.';
    // Нормализуем разделитель на точку для дальнейшего парсинга
    return intPart + '.' + fracPart; // используем точку внутренно для парсинга
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
const postingDateInput = document.getElementById('postingDate');
// Устанавливаем текущую локальную дату (без проблем с UTC)
const today = new Date();
const yyyy = today.getFullYear();
const mm = String(today.getMonth() + 1).padStart(2, '0');
const dd = String(today.getDate()).padStart(2, '0');
startDateInput.value = `${yyyy}-${mm}-${dd}`;
if (postingDateInput) postingDateInput.value = `${yyyy}-${mm}-${dd}`;

const startTimeInput = document.getElementById('startTime');
const container = document.getElementById('fieldsContainer');
// Attach handler to timeMode selector to toggle worker UI
try {
    const timeModeEl = document.getElementById('timeMode');
    if (timeModeEl) {
        timeModeEl.addEventListener('change', () => updateWorkerUIByTimeMode());
    }
} catch (e) { console.debug?.('attach timeMode listener failed:', e?.message); }
// State for operations modal (moved early to avoid TDZ when functions run)
let operationFirstId = ''; // Первый 8-значный номер подтверждения
let lastOperationIndex = null; // Индекс операции, которая будет "последней"

// Ограничение ввода в поле 'Заказ' — только цифры
try {
    const orderInputEl = document.getElementById('orderName');
    if (orderInputEl) {
        orderInputEl.addEventListener('input', (e) => {
            // Оставляем только цифры
            e.target.value = e.target.value.replaceAll(/[^0-9]/g, '');
        });
        orderInputEl.setAttribute('inputmode', 'numeric');
        orderInputEl.setAttribute('autocomplete', 'off');
    }
} catch (e) {
    console.debug?.('Order input listener attach failed:', e?.message);
}

// Ограничение ввода в поле 'Rиз' — только цифры
try {
    const rizInputEl = document.getElementById('resIz');
    if (rizInputEl) {
        rizInputEl.addEventListener('input', (e) => {
            e.target.value = e.target.value.replaceAll(/[^0-9]/g, '');
        });
        rizInputEl.setAttribute('inputmode', 'numeric');
        rizInputEl.setAttribute('autocomplete', 'off');
    }
} catch (e) {
    console.debug?.('Riz input listener attach failed:', e?.message);
}

// Ограничение/санитизация ввода для длительности обеда (до 5 цифр + 2 дробных)
try {
    const lunchDurEl = document.getElementById('lunchDur');
    if (lunchDurEl) {
        lunchDurEl.addEventListener('input', (e) => {
            const v = sanitizeDecimalInput(e.target.value);
            e.target.value = v;
        });
        lunchDurEl.addEventListener('blur', (e) => {
            let v = sanitizeDecimalInput(e.target.value);
            if (v === '') v = '0';
            if (v.endsWith('.')) v = v + '0';
            e.target.value = v;
        });
        lunchDurEl.setAttribute('inputmode', 'decimal');
        lunchDurEl.setAttribute('autocomplete', 'off');
    }
} catch (e) {
    console.debug?.('lunchDur listener attach failed:', e?.message);
}

// Live character counters for statusBefore, workExtra, devRec (max 300)
try {
    const fields = ['statusBefore', 'workExtra', 'devRec'];
    fields.forEach(id => {
        const el = document.getElementById(id);
        const ctr = document.getElementById(id + '_counter');
        if (!el || !ctr) return;
        const update = () => {
            const max = Number.parseInt(el.getAttribute('maxlength') || '300', 10) || 300;
            const len = String(el.value || '').length;
            const remaining = Math.max(0, max - len);
            ctr.textContent = `осталось ${remaining} / ${max}`;
        };
        // Init
        update();
        el.addEventListener('input', update);
    });
} catch (e) {
    console.debug?.('char counter attach failed:', e?.message);
}

// Ограничение ввода в поле 'Коэф. K' — числа с максимум 2 десятичными знаками
try {
    const kInputEl = document.getElementById('coefK');
    if (kInputEl) {
        kInputEl.addEventListener('input', (e) => {
            let v = String(e.target.value || '');
            // Разрешаем цифры, точку и запятую. Удаляем остальные символы.
            v = v.replaceAll(/[^0-9.,]/g, '');
            // Оставляем только первый разделитель (точку или запятую) и максимум 2 знака дробной части
            const sepMatch = v.match(/[.,]/);
            if (sepMatch) {
                const sep = sepMatch[0];
                const idx = v.indexOf(sep);
                const intPart = v.slice(0, idx).replaceAll(/[.,]/g, '');
                const dec = v.slice(idx + 1).replaceAll(/[.,]/g, '').slice(0, 2);
                v = intPart + sep + dec;
            } else {
                // Нет разделителя — просто удалить все разделители
                v = v.replaceAll(/[.,]/g, '');
            }
            e.target.value = v;
        });
        kInputEl.setAttribute('inputmode', 'decimal');
        kInputEl.setAttribute('autocomplete', 'off');
    }
} catch (e) {
    console.debug?.('CoefK input listener attach failed:', e?.message);
}

// Live strict sanitization for several text fields: itemName, statusBefore, workExtra, devRec
try {
    const itemEl = document.getElementById('itemName');
    if (itemEl) {
        itemEl.addEventListener('input', (e) => {
            const v = sanitizeStrict(e.target.value || '', 70);
            e.target.value = v;
        });
    }

    const strictFields = ['statusBefore', 'workExtra', 'devRec'];
    strictFields.forEach(id => {
        const el = document.getElementById(id);
        if (!el) return;
        el.addEventListener('input', (e) => {
            const max = Number.parseInt(el.getAttribute('maxlength') || '300', 10) || 300;
            const v = sanitizeStrict(e.target.value || '', max);
            e.target.value = v;
            // update char counter if exists
            try {
                const ctr = document.getElementById(id + '_counter');
                if (ctr) {
                    const len = String(v).length;
                    const remaining = Math.max(0, max - len);
                    ctr.textContent = `осталось ${remaining} / ${max}`;
                }
            } catch (ee) {}
        });
    });
} catch (e) {
    console.debug?.('attach strict sanitizers failed:', e?.message);
}

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
                    let confirmed = false;
                    if (tauriDialog?.confirm) {
                        try {
                            confirmed = await tauriDialog.confirm('Удалить эту запись из истории?', { title: 'Подтверждение', kind: 'warning' });
                        } catch (e) {
                            console.error('Tauri confirm error:', e);
                            confirmed = globalThis.confirm('Удалить эту запись из истории?');
                        }
                    } else {
                        confirmed = globalThis.confirm('Удалить эту запись из истории?');
                    }
                    if (confirmed) {
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
                
                ['№', 'ПДТВ', 'Операция', 'Обед?', 'Пауза', `ФактРабота${restoreHeaderUnit}`, 'Дата проводки', 'Исполнитель', 'Дата Начала', 'Время Начала', 'Дата конца', 'Время конца'].forEach(text => {
                    trHead.append(createEl('th', {}, text));
                });
                thead.append(trHead);

                const tbody = createEl('tbody');
                data.rows.forEach((r, ri) => {
                    const tr = createEl('tr');
                    tr.append(
                        createEl('td', {}, ri + 1),
                        createEl('td', {}, r.opIdx),
                        createEl('td', { style: 'text-align:center; font-weight:600;' }, r.name),
                        createEl('td', {}, r.crossedLunch ? '🍽️' : ''),
                        createEl('td', { style: 'color: #555;' }, r.pauseText || ''),
                        createEl('td', {}, r.durText),
                        createEl('td', {}, r.postingDate || ''),
                        createEl('td', {}, r.worker),
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
                const thZ7 = createEl('th', { className: 'z7-header-common', colspan: '12' }, 'Z7');
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
    const historyList = document.getElementById('historyList');
    const isFirstCalculation = historyList.children.length === 0;

    // If this is the very first calculation (history empty), hide break input for the first operation
    try {
        const breakGroup = firstOpBlock.querySelector('.break-container');
        const breakInput = firstOpBlock.querySelector('.op-break-val');
        const breakUnit = firstOpBlock.querySelector('.op-break-unit');
        if (isFirstCalculation) {
            if (breakGroup) breakGroup.style.display = 'none';
            if (breakInput) {
                breakInput.value = '0';
                breakInput.dispatchEvent(new Event('input'));
            }
            if (breakUnit) breakUnit.value = 'min';
        } else {
            if (breakGroup) breakGroup.style.display = 'flex';
        }
    } catch (e) {
        console.debug?.('reset pause visibility error:', e?.message);
    }
}

function renderFields() {
    const targetCount = validateNumber(document.getElementById('totalOps').value, 1, 20);
    document.getElementById('totalOps').value = targetCount;
    
    // Валидация отрицательных значений для #workerCount
    let workerCount = Number.parseInt(document.getElementById('workerCount').value, 10);
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
    // If operations modal is open, re-render its inputs and recalculate confirmation numbers
    try {
        const oModal = document.getElementById('opsModal');
        if (oModal && oModal.classList.contains('active')) {
            renderOpsInputList();
            updateOpsCalculatedValues();
        }
    } catch (e) {
        console.debug?.('renderFields modal update error:', e?.message);
    }
        try { updateMainOperationLabels(); updateOperationInputPrefixes(); updateWorkerUIByTimeMode(); } catch (e) { /* ignore */ }
}

function createOperationBlock(index) {
    const block = createEl('div', { className: 'op-block' });
    // Operation number label (shows confirmation number if set, otherwise sequential index)
    const totalOpsCurrent = Number.parseInt(document.getElementById('totalOps')?.value || '0', 10) || 0;
    const opNumText = (typeof getOperationLabel === 'function') ? getOperationLabel(index, totalOpsCurrent) : String(index);
    const numLabel = createEl('div', { className: 'op-num-label' }, opNumText);

    const prefix = `${index}) `;
    const nameInp = createEl('input', {
        className: 'op-header-input',
        name: `op_name_${index}`,
        value: `${prefix}Операция №${index}`,
        type: 'text',
        placeholder: 'Название операции',
        maxlength: '200',
        autocomplete: 'off'
    });
    // Make the numeric prefix immutable: keep it at start, sanitize only the suffix
    try {
        const handleInput = (e) => {
            const el = e.target;
            let v = el.value || '';
            // remove any leading numeric prefix user might paste/type
            v = v.replace(/^\s*\d+\)\s*/, '');
            // sanitize only the meaningful part
            v = sanitizeStrict(v, 200);
            el.value = prefix + v;
            // keep caret after prefix
            const pos = Math.max(prefix.length, (el.selectionStart || 0));
            try { el.setSelectionRange(pos, pos); } catch (ee) {}
        };

        nameInp.addEventListener('input', handleInput);
        nameInp.addEventListener('focus', (e) => {
            const el = e.target;
            if ((el.selectionStart || 0) < prefix.length) {
                try { el.setSelectionRange(prefix.length, prefix.length); } catch (ee) {}
            }
        });

        nameInp.addEventListener('keydown', (e) => {
            const el = e.target;
            const selStart = el.selectionStart || 0;
            const selEnd = el.selectionEnd || 0;
            // prevent deleting or selecting the prefix
            if ((e.key === 'Backspace' || e.key === 'Delete') && selEnd <= prefix.length) {
                e.preventDefault();
            }
            // prevent selection that includes prefix and replacing it with typing
            if (e.key.length === 1 && selStart < prefix.length && selEnd <= prefix.length) {
                // place cursor after prefix before inserting
                try { el.setSelectionRange(prefix.length, prefix.length); } catch (ee) {}
            }
        });

        nameInp.addEventListener('paste', (e) => {
            e.preventDefault();
            const paste = (e.clipboardData || window.clipboardData).getData('text') || '';
            const sanitized = sanitizeStrict(paste, 200);
            const el = e.target;
            const cur = el.value || '';
            const insertPos = Math.max(prefix.length, el.selectionStart || prefix.length);
            const before = cur.slice(prefix.length, insertPos);
            const after = cur.slice(insertPos);
            const newBody = (before + sanitized + after).slice(0, 200);
            el.value = prefix + sanitizeStrict(newBody, 200);
            const pos = prefix.length + Math.min(newBody.length, 200);
            try { el.setSelectionRange(pos, pos); } catch (ee) {}
        });
    } catch (e) {
        console.debug?.('op name input attach failed:', e?.message);
    }
    
    
    const controls = createEl('div', { className: 'op-controls' });

    // Исполнители: чекбоксы под названием операции
    const workersWrapper = createEl('div', { className: 'op-workers-wrapper' });
    workersWrapper.append(createEl('label', { className: 'op-workers-label' }, 'Исполнители:'));
    const workersBox = createEl('div', { className: 'op-workers-box' });
    // populate according to current workerCount
    try {
        const curCount = Number.parseInt(document.getElementById('workerCount')?.value || '1', 10) || 1;
        for (let w = 1; w <= curCount; w++) {
            const id = `op_${index}_worker_${w}`;
            const cb = createEl('input', { type: 'checkbox', className: 'op-worker-checkbox', id, 'data-worker': String(w) });
            cb.checked = true;
            const lbl = createEl('label', { htmlFor: id, className: 'op-worker-label' }, String(w));
            const wrapper = createEl('span', { className: 'op-worker-item' });
            wrapper.append(cb, lbl);
            workersBox.append(wrapper);

            // propagate unchecked to subsequent ops
            cb.addEventListener('change', (e) => {
                if (!cb.checked) {
                    try {
                        const blocks = Array.from(document.querySelectorAll('.op-block'));
                        const curIdx = blocks.indexOf(block);
                        if (curIdx >= 0) {
                            for (let bi = curIdx + 1; bi < blocks.length; bi++) {
                                const other = blocks[bi].querySelector(`.op-worker-checkbox[data-worker="${w}"]`);
                                if (other) other.checked = false;
                            }
                        }
                    } catch (err) { console.debug?.('propagate worker checkbox change error', err?.message); }
                }
            });
        }
    } catch (err) {
        console.debug?.('init op workers failed:', err?.message);
    }
    workersWrapper.append(workersBox);
    // Element shown when all workers apply (replaces checkboxes in non-individual mode)
    const workersAll = createEl('div', { className: 'op-workers-all', style: 'display:none;' }, 'ВСЕ');
    workersWrapper.append(workersAll);
    
    // Блок времени работы
    const workGroup = createEl('div', { className: 'time-group' });
    workGroup.append(createEl('label', { htmlFor: `op_duration_${index}` }, 'Время:'));
    const workInput = createEl('input', {
        type: 'text',
        className: 'op-duration',
        id: `op_duration_${index}`,
        name: `op_duration_${index}`,
        inputmode: 'decimal',
        pattern: '\\d{0,5}([.,]\\d{1,2})?',
        maxlength: '8',
        size: '6',
        style: 'width:8ch',
        value: '10',
        autocomplete: 'off'
    });
    // Санитизация и ограничение ввода: до 5 цифр целой части и 2 дробных
    workInput.addEventListener('input', (e) => {
        const v = sanitizeDecimalInput(e.target.value);
        e.target.value = v;
    });
    workInput.addEventListener('blur', (e) => {
        let v = sanitizeDecimalInput(e.target.value);
        if (v === '') v = '0';
        // Если пользователь оставил только разделитель, дополним 0:  '10.' -> '10.0'
        if (v.endsWith('.')) v = v + '0';
        e.target.value = v;
    });
    workGroup.append(workInput);
    // placeholder shown when mode == individual
    const workAll = createEl('div', { className: 'op-dur-all', style: 'display:none;' }, 'В Excel');
    workGroup.append(workAll);
    const workUnit = createEl('select', {
        className: 'op-unit',
        name: `op_unit_${index}`,
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
    
    // Блок паузы между заказами (видим во всех карточках, кроме первой операции первой записи)
    const breakGroup = createEl('div', { className: 'time-group break-container' });
    // Visible label for the break input — use same style as 'Время' label
    breakGroup.append(createEl('label', { htmlFor: `op_break_${index}` }, 'Пауза:'));
    const breakInput = createEl('input', {
        type: 'text',
        className: 'op-break-val',
        id: `op_break_${index}`,
        name: `op_break_${index}`,
        inputmode: 'decimal',
        pattern: '\\d{0,5}([.,]\\d{1,2})?',
        maxlength: '8',
        size: '6',
        style: 'width:8ch',
        value: '0',
        autocomplete: 'off'
    });
    // Санитизация и ограничение ввода: до 5 цифр целой части и 2 дробных
    breakInput.addEventListener('input', (e) => {
        const v = sanitizeDecimalInput(e.target.value);
        e.target.value = v;
    });
    breakInput.addEventListener('blur', (e) => {
        let v = sanitizeDecimalInput(e.target.value);
        if (v === '') v = '0';
        if (v.endsWith('.')) v = v + '0';
        e.target.value = v;
    });
    breakGroup.append(breakInput);
    const breakUnit = createEl('select', {
        className: 'op-break-unit',
        name: `op_break_unit_${index}`,
        style: 'width:70px; background:transparent; border:none;'
    });
    breakUnit.append(
        new Option('мин', 'min'),
        new Option('час', 'hour')
    );
    breakGroup.append(breakUnit);
    const breakAll = createEl('div', { className: 'op-break-all', style: 'display:none;' }, 'В Excel');
    breakGroup.append(breakAll);
    
    // Append break group and controls. Initial visibility for breakGroup
    // Default visibility: show break for all ops except first (first is managed by updateFirstPauseVisibility)
    if (index !== 1) {
        breakGroup.style.display = 'flex';
    } else {
        breakGroup.style.display = 'none';
    }
    controls.append(breakGroup, workGroup);
    // name input + workers UI
    const nameCol = createEl('div', { className: 'op-name-col' });
    nameCol.append(nameInp, workersWrapper);
    block.append(numLabel, nameCol, controls);
    container.append(block);
    
    // Обновить видимость паузы первого блока после создания нового блока
    updateFirstPauseVisibility();
    // Ensure worker UI reflects current timeMode selection
    try { updateWorkerUIByTimeMode(); } catch (e) {}
}

// Toggle per-operation worker checkboxes visibility according to #timeMode
function updateWorkerUIByTimeMode() {
    const modeEl = document.getElementById('timeMode');
    if (!modeEl) return;
    const mode = modeEl.value;
    const blocks = Array.from(document.querySelectorAll('.op-block'));
    blocks.forEach(block => {
        const box = block.querySelector('.op-workers-box');
        const allEl = block.querySelector('.op-workers-all');
        const workInput = block.querySelector('.op-duration');
        const workAll = block.querySelector('.op-dur-all');
        const breakInput = block.querySelector('.op-break-val');
        const breakUnit = block.querySelector('.op-break-unit');
        const breakAll = block.querySelector('.op-break-all');
        if (!box || !allEl) return;
        if (mode === 'individual') {
            // Individual: show per-op worker checkboxes, hide numeric inputs and show 'В Excel' placeholders
            box.style.display = 'grid';
            allEl.style.display = 'none';
            if (workInput) {
                workInput.style.display = 'none';
            }
            if (workAll) workAll.style.display = '';
            if (breakInput) {
                breakInput.style.display = 'none';
            }
            if (breakUnit) breakUnit.style.display = 'none';
            if (breakAll) breakAll.style.display = '';
        } else {
            // total / per_worker: hide per-op worker checkboxes and show unified inputs
            const cbs = Array.from(box.querySelectorAll('.op-worker-checkbox'));
            cbs.forEach(cb => { cb.checked = true; });
            box.style.display = 'none';
            allEl.style.display = 'inline-flex';
            if (workInput) workInput.style.display = '';
            if (workAll) workAll.style.display = 'none';
            if (breakInput) { breakInput.style.display = ''; }
            if (breakUnit) { breakUnit.style.display = ''; }
            if (breakAll) breakAll.style.display = 'none';
        }
    });
}

async function generateTable() {
    const tableResult = document.getElementById('tableResult');
    const z7Result = document.getElementById('z7Result');
    tableResult.textContent = '';
    z7Result.textContent = '';

    const startD = document.getElementById('startDate').value;
    const startT = document.getElementById('startTime').value;
    const postingD = (document.getElementById('postingDate') && document.getElementById('postingDate').value) ? document.getElementById('postingDate').value : startD;
    const workerCount = validateNumber(document.getElementById('workerCount').value, 1, 10);
    const timeMode = document.getElementById('timeMode').value;
    const lunchStartInput = document.getElementById('lunchStart').value;
    const lunchStartInput2 = document.getElementById('lunchStart2').value;
    // Lunch duration may be fractional now; parse as float and clamp between 0 and 480
    let lunchDurMin = Number.parseFloat(String(document.getElementById('lunchDur').value).replace(',', '.')) || 0;
    if (!Number.isFinite(lunchDurMin)) lunchDurMin = 0;
    lunchDurMin = Math.max(0, Math.min(480, lunchDurMin));
    const isChain = document.getElementById('chainMode').checked;
    // Validate select values to expected enums
    if (timeMode !== 'per_worker' && timeMode !== 'total' && timeMode !== 'individual') {
        console.warn('Unexpected timeMode value, defaulting to "total"');
    }
    
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
    
    // Пер-операционная пауза будет применяться перед каждой операции в цикле ниже
    
    // --- 
    
    // --- Настройка обедов (JS) ---
    // Validate lunch time format (HH:MM or HH:MM:SS)
    const timeRe = /^(\d{1,2}):(\d{2})(?::(\d{2}))?$/;
    let lh = 0, lm = 0;
    try {
        const m = String(lunchStartInput || '').match(timeRe);
        if (m) { lh = Number(m[1]); lm = Number(m[2]); } else { throw new Error('invalid lunchStart'); }
    } catch (e) {
        lh = 12; lm = 0; // fallback to noon
    }
    let lunchStartTime = new Date(y, m - 1, d, lh, lm, 0);
    let lunchEndTime = new Date(lunchStartTime.getTime() + lunchDurMin * 60000);

    // Второй обед
    let lh2 = 0, lm2 = 0;
    try {
        const m2 = String(lunchStartInput2 || '').match(timeRe);
        if (m2) { lh2 = Number(m2[1]); lm2 = Number(m2[2]); } else { throw new Error('invalid lunchStart2'); }
    } catch (e) {
        lh2 = 0; lm2 = 0; // fallback to midnight
    }
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
        // Удаляем возможный префикс вида "N) " перед санитаризацией
        const rawOpName = block.querySelector('.op-header-input').value || '';
        const name = sanitizeStrict(stripOrdinalPrefix(rawOpName), 200);
        operationNames.push(name);
        const dur = Math.max(0, Number.parseFloat(block.querySelector('.op-duration').value) || 0);
        let unit = block.querySelector('.op-unit').value;
        if (unit !== 'min' && unit !== 'hour') unit = 'min';

        // Original duration in ms (from card inputs)
        let origDurationMs = 0;
        if (unit === 'hour') origDurationMs = dur * 3600 * 1000;
        else origDurationMs = dur * 60 * 1000;

        // Decide what duration is used for calculations vs what is shown/exported
        let durationMsForCalc = origDurationMs;
        let displayDurVal = dur; // value used for display/export in tables/Excel
        if (timeMode === 'total' && workerCount > 1) {
            durationMsForCalc = origDurationMs / workerCount;
            displayDurVal = displayDurVal / workerCount;
        }
        // In 'individual' mode we keep the stored values in UI/export, but treat durations as zero for timeline calculations
        if (timeMode === 'individual') {
            durationMsForCalc = 0;
            // displayDurVal remains dur so cards keep their values and Excel cells can be prefilled with original durations
        }

        // Apply per-operation break BEFORE starting this operation (even if 0)
        const opBreakVal = Math.max(0, Number.parseFloat(block.querySelector('.op-break-val').value) || 0);
        let opBreakUnit = block.querySelector('.op-break-unit')?.value || 'min';
        if (opBreakUnit !== 'min' && opBreakUnit !== 'hour') opBreakUnit = 'min';
        const opBreakSec = (opBreakUnit === 'hour') ? (opBreakVal * 3600) : (opBreakVal * 60);
        const origOpBreakMs = Math.floor(opBreakSec * 1000);
        const opBreakMsForCalc = (timeMode === 'individual') ? 0 : origOpBreakMs;
        globalTime = new Date(globalTime.getTime() + opBreakMsForCalc);

        let opStart = new Date(globalTime);
        let opEnd = new Date(opStart.getTime() + durationMsForCalc);
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
                opEnd = new Date(opStart.getTime() + durationMsForCalc);
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
            // If a checkbox for this worker exists on this operation and is unchecked, skip creating rows for them
            try {
                const cb = block.querySelector(`.op-worker-checkbox[data-worker="${w}"]`);
                if (cb && !cb.checked) continue;
            } catch (err) { /* ignore selector errors */ }
            // Пауза операции (показываем текстовое значение, если >0)
            const rowPauseText = opBreakVal > 0 ? formatDurationToTime(opBreakVal, opBreakUnit) : "";
            const rowPauseExcel = opBreakSec / 86400.0;

            dataMain.push({
                opIdx: getOperationLabel(opIndex + 1, ops.length), // Номер подтверждения или порядковый номер
                opNumeric: opIndex + 1, // Числовой индекс для Excel формул
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
                postingDateIso: postingD,
                postingDate: fmtDate(new Date(postingD + 'T00:00:00')),
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

    const tblOps = createSubTable(['№', 'ПДТВ', 'Операция', 'Обед?', 'Пауза'], 2);
    
    // Определяем единицу измерения для заголовка ФактРабота
    let headerUnit = "";
    const uniqueUnits = [...new Set(dataMain.map(r => r.unit || 'min'))];
    if (uniqueUnits.length === 1) {
        if (uniqueUnits[0] === 'min') headerUnit = " (мин)";
        else if (uniqueUnits[0] === 'hour') headerUnit = " (час)";
    }
    
    const tblDur = createSubTable([`ФактРабота${headerUnit}`], 1);
    const tblPostingDate = createSubTable(['Дата проводки'], 1);
    const tblWorker = createSubTable(['Исполнитель'], 1);
    const tblTime = createSubTable(['Дата Начала', 'Время Начала', 'Дата конца', 'Время конца'], 3);

    dataMain.forEach((row, ri) => {
        const trOps = createEl('tr');
        trOps.append(
            createEl('td', {}, ri + 1),
            createEl('td', {}, row.opIdx),
            createEl('td', { style: 'text-align:center; font-weight:600;' }, row.name),
            createEl('td', { style: 'font-size: 24px; line-height: 1; padding: 4px 12px;' }, row.crossedLunch ? '🍽️' : ''),
            createEl('td', { style: 'color: #555;' }, row.pauseText || '')
        );
        tblOps.tbody.append(trOps);

        const trDur = createEl('tr');
        trDur.append(createEl('td', {}, row.durText));
        tblDur.tbody.append(trDur);

        const trPostingDate = createEl('tr');
        trPostingDate.append(createEl('td', {}, row.postingDate || ''));
        tblPostingDate.tbody.append(trPostingDate);

        const trWorker = createEl('tr');
        trWorker.append(createEl('td', {}, row.worker));
        tblWorker.tbody.append(trWorker);

        const trTime = createEl('tr');
        trTime.append(
            createEl('td', {}, row.startDate),
            createEl('td', {}, row.startTime),
            createEl('td', {}, row.endDate),
            createEl('td', {}, row.endTime)
        );
        tblTime.tbody.append(trTime);
    });

    tableResult.append(tblOps.wrapper, tblDur.wrapper, tblPostingDate.wrapper, tblWorker.wrapper, tblTime.wrapper);

    const statusText = sanitizeStrict(document.getElementById('statusBefore').value, 300) || "замечаний нет";
    const extraWorks = sanitizeStrict(document.getElementById('workExtra').value, 300) || "нет";
    const devRec = sanitizeStrict(document.getElementById('devRec').value, 300) || "нет";
    const rizVal = sanitizeInput(document.getElementById('resIz').value, 6) || "";
    const kVal = sanitizeInput(document.getElementById('coefK').value, 5) || "";
        const kValForZ7 = kVal.replace(',', '.');
    const worksText = operationNames.join(', ');
    const rizDisplay = rizVal ? `${rizVal} МОм` : "";

    const z7Lines = [
        `1. состояние объекта ремонта до начала работ: ${statusText}`,
        `2. выполненные работы в рамках планового объёма работ: ${worksText}`,
        `3. выполненные работы в рамках дополнительного объёма работ: ${extraWorks}`,
            `4. результаты испытаний, тестов, замеров, инспекций: Rиз= ${rizDisplay} K= ${kValForZ7}`,
        `5. отклонения от ТК и рекомендации по корректировке ТК: ${devRec}`
    ];
    
    const z7Div = createEl('div', { className: 'z7-report-wrapper' });
    const z7Table = createEl('table', { className: 'z7-table' });
    const z7Head = createEl('thead');
    const thZ7 = createEl('th', { className: 'z7-header-common', colspan: '12' }, 'Z7');
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
    const cardNameBase = select.value === 'manual' ? 'Ручной ввод' : select.options[select.selectedIndex].text;
    const orderInput = sanitizeInput(document.getElementById('orderName')?.value || '', 12);
    const nameInput = sanitizeStrict(document.getElementById('itemName')?.value || '', 70);
    const cardName = (orderInput ? (orderInput + ' ') : '') + (nameInput ? nameInput : cardNameBase);
    
    const lunchConfig = { h: lh, m: lm, h2: lh2, m2: lm2, dur: lunchDurMin };
    
    // orderPauseConfig сохраняем для совместимости, но данные уже в строках
    const orderPauseConfig = { dur: 0, unit: 'min', isApplied: !isFirstCalculation }; // Dummy values as actual are in rows
    await addToHistoryTable(dataMain, cardName, z7Lines, lunchConfig, isChain, orderPauseConfig, timeMode);
}

async function addToHistoryTable(data, cardName, z7LinesArray, lunchConfig, isChain, orderPauseConfig, timeMode) {
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
            orderPause: orderPauseConfig,
            timeMode: timeMode || 'total'
        });

        const header = createEl('div', { className: 'history-header' });
        const leftSpan = createEl('span');
        const bName = createEl('b', {}, cardName);
        leftSpan.append(bName, document.createTextNode(` (${timestamp})`));

        const rightSpan = createEl('span', { style: 'display:flex; align-items:center;' });
        const infoText = createEl('span', { style: 'font-size:12px' }, ` Строк: ${data.length}`);
        const delBtn = createEl('button', { className: 'btn-sm btn-del-history' }, 'Удалить');
        delBtn.onclick = async () => {
            let confirmed = false;
            if (tauriDialog?.confirm) {
                try {
                    confirmed = await tauriDialog.confirm('Удалить эту запись из истории?', { title: 'Подтверждение', kind: 'warning' });
                } catch (e) {
                    console.error('Tauri confirm error:', e);
                    confirmed = globalThis.confirm('Удалить эту запись из истории?');
                }
            } else {
                confirmed = globalThis.confirm('Удалить эту запись из истории?');
            }
            if (confirmed) {
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
        
        ['№', 'ПДТВ', 'Операция', 'Обед?', 'Пауза', `ФактРабота${histHeaderUnit}`, 'Дата проводки', 'Исполнитель', '-', 'Дата Начала', 'Время Начала', 'Дата конца', 'Время конца'].forEach(text => {
            trHead.append(createEl('th', {}, text));
        });
        thead.append(trHead);

        const tbody = createEl('tbody');
        data.forEach((r, ri) => {
            const tr = createEl('tr');
            tr.append(
                createEl('td', {}, ri + 1),
                createEl('td', {}, r.opIdx),
                createEl('td', { style: 'text-align:center;' }, r.name),
                createEl('td', {}, r.crossedLunch ? '🍽️' : ''),
                createEl('td', { style: 'color: #555;' }, r.pauseText || ''),
                createEl('td', {}, r.durText),
                createEl('td', {}, r.postingDate || ''),
                    createEl('td', {}, r.worker),
                    createEl('td', {}, ''),
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
        const thZ7 = createEl('th', { className: 'z7-header-common', colspan: '12' }, 'Z7');
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

// Undo / Redo support (Ctrl+Z / Ctrl+Y / Ctrl+Shift+Z)

// In-memory undo/redo stacks. We keep a small bounded history.
const _undoStack = [];
const _redoStack = [];
const _UNDO_LIMIT = 100;
let _snapshotTimer = null;
const _SNAPSHOT_DEBOUNCE = 500;

function captureAppState() {
    const getVal = (id) => {
        const el = document.getElementById(id);
        return el ? el.value : null;
    };

    const state = {
        totalOps: Number(getVal('totalOps') || 0),
        workerCount: Number(getVal('workerCount') || 1),
        timeMode: getVal('timeMode') || 'total',
        startDate: getVal('startDate') || '',
        startTime: getVal('startTime') || '',
        postingDate: getVal('postingDate') || '',
        lunchStart: getVal('lunchStart') || '',
        lunchStart2: getVal('lunchStart2') || '',
        lunchDur: getVal('lunchDur') || '',
        orderName: getVal('orderName') || '',
        itemName: getVal('itemName') || '',
        statusBefore: getVal('statusBefore') || '',
        workExtra: getVal('workExtra') || '',
        devRec: getVal('devRec') || '',
        coefK: getVal('coefK') || '',
        ops: []
    };

    const blocks = document.querySelectorAll('.op-block');
    blocks.forEach(block => {
        const name = block.querySelector('.op-header-input')?.value || '';
        const dur = block.querySelector('.op-duration')?.value || '';
        const unit = block.querySelector('.op-unit')?.value || 'min';
        const breakVal = block.querySelector('.op-break-val')?.value || '';
        const breakUnit = block.querySelector('.op-break-unit')?.value || 'min';
        const workerCbs = [];
        const cbs = block.querySelectorAll('.op-worker-checkbox');
        cbs.forEach(cb => workerCbs.push({ w: cb.getAttribute('data-worker'), checked: !!cb.checked }));
        state.ops.push({ name, dur, unit, breakVal, breakUnit, workers: workerCbs });
    });

    return state;
}

function restoreAppState(state) {
    if (!state || typeof state !== 'object') return;
    try {
        // Top-level fields
        if (document.getElementById('workerCount')) document.getElementById('workerCount').value = state.workerCount || 1;
        if (document.getElementById('totalOps')) document.getElementById('totalOps').value = state.totalOps || 1;
        if (document.getElementById('timeMode')) document.getElementById('timeMode').value = state.timeMode || 'total';
        if (document.getElementById('startDate')) document.getElementById('startDate').value = state.startDate || '';
        if (document.getElementById('startTime')) document.getElementById('startTime').value = state.startTime || '';
        if (document.getElementById('postingDate')) document.getElementById('postingDate').value = state.postingDate || state.startDate || '';
        if (document.getElementById('lunchStart')) document.getElementById('lunchStart').value = state.lunchStart || '';
        if (document.getElementById('lunchStart2')) document.getElementById('lunchStart2').value = state.lunchStart2 || '';
        if (document.getElementById('lunchDur')) document.getElementById('lunchDur').value = state.lunchDur || '';
        if (document.getElementById('orderName')) document.getElementById('orderName').value = state.orderName || '';
        if (document.getElementById('itemName')) document.getElementById('itemName').value = state.itemName || '';
        if (document.getElementById('statusBefore')) document.getElementById('statusBefore').value = state.statusBefore || '';
        if (document.getElementById('workExtra')) document.getElementById('workExtra').value = state.workExtra || '';
        if (document.getElementById('devRec')) document.getElementById('devRec').value = state.devRec || '';
        if (document.getElementById('coefK')) document.getElementById('coefK').value = state.coefK || '';

        // Rebuild operation blocks to match desired count and then populate fields
        renderFields();
        const blocks = document.querySelectorAll('.op-block');
        blocks.forEach((block, idx) => {
            const row = state.ops[idx];
            if (!row) return;
            const nameInp = block.querySelector('.op-header-input');
            if (nameInp) nameInp.value = row.name;
            const durInp = block.querySelector('.op-duration');
            if (durInp) durInp.value = row.dur;
            const unitSel = block.querySelector('.op-unit');
            if (unitSel) unitSel.value = row.unit || 'min';
            const breakInp = block.querySelector('.op-break-val');
            if (breakInp) breakInp.value = row.breakVal;
            const breakUnit = block.querySelector('.op-break-unit');
            if (breakUnit) breakUnit.value = row.breakUnit || 'min';
            const cbs = block.querySelectorAll('.op-worker-checkbox');
            cbs.forEach(cb => {
                const w = cb.getAttribute('data-worker');
                const found = (row.workers || []).find(x => String(x.w) === String(w));
                if (found) cb.checked = !!found.checked;
            });
        });

        // Refresh UI states
        try { updateWorkerUIByTimeMode(); syncTimeUnits(); updateFirstPauseVisibility(); } catch (e) {}
    } catch (e) {
        console.error('restoreAppState error:', e);
    }
}

function _pushUndoSnapshot() {
    try {
        const s = captureAppState();
        // Avoid pushing duplicate consecutive states
        const last = _undoStack[_undoStack.length - 1];
        if (JSON.stringify(last) === JSON.stringify(s)) return;
        _undoStack.push(s);
        if (_undoStack.length > _UNDO_LIMIT) _undoStack.shift();
        // New action clears redo stack
        _redoStack.length = 0;
    } catch (e) { console.debug?.('pushUndo error', e?.message); }
}

function scheduleSnapshotDebounced() {
    if (_snapshotTimer) clearTimeout(_snapshotTimer);
    _snapshotTimer = setTimeout(() => { _pushUndoSnapshot(); _snapshotTimer = null; }, _SNAPSHOT_DEBOUNCE);
}

function undo() {
    if (_undoStack.length === 0) return;
    try {
        const current = captureAppState();
        _redoStack.push(current);
        const prev = _undoStack.pop();
        restoreAppState(prev);
    } catch (e) { console.error('undo error', e); }
}

function redo() {
    if (_redoStack.length === 0) return;
    try {
        const curr = captureAppState();
        _undoStack.push(curr);
        const next = _redoStack.pop();
        restoreAppState(next);
    } catch (e) { console.error('redo error', e); }
}

// Initial snapshot after load
window.addEventListener('load', () => { try { _pushUndoSnapshot(); } catch (e) {} });

// Keyboard shortcuts: Ctrl/Cmd+Z = undo, Ctrl/Cmd+Y or Ctrl+Shift+Z = redo
document.addEventListener('keydown', (e) => {
    const key = (e.key || '').toLowerCase();
    const mod = (e.ctrlKey || e.metaKey);
    if (!mod) return;
    if (!e.shiftKey && key === 'z') {
        e.preventDefault();
        undo();
    } else if (key === 'y' || (e.shiftKey && key === 'z')) {
        e.preventDefault();
        redo();
    }
});

// Debounced snapshots for user edits: inputs inside the main container and some top-level controls
const _snapshotTargets = ['totalOps','workerCount','timeMode','startDate','startTime','postingDate','lunchStart','lunchStart2','lunchDur','orderName','itemName','statusBefore','workExtra','devRec','coefK'];
_snapshotTargets.forEach(id => {
    const el = document.getElementById(id);
    if (!el) return;
    el.addEventListener('input', scheduleSnapshotDebounced);
    el.addEventListener('change', scheduleSnapshotDebounced);
});
// delegate input events inside ops container
const _opsContainer = document.getElementById('fieldsContainer');
if (_opsContainer) {
    _opsContainer.addEventListener('input', scheduleSnapshotDebounced, true);
    _opsContainer.addEventListener('change', scheduleSnapshotDebounced, true);
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
    // Track absolute row number within the sheet to build absolute R1C1 ranges for INDEX/MATCH
    let sheetRow = 0;
    // Вставляем строку авторства в самый верх и пустую строку после неё
    xmlBody += `
    <Row ss:Height="50" ss:AutoFitHeight="0">
        <Cell ss:Index="2" ss:MergeAcross="13" ss:StyleID="sAuthor"><Data ss:Type="String">${escapeXml('Создано при помощи калькулятора для ленивых. Ленивым от ленивого. 🙂')}</Data></Cell>
    </Row>
    <Row>
        <Cell ss:Index="2" ss:MergeAcross="13" ss:StyleID="sTextLocked"><Data ss:Type="String"></Data></Cell>
    </Row>
    `;
    // Two rows emitted above
    sheetRow += 2;
    let previousEntryData = null;
    const entriesArray = Array.from(entries).reverse();

    entriesArray.forEach((entry, entryIndex) => {
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
            <Cell ss:Index="2" ss:MergeAcross="13" ss:StyleID="sTitle"><Data ss:Type="String">${escapeXml(excelSanitizeCell(data.title))}</Data></Cell>
        </Row>
        <Row>
            <Cell ss:Index="2" ss:StyleID="sHeader"><Data ss:Type="String">№</Data></Cell>
            <Cell ss:StyleID="sHeader"><Data ss:Type="String">ПДТВ</Data></Cell>
            <Cell ss:StyleID="sHeader"><Data ss:Type="String">Операция</Data></Cell>
            <Cell ss:StyleID="sHeader"><Data ss:Type="String">Обед?</Data></Cell>
            <Cell ss:StyleID="sHeader"><Data ss:Type="String">Пауза перед началом операции</Data></Cell>
            <Cell ss:StyleID="sHeader"><Data ss:Type="String">ФактРабота${headerUnit}</Data></Cell>
            <Cell ss:StyleID="sHeader"><Data ss:Type="String">Дата проводки</Data></Cell>
            <Cell ss:StyleID="sHeader"><Data ss:Type="String">Исполнитель</Data></Cell>
            <Cell ss:StyleID="sHeader"><Data ss:Type="String">-</Data></Cell>
            <Cell ss:StyleID="sHeader"><Data ss:Type="String">Дата Начала</Data></Cell>
            <Cell ss:StyleID="sHeader"><Data ss:Type="String">Время Начала</Data></Cell>
            <Cell ss:StyleID="sHeader"><Data ss:Type="String">Дата конца</Data></Cell>
            <Cell ss:StyleID="sHeader"><Data ss:Type="String">Время конца</Data></Cell>
            <Cell ss:StyleID="sHeader"><Data ss:Type="String">INDEX</Data></Cell>
        </Row>
        `;
        // Added two rows for title+header
        sheetRow += 2;

        // Preserve web order (by operation number); stable sort by opNumeric then workerIndex
        let rowsForExport = data.rows.slice().sort((a, b) => {
            const na = (a.opNumeric ?? a.opIdx) || 0;
            const nb = (b.opNumeric ?? b.opIdx) || 0;
            if (na !== nb) return na - nb;
            const wa = (a.workerIndex || 1);
            const wb = (b.workerIndex || 1);
            return wa - wb;
        });

        // Compute absolute row range for the data rows of this entry (used for INDEX/MATCH ranges)
        const dataStartRow = sheetRow + 1;
        const dataEndRow = dataStartRow + rowsForExport.length - 1;

        // Map to remember row index (within this entry) for a given opNumeric+workerIndex
        const rowPosMap = {};
        rowsForExport.forEach((r, idx) => {
            const startXml = formatXmlDate(new Date(r.startObj));
            const endXml = formatXmlDate(new Date(r.endObj));
            const postingXml = (r.postingDateIso) ? formatXmlDate(new Date(String(r.postingDateIso) + 'T00:00:00')) : startXml;
            const startTimeXml = formatXmlTime(new Date(r.startObj));
            const pauseVal = typeof r.pauseExcelVal === 'number' ? r.pauseExcelVal : 0;
            
            // Делитель для формул времени
            const unitDiv = (r.unit === 'hour') ? 24.0 : 1440.0;
            
            let startTimeCell;
            let durCell;
            // Используем opNumeric если есть, иначе fallback на opIdx для старых записей
            const curOpNum = r.opNumeric ?? r.opIdx;
            const prevRowOpNum = (idx > 0) ? (rowsForExport[idx - 1].opNumeric ?? rowsForExport[idx - 1].opIdx) : -1;
            const nextRowOpNum = (idx < rowsForExport.length - 1) ? (rowsForExport[idx + 1].opNumeric ?? rowsForExport[idx + 1].opIdx) : -1;
            // Detect group end (last row of an operation group)
            const isGroupEnd = (idx === rowsForExport.length - 1) || (curOpNum !== nextRowOpNum);
            // Style mapping: use Bottom variants when row is end of group to render a thick bottom border
            const styleMap = {
                borderLocked: isGroupEnd ? 'sBorderLockedBottom' : 'sBorderLocked',
                borderLeftLocked: isGroupEnd ? 'sBorderLeftLockedBottom' : 'sBorderLeftLocked',
                iconLocked: isGroupEnd ? 'sIconLockedBottom' : 'sIconLocked',
                timeLocked: isGroupEnd ? 'sTimeLockedBottom' : 'sTimeLocked',
                timeEditable: isGroupEnd ? 'sTimeEditableBottom' : 'sTimeEditable',
                durEditable: isGroupEnd ? 'sDurEditableBottom' : 'sDurEditable',
                durLocked: isGroupEnd ? 'sDurLockedBottom' : 'sDurLocked',
                dateLocked: isGroupEnd ? 'sDateLockedBottom' : 'sDateLocked'
            };
            
            // If the saved calculation used 'individual' mode, make all duration cells editable in Excel
            if (data.timeMode === 'individual') {
                durCell = `<Cell ss:StyleID="${styleMap.durEditable}"><Data ss:Type="Number">${r.durVal}</Data></Cell>`;
            } else {
                if (curOpNum === prevRowOpNum) {
                    durCell = `<Cell ss:StyleID="${styleMap.durLocked}" ss:Formula="=R[-1]C"><Data ss:Type="Number">${r.durVal}</Data></Cell>`;
                } else {
                    durCell = `<Cell ss:StyleID="${styleMap.durEditable}"><Data ss:Type="Number">${r.durVal}</Data></Cell>`;
                }
            }

            // Ячейка паузы — переносим реальное значение паузы для каждой операции/строки
            // Правила защиты:
            // - Первая операция первой записи: защищённая (locked) — значение из данных (обычно 0)
            // - Первая операция второй+ записей: значение из данных, editable для первого исполнителя, locked (formula) для остальных
            // - Вторая+ операции всех записей: значение из данных (обычно 0), editable для первого исполнителя, locked (formula) для остальных
            const isFirstEntryFirstOp = (entryIndex === 0 && curOpNum === 1);
            const isFirstOpOfEntry = (curOpNum === 1);
            const isFirstWorkerOfOp = (curOpNum !== prevRowOpNum);

            let pauseCell;
            if (isFirstEntryFirstOp) {
                // Первая операция первой записи - защищённая ячейка с реальным значением паузы
                if (r.workerIndex === 1) {
                    pauseCell = `<Cell ss:StyleID="${styleMap.timeLocked}"><Data ss:Type="Number">${pauseVal}</Data></Cell>`;
                } else {
                    pauseCell = `<Cell ss:StyleID="${styleMap.timeLocked}" ss:Formula="=R[-1]C"><Data ss:Type="Number">${pauseVal}</Data></Cell>`;
                }
            } else if (isFirstOpOfEntry) {
                // Первая операция второй+ записей - значение из данных
                if (r.workerIndex === 1) {
                    pauseCell = `<Cell ss:StyleID="${styleMap.timeEditable}"><Data ss:Type="Number">${pauseVal}</Data></Cell>`;
                } else {
                    pauseCell = `<Cell ss:StyleID="${styleMap.timeLocked}" ss:Formula="=R[-1]C"><Data ss:Type="Number">${pauseVal}</Data></Cell>`;
                }
            } else {
                // Вторая+ операции всех записей - значение из данных
                if (isFirstWorkerOfOp) {
                    pauseCell = `<Cell ss:StyleID="${styleMap.timeEditable}"><Data ss:Type="Number">${pauseVal}</Data></Cell>`;
                } else {
                    pauseCell = `<Cell ss:StyleID="${styleMap.timeLocked}" ss:Formula="=R[-1]C"><Data ss:Type="Number">${pauseVal}</Data></Cell>`;
                }
            }

            if (idx === 0) {
                if (isChain && previousEntryData) {
                    // offset = 5 (заголовок Z7 + разделители) + (z7.length * 2) т.к. после каждой строки Z7 пустая строка
                    const offset = 5 + (previousEntryData.z7.length * 2);
                    // Формула: (Конец пред. таблицы) + (Пауза этой строки), со сдвигом если попадает в обед
                    const rawTimeRef = `(R[-${offset}]C[2] + RC[-6])`;
                    const l1ValChain = `TIME(${lh},${lm},0)`;
                    const l1EndChain = `(TIME(${lh},${lm},0)+TIME(0,${ld},0))`;
                    const chainShiftCond1 = `AND(${rawTimeRef}>=${l1ValChain}, ${rawTimeRef}<${l1EndChain})`;
                    const hasLunch2Chain = !(lh2 === 0 && lm2 === 0);
                    let chainFormula;
                    if (hasLunch2Chain) {
                        const l2ValChain = `TIME(${lh2},${lm2},0)`;
                        const l2EndChain = `(TIME(${lh2},${lm2},0)+TIME(0,${ld},0))`;
                        const shifted1 = `IF(${chainShiftCond1},${l1EndChain},${rawTimeRef})`;
                        const chainShiftCond2 = `AND(${shifted1}>=${l2ValChain}, ${shifted1}<${l2EndChain})`;
                        chainFormula = `=MOD(IF(${chainShiftCond2},${l2EndChain},${shifted1}),1)`;
                    } else {
                        chainFormula = `=MOD(IF(${chainShiftCond1},${l1EndChain},${rawTimeRef}),1)`;
                    }
                    startTimeCell = `<Cell ss:StyleID="${styleMap.timeLocked}" ss:Formula="${escapeXml(chainFormula)}"><Data ss:Type="DateTime">${startTimeXml}</Data></Cell>`;
                } else {
                    // Если первая таблица или не цепочка - время фиксировано
                    startTimeCell = `<Cell ss:StyleID="${styleMap.timeEditable}"><Data ss:Type="DateTime">${startTimeXml}</Data></Cell>`;
                }
            } else {
                // For individual mode try to locate previous operation for the same worker using INDEX/MATCH
                if (data.timeMode === 'individual') {
                    if ((curOpNum || 0) > 1) {
                        const prevKey = `${(curOpNum - 1)}_${r.workerIndex || 1}`;
                        const keyCol = 15; // helper key column (_KEY) appended after end time (end time is col 14)
                        const endCol = 14;
                        const keyRange = `R${dataStartRow}C${keyCol}:R${dataEndRow}C${keyCol}`;
                        const endRange = `R${dataStartRow}C${endCol}:R${dataEndRow}C${endCol}`;
                        const lookupExpr = `INDEX(${endRange}, MATCH("${prevKey}", ${keyRange}, 0))`;
                        const l1ValStart = `TIME(${lh},${lm},0)`;
                        const l1EndStart = `(TIME(${lh},${lm},0)+TIME(0,${ld},0))`;
                        const rawTimeWithPause = `(${lookupExpr}+RC[-6])`;
                        const startShiftCond1 = `AND(${rawTimeWithPause}>=${l1ValStart}, ${rawTimeWithPause}<${l1EndStart})`;
                        let startFormula;
                        const hasLunch2Local = !(lh2 === 0 && lm2 === 0);
                        if (hasLunch2Local) {
                            const l2ValStart = `TIME(${lh2},${lm2},0)`;
                            const l2EndStart = `(TIME(${lh2},${lm2},0)+TIME(0,${ld},0))`;
                            const shifted1 = `IF(${startShiftCond1},${l1EndStart},${rawTimeWithPause})`;
                            const startShiftCond2 = `AND(${shifted1}>=${l2ValStart}, ${shifted1}<${l2EndStart})`;
                            startFormula = `=MOD(IF(${startShiftCond2},${l2EndStart},${shifted1}),1)`;
                        } else {
                            startFormula = `=MOD(IF(${startShiftCond1},${l1EndStart},${rawTimeWithPause}),1)`;
                        }
                        startTimeCell = `<Cell ss:StyleID="${styleMap.timeLocked}" ss:Formula="${escapeXml(startFormula)}"><Data ss:Type="DateTime">${startTimeXml}</Data></Cell>`;
                    } else {
                        // no previous op number -> fallback to previous-row logic
                        if (curOpNum === prevRowOpNum) {
                            startTimeCell = `<Cell ss:StyleID="${styleMap.timeLocked}" ss:Formula="=R[-1]C"><Data ss:Type="DateTime">${startTimeXml}</Data></Cell>`;
                        } else {
                            const l1ValStart = `TIME(${lh},${lm},0)`;
                            const l1EndStart = `(TIME(${lh},${lm},0)+TIME(0,${ld},0))`;
                            const rawTimeWithPause = `(R[-1]C[2]+RC[-6])`;
                            const startShiftCond1 = `AND(${rawTimeWithPause}>=${l1ValStart}, ${rawTimeWithPause}<${l1EndStart})`;
                            let startFormula;
                            const hasLunch2Local = !(lh2 === 0 && lm2 === 0);
                            if (hasLunch2Local) {
                                const l2ValStart = `TIME(${lh2},${lm2},0)`;
                                const l2EndStart = `(TIME(${lh2},${lm2},0)+TIME(0,${ld},0))`;
                                const shifted1 = `IF(${startShiftCond1},${l1EndStart},${rawTimeWithPause})`;
                                const startShiftCond2 = `AND(${shifted1}>=${l2ValStart}, ${shifted1}<${l2EndStart})`;
                                startFormula = `=MOD(IF(${startShiftCond2},${l2EndStart},${shifted1}),1)`;
                            } else {
                                startFormula = `=MOD(IF(${startShiftCond1},${l1EndStart},${rawTimeWithPause}),1)`;
                            }
                            startTimeCell = `<Cell ss:StyleID="${styleMap.timeLocked}" ss:Formula="${escapeXml(startFormula)}"><Data ss:Type="DateTime">${startTimeXml}</Data></Cell>`;
                        }
                    }
                } else {
                    if (curOpNum === prevRowOpNum) {
                        startTimeCell = `<Cell ss:StyleID="${styleMap.timeLocked}" ss:Formula="=R[-1]C"><Data ss:Type="DateTime">${startTimeXml}</Data></Cell>`;
                    } else {
                        // Начало операции (кроме первой) ссылается на конец предыдущей + пауза.
                        // Но если результат попадает в обед - сдвигаем на конец обеда.
                        const l1ValStart = `TIME(${lh},${lm},0)`;
                        const l1EndStart = `(TIME(${lh},${lm},0)+TIME(0,${ld},0))`;
                        // RC[-6] = пауза текущей строки (столбец E, Пауза)
                        const rawTimeWithPause = `(R[-1]C[2]+RC[-6])`;
                        // Условие: (prevEnd + pause) >= lunchStart AND (prevEnd + pause) < lunchEnd => сдвиг на lunchEnd
                        const startShiftCond1 = `AND(${rawTimeWithPause}>=${l1ValStart}, ${rawTimeWithPause}<${l1EndStart})`;
                        let startFormula;
                        const hasLunch2Local = !(lh2 === 0 && lm2 === 0);
                        if (hasLunch2Local) {
                            const l2ValStart = `TIME(${lh2},${lm2},0)`;
                            const l2EndStart = `(TIME(${lh2},${lm2},0)+TIME(0,${ld},0))`;
                            const shifted1 = `IF(${startShiftCond1},${l1EndStart},${rawTimeWithPause})`;
                            const startShiftCond2 = `AND(${shifted1}>=${l2ValStart}, ${shifted1}<${l2EndStart})`;
                            startFormula = `=MOD(IF(${startShiftCond2},${l2EndStart},${shifted1}),1)`;
                        } else {
                            startFormula = `=MOD(IF(${startShiftCond1},${l1EndStart},${rawTimeWithPause}),1)`;
                        }
                        startTimeCell = `<Cell ss:StyleID="${styleMap.timeLocked}" ss:Formula="${escapeXml(startFormula)}"><Data ss:Type="DateTime">${startTimeXml}</Data></Cell>`;
                    }
                }
            }

            const l1Val = `TIME(${lh},${lm},0)`;
            const l1End = `(TIME(${lh},${lm},0)+TIME(0,${ld},0))`;
            const lDurVal = `TIME(0,${ld},0)`;
            
            // Проверяем, задан ли второй обед (не 00:00)
            const hasLunch2 = !(lh2 === 0 && lm2 === 0);
            const l2Val = `TIME(${lh2},${lm2},0)`;
            const l2End = `(TIME(${lh2},${lm2},0)+TIME(0,${ld},0))`;
            
            // --- ICONS (RC[7] = Start, RC[2] = Dur) ---
            // JS логика: показать иконку если:
            // 1) начало попадало в обед (в Excel уже сдвинуто на конец обеда)
            // 2) начало < lunchStart И конец СТРОГО > lunchStart (накрывает обед)
            // Условие 1: start ≈ lunchEnd (был сдвинут, проверяем с допуском 1 сек)
            // Условие 2: start < lunchStart AND rawEnd > lunchStart + 1сек
            const icRawEnd = `(RC[7]+(RC[2]/${unitDiv}))`;
            const icWasShifted1 = `ABS(RC[7]-${l1End})<TIME(0,0,1)`;
            const icCovers1 = `AND(RC[7]<${l1Val}, ${icRawEnd}>(${l1Val}+TIME(0,0,1)))`;
            const icC1 = `OR(${icWasShifted1}, ${icCovers1})`;
            const icShift1 = `IF(${icC1}, ${lDurVal}, 0)`;
            
            let formulaIcon;
            if (hasLunch2) {
                // Для второго обеда: аналогичная логика с учётом сдвига от первого
                const shiftedStart = `(RC[7]+${icShift1})`;
                const shiftedEnd = `(${icRawEnd}+${icShift1})`;
                const icWasShifted2 = `ABS(${shiftedStart}-${l2End})<TIME(0,0,1)`;
                const icCovers2 = `AND(${shiftedStart}<${l2Val}, ${shiftedEnd}>(${l2Val}+TIME(0,0,1)))`;
                const icC2 = `OR(${icWasShifted2}, ${icCovers2})`;
                formulaIcon = `=IF(OR(${icC1}, ${icC2}), "🍽️", "")`;
            } else {
                // Второй обед не задан - проверяем только первый
                formulaIcon = `=IF(${icC1}, "🍽️", "")`;
            }

            // --- END TIME (RC[-2] = Start Time, RC[-7] = Dur) ---
            // Условие: операция НАКРЫВАЕТ обед (начало ДО начала обеда И конец СТРОГО ПОСЛЕ начала обеда)
            // Добавляем порог 1 секунда чтобы избежать погрешности floating point
            // Если конец = началу обеда, обед НЕ добавляется
            const rawEnd = `(RC[-2]+(RC[-7]/${unitDiv}))`;
            const enC1 = `AND(RC[-2] < ${l1Val}, ${rawEnd} > (${l1Val}+TIME(0,0,1)))`;
            const enShift1 = `IF(${enC1}, ${lDurVal}, 0)`;
            
            let formulaEnd;
            if (hasLunch2) {
                const shiftedEnd = `(${rawEnd} + ${enShift1})`;
                const enC2 = `AND((RC[-2] + ${enShift1}) < ${l2Val}, ${shiftedEnd} > (${l2Val}+TIME(0,0,1)))`;
                const enShift2 = `IF(${enC2}, ${lDurVal}, 0)`;
                formulaEnd = `=MOD(${rawEnd} + ${enShift1} + ${enShift2}, 1)`;
            } else {
                // Второй обед не задан - учитываем только первый
                formulaEnd = `=MOD(${rawEnd} + ${enShift1}, 1)`;
            }

            // Determine numericness for opIdx and worker to avoid Excel 'number stored as text' warnings
            const opIdxNum = Number(String(r.opIdx).replaceAll("'", ""));
            const opIdxCell = Number.isFinite(opIdxNum) && String(opIdxNum) !== 'NaN'
                ? `<Cell ss:Index="3" ss:StyleID="${styleMap.borderLocked}"><Data ss:Type="Number">${opIdxNum}</Data></Cell>`
                    : `<Cell ss:Index="3" ss:StyleID="${styleMap.borderLocked}"><Data ss:Type="String">${escapeXml(String(r.opIdx))}</Data></Cell>`;

            const workerRaw = String(r.worker || '');
            const workerNum = Number(workerRaw.replaceAll("'", ""));
            const workerCell = (workerRaw.trim() !== '' && Number.isFinite(workerNum))
                ? `<Cell ss:StyleID="${styleMap.borderLocked}"><Data ss:Type="Number">${workerNum}</Data></Cell>`
                : `<Cell ss:StyleID="${styleMap.borderLocked}"><Data ss:Type="String">${escapeXml(excelSanitizeCell(workerRaw))}</Data></Cell>`;

            xmlBody += `
            <Row>
                <Cell ss:Index="2" ss:StyleID="${styleMap.borderLocked}"><Data ss:Type="Number">${idx + 1}</Data></Cell>
                ${opIdxCell}
                <Cell ss:StyleID="${styleMap.borderLeftLocked}"><Data ss:Type="String">${escapeXml(excelSanitizeCell(r.name))}</Data></Cell>
                <Cell ss:StyleID="${styleMap.iconLocked}" ss:Formula="${escapeXml(formulaIcon)}"><Data ss:Type="String">${r.crossedLunch ? '🍽️' : ''}</Data></Cell>
                ${pauseCell}
                ${durCell}
                <Cell ss:StyleID="${styleMap.dateLocked}"><Data ss:Type="DateTime">${postingXml}</Data></Cell>
                ${workerCell}
                <Cell ss:StyleID="${styleMap.borderLocked}"><Data ss:Type="String"></Data></Cell>
                <Cell ss:StyleID="${styleMap.dateLocked}"><Data ss:Type="DateTime">${startXml}</Data></Cell>
                ${startTimeCell}
                <Cell ss:StyleID="${styleMap.dateLocked}"><Data ss:Type="DateTime">${endXml}</Data></Cell>
                    <Cell ss:StyleID="${styleMap.timeLocked}" ss:Formula="${escapeXml(formulaEnd)}"><Data ss:Type="DateTime">${startTimeXml}</Data></Cell>
                    <Cell ss:StyleID="${styleMap.borderLocked}"><Data ss:Type="String">${escapeXml(String(curOpNum) + '_' + String(r.workerIndex || 1))}</Data></Cell>
                </Row>
                `;
            // debug logging removed
                // remember position of this op+worker within the exported rows (index relative to start of this entry)
                rowPosMap[`${curOpNum}_${r.workerIndex || 1}`] = idx;
                // advance absolute sheet row counter
                sheetRow += 1;
        });

            xmlBody += `
            <Row>
                <Cell ss:Index="2" ss:MergeAcross="13" ss:StyleID="sTitle"><Data ss:Type="String">Z7</Data></Cell>
            </Row>
            `;
            // one row for Z7 title
            sheetRow += 1;

            data.z7.forEach((line, zi) => {
            // Excel cannot auto-fit height for merged cells reliably,
            // so estimate row height from text length and set ss:Height for Z7 rows.
            const sanitizedZ7 = excelSanitizeCell(line);
            const charsPerLine = 80; // rough approximation for wrapping
            const linesNeeded = Math.max(1, Math.ceil(String(sanitizedZ7).length / charsPerLine));
            let heightAttr = '';
            if (linesNeeded > 1) {
                const perLinePx = 18; // approx pixel height per text line
                const h = Math.min(400, perLinePx * linesNeeded);
                heightAttr = ` ss:Height="${h}"`;
            }

            xmlBody += `
            <Row${heightAttr}>
                    <Cell ss:Index="2" ss:MergeAcross="13" ss:StyleID="sZ7Locked"><Data ss:Type="String">${escapeXml(sanitizedZ7)}</Data></Cell>
            </Row>
            <Row>
                <Cell ss:Index="2" ss:MergeAcross="13" ss:StyleID="sZ7Locked"><Data ss:Type="String"></Data></Cell>
            </Row>
            `;
            // two rows per Z7 line
            sheetRow += 2;
        });
        xmlBody += `<Row></Row>`;
        // final spacer row
        sheetRow += 1;
        previousEntryData = data;
    });

    const sheetName = new Date().toLocaleDateString('ru-RU').replaceAll('.', '-');
    const xmlContent = buildExcelXml(xmlBody, sheetName);
    downloadExcelFile(xmlContent);
}

function buildExcelXml(xmlBody, sheetName) {
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
     <Font ss:FontName="Arial" ss:Size="12"/>
     <Interior/>
     <Protection ss:Protected="1"/>
    </Style>
    <Style ss:ID="sHeader">
     <Alignment ss:Horizontal="Center" ss:Vertical="Center" ss:WrapText="1"/>
   <Borders>
    <Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="1"/>
    <Border ss:Position="Left" ss:LineStyle="Continuous" ss:Weight="1"/>
    <Border ss:Position="Right" ss:LineStyle="Continuous" ss:Weight="1"/>
    <Border ss:Position="Top" ss:LineStyle="Continuous" ss:Weight="1"/>
   </Borders>
    <Font ss:Color="#FFFFFF" ss:Bold="1" ss:Size="12"/>
   <Interior ss:Color="#374151" ss:Pattern="Solid"/>
   <Protection ss:Protected="1"/>
  </Style>
    <Style ss:ID="sAuthor">
     <Alignment ss:Horizontal="Center" ss:Vertical="Center"/>
     <Font ss:Size="30" ss:Bold="1"/>
     <Interior ss:Color="#b7eeb9" ss:Pattern="Solid"/>
     <Protection ss:Protected="1"/>
    </Style>
    <Style ss:ID="sTitle">
     <Alignment ss:Horizontal="Center" ss:Vertical="Center" ss:WrapText="1"/>
   <Borders>
    <Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="1"/>
    <Border ss:Position="Left" ss:LineStyle="Continuous" ss:Weight="1"/>
    <Border ss:Position="Right" ss:LineStyle="Continuous" ss:Weight="1"/>
    <Border ss:Position="Top" ss:LineStyle="Continuous" ss:Weight="1"/>
   </Borders>
    <Font ss:Color="#FFFFFF" ss:Bold="1" ss:Size="12"/>
   <Interior ss:Color="#374151" ss:Pattern="Solid"/>
   <Protection ss:Protected="1"/>
  </Style>
    <Style ss:ID="sTextLocked">
     <Alignment ss:Vertical="Center" ss:WrapText="1"/>
     <Font ss:Size="12"/>
     <Protection ss:Protected="1"/>
    </Style>
    <Style ss:ID="sBorderLocked">
     <Alignment ss:Horizontal="Center" ss:Vertical="Center" ss:WrapText="1"/>
     <Borders><Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Left" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Right" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Top" ss:LineStyle="Continuous" ss:Weight="1"/></Borders>
     <Font ss:Size="12"/>
     <Interior ss:Color="#F4CCCC" ss:Pattern="Solid"/>
     <Protection ss:Protected="1"/>
    </Style>
    <Style ss:ID="sBorderLeftLocked">
     <Alignment ss:Horizontal="Center" ss:Vertical="Center" ss:WrapText="1"/>
     <Borders><Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Left" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Right" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Top" ss:LineStyle="Continuous" ss:Weight="1"/></Borders>
     <Font ss:Size="12"/>
     <Interior ss:Color="#F4CCCC" ss:Pattern="Solid"/>
     <Protection ss:Protected="1"/>
    </Style>
    <Style ss:ID="sZ7Locked">
     <Alignment ss:Horizontal="Left" ss:Vertical="Center" ss:WrapText="1"/>
     <Borders><Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Left" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Right" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Top" ss:LineStyle="Continuous" ss:Weight="1"/></Borders>
     <Font ss:Size="12"/>
     <Interior ss:Color="#F4CCCC" ss:Pattern="Solid"/>
     <Protection ss:Protected="1"/>
    </Style>
    <Style ss:ID="sDurLocked">
     <Alignment ss:Horizontal="Center" ss:Vertical="Center" ss:WrapText="1"/>
     <Borders><Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Left" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Right" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Top" ss:LineStyle="Continuous" ss:Weight="1"/></Borders>
     <Font ss:Size="12"/>
     <Interior ss:Color="#F4CCCC" ss:Pattern="Solid"/>
     <Protection ss:Protected="1"/>
    </Style>
    <Style ss:ID="sTimeLocked">
     <Alignment ss:Horizontal="Center" ss:Vertical="Center" ss:WrapText="1"/>
     <Borders><Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Left" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Right" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Top" ss:LineStyle="Continuous" ss:Weight="1"/></Borders>
     <Font ss:Size="12"/>
     <NumberFormat ss:Format="h:mm:ss"/>
     <Interior ss:Color="#F4CCCC" ss:Pattern="Solid"/>
     <Protection ss:Protected="1"/>
    </Style>
    <Style ss:ID="sDateLocked">
     <Alignment ss:Horizontal="Center" ss:Vertical="Center" ss:WrapText="1"/>
     <Borders><Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Left" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Right" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Top" ss:LineStyle="Continuous" ss:Weight="1"/></Borders>
     <Font ss:Size="12"/>
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
     <Alignment ss:Horizontal="Center" ss:Vertical="Center" ss:WrapText="1"/>
     <Borders><Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Left" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Right" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Top" ss:LineStyle="Continuous" ss:Weight="1"/></Borders>
     <Font ss:Size="12"/>
     <Interior ss:Color="#FFFFFF" ss:Pattern="Solid"/>
     <Protection ss:Protected="0"/>
    </Style>
    <Style ss:ID="sTimeEditable">
     <Alignment ss:Horizontal="Center" ss:Vertical="Center" ss:WrapText="1"/>
     <Borders><Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Left" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Right" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Top" ss:LineStyle="Continuous" ss:Weight="1"/></Borders>
     <Font ss:Size="12"/>
     <NumberFormat ss:Format="h:mm:ss"/>
     <Interior ss:Color="#FFFFFF" ss:Pattern="Solid"/>
     <Protection ss:Protected="0"/>
    </Style>
    <!-- Styles with thicker bottom border for group separation -->
    <Style ss:ID="sBorderLockedBottom">
     <Alignment ss:Horizontal="Center" ss:Vertical="Center" ss:WrapText="1"/>
     <Borders><Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="3"/><Border ss:Position="Left" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Right" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Top" ss:LineStyle="Continuous" ss:Weight="1"/></Borders>
     <Font ss:Size="12"/>
     <Interior ss:Color="#F4CCCC" ss:Pattern="Solid"/>
     <Protection ss:Protected="1"/>
    </Style>
    <Style ss:ID="sBorderLeftLockedBottom">
     <Alignment ss:Horizontal="Center" ss:Vertical="Center" ss:WrapText="1"/>
     <Borders><Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="3"/><Border ss:Position="Left" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Right" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Top" ss:LineStyle="Continuous" ss:Weight="1"/></Borders>
     <Font ss:Size="12"/>
     <Interior ss:Color="#F4CCCC" ss:Pattern="Solid"/>
     <Protection ss:Protected="1"/>
    </Style>
    <Style ss:ID="sIconLockedBottom">
     <Alignment ss:Horizontal="Center" ss:Vertical="Center"/>
     <Borders><Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="3"/><Border ss:Position="Left" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Right" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Top" ss:LineStyle="Continuous" ss:Weight="1"/></Borders>
     <Font ss:Size="14"/>
     <Interior ss:Color="#F4CCCC" ss:Pattern="Solid"/>
     <Protection ss:Protected="1"/>
    </Style>
    <Style ss:ID="sTimeLockedBottom">
     <Alignment ss:Horizontal="Center" ss:Vertical="Center" ss:WrapText="1"/>
     <Borders><Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="3"/><Border ss:Position="Left" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Right" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Top" ss:LineStyle="Continuous" ss:Weight="1"/></Borders>
     <Font ss:Size="12"/>
     <NumberFormat ss:Format="h:mm:ss"/>
     <Interior ss:Color="#F4CCCC" ss:Pattern="Solid"/>
     <Protection ss:Protected="1"/>
    </Style>
    <Style ss:ID="sTimeEditableBottom">
     <Alignment ss:Horizontal="Center" ss:Vertical="Center" ss:WrapText="1"/>
     <Borders><Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="3"/><Border ss:Position="Left" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Right" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Top" ss:LineStyle="Continuous" ss:Weight="1"/></Borders>
     <Font ss:Size="12"/>
     <NumberFormat ss:Format="h:mm:ss"/>
     <Interior ss:Color="#FFFFFF" ss:Pattern="Solid"/>
     <Protection ss:Protected="0"/>
    </Style>
    <Style ss:ID="sDurEditableBottom">
     <Alignment ss:Horizontal="Center" ss:Vertical="Center" ss:WrapText="1"/>
     <Borders><Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="3"/><Border ss:Position="Left" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Right" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Top" ss:LineStyle="Continuous" ss:Weight="1"/></Borders>
     <Font ss:Size="12"/>
     <Interior ss:Color="#FFFFFF" ss:Pattern="Solid"/>
     <Protection ss:Protected="0"/>
    </Style>
    <Style ss:ID="sDurLockedBottom">
     <Alignment ss:Horizontal="Center" ss:Vertical="Center" ss:WrapText="1"/>
     <Borders><Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="3"/><Border ss:Position="Left" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Right" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Top" ss:LineStyle="Continuous" ss:Weight="1"/></Borders>
     <Font ss:Size="12"/>
     <Interior ss:Color="#F4CCCC" ss:Pattern="Solid"/>
     <Protection ss:Protected="1"/>
    </Style>
    <Style ss:ID="sDateLockedBottom">
     <Alignment ss:Horizontal="Center" ss:Vertical="Center" ss:WrapText="1"/>
     <Borders><Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="3"/><Border ss:Position="Left" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Right" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Top" ss:LineStyle="Continuous" ss:Weight="1"/></Borders>
     <Font ss:Size="12"/>
     <NumberFormat ss:Format="dd.mm.yyyy"/>
     <Interior ss:Color="#F4CCCC" ss:Pattern="Solid"/>
     <Protection ss:Protected="1"/>
    </Style>
    <!-- Styles with thicker top border for group separation -->
    <Style ss:ID="sBorderLockedTop">
     <Alignment ss:Horizontal="Center" ss:Vertical="Center" ss:WrapText="1"/>
     <Borders><Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Left" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Right" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Top" ss:LineStyle="Continuous" ss:Weight="3"/></Borders>
     <Font ss:Size="12"/>
     <Interior ss:Color="#F4CCCC" ss:Pattern="Solid"/>
     <Protection ss:Protected="1"/>
    </Style>
    <Style ss:ID="sBorderLeftLockedTop">
     <Alignment ss:Horizontal="Center" ss:Vertical="Center" ss:WrapText="1"/>
     <Borders><Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Left" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Right" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Top" ss:LineStyle="Continuous" ss:Weight="3"/></Borders>
     <Font ss:Size="12"/>
     <Interior ss:Color="#F4CCCC" ss:Pattern="Solid"/>
     <Protection ss:Protected="1"/>
    </Style>
    <Style ss:ID="sIconLockedTop">
     <Alignment ss:Horizontal="Center" ss:Vertical="Center"/>
     <Borders><Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Left" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Right" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Top" ss:LineStyle="Continuous" ss:Weight="3"/></Borders>
     <Font ss:Size="14"/>
     <Interior ss:Color="#F4CCCC" ss:Pattern="Solid"/>
     <Protection ss:Protected="1"/>
    </Style>
    <Style ss:ID="sTimeLockedTop">
     <Alignment ss:Horizontal="Center" ss:Vertical="Center" ss:WrapText="1"/>
     <Borders><Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Left" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Right" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Top" ss:LineStyle="Continuous" ss:Weight="3"/></Borders>
     <Font ss:Size="12"/>
     <NumberFormat ss:Format="h:mm:ss"/>
     <Interior ss:Color="#F4CCCC" ss:Pattern="Solid"/>
     <Protection ss:Protected="1"/>
    </Style>
    <Style ss:ID="sTimeEditableTop">
     <Alignment ss:Horizontal="Center" ss:Vertical="Center" ss:WrapText="1"/>
     <Borders><Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Left" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Right" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Top" ss:LineStyle="Continuous" ss:Weight="3"/></Borders>
     <Font ss:Size="12"/>
     <NumberFormat ss:Format="h:mm:ss"/>
     <Interior ss:Color="#FFFFFF" ss:Pattern="Solid"/>
     <Protection ss:Protected="0"/>
    </Style>
    <Style ss:ID="sDurEditableTop">
     <Alignment ss:Horizontal="Center" ss:Vertical="Center" ss:WrapText="1"/>
     <Borders><Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Left" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Right" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Top" ss:LineStyle="Continuous" ss:Weight="3"/></Borders>
     <Font ss:Size="12"/>
     <Interior ss:Color="#FFFFFF" ss:Pattern="Solid"/>
     <Protection ss:Protected="0"/>
    </Style>
    <Style ss:ID="sDurLockedTop">
     <Alignment ss:Horizontal="Center" ss:Vertical="Center" ss:WrapText="1"/>
     <Borders><Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Left" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Right" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Top" ss:LineStyle="Continuous" ss:Weight="3"/></Borders>
     <Font ss:Size="12"/>
     <Interior ss:Color="#F4CCCC" ss:Pattern="Solid"/>
     <Protection ss:Protected="1"/>
    </Style>
    <Style ss:ID="sDateLockedTop">
     <Alignment ss:Horizontal="Center" ss:Vertical="Center" ss:WrapText="1"/>
     <Borders><Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Left" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Right" ss:LineStyle="Continuous" ss:Weight="1"/><Border ss:Position="Top" ss:LineStyle="Continuous" ss:Weight="3"/></Borders>
     <Font ss:Size="12"/>
     <NumberFormat ss:Format="dd.mm.yyyy"/>
     <Interior ss:Color="#F4CCCC" ss:Pattern="Solid"/>
     <Protection ss:Protected="1"/>
    </Style>
 </Styles>
 <Worksheet ss:Name="${escapeXml(sheetName)}" ss:Protected="1" x:Password="">
    <Table>
    <Column ss:Width="10" ss:StyleID="sTextLocked"/> <!-- A -->
    <Column ss:Width="20" ss:StyleID="sTextLocked"/> <!-- B -->
    <Column ss:Width="50" ss:StyleID="sTextLocked"/> <!-- C -->
    <Column ss:Width="400" ss:StyleID="sTextLocked"/> <!-- D -->
    <Column ss:Width="40" ss:StyleID="sTextLocked"/> <!-- E -->
    <Column ss:Width="100" ss:StyleID="sTextLocked"/> <!-- F -->
    <Column ss:Width="80" ss:StyleID="sTextLocked"/> <!-- G -->
    <Column ss:Width="100" ss:StyleID="sTextLocked"/> <!-- H -->
    <Column ss:Width="100" ss:StyleID="sTextLocked"/> <!-- I -->
    <Column ss:Width="20" ss:StyleID="sTextLocked"/> <!-- J -->
    <Column ss:Width="100" ss:StyleID="sTextLocked"/> <!-- K -->
    <Column ss:Width="100" ss:StyleID="sTextLocked"/> <!-- L -->
    <Column ss:Width="100" ss:StyleID="sTextLocked"/> <!-- M -->
    <Column ss:Width="100" ss:StyleID="sTextLocked"/> <!-- N -->
    <Column ss:Width="50" ss:StyleID="sTextLocked"/> <!-- O -->
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
    const fileName = `История_Расчетов_${new Date().toLocaleDateString('ru-RU').replaceAll('.', '-')}.xml`;
    
    // Пробуем использовать Tauri API
    if (tauriDialog?.save && tauriInvoke) {
        try {
                const filePath = await tauriDialog.save({
                defaultPath: fileName,
                filters: [{ name: 'XML', extensions: ['xml'] }]
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
    const blob = new Blob([xmlContent], { type: 'application/xml' });
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
        // Сохраняем имя операции без порядкового префикса
        name: sanitizeStrict(stripOrdinalPrefix(b.querySelector('.op-header-input').value), 200),
        dur: Math.max(0, Number.parseFloat(b.querySelector('.op-duration').value) || 0),
        unit: b.querySelector('.op-unit').value,
        // hasBreak: derive from break value (no checkbox now)
        hasBreak: (Math.max(0, Number.parseFloat(b.querySelector('.op-break-val').value) || 0) > 0),
        breakVal: Math.max(0, Number.parseFloat(b.querySelector('.op-break-val').value) || 0),
        breakUnit: b.querySelector('.op-break-unit').value
    }));
}

function setCardData(steps) {
    if (!validateCardData(steps)) {
        alert('Ошибка: некорректные данные шаблона');
        return;
    }

    document.getElementById('totalOps').value = Math.min(steps.length, 20);
    container.textContent = '';
    renderFields();

    const blocks = document.querySelectorAll('.op-block');
    
    // Сначала устанавливаем единицу для первой операции
    if (steps[0] && blocks[0]) {
        blocks[0].querySelector('.op-unit').value = steps[0].unit;
    }
    
    steps.forEach((s, i) => {
        if (!blocks[i]) return;
        // Для отображения в UI добавляем порядковый префикс, но сохраняем внутри шаблона только имя
        blocks[i].querySelector('.op-header-input').value = `${i + 1}) ${sanitizeStrict(s.name, 200)}`;
        
        blocks[i].querySelector('.op-duration').value = Math.max(0, Number.parseFloat(s.dur) || 0);
        // Для всех операций кроме первой единица будет синхронизирована
        if (i === 0) {
            blocks[i].querySelector('.op-unit').value = s.unit;
        }

        if (s.hasBreak) {
            const breakGroup = blocks[i].querySelector('.break-container');
            try {
                if (breakGroup) breakGroup.style.display = 'flex';
            } catch (ee) {}
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
    const keys = Object.keys(localStorage).filter(k => k.startsWith('z7_card_'));
    // Map to labels and sort using numeric-aware comparison so '10' > '2' is handled
    const mapped = keys.map(k => ({ key: k, label: k.replace('z7_card_', '') }));
    mapped.sort((a, b) => a.label.localeCompare(b.label, undefined, { numeric: true, sensitivity: 'base' }));
    mapped.forEach(({ key, label }) => {
        userGroup.append(createEl('option', { value: key }, label));
    });
}

// === ПРИВЯЗКА СОБЫТИЙ ===
document.getElementById('chainMode').addEventListener('change', () => {
    updateStartTimeFromHistory();
    updateFirstPauseVisibility();
});
const totalOpsEl = document.getElementById('totalOps');
if (totalOpsEl) {
    // While typing: keep only digits and clamp to max immediately
    totalOpsEl.addEventListener('input', (e) => {
    let v = String(e.target.value).replaceAll(/[^0-9]/g, '');
        if (v !== '') {
            const n = Number.parseInt(v, 10);
            if (!Number.isNaN(n)) {
                const clamped = Math.max(1, Math.min(20, n));
                if (clamped !== n) v = String(clamped);
            }
        }
        e.target.value = v;
    });

    // Paste: sanitize and clamp
    totalOpsEl.addEventListener('paste', (e) => {
        e.preventDefault();
        const text = (e.clipboardData || window.clipboardData).getData('text') || '';
        const digits = text.replaceAll(/[^0-9]/g, '');
        const n = Number.parseInt(digits || '0', 10) || 0;
        const clamped = validateNumber(n, 1, 20);
        totalOpsEl.value = clamped;
        renderFields();
    });

    totalOpsEl.addEventListener('change', (e) => {
        // Clamp to allowed range and re-render
        const val = validateNumber(e.target.value, 1, 20);
        e.target.value = val;
        renderFields();
    });
    totalOpsEl.addEventListener('keyup', renderFields);
}
// Handler for the "ЗАДАТЬ" button near #totalOps: confirm and lock the input
// NOTE: setOpsBtn handler implemented below (near modal open) to ensure single unified behavior
document.getElementById('generateBtn').addEventListener('click', generateTable);

document.getElementById('clearBtn').addEventListener('click', async () => {
    let confirmed = false;
    
    if (tauriDialog?.confirm) {
        try {
            confirmed = await tauriDialog.confirm('Очистить?', {
                title: 'Подтверждение',
                kind: 'warning'
            });
        } catch (e) {
            confirmed = globalThis.confirm('Очистить?');
        }
    } else {
        confirmed = globalThis.confirm('Очистить?');
    }
    
    if (confirmed) {
        // Reset form fields to defaults (like F5) but keep history
        // Compute today's date in ISO yyyy-mm-dd for default startDate
        const _today = new Date();
        const _yyyy = _today.getFullYear();
        const _mm = String(_today.getMonth() + 1).padStart(2, '0');
        const _dd = String(_today.getDate()).padStart(2, '0');
        const _todayStr = `${_yyyy}-${_mm}-${_dd}`;

        const defaults = {
            totalOps: 1,
            workerCount: 1,
            startDate: _todayStr,
            startTime: '08:00:00',
            chainMode: true,
            lunchStart: '12:00',
            lunchStart2: '00:00',
            lunchDur: 45,
            timeMode: 'total',
            resIz: '',
            coefK: '',
            orderName: '',
            itemName: '',
            postingDate: _todayStr,
            statusBefore: 'замечаний нет',
            workExtra: 'нет',
            devRec: 'нет'
        };

        try {
            // If user has saved a config in localStorage, prefer restoring it for these controls
            let cfg = null;
            try { cfg = JSON.parse(localStorage.getItem(CONFIG_KEY) || 'null'); } catch (ee) { cfg = null; }

            document.getElementById('totalOps').value = defaults.totalOps;
            document.getElementById('workerCount').value = defaults.workerCount;
            document.getElementById('startDate').value = defaults.startDate;
            try {
                // Preserve postingDate: restore from saved config if present, otherwise do not overwrite current value
                const pdEl = document.getElementById('postingDate');
                if (pdEl) {
                    if (cfg && cfg.postingDate) {
                        pdEl.value = cfg.postingDate;
                    }
                    // else: leave existing postingDate untouched
                }
            } catch(e){}
            document.getElementById('startTime').value = defaults.startTime;
            document.getElementById('chainMode').checked = defaults.chainMode;
            document.getElementById('lunchStart').value = (cfg && cfg.lunchStart) ? cfg.lunchStart : defaults.lunchStart;
            document.getElementById('lunchStart2').value = (cfg && cfg.lunchStart2) ? cfg.lunchStart2 : defaults.lunchStart2;
            document.getElementById('lunchDur').value = (cfg && cfg.lunchDur !== undefined) ? cfg.lunchDur : defaults.lunchDur;
            // Always reset timeMode to default ('total') on Clear (do not restore persisted value)
            try { if (document.getElementById('timeMode')) document.getElementById('timeMode').value = defaults.timeMode; } catch(e) {}
            document.getElementById('resIz').value = defaults.resIz;
            document.getElementById('coefK').value = defaults.coefK;
            document.getElementById('orderName').value = defaults.orderName;
            document.getElementById('itemName').value = defaults.itemName;
            document.getElementById('statusBefore').value = defaults.statusBefore;
            document.getElementById('workExtra').value = defaults.workExtra;
            document.getElementById('devRec').value = defaults.devRec;
        } catch (e) {
            console.debug?.('clearBtn reset fields error:', e?.message);
        }

        // Re-enable totalOps input and tech-card controls if they were locked by "ЗАДАТЬ"
        try {
            const totalEl = document.getElementById('totalOps');
            if (totalEl) {
                totalEl.disabled = false;
                totalEl.classList.remove('locked-input');
            }
            const workerCountEl = document.getElementById('workerCount');
            if (workerCountEl) {
                workerCountEl.disabled = false;
                workerCountEl.classList.remove('locked-input');
            }
            const sel = document.getElementById('techCardSelect');
            if (sel) { sel.disabled = false; sel.classList.remove('locked-input'); }
            const saveBtn = document.getElementById('saveCardBtn');
            if (saveBtn) { saveBtn.disabled = false; saveBtn.classList.remove('locked-control'); }
            const delBtn = document.getElementById('deleteCardBtn');
            if (delBtn) { delBtn.disabled = false; delBtn.classList.remove('locked-control'); }
        } catch (e) { console.debug?.('clearBtn re-enable controls error:', e?.message); }

        // Clear generated results and dynamic fields
        container.textContent = '';
        const tableResult = document.getElementById('tableResult');
        const z7Result = document.getElementById('z7Result');
        if (tableResult) tableResult.textContent = '';
        if (z7Result) z7Result.textContent = '';

        // Reset modals and internal state
        try {
            workerIds = [];
            operationFirstId = '';
            lastOperationIndex = null;
            // Re-render modal lists if open
            const wModal = document.getElementById('workersModal');
            const oModal = document.getElementById('opsModal');
            if (wModal && wModal.classList.contains('active')) renderWorkersInputList();
            if (oModal && oModal.classList.contains('active')) renderOpsInputList();
        } catch (e) {
            console.debug?.('clearBtn reset state error:', e?.message);
        }

        // Re-create one empty operation block
        renderFields();
    }
});

// Handler for destructive Reset button: clears most localStorage and reset fields to defaults
document.getElementById('resetBtn').addEventListener('click', async () => {
    let confirmed = false;
    const msg = 'Сбросить все поля и очистить локальное хранилище?\nИстория расчетов, сохранённые техкарты и заметки исполнителей сохранятся.';
    if (tauriDialog?.confirm) {
        try {
            confirmed = await tauriDialog.confirm(msg, { title: 'Подтверждение', kind: 'warning' });
        } catch (e) {
            confirmed = globalThis.confirm(msg);
        }
    } else {
        confirmed = globalThis.confirm(msg);
    }

    if (!confirmed) return;

    // Compute today's date
    const _today = new Date();
    const _yyyy = _today.getFullYear();
    const _mm = String(_today.getMonth() + 1).padStart(2, '0');
    const _dd = String(_today.getDate()).padStart(2, '0');
    const _todayStr = `${_yyyy}-${_mm}-${_dd}`;

    const defaults = {
        totalOps: 1,
        workerCount: 1,
        startDate: _todayStr,
        startTime: '08:00:00',
        chainMode: true,
        lunchStart: '12:00',
        lunchStart2: '00:00',
        lunchDur: 45,
        timeMode: 'total',
        resIz: '',
        coefK: '',
        orderName: '',
        itemName: '',
        postingDate: _todayStr,
        statusBefore: 'замечаний нет',
        workExtra: 'нет',
        devRec: 'нет'
    };

    try {
        // Clear localStorage except preserved keys: history, tech cards, workers cheat
        const preservePrefixes = ['z7_card_'];
        const preserveKeys = new Set(['z7_history_session', 'z7_workers_cheat']);
        const allKeys = Array.from(Object.keys(localStorage));
        for (const k of allKeys) {
            if (preserveKeys.has(k)) continue;
            if (preservePrefixes.some(p => k.startsWith(p))) continue;
            try { await safeLocalStorageRemove(k); } catch (e) { try { localStorage.removeItem(k); } catch (ee) {} }
        }

        // Reset UI fields to defaults (full reset)
        document.getElementById('totalOps').value = defaults.totalOps;
        document.getElementById('workerCount').value = defaults.workerCount;
        document.getElementById('startDate').value = defaults.startDate;
        try { if (document.getElementById('postingDate')) document.getElementById('postingDate').value = defaults.postingDate; } catch(e){}
        document.getElementById('startTime').value = defaults.startTime;
        document.getElementById('chainMode').checked = defaults.chainMode;
        document.getElementById('lunchStart').value = defaults.lunchStart;
        document.getElementById('lunchStart2').value = defaults.lunchStart2;
        document.getElementById('lunchDur').value = defaults.lunchDur;
        try { if (document.getElementById('timeMode')) document.getElementById('timeMode').value = defaults.timeMode; } catch(e){}
        document.getElementById('resIz').value = defaults.resIz;
        document.getElementById('coefK').value = defaults.coefK;
        document.getElementById('orderName').value = defaults.orderName;
        document.getElementById('itemName').value = defaults.itemName;
        document.getElementById('statusBefore').value = defaults.statusBefore;
        document.getElementById('workExtra').value = defaults.workExtra;
        document.getElementById('devRec').value = defaults.devRec;

        // Re-enable controls and clear generated results
        try {
            const totalEl = document.getElementById('totalOps'); if (totalEl) { totalEl.disabled = false; totalEl.classList.remove('locked-input'); }
            const workerCountEl = document.getElementById('workerCount'); if (workerCountEl) { workerCountEl.disabled = false; workerCountEl.classList.remove('locked-input'); }
            const sel = document.getElementById('techCardSelect'); if (sel) { sel.disabled = false; sel.classList.remove('locked-input'); }
            const saveBtn = document.getElementById('saveCardBtn'); if (saveBtn) { saveBtn.disabled = false; saveBtn.classList.remove('locked-control'); }
            const delBtn = document.getElementById('deleteCardBtn'); if (delBtn) { delBtn.disabled = false; delBtn.classList.remove('locked-control'); }
        } catch (e) { console.debug?.('reset re-enable controls error', e?.message); }

        container.textContent = '';
        const tableResult = document.getElementById('tableResult');
        const z7Result = document.getElementById('z7Result');
        if (tableResult) tableResult.textContent = '';
        if (z7Result) z7Result.textContent = '';

        // Re-render blank operation blocks
        try { renderFields(); } catch (e) {}

        if (tauriDialog?.message) await tauriDialog.message('Сброс выполнен', { title: 'Готово' }); else alert('Сброс выполнен');
    } catch (e) {
        console.error('Reset error', e);
        if (tauriDialog?.message) await tauriDialog.message(String(e), { title: 'Ошибка', kind: 'error' }); else alert('Ошибка: ' + e);
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

    // Строгая санитизация имени шаблона: ограничение по длине и очистка запрещённых символов
    name = sanitizeStrict(String(name), 100).trim();
    // Блокируем потенциально опасные имена ключей (prototype pollution и т.п.)
    if (name.length === 0 || name.includes('__proto__') || name.includes('constructor') || name.includes('prototype')) {
        if (tauriDialog?.message) {
            await tauriDialog.message('Название не может быть пустым или содержать недопустимые последовательности', { title: 'Ошибка', kind: 'error' });
        } else {
            alert('Название не может быть пустым или содержать недопустимые последовательности');
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
    // Note: `z7_workers_cheat` intentionally excluded from JSON export (keeps local-only notes private)

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

// === PERSISTENT CONFIG (timeMode + lunch settings) ===
const CONFIG_KEY = 'z7_config';
function saveConfig() {
    try {
        const cfg = {
                lunchStart: document.getElementById('lunchStart')?.value || '12:00',
                lunchStart2: document.getElementById('lunchStart2')?.value || '00:00',
                lunchDur: document.getElementById('lunchDur')?.value || '45',
                postingDate: document.getElementById('postingDate')?.value || null
            };
        localStorage.setItem(CONFIG_KEY, JSON.stringify(cfg));
    } catch (e) { console.debug?.('saveConfig error', e?.message); }
}

function loadConfig() {
    try {
        const raw = localStorage.getItem(CONFIG_KEY);
        if (!raw) return null;
        const cfg = JSON.parse(raw);
        if (cfg.lunchStart && document.getElementById('lunchStart')) document.getElementById('lunchStart').value = cfg.lunchStart;
        if (cfg.lunchStart2 && document.getElementById('lunchStart2')) document.getElementById('lunchStart2').value = cfg.lunchStart2;
        if (cfg.lunchDur !== undefined && document.getElementById('lunchDur')) document.getElementById('lunchDur').value = cfg.lunchDur;
        if (cfg.postingDate && document.getElementById('postingDate')) document.getElementById('postingDate').value = cfg.postingDate;
        try { updateWorkerUIByTimeMode(); } catch (e) {}
        return cfg;
    } catch (e) { console.debug?.('loadConfig error', e?.message); return null; }
}

// Wire up auto-save for these controls
try {
    const ids = ['lunchStart','lunchStart2','lunchDur','postingDate'];
    ids.forEach(id => {
        const el = document.getElementById(id);
        if (!el) return;
        el.addEventListener('change', saveConfig);
        el.addEventListener('input', saveConfig);
    });
} catch (e) { console.debug?.('attach saveConfig listeners failed', e?.message); }

// Load persisted config now (so Clear/Reload restores these values)
loadConfig();
// Ensure timeMode is not restored from storage: always start in default 'total' on load/refresh
try { const tEl = document.getElementById('timeMode'); if (tEl) { tEl.value = 'total'; updateWorkerUIByTimeMode(); } } catch(e) { console.debug?.('reset timeMode default error', e?.message); }

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

// === МОДАЛЬНОЕ ОКНО НОМЕРОВ ПОДТВЕРЖДЕНИЯ ОПЕРАЦИЙ ===

// Возвращает номер подтверждения для операции (index начинается с 1)
// Логика: если операция отмечена как "последняя" - она пропускается в нумерации,
// остальные нумеруются последовательно, а пропущенная получает последний номер
function getOperationLabel(index, totalOps) {
    if (!operationFirstId || operationFirstId.trim() === '') {
        return String(index); // По умолчанию порядковый номер
    }
    
    const firstNum = Number.parseInt(operationFirstId, 10);
    if (Number.isNaN(firstNum)) return String(index);
    
    // Если эта операция отмечена как "последняя" - присваиваем ей последний номер
    if (lastOperationIndex !== null && index === lastOperationIndex) {
        const lastNum = firstNum + (totalOps - 1);
        return String(lastNum).padStart(8, '0');
    }
    
    // Для остальных операций: считаем позицию без учёта "последней"
    let position = index;
    if (lastOperationIndex !== null && index > lastOperationIndex) {
        // Если текущая операция после "последней", сдвигаем номер на 1 назад
        position = index - 1;
    }
    
    const opNum = firstNum + (position - 1);
    return String(opNum).padStart(8, '0');
}

// Обновляет текстовые метки с номерами операций в основной части (справа/слева)
function updateMainOperationLabels() {
    const blocks = document.querySelectorAll('.op-block');
    if (!blocks || blocks.length === 0) return;
    const total = Number.parseInt(document.getElementById('totalOps').value, 10) || blocks.length;
    blocks.forEach((blk, i) => {
        const lbl = blk.querySelector('.op-num-label');
        if (lbl) {
            try {
                lbl.textContent = getOperationLabel(i + 1, total);
            } catch (e) {
                // Safety: do not break UI if getOperationLabel fails
                lbl.textContent = String(i + 1);
            }
        }
    });
}

// Обновляет префиксы в полях ввода операций (например после изменения количества)
function updateOperationInputPrefixes() {
    const blocks = document.querySelectorAll('.op-block');
    if (!blocks) return;
    blocks.forEach((blk, i) => {
        const inp = blk.querySelector('.op-header-input');
        if (!inp) return;
        const prefix = `${i + 1}) `;
        const body = stripOrdinalPrefix(inp.value || '');
        inp.value = prefix + sanitizeStrict(body, 200);
    });
}

function renderOpsInputList() {
    const container = document.getElementById('opsInputList');
    const count = Number.parseInt(document.getElementById('totalOps').value, 10) || 1;
    container.innerHTML = '';
    
    // Получаем названия операций из полей ввода
    const opBlocks = document.querySelectorAll('.op-block');
    
    for (let i = 1; i <= count; i++) {
        const row = createEl('div', { className: 'op-input-row' });
        
        // Берём название операции из соответствующего блока
        let opName = `Операция ${i}`;
        if (opBlocks[i - 1]) {
            const nameInput = opBlocks[i - 1].querySelector('.op-header-input');
            if (nameInput && nameInput.value.trim()) {
                // Показываем полное значение поля, включая префикс (например "1) ...")
                opName = nameInput.value.trim();
            }
        }
        
        const label = createEl('label', { className: 'op-label', htmlFor: `op_id_${i}` }, `${opName}:`);
        
        // Для первой операции - редактируемый input, для остальных - disabled
        const isFirst = (i === 1);
        const input = createEl('input', {
            type: 'text',
            id: `op_id_${i}`,
            name: `op_id_${i}`,
            maxLength: '8',
            placeholder: isFirst ? '00000000' : 'авто',
            autocomplete: 'off'
        });
        
        if (isFirst) {
            input.value = operationFirstId || '';
            // Разрешаем только цифры
            input.addEventListener('input', (e) => {
                e.target.value = e.target.value.replaceAll(/[^0-9]/g, '').substring(0, 8);
                updateOpsCalculatedValues();
            });
        } else {
            input.disabled = true;
            // Рассчитываем значение с учётом галочки "последняя"
            if (operationFirstId && operationFirstId.trim()) {
                const firstNum = Number.parseInt(operationFirstId, 10);
                if (!Number.isNaN(firstNum)) {
                    // Если эта операция отмечена как "последняя" - показываем последний номер
                    if (lastOperationIndex === i) {
                        const lastNum = firstNum + (count - 1);
                        input.value = String(lastNum).padStart(8, '0');
                    } else {
                        // Считаем позицию без учёта "последней"
                        let position = i;
                        if (lastOperationIndex !== null && i > lastOperationIndex) {
                            position = i - 1;
                        }
                        input.value = String(firstNum + (position - 1)).padStart(8, '0');
                    }
                }
            }
        }
        
        // Галочка "последняя операция" (только для операций кроме первой)
        const checkboxWrapper = createEl('div', { 
            className: `op-checkbox-wrapper ${isFirst ? 'hidden' : ''}` 
        });
        const checkbox = createEl('input', {
            type: 'checkbox',
            id: `op_last_${i}`,
            name: 'op_last'
        });
        checkbox.checked = (lastOperationIndex === i);
        checkbox.dataset.opIndex = i;
        
        checkbox.addEventListener('change', (e) => {
            if (e.target.checked) {
                // Снимаем все остальные галочки
                document.querySelectorAll('#opsInputList input[name="op_last"]').forEach(cb => {
                    if (cb !== e.target) cb.checked = false;
                });
            }
            // Обновляем отображаемые номера
            updateOpsCalculatedValues();
        });
        
        const checkboxLabel = createEl('label', { htmlFor: `op_last_${i}` }, 'последняя');
        checkboxWrapper.append(checkbox, checkboxLabel);
        
        row.append(label, input, checkboxWrapper);
        container.append(row);
    }
}

function updateOpsCalculatedValues() {
    const firstInput = document.getElementById('op_id_1');
    if (!firstInput) return;
    
    const firstVal = firstInput.value.trim();
    const count = Number.parseInt(document.getElementById('totalOps').value, 10) || 1;
    
    // Находим, какая операция отмечена как "последняя"
    let markedLastIndex = null;
    document.querySelectorAll('#opsInputList input[name="op_last"]').forEach(cb => {
        if (cb.checked) {
            markedLastIndex = Number.parseInt(cb.dataset.opIndex, 10);
        }
    });
    
    for (let i = 2; i <= count; i++) {
        const input = document.getElementById(`op_id_${i}`);
        if (input) {
            if (firstVal && firstVal.length > 0) {
                const firstNum = Number.parseInt(firstVal, 10);
                if (!Number.isNaN(firstNum)) {
                    // Если эта операция отмечена как "последняя" - показываем последний номер
                    if (markedLastIndex === i) {
                        const lastNum = firstNum + (count - 1);
                        input.value = String(lastNum).padStart(8, '0');
                    } else {
                        // Считаем позицию без учёта "последней"
                        let position = i;
                        if (markedLastIndex !== null && i > markedLastIndex) {
                            position = i - 1;
                        }
                        input.value = String(firstNum + (position - 1)).padStart(8, '0');
                    }
                } else {
                    input.value = '';
                }
            } else {
                input.value = '';
            }
        }
    }
    // Обновляем метки в основной части, чтобы изменения в модальном окне были видны сразу
    try { updateMainOperationLabels(); } catch (e) { /* ignore */ }
}

function saveOperationIds() {
    const firstInput = document.getElementById('op_id_1');
    if (firstInput) {
        let val = firstInput.value.trim();
        if (val && val.length > 0 && val.length < 8) {
            val = val.padStart(8, '0');
        }
        operationFirstId = val;
    }
    
    // Проверяем, какая галочка "последняя операция" выбрана
    lastOperationIndex = null;
    document.querySelectorAll('#opsInputList input[name="op_last"]').forEach(cb => {
        if (cb.checked) {
            lastOperationIndex = Number.parseInt(cb.dataset.opIndex, 10);
        }
    });
    
    document.getElementById('opsModal').classList.remove('active');
    
    // Перерисовываем поля операций с учётом "последней операции"
    renderFields();
    // Обновляем метки операций в основной части
    try { updateMainOperationLabels(); } catch (e) { /* ignore */ }
}

function resetOperationIds() {
    operationFirstId = '';
    lastOperationIndex = null;
    renderOpsInputList();
    try { updateMainOperationLabels(); } catch (e) { /* ignore */ }
}

document.getElementById('setOpsBtn').addEventListener('click', async () => {
    const totalEl = document.getElementById('totalOps');
    if (!totalEl) return;

    // If totalOps is not locked yet, ask confirmation first
    if (!totalEl.disabled) {
        const msg = 'Вы уверены? Количество операций нельзя будет изменить.\nРазблокировка кнопкой "Очистить" или F5.';
        let confirmed = false;
        if (tauriDialog?.confirm) {
            try {
                confirmed = await tauriDialog.confirm(msg, { title: 'Подтверждение', kind: 'warning' });
            } catch (e) {
                confirmed = globalThis.confirm(msg);
            }
        } else {
            confirmed = globalThis.confirm(msg);
        }

        if (!confirmed) return;

        // Lock the input and mark visually
        totalEl.disabled = true;
        totalEl.classList.add('locked-input');
        try { renderFields(); } catch (e) { console.debug?.('renderFields after setOps lock failed', e?.message); }

        // Also disable tech-card selection and Save/Delete buttons
        try {
            const sel = document.getElementById('techCardSelect');
            if (sel) { sel.disabled = true; sel.classList.add('locked-input'); }
            const saveBtn = document.getElementById('saveCardBtn');
            if (saveBtn) { saveBtn.disabled = true; saveBtn.classList.add('locked-control'); }
            const delBtn = document.getElementById('deleteCardBtn');
            if (delBtn) { delBtn.disabled = true; delBtn.classList.add('locked-control'); }
        } catch (e) { console.debug?.('lock tech card controls failed', e?.message); }
    }

    // Now open the modal (no extra confirmation when already locked)
    renderOpsInputList();
    document.getElementById('opsModal').classList.add('active');
});

document.getElementById('closeOpsModal').addEventListener('click', () => {
    document.getElementById('opsModal').classList.remove('active');
});

document.getElementById('opsModal').addEventListener('click', (e) => {
    if (e.target.id === 'opsModal') {
        document.getElementById('opsModal').classList.remove('active');
    }
});

document.getElementById('saveOpsBtn').addEventListener('click', saveOperationIds);
document.getElementById('resetOpsBtn').addEventListener('click', resetOperationIds);

// При изменении количества операций обновляем модальное окно (если открыто)
document.getElementById('totalOps').addEventListener('change', () => {
    const modal = document.getElementById('opsModal');
    if (modal && modal.classList.contains('active')) {
        renderOpsInputList();
    }
});

// === МОДАЛЬНОЕ ОКНО НОМЕРОВ ИСПОЛНИТЕЛЕЙ ===
let workerIds = []; // Массив 8-значных номеров исполнителей

function getWorkerLabel(index) {
    // index начинается с 1
    if (workerIds[index - 1] && workerIds[index - 1].trim()) {
        // Ensure only digits are returned; pad to 8 if partially entered
        const raw = String(workerIds[index - 1]).trim();
        const digits = raw.replaceAll(/[^0-9]/g, '');
        if (digits.length === 0) return String(index);
        return digits.length >= 8 ? digits : digits.padStart(8, '0');
    }
    return String(index); // По умолчанию порядковый номер
}

function renderWorkersInputList() {
    const container = document.getElementById('workersInputList');
    const count = Number.parseInt(document.getElementById('workerCount').value, 10) || 1;
    container.innerHTML = '';
    
    for (let i = 1; i <= count; i++) {
        const row = createEl('div', { className: 'worker-input-row' });
        const label = createEl('label', { htmlFor: `worker_id_${i}` }, `Исполнитель ${i}:`);
        const input = createEl('input', {
            type: 'text',
            id: `worker_id_${i}`,
            name: `worker_id_${i}`,
            maxLength: '8',
            placeholder: '00000000',
            pattern: '[0-9]{8}',
            autocomplete: 'off'
        });
        input.value = workerIds[i - 1] || '';
        input.dataset.workerIndex = i - 1;
        
        // Разрешаем только цифры
        input.addEventListener('input', (e) => {
            // заменить все не-цифры (используем replaceAll с глобальным regex)
            e.target.value = e.target.value.replaceAll(/[^0-9]/g, '').substring(0, 8);
        });
        
        row.append(label, input);
        container.append(row);
    }
    // Load saved cheat notes into textarea (if any) and make it inactive by default
    try {
        const cheatEl = document.getElementById('workersCheat');
        const editBtn = document.getElementById('editWorkersBtn');
        if (cheatEl) {
            const saved = localStorage.getItem('z7_workers_cheat') || '';
            cheatEl.value = saved;
            // By default the cheat field is inactive until user presses "Изменить"
            cheatEl.disabled = true;
        }
        if (editBtn) editBtn.textContent = 'Изменить';
    } catch (e) {
        console.debug?.('renderWorkersInputList cheat load error:', e?.message);
    }
}

async function saveWorkerIds() {
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
    // Close modal; do NOT persist cheat here (user requested Save should not save cheat)
    document.getElementById('workersModal').classList.remove('active');
}

function resetWorkerIds() {
    workerIds = [];
    renderWorkersInputList();
}

document.getElementById('setWorkersBtn').addEventListener('click', async () => {
    const wcEl = document.getElementById('workerCount');
    if (!wcEl) return;

    // If workerCount is not locked yet, ask confirmation first
    if (!wcEl.disabled) {
        const msg = 'Вы уверены? Количество исполнителей нельзя будет изменить.\nРазблокировка кнопкой "Очистить" или F5.';
        let confirmed = false;
        if (tauriDialog?.confirm) {
            try {
                confirmed = await tauriDialog.confirm(msg, { title: 'Подтверждение', kind: 'warning' });
            } catch (e) {
                confirmed = globalThis.confirm(msg);
            }
        } else {
            confirmed = globalThis.confirm(msg);
        }

        if (!confirmed) return;

        // Lock the workerCount input and mark visually (do NOT disable tech-card controls)
        wcEl.disabled = true;
        wcEl.classList.add('locked-input');
        try { renderFields(); } catch (e) { console.debug?.('renderFields after setWorkers lock failed', e?.message); }
    }

    // Open workers modal (no extra confirmation when already locked)
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
// rememberWorkersBtn removed — its functionality is merged into edit button.

// Toggle edit mode for cheat textarea
document.getElementById('editWorkersBtn').addEventListener('click', async (e) => {
    try {
        const cheatEl = document.getElementById('workersCheat');
        const btn = e.target;
        if (!cheatEl || !btn) return;
        if (cheatEl.disabled) {
            // enable editing
            cheatEl.disabled = false;
            cheatEl.focus();
            btn.textContent = 'Готово';
        } else {
            // disable editing and auto-save the cheat
            cheatEl.disabled = true;
            btn.textContent = 'Изменить';
            try {
                const safeText = sanitizeInput(cheatEl.value || '', 5000);
                await safeLocalStorageSet('z7_workers_cheat', safeText);
                try { if (tauriDialog?.message) tauriDialog.message('Шпаргалка сохранена', { title: 'Инфо' }); } catch(e){}
            } catch (saveErr) {
                console.error('Auto-save workersCheat error:', saveErr);
            }
        }
    } catch (err) {
        console.error('editWorkersBtn toggle error:', err);
    }
});

// При изменении количества исполнителей обновляем модальное окно (если открыто)
const workerCountEl = document.getElementById('workerCount');
if (workerCountEl) {
    // While typing: keep only digits and clamp to max immediately
    workerCountEl.addEventListener('input', (e) => {
        let v = String(e.target.value).replaceAll(/[^0-9]/g, '');
        if (v !== '') {
            const n = Number.parseInt(v, 10);
            if (!Number.isNaN(n)) {
                const clamped = Math.max(1, Math.min(10, n));
                if (clamped !== n) v = String(clamped);
            }
        }
        e.target.value = v;
    });

    // Paste: sanitize and clamp
    workerCountEl.addEventListener('paste', (e) => {
        e.preventDefault();
        const text = (e.clipboardData || window.clipboardData).getData('text') || '';
        const digits = text.replaceAll(/[^0-9]/g, '');
        const n = Number.parseInt(digits || '0', 10) || 0;
        const clamped = validateNumber(n, 1, 10);
        workerCountEl.value = clamped;
        const modal = document.getElementById('workersModal');
        if (modal && modal.classList.contains('active')) {
            renderWorkersInputList();
        }
    });

    workerCountEl.addEventListener('change', (e) => {
        const val = validateNumber(e.target.value, 1, 10);
        e.target.value = val;
        const modal = document.getElementById('workersModal');
        if (modal && modal.classList.contains('active')) {
            renderWorkersInputList();
        }
        // Update per-operation worker checkboxes to reflect new count
        try { syncOpWorkersToCount(); } catch (ee) {}
    });
}

function syncOpWorkersToCount() {
    const count = Number.parseInt(document.getElementById('workerCount')?.value || '1', 10) || 1;
    const blocks = Array.from(document.querySelectorAll('.op-block'));
    blocks.forEach((block, idx) => {
        const box = block.querySelector('.op-workers-box');
        if (!box) return;
        const existing = Array.from(box.querySelectorAll('.op-worker-item'));
        const cur = existing.length;
        if (cur < count) {
            for (let w = cur + 1; w <= count; w++) {
                const id = `op_${idx+1}_worker_${w}`;
                const cb = createEl('input', { type: 'checkbox', className: 'op-worker-checkbox', id, 'data-worker': String(w) });
                cb.checked = true;
                const lbl = createEl('label', { htmlFor: id, className: 'op-worker-label' }, String(w));
                const wrapper = createEl('span', { className: 'op-worker-item' });
                wrapper.append(cb, lbl);
                box.append(wrapper);
                cb.addEventListener('change', (e) => {
                    if (!cb.checked) {
                        try {
                            const blocks2 = Array.from(document.querySelectorAll('.op-block'));
                            const curIdx2 = blocks2.indexOf(block);
                            if (curIdx2 >= 0) {
                                for (let bi = curIdx2 + 1; bi < blocks2.length; bi++) {
                                    const other = blocks2[bi].querySelector(`.op-worker-checkbox[data-worker="${w}"]`);
                                    if (other) other.checked = false;
                                }
                            }
                        } catch (err) { console.debug?.('propagate worker checkbox change error', err?.message); }
                    }
                });
            }
        } else if (cur > count) {
            // remove extra
            for (let i = cur; i > count; i--) {
                const item = existing[i-1];
                if (item) box.removeChild(item);
            }
        }
    });
}
