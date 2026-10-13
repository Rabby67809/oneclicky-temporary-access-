(function () {
    'use strict';

    [['amta-role', 'amta-admin-warning'], ['amta-role-bulk', 'amta-admin-warning-bulk']].forEach(function (pair) {
        const role = document.getElementById(pair[0]);
        const warning = document.getElementById(pair[1]);
        if (!role || !warning) return;
        const updateWarning = function () {
            warning.hidden = role.value !== 'administrator';
            const consent = warning.querySelector('input[type="checkbox"]');
            if (consent) {
                consent.required = !warning.hidden;
                if (warning.hidden) consent.checked = false;
            }
        };
        role.addEventListener('change', updateWarning);
        updateWarning();
    });

    document.querySelectorAll('.amta-revoke-form').forEach(function (form) {
        form.addEventListener('submit', function (event) {
            if (!window.confirm(amtaUI.confirmRevoke)) event.preventDefault();
        });
    });

    document.querySelectorAll('.amta-delete-form').forEach(function (form) {
        form.addEventListener('submit', function (event) {
            if (!window.confirm(amtaUI.confirmDelete)) event.preventDefault();
        });
    });

    // A hidden duration option must be disabled so the server receives only
    // the values for the selected custom/exact mode.
    document.querySelectorAll('.amta-duration-fields').forEach(function (widget) {
        const selector = widget.querySelector('.amta-duration-select');
        const custom = widget.querySelector('.amta-duration-custom');
        const exact = widget.querySelector('.amta-duration-exact');
        if (!selector || !custom || !exact) return;
        const update = function () {
            [[custom, selector.value === 'custom'], [exact, selector.value === 'exact']].forEach(function (entry) {
                entry[0].hidden = !entry[1];
                entry[0].querySelectorAll('input, select').forEach(function (field) {
                    field.disabled = !entry[1];
                    field.required = entry[1] && (field.name === 'amta_custom_value' || field.name === 'amta_exact_time');
                });
            });
        };
        selector.addEventListener('change', update);
        update();
    });

    async function copyText(value) {
        if (navigator.clipboard && window.isSecureContext) {
            await navigator.clipboard.writeText(value);
            return;
        }
        const temp = document.createElement('textarea');
        temp.value = value;
        temp.setAttribute('readonly', '');
        temp.style.position = 'fixed';
        temp.style.left = '-9999px';
        document.body.appendChild(temp);
        temp.select();
        let copied = false;
        try { copied = document.execCommand('copy'); }
        finally { document.body.removeChild(temp); }
        if (!copied) throw new Error('clipboard unavailable');
    }

    function showCopied(button) {
        const oldLabel = button.textContent;
        button.textContent = amtaUI.copied;
        window.setTimeout(function () { button.textContent = oldLabel; }, 1800);
    }

    document.querySelectorAll('.amta-copy').forEach(function (button) {
        button.addEventListener('click', async function () {
            const input = document.querySelector(button.getAttribute('data-copy'));
            if (!input) return;
            try {
                await copyText(input.value);
                showCopied(button);
            } catch (error) {
                input.focus();
                input.select();
                window.alert(amtaUI.copyFailed);
            }
        });
    });

    document.querySelectorAll('.amta-copy-all').forEach(function (button) {
        button.addEventListener('click', async function () {
            const rows = Array.from(document.querySelectorAll('.amta-new-recipient'));
            const content = rows.map(function (row) {
                const name = row.querySelector('strong');
                const email = row.querySelector('small');
                const link = row.querySelector('input.amta-generated-link');
                return (name ? name.textContent : '') + ' (' + (email ? email.textContent : '') + ')\n' + (link ? link.value : '');
            }).join('\n\n');
            try {
                await copyText(content);
                showCopied(button);
            } catch (error) {
                window.alert(amtaUI.copyFailed);
            }
        });
    });
})();

// OneClicky 1.3: visual countdowns; never authoritative for permissions.
(function () {
    'use strict';
    const list = document.querySelector('.amta-link-grid[data-server-now]');
    if (!list) return;
    const serverNow = Number(list.dataset.serverNow);
    const clockOffset = Number.isFinite(serverNow) ? serverNow * 1000 - Date.now() : 0;
    const timers = Array.from(list.querySelectorAll('[data-amta-countdown][data-until]'));
    const pad = function (v) { return String(v).padStart(2, '0'); };
    const update = function () {
        const now = (Date.now() + clockOffset) / 1000;
        timers.forEach(function (timer) {
            const node = timer.querySelector('.amta-timer-value');
            if (!node) return;
            const remaining = Math.max(0, Math.ceil(Number(timer.dataset.until) - now));
            const days = Math.floor(remaining / 86400);
            const hours = Math.floor(remaining % 86400 / 3600);
            const mins = Math.floor(remaining % 3600 / 60);
            const seconds = remaining % 60;
            node.textContent = remaining === 0 ? '00:00:00' : (days ? days + 'd ' : '') + pad(hours) + ':' + pad(mins) + ':' + pad(seconds);
            timer.classList.toggle('amta-time-ended', remaining === 0);
            timer.classList.toggle('amta-time-warning', remaining > 0 && remaining <= 300);
            if (remaining === 0 && timer.classList.contains('amta-countdown-restore')) {
                const restore = timer.closest('.amta-link-card').querySelector('.amta-restore-details');
                if (restore) {
                    restore.remove();
                }
            }
        });
    };
    update();
    window.setInterval(update, 1000);
    document.querySelectorAll('.amta-restore-form').forEach(function (form) {
        form.addEventListener('submit', function (event) {
            if (!window.confirm(amtaUI.confirmRestore)) event.preventDefault();
        });
    });
})();


// OneClicky 1.5: admin status is read from the server, not guessed from link clicks.
(function () {
    'use strict';
    const config = window.amtaUI && window.amtaUI.presence;
    const cards = Array.from(document.querySelectorAll('.amta-link-card[data-amta-access-id]'));
    if (!config || !cards.length || !window.fetch) return;
    let inFlight = false;
    async function refreshPresence() {
        if (inFlight || document.visibilityState === 'hidden') return;
        inFlight = true;
        const body = new URLSearchParams();
        body.set('action', 'amta_presence_statuses');
        body.set('nonce', config.nonce);
        cards.forEach(function (card) { body.append('ids[]', card.dataset.amtaAccessId); });
        try {
            const response = await fetch(config.url, {method: 'POST', credentials: 'same-origin', cache: 'no-store', body: body});
            if (!response.ok) return;
            const result = await response.json();
            if (!result || !result.success || !result.data || !result.data.states) return;
            cards.forEach(function (card) {
                const state = result.data.states[card.dataset.amtaAccessId];
                if (!state) return;
                const badge = card.querySelector('[data-amta-presence-status]');
                const detail = card.querySelector('[data-amta-presence-detail] span:last-child');
                if (badge && badge.textContent !== state.label) badge.textContent = state.label;
                if (badge) {
                    ['pending','working','idle','active','expired','revoked','deleted'].forEach(function (name) { badge.classList.remove('amta-status-' + name); });
                    badge.classList.add('amta-status-' + state.code);
                }
                if (detail && detail.textContent !== state.detail) detail.textContent = state.detail;
            });
        } catch (error) {
            // A lost connection must never present an invented online status.
        } finally {
            inFlight = false;
        }
    }
    window.setInterval(refreshPresence, Math.max(15000, Number(config.refreshMs) || 30000));
    document.addEventListener('visibilitychange', function () {
        if (document.visibilityState === 'visible') refreshPresence();
    });
})();

// OneClicky 1.7: Show the allowed-plugin selector only for plugin toggle scope.
(function () {
    'use strict';
    document.querySelectorAll('.amta-unlock-form').forEach(function (form) {
        var scope = form.querySelector('.amta-unlock-scope');
        var row = form.querySelector('.amta-unlock-plugin-label');
        if (!scope || !row) return;
        var field = row.querySelector('select');
        function sync() {
            var plugins = scope.value === 'plugin_toggle';
            row.hidden = !plugins;
            if (field) { field.disabled = !plugins; field.required = plugins; }
        }
        scope.addEventListener('change', sync);
        sync();
    });
})();

// v1.9 multi-select convenience only; server policy remains authoritative.
(function () {
  'use strict';
  document.querySelectorAll('.amta-multi-unlock').forEach(function (form) {
    const selectContent = form.querySelector('[data-amta-select="content"]');
    const clear = form.querySelector('[data-amta-select="clear"]');
    const choices = Array.from(form.querySelectorAll('input[name="amta_scopes[]"]'));
    if (selectContent) selectContent.addEventListener('click', function () {
      choices.forEach(function (item) {
        if (!item.disabled && ['posts_edit','posts_publish','posts_delete','pages_edit','pages_publish','pages_delete','media','comments','categories'].indexOf(item.value) !== -1) item.checked = true;
      });
    });
    if (clear) clear.addEventListener('click', function () {
      choices.forEach(function (item) { item.checked = false; });
    });
  });
})();


// v1.12: convenience for the per-invitation owner-only lock manager.
(function () {
    'use strict';
    document.querySelectorAll('.amta-feature-lock-form').forEach(function (form) {
        var groups = Array.from(form.querySelectorAll('input[name="amta_locked_groups[]"]'));
        var extras = Array.from(form.querySelectorAll('input[name="amta_locked_caps[]"]'));
        var all = form.querySelector('.amta-lock-select-all');
        var clear = form.querySelector('.amta-lock-clear');
        if (all) all.addEventListener('click', function () { groups.forEach(function (input) { input.checked = true; }); });
        if (clear) clear.addEventListener('click', function () { groups.concat(extras).forEach(function (input) { input.checked = false; }); });
        var search = form.querySelector('.amta-extra-cap-search');
        if (search) search.addEventListener('input', function () {
            var filter = search.value.trim().toLowerCase();
            form.querySelectorAll('.amta-extra-cap-item').forEach(function (row) {
                row.hidden = row.textContent.toLowerCase().indexOf(filter) === -1;
            });
        });
    });
})();

;document.querySelectorAll('[data-amta-emergency-confirm]').forEach(function(btn){btn.addEventListener('click',function(event){if(!window.confirm(btn.getAttribute('data-amta-emergency-confirm'))){event.preventDefault();}});});


// v1.14 expiry manager — server timestamps are authoritative; this is only a preview.
(function () {
    'use strict';
    const editors = Array.from(document.querySelectorAll('[data-amta-expiry-editor]'));
    if (!editors.length) return;
    const factors = {minutes: 60, hours: 3600, days: 86400};
    function formatSeconds(seconds) {
        seconds = Math.max(0, Math.ceil(seconds));
        const days = Math.floor(seconds / 86400);
        const hours = Math.floor((seconds % 86400) / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        const secs = seconds % 60;
        return (days ? days + 'd ' : '') + [hours, minutes, secs].map(function (n) { return String(n).padStart(2, '0'); }).join(':');
    }
    editors.forEach(function (form) {
        const initialNow = Number(form.dataset.serverNow);
        const clockOffset = Number.isFinite(initialNow) ? initialNow * 1000 - Date.now() : 0;
        const currentEnd = Number(form.dataset.currentUntil);
        const mode = form.querySelector('[data-amta-expiry-mode]');
        const basis = form.querySelector('[data-amta-expiry-basis]');
        const basisWrap = form.querySelector('[data-amta-basis-wrap]');
        const custom = form.querySelector('[data-amta-expiry-custom]');
        const exact = form.querySelector('[data-amta-expiry-exact]');
        const currentEl = form.querySelector('[data-amta-current-remaining]');
        const afterEl = form.querySelector('[data-amta-new-remaining]');
        const deltaEl = form.querySelector('[data-amta-expiry-change]');
        const submit = form.querySelector('[type="submit"]');
        const amount = custom.querySelector('input');
        const unit = custom.querySelector('select');
        const exactDate = exact.querySelector('input');
        function update() {
            const now = (Date.now() + clockOffset) / 1000;
            const remainder = Math.max(0, currentEnd - now);
            currentEl.textContent = formatSeconds(remainder);
            const isCustom = mode.value === 'custom';
            const isExact = mode.value === 'exact';
            custom.hidden = !isCustom;
            exact.hidden = !isExact;
            amount.disabled = !isCustom;
            unit.disabled = !isCustom;
            amount.required = isCustom;
            exactDate.disabled = !isExact;
            exactDate.required = isExact;
            basisWrap.hidden = isExact;
            basis.disabled = isExact;
            if (isExact) {
                afterEl.textContent = exactDate.value ? exactDate.value.replace('T', ' ') : 'Select a date and time';
                deltaEl.textContent = 'Site timezone. WordPress will validate the exact expiry when you save.';
                submit.disabled = !exactDate.value;
                return;
            }
            const value = isCustom ? Number(amount.value) * (factors[unit.value] || 0) : Number(mode.value) * 60;
            if (!Number.isFinite(value) || !Number.isInteger(value) || value <= 0 || (isCustom && (!/^[1-9]\d*$/.test(amount.value)))) {
                afterEl.textContent = 'Enter a valid duration';
                deltaEl.textContent = 'Only positive whole-number amounts are allowed.';
                submit.disabled = true;
                return;
            }
            const target = (basis.value === 'current' ? currentEnd : now) + value;
            const result = target - now;
            const valid = result >= 300 && result <= 365 * 86400;
            afterEl.textContent = formatSeconds(result);
            const change = target - currentEnd;
            deltaEl.textContent = !valid ? 'Outside the allowed range: 5 minutes to 365 days from now.' :
                (change < -1 ? 'Shortens access by ' + formatSeconds(-change) + '.' :
                (change > 1 ? 'Extends access by ' + formatSeconds(change) + '.' : 'Expiration stays approximately the same.'));
            submit.disabled = !valid;
        }
        [mode, basis, amount, unit, exactDate].forEach(function (el) {
            el.addEventListener('change', update);
            el.addEventListener('input', update);
        });
        form.closest('details').addEventListener('toggle', function (event) { if (event.target.open) update(); });
        update();
        window.setInterval(function () {
            if (form.closest('details').open && document.visibilityState !== 'hidden') update();
        }, 1000);
    });
})();
