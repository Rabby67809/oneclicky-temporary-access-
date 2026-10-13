/* OneClicky temporary-account presence: no page titles, input data or cursor data is collected. */
(function () {
    'use strict';
    const config = window.amtaPresence;
    if (!config || !config.url || !config.nonce || !window.fetch) return;

    let lastInteraction = Date.now();
    let lastSubmission = 0;
    let inFlight = false;
    let ended = false;

    // Track only WHEN the browser was used (not what was typed or clicked).
    const touched = function () { lastInteraction = Date.now(); };
    ['pointerdown', 'keydown', 'scroll', 'touchstart'].forEach(function (name) {
        window.addEventListener(name, touched, { passive: true });
    });
    window.addEventListener('focus', touched);
    document.addEventListener('visibilitychange', function () {
        if (document.visibilityState === 'visible') touched();
    });

    async function ping() {
        const now = Date.now();
        if (ended || inFlight || document.visibilityState !== 'visible' ||
            now - lastInteraction > 120000 || now - lastSubmission < 45000) return;
        inFlight = true;
        lastSubmission = now;
        const body = new URLSearchParams({ action: 'amta_presence_ping', nonce: config.nonce });
        try {
            const response = await fetch(config.url, {method: 'POST', credentials: 'same-origin', cache: 'no-store', body: body});
            if (response.status === 403) ended = true;
        } catch (error) {
            // No connectivity: server-side presence naturally expires after 3 minutes.
        } finally {
            inFlight = false;
        }
    }
    // Initial dashboard load has already been recorded server-side.
    window.setInterval(ping, 45000);
})();
