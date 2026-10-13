/* Mint Runner – an original, fully local canvas runner inspired by offline jump games.
 * No external assets, analytics, score storage, or access-control interactions.
 */
(function () {
    'use strict';
    const canvas = document.getElementById('amta-runner-canvas');
    const start = document.getElementById('amta-runner-start');
    const jump = document.getElementById('amta-runner-jump');
    const scoreNode = document.getElementById('amta-runner-score');
    const bestNode = document.getElementById('amta-runner-best');
    const message = document.getElementById('amta-runner-message');
    if (!canvas || !start || !jump || !scoreNode || !bestNode || !message || !canvas.getContext) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    const W = 640;
    const H = 220;
    const GROUND = 177;
    const HERO_X = 70;
    const HERO_W = 42;
    const HERO_H = 48;
    let mode = 'ready';
    let score = 0;
    let best = 0; // This-page memory only, never persisted.
    let offset = 0;
    let distance = 0;
    let speed = 5.3;
    let obstacleDelay = 74;
    let obstacles = [];
    let playerY = 0;
    let vy = 0;
    let frameId = 0;
    let lastFrame = 0;
    let stride = 0;
    const clouds = [{x: 115, y: 43, s: 1.1}, {x: 350, y: 28, s: .85}, {x: 570, y: 59, s: 1}];

    function digits(n) { return String(Math.max(0, Math.floor(n))).padStart(5, '0'); }
    function rect(x, y, w, h, color) {
        ctx.fillStyle = color;
        ctx.fillRect(Math.round(x), Math.round(y), Math.round(w), Math.round(h));
    }
    function print(text, y, size, color) {
        ctx.save();
        ctx.fillStyle = color;
        ctx.textAlign = 'center';
        ctx.font = 'bold ' + size + 'px system-ui, sans-serif';
        ctx.fillText(text, W / 2, y);
        ctx.restore();
    }
    function drawCloud(x, y, scale) {
        ctx.save();
        ctx.translate(x, y);
        ctx.scale(scale, scale);
        ctx.fillStyle = '#dfede5';
        ctx.fillRect(6, 11, 52, 3);
        ctx.fillRect(13, 6, 30, 6);
        ctx.fillRect(22, 2, 16, 6);
        ctx.restore();
    }
    function drawHero(y) {
        const x = HERO_X;
        // Green pixel dinosaur: custom silhouette, not Chrome's copyrighted sprite.
        const moss = '#176d53';
        const mint = '#27ad77';
        rect(x + 20, y, 25, 22, moss);
        rect(x + 26, y - 3, 18, 5, mint);
        rect(x + 40, y + 9, 10, 8, moss);
        rect(x + 18, y + 15, 21, 18, moss);
        rect(x + 11, y + 24, 26, 10, mint);
        rect(x + 2, y + 25, 15, 7, moss);
        rect(x - 5, y + 20, 11, 5, moss);
        rect(x + 33, y + 26, 13, 5, moss);
        rect(x + 37, y + 30, 5, 5, moss);
        const jumpPhase = playerY > 2;
        const legA = !jumpPhase && Math.floor(stride / 6) % 2 === 0;
        rect(x + 13, y + 33, 7, legA ? 14 : 11, moss);
        rect(x + 28, y + 33, 7, legA ? 11 : 14, moss);
        rect(x + 9, y + (legA ? 44 : 41), 13, 4, moss);
        rect(x + 27, y + (legA ? 41 : 44), 13, 4, moss);
        rect(x + 35, y + 6, 4, 4, '#ffffff');
        rect(x + 37, y + 7, 2, 2, '#0a2730');
        rect(x + 41, y + 18, 7, 2, '#fbfcf9');
    }
    function drawCactus(obstacle) {
        const x = obstacle.x;
        const y = GROUND - obstacle.h;
        const c = '#218c65';
        const shade = '#137657';
        const mainX = x + Math.round(obstacle.w * .45);
        rect(mainX - 4, y, 10, obstacle.h, c);
        rect(mainX - 10, y + 15, 7, 6, c);
        rect(mainX - 13, y + 5, 6, 16, c);
        rect(mainX + 6, y + 27, 10, 6, c);
        rect(mainX + 12, y + 17, 5, 17, shade);
        rect(mainX - 4, y + 3, 3, obstacle.h - 7, '#50c892');
        if (obstacle.w > 28) {
            rect(x + 4, GROUND - 26, 7, 26, shade);
            rect(x, GROUND - 21, 6, 5, shade);
            rect(x, GROUND - 29, 4, 13, shade);
        }
    }
    function paint() {
        // Backdrop and parallax decoration remain visible while idle.
        ctx.clearRect(0, 0, W, H);
        rect(0, 0, W, H, '#fbfefb');
        rect(0, GROUND + 2, W, H - GROUND, '#f0f8f1');
        clouds.forEach(function (cloud) { drawCloud(cloud.x, cloud.y, cloud.s); });
        rect(0, GROUND, W, 2, '#709d86');
        for (let i = 0; i < 22; i++) {
            const xx = ((i * 39 - offset) % (W + 45) + W + 45) % (W + 45);
            rect(xx, GROUND + 12 + i % 3 * 6, (i % 3 + 1) * 5, 2, '#aac7b3');
        }
        obstacles.forEach(drawCactus);
        drawHero(GROUND - HERO_H - playerY);
        if (mode === 'ready') {
            print('MINT RUNNER', 74, 26, '#1b7657');
            print('Tap START or press SPACE to run', 97, 14, '#688f79');
        } else if (mode === 'over') {
            rect(158, 45, 325, 78, '#f3faf4');
            print('GAME OVER', 77, 26, '#244c3a');
            print('Tap RESTART to try again', 101, 14, '#688f79');
        }
    }
    function spawn() {
        const h = 35 + Math.random() * 16;
        const w = Math.random() > 0.7 ? 34 : 22;
        obstacles.push({x: W + 10, w: w, h: h});
        obstacleDelay = (62 + Math.random() * 57) * Math.max(.69, 5.3 / speed);
    }
    function collision(o) {
        // A conservative hitbox avoids unfair near-misses against pixel art.
        const px = HERO_X + 8;
        const py = GROUND - HERO_H - playerY + 8;
        const pw = HERO_W - 8;
        const ph = HERO_H - 8;
        return px + pw > o.x + 4 && px < o.x + o.w - 2 && py + ph > GROUND - o.h + 5 && py < GROUND - 5;
    }
    function endGame() {
        mode = 'over';
        best = Math.max(best, score);
        bestNode.textContent = digits(best);
        start.textContent = 'Restart';
        message.textContent = 'Game over! ' + score + ' points. Try another run!';
        if (frameId) cancelAnimationFrame(frameId);
        frameId = 0;
        paint();
    }
    function step(time) {
        if (mode !== 'running') return;
        if (!lastFrame) lastFrame = time;
        const factor = Math.min(2.25, (time - lastFrame) / (1000 / 60));
        lastFrame = time;
        if (factor > 0) {
            distance += speed * factor;
            score = Math.floor(distance / 11);
            scoreNode.textContent = digits(score);
            speed = Math.min(11.5, 5.3 + distance / 1700);
            offset = (offset + speed * factor) % (W + 45);
            stride += factor;
            clouds.forEach(function (c) { c.x -= speed * factor * .18; if (c.x < -75) c.x = W + 30; });
            if (playerY > 0 || vy > 0) {
                playerY += vy * factor;
                vy -= .8 * factor;
                if (playerY <= 0) { playerY = 0; vy = 0; }
            }
            obstacleDelay -= factor;
            if (obstacleDelay <= 0) spawn();
            obstacles.forEach(function (o) { o.x -= speed * factor; });
            obstacles = obstacles.filter(function (o) { return o.x + o.w > -15; });
            if (obstacles.some(collision)) { endGame(); return; }
        }
        paint();
        frameId = requestAnimationFrame(step);
    }
    function begin() {
        if (frameId) cancelAnimationFrame(frameId);
        mode = 'running';
        score = 0;
        distance = 0;
        offset = 0;
        speed = 5.3;
        stride = 0;
        playerY = 0;
        vy = 0;
        obstacles = [];
        obstacleDelay = 85;
        lastFrame = 0;
        scoreNode.textContent = digits(0);
        start.textContent = 'Restart';
        message.textContent = 'Jump over the cactus! Space, Up Arrow or tap Jump.';
        paint();
        frameId = requestAnimationFrame(step);
    }
    function doJump() {
        if (mode !== 'running') begin();
        if (playerY === 0) vy = 13.6;
        if (typeof canvas.focus === 'function') canvas.focus({preventScroll: true});
    }
    start.addEventListener('click', function () {
        begin();
        canvas.focus({preventScroll: true});
    });
    jump.addEventListener('click', doJump);
    canvas.addEventListener('pointerdown', doJump);
    document.addEventListener('keydown', function (e) {
        if (e.code !== 'Space' && e.code !== 'ArrowUp') return;
        const target = e.target;
        const inGame = target === canvas || target === start || target === jump;
        if (!inGame && mode !== 'running') return;
        if (target && /^(INPUT|TEXTAREA|SELECT)$/.test(target.tagName)) return;
        e.preventDefault();
        doJump();
    });
    document.addEventListener('visibilitychange', function () {
        if (document.hidden && mode === 'running') {
            // Pause by ending the animation, preventing time jumps on tab return.
            if (frameId) cancelAnimationFrame(frameId);
            frameId = 0;
            mode = 'over';
            best = Math.max(best, score);
            bestNode.textContent = digits(best);
            start.textContent = 'Restart';
            message.textContent = 'Run paused when you left the tab. Tap Restart to play again.';
            paint();
        }
    });
    paint();
})();
