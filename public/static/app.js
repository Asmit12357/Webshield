/*
 * WebShield progressive enhancements. Every page works without this file.
 * Each feature looks for its own data- attribute and does nothing if it is absent:
 *   [data-scan-form]   scan form: disable the button and animate the console while the scan runs
 *   [data-fill]        quick-fill button; its value goes into the input named by data-fill-into
 *   [data-copy]        button that copies the text of the element named by its value
 *   details.fix        opened before printing so a printed report shows every fix
 */
(function () {
    'use strict';

    var reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    function initScanForm() {
        var form = document.querySelector('[data-scan-form]');
        if (!form) return;

        var button = form.querySelector('[data-scan-button]');
        var status = document.querySelector('[data-scan-status]');
        var log = document.querySelector('[data-console-log]');
        var rows = log ? Array.prototype.slice.call(log.querySelectorAll('li')) : [];
        var tags = rows.map(function (row) { return row.querySelector('.log-tag'); });
        var originalTags = tags.map(function (tag) { return tag ? tag.textContent : null; });
        var idleLabel = button.textContent;
        var timers = [];

        // The example lines step through "checking" so the page visibly works. It cannot follow the
        // real scan, so it shows activity only, never which check has finished.
        function start() {
            button.disabled = true;
            button.textContent = 'Scanning…';
            if (status) status.hidden = false;
            if (!log) return;
            log.classList.add('is-scanning');
            rows.forEach(function (row, i) {
                timers.push(setTimeout(function () {
                    rows.forEach(function (r) { r.classList.remove('is-active'); });
                    row.classList.add('is-active');
                    if (tags[i]) tags[i].textContent = 'checking…';
                }, reducedMotion ? 0 : i * 900));
            });
        }

        function reset() {
            timers.forEach(clearTimeout);
            timers = [];
            button.disabled = false;
            button.textContent = idleLabel;
            if (status) status.hidden = true;
            if (!log) return;
            log.classList.remove('is-scanning');
            rows.forEach(function (row, i) {
                row.classList.remove('is-active');
                if (tags[i]) tags[i].textContent = originalTags[i];
            });
        }

        form.addEventListener('submit', start);
        // The back/forward cache can restore the page in its mid-scan state.
        window.addEventListener('pageshow', reset);
    }

    function initQuickFill() {
        document.querySelectorAll('[data-fill]').forEach(function (el) {
            el.addEventListener('click', function () {
                var input = document.querySelector(el.getAttribute('data-fill-into'));
                if (!input) return;
                input.value = el.getAttribute('data-fill');
                input.focus();
            });
        });
    }

    function initCopyButtons() {
        if (!navigator.clipboard) return;
        document.querySelectorAll('[data-copy]').forEach(function (btn) {
            var source = document.querySelector(btn.getAttribute('data-copy'));
            if (!source) return;
            var idleLabel = btn.textContent;
            btn.hidden = false;
            btn.addEventListener('click', function () {
                navigator.clipboard.writeText(source.textContent).then(function () {
                    btn.textContent = 'Copied';
                    setTimeout(function () { btn.textContent = idleLabel; }, 2000);
                });
            });
        });
    }

    function initPrint() {
        window.addEventListener('beforeprint', function () {
            document.querySelectorAll('details.fix').forEach(function (d) { d.open = true; });
        });
    }

    initScanForm();
    initQuickFill();
    initCopyButtons();
    initPrint();
})();
