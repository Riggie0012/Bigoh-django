// JavaScript Document
function initFlashTimers() {
    const timers = document.querySelectorAll(".flash-sale-timer[data-countdown]");
    timers.forEach((timer) => {
        let remaining = parseInt(timer.getAttribute("data-countdown"), 10);
        if (Number.isNaN(remaining) || remaining <= 0) {
            return;
        }
        const label = timer.querySelector("span");
        if (!label) {
            return;
        }
        const pad = (value) => String(value).padStart(2, "0");
        const render = () => {
            const hours = Math.floor(remaining / 3600);
            const minutes = Math.floor((remaining % 3600) / 60);
            const seconds = remaining % 60;
            label.textContent = `${pad(hours)}h : ${pad(minutes)}m : ${pad(seconds)}s`;
        };
        render();
        const interval = setInterval(() => {
            remaining -= 1;
            if (remaining < 0) {
                clearInterval(interval);
                return;
            }
            render();
        }, 1000);
    });
}

if (typeof window.jQuery !== "undefined") {
    jQuery(function($) {
        if ($.fn.lightSlider) {
            $(".autoWidth").lightSlider({
                autoWidth: true,
                loop: true,
                onSliderLoad: function() {
                    $(".autoWidth").removeClass("cS-hidden");
                }
            });
        }
        initFlashTimers();
    });
} else {
    document.addEventListener("DOMContentLoaded", initFlashTimers);
}

function applyCsrfToForms() {
    const meta = document.querySelector("meta[name='csrf-token']");
    if (!meta) return;
    const token = meta.getAttribute("content");
    if (!token) return;
    document.querySelectorAll("form").forEach((form) => {
        const method = (form.getAttribute("method") || "GET").toUpperCase();
        if (method !== "POST") return;
        if (form.querySelector("input[name='csrf_token']")) return;
        const input = document.createElement("input");
        input.type = "hidden";
        input.name = "csrf_token";
        input.value = token;
        form.appendChild(input);
    });
}

document.addEventListener("DOMContentLoaded", applyCsrfToForms);

function applyCsrfToFetch() {
    const meta = document.querySelector("meta[name='csrf-token']");
    const token = meta?.getAttribute("content");
    if (!token || !window.fetch) return;

    const originalFetch = window.fetch.bind(window);
    window.fetch = (input, init = {}) => {
        const method = (init.method || "GET").toUpperCase();
        if (method === "GET" || method === "HEAD") {
            return originalFetch(input, init);
        }
        const headers = new Headers(init.headers || {});
        if (!headers.has("X-CSRF-Token")) {
            headers.set("X-CSRF-Token", token);
        }
        return originalFetch(input, { ...init, headers });
    };
}

document.addEventListener("DOMContentLoaded", applyCsrfToFetch);

function updateCartBadge(count) {
    const badge = document.getElementById("cartCountBadge");
    if (!badge) return;
    const value = Number.isFinite(count) ? count : parseInt(count, 10) || 0;
    badge.textContent = value;
    if (value > 0) {
        badge.classList.remove("d-none");
    } else {
        badge.classList.add("d-none");
    }
}

function showCartToast(message, level) {
    const toast = document.getElementById("cartToast");
    if (!toast || !message) return;
    toast.textContent = message;
    toast.classList.remove("success", "warning", "danger", "show");
    if (level) toast.classList.add(level);
    requestAnimationFrame(() => toast.classList.add("show"));
    clearTimeout(showCartToast._timer);
    showCartToast._timer = setTimeout(() => {
        toast.classList.remove("show");
    }, 1800);
}

document.addEventListener("submit", (event) => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement)) return;
    if (!form.action || !form.action.includes("/add_to_cart/")) return;
    event.preventDefault();

    const submitBtn = form.querySelector("button[type='submit'], input[type='submit']");
    const originalText = submitBtn && submitBtn.tagName === "BUTTON" ? submitBtn.textContent : null;
    if (submitBtn) {
        submitBtn.disabled = true;
        if (originalText) submitBtn.textContent = "Adding...";
    }

    fetch(form.action, {
        method: "POST",
        body: new FormData(form),
        headers: {
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "application/json",
            "X-CSRF-Token": document.querySelector("meta[name='csrf-token']")?.getAttribute("content") || ""
        },
        credentials: "same-origin"
    })
        .then(async (res) => {
            const data = await res.json().catch(() => ({}));
            if (!res.ok || data.ok === false) {
                const msg = data.message || "Unable to add item.";
                showCartToast(msg, data.level || "danger");
                throw new Error(msg);
            }
            updateCartBadge(data.cart_count);
            showCartToast(data.message || "Added to cart.", data.level || "success");
        })
        .catch(() => {})
        .finally(() => {
            if (submitBtn) {
                submitBtn.disabled = false;
                if (originalText) submitBtn.textContent = originalText;
            }
        });
});
