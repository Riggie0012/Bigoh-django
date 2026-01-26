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
