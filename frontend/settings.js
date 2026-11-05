const defaults = {
    appName: "ReconSuite Lite",
    language: "en",
    startupPage: "/",
    theme: "dark",
    compactMode: false,
    scanProfile: "passive",
    timeout: 15,
    requestDelay: 1000,
    passiveMode: true,
    targetReminder: true,
    exportFormat: "pdf",
    includeTimestamp: true
};

const fields = Object.keys(defaults);

function applySettings(settings) {
    fields.forEach(key => {
        const element = document.getElementById(key);
        if (!element) return;

        if (element.type === "checkbox") {
            element.checked = Boolean(settings[key]);
        } else {
            element.value = settings[key];
        }
    });

    document.body.classList.toggle(
        "light-mode",
        settings.theme === "light"
    );

    document.body.classList.toggle(
        "compact-mode",
        Boolean(settings.compactMode)
    );
}

function getSettings() {
    const settings = {};

    fields.forEach(key => {
        const element = document.getElementById(key);

        if (element.type === "checkbox") {
            settings[key] = element.checked;
        } else if (["timeout", "requestDelay"].includes(key)) {
            settings[key] = Number(element.value);
        } else {
            settings[key] = element.value;
        }
    });

    return settings;
}

function validate(settings) {
    if (!settings.appName.trim()) {
        return "Application name cannot be empty.";
    }

    if (!Number.isInteger(settings.timeout) ||
        settings.timeout < 3 || settings.timeout > 120) {
        return "Timeout must be between 3 and 120 seconds.";
    }

    if (!Number.isInteger(settings.requestDelay) ||
        settings.requestDelay < 0 ||
        settings.requestDelay > 10000) {
        return "Request delay must be between 0 and 10000 ms.";
    }

    return null;
}

function loadSettings() {
    try {
        const saved = JSON.parse(
            localStorage.getItem("reconsuite_settings") || "{}"
        );

        applySettings({...defaults, ...saved});
    } catch {
        applySettings(defaults);
    }
}

document.getElementById("saveBtn").addEventListener("click", () => {
    const settings = getSettings();
    const error = validate(settings);

    if (error) {
        document.getElementById("message").textContent = error;
        return;
    }

    localStorage.setItem(
        "reconsuite_settings",
        JSON.stringify(settings)
    );

    applySettings(settings);

    document.getElementById("message").textContent =
        "✓ Settings saved successfully.";
});

document.getElementById("resetBtn").addEventListener("click", () => {
    if (!confirm("Reset all settings to their default values?")) return;

    localStorage.removeItem("reconsuite_settings");
    applySettings(defaults);

    document.getElementById("message").textContent =
        "Default settings restored.";
});

document.getElementById("theme").addEventListener("change", event => {
    document.body.classList.toggle(
        "light-mode",
        event.target.value === "light"
    );
});

document.getElementById("compactMode").addEventListener("change", event => {
    document.body.classList.toggle("compact-mode", event.target.checked);
});

loadSettings();
