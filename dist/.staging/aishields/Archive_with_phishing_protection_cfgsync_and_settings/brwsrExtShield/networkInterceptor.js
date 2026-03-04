chrome.declarativeNetRequest.onBeforeRequest.addListener(
    (details) => {
        const redactPII = (text) => {
            if (!text) return text;
            const patterns = [
                [/\b\d{3}-\d{2}-\d{4}\b/g],
                [/\b\d{10}\b/g],
                [/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z]{2,}\b/gi],
                [/\b\d{5}(?:-\d{4})?\b/g],
                [/\b\d{9}\b/g],
                [/\b(?:\d{4}[-\s]?){3}\d{4}\b/g],
                [/\b[A-Z]{1,2}\d{4,8}\b/g],
                [/\b(?:[A-Za-z]{1}\d{3})[-\d{4}]{2}\b/g],
                [/\b[A-Z]{2}[0-9]{2}[a-zA-Z0-9]{4}[0-9]{14}\b/g]
            ];
            let redacted = String(text);
            patterns.forEach(([regex]) => {
                redacted = redacted.replace(regex, "[REDACTED]");
            });
            return redacted;
        };
        if (details.requestBody && details.requestBody.formData) {
            for (const key in details.requestBody.formData) {
                details.requestBody.formData[key] = details.requestBody.formData[key].map(redactPII);
            }
        }
        return { requestBody: details.requestBody };
    },
    { urls: ["<all_urls>"]},
    ["requestBody"]
);
/* */
