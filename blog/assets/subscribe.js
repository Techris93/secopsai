(() => {
  const form = document.querySelector("[data-subscribe-form]");
  if (!form) return;

  const input = form.querySelector('input[name="email"]');
  const button = form.querySelector('button[type="submit"]');
  const status = form.querySelector("[data-subscribe-status]");
  const slot = form.querySelector("[data-subscribe-turnstile]");
  let siteKey = "";
  let widgetId = null;
  let ready = null;

  const say = (text, state = "") => {
    status.textContent = text;
    status.dataset.state = state;
  };

  const loadTurnstile = () =>
    new Promise((resolve, reject) => {
      if (window.turnstile) return resolve();
      const script = document.createElement("script");
      script.src = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
      script.async = true;
      script.addEventListener("load", resolve, {once: true});
      script.addEventListener("error", reject, {once: true});
      document.head.appendChild(script);
    });

  // The spam check loads only once someone starts to subscribe.
  const prepare = () => {
    ready ||= (async () => {
      const response = await fetch("/api/comments?config=1");
      const config = await response.json();
      siteKey = config.turnstile_site_key || "";
      if (!siteKey) return;
      await loadTurnstile();
      slot.hidden = false;
      widgetId = window.turnstile.render(slot, {sitekey: siteKey, size: "flexible"});
    })().catch(() => {
      ready = null;
      throw new Error("The spam check did not load. Try again.");
    });
    return ready;
  };

  input.addEventListener("focus", () => prepare().catch(() => {}), {once: true});

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const email = input.value.trim();
    if (!input.checkValidity() || !email) {
      say("Enter a valid email address.", "error");
      input.focus();
      return;
    }
    button.disabled = true;
    try {
      await prepare();
      const body = {email, website: form.elements.website.value};
      if (siteKey) {
        body.turnstileToken = window.turnstile?.getResponse(widgetId) || "";
        if (!body.turnstileToken) {
          say("Complete the spam check, then press Subscribe.", "error");
          return;
        }
      }
      say("Subscribing…");
      const response = await fetch("/api/subscribe", {
        method: "POST",
        headers: {"content-type": "application/json"},
        body: JSON.stringify(body),
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok || !payload.ok) throw new Error(payload.error || "Subscription failed. Try again later.");
      form.reset();
      say(`Check ${email} for a confirmation link.`, "ok");
    } catch (error) {
      say(error.message, "error");
    } finally {
      if (widgetId !== null) window.turnstile?.reset(widgetId);
      button.disabled = false;
    }
  });
})();
