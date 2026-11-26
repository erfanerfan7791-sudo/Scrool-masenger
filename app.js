
"use strict";

const $ = id => document.getElementById(id);
let mode = "login";

function msg(t) {
  $("message").textContent = t || "";
}

function setMode(m) {
  mode = m;
  const reg = m === "register";

  $("loginTab").classList.toggle("active", !reg);
  $("registerTab").classList.toggle("active", reg);

  $("title").textContent = reg ? "ساخت حساب جدید" : "ورود به حساب";
  $("subtitle").textContent = reg
    ? "یک نام کاربری و رمز عبور انتخاب کن."
    : "برای ادامه، اطلاعات حسابت رو وارد کن.";

  $("submit").textContent = reg ? "ساخت حساب" : "ورود";
  $("confirmWrap").classList.toggle("hidden", !reg);
  $("confirm").required = reg;
  $("password").autocomplete = reg ? "new-password" : "current-password";

  msg("");
}

$("loginTab").onclick = () => setMode("login");
$("registerTab").onclick = () => setMode("register");

async function api(url, opts = {}) {
  const r = await fetch(url, {
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    ...opts
  });

  const d = await r.json().catch(() => ({}));

  if (!r.ok) throw Error(d.error || "درخواست انجام نشد.");

  return d;
}

function showHome(u) {
  $("authView").classList.add("hidden");
  $("home").classList.remove("hidden");
  $("who").textContent = "@" + u.username;
}

$("form").addEventListener("submit", async e => {
  e.preventDefault();
  msg("");

  const username = $("username").value.trim().toLowerCase();
  const password = $("password").value;

  if (mode === "register" && password !== $("confirm").value) {
    return msg("تکرار رمز عبور با رمز اصلی یکی نیست.");
  }

  if (mode === "register" && !/^[a-z0-9_]{3,24}$/.test(username)) {
    return msg("نام کاربری باید ۳ تا ۲۴ کاراکتر و شامل حروف انگلیسی، عدد یا _ باشد.");
  }

  $("submit").disabled = true;
  $("submit").textContent = "لطفاً صبر کن...";

  try {
    const body = {
      username,
      password,
      display_name: username
    };

    const d = await api(
      mode === "register"
        ? "/api/auth/register"
        : "/api/auth/login",
      {
        method: "POST",
        body: JSON.stringify(body)
      }
    );

    showHome(d.user);

  } catch (err) {
    msg(err.message);

  } finally {
    $("submit").disabled = false;
    $("submit").textContent =
      mode === "register" ? "ساخت حساب" : "ورود";
  }
});

$("logout").onclick = async () => {
  try {
    await api("/api/auth/logout", {
      method: "POST",
      body: "{}"
    });
  } finally {
    $("home").classList.add("hidden");
    $("authView").classList.remove("hidden");
    $("form").reset();
    setMode("login");
  }
};

(async () => {
  try {
    const d = await api("/api/auth/me");
    showHome(d.user);
  } catch (e) {}
})();
