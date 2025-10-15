// auth.js - small client helper for fetch calls
async function api(path, data) {
  const res = await fetch(path, {
    method: data ? "POST" : "GET",
    headers: { "Content-Type": "application/json" },
    body: data ? JSON.stringify(data) : undefined,
  });
  return res.json();
}

// registration
async function registerHandler(e) {
  e.preventDefault();
  const email = document.querySelector("#reg-email").value;
  const password = document.querySelector("#reg-password").value;
  const r = await api("/api/register", { email, password });
  if (r.success) {
    alert("Inscription réussie — vous pouvez vous connecter.");
    window.location.href = "/login.html";
  } else alert(r.error || "Erreur");
}

// login step 1
async function loginHandler(e) {
  e.preventDefault();
  const email = document.querySelector("#login-email").value;
  const password = document.querySelector("#login-password").value;
  const r = await api("/api/login", { email, password });
  if (r.twoFactorRequired) {
    // show 2FA prompt
    document.querySelector("#login-form").style.display = "none";
    document.querySelector("#login-2fa").style.display = "block";
  } else if (r.success) {
    window.location.href = "/profile.html";
  } else alert(r.error || "Erreur");
}

// 2FA during login
async function login2faHandler(e) {
  e.preventDefault();
  const token = document.querySelector("#login-2fa-token").value;
  const r = await api("/api/login/2fa", { token });
  if (r.success) window.location.href = "/profile.html";
  else alert(r.error || "Erreur 2FA");
}

// load profile
async function loadProfile() {
  const r = await api("/api/me");
  if (r.user) {
    document.querySelector("#profile-email").textContent = r.user.email;
    document.querySelector("#profile-created").textContent = r.user.created_at;
    document.querySelector("#profile-2fa").textContent = r.user.is_2fa_enabled
      ? "Activé"
      : "Désactivé";
  } else {
    window.location.href = "/login.html";
  }
}

// setup 2FA
async function start2FA() {
  const r = await api("/api/2fa/setup");
  if (r.qr) {
    document.querySelector("#qr-img").src = r.qr;
    document.querySelector("#qr-secret").textContent = r.secret;
    document.querySelector("#setup-step1").style.display = "none";
    document.querySelector("#setup-step2").style.display = "block";
  } else alert(r.error || "Erreur");
}
async function verifySetup(e) {
  e.preventDefault();
  const token = document.querySelector("#setup-token").value;
  const r = await api("/api/2fa/verify-setup", { token });
  if (r.success) {
    alert("2FA activé");
    window.location.href = "/profile.html";
  } else alert(r.error || "Erreur");
}

async function logout() {
  await api("/api/logout");
  window.location.href = "/login.html";
}

// attach handlers when pages load
document.addEventListener("DOMContentLoaded", () => {
  if (document.querySelector("#register-form"))
    document
      .querySelector("#register-form")
      .addEventListener("submit", registerHandler);
  if (document.querySelector("#login-form"))
    document
      .querySelector("#login-form")
      .addEventListener("submit", loginHandler);
  if (document.querySelector("#login-2fa-form"))
    document
      .querySelector("#login-2fa-form")
      .addEventListener("submit", login2faHandler);
  if (document.querySelector("#profile-page")) loadProfile();
  if (document.querySelector("#start-2fa"))
    document.querySelector("#start-2fa").addEventListener("click", start2FA);
  if (document.querySelector("#setup-form"))
    document
      .querySelector("#setup-form")
      .addEventListener("submit", verifySetup);
  if (document.querySelector("#logout"))
    document.querySelector("#logout").addEventListener("click", logout);
});
