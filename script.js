function base64UrlDecode(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  return decodeURIComponent(
    atob(str)
      .split("")
      .map(c => "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2))
      .join("")
  );
}

function analyzeSecurity(header, payload) {
  const findings = [];

  if (header.alg === "none") {
    findings.push("❗ Token uses alg=none (INSECURE).");
  }

  if (!payload.exp) {
    findings.push("⚠️ No expiration (exp) claim present.");
  } else if (Date.now() / 1000 > payload.exp) {
    findings.push("❗ Token is expired.");
  }

  if (!payload.aud) {
    findings.push("⚠️ Missing audience (aud) claim.");
  }

  if (!payload.iss) {
    findings.push("⚠️ Missing issuer (iss) claim.");
  }

  if (payload.nbf && Date.now() / 1000 < payload.nbf) {
    findings.push("⚠️ Token is not valid yet (nbf).");
  }

  return findings.length ? findings : ["✅ No obvious security issues detected."];
}

document.getElementById("jwtInput").addEventListener("input", e => {
  const token = e.target.value.trim();
  const error = document.getElementById("error");
  const findingsEl = document.getElementById("securityFindings");

  if (!token) return;

  try {
    const parts = token.split(".");
    if (parts.length !== 3) throw "Invalid JWT format";

    const header = JSON.parse(base64UrlDecode(parts[0]));
    const payload = JSON.parse(base64UrlDecode(parts[1]));

    document.getElementById("headerOut").textContent =
      JSON.stringify(header, null, 2);
    document.getElementById("payloadOut").textContent =
      JSON.stringify(payload, null, 2);
    document.getElementById("signatureOut").textContent = parts[2];

    findingsEl.innerHTML = "";
    analyzeSecurity(header, payload).forEach(f => {
      const li = document.createElement("li");
      li.textContent = f;
      findingsEl.appendChild(li);
    });

    error.textContent = "";

  } catch (err) {
    error.textContent = err;
  }
});

document.getElementById("year").textContent =
  new Date().getFullYear();
