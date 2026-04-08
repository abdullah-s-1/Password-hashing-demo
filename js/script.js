const levelConfig = [
  { label: "Weak", color: "#f87171", bars: 1 },
  { label: "Fair", color: "#fbbf24", bars: 2 },
  { label: "Good", color: "#60a5fa", bars: 3 },
  { label: "Strong", color: "#34d399", bars: 4 }
];

const algoNotes = {
  "SHA-256": "SHA-256 is strong for integrity checks, but password storage still needs salt and a slow algorithm like bcrypt.",
  "SHA-1": "SHA-1 is broken for security-sensitive use. Collisions have been demonstrated in practice.",
  bcrypt: "bcrypt is designed for password hashing. It is intentionally slow and includes salt."
};

let currentAlgo = "SHA-256";
let currentSalt = "";
let passwordVisible = false;

const pwInput = document.getElementById("pw-input");
const hashInput = document.getElementById("hash-input");
const hashOut = document.getElementById("hash-out");
const algoNote = document.getElementById("algo-note");
const toggleButton = document.getElementById("pw-toggle");

toggleButton.addEventListener("click", () => {
  passwordVisible = !passwordVisible;
  pwInput.type = passwordVisible ? "text" : "password";
  toggleButton.textContent = passwordVisible ? "Hide" : "Show";
});

pwInput.addEventListener("input", analyzePassword);
hashInput.addEventListener("input", runHashDemo);
document.getElementById("salt-generate").addEventListener("click", generateSalt);

document.querySelectorAll(".algo-tab").forEach((button) => {
  button.addEventListener("click", () => setAlgorithm(button.dataset.algo || "SHA-256", button));
});

document.querySelectorAll(".faq-question").forEach((button) => {
  button.addEventListener("click", () => {
    const item = button.closest(".faq-item");
    const answer = item?.querySelector(".faq-answer");
    if (!item || !answer) return;

    const isOpen = item.classList.contains("open");
    item.classList.toggle("open", !isOpen);
    answer.hidden = isOpen;
  });
});

function setCheckState(id, passed) {
  document.getElementById(id).classList.toggle("pass", passed);
}

function analyzePassword() {
  const password = pwInput.value;
  hashInput.value = password;
  void runHashDemo();
  void updateSaltedHash();

  const hasLength = password.length >= 8;
  const hasUpper = /[A-Z]/.test(password);
  const hasLower = /[a-z]/.test(password);
  const hasNumber = /[0-9]/.test(password);
  const hasSymbol = /[^a-zA-Z0-9]/.test(password);
  const isLonger = password.length >= 12;

  setCheckState("c-len", hasLength);
  setCheckState("c-up", hasUpper);
  setCheckState("c-low", hasLower);
  setCheckState("c-num", hasNumber);
  setCheckState("c-sym", hasSymbol);
  setCheckState("c-long", isLonger);

  let poolSize = 0;
  if (hasLower) poolSize += 26;
  if (hasUpper) poolSize += 26;
  if (hasNumber) poolSize += 10;
  if (hasSymbol) poolSize += 32;

  const entropy = poolSize > 0 ? Math.round(password.length * Math.log2(poolSize)) : 0;
  document.getElementById("s-len").textContent = String(password.length);
  document.getElementById("s-ent").textContent = `${entropy} bits`;
  document.getElementById("s-crack").textContent = estimateCrackTime(password.length, entropy);

  const score = [hasLength, hasUpper, hasLower, hasNumber, hasSymbol, isLonger].filter(Boolean).length;
  const levelIndex = password.length === 0 ? -1 : score <= 2 ? 0 : score <= 3 ? 1 : score <= 4 ? 2 : 3;
  const level = levelIndex >= 0 ? levelConfig[levelIndex] : null;

  for (let index = 1; index <= 4; index += 1) {
    document.getElementById(`sb${index}`).style.background =
      level && index <= level.bars ? level.color : "rgba(255,255,255,0.08)";
  }

  const label = document.getElementById("strength-lbl");
  label.textContent = level ? level.label : "-";
  label.style.color = level ? level.color : "#6f88ad";
}

function estimateCrackTime(length, entropy) {
  if (length === 0) return "-";
  if (entropy < 28) return "Instant";
  if (entropy < 36) return "Seconds";
  if (entropy < 50) return "Hours";
  if (entropy < 60) return "Years";
  return "Centuries";
}

async function shaDigest(algorithm, message) {
  const buffer = await crypto.subtle.digest(algorithm, new TextEncoder().encode(message));
  return Array.from(new Uint8Array(buffer))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function runHashDemo() {
  const value = hashInput.value;
  hashOut.className = "hash-output";

  if (!value) {
    hashOut.textContent = "-";
    return;
  }

  if (currentAlgo === "bcrypt") {
    const encoded = Array.from(new TextEncoder().encode(value))
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join("");
    hashOut.classList.add("bcrypt");
    hashOut.textContent = `$2b$12$${encoded.padEnd(53, "a").slice(0, 53)}`;
    return;
  }

  if (currentAlgo === "SHA-1") {
    hashOut.classList.add("danger");
  }

  hashOut.textContent = await shaDigest(currentAlgo === "SHA-1" ? "SHA-1" : "SHA-256", value);
  hashOut.classList.add("flash");
  setTimeout(() => hashOut.classList.remove("flash"), 300);
}

function setAlgorithm(algorithm, button) {
  currentAlgo = algorithm;
  document.querySelectorAll(".algo-tab").forEach((tab) => tab.classList.remove("active"));
  button.classList.add("active");

  algoNote.className = "algo-note";
  algoNote.textContent = algoNotes[algorithm];
  if (algorithm === "SHA-1") algoNote.classList.add("danger");
  if (algorithm === "bcrypt") algoNote.classList.add("bcrypt");

  void runHashDemo();
}

function randomHex(bytes) {
  const array = new Uint8Array(bytes);
  crypto.getRandomValues(array);
  return Array.from(array)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function generateSalt() {
  currentSalt = randomHex(32);
  const saltValue = document.getElementById("salt-val");
  saltValue.textContent = currentSalt;
  saltValue.classList.add("flash");
  setTimeout(() => saltValue.classList.remove("flash"), 300);
  await updateSaltedHash();
}

async function updateSaltedHash() {
  const password = pwInput.value || hashInput.value;
  if (!password || !currentSalt) return;

  const saltedValue = document.getElementById("salted-val");
  saltedValue.textContent = await shaDigest("SHA-256", password + currentSalt);
  saltedValue.classList.add("flash");
  setTimeout(() => saltedValue.classList.remove("flash"), 300);
}

void generateSalt();
