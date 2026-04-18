import { AnimatePresence, motion } from "framer-motion";
import { FormEvent, useCallback, useEffect, useMemo, useRef, useState } from "react";

type VaultEntry = {
  id: string;
  website: string;
  username: string;
  email: string;
  password: string;
  notes: string;
  createdAt: string;
  updatedAt: string;
  isFavorite?: boolean;
};

type EncryptedVault = {
  salt: string;
  iv: string;
  cipherText: string;
  updatedAt: string;
  version: number;
};

type SortField = "website" | "createdAt" | "updatedAt";
type SortDir = "asc" | "desc";
type ActiveTab = "all" | "favorites";

const STORAGE_KEY = "password_manager_vault_v1";
const AUTO_LOCK_MS = 5 * 60 * 1000;
const VAULT_VERSION = 2;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function toBase64(bytes: Uint8Array) {
  let bin = "";
  for (let i = 0; i < bytes.byteLength; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}
function fromBase64(b64: string) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}
function toAB(view: Uint8Array) {
  const c = new Uint8Array(view.byteLength);
  c.set(view);
  return c.buffer;
}

async function deriveKey(password: string, salt: Uint8Array) {
  const km = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: toAB(salt), iterations: 310000, hash: "SHA-256" },
    km, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
  );
}

async function encryptVault(entries: VaultEntry[], password: string): Promise<EncryptedVault> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt);
  const buf = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: toAB(iv) }, key,
    toAB(encoder.encode(JSON.stringify(entries)))
  );
  return { salt: toBase64(salt), iv: toBase64(iv), cipherText: toBase64(new Uint8Array(buf)), updatedAt: new Date().toISOString(), version: VAULT_VERSION };
}

async function decryptVault(vault: EncryptedVault, password: string): Promise<VaultEntry[]> {
  const key = await deriveKey(password, fromBase64(vault.salt));
  const buf = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: toAB(fromBase64(vault.iv)) }, key, toAB(fromBase64(vault.cipherText))
  );
  const parsed = JSON.parse(decoder.decode(buf));
  return Array.isArray(parsed) ? parsed : [];
}

function readStoredVault(): EncryptedVault | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const p = JSON.parse(raw) as EncryptedVault;
    if (!p?.salt || !p?.iv || !p?.cipherText) return null;
    return p;
  } catch { return null; }
}

const CHARS = { lower: "abcdefghijklmnopqrstuvwxyz", upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ", digits: "0123456789", symbols: "!@#$%^&*()_+-=[]{}|;:,.<>?" };

function generatePassword(length = 20, opts = { upper: true, digits: true, symbols: true }) {
  let pool = CHARS.lower;
  if (opts.upper) pool += CHARS.upper;
  if (opts.digits) pool += CHARS.digits;
  if (opts.symbols) pool += CHARS.symbols;
  const arr = crypto.getRandomValues(new Uint32Array(length));
  return Array.from(arr, (n) => pool[n % pool.length]).join("");
}

function calcStrength(pw: string): { score: number; label: string; color: string; textColor: string } {
  if (!pw) return { score: 0, label: "", color: "bg-lime-300/20", textColor: "text-lime-300/30" };
  let s = 0;
  if (pw.length >= 8) s++;
  if (pw.length >= 14) s++;
  if (pw.length >= 20) s++;
  if (/[A-Z]/.test(pw)) s++;
  if (/[0-9]/.test(pw)) s++;
  if (/[^A-Za-z0-9]/.test(pw)) s++;
  if (s <= 2) return { score: s, label: "Weak", color: "bg-red-400", textColor: "text-red-400" };
  if (s <= 4) return { score: s, label: "Fair", color: "bg-yellow-400", textColor: "text-yellow-400" };
  if (s <= 5) return { score: s, label: "Strong", color: "bg-lime-300", textColor: "text-lime-300" };
  return { score: s, label: "Very Strong", color: "bg-lime-400", textColor: "text-lime-400" };
}

function exportToJSON(entries: VaultEntry[]) {
  const blob = new Blob([JSON.stringify(entries, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a"); a.href = url; a.download = `vault-export-${new Date().toISOString().slice(0, 10)}.json`; a.click();
  URL.revokeObjectURL(url);
}

function exportToCSV(entries: VaultEntry[]) {
  const header = "Website,Username,Email,Password,Notes,Created\n";
  const rows = entries.map((e) => [e.website, e.username || "", e.email, e.password, (e.notes || "").replace(/,/g, ";"), e.createdAt].map((v) => `"${v}"`).join(",")).join("\n");
  const blob = new Blob([header + rows], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a"); a.href = url; a.download = `vault-export-${new Date().toISOString().slice(0, 10)}.csv`; a.click();
  URL.revokeObjectURL(url);
}

const IC = "w-full border border-lime-300/35 bg-black/75 px-3 py-2 text-sm text-lime-100 outline-none transition-all duration-200 focus:border-lime-200 focus:shadow-[0_0_18px_rgba(132,255,91,0.2)] placeholder:text-lime-300/25";
const BP = "border border-lime-300/45 bg-lime-400/10 px-4 py-2 text-xs font-semibold tracking-[0.16em] uppercase text-lime-100 transition-all duration-200 hover:border-lime-200 hover:bg-lime-400/20 disabled:cursor-not-allowed disabled:opacity-50";
const BD = "border border-red-400/55 bg-red-500/10 px-4 py-2 text-xs font-semibold tracking-[0.16em] uppercase text-red-200 transition-all duration-200 hover:border-red-300 hover:bg-red-500/20 hover:text-red-100";
const BG = "text-[11px] uppercase tracking-[0.14em] text-lime-300/60 transition-colors hover:text-lime-100";

function StrengthBar({ pw }: { pw: string }) {
  const { score, label, color, textColor } = calcStrength(pw);
  if (!pw) return null;
  return (
    <div className="mt-1 space-y-1">
      <div className="flex gap-1">{Array.from({ length: 6 }).map((_, i) => <div key={i} className={`h-1 flex-1 transition-all duration-300 ${i < score ? color : "bg-lime-300/15"}`} />)}</div>
      <p className={`text-[10px] uppercase tracking-[0.14em] ${textColor}`}>{label}</p>
    </div>
  );
}

function PwGen({ onAccept }: { onAccept: (pw: string) => void }) {
  const [len, setLen] = useState(20);
  const [opts, setOpts] = useState({ upper: true, digits: true, symbols: true });
  const [pw, setPw] = useState(() => generatePassword(20, { upper: true, digits: true, symbols: true }));
  const [copied, setCopied] = useState(false);
  const regen = useCallback(() => setPw(generatePassword(len, opts)), [len, opts]);
  async function copy() { await navigator.clipboard.writeText(pw); setCopied(true); setTimeout(() => setCopied(false), 1500); }
  return (
    <div className="space-y-3 border border-lime-300/20 bg-black/50 p-4">
      <p className="text-[10px] uppercase tracking-[0.18em] text-lime-300/50">Password Generator</p>
      <div className="flex items-center gap-2">
        <code className="flex-1 overflow-hidden overflow-ellipsis whitespace-nowrap border border-lime-300/20 bg-black/70 px-2 py-1.5 text-xs text-lime-200">{pw}</code>
        <button type="button" onClick={copy} className={BG}>{copied ? "✓" : "Copy"}</button>
      </div>
      <StrengthBar pw={pw} />
      <div className="flex flex-wrap items-center gap-4 text-xs">
        <label className="flex items-center gap-1.5 text-lime-300/60">
          Len <input type="number" min={8} max={64} value={len} onChange={(e) => setLen(Number(e.target.value))} className="w-14 border border-lime-300/25 bg-black/70 px-2 py-0.5 text-lime-100 outline-none" />
        </label>
        {(["upper", "digits", "symbols"] as const).map((k) => (
          <label key={k} className="flex cursor-pointer items-center gap-1 text-lime-300/60">
            <input type="checkbox" checked={opts[k]} onChange={(e) => setOpts((p) => ({ ...p, [k]: e.target.checked }))} className="accent-lime-400" />
            <span className="capitalize">{k}</span>
          </label>
        ))}
      </div>
      <div className="flex gap-2">
        <button type="button" onClick={regen} className={BP}>Regenerate</button>
        <button type="button" onClick={() => onAccept(pw)} className={BP}>Use This</button>
      </div>
    </div>
  );
}

function ConfirmDialog({ message, onConfirm, onCancel }: { message: string; onConfirm: () => void; onCancel: () => void }) {
  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm">
      <motion.div initial={{ scale: 0.9, y: 10 }} animate={{ scale: 1, y: 0 }} exit={{ scale: 0.9, y: 10 }} className="terminal-panel w-full max-w-sm border border-red-400/45 bg-black/90 p-6">
        <p className="mb-5 text-sm text-lime-100 leading-relaxed">{message}</p>
        <div className="flex gap-3">
          <button type="button" onClick={onConfirm} className={BD}>Confirm</button>
          <button type="button" onClick={onCancel} className={BP}>Cancel</button>
        </div>
      </motion.div>
    </motion.div>
  );
}

function EditModal({ entry, onSave, onClose, isLoading }: { entry: VaultEntry; onSave: (u: VaultEntry) => Promise<void>; onClose: () => void; isLoading: boolean }) {
  const [form, setForm] = useState({ ...entry });
  const [showGen, setShowGen] = useState(false);
  function set(k: keyof VaultEntry, v: string) { setForm((p) => ({ ...p, [k]: v })); }
  async function submit(e: FormEvent) { e.preventDefault(); await onSave({ ...form, updatedAt: new Date().toISOString() }); }
  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm overflow-y-auto py-8">
      <motion.form initial={{ scale: 0.95, y: 12 }} animate={{ scale: 1, y: 0 }} exit={{ scale: 0.95, y: 12 }} onSubmit={submit} className="terminal-panel w-full max-w-lg border border-lime-300/35 bg-black/90 p-6 mx-4">
        <div className="mb-4 flex items-center justify-between">
          <p className="text-xs uppercase tracking-[0.16em] text-lime-300/80">Edit Credential</p>
          <button type="button" onClick={onClose} className={BG}>✕ Close</button>
        </div>
        <div className="space-y-3">
          <label className="grid gap-1.5 text-sm"><span className="text-lime-300/70">Website / App</span><input required value={form.website} onChange={(e) => set("website", e.target.value)} className={IC} /></label>
          <label className="grid gap-1.5 text-sm"><span className="text-lime-300/70">Username</span><input value={form.username || ""} onChange={(e) => set("username", e.target.value)} className={IC} /></label>
          <label className="grid gap-1.5 text-sm"><span className="text-lime-300/70">Email</span><input required type="email" value={form.email} onChange={(e) => set("email", e.target.value)} className={IC} /></label>
          <label className="grid gap-1.5 text-sm">
            <span className="text-lime-300/70">Password</span>
            <input required value={form.password} onChange={(e) => set("password", e.target.value)} className={IC} />
            <StrengthBar pw={form.password} />
          </label>
          <button type="button" onClick={() => setShowGen((p) => !p)} className={`${BG} text-left`}>{showGen ? "▲ Hide generator" : "▼ Generate password"}</button>
          {showGen && <PwGen onAccept={(pw) => set("password", pw)} />}
          <label className="grid gap-1.5 text-sm"><span className="text-lime-300/70">Notes</span><textarea rows={3} value={form.notes || ""} onChange={(e) => set("notes", e.target.value)} className={`${IC} resize-none`} /></label>
        </div>
        <div className="mt-5 flex gap-3">
          <button type="submit" disabled={isLoading} className={BP}>{isLoading ? "Saving…" : "Save Changes"}</button>
          <button type="button" onClick={onClose} className={BG}>Cancel</button>
        </div>
      </motion.form>
    </motion.div>
  );
}

export default function App() {
  const [storedVault, setStoredVault] = useState<EncryptedVault | null>(() => readStoredVault());
  const [masterPassword, setMasterPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [unlockPassword, setUnlockPassword] = useState("");
  const [entries, setEntries] = useState<VaultEntry[]>([]);
  const [search, setSearch] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [activeMasterPassword, setActiveMasterPassword] = useState<string | null>(null);
  const [showEntryPasswordId, setShowEntryPasswordId] = useState<string | null>(null);
  const [editingEntry, setEditingEntry] = useState<VaultEntry | null>(null);
  const [confirmAction, setConfirmAction] = useState<{ message: string; onConfirm: () => void } | null>(null);
  const [sortField, setSortField] = useState<SortField>("createdAt");
  const [sortDir, setSortDir] = useState<SortDir>("desc");
  const [activeTab, setActiveTab] = useState<ActiveTab>("all");
  const [showGenInForm, setShowGenInForm] = useState(false);
  const [showMasterPw, setShowMasterPw] = useState(false);
  const [showConfirmPw, setShowConfirmPw] = useState(false);
  const [showUnlockPw, setShowUnlockPw] = useState(false);
  const [formState, setFormState] = useState({ website: "", username: "", email: "", password: "", notes: "" });

  const isUnlocked = activeMasterPassword !== null;
  const autoLockTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  function lockVault() {
    setActiveMasterPassword(null);
    setEntries([]);
    setSearch("");
    setShowEntryPasswordId(null);
    setEditingEntry(null);
    if (autoLockTimer.current) clearTimeout(autoLockTimer.current);
  }

  const resetAutoLock = useCallback(() => {
    if (autoLockTimer.current) clearTimeout(autoLockTimer.current);
    autoLockTimer.current = setTimeout(() => { lockVault(); setNotice("Auto-locked after inactivity."); }, AUTO_LOCK_MS);
  }, []);

  useEffect(() => {
    if (!isUnlocked) return;
    const events = ["mousemove", "keydown", "click", "touchstart"];
    events.forEach((ev) => window.addEventListener(ev, resetAutoLock));
    resetAutoLock();
    return () => { events.forEach((ev) => window.removeEventListener(ev, resetAutoLock)); if (autoLockTimer.current) clearTimeout(autoLockTimer.current); };
  }, [isUnlocked, resetAutoLock]);

  useEffect(() => {
    function onVis() { if (document.hidden && isUnlocked) { lockVault(); setNotice("Locked: tab left."); } }
    document.addEventListener("visibilitychange", onVis);
    return () => document.removeEventListener("visibilitychange", onVis);
  }, [isUnlocked]);

  useEffect(() => { if (!notice) return; const t = setTimeout(() => setNotice(""), 2400); return () => clearTimeout(t); }, [notice]);

  function showErr(msg: string) { setError(msg); setTimeout(() => setError(""), 3500); }

  async function persistEntries(next: VaultEntry[]) {
    if (!activeMasterPassword) return;
    const enc = await encryptVault(next, activeMasterPassword);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(enc));
    setStoredVault(enc);
    setEntries(next);
  }

  async function handleCreateVault(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (masterPassword.length < 12) { showErr("Master password must be at least 12 characters."); return; }
    if (masterPassword !== confirmPassword) { showErr("Passwords do not match."); return; }
    setIsLoading(true);
    try {
      const enc = await encryptVault([], masterPassword);
      localStorage.setItem(STORAGE_KEY, JSON.stringify(enc));
      setStoredVault(enc); setActiveMasterPassword(masterPassword); setEntries([]);
      setMasterPassword(""); setConfirmPassword(""); setNotice("Vault created.");
    } catch { showErr("Could not create vault."); } finally { setIsLoading(false); }
  }

  async function handleUnlock(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!storedVault) return;
    setIsLoading(true);
    try {
      const dec = await decryptVault(storedVault, unlockPassword);
      setEntries(dec); setActiveMasterPassword(unlockPassword); setUnlockPassword(""); setNotice("Vault unlocked.");
    } catch { showErr("Incorrect password or corrupted vault."); } finally { setIsLoading(false); }
  }

  function handleClearVault() {
    setConfirmAction({ message: "This will permanently delete your vault and all saved credentials. This cannot be undone.", onConfirm: () => {
      localStorage.removeItem(STORAGE_KEY); setStoredVault(null); setEntries([]); setActiveMasterPassword(null);
      setUnlockPassword(""); setMasterPassword(""); setConfirmPassword(""); setError(""); setNotice("Vault reset."); setConfirmAction(null);
    }});
  }

  async function handleAddEntry(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!formState.website.trim() || !formState.email.trim() || !formState.password.trim()) { showErr("Website, email, and password are required."); return; }
    setIsLoading(true);
    try {
      const now = new Date().toISOString();
      await persistEntries([{ id: crypto.randomUUID(), website: formState.website.trim(), username: formState.username.trim(), email: formState.email.trim(), password: formState.password, notes: formState.notes.trim(), createdAt: now, updatedAt: now, isFavorite: false }, ...entries]);
      setFormState({ website: "", username: "", email: "", password: "", notes: "" }); setShowGenInForm(false); setNotice("Entry saved.");
    } catch { showErr("Could not save entry."); } finally { setIsLoading(false); }
  }

  function promptDelete(id: string) {
    setConfirmAction({ message: "Delete this credential? This cannot be undone.", onConfirm: async () => {
      setConfirmAction(null); setIsLoading(true);
      try { await persistEntries(entries.filter((e) => e.id !== id)); setNotice("Entry deleted."); }
      catch { showErr("Could not delete."); } finally { setIsLoading(false); }
    }});
  }

  async function handleSaveEdit(updated: VaultEntry) {
    setIsLoading(true);
    try { await persistEntries(entries.map((e) => (e.id === updated.id ? updated : e))); setEditingEntry(null); setNotice("Entry updated."); }
    catch { showErr("Could not save."); } finally { setIsLoading(false); }
  }

  async function toggleFavorite(id: string) {
    await persistEntries(entries.map((e) => e.id === id ? { ...e, isFavorite: !e.isFavorite, updatedAt: new Date().toISOString() } : e));
  }

  async function handleCopy(value: string, label: string) {
    try { await navigator.clipboard.writeText(value); setNotice(`${label} copied.`); }
    catch { showErr("Clipboard access denied."); }
  }

  const filteredEntries = useMemo(() => {
    const term = search.toLowerCase().trim();
    let list = entries;
    if (activeTab === "favorites") list = list.filter((e) => e.isFavorite);
    if (term) list = list.filter((e) => [e.website, e.email, e.username, e.notes].join(" ").toLowerCase().includes(term));
    return [...list].sort((a, b) => {
      const av = a[sortField] ?? ""; const bv = b[sortField] ?? "";
      return sortDir === "asc" ? av.localeCompare(bv) : bv.localeCompare(av);
    });
  }, [entries, search, sortField, sortDir, activeTab]);

  function toggleSort(f: SortField) { if (sortField === f) setSortDir((d) => (d === "asc" ? "desc" : "asc")); else { setSortField(f); setSortDir("asc"); } }
  const sa = (f: SortField) => sortField === f ? (sortDir === "asc" ? " ↑" : " ↓") : "";

  return (
    <main className="relative min-h-screen overflow-hidden bg-[#020503] font-mono text-lime-100">
      <div className="pointer-events-none absolute inset-0 tech-grid opacity-40" aria-hidden="true" />
      <div className="pointer-events-none absolute inset-0 matrix-rain opacity-35" aria-hidden="true" />
      <div className="pointer-events-none absolute inset-0 noise-mask opacity-30" aria-hidden="true" />
      <div className="pointer-events-none absolute inset-0 scanline opacity-60" aria-hidden="true" />
      <motion.div aria-hidden="true" className="pointer-events-none absolute top-[-14rem] left-1/2 h-[36rem] w-[36rem] -translate-x-1/2 rounded-full bg-lime-400/10 blur-[120px]" animate={{ scale: [1, 1.09, 1], opacity: [0.16, 0.3, 0.16] }} transition={{ duration: 9, repeat: Infinity, ease: "easeInOut" }} />

      <div className="relative z-10 mx-auto flex min-h-screen w-full max-w-6xl flex-col px-6 py-8 md:px-10">
        <header className="mb-3 flex items-center justify-between border border-lime-300/30 bg-black/60 px-4 py-3 terminal-panel">
          <div>
            <p className="text-[11px] tracking-[0.22em] text-lime-400/90 uppercase">Root Access Channel</p>
            <h1 className="glitch-text mt-1 text-2xl font-semibold tracking-tight text-lime-100" data-text="ROOT.KEYRING.EXE">
              ROOT.KEYRING.EXE<span className="terminal-cursor ml-1 inline-block h-5 w-2 align-[-2px] bg-lime-300" />
            </h1>
          </div>
          <div className="flex items-center gap-3 text-[11px] uppercase tracking-[0.18em] text-lime-300/80">
            <motion.span className="h-2.5 w-2.5 rounded-full bg-lime-300" animate={{ opacity: [0.35, 1, 0.35] }} transition={{ duration: 1.6, repeat: Infinity, ease: "easeInOut" }} />
            {isUnlocked ? (
              <>
                <span className="hidden sm:inline">{entries.length} credentials</span>
                <button type="button" onClick={() => { lockVault(); setNotice("Vault locked."); }} className={BP}>Lock</button>
                <button type="button" onClick={() => exportToJSON(entries)} className={`${BP} px-2`} title="Export JSON">JSON ↓</button>
                <button type="button" onClick={() => exportToCSV(entries)} className={`${BP} px-2`} title="Export CSV">CSV ↓</button>
              </>
            ) : "Awaiting auth"}
          </div>
        </header>

        <p className="mb-7 border border-lime-300/25 bg-black/55 px-4 py-2 text-[11px] uppercase tracking-[0.14em] text-lime-300/90 terminal-panel">
          [syslog] kdf armed :: aes-gcm-256 :: pbkdf2 310k iter :: auto-lock 5m :: lock-on-tab-switch
        </p>

        {/* Create vault */}
        {!storedVault && (
          <section className="grid flex-1 place-items-center">
            <motion.form initial={{ opacity: 0, y: 18 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.45 }} onSubmit={handleCreateVault} className="terminal-panel w-full max-w-xl border border-lime-300/35 bg-black/60 p-6">
              <p className="mb-5 text-xs uppercase tracking-[0.16em] text-lime-300/80">Create master key to initialize encrypted vault</p>
              <div className="grid gap-4">
                <label className="grid gap-2 text-sm">
                  <span>Master Password <span className="text-lime-400/40 text-[10px]">(min 12 chars)</span></span>
                  <div className="relative">
                    <input required type={showMasterPw ? "text" : "password"} minLength={12} value={masterPassword} onChange={(e) => setMasterPassword(e.target.value)} className={IC} placeholder="At least 12 characters" />
                    <button type="button" onClick={() => setShowMasterPw(p => !p)} className="absolute right-2 top-1/2 -translate-y-1/2 text-[10px] text-lime-300/40 hover:text-lime-300">{showMasterPw ? "hide" : "show"}</button>
                  </div>
                  <StrengthBar pw={masterPassword} />
                </label>
                <label className="grid gap-2 text-sm">
                  <span>Confirm Password</span>
                  <div className="relative">
                    <input required type={showConfirmPw ? "text" : "password"} value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} className={IC} placeholder="Repeat master password" />
                    <button type="button" onClick={() => setShowConfirmPw(p => !p)} className="absolute right-2 top-1/2 -translate-y-1/2 text-[10px] text-lime-300/40 hover:text-lime-300">{showConfirmPw ? "hide" : "show"}</button>
                  </div>
                  {confirmPassword && masterPassword !== confirmPassword && <p className="text-[10px] text-red-400">Passwords do not match</p>}
                </label>
              </div>
              <div className="mt-5"><button type="submit" disabled={isLoading} className={BP}>{isLoading ? "Creating…" : "Create Vault"}</button></div>
              <p className="mt-4 text-[10px] text-lime-300/35 leading-relaxed">⚠ Your master password is never stored or transmitted. If lost, vault access is permanently unrecoverable.</p>
            </motion.form>
          </section>
        )}

        {/* Unlock vault */}
        {storedVault && !isUnlocked && (
          <section className="grid flex-1 place-items-center">
            <motion.form initial={{ opacity: 0, y: 18 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.45 }} onSubmit={handleUnlock} className="terminal-panel w-full max-w-xl border border-lime-300/35 bg-black/60 p-6">
              <p className="mb-1 text-xs uppercase tracking-[0.16em] text-lime-300/80">Authenticate to decrypt credentials</p>
              {storedVault.updatedAt && <p className="mb-5 text-[10px] text-lime-300/35">Last modified: {new Date(storedVault.updatedAt).toLocaleString()}</p>}
              <label className="grid gap-2 text-sm">
                <span>Master Password</span>
                <div className="relative">
                  <input autoFocus required type={showUnlockPw ? "text" : "password"} value={unlockPassword} onChange={(e) => setUnlockPassword(e.target.value)} className={IC} placeholder="Enter master password" />
                  <button type="button" onClick={() => setShowUnlockPw(p => !p)} className="absolute right-2 top-1/2 -translate-y-1/2 text-[10px] text-lime-300/40 hover:text-lime-300">{showUnlockPw ? "hide" : "show"}</button>
                </div>
              </label>
              <div className="mt-5 flex flex-wrap gap-3">
                <button type="submit" disabled={isLoading} className={BP}>{isLoading ? "Decrypting…" : "Unlock"}</button>
                <button type="button" onClick={handleClearVault} className={BD}>Reset Vault</button>
              </div>
            </motion.form>
          </section>
        )}

        {/* Main vault */}
        {isUnlocked && (
          <section className="grid flex-1 gap-6 lg:grid-cols-[340px_1fr]">
            <motion.form initial={{ opacity: 0, x: -16 }} animate={{ opacity: 1, x: 0 }} transition={{ duration: 0.4 }} onSubmit={handleAddEntry} className="terminal-panel h-fit border border-lime-300/35 bg-black/60 p-5">
              <p className="mb-4 text-xs uppercase tracking-[0.14em] text-lime-300/80">Inject new credential</p>
              <div className="space-y-3">
                <label className="grid gap-1.5 text-sm"><span>Website / App</span><input required value={formState.website} onChange={(e) => setFormState((p) => ({ ...p, website: e.target.value }))} className={IC} placeholder="github.com" /></label>
                <label className="grid gap-1.5 text-sm"><span className="text-lime-300/70">Username <span className="text-[10px] text-lime-300/40">(optional)</span></span><input value={formState.username} onChange={(e) => setFormState((p) => ({ ...p, username: e.target.value }))} className={IC} placeholder="@handle" /></label>
                <label className="grid gap-1.5 text-sm"><span>Email</span><input required type="email" value={formState.email} onChange={(e) => setFormState((p) => ({ ...p, email: e.target.value }))} className={IC} placeholder="you@example.com" /></label>
                <label className="grid gap-1.5 text-sm">
                  <span>Password</span>
                  <input required value={formState.password} onChange={(e) => setFormState((p) => ({ ...p, password: e.target.value }))} className={IC} placeholder="Enter or generate" />
                  <StrengthBar pw={formState.password} />
                </label>
                <button type="button" onClick={() => setShowGenInForm((p) => !p)} className={`${BG} text-left`}>{showGenInForm ? "▲ Hide generator" : "▼ Generate password"}</button>
                {showGenInForm && <PwGen onAccept={(pw) => setFormState((p) => ({ ...p, password: pw }))} />}
                <label className="grid gap-1.5 text-sm"><span className="text-lime-300/70">Notes <span className="text-[10px] text-lime-300/40">(optional)</span></span><textarea rows={2} value={formState.notes} onChange={(e) => setFormState((p) => ({ ...p, notes: e.target.value }))} className={`${IC} resize-none`} placeholder="2FA backup, hints…" /></label>
              </div>
              <button type="submit" disabled={isLoading} className={`${BP} mt-5 w-full`}>{isLoading ? "Saving…" : "Save Entry"}</button>
            </motion.form>

            <motion.div initial={{ opacity: 0, x: 16 }} animate={{ opacity: 1, x: 0 }} transition={{ duration: 0.4, delay: 0.07 }} className="terminal-panel border border-lime-300/35 bg-black/55 p-5">
              <div className="mb-4 space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <h2 className="text-sm uppercase tracking-[0.16em] text-lime-200">Credentials Index</h2>
                  <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search website, email, username…" className="w-full max-w-xs border border-lime-300/35 bg-black/70 px-3 py-2 text-sm outline-none transition-all focus:border-lime-200 placeholder:text-lime-300/25" />
                </div>
                <div className="flex flex-wrap items-center gap-3 text-[11px] uppercase tracking-[0.14em]">
                  <button type="button" onClick={() => setActiveTab("all")} className={activeTab === "all" ? "text-lime-200 border-b border-lime-300" : "text-lime-300/45 hover:text-lime-300"}>All ({entries.length})</button>
                  <button type="button" onClick={() => setActiveTab("favorites")} className={activeTab === "favorites" ? "text-lime-200 border-b border-lime-300" : "text-lime-300/45 hover:text-lime-300"}>★ Fav ({entries.filter((e) => e.isFavorite).length})</button>
                  <span className="ml-auto flex gap-3 text-lime-300/45">
                    {(["website", "createdAt", "updatedAt"] as SortField[]).map((f) => (
                      <button key={f} type="button" onClick={() => toggleSort(f)} className="hover:text-lime-200">
                        {f === "website" ? "Name" : f === "createdAt" ? "Created" : "Modified"}{sa(f)}
                      </button>
                    ))}
                  </span>
                </div>
              </div>

              {filteredEntries.length === 0 ? (
                <p className="border border-dashed border-lime-300/25 px-4 py-8 text-sm text-lime-200/50 text-center">
                  {search ? "No results." : "No credentials yet. Add your first one."}
                </p>
              ) : (
                <ul className="space-y-3">
                  <AnimatePresence initial={false}>
                    {filteredEntries.map((entry) => {
                      const visible = showEntryPasswordId === entry.id;
                      return (
                        <motion.li layout initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }} transition={{ duration: 0.22 }} key={entry.id} className="terminal-panel border border-lime-300/30 bg-black/65 p-4">
                          <div className="mb-3 flex items-start justify-between gap-3">
                            <div className="min-w-0">
                              <p className="text-[10px] uppercase tracking-[0.16em] text-lime-300/40">#{entry.id.slice(0, 8)} · {new Date(entry.createdAt).toLocaleDateString()}</p>
                              <h3 className="truncate text-lime-200">{entry.website}</h3>
                              {entry.username && <p className="text-xs text-lime-300/55">@{entry.username}</p>}
                              <p className="text-sm text-lime-300/80">{entry.email}</p>
                            </div>
                            <div className="flex shrink-0 items-center gap-3">
                              <button type="button" onClick={() => toggleFavorite(entry.id)} title={entry.isFavorite ? "Unfavorite" : "Favorite"} className={`text-base transition-colors ${entry.isFavorite ? "text-yellow-300" : "text-lime-300/25 hover:text-yellow-300"}`}>★</button>
                              <button type="button" onClick={() => setEditingEntry(entry)} className={BG}>Edit</button>
                              <button type="button" onClick={() => promptDelete(entry.id)} className="text-[11px] uppercase tracking-[0.14em] text-red-300/55 transition-colors hover:text-red-200">Del</button>
                            </div>
                          </div>
                          <div className="space-y-2 text-sm">
                            <div className="flex flex-wrap items-center justify-between gap-2">
                              <span className="text-lime-400/65 text-xs">Email</span>
                              <div className="flex items-center gap-2">
                                <code className="border border-lime-300/20 bg-black/70 px-2 py-0.5 text-xs">{entry.email}</code>
                                <button type="button" onClick={() => handleCopy(entry.email, "Email")} className={BG}>Copy</button>
                              </div>
                            </div>
                            <div className="flex flex-wrap items-center justify-between gap-2">
                              <span className="text-lime-400/65 text-xs">Password</span>
                              <div className="flex items-center gap-2">
                                <code className="border border-lime-300/20 bg-black/70 px-2 py-0.5 text-xs max-w-[180px] truncate">{visible ? entry.password : "••••••••••••"}</code>
                                {visible && <span className={`text-[9px] uppercase tracking-wide ${calcStrength(entry.password).textColor}`}>{calcStrength(entry.password).label}</span>}
                                <button type="button" onClick={() => setShowEntryPasswordId(visible ? null : entry.id)} className={BG}>{visible ? "Hide" : "Show"}</button>
                                <button type="button" onClick={() => handleCopy(entry.password, "Password")} className={BG}>Copy</button>
                              </div>
                            </div>
                            {entry.notes && <p className="mt-1 border-t border-lime-300/10 pt-2 text-xs text-lime-300/55">{entry.notes}</p>}
                            {entry.updatedAt !== entry.createdAt && <p className="text-[9px] text-lime-300/25">Updated {new Date(entry.updatedAt).toLocaleString()}</p>}
                          </div>
                        </motion.li>
                      );
                    })}
                  </AnimatePresence>
                </ul>
              )}
            </motion.div>
          </section>
        )}

        <footer className="terminal-panel mt-7 border border-lime-300/25 bg-black/50 px-4 py-3 text-xs text-lime-300/50 flex flex-wrap justify-between gap-2">
          <span>Local-only · AES-GCM-256 · PBKDF2 310k iter · Zero network calls</span>
          <span>Auto-lock 5 min idle · Locks on tab switch</span>
        </footer>
      </div>

      <AnimatePresence>{editingEntry && <EditModal entry={editingEntry} onSave={handleSaveEdit} onClose={() => setEditingEntry(null)} isLoading={isLoading} />}</AnimatePresence>
      <AnimatePresence>{confirmAction && <ConfirmDialog message={confirmAction.message} onConfirm={confirmAction.onConfirm} onCancel={() => setConfirmAction(null)} />}</AnimatePresence>

      <AnimatePresence>
        {error && <motion.p initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: 10 }} className="fixed right-4 bottom-4 z-50 border border-red-400/70 bg-red-950/90 px-3 py-2 text-sm text-red-100 terminal-panel">{error}</motion.p>}
      </AnimatePresence>
      <AnimatePresence>
        {notice && <motion.p initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: 10 }} className="fixed left-4 bottom-4 z-50 border border-lime-300/70 bg-lime-950/80 px-3 py-2 text-sm text-lime-100 terminal-panel">{notice}</motion.p>}
      </AnimatePresence>
    </main>
  );
}
