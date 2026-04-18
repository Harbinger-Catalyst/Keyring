# ROOT.LOCKSY.EXE

A local-first, browser-based password manager with a focus on creating tech-savvy vibes through terminal-like user interface. All credentials are encrypted and stored entirely in your browser — no servers, no accounts, no network calls.

## Features

- **AES-GCM-256 encryption** — vault data is encrypted with a 256-bit key before being written to `localStorage`
- **PBKDF2 key derivation** — 310,000 iterations with SHA-256 to derive the encryption key from your master password
- **Zero network calls** — everything runs locally in the browser; credentials never leave your device
- **Auto-lock** — vault locks automatically after 5 minutes of inactivity
- **Tab-switch lock** — vault locks instantly when you switch away from the tab
- **Password generator** — configurable length (8–64 chars) with uppercase, digits, and symbol toggles
- **Password strength meter** — real-time visual strength bar on all password fields
- **Favorites** — star entries for quick access in the Favorites tab
- **Search** — full-text search across website, email, username, and notes
- **Sortable list** — sort by name, creation date, or last modified date
- **Export** — download your vault as JSON or CSV
- **Edit & delete** — update any credential with a confirmation prompt on delete

## Tech Stack

| Layer | Library |
|---|---|
| Framework | React 19 + TypeScript |
| Build tool | Vite 7 with `vite-plugin-singlefile` |
| Styling | Tailwind CSS v4 |
| Animations | Framer Motion |
| Utilities | clsx, tailwind-merge |

## Getting Started

**Prerequisites:** Node.js 18+

```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Build for production (outputs a single self-contained HTML file)
npm run build

# Preview production build
npm run preview
```

The production build (`npm run build`) generates a single portable `index.html` file via `vite-plugin-singlefile` — no separate JS or CSS assets required.

## Security Notes

- Your master password is **never stored or transmitted**. If you forget it, the vault is permanently unrecoverable.
- The vault is stored in `localStorage` under the key `password_manager_vault_v1` as an encrypted blob (`salt` + `iv` + `cipherText`).
- A random 16-byte salt and 12-byte IV are generated fresh on every save, so re-encrypting the same data always produces a different ciphertext.
- The minimum master password length is 12 characters.

## Project Structure

```
password-manager-v2/
├── src/
│   ├── App.tsx          # All application logic and UI
│   ├── main.tsx         # React entry point
│   ├── index.css        # Global styles and terminal visual effects
│   └── utils/
│       └── cn.ts        # clsx + tailwind-merge helper
├── index.html
├── vite.config.ts
├── tsconfig.json
└── package.json
```
