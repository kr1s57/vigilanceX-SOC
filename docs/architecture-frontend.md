# Architecture Frontend - React SPA

> **Généré**: 2026-01-28 | **Version**: 3.58.108

---

## Vue d'Ensemble

Le frontend VIGILANCE X est une SPA React moderne avec TypeScript et Tailwind CSS.

```
frontend/
├── src/
│   ├── App.tsx            # Router principal
│   ├── main.tsx           # Point d'entrée
│   ├── index.css          # Styles globaux
│   ├── pages/             # 20 pages
│   ├── components/        # Composants réutilisables
│   ├── contexts/          # React Context (3)
│   ├── stores/            # Zustand stores (4)
│   ├── hooks/             # Custom hooks
│   ├── lib/               # Utilitaires
│   └── types/             # TypeScript types
├── public/                # Assets statiques
├── vite.config.ts         # Config Vite
├── tailwind.config.js     # Config Tailwind
└── tsconfig.json          # Config TypeScript
```

---

## Stack Technologique

| Catégorie | Technologie | Version |
|-----------|-------------|---------|
| **Framework** | React | 19.0.0 |
| **Build** | Vite | 6.0.7 |
| **Langage** | TypeScript | 5.7.2 |
| **Routing** | React Router DOM | 7.1.1 |
| **State** | Zustand | 5.0.2 |
| **Styling** | Tailwind CSS | 4.0.0 |
| **UI** | Radix UI | 2.x |
| **HTTP** | Axios | 1.7.9 |
| **Charts** | Recharts | 2.15.0 |
| **Maps** | Leaflet + React-Leaflet | 1.9.4 / 5.0.0 |
| **Animation** | Framer Motion | 12.27.5 |

---

## Pages (20)

### Dashboard & Analyse

| Page | Fichier | Taille | Description |
|------|---------|--------|-------------|
| **Dashboard** | Dashboard.tsx | 27KB | Vue d'ensemble temps réel |
| **WAF Explorer** | WafExplorer.tsx | 45KB | Analyse logs ModSecurity |
| **Attacks Analyzer** | AttacksAnalyzer.tsx | 51KB | Événements IPS/WAF/ATP |
| **Advanced Threat** | AdvancedThreat.tsx | 18KB | Enrichissement TI |
| **Attack Map** | AttackMap.tsx | 25KB | Carte mondiale interactive |
| **Track IP** | TrackIP.tsx | 39KB | Recherche forensique |

### Gestion des Bans

| Page | Fichier | Taille | Description |
|------|---------|--------|-------------|
| **Active Bans** | ActiveBans.tsx | 46KB | Liste des IPs bannies |
| **Soft Whitelist** | SoftWhitelist.tsx | 36KB | Gestion whitelist 3 types |
| **Geoblocking** | Geoblocking.tsx | 36KB | Blocage par pays/ASN |

### Intelligence & Sync

| Page | Fichier | Taille | Description |
|------|---------|--------|-------------|
| **Neural-Sync** | NeuralSync.tsx | 19KB | CrowdSec via VigilanceKey |
| **CrowdSec BL** | CrowdSecBL.tsx | 31KB | Blocklist CrowdSec direct |
| **Vigimail Checker** | VigimailChecker.tsx | 44KB | Détection fuites emails |
| **Risk Scoring** | RiskScoring.tsx | 20KB | Système de scoring |

### VPN & Réseau

| Page | Fichier | Taille | Description |
|------|---------|--------|-------------|
| **VPN Network** | VpnNetwork.tsx | 27KB | Monitoring VPN |

### Rapports & Admin

| Page | Fichier | Taille | Description |
|------|---------|--------|-------------|
| **Reports** | Reports.tsx | 25KB | Génération PDF/XML |
| **Settings** | Settings.tsx | 132KB | Configuration complète |
| **User Management** | UserManagement.tsx | 24KB | Gestion utilisateurs RBAC |

### Authentification

| Page | Fichier | Taille | Description |
|------|---------|--------|-------------|
| **Login** | Login.tsx | 8KB | Page de connexion |
| **License Activation** | LicenseActivation.tsx | 19KB | Activation licence VX3 |

---

## Composants

### Structure

```
components/
├── ui/                    # Composants de base (Shadcn style)
│   ├── button.tsx
│   ├── card.tsx
│   ├── dialog.tsx
│   ├── dropdown-menu.tsx
│   ├── input.tsx
│   ├── select.tsx
│   ├── table.tsx
│   ├── tabs.tsx
│   └── ...
├── layout/                # Layout composants
│   └── Sidebar.tsx
├── dashboard/             # Widgets dashboard
│   └── ...
├── charts/                # Composants graphiques
│   └── ...
├── attackmap/             # Carte des attaques
│   └── ...
├── settings/              # Sous-composants settings
│   └── ...
├── AdminRoute.tsx         # Route admin-only
├── ProtectedRoute.tsx     # Route authentifiée
├── CountrySelector.tsx    # Sélecteur pays
├── IPThreatModal.tsx      # Modal détails IP
├── Logo.tsx               # Logo VIGILANCE X
├── PendingApprovalDetailModal.tsx
├── TerminalConsole.tsx    # Console admin
└── WAFServerModal.tsx     # Config serveur WAF
```

### Composants UI (Radix-based)

| Composant | Description |
|-----------|-------------|
| `Button` | Boutons avec variants |
| `Card` | Cartes avec glassmorphism |
| `Dialog` | Modales accessibles |
| `DropdownMenu` | Menus déroulants |
| `Select` | Sélecteurs |
| `Table` | Tableaux triables |
| `Tabs` | Navigation par onglets |
| `Toast` | Notifications |
| `Tooltip` | Infobulles |

---

## Gestion d'État

### React Context (Global)

| Context | Fichier | État |
|---------|---------|------|
| `AuthContext` | AuthContext.tsx | User, token, login/logout |
| `LicenseContext` | LicenseContext.tsx | Licence status, features |
| `SettingsContext` | SettingsContext.tsx | Préférences utilisateur |

### Zustand Stores (Domain)

| Store | Fichier | État |
|-------|---------|------|
| `bansStore` | bansStore.ts | Liste bans, filters |
| `eventsStore` | eventsStore.ts | Événements récents |
| `attackMapStore` | attackMapStore.ts | Données carte |
| `alertsStore` | alertsStore.ts | Alertes temps réel |

### Utilisation

```tsx
// Context (global)
const { user, isAuthenticated, logout } = useAuth();
const { isLicensed, features } = useLicense();
const { theme, setTheme } = useSettings();

// Zustand (domain)
const { bans, fetchBans, addBan } = useBansStore();
const { events, fetchEvents } = useEventsStore();
```

---

## Routing

### Configuration (`App.tsx`)

```tsx
<Routes>
  {/* Public */}
  <Route path="/login" element={<Login />} />
  <Route path="/license" element={<LicenseActivation />} />

  {/* Protected */}
  <Route element={<ProtectedRoute />}>
    <Route path="/" element={<Dashboard />} />
    <Route path="/waf-explorer" element={<WafExplorer />} />
    <Route path="/attacks" element={<AttacksAnalyzer />} />
    <Route path="/threats" element={<AdvancedThreat />} />
    <Route path="/bans" element={<ActiveBans />} />
    <Route path="/whitelist" element={<SoftWhitelist />} />
    <Route path="/geoblocking" element={<Geoblocking />} />
    <Route path="/attack-map" element={<AttackMap />} />
    <Route path="/track-ip" element={<TrackIP />} />
    <Route path="/neural-sync" element={<NeuralSync />} />
    <Route path="/crowdsec" element={<CrowdSecBL />} />
    <Route path="/vigimail" element={<VigimailChecker />} />
    <Route path="/vpn" element={<VpnNetwork />} />
    <Route path="/reports" element={<Reports />} />
    <Route path="/settings" element={<Settings />} />

    {/* Admin only */}
    <Route element={<AdminRoute />}>
      <Route path="/users" element={<UserManagement />} />
    </Route>
  </Route>
</Routes>
```

---

## API Client

### Configuration (`lib/api.ts`)

```typescript
import axios from 'axios';

const api = axios.create({
  baseURL: '/api/v1',
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Intercepteur JWT
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Intercepteur erreurs
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('token');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

export default api;
```

---

## Styling

### Tailwind Configuration

```javascript
// tailwind.config.js
export default {
  darkMode: ["class"],
  content: ["./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        // Semantic colors
        severity: {
          critical: "#dc2626",
          high: "#ea580c",
          medium: "#ca8a04",
          low: "#2563eb",
          info: "#6b7280",
        },
        status: {
          active: "#22c55e",
          blocked: "#ef4444",
          warning: "#f59e0b",
        },
        // Neon accents
        neon: {
          cyan: "#06b6d4",
          purple: "#a855f7",
          pink: "#ec4899",
          blue: "#3b82f6",
          green: "#10b981",
        },
      },
      boxShadow: {
        "neon-cyan": "0 0 20px rgba(6, 182, 212, 0.5)",
        "glass": "0 8px 32px rgba(0, 0, 0, 0.4)",
      },
      animation: {
        "pulse-glow": "pulse-glow 2s infinite",
        "neon-flicker": "neon-flicker 3s linear infinite",
        "fade-in-up": "fade-in-up 0.3s ease-out",
      },
    },
  },
};
```

### Theme Dark Mode

Le projet utilise exclusivement le dark mode avec:
- Background: `slate-900`, `slate-950`
- Cards: Glassmorphism avec `backdrop-blur`
- Accents: Neon colors (cyan, purple, pink)
- Animations: Glow, flicker, pulse

---

## Build Production

### Vite Configuration

```typescript
// vite.config.ts
export default defineConfig({
  plugins: [react()],
  build: {
    sourcemap: false,        // Sécurité
    minify: 'terser',        // Obfuscation
    terserOptions: {
      compress: {
        drop_console: true,  // Remove console.log
        drop_debugger: true, // Remove debugger
      },
      mangle: {
        toplevel: true,      // Mangle names
      },
    },
    rollupOptions: {
      output: {
        manualChunks: {
          vendor: ['react', 'react-dom', 'react-router-dom'],
          ui: ['@radix-ui/react-dialog', '@radix-ui/react-dropdown-menu'],
          charts: ['recharts'],
        },
        chunkFileNames: 'assets/[hash].js',
        assetFileNames: 'assets/[hash].[ext]',
      },
    },
  },
});
```

---

## Dépendances Clés

| Package | Version | Usage |
|---------|---------|-------|
| react | 19.0.0 | Framework UI |
| react-router-dom | 7.1.1 | Routing |
| zustand | 5.0.2 | State management |
| axios | 1.7.9 | HTTP client |
| @radix-ui/* | 2.x | UI primitives |
| recharts | 2.15.0 | Charts |
| leaflet | 1.9.4 | Maps |
| framer-motion | 12.27.5 | Animations |
| tailwindcss | 4.0.0 | CSS framework |
| date-fns | 3.x | Date utils |
| clsx | 2.x | Class names |
| lucide-react | - | Icons |

---

*Documentation générée par le workflow document-project*
