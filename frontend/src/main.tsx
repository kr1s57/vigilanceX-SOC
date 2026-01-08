import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { AuthProvider } from './contexts/AuthContext'
import { SettingsProvider } from './contexts/SettingsContext'
import { LicenseProvider } from './contexts/LicenseContext'
import App from './App'
import './index.css'

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <BrowserRouter>
      <AuthProvider>
        <LicenseProvider>
          <SettingsProvider>
            <App />
          </SettingsProvider>
        </LicenseProvider>
      </AuthProvider>
    </BrowserRouter>
  </React.StrictMode>,
)
