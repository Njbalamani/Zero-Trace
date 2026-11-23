import { Navigate, Route, Routes } from 'react-router-dom'
import { useAuth } from './context/AuthContext'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import DocumentScan from './pages/DocumentScan'
import RepositoryScan from './pages/RepositoryScan'
import Scans from './pages/Scans'
import ScanDetail from './pages/ScanDetail'
import PrivacyTools from './pages/PrivacyTools'
import Recommendations from './pages/Recommendations'
import Audit from './pages/Audit'
import Settings from './pages/Settings'
import Login from './pages/Login'
import Register from './pages/Register'

function ProtectedRoute({ children }) {
  const { user, loading } = useAuth()
  if (loading) return <div className="full-loader"><span className="spinner" /> Initialising ZeroTrace…</div>
  return user ? children : <Navigate to="/login" replace />
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/register" element={<Register />} />
      <Route element={<ProtectedRoute><Layout /></ProtectedRoute>}>
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/scan/document" element={<DocumentScan />} />
        <Route path="/scan/repository" element={<RepositoryScan />} />
        <Route path="/scans" element={<Scans />} />
        <Route path="/scans/:id" element={<ScanDetail />} />
        <Route path="/tools" element={<PrivacyTools />} />
        <Route path="/recommendations" element={<Recommendations />} />
        <Route path="/audit" element={<Audit />} />
        <Route path="/settings" element={<Settings />} />
      </Route>
      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  )
}
