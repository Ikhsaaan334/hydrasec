import { Routes, Route, Navigate } from 'react-router-dom';
import { useAuth } from './auth.jsx';
import Header from './components/Header.jsx';
import Login from './pages/Login.jsx';
import Dashboard from './pages/Dashboard.jsx';
import NewScan from './pages/NewScan.jsx';
import ScanDetail from './pages/ScanDetail.jsx';
import History from './pages/History.jsx';
import System from './pages/System.jsx';

function RequireAuth({ children }) {
  const { user, booting } = useAuth();
  if (booting) {
    return (
      <div className="empty" style={{ paddingTop: 120 }}>
        <span className="spinner" />
      </div>
    );
  }
  if (!user) return <Navigate to="/login" replace />;
  // Kontainer .wrap untuk semua halaman (tepi sejajar, padding responsif).
  // Halaman /login sengaja di luar — layout split-nya full-bleed.
  return <main className="wrap">{children}</main>;
}

export default function App() {
  const { user, logout } = useAuth();
  return (
    <>
      {user && <Header onLogout={logout} />}
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/" element={<RequireAuth><Dashboard /></RequireAuth>} />
        <Route path="/scan/new" element={<RequireAuth><NewScan /></RequireAuth>} />
        <Route path="/scans" element={<RequireAuth><History /></RequireAuth>} />
        <Route path="/scans/:id" element={<RequireAuth><ScanDetail /></RequireAuth>} />
        <Route path="/system" element={<RequireAuth><System /></RequireAuth>} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </>
  );
}
