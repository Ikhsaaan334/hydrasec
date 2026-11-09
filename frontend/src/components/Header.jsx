import { NavLink, useNavigate } from 'react-router-dom';
import { useAuth } from '../auth.jsx';

const Icon = () => (
  <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    <path d="M9 12l2 2 4-4" />
  </svg>
);

export default function Header({ onLogout }) {
  const navigate = useNavigate();
  const { user } = useAuth();
  const initial = (user?.email ?? '?')[0].toUpperCase();

  function handleLogout() {
    onLogout();
    navigate('/login');
  }

  return (
    <header className="site-header">
      <div className="wrap">
        <NavLink to="/" className="brand">
          <Icon />
          HydraSec
        </NavLink>
        <nav className="nav" aria-label="Main navigation">
          <NavLink to="/" end>Dashboard</NavLink>
          <NavLink to="/scan/new">New Scan</NavLink>
          <NavLink to="/scans">History</NavLink>
          <NavLink to="/system">System</NavLink>
        </nav>
        <div className="header-spacer" />
        <div className="user-chip">
          <span className="avatar" aria-hidden="true">{initial}</span>
          <span>{user?.username ?? user?.email ?? ''}</span>
        </div>
        <button type="button" className="btn-exit" onClick={handleLogout}>
          Sign out
        </button>
      </div>
    </header>
  );
}
