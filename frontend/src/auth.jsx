import { createContext, useContext, useEffect, useState, useCallback } from 'react';
import { api, getToken, setToken, clearToken } from './api.js';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [booting, setBooting] = useState(Boolean(getToken()));

  useEffect(() => {
    let alive = true;
    if (!getToken()) { setBooting(false); return; }
    api('/me')
      .then((data) => { if (alive && data.user) setUser(data.user); else if (alive) clearToken(); })
      .catch(() => { if (alive) clearToken(); })
      .finally(() => { if (alive) setBooting(false); });
    return () => { alive = false; };
  }, []);

  // Verifikasi OTP. Untuk email baru mengembalikan {pending, regToken} —
  // pendaftaran diselesaikan lewat completeRegistration(username).
  const login = useCallback(async (email, code) => {
    const data = await api('/auth/verify', { method: 'POST', body: { email, code } });
    if (data.pending) return data;
    setToken(data.token);
    setUser(data.user);
    return data;
  }, []);

  const completeRegistration = useCallback(async (username, regToken) => {
    const data = await api('/auth/complete', {
      method: 'POST',
      body: { username },
      token: regToken,
    });
    setToken(data.token);
    setUser(data.user);
    return data;
  }, []);

  const requestOtp = useCallback(async (email) => {
    return api('/auth/request-otp', { method: 'POST', body: { email } });
  }, []);

  const logout = useCallback(() => {
    clearToken();
    setUser(null);
  }, []);

  return (
    <AuthContext.Provider value={{ user, booting, login, completeRegistration, requestOtp, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
