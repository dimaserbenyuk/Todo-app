const API_URL = process.env.NEXT_PUBLIC_API_URL;

export const register = async (username: string, password: string) => {
  const response = await fetch(`${API_URL}/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });

  if (!response.ok) {
    throw new Error('Ошибка регистрации');
  }
};

export const login = async (username: string, password: string) => {
  const response = await fetch(`${API_URL}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });

  if (!response.ok) {
    throw new Error('Ошибка входа');
  }

  const data = await response.json();
  localStorage.setItem('token', data.token);
};

export const logout = () => {
  localStorage.removeItem('token');
};
