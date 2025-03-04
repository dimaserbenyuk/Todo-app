import Link from 'next/link';
import { useState, useEffect } from 'react';

export default function Navbar() {
  const [theme, setTheme] = useState('light');

  useEffect(() => {
    document.documentElement.classList.toggle('dark', theme === 'dark');
  }, [theme]);

  return (
    <nav className="p-4 bg-gray-200 dark:bg-gray-800 flex justify-between">
      <h1 className="text-xl font-bold text-gray-900 dark:text-white">Todo App</h1>
      <div className="flex gap-4">
        <Link href="/register" className="text-blue-500 dark:text-blue-300">Регистрация</Link>
        <Link href="/login" className="text-blue-500 dark:text-blue-300">Логин</Link>
        <button
          onClick={() => setTheme(theme === 'light' ? 'dark' : 'light')}
          className="bg-gray-300 dark:bg-gray-600 p-2 rounded"
        >
          {theme === 'light' ? '🌙' : '☀️'}
        </button>
      </div>
    </nav>
  );
}
