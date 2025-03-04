import { useState } from 'react';

export default function LoginPage() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    console.log('Logging in:', { email, password });
  };

  return (
    <div className="max-w-md mx-auto p-4">
      <h2 className="text-2xl font-bold mb-4">Вход</h2>
      <form onSubmit={handleSubmit} className="flex flex-col gap-2">
        <input 
          type="email" placeholder="Email"
          className="p-2 border rounded"
          value={email} onChange={(e) => setEmail(e.target.value)}
        />
        <input 
          type="password" placeholder="Пароль"
          className="p-2 border rounded"
          value={password} onChange={(e) => setPassword(e.target.value)}
        />
        <button className="p-2 bg-blue-500 text-white rounded">Войти</button>
      </form>
    </div>
  );
}
