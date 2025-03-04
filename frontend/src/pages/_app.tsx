import type { AppProps } from 'next/app';
import Navbar from '@/components/Navbar';
import '@/styles/globals.css';

export default function MyApp({ Component, pageProps }: AppProps) {
  return (
    <div className="dark:bg-gray-900 dark:text-white min-h-screen">
      <Navbar />
      <main className="p-4">
        <Component {...pageProps} />
      </main>
    </div>
  );
}
