import './globals.css';

export const metadata = {
  title: 'YazidSafeLab | Modern Web Security Training',
  description: 'Learn defensive coding by fixing real-world vulnerabilities.',
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>
        <header>
          <div className="container nav-content">
            <div className="logo">YazidSafeLab</div>
            <nav>
              <a href="/" className="btn-outline" style={{ padding: '0.5rem 1rem' }}>Dashboard</a>
            </nav>
          </div>
        </header>
        <main className="container">
          {children}
        </main>
        <footer style={{ borderTop: '1px solid var(--border)', padding: '2rem 0', marginTop: '4rem' }}>
          <div className="container text-muted" style={{ fontSize: '0.9rem', textAlign: 'center' }}>
            &copy; {new Date().getFullYear()} YazidSafeLab - Intentional Security Playground (Local Only)
          </div>
        </footer>
      </body>
    </html>
  );
}
