import Link from 'next/link';

export default function Home() {
    const labs = [
        { slug: 'input-validation', title: 'Input Validation', difficulty: 'Beginner', icon: '🛡️' },
        { slug: 'auth-vs-authz', title: 'Auth vs Authz', difficulty: 'Intermediate', icon: '🔑' },
        { slug: 'broken-access-control', title: 'Broken Access Control', difficulty: 'Intermediate', icon: '🚫' },
        { slug: 'csrf', title: 'CSRF Protection', difficulty: 'Advanced', icon: '🎣' },
        { slug: 'security-headers', title: 'Security Headers', difficulty: 'Beginner', icon: '📄' },
        { slug: 'rate-limiting', title: 'Rate Limiting', difficulty: 'Beginner', icon: '⏱️' },
        { slug: 'sql-injection', title: 'SQL Injection', difficulty: 'Intermediate', icon: '💾' },
        { slug: 'xss', title: 'Cross-Site Scripting', difficulty: 'Intermediate', icon: '📜' },
        { slug: 'path-traversal', title: 'Path Traversal', difficulty: 'Advanced', icon: '📂' },
        { slug: 'command-injection', title: 'Command Injection', difficulty: 'Advanced', icon: '💻' },
        { slug: 'linux-essentials', title: 'Linux Essentials', difficulty: 'Beginner', icon: '🐧' },
        { slug: 'cyber-commands', title: 'Cybersecurity Commands', difficulty: 'Beginner', icon: '⚡' },
        { slug: 'cryptography', title: 'Cryptography', difficulty: 'Intermediate', icon: '🔐' },
        { slug: 'threat-intel-tools', title: 'Threat Intel Tools', difficulty: 'Beginner', icon: '🔍' },
        { slug: 'ethical-hacking', title: 'Ethical Hacking', difficulty: 'Advanced', icon: '🎯' },
    ];

    return (
        <div className="animate-fade">
            <section style={{ marginBottom: '4rem', textAlign: 'center' }}>
                <h1 style={{ marginBottom: '1rem' }}>
                    Master <span className="text-primary">Defensive</span> Coding
                </h1>
                <p className="text-muted" style={{ fontSize: '1.1rem', maxWidth: '700px', margin: '0 auto' }}>
                    Explore 15 critical security modules. Identify vulnerabilities,
                    refresh scenarios for variety, and implement secure patterns to patch them.
                </p>
            </section>

            <div style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))',
                gap: '1.5rem'
            }}>
                {labs.map((lab) => (
                    <Link key={lab.slug} href={`/labs/${lab.slug}`} className="card">
                        <div style={{ fontSize: '2.5rem', marginBottom: '1.5rem' }}>{lab.icon}</div>
                        <h3>{lab.title}</h3>
                        <p className="text-muted" style={{ marginBottom: '1.5rem' }}>
                            Learn how to implement proper {lab.title.toLowerCase()} patterns and secure coding practices.
                        </p>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <span style={{
                                fontSize: '0.8rem',
                                padding: '0.25rem 0.75rem',
                                background: 'rgba(0, 255, 136, 0.1)',
                                color: 'var(--primary)',
                                borderRadius: '100px',
                                border: '1px solid rgba(0, 255, 136, 0.2)'
                            }}>
                                {lab.difficulty}
                            </span>
                            <span className="text-primary" style={{ fontWeight: '600' }}>Start Lab &rarr;</span>
                        </div>
                    </Link>
                ))}
            </div>
        </div>
    );
}
// YazidSafeLab Dashboard
