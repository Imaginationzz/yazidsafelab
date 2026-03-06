'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { labsData } from '../lib/labs-data';

export default function LabContent({ slug }) {
    const lab = labsData[slug];
    const [variantIndex, setVariantIndex] = useState(0);
    const [activeTab, setActiveTab] = useState('scenario');
    const [checkResult, setCheckResult] = useState(null);

    // Get current variant data safely
    const variant = lab?.variants ? lab.variants[variantIndex] : null;

    useEffect(() => {
        console.log('YazidSafeLab: Component hydrated');
    }, []);

    const handleTabChange = (tabId) => {
        setActiveTab(tabId);
        setCheckResult(null);
    };

    const handleRefresh = () => {
        if (!lab || !lab.variants) return;
        const nextIndex = (variantIndex + 1) % lab.variants.length;
        setVariantIndex(nextIndex);
        setCheckResult(null);
        setActiveTab('scenario'); // Reset to scenario on refresh
        console.log('YazidSafeLab: Refreshed to variant', nextIndex);
    };

    const runCheck = () => {
        if (!variant) return;
        setCheckResult('scanning');
        setTimeout(() => {
            // Use the specific check logic for the current variant
            const isPassed = variant.check_logic(variant.patched_code);
            setCheckResult(isPassed ? 'passed' : 'failed');
        }, 1500);
    };

    if (!lab || !variant) return <div className="card">Lab not found</div>;

    return (
        <div className="animate-fade">
            <div className="lab-header" style={{
                marginBottom: '2rem',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'flex-end',
                flexWrap: 'wrap',
                gap: '1rem'
            }}>
                <div style={{ flex: '1 1 300px' }}>
                    <Link href="/" style={{ fontSize: '0.9rem' }} className="text-muted">&larr; Back to Dashboard</Link>
                    <h1 style={{ marginTop: '0.5rem', marginBottom: 0 }}>{lab.title}</h1>
                </div>
                {lab.variants.length > 1 && (
                    <button
                        onClick={handleRefresh}
                        className="btn-outline"
                        style={{ padding: '0.5rem 1rem', fontSize: '0.85rem', display: 'flex', alignItems: 'center', gap: '0.5rem', whiteSpace: 'nowrap' }}
                    >
                        <span>🔄</span> Refresh Scenario
                    </button>
                )}
            </div>

            <div className="tabs-container" style={{
                gap: '1rem',
                marginBottom: '2rem',
                borderBottom: '1px solid var(--border)',
                position: 'relative',
                zIndex: 10
            }}>
                {[
                    { id: 'scenario', label: 'Scenario' },
                    { id: 'vulnerable', label: 'Vulnerable Code' },
                    { id: 'fix', label: 'Fix Steps' },
                    { id: 'patched', label: 'Patched Code' },
                    { id: 'explanation', label: 'Explanation' }
                ].map((tab) => (
                    <button
                        key={tab.id}
                        type="button"
                        onClick={() => handleTabChange(tab.id)}
                        style={{
                            background: 'none',
                            border: 'none',
                            padding: '1rem 0.5rem',
                            marginRight: '0.5rem',
                            cursor: 'pointer',
                            display: 'block',
                            position: 'relative',
                            zIndex: 20,
                            whiteSpace: 'nowrap',
                            borderBottom: activeTab === tab.id ? '2px solid var(--primary)' : '2px solid transparent',
                            color: activeTab === tab.id ? 'var(--primary)' : 'var(--text-muted)',
                            borderRadius: 0,
                            fontWeight: activeTab === tab.id ? '700' : '400'
                        }}
                    >
                        {tab.label}
                    </button>
                ))}
            </div>

            <div className="card">
                {activeTab === 'scenario' && (
                    <div className="animate-fade">
                        <h3>The Scenario</h3>
                        <p style={{ fontSize: '1.1rem', marginTop: '1rem' }}>{variant.scenario}</p>
                    </div>
                )}

                {activeTab === 'vulnerable' && (
                    <div className="animate-fade">
                        <h3>Vulnerable Implementation</h3>
                        <pre style={{
                            background: 'var(--bg-code)',
                            padding: '1.5rem',
                            borderRadius: '8px',
                            border: '1px solid var(--error)',
                            overflowX: 'auto',
                            color: '#ffa0a0',
                            marginTop: '1rem'
                        }}>
                            <code>{variant.vulnerable_code}</code>
                        </pre>
                    </div>
                )}

                {activeTab === 'fix' && (
                    <div className="animate-fade">
                        <h3>Defense Strategy</h3>
                        <ul style={{ paddingLeft: '1.5rem', marginTop: '1.2rem' }}>
                            {variant.fix_steps.map((step, i) => (
                                <li key={i} style={{ marginBottom: '1rem' }}>{step}</li>
                            ))}
                        </ul>
                    </div>
                )}

                {activeTab === 'explanation' && (
                    <div className="animate-fade">
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1.5rem', flexWrap: 'wrap' }}>
                            <h3 style={{ margin: 0 }}>Educational Context</h3>
                            <span style={{
                                fontSize: '0.7rem',
                                padding: '0.2rem 0.6rem',
                                background: 'var(--primary)',
                                color: 'var(--bg)',
                                borderRadius: '4px',
                                fontWeight: '700',
                                textTransform: 'uppercase'
                            }}>
                                Beginner Friendly
                            </span>
                        </div>
                        <p style={{
                            fontSize: '1.15rem',
                            lineHeight: '1.7',
                            color: 'var(--text)',
                            background: 'rgba(255, 255, 255, 0.03)',
                            padding: '1.5rem',
                            borderRadius: '12px',
                            borderLeft: '4px solid var(--primary)'
                        }}>
                            {variant.explanation || "Detailed explanation coming soon for this YazidSafeLab variant."}
                        </p>
                    </div>
                )}

                {activeTab === 'patched' && (
                    <div className="animate-fade" style={{ position: 'relative' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', flexWrap: 'wrap', gap: '0.75rem' }}>
                            <h3>Secure Implementation</h3>
                            <button
                                onClick={runCheck}
                                className="btn-primary"
                                style={{ padding: '0.5rem 1rem', fontSize: '0.8rem', flex: '0 0 auto' }}
                                disabled={checkResult === 'scanning'}
                                type="button"
                            >
                                {checkResult === 'scanning' ? 'Scanning...' : 'Run Safety Check'}
                            </button>
                        </div>
                        <pre style={{
                            background: 'var(--bg-code)',
                            padding: '1.5rem',
                            borderRadius: '8px',
                            border: '1px solid var(--success)',
                            overflowX: 'auto',
                            color: '#a0ffa0'
                        }}>
                            <code>{variant.patched_code}</code>
                        </pre>

                        {checkResult === 'passed' && (
                            <div style={{
                                marginTop: '1.5rem',
                                padding: '1rem',
                                background: 'rgba(0, 255, 136, 0.1)',
                                border: '1px solid var(--primary)',
                                borderRadius: '8px',
                                color: 'var(--primary)'
                            }}>
                                <strong>✓ Safety Check Passed:</strong> Secure patterns detected for this variant.
                            </div>
                        )}
                    </div>
                )}
            </div>
        </div>
    );
}
