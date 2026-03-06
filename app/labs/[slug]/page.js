import { labsData } from '../../../lib/labs-data';
import LabContent from '../../../components/LabContent';
import Link from 'next/link';

export default async function LabPage({ params }) {
    const { slug } = await params;
    const lab = labsData[slug];

    if (!lab) {
        return (
            <div style={{ textAlign: 'center', padding: '4rem' }}>
                <h2>Lab Not Fully Implemented</h2>
                <p className="text-muted">This module's content is coming soon.</p>
                <Link href="/" className="btn-primary" style={{ display: 'inline-block', marginTop: '1rem' }}>Back to Dashboard</Link>
            </div>
        );
    }

    return <LabContent slug={slug} />;
}
