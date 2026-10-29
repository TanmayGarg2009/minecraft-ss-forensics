import { useState, useEffect } from 'react';
import { Navbar } from './components/Layout/Navbar';
import { Footer } from './components/Layout/Footer';
import { HomePage } from './pages/HomePage';
import { ReportPage } from './pages/ReportPage';
import { UploadDemoPage } from './pages/UploadDemoPage';

export function App() {
  const [currentRoute, setCurrentRoute] = useState<{ page: 'home' | 'report' | 'ingest'; publicId?: string }>(() => {
    return parseHash(window.location.hash);
  });

  function parseHash(hash: string): { page: 'home' | 'report' | 'ingest'; publicId?: string } {
    const clean = hash.replace(/^#\/?/, '');
    if (clean.startsWith('report/')) {
      const publicId = clean.replace('report/', '');
      return { page: 'report', publicId };
    }
    if (clean === 'ingest') {
      return { page: 'ingest' };
    }
    return { page: 'home' };
  }

  useEffect(() => {
    const handleHashChange = () => {
      setCurrentRoute(parseHash(window.location.hash));
    };

    window.addEventListener('hashchange', handleHashChange);
    return () => window.removeEventListener('hashchange', handleHashChange);
  }, []);

  const navigateToReport = (publicId: string) => {
    window.location.hash = `#/report/${publicId}`;
  };

  const navigateToHome = () => {
    window.location.hash = '#/';
  };

  const navigateToIngest = () => {
    window.location.hash = '#/ingest';
  };

  return (
    <div className="min-h-screen flex flex-col bg-slate-950 text-slate-100 selection:bg-emerald-500 selection:text-slate-950">
      <Navbar
        currentPublicId={currentRoute.publicId}
        onNavigateHome={navigateToHome}
        onNavigateIngest={navigateToIngest}
      />

      <main className="flex-1">
        {currentRoute.page === 'home' && (
          <HomePage
            onOpenReport={navigateToReport}
            onNavigateIngest={navigateToIngest}
          />
        )}

        {currentRoute.page === 'ingest' && (
          <UploadDemoPage onOpenReport={navigateToReport} />
        )}

        {currentRoute.page === 'report' && currentRoute.publicId && (
          <ReportPage
            publicId={currentRoute.publicId}
            onNavigateHome={navigateToHome}
            onNavigateIngest={navigateToIngest}
          />
        )}
      </main>

      <Footer />
    </div>
  );
}

export default App;
