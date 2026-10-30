import { useState, useEffect } from 'react';
import { Navbar } from './components/Layout/Navbar';
import { Footer } from './components/Layout/Footer';
import { HomePage } from './pages/HomePage';
import { ReportPage } from './pages/ReportPage';
import { UploadDemoPage } from './pages/UploadDemoPage';

export function App() {
  const [currentRoute, setCurrentRoute] = useState<{ page: 'home' | 'report' | 'ingest'; publicId?: string }>(() => {
    return parseCurrentLocation();
  });

  function parseCurrentLocation(): { page: 'home' | 'report' | 'ingest'; publicId?: string } {
    // 1. Check hash first (e.g. #/report/mc_123 or #report/mc_123)
    const hash = window.location.hash.replace(/^#\/?/, '');
    if (hash.startsWith('report/')) {
      const publicId = hash.replace('report/', '').split('/')[0];
      if (publicId) return { page: 'report', publicId };
    }
    if (hash === 'ingest') {
      return { page: 'ingest' };
    }

    // 2. Check pathname next (e.g. /report/mc_123)
    const pathname = window.location.pathname.replace(/^\//, '');
    if (pathname.startsWith('report/')) {
      const publicId = pathname.replace('report/', '').split('/')[0];
      if (publicId) return { page: 'report', publicId };
    }
    if (pathname === 'ingest') {
      return { page: 'ingest' };
    }

    // 3. Check search query parameter (e.g. ?report=mc_123)
    try {
      const searchParams = new URLSearchParams(window.location.search);
      const queryId = searchParams.get('report') || searchParams.get('id');
      if (queryId) {
        return { page: 'report', publicId: queryId };
      }
    } catch {
      // Ignore URL parsing errors
    }

    return { page: 'home' };
  }

  useEffect(() => {
    const handleRouteChange = () => {
      setCurrentRoute(parseCurrentLocation());
    };

    window.addEventListener('hashchange', handleRouteChange);
    window.addEventListener('popstate', handleRouteChange);
    return () => {
      window.removeEventListener('hashchange', handleRouteChange);
      window.removeEventListener('popstate', handleRouteChange);
    };
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
