import React, { useEffect, useState } from 'react';
import { 
  AlertCircle, RefreshCw, LayoutDashboard, 
  Search, Box, Cpu, History, Clock, FileCheck 
} from 'lucide-react';
import type { ReportDetail } from '../types/report';
import { fetchReport } from '../services/api';
import { OverviewSection } from '../components/ReportViewer/OverviewSection';
import { FindingsSection } from '../components/ReportViewer/FindingsSection';
import { MinecraftEnvSection } from '../components/ReportViewer/MinecraftEnvSection';
import { ProcessRuntimeSection } from '../components/ReportViewer/ProcessRuntimeSection';
import { HistoricalEvidenceSection } from '../components/ReportViewer/HistoricalEvidenceSection';
import { TimelineSection } from '../components/ReportViewer/TimelineSection';
import { DiagnosticsSection } from '../components/ReportViewer/DiagnosticsSection';
import { DeleteModal } from '../components/ReportViewer/DeleteModal';
import { ExportModal } from '../components/ReportViewer/ExportModal';

interface ReportPageProps {
  publicId: string;
  onNavigateHome: () => void;
  onNavigateIngest: () => void;
}

type TabType = 'overview' | 'findings' | 'minecraft' | 'process' | 'historical' | 'timeline' | 'diagnostics';

export const ReportPage: React.FC<ReportPageProps> = ({ publicId, onNavigateHome, onNavigateIngest }) => {
  const [report, setReport] = useState<ReportDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<TabType>('overview');
  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false);
  const [isExportModalOpen, setIsExportModalOpen] = useState(false);

  useEffect(() => {
    let isMounted = true;
    setLoading(true);
    setError(null);

    fetchReport(publicId)
      .then(data => {
        if (isMounted) {
          setReport(data);
          setLoading(false);
        }
      })
      .catch(err => {
        if (isMounted) {
          setError(err.message || 'Failed to load report.');
          setLoading(false);
        }
      });

    return () => {
      isMounted = false;
    };
  }, [publicId]);

  if (loading) {
    return (
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div className="flex flex-col items-center justify-center min-h-[400px] space-y-4">
          <RefreshCw className="w-8 h-8 text-emerald-400 animate-spin" />
          <div className="text-sm font-semibold text-slate-300">Loading Forensic Report {publicId}...</div>
          <p className="text-xs text-slate-500">Querying structured evidence records and verification logs.</p>
        </div>
      </div>
    );
  }

  if (error || !report) {
    return (
      <div className="max-w-3xl mx-auto px-4 py-16 text-center space-y-4">
        <div className="w-12 h-12 rounded-full bg-red-950/80 border border-red-800 text-red-400 flex items-center justify-center mx-auto">
          <AlertCircle className="w-6 h-6" />
        </div>
        <h2 className="text-xl font-bold text-slate-100">Report Unavailable</h2>
        <p className="text-sm text-slate-400 max-w-md mx-auto leading-relaxed">
          {error || 'This report may have expired, been deleted by the player, or never existed.'}
        </p>
        <div className="flex items-center justify-center gap-3 pt-4">
          <button
            onClick={onNavigateHome}
            className="px-4 py-2 text-xs font-semibold rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 transition"
          >
            Go to Home
          </button>
          <button
            onClick={onNavigateIngest}
            className="px-4 py-2 text-xs font-semibold rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white transition"
          >
            Open Ingest & Demo Sandbox
          </button>
        </div>
      </div>
    );
  }

  const tabs: { id: TabType; label: string; icon: React.ReactNode; count?: number }[] = [
    { id: 'overview', label: 'Overview', icon: <LayoutDashboard className="w-4 h-4" /> },
    { id: 'findings', label: 'Findings', icon: <Search className="w-4 h-4" />, count: report.findings.length },
    { id: 'minecraft', label: 'Minecraft Env', icon: <Box className="w-4 h-4" /> },
    { id: 'process', label: 'Process & Runtime', icon: <Cpu className="w-4 h-4" /> },
    { id: 'historical', label: 'Historical Artifacts', icon: <History className="w-4 h-4" />, count: report.evidenceItems.length },
    { id: 'timeline', label: 'Timeline', icon: <Clock className="w-4 h-4" />, count: report.timelineEvents.length },
    { id: 'diagnostics', label: 'Diagnostics', icon: <FileCheck className="w-4 h-4" />, count: report.diagnosticItems.length },
  ];

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
      {/* Navigation Tabs Bar */}
      <div className="border-b border-slate-800 no-print">
        <nav className="flex space-x-2 sm:space-x-4 overflow-x-auto pb-1 text-xs">
          {tabs.map((tab) => {
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-2 py-3 px-3 border-b-2 font-medium whitespace-nowrap transition ${
                  isActive
                    ? 'border-emerald-400 text-emerald-400 bg-slate-900/50 rounded-t-lg'
                    : 'border-transparent text-slate-400 hover:text-slate-200 hover:border-slate-700'
                }`}
              >
                {tab.icon}
                <span>{tab.label}</span>
                {tab.count !== undefined && (
                  <span className={`px-1.5 py-0.5 rounded-full text-[10px] font-mono ${
                    isActive ? 'bg-emerald-950 text-emerald-300' : 'bg-slate-800 text-slate-400'
                  }`}>
                    {tab.count}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Tab Panels */}
      <main>
        {activeTab === 'overview' && (
          <OverviewSection
            report={report}
            onOpenDeleteModal={() => setIsDeleteModalOpen(true)}
            onExportJson={() => setIsExportModalOpen(true)}
          />
        )}

        {activeTab === 'findings' && (
          <FindingsSection findings={report.findings} />
        )}

        {activeTab === 'minecraft' && (
          <MinecraftEnvSection report={report} />
        )}

        {activeTab === 'process' && (
          <ProcessRuntimeSection report={report} />
        )}

        {activeTab === 'historical' && (
          <HistoricalEvidenceSection report={report} />
        )}

        {activeTab === 'timeline' && (
          <TimelineSection events={report.timelineEvents} />
        )}

        {activeTab === 'diagnostics' && (
          <DiagnosticsSection diagnostics={report.diagnosticItems} />
        )}
      </main>

      {/* Modals */}
      <DeleteModal
        publicId={report.publicId}
        isOpen={isDeleteModalOpen}
        onClose={() => setIsDeleteModalOpen(false)}
        onDeleted={() => {
          setIsDeleteModalOpen(false);
          alert('Report and raw evidence have been permanently deleted.');
          onNavigateHome();
        }}
      />

      <ExportModal
        report={report}
        isOpen={isExportModalOpen}
        onClose={() => setIsExportModalOpen(false)}
      />
    </div>
  );
};
