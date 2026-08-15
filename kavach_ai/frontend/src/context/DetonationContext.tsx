import React, { createContext, useContext, useState, useEffect } from 'react';

export interface ApkDetails {
  name: string;
  size: string;
  package: string;
  hash?: string;
}

export interface NetworkConnection {
  ip: string;
  port: number;
  protocol: 'TCP' | 'UDP';
  status?: 'connected' | 'attempted' | 'refused';
}

export interface DnsResolution {
  domain: string;
  resolved_ip?: string;
  status: 'resolved' | 'nxdomain' | 'timeout' | 'failed';
}

export interface EbpfTelemetry {
  syscalls: string[];
  files_accessed: string[];
  network_connections: NetworkConnection[];
  dns_resolutions?: DnsResolution[];
  permissions_exercised?: string[];
}

export interface TelemetryPayload {
  execution_mode?: 'LIVE_ADB_FRIDA' | 'SIMULATION_FALLBACK';
  objection_root_bypass: boolean;
  objection_ssl_pinning_bypass: boolean;
  time_dilution_bypass?: boolean;
  time_dilution_count?: number;
  time_dilution_events?: string[];
  llm_frida_intercepts?: string[];
  fuzzed_intents?: any[];
  synthesized_hooks_code?: string;
  ebpf_telemetry: EbpfTelemetry;
  native_libraries?: string[];
}

export interface ModelInfo {
  id: string;
  name: string;
  description: string;
  path: string;
}

export interface StaticScanResults {
  apk_details: ApkDetails;
  triage: {
    package_name?: string;
    permissions?: string[];
    permission_combinations?: string[];
    triage_score?: number;
    code_signals?: string[];
    manifest_indicators?: string[];
    reflection_indicators?: string[];
    dynamic_loading_indicators?: string[];
    obfuscation_indicators?: string[];
    activities?: any[];
    services?: any[];
    receivers?: any[];
    providers?: any[];
    min_sdk?: number;
    target_sdk?: number;
  };
  ml_metrics: {
    model_id: string;
    verdict: 'MALICIOUS' | 'BENIGN';
    malicious_probability: number;
    confidence_score: number;
    slice_count: number;
    slice_evaluations: Array<{
      slice_index: number;
      malicious_probability: number;
      code_snippet: string;
    }>;
  };
  native_libraries?: string[];
}

interface DetonationContextType {
  status: 'landing' | 'analyzing' | 'completed' | 'error';
  currentView: 'dashboard' | 'scorecard' | 'static_scan' | 'bert_classifier' | 'mitre_map' | 'cert_in' | 'sandbox_health' | 'api_credentials' | 'settings' | 'kavach_report';
  apkDetails: ApkDetails | null;
  jobId: string | null;
  logs: string[];
  telemetry: TelemetryPayload | null;
  simulationMode: boolean;
  isAdbConnected: boolean;
  setSimulationMode: (mode: boolean) => void;
  detonationDuration: number;
  setDetonationDuration: (duration: number) => void;
  setCurrentView: (view: 'dashboard' | 'scorecard' | 'static_scan' | 'bert_classifier' | 'mitre_map' | 'cert_in' | 'sandbox_health' | 'api_credentials' | 'settings' | 'kavach_report') => void;
  viewScorecard: () => void;
  viewDashboard: () => void;
  loadRecentScan: () => Promise<void>;
  detonate: (file: File) => Promise<void>;
  reset: () => void;
  // Static Scan & Models extensions
  availableModels: ModelInfo[];
  selectedModelId: string;
  setSelectedModelId: (id: string) => void;
  staticScanStatus: 'landing' | 'analyzing' | 'completed' | 'error';
  staticResults: StaticScanResults | null;
  runStaticScan: (file: File, modelId?: string) => Promise<void>;
  currentFile: File | null;
}

const DetonationContext = createContext<DetonationContextType | undefined>(undefined);

export const DetonationProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [status, setStatus] = useState<DetonationContextType['status']>('landing');
  const [currentView, setCurrentView] = useState<DetonationContextType['currentView']>('static_scan');
  const [apkDetails, setApkDetails] = useState<ApkDetails | null>(null);
  const [logs, setLogs] = useState<string[]>([]);
  const [telemetry, setTelemetry] = useState<TelemetryPayload | null>(null);
  const [simulationMode, setSimulationMode] = useState<boolean>(false);
  const [isAdbConnected, setIsAdbConnected] = useState<boolean>(true);
  const [detonationDuration, setDetonationDuration] = useState<number>(10);
  const [currentFile, setCurrentFile] = useState<File | null>(null);
  const [jobId, setJobId] = useState<string | null>(null);

  // Static scan state
  const [availableModels, setAvailableModels] = useState<ModelInfo[]>([
    {
      id: 'securebert-full-weighted',
      name: 'SecureBERT Full Weighted (High Precision)',
      description: 'Extremely low false-positive rate (99.6% precision).',
      path: ''
    },
    {
      id: 'securebert-balanced-1to1',
      name: 'SecureBERT Balanced (High Recall)',
      description: 'High sensitivity/recall for catching subtle malware.',
      path: ''
    }
  ]);
  const [selectedModelId, setSelectedModelId] = useState<string>('securebert-full-weighted');
  const [staticScanStatus, setStaticScanStatus] = useState<'landing' | 'analyzing' | 'completed' | 'error'>('landing');
  const [staticResults, setStaticResults] = useState<StaticScanResults | null>(null);

  // Fetch available models from backend on mount
  useEffect(() => {
    setIsAdbConnected(true);
    fetch('/api/models')
      .then((res) => res.json())
      .then((data) => {
        if (data.status === 'success' && Array.isArray(data.models) && data.models.length > 0) {
          setAvailableModels(data.models);
          setSelectedModelId(data.models[0].id);
        }
      })
      .catch((err) => console.warn('Failed to fetch models list:', err));
  }, []);

  const loadRecentScan = async () => {
    try {
      const res = await fetch('/api/recent-scan');
      if (res.ok) {
        const data = await res.json();
        if (data.status === 'success' && data.telemetry) {
          setTelemetry(data.telemetry);
          if (data.apk_details) {
            setApkDetails(data.apk_details);
          }
        }
      }
    } catch (err) {
      console.warn('Failed to load recent scan from API:', err);
    }
  };

  const viewScorecard = () => {
    if (!telemetry) {
      loadRecentScan();
    }
    setCurrentView('scorecard');
  };

  const viewDashboard = () => setCurrentView('dashboard');

  const reset = () => {
    const nextView = currentView === 'static_scan' ? 'static_scan' : 'dashboard';
    setStatus('landing');
    setStaticScanStatus('landing');
    setCurrentView(nextView);
    setApkDetails(null);
    setLogs([]);
    setTelemetry(null);
    setStaticResults(null);
    setCurrentFile(null);
    setJobId(null);
  };

  const detonate = async (file: File) => {
    setCurrentFile(file);
    setStatus('analyzing');
    setLogs([]);
    setTelemetry(null);
    setApkDetails({
      name: file.name,
      size: `${(file.size / (1024 * 1024)).toFixed(2)} MB`,
      package: 'Resolving identifier...'
    });

    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await fetch(`/api/detonate-stream?simulation=${simulationMode}&duration=${detonationDuration}`, {
        method: 'POST',
        body: formData,
      });

      if (!response.body) {
        throw new Error('Readable stream not supported on response.');
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let rawBuffer = '';

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;

        rawBuffer += decoder.decode(value, { stream: true });
        const normalized = rawBuffer.replace(/\r\n/g, '\n');
        const parts = normalized.split('\n\n');
        
        rawBuffer = parts.pop() || '';

        for (const part of parts) {
          const lines = part.split('\n');
          for (const rawLine of lines) {
            const line = rawLine.trim();
            if (!line.startsWith('data: ')) continue;
            
            try {
              const data = JSON.parse(line.slice(6));

              if (data.type === 'log') {
                setLogs((prev) => [...prev, data.message]);
              } else if (data.type === 'metadata') {
                setApkDetails(data.apk_details);
                if (data.job_id) setJobId(data.job_id);
              } else if (data.type === 'result') {
                setTelemetry(data.telemetry);
                setStatus('completed');
              } else if (data.type === 'error') {
                setLogs((prev) => [...prev, `[Fatal] ${data.message}`]);
                setStatus('error');
              }
            } catch (err) {
              console.error('Failed to parse SSE payload:', err, line);
            }
          }
        }
      }
    } catch (err: any) {
      console.error('SSE connection error:', err);
      setLogs((prev) => [...prev, `[Connection Error] Failed to stream telemetry: ${err.message}`]);
      setStatus('error');
    }
  };

  const runStaticScan = async (file: File, modelId?: string) => {
    setCurrentFile(file);
    const targetModel = modelId || selectedModelId;
    setStaticScanStatus('analyzing');
    setCurrentView('static_scan');
    setLogs([]);
    setStaticResults(null);
    setApkDetails({
      name: file.name,
      size: `${(file.size / (1024 * 1024)).toFixed(2)} MB`,
      package: 'Resolving identifier...'
    });

    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await fetch(`/api/static-scan-stream?model_id=${encodeURIComponent(targetModel)}`, {
        method: 'POST',
        body: formData,
      });

      if (!response.body) {
        throw new Error('Readable stream not supported on response.');
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let rawBuffer = '';

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;

        rawBuffer += decoder.decode(value, { stream: true });
        const normalized = rawBuffer.replace(/\r\n/g, '\n');
        const parts = normalized.split('\n\n');
        
        rawBuffer = parts.pop() || '';

        for (const part of parts) {
          const lines = part.split('\n');
          for (const rawLine of lines) {
            const line = rawLine.trim();
            if (!line.startsWith('data: ')) continue;
            
            try {
              const data = JSON.parse(line.slice(6));

              if (data.type === 'log') {
                setLogs((prev) => [...prev, data.message]);
              } else if (data.type === 'metadata') {
                if (data.job_id) setJobId(data.job_id);
              } else if (data.type === 'result') {
                setStaticResults(data.static_results);
                if (data.static_results?.apk_details) {
                  setApkDetails(data.static_results.apk_details);
                }
                setStaticScanStatus('completed');
              } else if (data.type === 'error') {
                setLogs((prev) => [...prev, `[Fatal] ${data.message}`]);
                setStaticScanStatus('error');
              }
            } catch (err) {
              console.error('Failed to parse static scan SSE payload:', err, line);
            }
          }
        }
      }

      // Process any leftover string in rawBuffer when stream completes
      if (rawBuffer.trim()) {
        const lines = rawBuffer.replace(/\r\n/g, '\n').split('\n');
        for (const rawLine of lines) {
          const line = rawLine.trim();
          if (!line.startsWith('data: ')) continue;
          try {
            const data = JSON.parse(line.slice(6));
            if (data.type === 'result' && data.static_results) {
              setStaticResults(data.static_results);
              if (data.static_results?.apk_details) {
                setApkDetails(data.static_results.apk_details);
              }
              setStaticScanStatus('completed');
            }
          } catch (e) {
            // ignore trailing incomplete chunk
          }
        }
      }
    } catch (err: any) {
      console.error('Static scan connection error:', err);
      setLogs((prev) => [...prev, `[Connection Error] Failed to execute static scan: ${err.message}`]);
      setStaticScanStatus('error');
    }
  };

  return (
    <DetonationContext.Provider
      value={{
        status,
        currentView,
        apkDetails,
        logs,
        telemetry,
        simulationMode,
        isAdbConnected,
        setSimulationMode,
        detonationDuration,
        setDetonationDuration,
        setCurrentView,
        viewScorecard,
        viewDashboard,
        loadRecentScan,
        detonate,
        reset,
        availableModels,
        selectedModelId,
        setSelectedModelId,
        staticScanStatus,
        staticResults,
        runStaticScan,
        currentFile,
        jobId,
      }}
    >
      {children}
    </DetonationContext.Provider>
  );
};

export const useDetonation = () => {
  const context = useContext(DetonationContext);
  if (context === undefined) {
    throw new Error('useDetonation must be used within a DetonationProvider');
  }
  return context;
};

