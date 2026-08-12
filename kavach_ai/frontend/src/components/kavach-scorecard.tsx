import React, { useState, useEffect, useMemo } from 'react';
import { useDetonation } from '@/context/DetonationContext';
import { 
  ShieldAlert, Eye, ArrowLeft, Download, Printer, Search
} from 'lucide-react';

export interface FindingItem {
  id: string;
  title: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
  category: 'Runtime Security' | 'Network Privacy' | 'Data Storage' | 'Static Code' | 'System Integrity';
  isPrivacy: boolean;
  description: string;
  evidence: string;
}

export const KavachScorecard: React.FC = () => {
  const { telemetry, staticResults, apkDetails, viewDashboard, loadRecentScan, simulationMode } = useDetonation();
  const [filterSeverity, setFilterSeverity] = useState<string>('All');
  const [searchQuery, setSearchQuery] = useState<string>('');

  useEffect(() => {
    if (!telemetry && !staticResults) {
      loadRecentScan();
    }
  }, [telemetry, staticResults, loadRecentScan]);

  const { securityScore, grade, riskRating, privacyRiskScore, privacyRiskLevel, findings } = useMemo(() => {
    const objectionRoot = telemetry?.objection_root_bypass || false;
    const objectionSsl = telemetry?.objection_ssl_pinning_bypass || false;
    const filesAccessed = telemetry?.ebpf_telemetry?.files_accessed || [];
    const networkConns = telemetry?.ebpf_telemetry?.network_connections || [];
    const syscalls = telemetry?.ebpf_telemetry?.syscalls || [];

    const mlVerdict = staticResults?.ml_metrics?.verdict || 'BENIGN';
    const mlProb = staticResults?.ml_metrics?.malicious_probability || 0;
    const abusedCombinations = staticResults?.triage?.permission_combinations || [];
    const permissionsList = staticResults?.triage?.permissions || [];

    // Compute Security Score (0 to 100)
    let penalty = 0;
    
    // Dynamic Penalties
    if (objectionRoot) penalty += 30;
    if (objectionSsl) penalty += 25;
    
    filesAccessed.forEach((f: string) => {
      if (f.includes('app_process') || f.includes('system') || f.includes('su')) {
        penalty += 15;
      } else if (f.includes('/proc/')) {
        penalty += 5;
      }
    });

    networkConns.forEach((c: any) => {
      if (c.port === 4444) {
        penalty += 35;
      } else if (![80, 443, 8080, 53].includes(c.port)) {
        penalty += 5;
      }
    });

    if (syscalls.includes('sys_execve') && objectionRoot) {
      penalty += 10;
    }

    // Static Penalties
    if (mlProb > 0.8) penalty += 35;
    else if (mlProb > 0.5) penalty += 20;

    penalty += abusedCombinations.length * 10;

    // Base score calculation
    const rawScore = penalty === 0 ? 100 : Math.max(12, Math.min(98, 100 - penalty));
    const finalSecurityScore = (telemetry || staticResults) ? rawScore : 38;

    // Calculate Risk Rating & Letter Grade
    let currentRiskRating: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'SECURE' = 'SECURE';
    let currentGrade: 'A' | 'B' | 'C' | 'D' | 'F' = 'A';

    if (finalSecurityScore < 40) {
      currentRiskRating = 'CRITICAL';
      currentGrade = 'F';
    } else if (finalSecurityScore < 60) {
      currentRiskRating = 'HIGH';
      currentGrade = 'D';
    } else if (finalSecurityScore < 75) {
      currentRiskRating = 'MEDIUM';
      currentGrade = 'C';
    } else if (finalSecurityScore < 90) {
      currentRiskRating = 'LOW';
      currentGrade = 'B';
    }

    // Calculate Privacy Risk Score (0 to 100)
    let privacyPenalty = simulationMode ? 20 : 0;
    filesAccessed.forEach((f: string) => {
      if (f.includes('shared_prefs') || f.includes('config') || f.includes('user')) privacyPenalty += 25;
    });
    if (networkConns.length > 0) privacyPenalty += 20;
    if (objectionSsl) privacyPenalty += 25;

    // Static Privacy Penalties
    const dangerousPerms = ['READ_SMS', 'SEND_SMS', 'RECORD_AUDIO', 'CAMERA', 'READ_CONTACTS', 'ACCESS_FINE_LOCATION'];
    permissionsList.forEach((perm: string) => {
      if (dangerousPerms.some(dp => perm.includes(dp))) {
        privacyPenalty += 15;
      }
    });

    const finalPrivacyRiskScore = Math.min(100, Math.max(0, privacyPenalty));
    const finalPrivacyRiskLevel = finalPrivacyRiskScore > 75 ? 'CRITICAL' : finalPrivacyRiskScore > 50 ? 'HIGH' : finalPrivacyRiskScore > 25 ? 'MEDIUM' : 'LOW';

    // Construct Findings List
    const fList: FindingItem[] = [];

    // --- Dynamic Findings ---
    if (objectionRoot) {
      fList.push({
        id: 'KAV-DYN-01',
        title: 'Frida Dynamic Root Bypass Hook Executed',
        severity: 'Critical',
        category: 'Runtime Security',
        isPrivacy: false,
        description: 'The application contains insufficient tamper protection and allowed automated root detection bypass routines during instrumentation.',
        evidence: 'Frida hooking script injected into app_process runtime.'
      });
    }

    if (objectionSsl) {
      fList.push({
        id: 'KAV-DYN-02',
        title: 'SSL/TLS Certificate Pinning Defeated',
        severity: 'Critical',
        category: 'Network Privacy',
        isPrivacy: true,
        description: 'SSL Pinning was dynamically disabled using Objection runtime hooks, exposing encrypted socket communications.',
        evidence: 'TrustManager and NetworkSecurityConfig overridden.'
      });
    }

    networkConns.forEach((c: any, idx: number) => {
      if (c.port === 4444) {
        fList.push({
          id: `KAV-NET-${idx}`,
          title: `Active Reverse Shell / Non-Standard C2 Port Connection (${c.ip}:${c.port})`,
          severity: 'Critical',
          category: 'Network Privacy',
          isPrivacy: true,
          description: `Outbound ${c.protocol} socket established to non-standard remote port ${c.port} at ${c.ip}.`,
          evidence: `eBPF sys_connect log: Outbound ${c.protocol} connection to ${c.ip}:${c.port}`
        });
      }
    });

    // --- Static Findings ---
    if (mlProb > 0.8) {
      fList.push({
        id: 'KAV-STAT-01',
        title: `Malicious Code Segments Detected (Prob: ${(mlProb * 100).toFixed(1)}%)`,
        severity: 'Critical',
        category: 'Static Code',
        isPrivacy: false,
        description: 'SecureBERT identified highly malicious bytecode segments typical of banking trojans or spyware.',
        evidence: `ML Verdict: ${mlVerdict} with high confidence.`
      });
    }

    abusedCombinations.forEach((combo: string, idx: number) => {
      fList.push({
        id: `KAV-PERM-${idx}`,
        title: `Suspicious Permission Combination: ${combo}`,
        severity: 'High',
        category: 'Static Code',
        isPrivacy: true,
        description: 'Application requests a combination of permissions often abused for data exfiltration or device takeover.',
        evidence: `Static manifest analysis found ${combo}.`
      });
    });

    if (fList.length === 0) {
      fList.push({
        id: 'KAV-INFO-00',
        title: 'No Critical Threats Detected',
        severity: 'Info',
        category: 'System Integrity',
        isPrivacy: false,
        description: 'The holistic static and dynamic scan revealed no critical anomalies.',
        evidence: 'Both SecureBERT inference and eBPF runtime hooks reported clean.'
      });
    }

    return {
      securityScore: finalSecurityScore,
      grade: currentGrade,
      riskRating: currentRiskRating,
      privacyRiskScore: finalPrivacyRiskScore,
      privacyRiskLevel: finalPrivacyRiskLevel,
      findings: fList
    };
  }, [telemetry, staticResults, simulationMode]);

  const filteredFindings = useMemo(() => {
    return findings.filter(f => {
      const matchesSeverity = filterSeverity === 'All' || 
                              (filterSeverity === 'Privacy' ? f.isPrivacy : f.severity === filterSeverity);
      const matchesSearch = f.title.toLowerCase().includes(searchQuery.toLowerCase()) || 
                            f.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
                            f.category.toLowerCase().includes(searchQuery.toLowerCase());
      return matchesSeverity && matchesSearch;
    });
  }, [findings, filterSeverity, searchQuery]);

  const handlePrint = () => window.print();

  const handleExportJson = () => {
    const exportData = { scorecard: { securityScore, grade, riskRating, privacyRiskScore, findings } };
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(exportData, null, 2));
    const anchor = document.createElement('a');
    anchor.setAttribute("href", dataStr);
    anchor.setAttribute("download", `kavach_scorecard_${apkDetails?.package || 'app'}.json`);
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
  };

  const scoreColor = 
    securityScore < 40 ? 'text-destructive border-destructive shadow-[0_0_15px_rgba(239,68,68,0.3)]' :
    securityScore < 70 ? 'text-orange-500 border-orange-500 shadow-[0_0_15px_rgba(249,115,22,0.3)]' :
    'text-emerald-400 border-emerald-400 shadow-[0_0_15px_rgba(52,211,153,0.3)]';

  return (
    <div className="space-y-6 pb-12 animate-in fade-in zoom-in-95 duration-300">
      {/* Header */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 pb-4 border-b border-border">
        <div>
          <button 
            onClick={viewDashboard}
            className="flex items-center gap-1.5 text-xs font-semibold text-muted-foreground hover:text-foreground transition-all mb-2 cursor-pointer"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            Back to Dashboard
          </button>
          <div className="flex items-center gap-3">
            <h2 className="text-2xl font-extrabold tracking-tight text-foreground flex items-center gap-2">
              Holistic Security & Privacy Scorecard
            </h2>
            <span className="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 border border-primary/40 text-primary bg-primary/10 rounded-none shadow-[0_0_8px_rgba(59,130,246,0.3)]">
              Certified Audit
            </span>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button 
            onClick={handleExportJson}
            className="flex items-center gap-2 px-3.5 py-1.5 bg-muted hover:bg-muted/80 border border-border text-foreground text-xs font-semibold transition-all cursor-pointer rounded-none"
          >
            <Download className="w-3.5 h-3.5" />
            Export JSON
          </button>
          <button 
            onClick={handlePrint}
            className="flex items-center gap-2 px-4 py-1.5 bg-primary hover:bg-primary/90 text-primary-foreground text-xs font-bold transition-all cursor-pointer rounded-none shadow-[0_0_10px_rgba(59,130,246,0.4)]"
          >
            <Printer className="w-3.5 h-3.5" />
            Print Report
          </button>
        </div>
      </div>

      {/* Top Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        
        {/* Security Score */}
        <div className="p-6 border border-border bg-card/60 backdrop-blur-md flex flex-col justify-between relative overflow-hidden transition-all hover:bg-card/80">
          <div className="flex justify-between items-start">
            <div>
              <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-widest block">Overall Security Score</span>
              <span className="text-xs text-muted-foreground">Static & Dynamic Fusion</span>
            </div>
            <span className={`text-xs font-bold px-2 py-0.5 border bg-background/50 rounded-none ${scoreColor}`}>
              GRADE {grade}
            </span>
          </div>

          <div className="flex items-center gap-6 my-6">
            <div className="relative w-24 h-24 flex items-center justify-center">
              <svg className="w-full h-full transform -rotate-90 drop-shadow-md" viewBox="0 0 36 36">
                <path className="text-muted" strokeWidth="2" stroke="currentColor" fill="none" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" />
                <path 
                  className={securityScore < 50 ? 'text-destructive' : securityScore < 75 ? 'text-orange-500' : 'text-emerald-400'}
                  strokeDasharray={`${securityScore}, 100`} 
                  strokeWidth="2.5" stroke="currentColor" fill="none" 
                  d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" 
                />
              </svg>
              <div className="absolute flex flex-col items-center">
                <span className="text-3xl font-black text-foreground">{securityScore}</span>
              </div>
            </div>
            <div className="space-y-1">
              <div className="text-sm font-bold text-foreground">
                {securityScore < 50 ? 'Severe Vulnerabilities' : securityScore < 75 ? 'Moderate Exposure' : 'Strong Security Posture'}
              </div>
              <p className="text-[11px] text-muted-foreground leading-relaxed">
                Aggregated from SecureBERT ML static inference and eBPF dynamic telemetry hooks.
              </p>
            </div>
          </div>
        </div>

        {/* Risk Rating */}
        <div className="p-6 border border-border bg-card/60 backdrop-blur-md flex flex-col justify-between transition-all hover:bg-card/80">
          <div className="flex justify-between items-start">
            <div>
              <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-widest block">Threat Risk Rating</span>
              <span className="text-xs text-muted-foreground">Exploitability Assessment</span>
            </div>
            <ShieldAlert className={`w-5 h-5 ${riskRating === 'CRITICAL' ? 'text-destructive' : riskRating === 'HIGH' ? 'text-orange-500' : 'text-emerald-400'}`} />
          </div>

          <div className="my-6">
            <div className={`text-4xl font-black tracking-tight mb-4 ${
              riskRating === 'CRITICAL' ? 'text-destructive drop-shadow-[0_0_8px_rgba(239,68,68,0.5)]' : 
              riskRating === 'HIGH' ? 'text-orange-500 drop-shadow-[0_0_8px_rgba(249,115,22,0.5)]' : 
              'text-emerald-400 drop-shadow-[0_0_8px_rgba(52,211,153,0.5)]'
            }`}>
              {riskRating} RISK
            </div>
            <div className="space-y-2 text-[11px] uppercase tracking-wider font-bold text-muted-foreground">
              <div className="flex items-center justify-between border-b border-border/50 pb-1">
                <span>Code Toxicity:</span>
                <span className="text-foreground">{staticResults ? 'Analyzed' : 'Pending'}</span>
              </div>
              <div className="flex items-center justify-between border-b border-border/50 pb-1">
                <span>Runtime Hooks:</span>
                <span className="text-foreground">{telemetry ? 'Traced' : 'Pending'}</span>
              </div>
            </div>
          </div>
        </div>

        {/* Privacy Risk */}
        <div className="p-6 border border-border bg-card/60 backdrop-blur-md flex flex-col justify-between transition-all hover:bg-card/80">
          <div className="flex justify-between items-start">
            <div>
              <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-widest block">Privacy Exposure</span>
              <span className="text-xs text-muted-foreground">Data Harvesting Potential</span>
            </div>
            <Eye className="w-5 h-5 text-purple-400" />
          </div>

          <div className="my-6">
            <div className="flex items-baseline gap-2 mb-4">
              <span className="text-4xl font-black text-purple-400 drop-shadow-[0_0_8px_rgba(192,132,252,0.5)]">{privacyRiskScore}%</span>
            </div>

            <div className="space-y-3">
              <div>
                <div className="flex justify-between text-[10px] uppercase font-bold text-muted-foreground mb-1">
                  <span>Exposure Level</span>
                  <span className="text-foreground">{privacyRiskLevel}</span>
                </div>
                <div className="w-full bg-muted h-1 overflow-hidden">
                  <div className="bg-gradient-to-r from-purple-500 to-fuchsia-500 h-1 transition-all" style={{ width: `${privacyRiskScore}%` }} />
                </div>
              </div>
            </div>
          </div>
        </div>

      </div>

      {/* Findings Panel */}
      <div className="border border-border bg-card/40 backdrop-blur-sm p-6">
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 mb-6">
          <div>
            <h3 className="text-lg font-bold text-foreground">Audit Findings log</h3>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <div className="flex border border-border bg-background p-0.5">
              {['All', 'Critical', 'High', 'Medium', 'Privacy'].map((sev) => (
                <button
                  key={sev}
                  onClick={() => setFilterSeverity(sev)}
                  className={`px-3 py-1 text-[10px] uppercase font-bold tracking-widest transition-all cursor-pointer rounded-none ${
                    filterSeverity === sev ? 'bg-primary text-primary-foreground shadow-[0_0_10px_rgba(59,130,246,0.3)]' : 'text-muted-foreground hover:text-foreground hover:bg-muted'
                  }`}
                >
                  {sev}
                </button>
              ))}
            </div>
            <div className="relative">
              <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-muted-foreground" />
              <input
                type="text"
                placeholder="Search..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-48 pl-9 pr-3 py-1.5 bg-background border border-border text-[11px] text-foreground focus:outline-none focus:border-primary transition-all rounded-none"
              />
            </div>
          </div>
        </div>

        <div className="space-y-3">
          {filteredFindings.length === 0 ? (
            <div className="p-8 text-center text-muted-foreground text-[11px] uppercase font-bold tracking-widest border border-dashed border-border bg-background/50">
              No matching findings.
            </div>
          ) : (
            filteredFindings.map((item) => (
              <div key={item.id} className="border border-border p-4 bg-background/60 hover:bg-background/90 transition-all group backdrop-blur-md">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-border/40 pb-3">
                  <div className="flex items-center gap-3">
                    <span className="font-mono text-[10px] font-bold text-primary bg-primary/10 px-2 py-0.5 border border-primary/20">{item.id}</span>
                    <h4 className="text-sm font-semibold text-foreground group-hover:text-primary transition-colors">{item.title}</h4>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    {item.isPrivacy && (
                      <span className="text-[9px] font-bold uppercase tracking-wider px-2 py-0.5 border border-purple-500/30 text-purple-400 bg-purple-500/10">Privacy Risk</span>
                    )}
                    <span className={`text-[9px] font-bold uppercase tracking-wider px-2 py-0.5 border ${
                      item.severity === 'Critical' ? 'border-destructive/30 text-destructive bg-destructive/10' :
                      item.severity === 'High' ? 'border-orange-500/30 text-orange-400 bg-orange-500/10' :
                      item.severity === 'Medium' ? 'border-amber-500/30 text-amber-400 bg-amber-500/10' :
                      'border-blue-500/30 text-blue-400 bg-blue-500/10'
                    }`}>
                      {item.severity}
                    </span>
                  </div>
                </div>
                <p className="text-xs text-muted-foreground mt-3 leading-relaxed">
                  {item.description}
                </p>
                <div className="mt-3 bg-muted/30 border-l-2 border-border/80 p-3">
                  <span className="text-[9px] font-bold text-muted-foreground uppercase tracking-widest mb-1 block">Evidence</span>
                  <code className="text-[10px] font-mono text-emerald-400 break-all">{item.evidence}</code>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};

export default KavachScorecard;
