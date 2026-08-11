import React, { useEffect, useState } from 'react';
import { useDetonation } from '@/context/DetonationContext';
import { FileText, Download, ShieldAlert, Cpu, Activity, Lightbulb } from 'lucide-react';

export const KavachReportView: React.FC = () => {
  const { jobId } = useDetonation();
  const [reportData, setReportData] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (jobId) {
      setLoading(true);
      fetch(`/api/report/${jobId}`)
        .then(res => res.json())
        .then(data => {
          if (data.status === 'success') {
            setReportData(data.report);
          }
        })
        .finally(() => setLoading(false));
    }
  }, [jobId]);

  let executiveSummary = reportData?.executive_summary || reportData?.forensic?.summary;
  if (!executiveSummary && reportData?.contradiction_label) {
    executiveSummary = `Kavach AI completed the analysis. The threat verdict is classified as ${reportData.contradiction_label} with a final security risk score of ${reportData.final_score}/100.`;
  }

  // For static findings/narrative
  let staticNarrative = reportData?.static_analysis_narrative;
  if (!staticNarrative && reportData?.forensic?.static_findings) {
    staticNarrative = Array.isArray(reportData.forensic.static_findings)
      ? reportData.forensic.static_findings.join('\n')
      : reportData.forensic.static_findings;
  } else if (!staticNarrative && reportData?.static_evidence?.indicators) {
    staticNarrative = `Static indicators detected:\n` + reportData.static_evidence.indicators.map((ind: string) => `• ${ind}`).join('\n');
  }
  
  // For dynamic findings/narrative
  let behavioralNarrative = reportData?.behavioral_analysis_narrative;
  if (!behavioralNarrative && reportData?.forensic?.dynamic_findings) {
    behavioralNarrative = Array.isArray(reportData.forensic.dynamic_findings)
      ? reportData.forensic.dynamic_findings.join('\n')
      : reportData.forensic.dynamic_findings;
  } else if (!behavioralNarrative && reportData?.behavioral_fingerprint) {
    const bf = reportData.behavioral_fingerprint;
    const parts = [];
    if (bf.syscalls && bf.syscalls.length > 0) {
      parts.push(`Monitored system calls:\n${bf.syscalls.slice(0, 10).map((s: string) => `• ${s}`).join('\n')}`);
    }
    if (bf.ips && bf.ips.length > 0) {
      parts.push(`Observed connections to remote hosts:\n${bf.ips.map((ip: string) => `• ${ip}`).join('\n')}`);
    }
    if (bf.evasion_signals && bf.evasion_signals.length > 0) {
      parts.push(`Evasion mechanisms triggered:\n${bf.evasion_signals.map((es: string) => `• ${es}`).join('\n')}`);
    }
    behavioralNarrative = parts.length > 0 ? parts.join('\n\n') : undefined;
  }

  const remediationRecommendations = reportData?.remediation_recommendations || reportData?.cert_in?.recommended_mitigations;

  const mitreTactics = reportData?.cert_in?.mitre_attack_tactics || reportData?.mitre_attack_json?.tactics || [];
  const mitreTechniques = reportData?.cert_in?.mitre_attack_techniques || reportData?.mitre_attack_json?.techniques || [];

  const isPreliminary = reportData?.status === 'preliminary' || (!executiveSummary && !staticNarrative && !behavioralNarrative);

  if (!jobId) {
    return <div className="p-8 text-center text-muted-foreground">No Report Available (No Job ID)</div>;
  }

  if (loading) {
    return <div className="p-8 text-center text-muted-foreground">Generating Kavach AI Report...</div>;
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between border-b border-border pb-4">
        <h2 className="text-xl font-bold flex items-center gap-2">
          <FileText className="w-5 h-5 text-primary" />
          Generative AI Analysis Report
        </h2>
        <button className="flex items-center gap-2 px-3 py-1.5 bg-primary/10 hover:bg-primary/20 text-primary border border-primary/20 text-xs font-semibold transition-all">
          <Download className="w-4 h-4" />
          Export PDF
        </button>
      </div>
      {reportData ? (
        isPreliminary ? (
          <div className="border border-dashed border-border bg-card/30 p-8 text-center text-muted-foreground flex flex-col items-center justify-center space-y-4">
            <ShieldAlert className="w-12 h-12 text-primary/60 animate-pulse" />
            <div className="space-y-1">
              <h4 className="font-bold text-foreground">AI Forensic Report is Pending</h4>
              <p className="text-xs max-w-md">
                The generative analysis report has not been compiled yet. Please run a **Static Scan** or **Dynamic Sandbox Detonation** on your APK to generate the AI analysis report.
              </p>
            </div>
          </div>
        ) : (
          <div className="space-y-6">
            {executiveSummary && (
              <div className="border border-border bg-card/30 p-6 space-y-4">
                <h3 className="text-lg font-bold flex items-center gap-2 text-foreground"><ShieldAlert className="w-4 h-4 text-primary" /> Executive Summary</h3>
                <p className="text-sm text-muted-foreground leading-relaxed whitespace-pre-wrap">{executiveSummary}</p>
              </div>
            )}

            {(mitreTactics.length > 0 || mitreTechniques.length > 0) && (
              <div className="border border-border bg-card/30 p-6 space-y-4">
                <h3 className="text-lg font-bold flex items-center gap-2 text-foreground">🛡️ MITRE ATT&CK Mapping</h3>
                <div className="space-y-3 text-sm">
                  {mitreTactics.length > 0 && (
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-muted-foreground font-semibold text-xs uppercase tracking-wider w-24">Tactics:</span>
                      <div className="flex flex-wrap gap-2">
                        {mitreTactics.map((t: string, idx: number) => (
                          <span key={idx} className="bg-red-500/10 text-red-500 border border-red-500/20 px-2 py-0.5 text-xs font-mono font-bold">
                            {t}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                  {mitreTechniques.length > 0 && (
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-muted-foreground font-semibold text-xs uppercase tracking-wider w-24">Techniques:</span>
                      <div className="flex flex-wrap gap-2">
                        {mitreTechniques.map((t: string, idx: number) => (
                          <span key={idx} className="bg-amber-500/10 text-amber-500 border border-amber-500/20 px-2 py-0.5 text-xs font-mono font-bold">
                            {t}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}

            {staticNarrative && (
              <div className="border border-border bg-card/30 p-6 space-y-4">
                <h3 className="text-lg font-bold flex items-center gap-2 text-foreground"><Cpu className="w-4 h-4 text-primary" /> Static Analysis Narrative</h3>
                <p className="text-sm text-muted-foreground leading-relaxed whitespace-pre-wrap">{staticNarrative}</p>
              </div>
            )}
            {behavioralNarrative && (
              <div className="border border-border bg-card/30 p-6 space-y-4">
                <h3 className="text-lg font-bold flex items-center gap-2 text-foreground"><Activity className="w-4 h-4 text-primary" /> Behavioral Analysis Narrative</h3>
                <p className="text-sm text-muted-foreground leading-relaxed whitespace-pre-wrap">{behavioralNarrative}</p>
              </div>
            )}
            {remediationRecommendations && (
              <div className="border border-border bg-card/30 p-6 space-y-4">
                <h3 className="text-lg font-bold flex items-center gap-2 text-foreground"><Lightbulb className="w-4 h-4 text-primary" /> Remediation Recommendations</h3>
                <ul className="list-disc pl-5 text-sm text-muted-foreground space-y-1">
                  {Array.isArray(remediationRecommendations) 
                    ? remediationRecommendations.map((rec: string, i: number) => <li key={i}>{rec}</li>)
                    : <li className="whitespace-pre-wrap">{remediationRecommendations}</li>}
                </ul>
              </div>
            )}
          </div>
        )
      ) : (
        <div className="p-8 text-center text-muted-foreground">Report generation failed or no data returned.</div>
      )}
    </div>
  );
};
