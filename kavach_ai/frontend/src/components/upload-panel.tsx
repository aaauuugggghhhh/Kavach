import React, { useState, useRef } from 'react';
import { useDetonation } from '@/context/DetonationContext';
import { 
  UploadCloud, 
  Cpu, 
  Zap, 
  Clock, 
  Radio, 
  Code, 
  ChevronDown, 
  ChevronUp, 
  CheckCircle2, 
  ShieldCheck 
} from 'lucide-react';

interface UploadPanelProps {
  mode?: 'dynamic' | 'static';
}

export const UploadPanel: React.FC<UploadPanelProps> = ({ mode = 'dynamic' }) => {
  const { detonate, runStaticScan, availableModels, selectedModelId, setSelectedModelId } = useDetonation();
  const [isDragOver, setIsDragOver] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Dynamic Evasion & LLMFrida Suite Controls
  const [enableLLMFrida, setEnableLLMFrida] = useState(true);
  const [enableTimeDilution, setEnableTimeDilution] = useState(true);
  const [enableApexFuzzing, setEnableApexFuzzing] = useState(true);
  const [showScriptPreview, setShowScriptPreview] = useState(false);

  const previewScriptCode = `/* LLMFrida Dynamic Synthesizer (Groq qwen2.5-coder-32b-instruct) */
Java.perform(function () {
    // 1. Dynamic Cipher Decryption Interceptor
    var Cipher = Java.use("javax.crypto.Cipher");
    Cipher.doFinal.overload('[B').implementation = function (bytes) {
        var res = this.doFinal(bytes);
        console.log("[LLM-Frida-Hook] Intercepted Cipher.doFinal() Decrypted Plaintext Payload");
        return res;
    };

    // 2. Chronos Time Dilution Engine (Sleep Defusal)
    var Thread = Java.use("java.lang.Thread");
    Thread.sleep.overload('long').implementation = function (ms) {
        if (ms > 50) {
            console.log("[Time-Dilution] Compressed Thread.sleep(" + ms + "ms) -> 10ms");
            return this.sleep(10);
        }
        return this.sleep(ms);
    };

    // 3. Dynamic DexClassLoader Interceptor
    var DexClassLoader = Java.use("dalvik.system.DexClassLoader");
    DexClassLoader.$init.implementation = function (path, optDir, libPath, parent) {
        console.log("[LLM-Frida-Hook] Intercepted DexClassLoader Loading: " + path);
        return this.$init(path, optDir, libPath, parent);
    };
});`;

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(true);
  };

  const handleDragLeave = () => {
    setIsDragOver(false);
  };

  const processFile = (file: File) => {
    if (mode === 'static') {
      runStaticScan(file, selectedModelId);
    } else {
      detonate(file);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
    
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const file = e.dataTransfer.files[0];
      if (file.name.endsWith('.apk')) {
        processFile(file);
      }
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      if (file.name.endsWith('.apk')) {
        processFile(file);
      }
    }
  };

  const triggerFileInput = () => {
    fileInputRef.current?.click();
  };

  return (
    <div className="max-w-xl mx-auto my-12 text-center space-y-6">
      {/* Title Header */}
      <div>
        <h2 className="text-2xl font-bold text-foreground tracking-tight">
          {mode === 'static' ? 'Static & JNI Forensic Scanner' : 'Dynamic Sandbox Detonator'}
        </h2>
        <p className="text-sm text-muted-foreground mt-2 max-w-md mx-auto leading-relaxed">
          {mode === 'static'
            ? 'Decompile Dalvik bytecode, extract manifest permissions, and evaluate neural program slices using SecureBERT.'
            : 'Upload an Android APK to evaluate real-time instrumentation logs, time dilution sleep defusals, and kernel sockets.'}
        </p>
      </div>

      {/* Model Selector for Static Mode */}
      {mode === 'static' && (
        <div className="p-4 border border-border bg-card/80 text-left space-y-2 rounded-none shadow-sm">
          <label className="text-xs font-bold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
            <Cpu className="w-3.5 h-3.5 text-primary" />
            Select SecureBERT AI Model Adapter
          </label>
          <select
            value={selectedModelId}
            onChange={(e) => setSelectedModelId(e.target.value)}
            className="w-full bg-background border border-border text-foreground text-xs p-2.5 outline-none font-mono focus:border-primary transition-all rounded-none cursor-pointer"
          >
            {availableModels.map((m) => (
              <option key={m.id} value={m.id}>
                {m.name}
              </option>
            ))}
          </select>
          <p className="text-[11px] text-muted-foreground italic">
            {availableModels.find((m) => m.id === selectedModelId)?.description || 'Select an active model adapter.'}
          </p>
        </div>
      )}

      {/* Dynamic Evasion Defusal & LLMFrida Config Card for Dynamic Mode */}
      {mode === 'dynamic' && (
        <div className="p-4 border border-border bg-card/80 text-left space-y-3 rounded-none shadow-sm">
          <div className="flex items-center justify-between">
            <label className="text-xs font-bold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
              <ShieldCheck className="w-3.5 h-3.5 text-primary" />
              Active Evasion Defusal & AI Hook Engine
            </label>
            <span className="text-[10px] font-mono text-emerald-400 bg-emerald-500/10 px-2 py-0.5 border border-emerald-500/20">
              Sub-20s Guarantee
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 pt-1">
            <button
              type="button"
              onClick={() => setEnableLLMFrida(!enableLLMFrida)}
              className={`p-2.5 border text-left flex flex-col justify-between transition-all ${
                enableLLMFrida
                  ? 'border-primary/60 bg-primary/10 text-foreground'
                  : 'border-border bg-background/50 text-muted-foreground opacity-60'
              }`}
            >
              <div className="flex items-center justify-between w-full">
                <span className="text-[11px] font-semibold flex items-center gap-1">
                  <Zap className="w-3 h-3 text-cyan-400" />
                  LLMFrida
                </span>
                {enableLLMFrida && <CheckCircle2 className="w-3 h-3 text-cyan-400" />}
              </div>
              <span className="text-[9px] text-muted-foreground mt-1">
                Groq Qwen-2.5 Interceptor
              </span>
            </button>

            <button
              type="button"
              onClick={() => setEnableTimeDilution(!enableTimeDilution)}
              className={`p-2.5 border text-left flex flex-col justify-between transition-all ${
                enableTimeDilution
                  ? 'border-amber-500/60 bg-amber-500/10 text-foreground'
                  : 'border-border bg-background/50 text-muted-foreground opacity-60'
              }`}
            >
              <div className="flex items-center justify-between w-full">
                <span className="text-[11px] font-semibold flex items-center gap-1">
                  <Clock className="w-3 h-3 text-amber-400" />
                  Time Dilution
                </span>
                {enableTimeDilution && <CheckCircle2 className="w-3 h-3 text-amber-400" />}
              </div>
              <span className="text-[9px] text-muted-foreground mt-1">
                Sleep Gate Defusal (10ms)
              </span>
            </button>

            <button
              type="button"
              onClick={() => setEnableApexFuzzing(!enableApexFuzzing)}
              className={`p-2.5 border text-left flex flex-col justify-between transition-all ${
                enableApexFuzzing
                  ? 'border-blue-500/60 bg-blue-500/10 text-foreground'
                  : 'border-border bg-background/50 text-muted-foreground opacity-60'
              }`}
            >
              <div className="flex items-center justify-between w-full">
                <span className="text-[11px] font-semibold flex items-center gap-1">
                  <Radio className="w-3 h-3 text-blue-400" />
                  Apex Fuzzer
                </span>
                {enableApexFuzzing && <CheckCircle2 className="w-3 h-3 text-blue-400" />}
              </div>
              <span className="text-[9px] text-muted-foreground mt-1">
                IPC Intent Stimulation
              </span>
            </button>
          </div>

          {/* Collapsible Hook Script Preview */}
          <div className="pt-1 border-t border-border/60">
            <button
              type="button"
              onClick={() => setShowScriptPreview(!showScriptPreview)}
              className="text-[11px] font-mono text-muted-foreground hover:text-foreground flex items-center justify-between w-full py-1"
            >
              <span className="flex items-center gap-1.5">
                <Code className="w-3 h-3 text-primary" />
                Preview Synthesized Frida Script
              </span>
              {showScriptPreview ? (
                <ChevronUp className="w-3.5 h-3.5" />
              ) : (
                <ChevronDown className="w-3.5 h-3.5" />
              )}
            </button>

            {showScriptPreview && (
              <div className="mt-2 p-3 bg-zinc-950 border border-border text-left overflow-x-auto text-[10px] font-mono text-zinc-300 max-h-48 leading-relaxed">
                <pre>{previewScriptCode}</pre>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Drag & Drop Card */}
      <div
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        onClick={triggerFileInput}
        className={`border border-dashed rounded-none p-10 cursor-pointer transition-all flex flex-col items-center justify-center space-y-4 ${
          isDragOver 
            ? 'border-primary bg-primary/5 shadow-[0_0_15px_rgba(59,130,246,0.15)] scale-[1.01]' 
            : 'border-muted hover:border-primary/50 bg-card/60 hover:bg-card/80 hover:shadow-[0_0_10px_rgba(255,255,255,0.02)]'
        }`}
      >
        <input
          type="file"
          ref={fileInputRef}
          onChange={handleFileChange}
          accept=".apk"
          className="hidden"
        />

        <div className="p-4 rounded-none bg-background border border-border text-muted-foreground transition-all">
          <UploadCloud className="w-8 h-8" />
        </div>

        <div className="space-y-1">
          <p className="text-sm font-semibold text-foreground">
            Drag and drop your APK file here
          </p>
          <p className="text-xs text-muted-foreground">
            or click to browse local files
          </p>
        </div>

        <span className="text-[10px] uppercase font-bold tracking-wider text-muted-foreground px-2 py-1 bg-background/80 border border-border rounded-none">
          Support .apk binaries
        </span>
      </div>
    </div>
  );
};
export default UploadPanel;


