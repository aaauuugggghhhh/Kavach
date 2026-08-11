import React, { useState, useRef } from 'react';
import { useDetonation } from '@/context/DetonationContext';
import { UploadCloud, Cpu } from 'lucide-react';

interface UploadPanelProps {
  mode?: 'dynamic' | 'static';
}

export const UploadPanel: React.FC<UploadPanelProps> = ({ mode = 'dynamic' }) => {
  const { detonate, runStaticScan, availableModels, selectedModelId, setSelectedModelId } = useDetonation();
  const [isDragOver, setIsDragOver] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

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
            : 'Upload an Android APK to analyze code behaviors, instrumentation logs, and kernel sockets in real time.'}
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

      {/* Drag & Drop Card (Obsidian glass-morphism style) */}
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

