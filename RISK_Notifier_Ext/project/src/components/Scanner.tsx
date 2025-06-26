import React, { useState } from 'react';
import { Shield, Upload, Link, Hash, Globe } from 'lucide-react';
import { FileScanner } from './FileScanner';
import { UrlScanner } from './UrlScanner';
import { HashScanner } from './HashScanner';
import { DomainScanner } from './DomainScanner';
import { Results } from './Results';
import { ScanResult } from '../services/virusTotal';

type ScannerTab = 'file' | 'url' | 'hash' | 'domain';

export const Scanner: React.FC = () => {
  const [activeTab, setActiveTab] = useState<ScannerTab>('file');
  const [results, setResults] = useState<ScanResult[]>([]);
  const [isScanning, setIsScanning] = useState(false);

  const tabs = [
    { id: 'file' as ScannerTab, label: 'File Scan', icon: Upload },
    { id: 'url' as ScannerTab, label: 'URL Scan', icon: Link },
    { id: 'hash' as ScannerTab, label: 'Hash Lookup', icon: Hash },
    { id: 'domain' as ScannerTab, label: 'Domain/IP', icon: Globe }
  ];

  const handleScanComplete = (result: ScanResult) => {
    setResults(prev => [result, ...prev.slice(0, 9)]);
    setIsScanning(false);
  };

  const handleScanStart = () => {
    setIsScanning(true);
  };

  const handleScanError = () => {
    setIsScanning(false);
  };

  const renderScanner = () => {
    const props = {
      onScanStart: handleScanStart,
      onScanComplete: handleScanComplete,
      onScanError: handleScanError,
      isScanning
    };

    switch (activeTab) {
      case 'file':
        return <FileScanner {...props} />;
      case 'url':
        return <UrlScanner {...props} />;
      case 'hash':
        return <HashScanner {...props} />;
      case 'domain':
        return <DomainScanner {...props} />;
      default:
        return <FileScanner {...props} />;
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-red-900 to-slate-900">
      <div className="container mx-auto px-4 py-6 max-w-4xl">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="flex items-center justify-center mb-4">
            <div className="bg-gradient-to-r from-red-500 to-orange-500 p-3 rounded-full">
              <Shield className="w-8 h-8 text-white" />
            </div>
          </div>
          <h1 className="text-3xl font-bold text-white mb-2">
            Risk Notifier
          </h1>
          <p className="text-gray-300">
            Multi-source threat intelligence with real-time protection
          </p>
        </div>

        {/* Protection Status */}
        <div className="bg-gradient-to-r from-green-500/10 to-blue-500/10 border border-green-500/20 rounded-2xl p-4 mb-6">
          <div className="flex items-center justify-center space-x-3">
            <div className="w-3 h-3 bg-green-500 rounded-full animate-pulse"></div>
            <span className="text-green-300 font-medium">Real-time Protection Active</span>
          </div>
          <p className="text-center text-gray-400 text-sm mt-2">
            Pre-download scanning • URL protection • Multi-source intelligence
          </p>
        </div>

        {/* Tab Navigation */}
        <div className="bg-white/10 backdrop-blur-lg rounded-2xl p-1 mb-6 border border-white/20">
          <div className="grid grid-cols-4 gap-1">
            {tabs.map((tab) => {
              const Icon = tab.icon;
              const isActive = activeTab === tab.id;
              
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`relative px-4 py-3 rounded-xl text-sm font-medium transition-all duration-200 ${
                    isActive
                      ? 'bg-gradient-to-r from-red-600 to-orange-600 text-white shadow-lg'
                      : 'text-gray-300 hover:text-white hover:bg-white/10'
                  }`}
                >
                  <div className="flex flex-col items-center space-y-1">
                    <Icon className="w-5 h-5" />
                    <span className="hidden sm:block">{tab.label}</span>
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        {/* Scanner Content */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Scanner Panel */}
          <div className="lg:col-span-2">
            <div className="bg-white/10 backdrop-blur-lg rounded-2xl p-6 border border-white/20">
              {renderScanner()}
            </div>
          </div>

          {/* Results Panel */}
          <div className="lg:col-span-1">
            <Results results={results} />
          </div>
        </div>
      </div>
    </div>
  );
};