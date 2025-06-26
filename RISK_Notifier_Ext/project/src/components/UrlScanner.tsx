import React, { useState } from 'react';
import { Link, Globe, AlertTriangle } from 'lucide-react';
import { virusTotalService, ScanResult } from '../services/virusTotal';

interface UrlScannerProps {
  onScanStart: () => void;
  onScanComplete: (result: ScanResult) => void;
  onScanError: () => void;
  isScanning: boolean;
}

export const UrlScanner: React.FC<UrlScannerProps> = ({
  onScanStart,
  onScanComplete,
  onScanError,
  isScanning
}) => {
  const [url, setUrl] = useState('');
  const [error, setError] = useState('');

  const isValidUrl = (urlString: string) => {
    try {
      new URL(urlString);
      return true;
    } catch {
      return false;
    }
  };

  const handleScan = async () => {
    if (!url.trim()) {
      setError('Please enter a URL');
      return;
    }

    let urlToScan = url.trim();
    
    // Add protocol if missing
    if (!urlToScan.startsWith('http://') && !urlToScan.startsWith('https://')) {
      urlToScan = 'https://' + urlToScan;
    }

    if (!isValidUrl(urlToScan)) {
      setError('Please enter a valid URL');
      return;
    }

    onScanStart();
    setError('');

    try {
      const result = await virusTotalService.scanUrl(urlToScan);
      onScanComplete(result);
      setUrl('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Scan failed');
      onScanError();
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !isScanning) {
      handleScan();
    }
  };

  return (
    <div className="space-y-6">
      <div className="text-center">
        <h2 className="text-xl font-semibold text-white mb-2">URL Scanner</h2>
        <p className="text-gray-300 text-sm">
          Scan URLs for malicious content and phishing attempts
        </p>
      </div>

      {/* URL Input */}
      <div className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">
            URL to scan
          </label>
          <div className="relative">
            <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
              <Globe className="w-5 h-5 text-gray-400" />
            </div>
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              onKeyPress={handleKeyPress}
              placeholder="example.com or https://example.com"
              className="w-full pl-10 pr-4 py-3 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent transition-all"
              disabled={isScanning}
            />
          </div>
        </div>

        {/* Demo URLs */}
        <div className="space-y-2">
          <p className="text-xs font-medium text-gray-400">Demo URLs (try these):</p>
          <div className="grid grid-cols-1 gap-2">
            {[
              { url: 'google.com', label: 'Safe URL - Google' },
              { url: 'malware-test.com', label: 'Test Malware Detection' },
              { url: 'phishing-example.com', label: 'Test Phishing Detection' },
              { url: 'github.com', label: 'Safe URL - GitHub' }
            ].map((example) => (
              <button
                key={example.url}
                onClick={() => setUrl(example.url)}
                disabled={isScanning}
                className="w-full text-left px-3 py-2 bg-white/5 hover:bg-white/10 text-gray-300 text-xs rounded-md transition-colors border border-white/10 flex justify-between items-center"
              >
                <span>{example.url}</span>
                <span className="text-gray-500 text-xs">{example.label}</span>
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Error Message */}
      {error && (
        <div className="bg-red-500/20 border border-red-500/30 rounded-lg p-4">
          <div className="flex items-center space-x-2">
            <AlertTriangle className="w-5 h-5 text-red-300 flex-shrink-0" />
            <p className="text-red-300 text-sm">{error}</p>
          </div>
        </div>
      )}

      {/* Scan Button */}
      <button
        onClick={handleScan}
        disabled={!url.trim() || isScanning}
        className="w-full bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-700 hover:to-blue-700 disabled:from-gray-600 disabled:to-gray-700 text-white font-medium py-3 px-4 rounded-lg transition-all flex items-center justify-center space-x-2"
      >
        {isScanning ? (
          <>
            <div className="animate-spin rounded-full h-5 w-5 border-2 border-white/30 border-t-white"></div>
            <span>Scanning...</span>
          </>
        ) : (
          <>
            <Link className="w-5 h-5" />
            <span>Scan URL</span>
          </>
        )}
      </button>
    </div>
  );
};