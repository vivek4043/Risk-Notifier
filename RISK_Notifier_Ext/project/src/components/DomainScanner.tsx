import React, { useState } from 'react';
import { Globe, Wifi, AlertTriangle } from 'lucide-react';
import { virusTotalService, ScanResult } from '../services/virusTotal';

interface DomainScannerProps {
  onScanStart: () => void;
  onScanComplete: (result: ScanResult) => void;
  onScanError: () => void;
  isScanning: boolean;
}

export const DomainScanner: React.FC<DomainScannerProps> = ({
  onScanStart,
  onScanComplete,
  onScanError,
  isScanning
}) => {
  const [input, setInput] = useState('');
  const [scanType, setScanType] = useState<'domain' | 'ip'>('domain');
  const [error, setError] = useState('');

  const isValidDomain = (domain: string) => {
    const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9])*$/;
    return domainRegex.test(domain);
  };

  const isValidIP = (ip: string) => {
    const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
    return ipv4Regex.test(ip) || ipv6Regex.test(ip);
  };

  const detectInputType = (value: string) => {
    if (isValidIP(value)) return 'ip';
    if (isValidDomain(value)) return 'domain';
    return null;
  };

  const handleScan = async () => {
    if (!input.trim()) {
      setError('Please enter a domain or IP address');
      return;
    }

    const detectedType = detectInputType(input.trim());
    if (!detectedType) {
      setError('Please enter a valid domain or IP address');
      return;
    }

    onScanStart();
    setError('');

    try {
      let result: ScanResult;
      if (detectedType === 'domain') {
        result = await virusTotalService.getDomainReport(input.trim());
      } else {
        result = await virusTotalService.getIpReport(input.trim());
      }
      onScanComplete(result);
      setInput('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Analysis failed');
      onScanError();
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !isScanning) {
      handleScan();
    }
  };

  const detectedType = input.trim() ? detectInputType(input.trim()) : null;

  return (
    <div className="space-y-6">
      <div className="text-center">
        <h2 className="text-xl font-semibold text-white mb-2">Domain & IP Analysis</h2>
        <p className="text-gray-300 text-sm">
          Analyze domains and IP addresses for reputation and security threats
        </p>
      </div>

      {/* Input */}
      <div className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">
            Domain or IP Address
          </label>
          <div className="relative">
            <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
              {detectedType === 'ip' ? (
                <Wifi className="w-5 h-5 text-gray-400" />
              ) : (
                <Globe className="w-5 h-5 text-gray-400" />
              )}
            </div>
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyPress={handleKeyPress}
              placeholder="example.com or 8.8.8.8"
              className="w-full pl-10 pr-4 py-3 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent transition-all"
              disabled={isScanning}
            />
          </div>
          
          {/* Type Indicator */}
          {detectedType && (
            <div className="mt-2 flex items-center space-x-2">
              <div className="bg-blue-500/20 text-blue-300 px-2 py-1 rounded text-xs font-medium">
                {detectedType === 'ip' ? 'IP Address' : 'Domain'}
              </div>
            </div>
          )}
        </div>

        {/* Examples */}
        <div className="grid grid-cols-2 gap-4">
          <div className="space-y-2">
            <p className="text-xs font-medium text-gray-400">Domain examples:</p>
            <div className="space-y-1">
              {['google.com', 'github.com', 'malware-test.com'].map((domain) => (
                <button
                  key={domain}
                  onClick={() => setInput(domain)}
                  disabled={isScanning}
                  className="w-full text-left px-3 py-2 bg-white/5 hover:bg-white/10 text-gray-300 text-xs rounded-md transition-colors border border-white/10"
                >
                  {domain}
                </button>
              ))}
            </div>
          </div>
          
          <div className="space-y-2">
            <p className="text-xs font-medium text-gray-400">IP examples:</p>
            <div className="space-y-1">
              {['8.8.8.8', '1.1.1.1', '208.67.222.222'].map((ip) => (
                <button
                  key={ip}
                  onClick={() => setInput(ip)}
                  disabled={isScanning}
                  className="w-full text-left px-3 py-2 bg-white/5 hover:bg-white/10 text-gray-300 text-xs rounded-md transition-colors border border-white/10"
                >
                  {ip}
                </button>
              ))}
            </div>
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

      {/* Analyze Button */}
      <button
        onClick={handleScan}
        disabled={!input.trim() || isScanning}
        className="w-full bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-700 hover:to-blue-700 disabled:from-gray-600 disabled:to-gray-700 text-white font-medium py-3 px-4 rounded-lg transition-all flex items-center justify-center space-x-2"
      >
        {isScanning ? (
          <>
            <div className="animate-spin rounded-full h-5 w-5 border-2 border-white/30 border-t-white"></div>
            <span>Analyzing...</span>
          </>
        ) : (
          <>
            {detectedType === 'ip' ? (
              <Wifi className="w-5 h-5" />
            ) : (
              <Globe className="w-5 h-5" />
            )}
            <span>Analyze {detectedType === 'ip' ? 'IP' : 'Domain'}</span>
          </>
        )}
      </button>
    </div>
  );
};