import React, { useState } from 'react';
import { Hash, Search, AlertTriangle } from 'lucide-react';
import { virusTotalService, ScanResult } from '../services/virusTotal';

interface HashScannerProps {
  onScanStart: () => void;
  onScanComplete: (result: ScanResult) => void;
  onScanError: () => void;
  isScanning: boolean;
}

export const HashScanner: React.FC<HashScannerProps> = ({
  onScanStart,
  onScanComplete,
  onScanError,
  isScanning
}) => {
  const [hash, setHash] = useState('');
  const [error, setError] = useState('');

  const detectHashType = (hashString: string) => {
    const cleanHash = hashString.trim().toLowerCase();
    if (/^[a-f0-9]{32}$/i.test(cleanHash)) return 'MD5';
    if (/^[a-f0-9]{40}$/i.test(cleanHash)) return 'SHA-1';
    if (/^[a-f0-9]{64}$/i.test(cleanHash)) return 'SHA-256';
    return null;
  };

  const isValidHash = (hashString: string) => {
    return detectHashType(hashString) !== null;
  };

  const handleScan = async () => {
    if (!hash.trim()) {
      setError('Please enter a hash value');
      return;
    }

    if (!isValidHash(hash.trim())) {
      setError('Please enter a valid MD5, SHA-1, or SHA-256 hash');
      return;
    }

    onScanStart();
    setError('');

    try {
      const result = await virusTotalService.searchHash(hash.trim());
      onScanComplete(result);
      setHash('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Hash lookup failed');
      onScanError();
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !isScanning) {
      handleScan();
    }
  };

  const hashType = hash.trim() ? detectHashType(hash.trim()) : null;

  return (
    <div className="space-y-6">
      <div className="text-center">
        <h2 className="text-xl font-semibold text-white mb-2">Hash Lookup</h2>
        <p className="text-gray-300 text-sm">
          Search for MD5, SHA-1, or SHA-256 hashes in the VirusTotal database
        </p>
      </div>

      {/* Hash Input */}
      <div className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">
            File Hash
          </label>
          <div className="relative">
            <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
              <Hash className="w-5 h-5 text-gray-400" />
            </div>
            <input
              type="text"
              value={hash}
              onChange={(e) => setHash(e.target.value)}
              onKeyPress={handleKeyPress}
              placeholder="Enter MD5, SHA-1, or SHA-256 hash"
              className="w-full pl-10 pr-4 py-3 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent transition-all font-mono text-sm"
              disabled={isScanning}
            />
          </div>
          
          {/* Hash Type Indicator */}
          {hashType && (
            <div className="mt-2 flex items-center space-x-2">
              <div className="bg-green-500/20 text-green-300 px-2 py-1 rounded text-xs font-medium">
                {hashType} Hash
              </div>
            </div>
          )}
        </div>

        {/* Hash Examples */}
        <div className="space-y-2">
          <p className="text-xs font-medium text-gray-400">Hash examples:</p>
          <div className="space-y-1">
            {[
              { type: 'MD5', value: 'd41d8cd98f00b204e9800998ecf8427e' },
              { type: 'SHA-1', value: 'da39a3ee5e6b4b0d3255bfef95601890afd80709' },
              { type: 'SHA-256', value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' }
            ].map((example) => (
              <button
                key={example.type}
                onClick={() => setHash(example.value)}
                disabled={isScanning}
                className="w-full text-left px-3 py-2 bg-white/5 hover:bg-white/10 text-gray-300 text-xs rounded-md transition-colors border border-white/10 font-mono"
              >
                <span className="text-purple-300 font-medium">{example.type}:</span> {example.value}
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

      {/* Search Button */}
      <button
        onClick={handleScan}
        disabled={!hash.trim() || isScanning}
        className="w-full bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-700 hover:to-blue-700 disabled:from-gray-600 disabled:to-gray-700 text-white font-medium py-3 px-4 rounded-lg transition-all flex items-center justify-center space-x-2"
      >
        {isScanning ? (
          <>
            <div className="animate-spin rounded-full h-5 w-5 border-2 border-white/30 border-t-white"></div>
            <span>Searching...</span>
          </>
        ) : (
          <>
            <Search className="w-5 h-5" />
            <span>Lookup Hash</span>
          </>
        )}
      </button>
    </div>
  );
};