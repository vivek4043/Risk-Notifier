import React, { useCallback, useState } from 'react';
import { Upload, File, X, AlertTriangle } from 'lucide-react';
import { virusTotalService, ScanResult } from '../services/virusTotal';

interface FileScannerProps {
  onScanStart: () => void;
  onScanComplete: (result: ScanResult) => void;
  onScanError: () => void;
  isScanning: boolean;
}

export const FileScanner: React.FC<FileScannerProps> = ({
  onScanStart,
  onScanComplete,
  onScanError,
  isScanning
}) => {
  const [dragOver, setDragOver] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [error, setError] = useState('');

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    
    const files = Array.from(e.dataTransfer.files);
    if (files.length > 0) {
      const file = files[0];
      if (file.size > 32 * 1024 * 1024) { // 32MB limit
        setError('File size must be less than 32MB');
        return;
      }
      setSelectedFile(file);
      setError('');
    }
  }, []);

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (files && files.length > 0) {
      const file = files[0];
      if (file.size > 32 * 1024 * 1024) {
        setError('File size must be less than 32MB');
        return;
      }
      setSelectedFile(file);
      setError('');
    }
  };

  const handleScan = async () => {
    if (!selectedFile) return;

    onScanStart();
    setError('');

    try {
      const result = await virusTotalService.scanFile(selectedFile);
      onScanComplete(result);
      setSelectedFile(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Scan failed');
      onScanError();
    }
  };

  const clearFile = () => {
    setSelectedFile(null);
    setError('');
  };

  const formatFileSize = (bytes: number) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  return (
    <div className="space-y-6">
      <div className="text-center">
        <h2 className="text-xl font-semibold text-white mb-2">File Scanner</h2>
        <p className="text-gray-300 text-sm">
          Upload files to scan for malware and viruses
        </p>
      </div>

      {/* File Drop Zone */}
      <div
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        className={`relative border-2 border-dashed rounded-xl p-8 text-center transition-all ${
          dragOver
            ? 'border-purple-400 bg-purple-500/20'
            : 'border-white/30 hover:border-white/50'
        }`}
      >
        <input
          type="file"
          onChange={handleFileSelect}
          className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
          disabled={isScanning}
        />
        
        <div className="flex flex-col items-center space-y-4">
          <div className="bg-white/10 p-4 rounded-full">
            <Upload className="w-8 h-8 text-gray-300" />
          </div>
          
          <div>
            <p className="text-white font-medium mb-1">
              Drop your file here or click to browse
            </p>
            <p className="text-gray-400 text-sm">
              Maximum file size: 32MB
            </p>
          </div>
        </div>
      </div>

      {/* Selected File */}
      {selectedFile && (
        <div className="bg-white/5 rounded-lg p-4 border border-white/10">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="bg-blue-500/20 p-2 rounded-lg">
                <File className="w-5 h-5 text-blue-300" />
              </div>
              <div>
                <p className="text-white font-medium">{selectedFile.name}</p>
                <p className="text-gray-400 text-sm">
                  {formatFileSize(selectedFile.size)}
                </p>
              </div>
            </div>
            
            <button
              onClick={clearFile}
              className="p-2 hover:bg-white/10 rounded-lg transition-colors"
              disabled={isScanning}
            >
              <X className="w-5 h-5 text-gray-400" />
            </button>
          </div>
        </div>
      )}

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
        disabled={!selectedFile || isScanning}
        className="w-full bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-700 hover:to-blue-700 disabled:from-gray-600 disabled:to-gray-700 text-white font-medium py-3 px-4 rounded-lg transition-all flex items-center justify-center space-x-2"
      >
        {isScanning ? (
          <>
            <div className="animate-spin rounded-full h-5 w-5 border-2 border-white/30 border-t-white"></div>
            <span>Scanning...</span>
          </>
        ) : (
          <>
            <Upload className="w-5 h-5" />
            <span>Scan File</span>
          </>
        )}
      </button>
    </div>
  );
};