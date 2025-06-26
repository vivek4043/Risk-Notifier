import React, { useState } from 'react';
import { ChevronDown, ChevronUp, Shield, AlertTriangle, X, Clock, ExternalLink } from 'lucide-react';
import { ScanResult } from '../services/virusTotal';

interface ResultsProps {
  results: ScanResult[];
}

export const Results: React.FC<ResultsProps> = ({ results }) => {
  const [expandedResult, setExpandedResult] = useState<string | null>(null);

  if (results.length === 0) {
    return (
      <div className="bg-white/10 backdrop-blur-lg rounded-2xl p-6 border border-white/20">
        <div className="text-center">
          <div className="bg-white/10 p-4 rounded-full w-16 h-16 mx-auto mb-4 flex items-center justify-center">
            <Clock className="w-8 h-8 text-gray-400" />
          </div>
          <h3 className="text-lg font-medium text-white mb-2">No Results Yet</h3>
          <p className="text-gray-400 text-sm">
            Scan results will appear here
          </p>
        </div>
      </div>
    );
  }

  const getStatusColor = (status: ScanResult['status']) => {
    switch (status) {
      case 'safe':
        return 'text-green-300 bg-green-500/20 border-green-500/30';
      case 'malicious':
        return 'text-red-300 bg-red-500/20 border-red-500/30';
      case 'suspicious':
        return 'text-amber-300 bg-amber-500/20 border-amber-500/30';
      case 'scanning':
        return 'text-blue-300 bg-blue-500/20 border-blue-500/30';
      default:
        return 'text-gray-300 bg-gray-500/20 border-gray-500/30';
    }
  };

  const getStatusIcon = (status: ScanResult['status']) => {
    switch (status) {
      case 'safe':
        return <Shield className="w-4 h-4" />;
      case 'malicious':
      case 'suspicious':
        return <AlertTriangle className="w-4 h-4" />;
      default:
        return <Clock className="w-4 h-4" />;
    }
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const toggleExpanded = (resultId: string) => {
    setExpandedResult(expandedResult === resultId ? null : resultId);
  };

  return (
    <div className="bg-white/10 backdrop-blur-lg rounded-2xl p-6 border border-white/20">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-medium text-white">Recent Scans</h3>
        <div className="text-sm text-gray-400">
          {results.length} result{results.length !== 1 ? 's' : ''}
        </div>
      </div>

      <div className="space-y-3 max-h-96 overflow-y-auto">
        {results.map((result) => (
          <div
            key={result.id}
            className="bg-white/5 rounded-lg border border-white/10 overflow-hidden"
          >
            {/* Result Header */}
            <div className="p-4">
              <div className="flex items-start justify-between mb-3">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center space-x-2 mb-1">
                    <span className="text-xs font-medium text-gray-400 uppercase">
                      {result.type}
                    </span>
                    <div className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium border ${getStatusColor(result.status)}`}>
                      {getStatusIcon(result.status)}
                      <span className="ml-1 capitalize">{result.status}</span>
                    </div>
                  </div>
                  
                  <p className="text-white font-medium text-sm truncate mb-1">
                    {result.resource}
                  </p>
                  
                  <div className="flex items-center space-x-4 text-xs text-gray-400">
                    <span>
                      {result.detections}/{result.totalEngines} detections
                    </span>
                    <span>{formatDate(result.scanDate)}</span>
                  </div>
                </div>

                <button
                  onClick={() => toggleExpanded(result.id)}
                  className="p-1 hover:bg-white/10 rounded transition-colors ml-2"
                >
                  {expandedResult === result.id ? (
                    <ChevronUp className="w-4 h-4 text-gray-400" />
                  ) : (
                    <ChevronDown className="w-4 h-4 text-gray-400" />
                  )}
                </button>
              </div>

              {/* Detection Bar */}
              <div className="w-full bg-white/10 rounded-full h-2">
                <div
                  className={`h-full rounded-full transition-all ${
                    result.status === 'malicious'
                      ? 'bg-red-500'
                      : result.status === 'suspicious'
                      ? 'bg-amber-500'
                      : 'bg-green-500'
                  }`}
                  style={{
                    width: result.totalEngines > 0 
                      ? `${Math.max(5, (result.detections / result.totalEngines) * 100)}%`
                      : '0%'
                  }}
                />
              </div>
            </div>

            {/* Expanded Details */}
            {expandedResult === result.id && (
              <div className="border-t border-white/10 p-4 space-y-4">
                {/* Metadata */}
                {result.metadata && (
                  <div className="grid grid-cols-2 gap-3 text-xs">
                    {result.metadata.md5 && (
                      <div>
                        <span className="text-gray-400">MD5:</span>
                        <p className="text-white font-mono mt-1 break-all">
                          {result.metadata.md5}
                        </p>
                      </div>
                    )}
                    {result.metadata.fileSize && (
                      <div>
                        <span className="text-gray-400">Size:</span>
                        <p className="text-white mt-1">
                          {(result.metadata.fileSize / 1024).toFixed(1)} KB
                        </p>
                      </div>
                    )}
                  </div>
                )}

                {/* Top Detections */}
                {result.engines.length > 0 && (
                  <div>
                    <h4 className="text-sm font-medium text-white mb-2">
                      Engine Results ({result.engines.filter(e => e.result !== 'Clean').length} flagged)
                    </h4>
                    <div className="space-y-1 max-h-32 overflow-y-auto">
                      {result.engines
                        .filter(engine => engine.result !== 'Clean')
                        .slice(0, 5)
                        .map((engine, index) => (
                        <div
                          key={index}
                          className="flex items-center justify-between p-2 bg-white/5 rounded text-xs"
                        >
                          <span className="text-white font-medium">
                            {engine.engine}
                          </span>
                          <span className="text-red-300">
                            {engine.result}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* External Link */}
                {result.permalink && (
                  <a
                    href={result.permalink}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center space-x-2 text-purple-300 hover:text-purple-200 text-sm transition-colors"
                  >
                    <ExternalLink className="w-4 h-4" />
                    <span>View Full Report</span>
                  </a>
                )}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
};