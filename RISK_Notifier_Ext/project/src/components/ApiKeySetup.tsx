import React, { useState, useEffect } from 'react';
import { Shield, Save, ExternalLink, CheckCircle } from 'lucide-react';
import { virusTotalService } from '../services/virusTotal';

interface ApiKeySetupProps {
  onApiKeySet: () => void;
}

export const ApiKeySetup: React.FC<ApiKeySetupProps> = ({ onApiKeySet }) => {
  const [apiKey, setApiKey] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');

  // 🔒 HARDCODED API KEY - Replace with your actual API key
  const HARDCODED_API_KEY = 'YOUR_API_KEY_HERE'; // Replace this with your actual API key

  useEffect(() => {
    loadApiKey();
  }, []);

  const loadApiKey = async () => {
    // First try to use hardcoded API key
    if (HARDCODED_API_KEY && HARDCODED_API_KEY !== 'ce4b2bc95034d33a6fbb7a69fe82ce62e89aa3de60fadd25b893918683502f9a') {
      try {
        await virusTotalService.setApiKey(HARDCODED_API_KEY);
        onApiKeySet();
        return;
      } catch (error) {
        console.error('Failed to set hardcoded API key:', error);
      }
    }

    // Fallback to saved API key
    const savedApiKey = await virusTotalService.getApiKey();
    if (savedApiKey) {
      setApiKey(savedApiKey);
      onApiKeySet();
    }
  };

  const handleSave = async () => {
    if (!apiKey.trim()) {
      setError('Please enter a valid API key');
      return;
    }

    setIsLoading(true);
    setError('');

    try {
      await virusTotalService.setApiKey(apiKey.trim());
      onApiKeySet();
    } catch (err) {
      setError('Failed to save API key');
    } finally {
      setIsLoading(false);
    }
  };

  // If hardcoded API key is set, show auto-configuration message
  if (HARDCODED_API_KEY && HARDCODED_API_KEY !== 'YOUR_API_KEY_HERE') {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-red-900 to-slate-900 flex items-center justify-center p-4">
        <div className="bg-white/10 backdrop-blur-lg rounded-2xl p-8 w-full max-w-md border border-white/20 shadow-2xl">
          <div className="flex items-center justify-center mb-6">
            <div className="bg-green-500/20 p-3 rounded-full">
              <CheckCircle className="w-8 h-8 text-green-300" />
            </div>
          </div>
          
          <h1 className="text-2xl font-bold text-white text-center mb-2">
            Risk Notifier
          </h1>
          <p className="text-gray-300 text-center mb-6">
            API key configured automatically
          </p>

          <div className="bg-green-500/20 border border-green-500/30 rounded-lg p-4 mb-6">
            <div className="flex items-center space-x-3">
              <CheckCircle className="w-5 h-5 text-green-300 flex-shrink-0" />
              <div>
                <p className="text-green-300 text-sm font-medium mb-1">
                  Ready to Use
                </p>
                <p className="text-green-200 text-xs">
                  Your VirusTotal API key has been configured automatically. 
                  Risk Notifier is ready for real-time protection.
                </p>
              </div>
            </div>
          </div>

          <button
            onClick={onApiKeySet}
            className="w-full bg-gradient-to-r from-green-600 to-blue-600 hover:from-green-700 hover:to-blue-700 text-white font-medium py-3 px-4 rounded-lg transition-all flex items-center justify-center space-x-2"
          >
            <Shield className="w-5 h-5" />
            <span>Continue to Scanner</span>
          </button>

          {/* Feature Highlights */}
          <div className="bg-gradient-to-r from-red-500/10 to-orange-500/10 border border-red-500/20 rounded-lg p-4 mt-6">
            <h3 className="text-red-300 text-sm font-medium mb-2">🛡️ Active Protection Features</h3>
            <ul className="text-xs text-gray-300 space-y-1">
              <li>• Pre-download scanning and blocking</li>
              <li>• Multi-source threat intelligence</li>
              <li>• Real-time URL protection</li>
              <li>• HackerTarget subdomain analysis</li>
              <li>• Detailed security dashboard</li>
            </ul>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-red-900 to-slate-900 flex items-center justify-center p-4">
      <div className="bg-white/10 backdrop-blur-lg rounded-2xl p-8 w-full max-w-md border border-white/20 shadow-2xl">
        <div className="flex items-center justify-center mb-6">
          <div className="bg-red-500/20 p-3 rounded-full">
            <Shield className="w-8 h-8 text-red-300" />
          </div>
        </div>
        
        <h1 className="text-2xl font-bold text-white text-center mb-2">
          Risk Notifier
        </h1>
        <p className="text-gray-300 text-center mb-6">
          Enter your VirusTotal API key to enable real-time protection
        </p>

        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              API Key
            </label>
            <input
              type="password"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder="Enter your VirusTotal API key"
              className="w-full px-4 py-3 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-transparent transition-all"
            />
          </div>

          {error && (
            <div className="bg-red-500/20 border border-red-500/30 rounded-lg p-3">
              <p className="text-red-300 text-sm">{error}</p>
            </div>
          )}

          <button
            onClick={handleSave}
            disabled={isLoading}
            className="w-full bg-gradient-to-r from-red-600 to-orange-600 hover:from-red-700 hover:to-orange-700 disabled:from-gray-600 disabled:to-gray-700 text-white font-medium py-3 px-4 rounded-lg transition-all flex items-center justify-center space-x-2"
          >
            {isLoading ? (
              <div className="animate-spin rounded-full h-5 w-5 border-2 border-white/30 border-t-white"></div>
            ) : (
              <Save className="w-5 h-5" />
            )}
            <span>{isLoading ? 'Saving...' : 'Save API Key'}</span>
          </button>

          <div className="bg-blue-500/20 border border-blue-500/30 rounded-lg p-4">
            <div className="flex items-start space-x-3">
              <ExternalLink className="w-5 h-5 text-blue-300 mt-0.5 flex-shrink-0" />
              <div>
                <p className="text-blue-300 text-sm font-medium mb-1">
                  Need an API key?
                </p>
                <p className="text-blue-200 text-xs">
                  Get your free VirusTotal API key from their website. The free tier includes 4 requests per minute.
                </p>
                <a
                  href="https://www.virustotal.com/gui/my-apikey"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-blue-300 hover:text-blue-200 text-xs underline mt-1 inline-block"
                >
                  Get API Key →
                </a>
              </div>
            </div>
          </div>

          {/* Feature Highlights */}
          <div className="bg-gradient-to-r from-red-500/10 to-orange-500/10 border border-red-500/20 rounded-lg p-4">
            <h3 className="text-red-300 text-sm font-medium mb-2">🛡️ Risk Notifier Features</h3>
            <ul className="text-xs text-gray-300 space-y-1">
              <li>• Pre-download scanning and blocking</li>
              <li>• Multi-source threat intelligence</li>
              <li>• Real-time URL protection</li>
              <li>• HackerTarget subdomain analysis</li>
              <li>• Detailed security dashboard</li>
              <li>• User choice for risky downloads</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
};