import React, { useState, useEffect } from 'react';
import { ApiKeySetup } from './components/ApiKeySetup';
import { Scanner } from './components/Scanner';
import { virusTotalService } from './services/virusTotal';

function App() {
  const [hasApiKey, setHasApiKey] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    checkApiKey();
  }, []);

  const checkApiKey = async () => {
    try {
      const apiKey = await virusTotalService.getApiKey();
      setHasApiKey(!!apiKey);
    } catch (error) {
      console.error('Error checking API key:', error);
    } finally {
      setIsLoading(false);
    }
  };

  const handleApiKeySet = () => {
    setHasApiKey(true);
  };

  if (isLoading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-red-900 to-slate-900 flex items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-4 border-red-500/30 border-t-red-500"></div>
      </div>
    );
  }

  if (!hasApiKey) {
    return <ApiKeySetup onApiKeySet={handleApiKeySet} />;
  }

  return <Scanner />;
}

export default App;