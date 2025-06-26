// Content script for real-time protection
// Cross-platform compatibility for Chrome, Firefox, Edge, Brave

(function() {
  'use strict';
  
  // Cross-browser compatibility
  const browser = globalThis.browser || globalThis.chrome;
  
  let isScanning = false;
  
  // Monitor download links
  document.addEventListener('click', async (event) => {
    const target = event.target.closest('a[href], button[onclick]');
    if (!target) return;
    
    const href = target.href || target.getAttribute('onclick');
    if (!href) return;
    
    // Check if this looks like a download link
    if (isDownloadLink(href)) {
      event.preventDefault();
      event.stopPropagation();
      
      if (isScanning) return;
      isScanning = true;
      
      try {
        // Show scanning indicator
        showScanningIndicator(target);
        
        // Scan the URL
        const result = await scanUrl(href);
        
        if (result.status === 'malicious' || result.status === 'suspicious') {
          showThreatWarning(target, result, href);
        } else {
          // Safe to proceed with download
          window.location.href = href;
        }
      } catch (error) {
        console.error('Scan failed:', error);
        // Proceed with download if scan fails
        window.location.href = href;
      } finally {
        isScanning = false;
        hideScanningIndicator();
      }
    }
  });
  
  function isDownloadLink(href) {
    const downloadExtensions = [
      '.exe', '.msi', '.dmg', '.pkg', '.deb', '.rpm',
      '.zip', '.rar', '.7z', '.tar', '.gz',
      '.apk', '.ipa', '.app'
    ];
    
    return downloadExtensions.some(ext => 
      href.toLowerCase().includes(ext) || 
      href.includes('download')
    );
  }
  
  async function scanUrl(url) {
    return new Promise((resolve, reject) => {
      if (browser && browser.runtime) {
        browser.runtime.sendMessage(
          { action: 'scanUrl', url: url },
          (response) => {
            if (browser.runtime.lastError) {
              reject(new Error(browser.runtime.lastError.message));
              return;
            }
            
            if (response && response.success) {
              resolve(response.result);
            } else {
              reject(new Error(response ? response.error : 'Unknown error'));
            }
          }
        );
      } else {
        reject(new Error('Browser runtime not available'));
      }
    });
  }
  
  function showScanningIndicator(element) {
    const indicator = document.createElement('div');
    indicator.id = 'risk-notifier-scanning-indicator';
    indicator.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      background: #4f46e5;
      color: white;
      padding: 12px 20px;
      border-radius: 8px;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      font-size: 14px;
      z-index: 999999;
      box-shadow: 0 10px 25px -3px rgba(0, 0, 0, 0.1);
      display: flex;
      align-items: center;
      gap: 8px;
    `;
    
    indicator.innerHTML = `
      <div style="
        width: 16px;
        height: 16px;
        border: 2px solid rgba(255, 255, 255, 0.3);
        border-top: 2px solid white;
        border-radius: 50%;
        animation: spin 1s linear infinite;
      "></div>
      Scanning for threats...
    `;
    
    // Add CSS animation
    const style = document.createElement('style');
    style.textContent = `
      @keyframes spin {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
      }
    `;
    document.head.appendChild(style);
    
    document.body.appendChild(indicator);
  }
  
  function hideScanningIndicator() {
    const indicator = document.getElementById('risk-notifier-scanning-indicator');
    if (indicator) {
      indicator.remove();
    }
  }
  
  function showThreatWarning(element, scanResult, originalUrl) {
    const overlay = document.createElement('div');
    overlay.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(0, 0, 0, 0.8);
      z-index: 999999;
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    `;
    
    const riskColor = scanResult.status === 'malicious' ? '#dc2626' : '#f59e0b';
    
    overlay.innerHTML = `
      <div style="
        background: white;
        padding: 2rem;
        border-radius: 1rem;
        max-width: 500px;
        text-align: center;
        box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
        margin: 20px;
      ">
        <div style="color: ${riskColor}; font-size: 3rem; margin-bottom: 1rem;">🛡️</div>
        <h2 style="color: ${riskColor}; margin: 0 0 1rem 0; font-size: 1.5rem; font-weight: 600;">
          Download Blocked
        </h2>
        <p style="color: #374151; margin: 0 0 1rem 0; line-height: 1.6;">
          This download has been flagged by <strong>${scanResult.detections}/${scanResult.totalEngines}</strong> 
          security engines as potentially dangerous.
        </p>
        <div style="
          background: #fef2f2;
          border: 1px solid #fecaca;
          border-radius: 0.5rem;
          padding: 1rem;
          margin: 1rem 0;
          font-size: 0.875rem;
          color: #991b1b;
        ">
          <strong>Risk Level:</strong> ${scanResult.status === 'malicious' ? 'High' : 'Medium'}
        </div>
        <div style="display: flex; gap: 1rem; justify-content: center; flex-wrap: wrap;">
          <button onclick="this.parentElement.parentElement.parentElement.remove()" style="
            background: #059669;
            color: white;
            border: none;
            padding: 0.75rem 1.5rem;
            border-radius: 0.5rem;
            font-weight: 500;
            cursor: pointer;
            font-size: 0.875rem;
          ">Cancel Download</button>
          <button onclick="window.location.href='${originalUrl}'; this.parentElement.parentElement.parentElement.remove();" style="
            background: ${riskColor};
            color: white;
            border: none;
            padding: 0.75rem 1.5rem;
            border-radius: 0.5rem;
            font-weight: 500;
            cursor: pointer;
            font-size: 0.875rem;
          ">Download Anyway</button>
        </div>
        <p style="color: #6b7280; font-size: 0.75rem; margin-top: 1rem;">
          Powered by Risk Notifier - Cross-platform security extension
        </p>
      </div>
    `;
    
    document.body.appendChild(overlay);
    
    // Auto-remove after 30 seconds
    setTimeout(() => {
      if (overlay.parentNode) {
        overlay.remove();
      }
    }, 30000);
  }
  
})();