// Background script for Risk Notifier browser extension
// Cross-platform compatibility for Chrome, Firefox, Edge, Brave

// Cross-browser compatibility
const browser = globalThis.browser || globalThis.chrome;

// Initialize extension
browser.runtime.onInstalled.addListener(() => {
  console.log('Risk Notifier extension installed');
  
  // Set default settings
  browser.storage.sync.set({
    riskNotifierSettings: {
      enablePreDownloadScan: true,
      enableUrlScanning: true,
      enableSubdomainAnalysis: true,
      blockMaliciousDownloads: true,
      showDetailedAlerts: true
    }
  });
});

// Cross-browser download handling
if (browser.downloads && browser.downloads.onDeterminingFilename) {
  // Chrome/Edge implementation
  browser.downloads.onDeterminingFilename.addListener((downloadItem, suggest) => {
    handleDownloadDetermining(downloadItem, suggest);
  });
} else if (browser.downloads && browser.downloads.onCreated) {
  // Firefox fallback
  browser.downloads.onCreated.addListener((downloadItem) => {
    handleDownloadCreated(downloadItem);
  });
}

// Cross-browser navigation handling
if (browser.webNavigation && browser.webNavigation.onBeforeNavigate) {
  browser.webNavigation.onBeforeNavigate.addListener((details) => {
    if (details.frameId === 0) { // Main frame only
      scanUrlBeforeNavigation(details.url, details.tabId);
    }
  });
}

function handleDownloadDetermining(downloadItem, suggest) {
  if (shouldScanDownload(downloadItem)) {
    // BLOCK the download immediately for scanning
    browser.downloads.pause(downloadItem.id);
    
    // Scan the file BEFORE allowing download
    scanDownloadBeforeAllowing(downloadItem)
      .then((result) => {
        if (result.status === 'malicious' || result.status === 'suspicious') {
          showDetailedThreatAlert(downloadItem, result);
        } else {
          browser.downloads.resume(downloadItem.id);
          showSafeDownloadNotification(downloadItem);
        }
      })
      .catch((error) => {
        console.error('Pre-download scan failed:', error);
        showScanFailureAlert(downloadItem, error);
      });
  }
  
  if (suggest) suggest();
}

function handleDownloadCreated(downloadItem) {
  if (shouldScanDownload(downloadItem)) {
    // Firefox implementation - scan after creation
    scanDownloadBeforeAllowing(downloadItem)
      .then((result) => {
        if (result.status === 'malicious' || result.status === 'suspicious') {
          browser.downloads.cancel(downloadItem.id);
          showDetailedThreatAlert(downloadItem, result);
        } else {
          showSafeDownloadNotification(downloadItem);
        }
      })
      .catch((error) => {
        console.error('Download scan failed:', error);
        showScanFailureAlert(downloadItem, error);
      });
  }
}

function shouldScanDownload(downloadItem) {
  const dangerousExtensions = [
    '.exe', '.msi', '.dmg', '.pkg', '.deb', '.rpm', '.app',
    '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2',
    '.apk', '.ipa', '.jar', '.bat', '.cmd', '.scr',
    '.vbs', '.js', '.ps1', '.sh', '.com', '.pif'
  ];
  
  const maxSize = 100 * 1024 * 1024; // 100MB limit
  
  if (downloadItem.totalBytes > maxSize) {
    return false;
  }
  
  const extension = getFileExtension(downloadItem.filename);
  return dangerousExtensions.includes(extension.toLowerCase()) || 
         downloadItem.url.includes('download') ||
         downloadItem.mime?.includes('application');
}

function getFileExtension(filename) {
  return filename.substring(filename.lastIndexOf('.'));
}

async function scanDownloadBeforeAllowing(downloadItem) {
  try {
    const result = await browser.storage.sync.get(['vtApiKey', 'riskNotifierSettings']);
    const apiKey = result.vtApiKey;
    const settings = result.riskNotifierSettings || { enablePreDownloadScan: true };
    
    if (!apiKey || !settings.enablePreDownloadScan) {
      throw new Error('Pre-download scanning disabled or API key not found');
    }
    
    // Multi-source threat intelligence
    const scanResults = await Promise.allSettled([
      scanWithVirusTotal(downloadItem.url, apiKey),
      scanWithSubdomainIntelligence(downloadItem.url),
      scanWithUrlReputation(downloadItem.url)
    ]);
    
    return combineThreatIntelligence(scanResults, downloadItem);
  } catch (error) {
    console.error('Multi-source scan failed:', error);
    throw error;
  }
}

async function scanWithVirusTotal(url, apiKey) {
  const formData = new FormData();
  formData.append('apikey', apiKey);
  formData.append('url', url);
  
  try {
    const scanResponse = await fetch('https://www.virustotal.com/vtapi/v2/url/scan', {
      method: 'POST',
      body: formData
    });
    
    const scanData = await scanResponse.json();
    
    if (scanData.response_code === 1) {
      await new Promise(resolve => setTimeout(resolve, 3000));
      
      const reportFormData = new FormData();
      reportFormData.append('apikey', apiKey);
      reportFormData.append('resource', url);
      
      const reportResponse = await fetch('https://www.virustotal.com/vtapi/v2/url/report', {
        method: 'POST',
        body: reportFormData
      });
      
      const reportData = await reportResponse.json();
      return { source: 'VirusTotal', data: reportData };
    }
  } catch (error) {
    console.error('VirusTotal scan failed:', error);
  }
  
  return { source: 'VirusTotal', data: null };
}

async function scanWithSubdomainIntelligence(url) {
  try {
    const domain = new URL(url).hostname;
    console.log(`🔍 Scanning subdomains for: ${domain}`);
    
    const response = await fetch(`https://api.hackertarget.com/hostsearch/?q=${domain}`, {
      method: 'GET',
      headers: {
        'User-Agent': 'Risk-Notifier-Extension/1.0'
      }
    });
    
    if (!response.ok) {
      throw new Error(`HackerTarget API failed: ${response.status}`);
    }
    
    const subdomainData = await response.text();
    console.log(`📊 HackerTarget response for ${domain}:`, subdomainData);
    
    const subdomains = subdomainData
      .split('\n')
      .filter(line => line.trim() && !line.includes('error') && !line.includes('API count exceeded'))
      .map(line => line.trim());
    
    const suspiciousPatterns = [
      'admin', 'test', 'dev', 'staging', 'temp', 'backup', 'old', 'new',
      'beta', 'alpha', 'demo', 'sandbox', 'mail', 'ftp', 'ssh', 'vpn',
      'login', 'secure', 'private', 'internal', 'hidden', 'secret'
    ];
    
    const foundSuspiciousSubdomains = [];
    const foundPatterns = [];
    
    subdomains.forEach(subdomain => {
      suspiciousPatterns.forEach(pattern => {
        if (subdomain.toLowerCase().includes(pattern)) {
          foundSuspiciousSubdomains.push(subdomain);
          if (!foundPatterns.includes(pattern)) {
            foundPatterns.push(pattern);
          }
        }
      });
    });
    
    const isSuspicious = foundSuspiciousSubdomains.length > 0;
    const riskScore = Math.min(foundSuspiciousSubdomains.length * 10, 100);
    
    return {
      source: 'HackerTarget Subdomain Intelligence',
      data: {
        domain,
        totalSubdomains: subdomains.length,
        subdomains: subdomains.slice(0, 20),
        suspiciousSubdomains: foundSuspiciousSubdomains,
        suspiciousPatterns: foundPatterns,
        isSuspicious,
        riskScore,
        apiWorking: true,
        timestamp: new Date().toISOString()
      }
    };
  } catch (error) {
    console.error('❌ HackerTarget Subdomain Intelligence failed:', error);
    
    try {
      const domain = new URL(url).hostname;
      const suspiciousPatterns = ['malware', 'phishing', 'scam', 'fraud', 'fake', 'temp', 'test'];
      const foundPatterns = suspiciousPatterns.filter(pattern => 
        domain.toLowerCase().includes(pattern)
      );
      
      return {
        source: 'HackerTarget Subdomain Intelligence (Fallback)',
        data: {
          domain,
          totalSubdomains: 0,
          subdomains: [],
          suspiciousSubdomains: [],
          suspiciousPatterns: foundPatterns,
          isSuspicious: foundPatterns.length > 0,
          riskScore: foundPatterns.length * 20,
          apiWorking: false,
          error: error.message,
          timestamp: new Date().toISOString()
        }
      };
    } catch (fallbackError) {
      return { 
        source: 'HackerTarget Subdomain Intelligence', 
        data: null,
        error: fallbackError.message
      };
    }
  }
}

async function scanWithUrlReputation(url) {
  try {
    const domain = new URL(url).hostname;
    console.log(`🔍 Analyzing URL reputation for: ${domain}`);
    
    const checks = await Promise.allSettled([
      checkMaliciousDomainsList(domain),
      checkDomainAge(domain),
      checkSSLCertificate(url)
    ]);
    
    const results = {
      maliciousCheck: checks[0].status === 'fulfilled' ? checks[0].value : null,
      domainAge: checks[1].status === 'fulfilled' ? checks[1].value : null,
      sslCheck: checks[2].status === 'fulfilled' ? checks[2].value : null
    };
    
    return {
      source: 'URL Reputation Analysis',
      data: results
    };
  } catch (error) {
    console.error('❌ URL reputation check failed:', error);
    return { source: 'URL Reputation Analysis', data: null };
  }
}

async function checkMaliciousDomainsList(domain) {
  const maliciousPatterns = [
    'malware', 'phishing', 'scam', 'fraud', 'fake', 'suspicious',
    'temp', 'temporary', 'test', 'example', 'spam', 'virus',
    'trojan', 'worm', 'backdoor', 'keylogger', 'ransomware'
  ];
  
  const matchedPatterns = maliciousPatterns.filter(pattern => 
    domain.toLowerCase().includes(pattern)
  );
  
  return {
    isMalicious: matchedPatterns.length > 0,
    matchedPatterns,
    riskScore: matchedPatterns.length * 25
  };
}

async function checkDomainAge(domain) {
  const suspiciousIndicators = {
    isNewDomain: domain.includes('temp') || domain.includes('test'),
    hasNumbers: /\d/.test(domain),
    isShortDomain: domain.length < 6,
    hasHyphens: domain.includes('-'),
    hasMultipleHyphens: (domain.match(/-/g) || []).length > 2,
    isIPAddress: /^\d+\.\d+\.\d+\.\d+$/.test(domain),
    hasRandomPattern: /[a-z]{1}[0-9]{3,}/.test(domain)
  };
  
  const suspiciousCount = Object.values(suspiciousIndicators).filter(Boolean).length;
  
  return {
    ...suspiciousIndicators,
    suspiciousCount,
    riskScore: suspiciousCount * 15
  };
}

async function checkSSLCertificate(url) {
  return {
    hasSSL: url.startsWith('https://'),
    isSecure: url.startsWith('https://') && !url.includes('self-signed'),
    riskScore: url.startsWith('https://') ? 0 : 30
  };
}

function combineThreatIntelligence(scanResults, downloadItem) {
  let totalDetections = 0;
  let totalEngines = 0;
  let threatSources = [];
  let riskLevel = 'safe';
  let combinedRiskScore = 0;
  
  console.log('🔄 Combining threat intelligence from multiple sources...');
  
  scanResults.forEach((result, index) => {
    if (result.status === 'fulfilled' && result.value.data) {
      const source = result.value.source;
      const data = result.value.data;
      
      console.log(`📊 Processing ${source}:`, data);
      
      if (source === 'VirusTotal' && data.positives !== undefined) {
        totalDetections += data.positives || 0;
        totalEngines += data.total || 0;
        combinedRiskScore += (data.positives || 0) * 10;
        if (data.positives > 0) {
          threatSources.push(`${source}: ${data.positives}/${data.total} engines detected threats`);
        }
      }
      
      if (source.includes('Subdomain Intelligence')) {
        totalEngines += 1;
        if (data.isSuspicious) {
          totalDetections += 1;
          combinedRiskScore += data.riskScore || 20;
          threatSources.push(`${source}: Found ${data.suspiciousSubdomains?.length || 0} suspicious subdomains`);
        }
      }
      
      if (source === 'URL Reputation Analysis') {
        totalEngines += 1;
        let reputationThreats = [];
        
        if (data.maliciousCheck?.isMalicious) {
          totalDetections += 1;
          combinedRiskScore += data.maliciousCheck.riskScore || 25;
          reputationThreats.push(`malicious patterns detected`);
        }
        
        if (data.domainAge?.suspiciousCount > 2) {
          totalDetections += 1;
          combinedRiskScore += data.domainAge.riskScore || 15;
          reputationThreats.push(`suspicious domain characteristics`);
        }
        
        if (!data.sslCheck?.hasSSL) {
          combinedRiskScore += data.sslCheck?.riskScore || 30;
          reputationThreats.push(`no SSL certificate`);
        }
        
        if (reputationThreats.length > 0) {
          threatSources.push(`${source}: ${reputationThreats.join(', ')}`);
        }
      }
    }
  });
  
  if (combinedRiskScore === 0) {
    riskLevel = 'safe';
  } else if (combinedRiskScore >= 50) {
    riskLevel = 'malicious';
  } else if (combinedRiskScore >= 20) {
    riskLevel = 'suspicious';
  } else {
    riskLevel = 'low-risk';
  }
  
  const finalResult = {
    status: riskLevel,
    detections: totalDetections,
    totalEngines: Math.max(totalEngines, 1),
    threatSources,
    resource: downloadItem.url || downloadItem.filename,
    filename: downloadItem.filename,
    fileSize: downloadItem.totalBytes,
    combinedRiskScore,
    scanDate: new Date().toISOString()
  };
  
  console.log('✅ Final threat intelligence result:', finalResult);
  return finalResult;
}

function showDetailedThreatAlert(downloadItem, scanResult) {
  // Cross-browser notification
  if (browser.notifications) {
    browser.notifications.create({
      type: 'basic',
      iconUrl: 'icons/icon48.png',
      title: 'Risk Notifier - Threat Detected',
      message: `Download blocked: ${downloadItem.filename} flagged by ${scanResult.detections}/${scanResult.totalEngines} sources.`
    });
  }
  
  // Inject detailed dashboard
  browser.tabs.query({active: true, currentWindow: true}, (tabs) => {
    if (tabs[0]) {
      if (browser.scripting) {
        // Manifest V3 (Chrome/Edge)
        browser.scripting.executeScript({
          target: { tabId: tabs[0].id },
          function: injectDetailedThreatDashboard,
          args: [downloadItem, scanResult]
        });
      } else if (browser.tabs.executeScript) {
        // Manifest V2 fallback (Firefox)
        browser.tabs.executeScript(tabs[0].id, {
          code: `(${injectDetailedThreatDashboard.toString()})(${JSON.stringify(downloadItem)}, ${JSON.stringify(scanResult)})`
        });
      }
    }
  });
}

function injectDetailedThreatDashboard(downloadItem, scanResult) {
  const existingDashboard = document.getElementById('risk-notifier-dashboard');
  if (existingDashboard) {
    existingDashboard.remove();
  }
  
  const dashboard = document.createElement('div');
  dashboard.id = 'risk-notifier-dashboard';
  dashboard.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: rgba(0, 0, 0, 0.95);
    z-index: 999999;
    display: flex;
    align-items: center;
    justify-content: center;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    color: white;
  `;
  
  const riskColor = scanResult.status === 'malicious' ? '#dc2626' : '#f59e0b';
  const riskIcon = scanResult.status === 'malicious' ? '🚨' : '⚠️';
  
  dashboard.innerHTML = `
    <div style="
      background: linear-gradient(135deg, #1f2937 0%, #374151 100%);
      padding: 2rem;
      border-radius: 1rem;
      max-width: 600px;
      width: 90%;
      max-height: 80vh;
      overflow-y: auto;
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
      border: 1px solid rgba(255, 255, 255, 0.1);
    ">
      <div style="text-align: center; margin-bottom: 2rem;">
        <div style="font-size: 4rem; margin-bottom: 1rem;">${riskIcon}</div>
        <h1 style="color: ${riskColor}; margin: 0 0 0.5rem 0; font-size: 2rem; font-weight: 700;">
          Download Blocked
        </h1>
        <p style="color: #9ca3af; margin: 0; font-size: 1.1rem;">
          Risk Notifier has detected potential threats
        </p>
      </div>
      
      <div style="background: rgba(0, 0, 0, 0.3); padding: 1.5rem; border-radius: 0.75rem; margin-bottom: 2rem;">
        <h3 style="color: white; margin: 0 0 1rem 0; font-size: 1.2rem;">File Details</h3>
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; font-size: 0.9rem;">
          <div>
            <span style="color: #9ca3af;">Filename:</span>
            <p style="color: white; margin: 0.25rem 0 0 0; font-weight: 500; word-break: break-all;">
              ${scanResult.filename}
            </p>
          </div>
          <div>
            <span style="color: #9ca3af;">Size:</span>
            <p style="color: white; margin: 0.25rem 0 0 0; font-weight: 500;">
              ${(scanResult.fileSize / 1024 / 1024).toFixed(2)} MB
            </p>
          </div>
          <div style="grid-column: 1 / -1;">
            <span style="color: #9ca3af;">Source URL:</span>
            <p style="color: white; margin: 0.25rem 0 0 0; font-weight: 500; word-break: break-all;">
              ${scanResult.resource}
            </p>
          </div>
        </div>
      </div>
      
      <div style="background: rgba(220, 38, 38, 0.1); border: 1px solid rgba(220, 38, 38, 0.3); padding: 1.5rem; border-radius: 0.75rem; margin-bottom: 2rem;">
        <h3 style="color: ${riskColor}; margin: 0 0 1rem 0; font-size: 1.2rem;">Multi-Source Threat Analysis</h3>
        <div style="margin-bottom: 1rem;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
            <span style="color: #9ca3af;">Risk Level:</span>
            <span style="color: ${riskColor}; font-weight: 600; text-transform: uppercase;">
              ${scanResult.status}
            </span>
          </div>
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
            <span style="color: #9ca3af;">Detections:</span>
            <span style="color: white; font-weight: 600;">
              ${scanResult.detections}/${scanResult.totalEngines} sources
            </span>
          </div>
          <div style="display: flex; justify-content: space-between; align-items: center;">
            <span style="color: #9ca3af;">Risk Score:</span>
            <span style="color: ${riskColor}; font-weight: 600;">
              ${scanResult.combinedRiskScore || 0}/100
            </span>
          </div>
        </div>
        
        ${scanResult.threatSources.length > 0 ? `
          <div>
            <h4 style="color: white; margin: 0 0 0.75rem 0; font-size: 1rem;">Intelligence Sources:</h4>
            <ul style="margin: 0; padding-left: 1.5rem; color: #d1d5db; font-size: 0.85rem;">
              ${scanResult.threatSources.map(source => `<li style="margin-bottom: 0.5rem;">${source}</li>`).join('')}
            </ul>
          </div>
        ` : ''}
      </div>
      
      <div style="display: flex; gap: 1rem; justify-content: center; flex-wrap: wrap;">
        <button onclick="riskNotifierCancelDownload()" style="
          background: #059669;
          color: white;
          border: none;
          padding: 1rem 2rem;
          border-radius: 0.75rem;
          font-weight: 600;
          cursor: pointer;
          font-size: 1rem;
          transition: all 0.2s;
        ">
          🛡️ Cancel Download
        </button>
        <button onclick="riskNotifierProceedAnyway()" style="
          background: #dc2626;
          color: white;
          border: none;
          padding: 1rem 2rem;
          border-radius: 0.75rem;
          font-weight: 600;
          cursor: pointer;
          font-size: 1rem;
          transition: all 0.2s;
        ">
          ⚠️ Download at My Own Risk
        </button>
      </div>
      
      <p style="color: #6b7280; font-size: 0.8rem; text-align: center; margin-top: 1.5rem;">
        Powered by Risk Notifier - Cross-platform security extension
      </p>
    </div>
  `;
  
  window.riskNotifierCancelDownload = () => {
    if (typeof browser !== 'undefined' && browser.runtime) {
      browser.runtime.sendMessage({
        action: 'cancelDownload',
        downloadId: downloadItem.id
      });
    } else if (typeof chrome !== 'undefined' && chrome.runtime) {
      chrome.runtime.sendMessage({
        action: 'cancelDownload',
        downloadId: downloadItem.id
      });
    }
    dashboard.remove();
  };
  
  window.riskNotifierProceedAnyway = () => {
    if (typeof browser !== 'undefined' && browser.runtime) {
      browser.runtime.sendMessage({
        action: 'proceedWithDownload',
        downloadId: downloadItem.id
      });
    } else if (typeof chrome !== 'undefined' && chrome.runtime) {
      chrome.runtime.sendMessage({
        action: 'proceedWithDownload',
        downloadId: downloadItem.id
      });
    }
    dashboard.remove();
  };
  
  document.body.appendChild(dashboard);
}

function showSafeDownloadNotification(downloadItem) {
  if (browser.notifications) {
    browser.notifications.create({
      type: 'basic',
      iconUrl: 'icons/icon48.png',
      title: 'Risk Notifier - Download Safe',
      message: `${downloadItem.filename} has been scanned and is safe to download.`
    });
  }
}

function showScanFailureAlert(downloadItem, error) {
  if (browser.notifications) {
    browser.notifications.create({
      type: 'basic',
      iconUrl: 'icons/icon48.png',
      title: 'Risk Notifier - Scan Failed',
      message: `Unable to scan ${downloadItem.filename}. Proceed with caution.`
    });
  }
}

async function scanUrlBeforeNavigation(url, tabId) {
  try {
    const safeDomains = ['google.com', 'youtube.com', 'facebook.com', 'github.com', 'stackoverflow.com'];
    const domain = new URL(url).hostname;
    
    if (safeDomains.some(safeDomain => domain.includes(safeDomain))) {
      return;
    }
    
    const result = await browser.storage.sync.get(['vtApiKey', 'riskNotifierSettings']);
    const apiKey = result.vtApiKey;
    const settings = result.riskNotifierSettings || { enableUrlScanning: true };
    
    if (!apiKey || !settings.enableUrlScanning) return;
    
    const scanResults = await Promise.allSettled([
      scanWithVirusTotal(url, apiKey),
      scanWithSubdomainIntelligence(url),
      scanWithUrlReputation(url)
    ]);
    
    const combinedResult = combineThreatIntelligence(scanResults, { url, filename: 'webpage' });
    
    if (combinedResult.status === 'malicious' || combinedResult.status === 'suspicious') {
      showUrlThreatAlert(tabId, combinedResult);
    }
  } catch (error) {
    console.error('URL pre-navigation scan failed:', error);
  }
}

function showUrlThreatAlert(tabId, scanResult) {
  if (browser.scripting) {
    browser.scripting.executeScript({
      target: { tabId: tabId },
      function: injectUrlThreatWarning,
      args: [scanResult]
    });
  } else if (browser.tabs.executeScript) {
    browser.tabs.executeScript(tabId, {
      code: `(${injectUrlThreatWarning.toString()})(${JSON.stringify(scanResult)})`
    });
  }
}

function injectUrlThreatWarning(scanResult) {
  const overlay = document.createElement('div');
  overlay.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: rgba(0, 0, 0, 0.95);
    z-index: 999999;
    display: flex;
    align-items: center;
    justify-content: center;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  `;
  
  const riskColor = scanResult.status === 'malicious' ? '#dc2626' : '#f59e0b';
  
  overlay.innerHTML = `
    <div style="
      background: linear-gradient(135deg, #1f2937 0%, #374151 100%);
      padding: 2rem;
      border-radius: 1rem;
      max-width: 500px;
      text-align: center;
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
      color: white;
      border: 1px solid rgba(255, 255, 255, 0.1);
    ">
      <div style="color: ${riskColor}; font-size: 4rem; margin-bottom: 1rem;">🛡️</div>
      <h2 style="color: ${riskColor}; margin: 0 0 1rem 0; font-size: 1.8rem; font-weight: 700;">
        Website Blocked
      </h2>
      <p style="color: #d1d5db; margin: 0 0 1rem 0; line-height: 1.6;">
        This website has been flagged by <strong>${scanResult.detections}/${scanResult.totalEngines}</strong> 
        security sources as potentially dangerous.
      </p>
      <div style="
        background: rgba(220, 38, 38, 0.1);
        border: 1px solid rgba(220, 38, 38, 0.3);
        border-radius: 0.5rem;
        padding: 1rem;
        margin: 1rem 0;
        font-size: 0.9rem;
        color: #fca5a5;
      ">
        <strong>Risk Level:</strong> ${scanResult.status.toUpperCase()}<br>
        <strong>Risk Score:</strong> ${scanResult.combinedRiskScore || 0}/100
        ${scanResult.threatSources.length > 0 ? `<br><br><strong>Detected by:</strong><br>${scanResult.threatSources.join('<br>')}` : ''}
      </div>
      <div style="display: flex; gap: 1rem; justify-content: center; flex-wrap: wrap;">
        <button onclick="window.history.back(); this.parentElement.parentElement.parentElement.remove();" style="
          background: #059669;
          color: white;
          border: none;
          padding: 0.75rem 1.5rem;
          border-radius: 0.5rem;
          font-weight: 600;
          cursor: pointer;
          font-size: 0.9rem;
        ">🔙 Go Back Safely</button>
        <button onclick="this.parentElement.parentElement.parentElement.remove()" style="
          background: #dc2626;
          color: white;
          border: none;
          padding: 0.75rem 1.5rem;
          border-radius: 0.5rem;
          font-weight: 600;
          cursor: pointer;
          font-size: 0.9rem;
        ">⚠️ Continue at Risk</button>
      </div>
      <p style="color: #6b7280; font-size: 0.75rem; margin-top: 1.5rem;">
        Powered by Risk Notifier - Cross-platform security extension
      </p>
    </div>
  `;
  
  document.body.appendChild(overlay);
}

// Message handling for download actions
browser.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'cancelDownload') {
    browser.downloads.cancel(request.downloadId);
    sendResponse({ success: true });
  } else if (request.action === 'proceedWithDownload') {
    if (browser.downloads.resume) {
      browser.downloads.resume(request.downloadId);
    }
    sendResponse({ success: true });
  } else if (request.action === 'scanUrl') {
    scanUrl(request.url)
      .then(result => sendResponse({ success: true, result }))
      .catch(error => sendResponse({ success: false, error: error.message }));
    return true;
  } else if (request.action === 'testSubdomainAPI') {
    testHackerTargetAPI()
      .then(result => sendResponse({ success: true, result }))
      .catch(error => sendResponse({ success: false, error: error.message }));
    return true;
  }
});

async function testHackerTargetAPI() {
  try {
    console.log('🧪 Testing HackerTarget API...');
    
    const testDomain = 'example.com';
    const response = await fetch(`https://api.hackertarget.com/hostsearch/?q=${testDomain}`, {
      method: 'GET',
      headers: {
        'User-Agent': 'Risk-Notifier-Extension/1.0'
      }
    });
    
    const responseText = await response.text();
    console.log('📊 HackerTarget API Test Response:', responseText);
    
    if (!response.ok) {
      throw new Error(`API returned status ${response.status}: ${responseText}`);
    }
    
    if (responseText.includes('error') || responseText.includes('API count exceeded')) {
      throw new Error(`API Error: ${responseText}`);
    }
    
    const subdomains = responseText.split('\n').filter(line => line.trim()).length;
    
    return {
      status: 'working',
      testDomain,
      subdomainsFound: subdomains,
      response: responseText.substring(0, 200) + '...',
      timestamp: new Date().toISOString()
    };
  } catch (error) {
    console.error('❌ HackerTarget API Test Failed:', error);
    return {
      status: 'failed',
      error: error.message,
      timestamp: new Date().toISOString()
    };
  }
}

async function scanUrl(url) {
  const result = await browser.storage.sync.get(['vtApiKey']);
  const apiKey = result.vtApiKey;
  
  if (!apiKey) {
    throw new Error('VirusTotal API key not found');
  }
  
  return await scanWithVirusTotal(url, apiKey);
}