import React, { useState } from 'react';
import { ChevronLeft, ChevronRight, Shield, Network, Download, AlertTriangle, Lock, Search } from 'lucide-react';
import './index.css'

const Presentation = () => {
  const [currentSlide, setCurrentSlide] = useState(0);

  const slides = [
    // Slide 1: Title
    {
      title: "NetSniff Pro",
      subtitle: "Advanced Network Security Suite with Real-time Packet Analysis",
      content: (
        <div className="text-center space-y-6">
          <Shield className="w-32 h-32 mx-auto text-blue-600" />
          <div className="space-y-4">
            <h3 className="text-2xl font-bold text-gray-700">A Comprehensive Network Monitoring & Security Platform</h3>
            <div className="grid grid-cols-2 gap-4 mt-8">
              <div className="bg-blue-50 p-4 rounded-lg">
                <Network className="w-12 h-12 mx-auto mb-2 text-blue-600" />
                <p className="font-semibold">Real-time Packet Capture</p>
              </div>
              <div className="bg-green-50 p-4 rounded-lg">
                <Shield className="w-12 h-12 mx-auto mb-2 text-green-600" />
                <p className="font-semibold">Threat Detection</p>
              </div>
              <div className="bg-purple-50 p-4 rounded-lg">
                <Download className="w-12 h-12 mx-auto mb-2 text-purple-600" />
                <p className="font-semibold">Download Security</p>
              </div>
              <div className="bg-red-50 p-4 rounded-lg">
                <Lock className="w-12 h-12 mx-auto mb-2 text-red-600" />
                <p className="font-semibold">Privacy Protection</p>
              </div>
            </div>
          </div>
        </div>
      )
    },

    // Slide 2: Architecture Overview
    {
      title: "System Architecture",
      subtitle: "Modular Design with 6 Core Components",
      content: (
        <div className="space-y-4">
          <div className="bg-gradient-to-r from-blue-50 to-blue-100 p-4 rounded-lg border-l-4 border-blue-600">
            <h4 className="font-bold text-lg mb-2">1. Core Network Layer (network_utils.py)</h4>
            <p className="text-sm">Handles packet capture using Scapy, DNS resolution, and HTTP traffic extraction</p>
          </div>
          
          <div className="bg-gradient-to-r from-green-50 to-green-100 p-4 rounded-lg border-l-4 border-green-600">
            <h4 className="font-bold text-lg mb-2">2. Security Manager (security_manager.py)</h4>
            <p className="text-sm">Central security engine - threat analysis, reputation scoring, VirusTotal integration</p>
          </div>
          
          <div className="bg-gradient-to-r from-purple-50 to-purple-100 p-4 rounded-lg border-l-4 border-purple-600">
            <h4 className="font-bold text-lg mb-2">3. Data Manager (data_manager.py)</h4>
            <p className="text-sm">Packet storage, filtering logic, and CSV export functionality</p>
          </div>
          
          <div className="bg-gradient-to-r from-yellow-50 to-yellow-100 p-4 rounded-lg border-l-4 border-yellow-600">
            <h4 className="font-bold text-lg mb-2">4. UI Layer (6 Tab Modules)</h4>
            <p className="text-sm">Tkinter-based interface with specialized tabs for different security aspects</p>
          </div>
          
          <div className="bg-gradient-to-r from-red-50 to-red-100 p-4 rounded-lg border-l-4 border-red-600">
            <h4 className="font-bold text-lg mb-2">5. Main Controller (main_modular.py)</h4>
            <p className="text-sm">Orchestrates all components, manages packet distribution and UI updates</p>
          </div>
        </div>
      )
    },

    // Slide 3: Network Utils Deep Dive
    {
      title: "Network Utilities Module",
      subtitle: "Packet Capture & Processing Engine",
      content: (
        <div className="space-y-3">
          <div className="bg-blue-50 p-4 rounded-lg">
            <h4 className="font-bold mb-2">🔍 PacketCapture Class</h4>
            <ul className="text-sm space-y-2 ml-4">
              <li><strong>Scapy Integration:</strong> Uses sniff() for real-time packet capture</li>
              <li><strong>Threading:</strong> Runs capture_loop() in daemon thread to prevent UI blocking</li>
              <li><strong>Stop Filter:</strong> Lambda function checks self.running flag for graceful shutdown</li>
            </ul>
          </div>
          
          <div className="bg-green-50 p-4 rounded-lg">
            <h4 className="font-bold mb-2">🌐 DNS Resolution</h4>
            <ul className="text-sm space-y-2 ml-4">
              <li><strong>DNS Cache:</strong> Dictionary mapping IPs to domains (self.dns_map)</li>
              <li><strong>process_dns_packet():</strong> Extracts DNSRR answers where type=1 (A records)</li>
              <li><strong>Decoding:</strong> Handles bytes to UTF-8 conversion, strips trailing dots</li>
              <li><strong>Sync:</strong> Updates both local cache and SecurityManager's dns_cache</li>
            </ul>
          </div>
          
          <div className="bg-purple-50 p-4 rounded-lg">
            <h4 className="font-bold mb-2">📡 HTTP Traffic Extraction</h4>
            <ul className="text-sm space-y-2 ml-4">
              <li><strong>Raw Layer Detection:</strong> Checks packet.haslayer(Raw) for payload</li>
              <li><strong>Request Parsing:</strong> Identifies GET/POST/PUT/DELETE/HEAD methods</li>
              <li><strong>Header Extraction:</strong> Splits by \r\n, extracts Host and User-Agent</li>
              <li><strong>URL Construction:</strong> Combines http:// + host + path for full URL</li>
            </ul>
          </div>
          
          <div className="bg-red-50 p-4 rounded-lg">
            <h4 className="font-bold mb-2">🚨 Suspicious Port Detection</h4>
            <p className="text-sm"><strong>SUSPICIOUS_PORTS Set:</strong> {4444, 5555, 6666, 12345, 31337, 1337, 8888, 9999}</p>
            <p className="text-sm mt-2"><strong>Logic:</strong> Checks if TCP sport OR dport in SUSPICIOUS_PORTS set</p>
          </div>
        </div>
      )
    },

    // Slide 4: Security Manager - Part 1
    {
      title: "Security Manager - Threat Analysis Engine",
      subtitle: "Multi-layered Security Intelligence System",
      content: (
        <div className="space-y-3">
          <div className="bg-red-50 p-4 rounded-lg border-2 border-red-300">
            <h4 className="font-bold mb-2">🎯 Threat Scoring Algorithm</h4>
            <div className="text-sm space-y-2">
              <p className="font-semibold">Base Score Calculation:</p>
              <ul className="ml-4 space-y-1">
                <li>• <strong>Suspicious Ports:</strong> +30 points (if sport/dport in {4444,5555,6666,12345,31337,1337,8888,9999})</li>
                <li>• <strong>High Frequency Connections:</strong> +20 points (if connection_frequency[src:dst]  100)</li>
                <li>• <strong>Blocked Domains:</strong> +40 points (if domain matches blocklist patterns)</li>
                <li>• <strong>Port Scanning Detection:</strong> +15 points (if unique_ports  50)</li>
              </ul>
              <p className="font-semibold mt-2">Final Score: min(sum of all factors, 100)</p>
            </div>
          </div>
          
          <div className="bg-orange-50 p-4 rounded-lg">
            <h4 className="font-bold mb-2">🏷️ Reputation System</h4>
            <div className="text-sm grid grid-cols-2 gap-2">
              <div>
                <p className="font-semibold">IP Reputation:</p>
                <ul className="ml-4 text-xs">
                  <li>Initial: 80/100</li>
                  <li>Decay: -threat_score/10</li>
                  <li>Min: 0 (blocked)</li>
                  <li>Tracks: hits, blocks, history</li>
                </ul>
              </div>
              <div>
                <p className="font-semibold">Domain Reputation:</p>
                <ul className="ml-4 text-xs">
                  <li>Initial: 50/100</li>
                  <li>Blocklist match: instant flag</li>
                  <li>Tracks: hits, blocked count</li>
                  <li>Dynamic scoring</li>
                </ul>
              </div>
            </div>
          </div>
          
          <div className="bg-yellow-50 p-4 rounded-lg">
            <h4 className="font-bold mb-2">📊 Threat History Storage</h4>
            <p className="text-sm">Stores threats with score ≥ 30 in threat_history list with:</p>
            <ul className="text-xs ml-4 mt-1">
              <li>• Time, source_ip, dest_ip, protocol</li>
              <li>• Threat score and detailed reasons array</li>
              <li>• Used for trending and pattern analysis</li>
            </ul>
          </div>
        </div>
      )
    },

    // Slide 5: Security Manager - Part 2
    {
      title: "Security Manager - Advanced Features",
      subtitle: "VirusTotal Integration & Privacy Detection",
      content: (
        <div className="space-y-3">
          <div className="bg-blue-50 p-4 rounded-lg">
            <h4 className="font-bold mb-2">🦠 VirusTotal API Integration</h4>
            <div className="text-sm space-y-2">
              <p className="font-semibold">URL Scanning Workflow:</p>
              <ol className="ml-4 space-y-1">
                <li>1. POST URL to api.v3/urls endpoint with API key</li>
                <li>2. Extract analysis_id from response</li>
                <li>3. Wait 2 seconds for analysis completion</li>
                <li>4. GET analysis results from api.v3/analyses/{'{analysis_id}'}</li>
                <li>5. Parse stats: malicious, suspicious, harmless, undetected</li>
                <li>6. Calculate threat_score = (malicious + suspicious) / total * 100</li>
              </ol>
              <p className="mt-2"><strong>Auto-block threshold:</strong> 30% malicious detection rate</p>
            </div>
          </div>
          
          <div className="bg-green-50 p-4 rounded-lg">
            <h4 className="font-bold mb-2">🔐 SSL Certificate Verification</h4>
            <p className="text-sm">Uses ssl.create_default_context() to:</p>
            <ul className="text-xs ml-4 mt-1">
              <li>• Connect to hostname:443</li>
              <li>• Extract certificate with getpeercert()</li>
              <li>• Validate issuer, subject, expiration (notAfter)</li>
              <li>• Return validity status and certificate details</li>
            </ul>
          </div>
          
          <div className="bg-red-50 p-4 rounded-lg">
            <h4 className="font-bold mb-2">🕵️ Privacy Leak Detection</h4>
            <div className="text-sm">
              <p className="font-semibold">Monitored Keywords:</p>
              <p className="text-xs">password, passwd, pwd, user, username, email, token, api_key, secret</p>
              <p className="font-semibold mt-2">Detection Process:</p>
              <ul className="text-xs ml-4">
                <li>1. Extract Raw layer payload and decode to UTF-8</li>
                <li>2. Convert to lowercase for case-insensitive matching</li>
                <li>3. Check for keyword presence in payload</li>
                <li>4. Classify severity: HIGH (password, secret, keys) or MEDIUM (others)</li>
                <li>5. Store: time, keyword, source_ip, dest_ip, severity</li>
              </ul>
            </div>
          </div>
        </div>
      )
    },

    // Slide 6: Data Manager & Filtering
    {
      title: "Data Management & Filtering System",
      subtitle: "Packet Storage and Multi-criteria Filtering",
      content: (
        <div className="space-y-3">
          <div className="bg-purple-50 p-4 rounded-lg">
            <h4 className="font-bold mb-2">💾 PacketDataManager Class</h4>
            <div className="text-sm space-y-2">
              <p className="font-semibold">Data Structure:</p>
              <ul className="text-xs ml-4">
                <li>• <strong>packet_data[]:</strong> List storing all captured packets (without packet object)</li>
                <li>• <strong>packet_count:</strong> Integer counter for total packets</li>
                <li>• <strong>alert_count:</strong> Integer counter for security alerts</li>
              </ul>
              <p className="font-semibold mt-2">Key Methods:</p>
              <ul className="text-xs ml-4">
                <li>• <strong>add_packet():</strong> Removes packet object (index -1), appends packet_info[:8]</li>
                <li>• <strong>export_to_csv():</strong> Uses csv.writer with headers: Time, Source IP, Dest IP, Protocol, Ports, DNS</li>
                <li>• <strong>clear_data():</strong> Resets all lists and counters to initial state</li>
              </ul>
            </div>
          </div>
          
          <div className="bg-blue-50 p-4 rounded-lg">
            <h4 className="font-bold mb-2">🔍 FilterManager Logic</h4>
            <div className="text-sm">
              <p className="font-semibold">should_display_packet() - Multi-criteria filtering:</p>
              <div className="grid grid-cols-2 gap-2 mt-2 text-xs">
                <div className="bg-white p-2 rounded">
                  <p className="font-semibold">Protocol Filter:</p>
                  <p>Returns False if protocol ≠ filter (TCP/UDP/ICMP)</p>
                </div>
                <div className="bg-white p-2 rounded">
                  <p className="font-semibold">IP Filter:</p>
                  <p>Returns False if filter not in (source_ip, dest_ip)</p>
                </div>
                <div className="bg-white p-2 rounded">
                  <p className="font-semibold">Port Filter:</p>
                  <p>Converts to int, checks if port in (sport, dport)</p>
                </div>
                <div className="bg-white p-2 rounded">
                  <p className="font-semibold">DNS Filter:</p>
                  <p>Lowercase match in source_dns OR dest_dns</p>
                </div>
              </div>
              <p className="mt-2 font-semibold">Public IP Only Filter:</p>
              <p className="text-xs">Returns False if public_ip not in (source_ip, dest_ip)</p>
              <p className="text-xs italic mt-1">All filters use AND logic - packet must pass ALL active filters</p>
            </div>
          </div>
        </div>
      )
    },

    // Slide 7: Packet Capture Tab
    {
      title: "Packet Capture Tab Module",
      subtitle: "Real-time Display with DNS Resolution",
      content: (
        <div className="space-y-3">
          <div className="bg-green-50 p-4 rounded-lg">
            <h4 className="font-bold mb-2">📋 UI Components</h4>
            <ul className="text-sm space-y-1 ml-4">
              <li>• <strong>Treeview Table:</strong> 9 columns (Time, Source IP, Source DNS, Dest IP, Dest DNS, Protocol, Ports, Info)</li>
              <li>• <strong>Column Widths:</strong> Time(70), IPs(100), DNS(120), Protocol(70), Ports(70), Info(150)</li>
              <li>• <strong>Color Tags:</strong> TCP=green (#e8f5e8), UDP=blue (#f0f8ff), ICMP=orange (#fff5ee), Suspicious=red</li>
            </ul>
          </div>
          
          <div className="bg-blue-50 p-4 rounded-lg">
            <h4 className="font-bold mb-2">🎨 Packet Processing Flow</h4>
            <div className="text-sm">
              <ol className="ml-4 space-y-1">
                <li>1. <strong>Extract:</strong> Unpack packet_info tuple (time, src_ip, dst_ip, protocol, ports, dns names)</li>
                <li>2. <strong>Check Suspicious:</strong> sport/dport in SUSPICIOUS_PORTS set</li>
                <li>3. <strong>Shorten DNS:</strong> Truncate to 25 chars with "..." if longer</li>
                <li>4. <strong>Create Info:</strong> Format as "ip:port → ip:port" or just "ip → ip"</li>
                <li>5. <strong>Apply Tag:</strong> "suspicious" if suspicious ports, else protocol name</li>
                <li>6. <strong>Insert:</strong> Add to index 0 (top of tree) with tag styling</li>
                <li>7. <strong>Auto-scroll:</strong> Use tree.see(item) to keep latest visible</li>
              </ol>
            </div>
          </div>
          
          <div className="bg-yellow-50 p-4 rounded-lg">
            <h4 className="font-bold mb-2">🚨 Alert System</h4>
            <p className="text-sm">Text widget with dark theme (#1a1a1a bg, #ff6b6b fg)</p>
            <ul className="text-xs ml-4 mt-1">
              <li>• Timestamps each alert with [HH:MM:SS] format</li>
              <li>• Auto-scrolls to end on new alert</li>
              <li>• Disabled state prevents user editing</li>
            </ul>
          </div>
        </div>
      )
    },

    // Slide 8: Download Manager
    {
      title: "Download Manager Module",
      subtitle: "Secure Download with Real-time Scanning",
      content: (
        <div className="space-y-3">
          <div className="bg-purple-50 p-4 rounded-lg">
            <h4 className="font-bold mb-2">⬇️ Download Workflow</h4>
            <div className="text-sm">
              <p className="font-semibold">Phase 1: Pre-download Security Scan</p>
              <ol className="ml-4 text-xs space-y-1">
                <li>1. Extract filename from URL (split by '/', remove query params)</li>
                <li>2. If scan_first=True, call scan_url_virustotal(url)</li>
                <li>3. Check threat percentage: (malicious + suspicious) / total * 100</li>
                <li>4. If  30% AND auto_block=True, set status="BLOCKED", abort download</li>
                <li>5. Update safety status: "✓ Safe" or "⚠ Suspicious"</li>
              </ol>
            </div>
          </div>
          
          <div className="bg-blue-50 p-4 rounded-lg">
            <h4 className="font-bold mb-2">📥 Download Execution</h4>
            <div className="text-sm">
              <p className="font-semibold">Phase 2: File Download with Progress Tracking</p>
              <ol className="ml-4 text-xs space-y-1">
                <li>1. Use urllib.request.urlretrieve() with progress callback</li>
                <li>2. Callback calculates: progress = (downloaded/total) * 100</li>
                <li>3. Speed calculation: (downloaded_kb / elapsed_time) → KB/s or MB/s</li>
                <li>4. Update UI every 10 blocks (block_count % 10 == 0)</li>
                <li>5. Check cancelled flag in callback to abort if user cancels</li>
              </ol>
              
              <p className="font-semibold mt-2">Phase 3: Post-download Verification</p>
              <ol className="ml-4 text-xs space-y-1">
                <li>1. Calculate SHA256 hash: read file in 4KB chunks</li>
                <li>2. Update hash in download_info dictionary</li>
                <li>3. Set status to "✓ Completed"</li>
                <li>4. Show completion dialog with file location and safety status</li>
              </ol>
            </div>
          </div>
          
          <div className="bg-green-50 p-4 rounded-lg">
            <h4 className="font-bold mb-2">📊 Download Statistics</h4>
            <ul className="text-xs ml-4">
              <li>• <strong>Total:</strong> detected downloads + manual downloads</li>
              <li>• <strong>Active:</strong> Count where status contains "Downloading"</li>
              <li>• <strong>Blocked:</strong> Sum of unsafe detected + "BLOCKED" manual</li>
              <li>• <strong>Safe:</strong> Total - Blocked</li>
            </ul>
          </div>
        </div>
      )
    },

    // Slide 9: Threat Detection Tab
    {
      title: "Threat Detection & Analysis Module",
      subtitle: "Behavioral Pattern Analysis System",
      content: (
        <div className="space-y-3">
          <div className="bg-red-50 p-4 rounded-lg border-2 border-red-400">
            <h4 className="font-bold mb-2">🎯 Threat Classification System</h4>
            <div className="text-sm">
              <p className="font-semibold">Severity Levels:</p>
              <div className="grid grid-cols-3 gap-2 mt-2 text-xs">
                <div className="bg-yellow-100 p-2 rounded">
                  <p className="font-bold">LOW (<30)</p>
                  <p>Minor anomalies</p>
                  <p>Yellow highlight</p>
                </div>
                <div className="bg-orange-100 p-2 rounded">
                  <p className="font-bold">MEDIUM (30-50)</p>
                  <p>Suspicious activity</p>
                  <p>Orange highlight</p>
                </div>
                <div className="bg-red-100 p-2 rounded">
                  <p className="font-bold">HIGH (>50)</p>
                  <p>Critical threats</p>
                  <p>Red highlight + alert</p>
                </div>
              </div>
            </div>
          </div>
          
          <div className="bg-orange-50 p-4 rounded-lg">
            <h4 className="font-bold mb-2">📊 Statistics Calculation</h4>
            <div className="text-sm space-y-2">
              <p><strong>Total Threats:</strong> len(threat_history) - all threats with score ≥ 30</p>
              <p><strong>High Severity:</strong> sum(1 for t in threats if t["score"] ≥ 50)</p>
              <p><strong>Average Score:</strong> sum(all scores) / count (or 0 if empty)</p>
              <p><strong>Display Limit:</strong> Shows last 50 threats only (threats[-50:])</p>
            </div>
          </div>
          
          <div className="bg-yellow-50 p-4 rounded-lg">
            <h4 className="font-bold mb-2">🔍 Reason Aggregation</h4>
            <p className="text-sm">Each threat stores reasons[] array containing:</p>
            <ul className="text-xs ml-4 mt-1">
              <li>• "Suspicious port usage: {'{port}'}"</li>
              <li>• "High frequency connections"</li>
              <li>• "Blocked domain: {'{domain}'}"</li>
              <li>• "Potential port scanning"</li>
            </ul>
            <p className="text-xs mt-2 italic">Table displays first 2 reasons joined by comma</p>
          </div>
          
          <div className="bg-blue-50 p-4 rounded-lg">
            <h4 className="font-bold mb-2">🔄 Real-time Updates</h4>
            <p className="text-sm">process_packet() → refresh_threats() on every packet</p>
            <p className="text-xs mt-1">Clears and rebuilds entire table to show latest threats</p>
          </div>
        </div>
      )
    },

    // Slide 10: Reputation System
    {
      title: "Network Reputation System",
      subtitle: "Dynamic IP and Domain Trust Scoring",
      content: (
        <div className="space-y-3">
          <div className="bg-green-50 p-4 rounded-lg">
            <h4 className="font-bold mb-2">🏷️ IP Reputation Algorithm</h4>
            <div className="text-sm space-y-2">
              <p className="font-semibold">Initial State (defaultdict):</p>
              <pre className="bg-white p-2 rounded text-xs">
{`{
  "score": 80,  // Start with good reputation
  "hits": 0,     // Connection counter
  "blocked": 0,  // Times flagged as threat
  "history": []  // Threat event log
}`}
              </pre>
              <p className="font-semibold">Score Decay Formula:</p>
              <p className="text-xs">new_score = max(0, current_score - (threat_score / 10))</p>
              <p className="text-xs">Example: 80 - (40/10) = 76 after medium threat</p>
              
              <p className="font-semibold mt-2">History Tracking:</p>
              <p className="text-xs">Each threat appends: {'{'}"time", "threat", "reasons"{'}'}</p>
            </div>
          </div>
          
          <div className="bg-blue-50 p-4 rounded-lg">
            <h4 className="font-bold mb-2">🌐 Domain Reputation System</h4>
            <div className="text-sm">
              <p className="font-semibold">Blocklist Matching:</p>
              <p className="text-xs">Checks if any blocklist pattern in domain.lower():</p>
              <ul className="text-xs ml-4 mt-1">
                <li>• 'doubleclick.net', 'google-analytics.com'</li>
                <li>• 'ads.', 'tracker.', 'analytics.', 'telemetry.'</li>
                <li>• 'ad.', 'adservice.', 'metrics.'</li>
              </ul>
              <p className="text-xs mt-2">Match → +40 threat points + increment blocked counter</p>
            </div>
          </div>
          
          <div className="bg-purple-50 p-4 rounded-lg">
            <h4 className="font-bold mb-2">🎨 Visual Status Indicators</h4>
            <div className="grid grid-cols-3 gap-2 text-xs">
              <div className="bg-green-100 p-2 rounded text-center">
                <p className="font-bold">✓ Trusted</p>
                <p>Score ≥ 70</p>
                <p>Green bg</p>
              </div>
              <div className="bg-yellow-100 p-2 rounded text-center">
                <p className="font-bold">⚠ Suspicious</p>
                <p>40 ≤ Score {'<'} 70</p>
                <p>Yellow bg</p>
              </div>
              <div className="bg-red-100 p-2 rounded text-center">
                <p className="font-bold">✗ Blocked</p>
                <p>Score {'<'} 40</p>
                <p>Red bg + text</p>
              </div>
            </div>
          </div>
        </div>
      )
    },

    // Slide 11: Privacy & Protocol Analysis
    {
      title: "Privacy Leak & Protocol Inspector",
      subtitle: "Deep Packet Inspection Modules",
      content: (
        <div className="space-y-3">
          <div className="bg-red-50 p-4 rounded-lg">
            <h4 className="font-bold mb-2">🔐 Privacy Leak Detector</h4>
            <div className="text-sm space-y-2">
              <p className="font-semibold">Detection Method:</p>
              <ol className="ml-4 text-xs space-y-1">
                <li>1. Check packet.haslayer(Raw) for payload presence</li>
                <li>2. Decode bytes to UTF-8 string (errors='ignore')</li>
                <li>3. Convert to lowercase for case-insensitive search</li>
                <li>4. Iterate through keyword list with 'in' operator</li>
                <li>5. On match: extract IPs, classify severity, store leak</li>
                <li>6. Break after first match to avoid duplicates</li>
              </ol>
              
              <p className="font-semibold mt-2">Severity Classification:</p>
              <div className="text-xs grid grid-cols-2 gap-2">
                <div className="bg-red-100 p-2 rounded">
                  <p className="font-bold">HIGH Severity:</p>
                  <p>password, passwd, secret, private_key, api_key</p>
                </div>
                <div className="bg-yellow-100 p-2 rounded">
                  <p className="font-bold">MEDIUM Severity:</p>
                  <p>user, username, email, token, pwd</p>
                </div>
              </div>
            </div>
          </div>
          
          <div className="bg-blue-50 p-4 rounded-lg">
            <h4 className="font-bold mb-2">📡 Protocol Inspector - HTTP Analysis</h4>
            <div className="text-sm space-y-2">
              <p className="font-semibold">HTTP Request Processing:</p>
              <ol className="ml-4 text-xs space-y-1">
                <li>1. Check if payload starts with HTTP methods (GET/POST/PUT/DELETE/HEAD)</li>
                <li>2. Split payload by \r\n to get individual lines</li>
                <li>3. Parse first line: method + path extraction</li>
                <li>4. Loop through remaining lines for headers:</li>
                <li>   - Extract "Host:" header (case-insensitive)</li>
                <li>   - Extract "User-Agent:" header</li>
                <li>5. Construct full URL: http:// + host + path</li>
                <li>6. Store in http_traffic list with timestamp</li>
              </ol>
              
              <p className="font-semibold mt-2">Statistics Calculation:</p>
              <ul className="text-xs ml-4">
                <li>• <strong>HTTP Requests:</strong> Count entries where type="request"</li>
                <li>• <strong>Total Traffic:</strong> Total length of http_traffic list</li>
                <li>• <strong>Encrypted Ratio:</strong> Placeholder for HTTPS detection</li>
              </ul>
            </div>
          </div>
        </div>
      )
    },

    // Slide 12: Integration & Data Flow
    {
      title: "System Integration & Data Flow",
      subtitle: "Component Communication Architecture",
      content: (
        <div className="space-y-3">
          <div className="bg-gradient-to-r from-blue-100 to-purple-100 p-4 rounded-lg">
            <h4 className="font-bold mb-2">🔄 Packet Processing Pipeline</h4>
            <div className="text-sm">
              <p className="font-semibold">Step-by-Step Flow:</p>
              <ol className="ml-4 text-xs space-y-1 mt-2">
                <li>1. <strong>Capture:</strong> Scapy sniff() → process_packet() in PacketCapture</li>
                <li>2. <strong>DNS Check:</strong> If DNS layer → update dns_map cache</li>
                <li>3. <strong>HTTP Check:</strong> If Raw layer → extract HTTP data → SecurityManager</li>
                <li>4. <strong>Privacy Check:</strong> Scan payload for keywords → trigger alerts</li>
                <li>5. <strong>Packet Data:</strong> Build tuple (time, IPs, protocol, ports, DNS, packet_obj)</li>
                <li>6. <strong>Main Handler:</strong> main.handle_packet() receives packet_info</li>
                <li>7. <strong>Filter Check:</strong> PacketCaptureTab.should_display() applies filters</li>
                <li>8. <strong>Data Storage:</strong> DataManager.add_packet() (removes packet_obj)</li>
                <li>9. <strong>Tab Distribution:</strong> All 6 tabs receive packet via process_packet()</li>
                <li>10. <strong>Threat Analysis:</strong> SecurityManager.analyze_threat() calculates score</li>
                <li>11. <strong>Alert Trigger:</strong> If score  50 → handle_alert() → display in UI</li>
                <li>12. <strong>Statistics Update:</strong> Update counters and threat score display</li>
              </ol>
            </div>
          </div>
          
          <div className="bg-gradient-to-r from-green-100 to-yellow-100 p-4 rounded-lg">
            <h4 className="font-bold mb-2">🎯 Main Controller Orchestration</h4>
            <div className="text-sm">
              <p className="font-semibold">NetworkSnifferApp Responsibilities:</p>
              <ul className="text-xs ml-4 space-y-1 mt-2">
                <li>• <strong>Initialization:</strong> Creates all managers (Data, Filter, Security)</li>
                <li>• <strong>UI Setup:</strong> Builds 6 tabs, passes manager references</li>
                <li>• <strong>Packet Routing:</strong> Distributes packets to all tabs</li>
                <li>• <strong>State Management:</strong> Controls start/stop capture state</li>
                <li>• <strong>Statistics Sync:</strong> Updates header displays (packets, alerts, threat score)</li>
                <li>• <strong>Alert Coordination:</strong> Routes security alerts to PacketCaptureTab</li>
                <li>• <strong>Clean Shutdown:</strong> Stops capture thread on window close</li>
              </ul>
            </div>
          </div>
          
          <div className="bg-gradient-to-r from-orange-100 to-red-100 p-4 rounded-lg">
            <h4 className="font-bold mb-2">📊 Threading Architecture</h4>
            <div className="text-sm">
              <p className="font-semibold">Thread Management:</p>
              <div className="grid grid-cols-2 gap-2 mt-2 text-xs">
                <div className="bg-white p-2 rounded">
                  <p className="font-bold">Main Thread (UI):</p>
                  <ul className="ml-3">
                    <li>• Tkinter event loop</li>
                    <li>• UI updates via .after()</li>
                    <li>• Button callbacks</li>
                  </ul>
                </div>
                <div className="bg-white p-2 rounded">
                  <p className="font-bold">Daemon Threads:</p>
                  <ul className="ml-3">
                    <li>• Packet capture (Scapy)</li>
                    <li>• Download workers</li>
                    <li>• Auto-terminates on exit</li>
                  </ul>
                </div>
              </div>
              <p className="mt-2 text-xs"><strong>Synchronization:</strong> frame.after(0, callback) for thread-safe UI updates</p>
            </div>
          </div>
        </div>
      )
    },

    // Slide 13: Performance & Security Considerations
    {
      title: "Performance Optimization & Security",
      subtitle: "Design Decisions and Implementation Details",
      content: (
        <div className="space-y-3">
          <div className="bg-blue-50 p-4 rounded-lg">
            <h4 className="font-bold mb-2">⚡ Performance Optimizations</h4>
            <div className="text-sm space-y-2">
              <p className="font-semibold">1. Packet Storage Optimization:</p>
              <ul className="text-xs ml-4">
                <li>• Removes packet object before storage (packet_info[:-1])</li>
                <li>• Prevents memory bloat from Scapy packet objects</li>
                <li>• Stores only essential data: time, IPs, protocol, ports, DNS</li>
              </ul>
              
              <p className="font-semibold">2. DNS Caching:</p>
              <ul className="text-xs ml-4">
                <li>• Dictionary lookup O(1) vs reverse DNS query</li>
                <li>• Shared between PacketCapture and SecurityManager</li>
                <li>• Eliminates redundant network calls</li>
              </ul>
              
              <p className="font-semibold">3. UI Update Throttling:</p>
              <ul className="text-xs ml-4">
                <li>• Download progress updates every 10 blocks (not every block)</li>
                <li>• Reduces UI thread overhead</li>
                <li>• Maintains smooth user experience</li>
              </ul>
              
              <p className="font-semibold">4. Data Structure Choices:</p>
              <ul className="text-xs ml-4">
                <li>• defaultdict for automatic initialization</li>
                <li>• Counter for efficient port counting</li>
                <li>• Sets for O(1) suspicious port lookups</li>
              </ul>
            </div>
          </div>
          
          <div className="bg-red-50 p-4 rounded-lg">
            <h4 className="font-bold mb-2">🔒 Security Implementation</h4>
            <div className="text-sm space-y-2">
              <p className="font-semibold">1. VirusTotal Integration:</p>
              <ul className="text-xs ml-4">
                <li>• API key stored in .env file (not hardcoded)</li>
                <li>• Error handling for 401 (invalid key), 429 (rate limit)</li>
                <li>• 2-second wait for analysis completion</li>
                <li>• Graceful degradation if API unavailable</li>
              </ul>
              
              <p className="font-semibold">2. Download Security:</p>
              <ul className="text-xs ml-4">
                <li>• Pre-download URL scanning with auto-block at 30% threshold</li>
                <li>• SHA256 hash verification post-download</li>
                <li>• User confirmation for file overwrites</li>
                <li>• Separate thread prevents UI blocking during download</li>
              </ul>
              
              <p className="font-semibold">3. Privacy Protection:</p>
              <ul className="text-xs ml-4">
                <li>• Real-time payload scanning for credentials</li>
                <li>• Alert generation with source/destination tracking</li>
                <li>• Severity classification for prioritization</li>
              </ul>
            </div>
          </div>
          
          <div className="bg-green-50 p-4 rounded-lg">
            <h4 className="font-bold mb-2">🛡️ Error Handling Strategy</h4>
            <ul className="text-sm ml-4 space-y-1">
              <li>• Try-except blocks in all network operations</li>
              <li>• Graceful degradation: continue on DNS failures</li>
              <li>• User notifications via messagebox for critical errors</li>
              <li>• Logging for debugging (print statements)</li>
              <li>• Cancelled download detection in callback</li>
            </ul>
          </div>
        </div>
      )
    },

    // Slide 14: Key Features & Capabilities
    {
      title: "Key Features Summary",
      subtitle: "Comprehensive Network Security Suite",
      content: (
        <div className="space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <div className="bg-blue-50 p-3 rounded-lg border-l-4 border-blue-600">
              <h4 className="font-bold text-sm mb-2">📡 Real-time Packet Capture</h4>
              <ul className="text-xs space-y-1">
                <li>✓ Live network traffic monitoring</li>
                <li>✓ DNS resolution for readable domains</li>
                <li>✓ Protocol identification (TCP/UDP/ICMP)</li>
                <li>✓ Multi-criteria filtering system</li>
                <li>✓ Color-coded protocol display</li>
                <li>✓ Suspicious port detection</li>
              </ul>
            </div>
            
            <div className="bg-red-50 p-3 rounded-lg border-l-4 border-red-600">
              <h4 className="font-bold text-sm mb-2">🛡️ Threat Detection</h4>
              <ul className="text-xs space-y-1">
                <li>✓ Multi-factor threat scoring (0-100)</li>
                <li>✓ Suspicious port monitoring</li>
                <li>✓ High-frequency connection detection</li>
                <li>✓ Domain blocklist matching</li>
                <li>✓ Port scanning identification</li>
                <li>✓ Real-time alert system</li>
              </ul>
            </div>
            
            <div className="bg-green-50 p-3 rounded-lg border-l-4 border-green-600">
              <h4 className="font-bold text-sm mb-2">⭐ Reputation System</h4>
              <ul className="text-xs space-y-1">
                <li>✓ Dynamic IP scoring (0-100)</li>
                <li>✓ Domain trust evaluation</li>
                <li>✓ Historical threat tracking</li>
                <li>✓ Automated score decay</li>
                <li>✓ Visual status indicators</li>
                <li>✓ Blocklist integration</li>
              </ul>
            </div>
            
            <div className="bg-purple-50 p-3 rounded-lg border-l-4 border-purple-600">
              <h4 className="font-bold text-sm mb-2">⬇️ Download Manager</h4>
              <ul className="text-xs space-y-1">
                <li>✓ Network download detection</li>
                <li>✓ Manual download with UI</li>
                <li>✓ VirusTotal pre-scan</li>
                <li>✓ Real-time progress tracking</li>
                <li>✓ SHA256 hash verification</li>
                <li>✓ Auto-block malicious files</li>
              </ul>
            </div>
            
            <div className="bg-yellow-50 p-3 rounded-lg border-l-4 border-yellow-600">
              <h4 className="font-bold text-sm mb-2">🔐 Privacy Protection</h4>
              <ul className="text-xs space-y-1">
                <li>✓ Credential leak detection</li>
                <li>✓ Payload keyword scanning</li>
                <li>✓ Severity classification</li>
                <li>✓ Source/destination tracking</li>
                <li>✓ Real-time alerts</li>
                <li>✓ Plain-text monitoring</li>
              </ul>
            </div>
            
            <div className="bg-orange-50 p-3 rounded-lg border-l-4 border-orange-600">
              <h4 className="font-bold text-sm mb-2">🔍 Protocol Inspector</h4>
              <ul className="text-xs space-y-1">
                <li>✓ HTTP request analysis</li>
                <li>✓ Method extraction (GET/POST)</li>
                <li>✓ URL reconstruction</li>
                <li>✓ User-Agent tracking</li>
                <li>✓ Response code monitoring</li>
                <li>✓ Traffic statistics</li>
              </ul>
            </div>
          </div>
        </div>
      )
    },

    // Slide 15: Technical Specifications
    {
      title: "Technical Specifications",
      subtitle: "Technologies and Dependencies",
      content: (
        <div className="space-y-3">
          <div className="bg-gradient-to-r from-blue-50 to-blue-100 p-4 rounded-lg">
            <h4 className="font-bold mb-2">🐍 Core Technologies</h4>
            <div className="grid grid-cols-2 gap-3 text-sm">
              <div>
                <p className="font-semibold">Programming Language:</p>
                <ul className="text-xs ml-4">
                  <li>• Python 3.x</li>
                  <li>• Object-oriented architecture</li>
                  <li>• Modular design pattern</li>
                </ul>
              </div>
              <div>
                <p className="font-semibold">UI Framework:</p>
                <ul className="text-xs ml-4">
                  <li>• Tkinter (standard GUI library)</li>
                  <li>• ttk themed widgets</li>
                  <li>• Custom styling with tags</li>
                </ul>
              </div>
            </div>
          </div>
          
          <div className="bg-gradient-to-r from-green-50 to-green-100 p-4 rounded-lg">
            <h4 className="font-bold mb-2">📚 Key Libraries & Dependencies</h4>
            <div className="grid grid-cols-3 gap-2 text-xs">
              <div className="bg-white p-2 rounded">
                <p className="font-bold">Scapy</p>
                <p>Packet capture & manipulation</p>
                <p className="text-gray-600">sniff(), IP, TCP, UDP, DNS layers</p>
              </div>
              <div className="bg-white p-2 rounded">
                <p className="font-bold">urllib</p>
                <p>HTTP requests & downloads</p>
                <p className="text-gray-600">urlopen(), urlretrieve()</p>
              </div>
              <div className="bg-white p-2 rounded">
                <p className="font-bold">ssl/socket</p>
                <p>Certificate verification</p>
                <p className="text-gray-600">SSL context, cert inspection</p>
              </div>
              <div className="bg-white p-2 rounded">
                <p className="font-bold">hashlib</p>
                <p>File integrity checking</p>
                <p className="text-gray-600">SHA256 hash calculation</p>
              </div>
              <div className="bg-white p-2 rounded">
                <p className="font-bold">threading</p>
                <p>Concurrent operations</p>
                <p className="text-gray-600">Daemon threads for capture</p>
              </div>
              <div className="bg-white p-2 rounded">
                <p className="font-bold">csv</p>
                <p>Data export</p>
                <p className="text-gray-600">Packet data to CSV format</p>
              </div>
              <div className="bg-white p-2 rounded">
                <p className="font-bold">collections</p>
                <p>Data structures</p>
                <p className="text-gray-600">defaultdict, Counter</p>
              </div>
              <div className="bg-white p-2 rounded">
                <p className="font-bold">datetime</p>
                <p>Timestamp management</p>
                <p className="text-gray-600">Event timing, duration calc</p>
              </div>
              <div className="bg-white p-2 rounded">
                <p className="font-bold">dotenv</p>
                <p>Environment variables</p>
                <p className="text-gray-600">API key configuration</p>
              </div>
            </div>
          </div>
          
          <div className="bg-gradient-to-r from-purple-50 to-purple-100 p-4 rounded-lg">
            <h4 className="font-bold mb-2">🔌 External API Integration</h4>
            <div className="text-sm">
              <p className="font-semibold">VirusTotal API v3:</p>
              <ul className="text-xs ml-4 space-y-1">
                <li>• Endpoint: https://www.virustotal.com/api/v3/</li>
                <li>• Authentication: x-apikey header</li>
                <li>• Rate Limiting: Handled with error codes</li>
                <li>• Response: JSON with analysis statistics</li>
              </ul>
            </div>
          </div>
          
          <div className="bg-gradient-to-r from-orange-50 to-orange-100 p-4 rounded-lg">
            <h4 className="font-bold mb-2">💾 Data Storage</h4>
            <div className="text-sm">
              <ul className="text-xs space-y-1">
                <li>• <strong>In-memory storage:</strong> Lists and dictionaries for runtime data</li>
                <li>• <strong>CSV export:</strong> Persistent storage option for captured packets</li>
                <li>• <strong>No database:</strong> Lightweight, portable solution</li>
                <li>• <strong>Session-based:</strong> Data cleared between capture sessions</li>
              </ul>
            </div>
          </div>
        </div>
      )
    },

    // Slide 16: Use Cases & Applications
    {
      title: "Use Cases & Applications",
      subtitle: "Real-world Scenarios and Benefits",
      content: (
        <div className="space-y-3">
          <div className="bg-blue-50 p-4 rounded-lg">
            <h4 className="font-bold mb-2">🏢 Enterprise Security</h4>
            <ul className="text-sm ml-4 space-y-1">
              <li>• Monitor internal network for suspicious activity</li>
              <li>• Detect unauthorized data exfiltration attempts</li>
              <li>• Identify compromised machines via behavioral analysis</li>
              <li>• Track employee download activities for compliance</li>
              <li>• Verify encrypted vs unencrypted traffic ratios</li>
            </ul>
          </div>
          
          <div className="bg-green-50 p-4 rounded-lg">
            <h4 className="font-bold mb-2">🎓 Educational Purposes</h4>
            <ul className="text-sm ml-4 space-y-1">
              <li>• Learn network protocols and packet structure</li>
              <li>• Understand security threats in real-time</li>
              <li>• Demonstrate DNS resolution processes</li>
              <li>• Teach threat detection methodologies</li>
              <li>• Visualize network traffic patterns</li>
            </ul>
          </div>
          
          <div className="bg-purple-50 p-4 rounded-lg">
            <h4 className="font-bold mb-2">🔒 Personal Privacy Protection</h4>
            <ul className="text-sm ml-4 space-y-1">
              <li>• Detect applications sending sensitive data</li>
              <li>• Identify tracking and analytics connections</li>
              <li>• Monitor for credential leaks in plain text</li>
              <li>• Verify file downloads before execution</li>
              <li>• Audit home network for suspicious activity</li>
            </ul>
          </div>
          
          <div className="bg-yellow-50 p-4 rounded-lg">
            <h4 className="font-bold mb-2">🐛 Debugging & Development</h4>
            <ul className="text-sm ml-4 space-y-1">
              <li>• Debug API calls and HTTP traffic</li>
              <li>• Verify application network behavior</li>
              <li>• Test security implementations</li>
              <li>• Monitor bandwidth usage by protocol</li>
              <li>• Inspect packet structures for development</li>
            </ul>
          </div>
          
          <div className="bg-red-50 p-4 rounded-lg">
            <h4 className="font-bold mb-2">🚨 Incident Response</h4>
            <ul className="text-sm ml-4 space-y-1">
              <li>• Capture evidence during security incidents</li>
              <li>• Identify attack patterns and sources</li>
              <li>• Export packet data for forensic analysis</li>
              <li>• Track malware communication attempts</li>
              <li>• Generate threat reports with timestamps</li>
            </ul>
          </div>
        </div>
      )
    },

    // Slide 17: Future Enhancements
    {
      title: "Future Enhancements & Roadmap",
      subtitle: "Planned Features and Improvements",
      content: (
        <div className="space-y-3">
          <div className="bg-gradient-to-r from-blue-100 to-purple-100 p-4 rounded-lg">
            <h4 className="font-bold mb-2">🚀 Phase 1: Core Improvements</h4>
            <ul className="text-sm ml-4 space-y-1">
              <li>• <strong>Database Integration:</strong> SQLite for persistent threat history</li>
              <li>• <strong>Machine Learning:</strong> Anomaly detection using scikit-learn</li>
              <li>• <strong>HTTPS Decryption:</strong> SSL/TLS traffic inspection (with certificates)</li>
              <li>• <strong>Geolocation:</strong> IP-to-location mapping with visual map</li>
              <li>• <strong>Performance:</strong> Optimize for high-traffic networks (1000+ packets/sec)</li>
            </ul>
          </div>
          
          <div className="bg-gradient-to-r from-green-100 to-yellow-100 p-4 rounded-lg">
            <h4 className="font-bold mb-2">🎨 Phase 2: UI/UX Enhancements</h4>
            <ul className="text-sm ml-4 space-y-1">
              <li>• <strong>Dashboard:</strong> Real-time graphs with matplotlib/plotly</li>
              <li>• <strong>Dark Mode:</strong> Theme switching for better visibility</li>
              <li>• <strong>Custom Alerts:</strong> User-defined rules and notifications</li>
              <li>• <strong>Export Options:</strong> JSON, XML, PCAP formats</li>
              <li>• <strong>Search:</strong> Advanced filtering with regex support</li>
            </ul>
          </div>
          
          <div className="bg-gradient-to-r from-orange-100 to-red-100 p-4 rounded-lg">
            <h4 className="font-bold mb-2">🔐 Phase 3: Security Features</h4>
            <ul className="text-sm ml-4 space-y-1">
              <li>• <strong>Firewall Integration:</strong> Auto-block malicious IPs</li>
              <li>• <strong>IDS/IPS:</strong> Intrusion detection/prevention system</li>
              <li>• <strong>Threat Intelligence:</strong> Multiple API sources (AbuseIPDB, etc.)</li>
              <li>• <strong>DPI:</strong> Deep packet inspection for encrypted traffic</li>
              <li>• <strong>Automated Response:</strong> Quarantine suspicious connections</li>
            </ul>
          </div>
          
          <div className="bg-gradient-to-r from-pink-100 to-purple-100 p-4 rounded-lg">
            <h4 className="font-bold mb-2">🌐 Phase 4: Enterprise Features</h4>
            <ul className="text-sm ml-4 space-y-1">
              <li>• <strong>Multi-user:</strong> Role-based access control</li>
              <li>• <strong>Cloud Sync:</strong> Central management dashboard</li>
              <li>• <strong>Reporting:</strong> Automated security reports (PDF/HTML)</li>
              <li>• <strong>API:</strong> RESTful API for integration with SIEM systems</li>
              <li>• <strong>Compliance:</strong> GDPR, HIPAA audit logging</li>
            </ul>
          </div>
        </div>
      )
    },

    // Slide 18: Conclusion
    {
      title: "Conclusion",
      subtitle: "NetSniff Pro - Comprehensive Network Security",
      content: (
        <div className="text-center space-y-6">
          <div className="bg-gradient-to-r from-blue-100 via-purple-100 to-pink-100 p-6 rounded-lg">
            <h3 className="text-2xl font-bold mb-4">Key Takeaways</h3>
            <div className="grid grid-cols-2 gap-4 text-left">
              <div className="bg-white p-4 rounded-lg shadow">
                <h4 className="font-bold text-blue-600 mb-2">✅ What We Built</h4>
                <ul className="text-sm space-y-1">
                  <li>• Modular 6-tab security suite</li>
                  <li>• Real-time threat detection</li>
                  <li>• VirusTotal integration</li>
                  <li>• Privacy leak monitoring</li>
                  <li>• Dynamic reputation system</li>
                </ul>
              </div>
              
              <div className="bg-white p-4 rounded-lg shadow">
                <h4 className="font-bold text-green-600 mb-2">🎯 Core Strengths</h4>
                <ul className="text-sm space-y-1">
                  <li>• User-friendly interface</li>
                  <li>• Multi-layered security</li>
                  <li>• Comprehensive logging</li>
                  <li>• Extensible architecture</li>
                  <li>• Zero-cost deployment</li>
                </ul>
              </div>
            </div>
          </div>
          
          <div className="bg-blue-50 p-6 rounded-lg">
            <h4 className="font-bold text-xl mb-3">Technical Highlights</h4>
            <div className="grid grid-cols-4 gap-3 text-xs">
              <div className="bg-white p-3 rounded text-center">
                <div className="text-3xl font-bold text-blue-600">1800+</div>
                <p>Lines of Code</p>
              </div>
              <div className="bg-white p-3 rounded text-center">
                <div className="text-3xl font-bold text-green-600">6</div>
                <p>Security Modules</p>
              </div>
              <div className="bg-white p-3 rounded text-center">
                <div className="text-3xl font-bold text-purple-600">100</div>
                <p>Threat Score Scale</p>
              </div>
              <div className="bg-white p-3 rounded text-center">
                <div className="text-3xl font-bold text-orange-600">Real-time</div>
                <p>Packet Analysis</p>
              </div>
            </div>
          </div>
          
          <div className="bg-gradient-to-r from-green-400 to-blue-500 text-white p-6 rounded-lg shadow-lg">
            <h3 className="text-2xl font-bold mb-2">Thank You!</h3>
            <p className="text-lg">NetSniff Pro - Advanced Network Security Suite</p>
            <p className="mt-4 text-sm">Questions & Discussion</p>
          </div>
        </div>
      )
    }
  ];

  const nextSlide = () => {
    if (currentSlide < slides.length - 1) {
      setCurrentSlide(currentSlide + 1);
    }
  };

  const prevSlide = () => {
    if (currentSlide > 0) {
      setCurrentSlide(currentSlide - 1);
    }
  };

  const goToSlide = (index) => {
    setCurrentSlide(index);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-blue-900 to-purple-900 p-8">
      <div className="max-w-7xl mx-auto">
        {/* Slide Container */}
        <div className="bg-white rounded-2xl shadow-2xl p-12 min-h-[600px] mb-6">
          {/* Slide Header */}
          <div className="mb-8 border-b-4 border-blue-600 pb-4">
            <h1 className="text-4xl font-bold text-gray-800 mb-2">
              {slides[currentSlide].title}
            </h1>
            <p className="text-xl text-gray-600 italic">
              {slides[currentSlide].subtitle}
            </p>
          </div>
          
          {/* Slide Content */}
          <div className="text-gray-700">
            {slides[currentSlide].content}
          </div>
        </div>

        {/* Navigation Controls */}
        <div className="flex items-center justify-between mb-4">
          <button
            onClick={prevSlide}
            disabled={currentSlide === 0}
            className={`flex items-center gap-2 px-6 py-3 rounded-lg font-semibold transition-all ${
              currentSlide === 0
                ? 'bg-gray-300 text-gray-500 cursor-not-allowed'
                : 'bg-blue-600 text-white hover:bg-blue-700 shadow-lg'
            }`}
          >
            <ChevronLeft className="w-5 h-5" />
            Previous
          </button>

          <div className="flex items-center gap-2 bg-white rounded-lg px-6 py-3 shadow-lg">
            <span className="text-gray-700 font-semibold">
              Slide {currentSlide + 1} of {slides.length}
            </span>
          </div>

          <button
            onClick={nextSlide}
            disabled={currentSlide === slides.length - 1}
            className={`flex items-center gap-2 px-6 py-3 rounded-lg font-semibold transition-all ${
              currentSlide === slides.length - 1
                ? 'bg-gray-300 text-gray-500 cursor-not-allowed'
                : 'bg-blue-600 text-white hover:bg-blue-700 shadow-lg'
            }`}
          >
            Next
            <ChevronRight className="w-5 h-5" />
          </button>
        </div>

        {/* Slide Indicators */}
        <div className="flex justify-center gap-2">
          {slides.map((_, index) => (
            <button
              key={index}
              onClick={() => goToSlide(index)}
              className={`transition-all ${
                currentSlide === index
                  ? 'w-12 h-3 bg-blue-600'
                  : 'w-3 h-3 bg-gray-400 hover:bg-gray-500'
              } rounded-full`}
              aria-label={`Go to slide ${index + 1}`}
            />
          ))}
        </div>

        {/* Quick Navigation */}
        <div className="mt-6 bg-white rounded-lg p-4 shadow-lg">
          <h3 className="text-sm font-bold text-gray-700 mb-3">Quick Navigation</h3>
          <div className="grid grid-cols-6 gap-2">
            {slides.map((slide, index) => (
              <button
                key={index}
                onClick={() => goToSlide(index)}
                className={`text-xs p-2 rounded transition-all ${
                  currentSlide === index
                    ? 'bg-blue-600 text-white font-bold'
                    : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
                }`}
              >
                {index + 1}. {slide.title.split(' ')[0]}
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Presentation;
