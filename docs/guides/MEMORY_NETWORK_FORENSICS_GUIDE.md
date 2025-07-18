# Memory and Network Forensics Guide

## Overview

This guide covers Intellicrack's advanced memory and network forensics capabilities for malware analysis, incident response, and security research. Learn to extract artifacts, analyze memory dumps, and investigate network traffic.

## Table of Contents

1. [Memory Forensics](#memory-forensics)
2. [Process Analysis](#process-analysis)
3. [Network Forensics](#network-forensics)
4. [Artifact Extraction](#artifact-extraction)
5. [Malware Analysis](#malware-analysis)
6. [Timeline Analysis](#timeline-analysis)
7. [Reporting](#reporting)

## Memory Forensics

### Memory Acquisition

```python
from intellicrack.core.analysis.memory_forensics_engine import MemoryForensicsEngine

# Initialize forensics engine
forensics = MemoryForensicsEngine()

# Acquire memory dump
dump_path = forensics.acquire_memory(
    method="kernel",  # kernel, usermode, or hardware
    output="memory.dmp"
)

# Verify dump integrity
if forensics.verify_dump(dump_path):
    print("Memory dump acquired successfully")
```

### Memory Analysis Setup

```python
# Load memory dump
forensics.load_dump("memory.dmp")

# Detect OS profile
profile = forensics.detect_profile()
print(f"OS Profile: {profile}")

# Set analysis parameters
forensics.configure({
    "profile": profile,
    "plugins": ["pslist", "dlllist", "handles", "malfind"],
    "yara_rules": "rules/malware.yar"
})
```

### Process Enumeration

```python
# List all processes
processes = forensics.pslist()

for proc in processes:
    print(f"PID: {proc['pid']}")
    print(f"Name: {proc['name']}")
    print(f"PPID: {proc['ppid']}")
    print(f"Creation Time: {proc['created']}")
    print(f"Exit Time: {proc['exited']}")
```

### Hidden Process Detection

```python
# Find hidden processes
hidden = forensics.find_hidden_processes()

# Compare different process lists
psscan = forensics.psscan()  # Pool scanning
pslist = forensics.pslist()  # Active process list

hidden_procs = [p for p in psscan if p not in pslist]
print(f"Found {len(hidden_procs)} hidden processes")
```

## Process Analysis

### DLL Analysis

```python
# List loaded DLLs
pid = 1234
dlls = forensics.dlllist(pid=pid)

for dll in dlls:
    print(f"Base: 0x{dll['base']:016x}")
    print(f"Size: {dll['size']}")
    print(f"Path: {dll['path']}")
    print(f"Load Time: {dll['load_time']}")
```

### Memory Injection Detection

```python
# Detect injected code
injections = forensics.malfind()

for inj in injections:
    print(f"Process: {inj['process_name']} (PID: {inj['pid']})")
    print(f"Address: 0x{inj['address']:016x}")
    print(f"Size: {inj['size']}")
    print(f"Protection: {inj['protection']}")
    print(f"Suspicious: {inj['reasons']}")
    
    # Dump injected code
    forensics.dump_memory_region(
        pid=inj['pid'],
        address=inj['address'],
        size=inj['size'],
        output=f"injection_{inj['pid']}_{inj['address']:x}.bin"
    )
```

### Handle Analysis

```python
# Enumerate handles
handles = forensics.handles(pid=pid)

# Filter by type
file_handles = [h for h in handles if h['type'] == 'File']
key_handles = [h for h in handles if h['type'] == 'Key']
mutex_handles = [h for h in handles if h['type'] == 'Mutant']

# Check for suspicious handles
suspicious_mutexes = [
    "\\BaseNamedObjects\\Malware123",
    "\\BaseNamedObjects\\SingleInstance"
]

for mutex in mutex_handles:
    if any(s in mutex['name'] for s in suspicious_mutexes):
        print(f"Suspicious mutex: {mutex['name']}")
```

## Network Forensics

### Network Connection Analysis

```python
from intellicrack.core.analysis.network_forensics_engine import NetworkForensicsEngine

net_forensics = NetworkForensicsEngine()

# Analyze network connections from memory
connections = forensics.netscan()

for conn in connections:
    print(f"Protocol: {conn['protocol']}")
    print(f"Local: {conn['local_addr']}:{conn['local_port']}")
    print(f"Remote: {conn['remote_addr']}:{conn['remote_port']}")
    print(f"State: {conn['state']}")
    print(f"PID: {conn['pid']}")
    print(f"Process: {conn['process_name']}")
```

### PCAP Analysis

```python
# Load network capture
net_forensics.load_pcap("capture.pcap")

# Extract conversations
conversations = net_forensics.extract_conversations()

# Analyze protocols
protocols = net_forensics.analyze_protocols()
print(f"HTTP requests: {protocols['http']['requests']}")
print(f"DNS queries: {protocols['dns']['queries']}")
print(f"SSL/TLS sessions: {protocols['tls']['sessions']}")
```

### Stream Reconstruction

```python
# Reconstruct TCP streams
streams = net_forensics.reconstruct_tcp_streams()

for stream_id, stream in streams.items():
    print(f"\nStream {stream_id}:")
    print(f"Client: {stream['client']}")
    print(f"Server: {stream['server']}")
    print(f"Bytes: {stream['bytes_transferred']}")
    
    # Extract transferred files
    files = net_forensics.extract_files_from_stream(stream_id)
    for file in files:
        print(f"Extracted: {file['filename']} ({file['size']} bytes)")
```

## Artifact Extraction

### Registry Analysis

```python
# Extract registry hives from memory
hives = forensics.hivelist()

for hive in hives:
    print(f"Virtual: 0x{hive['virtual']:016x}")
    print(f"Physical: 0x{hive['physical']:016x}")
    print(f"Name: {hive['name']}")

# Query registry keys
keys = forensics.printkey(
    hive_offset=hives[0]['virtual'],
    key="Software\\Microsoft\\Windows\\CurrentVersion\\Run"
)

for key in keys:
    print(f"Key: {key['name']}")
    print(f"Value: {key['value']}")
```

### File Extraction

```python
# Extract files from memory
files = forensics.filescan()

# Filter by extension
exes = [f for f in files if f['filename'].endswith('.exe')]
docs = [f for f in files if f['filename'].endswith(('.doc', '.docx', '.pdf'))]

# Dump files
for file in exes[:10]:  # First 10 executables
    forensics.dumpfiles(
        physical_offset=file['physical'],
        output_dir="extracted_files/"
    )
```

### Credential Extraction

```python
# Extract credentials
from intellicrack.core.exploitation.credential_harvester import CredentialHarvester

harvester = CredentialHarvester()

# Extract from lsass
lsass_pid = forensics.find_process_by_name("lsass.exe")['pid']
creds = harvester.extract_from_lsass(
    memory_dump="memory.dmp",
    pid=lsass_pid
)

for cred in creds:
    print(f"User: {cred['username']}")
    print(f"Domain: {cred['domain']}")
    print(f"Type: {cred['type']}")
    if cred['type'] == 'hash':
        print(f"NTLM: {cred['ntlm']}")
```

## Malware Analysis

### Malware Detection

```python
# Run YARA rules
yara_hits = forensics.yarascan(
    rules_file="malware_rules.yar",
    pid=None  # Scan all processes
)

for hit in yara_hits:
    print(f"Rule: {hit['rule']}")
    print(f"Process: {hit['process']} (PID: {hit['pid']})")
    print(f"Address: 0x{hit['address']:016x}")
    print(f"Match: {hit['match_string']}")
```

### Rootkit Detection

```python
# Check for SSDT hooks
ssdt_hooks = forensics.ssdt()

for hook in ssdt_hooks:
    if hook['hooked']:
        print(f"SSDT[{hook['index']}] hooked!")
        print(f"Original: {hook['original']}")
        print(f"Current: {hook['current']}")

# Check for IDT hooks
idt_hooks = forensics.idt()

# Check for driver modifications
drivers = forensics.driverscan()
for driver in drivers:
    if driver['suspicious']:
        print(f"Suspicious driver: {driver['name']}")
        print(f"Reason: {driver['reason']}")
```

### Behavioral Analysis

```python
# Analyze process behavior
behavior = forensics.analyze_process_behavior(pid=1234)

print(f"API calls: {behavior['api_calls']}")
print(f"Network activity: {behavior['network']}")
print(f"File activity: {behavior['files']}")
print(f"Registry activity: {behavior['registry']}")
print(f"Process creation: {behavior['child_processes']}")
```

## Timeline Analysis

### Create Timeline

```python
# Generate comprehensive timeline
timeline = forensics.timeliner()

# Add network events
timeline.add_network_events(net_forensics.get_events())

# Add file system events
timeline.add_filesystem_events(forensics.mftparser())

# Sort by timestamp
timeline.sort()

# Export timeline
timeline.export("timeline.csv", format="csv")
timeline.export("timeline.json", format="json")
```

### Analyze Timeline

```python
# Find suspicious activity windows
suspicious_windows = timeline.find_activity_clusters(
    threshold=10,  # events
    window=60      # seconds
)

for window in suspicious_windows:
    print(f"Time: {window['start']} - {window['end']}")
    print(f"Events: {window['event_count']}")
    print(f"Types: {window['event_types']}")
```

## Advanced Techniques

### Memory Diffing

```python
# Compare memory dumps
diff = forensics.diff_dumps(
    dump1="memory1.dmp",
    dump2="memory2.dmp"
)

# New processes
new_procs = diff['new_processes']
print(f"New processes: {len(new_procs)}")

# Modified memory regions
modified = diff['modified_regions']
for region in modified:
    print(f"Process: {region['process']}")
    print(f"Address: 0x{region['address']:016x}")
    print(f"Size changed: {region['size_delta']}")
```

### Volatility Plugin Integration

```python
# Use custom Volatility plugins
forensics.load_plugin("custom_plugin.py")

# Run custom analysis
results = forensics.run_plugin(
    "custom_analysis",
    param1="value1",
    param2="value2"
)
```

### Machine Learning Detection

```python
from intellicrack.ml.forensics_ml import ForensicsML

ml_forensics = ForensicsML()

# Detect anomalies in memory
anomalies = ml_forensics.detect_anomalies(
    memory_dump="memory.dmp",
    model="malware_detection_v2"
)

for anomaly in anomalies:
    print(f"Score: {anomaly['score']}")
    print(f"Type: {anomaly['type']}")
    print(f"Description: {anomaly['description']}")
```

## Reporting

### Generate Forensics Report

```python
from intellicrack.core.reporting.forensics_reporter import ForensicsReporter

reporter = ForensicsReporter()

# Create comprehensive report
report = reporter.create_report(
    title="Incident Response - System Compromise",
    sections=[
        forensics.get_summary(),
        net_forensics.get_summary(),
        timeline.get_summary()
    ]
)

# Add evidence
for evidence in forensics.get_evidence():
    report.add_evidence(
        type=evidence['type'],
        description=evidence['description'],
        data=evidence['data']
    )

# Generate final report
report.generate(
    output="forensics_report.pdf",
    format="pdf",
    include_raw_data=False
)
```

### Export for External Tools

```python
# Export for other forensics tools
forensics.export_for_x_ways("export_xways/")
forensics.export_for_encase("export_encase/")
forensics.export_for_ftk("export_ftk/")

# Create portable case file
forensics.create_portable_case(
    output="case.e01",
    compression=True,
    password="secure123"
)
```

## Best Practices

1. **Chain of Custody**
   - Document all acquisition steps
   - Use cryptographic hashing
   - Maintain evidence integrity
   - Create detailed logs

2. **Analysis Workflow**
   - Start with automated scans
   - Verify findings manually
   - Cross-reference artifacts
   - Document methodology

3. **Performance Optimization**
   - Use indexed searches
   - Cache analysis results
   - Parallelize where possible
   - Work with memory streams

## Troubleshooting

### Common Issues

1. **Large Memory Dumps**
   ```python
   # Enable streaming analysis
   forensics.enable_streaming(
       chunk_size=1024*1024*100  # 100MB chunks
   )
   ```

2. **Corrupted Dumps**
   ```python
   # Attempt recovery
   forensics.repair_dump(
       input="corrupted.dmp",
       output="repaired.dmp"
   )
   ```

3. **Profile Detection Failed**
   ```python
   # Manual profile selection
   forensics.set_profile("Win10x64_19041")
   ```