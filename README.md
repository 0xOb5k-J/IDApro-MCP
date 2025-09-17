# IDA Pro MCP Server Ultimate Edition

[![IDA Pro](https://img.shields.io/badge/IDA%20Pro-9.0+-blue.svg)](https://www.hex-rays.com/products/ida/)
[![Python](https://img.shields.io/badge/Python-3.8+-green.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-3.2.0%20FINAL-red.svg)]()

> **Advanced Model Context Protocol Server for IDA Pro 9.0 with 55+ Analysis Tools**

A comprehensive binary analysis toolkit that bridges IDA Pro with modern AI assistants through the Model Context Protocol (MCP). This tool transforms IDA Pro into a powerful AI-assisted reverse engineering platform with advanced caching, performance monitoring, and vulnerability detection capabilities.

## 🚀 Features

### Core Capabilities
- **55+ Analysis Tools** - Complete binary analysis suite
- **Advanced Caching System** - Smart TTL-based caching with LRU eviction
- **Performance Monitoring** - Real-time execution metrics and optimization
- **Batch Operations** - Process multiple targets efficiently
- **Pattern Recognition** - Automated detection of crypto, packing, and malware patterns
- **Vulnerability Detection** - Identify potential security issues
- **Zero Import Errors** - Guaranteed compatibility with IDA Pro 9.0

### Analysis Categories

#### 🔍 Core Analysis (Tools 1-10)
- Comprehensive binary information extraction
- Advanced function analysis with CFG metrics
- Deep function analysis with loop detection
- Cryptographic constant identification
- Anti-debugging technique detection
- Vulnerability assessment
- Advanced string analysis
- Detailed import/export analysis
- Segment information with permissions

#### 🌐 Cross-References & Flow (Tools 11-20)
- Cross-reference analysis (to/from)
- Call graph generation
- Data flow analysis
- Execution path tracing
- Dead code detection
- Loop analysis
- Recursive function identification
- Indirect call detection
- Function chunk analysis

#### 🔍 Pattern Recognition (Tools 21-30)
- Byte pattern searching
- String pattern matching
- Code pattern detection
- Shellcode identification
- Encoding pattern analysis
- Format string detection
- Network indicator extraction
- Registry operation analysis
- File operation tracking
- Process operation monitoring

#### 🛠️ Decompilation & Analysis (Tools 31-40)
- Hexrays decompiler integration
- Function signature extraction
- Stack variable analysis
- Function argument analysis
- Local type information
- Virtual table analysis
- Switch table detection
- Enumeration extraction
- Structure analysis
- Comment management

#### ⚡ Binary Manipulation (Tools 41-50)
- Runtime byte patching
- Comment addition/modification
- Symbol renaming
- Function creation/deletion
- Function type setting
- Code/data marking
- Memory undefining
- String creation
- Real-time modifications

#### 📊 Performance & Monitoring (Tools 51-55)
- Performance statistics
- Cache management
- Cache information
- IDA Python script execution
- Server status monitoring

## 🛠️ Installation

### Prerequisites - minimal
```bash
# IDA Pro 9.0 or higher
# Python 3.8+

# Install MCP dependencies
pip install mcp starlette uvicorn
```

### Setup
1. **Clone the repository:**
```bash
git clone https://github.com/0xOb5k-J/IDApro-MCP.git
cd IDApro-MCP
```

2. **Copy to IDA Pro plugins directory:**
```bash
# Windows
copy ida-mcp-server-ultimate.py "%IDADIR%\plugins\"

# Linux/macOS
cp ida-mcp-server-ultimate.py "$IDADIR/plugins/"
```

3. **Launch IDA Pro:**
   - The plugin auto-loads on startup
   - Server runs on port 3000 by default
   - Use hotkey `Ctrl+Alt+M` for quick access

## 🚦 Usage

### Basic Usage
```python
# Plugin automatically starts MCP server
# Access via http://localhost:3000

# Example tool calls:
get_comprehensive_info()           # Get binary overview
analyze_function_deep(0x401000)    # Deep function analysis
find_crypto_constants()            # Find crypto patterns
detect_anti_analysis()             # Detect anti-debugging
find_vulnerabilities()             # Security assessment
```

### Advanced Features
```python
# Performance monitoring
get_performance_stats()

# Cache management
clear_cache("function_*")
get_cache_info()

# Custom analysis
execute_ida_python("print('Custom script')")

# Pattern searching
search_bytes("48 89 E5")
find_shellcode_patterns()
```

## 🏗️ Architecture

### Smart Caching System
- **TTL-based expiration** - Automatic cache invalidation
- **LRU eviction** - Memory-efficient cache management
- **Pattern invalidation** - Selective cache clearing
- **Hit ratio tracking** - Performance metrics

### Performance Optimization
- **Execution timing** - Function performance tracking
- **Memory monitoring** - Cache usage statistics
- **Batch processing** - Efficient bulk operations
- **Threading support** - Non-blocking operations

### Security Features
- **Anti-analysis detection** - Identify evasion techniques
- **Vulnerability scanning** - Automated security assessment
- **Crypto identification** - Find encryption implementations
- **Malware signatures** - Pattern-based detection

## 📊 Performance Metrics

The server provides comprehensive performance monitoring:

```json
{
  "function_stats": {
    "analyze_function_deep": {
      "avg_time": 0.045,
      "min_time": 0.021,
      "max_time": 0.156,
      "total_calls": 42
    }
  },
  "cache_performance": {
    "hit_ratio": 0.87,
    "total_hits": 1240,
    "total_misses": 180
  },
  "uptime": 3600.5
}
```

## 🔧 Configuration Claude/VScode

### Client Configuration
```python
{
  "mcpServers": {
    "IDAPro": {
      "url": "http://127.0.0.1:3000/sse",
      "type": "sse"
    }
  }
}
```

### Analysis Levels
```python
class AnalysisLevel(Enum):
    BASIC = 1      # Quick overview
    STANDARD = 2   # Standard analysis
    DEEP = 3       # Comprehensive analysis
    FORENSIC = 4   # Maximum depth
```

## 🧪 Example Use Cases

### 1. Malware Analysis
```python
# Comprehensive malware assessment
info = get_comprehensive_info()
anti_debug = detect_anti_analysis()
crypto = find_crypto_constants()
vulns = find_vulnerabilities()
```

### 2. Vulnerability Research
```python
# Security-focused analysis
dangerous_funcs = find_vulnerabilities()
format_strings = find_format_strings()
network_indicators = find_network_indicators()
```

### 3. Reverse Engineering
```python
# Deep binary understanding
functions = get_functions_advanced(sort_by="size")
for func in functions[:10]:  # Top 10 largest
    analysis = analyze_function_deep(int(func["address"], 16))
    decompiled = decompile_function(int(func["address"], 16))
```

## 🛡️ Security Considerations

- **Read-only by default** - Safe exploration mode
- **Controlled modifications** - Explicit patching operations
- **Backup recommendations** - Always work on copies
- **Audit logging** - Track all modifications


## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**Made with ❤️ for the Reverse Engineering Community**

⭐ **Star this repo if you find it useful!** ⭐

</div>
