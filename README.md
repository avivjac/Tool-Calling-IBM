# Tool-Calling-IBM

A comprehensive cybersecurity threat intelligence aggregation framework that provides unified access to multiple security APIs and databases through the Model Context Protocol (MCP). This project enables seamless integration and tool-calling capabilities for various threat intelligence providers and vulnerability databases.

## All the available endpoints can be found at the mapping google sheet:
[https://docs.google.com/spreadsheets/d/17HiwjDoa-tblKsQIgQnr4ImooQOPicflwLq5PvVqI0A/edit?usp=sharing](https://docs.google.com/spreadsheets/d/17HiwjDoa-tblKsQIgQnr4ImooQOPicflwLq5PvVqI0A/edit?usp=sharing)

## Overview

Tool-Calling-IBM is a Python-based framework that consolidates multiple threat intelligence APIs and security databases into a single, unified interface.  It supports querying IP addresses, domains, URLs, file hashes, CVEs, and other security indicators across multiple platforms including VirusTotal, IBM X-Force, URLscan.io, AlienVault OTX, NIST NVD, and AbuseIPDB.

## Features

- **Multi-Provider Support**: Integrate with leading threat intelligence platforms
  
  **API-Based Tools:**
  - VirusTotal
  - IBM X-Force Exchange
  - URLscan.io
  
  **Database Tools:**
  - NIST NVD (National Vulnerability Database) - CVE lookup
  - AbuseIPDB - IP reputation and abuse reporting

- **MCP Integration**: Built on the Model Context Protocol for standardized tool-calling
- **LLM Service**: Integrated Ollama-based service for generating intelligent responses from tool outputs
- **Training Dataset**: Pre-built conversation seeds and tool definitions for fine-tuning and testing
- **Comprehensive Validation**: Built-in validators for IPs, domains, URLs, emails, hashes, CVEs, and CPEs
- **Asynchronous Operations**: Efficient async/await pattern for improved performance
- **Detailed Logging**: Complete logging system for debugging and monitoring
- **Type Safety**: Full type hints for better code quality and IDE support

## Project Structure

```
Tool-Calling-IBM/
├── src/
│   ├── dataset/
│   │   ├── LLM-service/              # LLM response generation service
│   │   │   ├── main.py               # Ollama integration for processing tool responses
│   │   │   └── docker-compose.yml    # Docker setup for Ollama backend
│   │   ├── seeds/                    # Training data & conversation examples
│   │   │   ├── Get_an_IP_address_report.txt
│   │   │   ├── Get_a_URL_report.txt
│   │   │   ├── Get_a_domain_report.jsonl
│   │   │   ├── Get_an_attack_tactic_object.txt
│   │   │   └── Get_an_attack_technique_object.txt
│   │   ├── mcp_tools/
│   │   │   └── tool_list.jsonl       # MCP tool definitions
│   │   └── tool_train_set/           # Generated training data output
│   ├── server/
│   │   └── providers/
│   │       ├── API_tools/
│   │       │   ├── virusTotal.py     # VirusTotal API integration
│   │       │   ├── Xforce. py         # IBM X-Force API integration
│   │       │   ├── URLscan.py        # URLscan.io API integration
│   │       │   ├── AlienVaultOTX.py  # AlienVault OTX API integration
│   │       │   └── tool_base.py      # Base provider class
│   │       └── DB_tools/
│   │           ├── NIST. py           # NIST NVD CVE database
│   │           └── AbuseIPDB.py      # AbuseIPDB integration
│   ├── tests/                        # Test suites
│   └── utils/
│       ├── validate. py               # Input validation utilities
│       ├── requests. py               # HTTP request helpers
│       ├── convert_txt_to_jsonl.py   # Data conversion utilities
│       └── list_tools_script.py      # Tool discovery script
├── main.py
└── README.md
```

## Dataset Structure

The `src/dataset/` directory contains training data and tool definitions for LLM fine-tuning and testing:

### LLM Service (`src/dataset/LLM-service/`)

An integrated service that processes tool responses using Ollama to generate human-readable answers. 

- **`main.py`** - Python service that: 
  - Takes user requests, tool calls, and tool responses
  - Formats them using a predefined prompt template
  - Sends to Ollama (llama3.1:8b model)
  - Returns structured JSON responses

- **`docker-compose.yml`** - Docker configuration for running Ollama backend
  - Exposes port 11434 for API access
  - Persistent model storage
  - Optional GPU acceleration support

### Seeds Directory (`src/dataset/seeds/`)
Contains conversation examples demonstrating tool usage patterns:  

Each JSONL file contains multiple seeds, where each seed is composed of a sequence of messages with predefined roles: 

```json
{
  {
    "content": ".. .",
    "role": "user"
  },
  {
    "content": "...",
    "role": "assistant"
  },
  {
    "content": "...",
    "role": "tool"
  }
}
```

#### Purpose

The seeds are used to build the training dataset for fine-tuning a language model to perform tool-calling. 

For each seed: 

- A user prompt is defined. 
- The corresponding tool call is executed and recorded.
- The response returned by the tool is appended to the seed. 
- The collected data is sent to the LLM service, which generates the final model response according to a predefined template.

#### Output Location

The generated training data is stored at: 

```
src/dataset/tool_train_set
```

### MCP Tools Directory (`src/dataset/mcp_tools/`)

- **`tool_list.jsonl`** - Structured tool definitions in MCP format
  - Function schemas for all available tools
  - Parameter specifications and requirements
  - Ready for LLM integration and fine-tuning

These datasets can be used for: 
- Training AI agents to use threat intelligence tools
- Testing tool-calling capabilities
- Creating conversation examples for security analysts
- Fine-tuning models for cybersecurity workflows

## Getting Started

### Prerequisites

- Python 3.8 or higher
- Docker and Docker Compose (for LLM service)
- API keys for the services you want to use

### Installation

1. Clone the repository:
```bash
git clone https://github.com/avivjac/Tool-Calling-IBM.git
cd Tool-Calling-IBM
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Create a `.env` file in the root directory with your API keys:  
```env
# API-based tools
VIRUSTOTAL_API_KEY=your_virustotal_api_key
XFORCE_API_KEY=your_xforce_api_key
XFORCE_API_PASSWORD=your_xforce_password
URLSCAN_API_KEY=your_urlscan_api_key
ALIENVAULT_OTX_API_KEY=your_alienvault_api_key

# Database tools
NIST_API_KEY=your_nist_api_key
ABUSELPDB_API_KEY=your_abuseipdb_api_key
```

4. (Optional) Set up the LLM service:
```bash
cd src/dataset/LLM-service
docker-compose up -d
```

This will start the Ollama backend on `http://127.0.0.1:11434`

### Required Dependencies

```
httpx
mcp
python-dotenv
requests
```

## Usage

### Running MCP Servers

This framework uses the Model Context Protocol (MCP) architecture.  To use the tools, you need to run an MCP server for the provider you want to use.

#### Starting an MCP Server

1. Navigate to the provider directory:
```bash
cd src/server/providers/API_tools
# or
cd src/server/providers/DB_tools
```

2. Run the MCP server for your chosen provider:
```bash
# Example:  VirusTotal
mcp dev virusTotal.py

# Example: X-Force
mcp dev Xforce. py

# Example:  NIST
cd ../DB_tools
mcp dev NIST.py
```

The MCP server will start and expose the available tools through the MCP protocol.

#### Connecting to the MCP Server

Once the server is running, you can connect to it using an MCP client and call the available functions.  The server exposes all the tools defined in that provider. 

Example workflow: 
1. Start the MCP server (e.g., `python virusTotal.py`)
2. The server registers all available tools (e.g., `Get_an_IP_address_report`, `Get_a_URL_report`)
3. Connect your MCP client to the server
4. Call the tools with appropriate parameters

## Example For Available Tools

### API-Based Tools

#### VirusTotal
- IP address reports and rescans
- URL and domain reputation checks
- Comments retrieval
- Related objects queries
- File analysis
- MITRE ATT&CK tactic and technique lookups

#### IBM X-Force
- Collection management
- STIX markup export
- Public collections access
- Threat intelligence queries

#### URLscan.io
- URL scanning with customization
- Scan result retrieval
- API quota management

#### AlienVault OTX
- File submission
- Threat intelligence queries
- Indicator analysis

### Database Tools

#### NIST NVD
- CVE (Common Vulnerabilities and Exposures) lookup
- Search by CVE ID, CPE, keyword, or date range
- Filter by CVSS severity (v2, v3, v4)
- Filter by CWE (Common Weakness Enumeration)
- Access to KEV (Known Exploited Vulnerabilities) catalog
- CERT alerts and notes filtering
- OVAL (Open Vulnerability Assessment Language) data

## Validation Features

The framework includes comprehensive validation for: 
- IPv4 and IPv6 addresses
- Domain names (RFC compliant)
- URLs (HTTP/HTTPS)
- Email addresses
- File hashes (MD5, SHA1, SHA256)
- CVE identifiers
- CPE (Common Platform Enumeration) strings

## Logging

All API interactions and validations are logged for auditing and debugging:  
- `VitusTotal. log` - VirusTotal API calls
- `Xforce_log.log` - X-Force API calls
- `URLscan_log.log` - URLscan API calls
- `NIST_log.log` - NIST NVD API calls
- `AbuseIPDB_log.log` - AbuseIPDB API calls
- `validate. log` - Validation operations
- `requests_log.log` - HTTP request logs

## Use Cases

- **Threat Intelligence Gathering**: Aggregate threat data from multiple sources
- **Security Incident Response**: Quick lookup of IOCs (Indicators of Compromise)
- **Vulnerability Management**: Track and monitor CVEs affecting your infrastructure
- **IP Reputation Analysis**: Check if IPs are associated with malicious activity
- **Automated Security Workflows**: Integrate with SOAR platforms
- **Research and Analysis**: Security research and threat hunting operations
- **AI/LLM Training**: Fine-tune models for cybersecurity tool-calling capabilities
- **Security Analyst Training**: Use conversation seeds as training examples

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.  

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [VirusTotal](https://www.virustotal.com/) for threat intelligence API
- [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/) for threat data
- [URLscan.io](https://urlscan.io/) for URL analysis
- [AlienVault OTX](https://otx.alienvault.com/) for open threat intelligence
- [NIST NVD](https://nvd.nist.gov/) for vulnerability data
- [AbuseIPDB](https://www.abuseipdb.com/) for IP reputation data
- [MITRE ATT&CK](https://attack.mitre.org/) for adversary tactics and techniques framework
- [MCP (Model Context Protocol)](https://github.com/anthropics/mcp) for the framework
- [Ollama](https://ollama.ai/) for local LLM inference

## Contact

Aviv Jacubovski - [@avivjac](https://github.com/avivjac)  
  avivj2012@gmail.com

Stav Ozeri - [@StavOzeri](https://github.com/StavOzeri)  
  stavozeri@gmail.com

Project Link: [https://github.com/avivjac/Tool-Calling-IBM](https://github.com/avivjac/Tool-Calling-IBM)

---

**Note**: Make sure to keep your API keys secure and never commit them to version control. Always use environment variables or secure secret management systems.  
