# FirmLLM - A Large Language Model-based Multi-Agent System for Large-scale Firmware Collection and Analysis

FirmLLM is an integrated system that combines firmware collection and analysis functions, leveraging large language models (LLM) for intelligent firmware analysis. The system consists of two core modules: the firmware collection system (FirmCrawler) and the firmware analysis system (FirmAnalyzer). Both systems adopt a multi-agent collaborative approach based on user-defined prompts, enabling autonomous exploration and analysis, and can solve long-cycle complex tasks.


## System Components

### 1. Firmware Collection System (FirmCrawler)

	**firmcrawler** is a multi-agent collaborative system for large-scale firmware crawling, optimized from [WebVoyager](https://langchain-ai.github.io/langgraph/tutorials/web-navigation/web_voyager/) ([Paper](https://arxiv.org/abs/2401.13919)). Inheriting WebVoyager's core capabilities, it leverages a Large Multimodal Model (LMM) to achieve end-to-end web interaction tasks, including visual perception, natural language understanding, and sequential decision-making. Tailored for firmware collection scenarios, the system enhances webpage navigation strategies and data extraction logic, enabling automated traversal of vendor websites, firmware identification, and download. It serves IoT security research, firmware vulnerability discovery, and device supply-chain analysis.

#### Main Features
- Automated web interaction
- Intelligent information collection
- Multi-agent collaboration for parallel crawling
- Distributed task scheduling

#### Core Files
- `crawler.py`: Core crawler implementation based on WebVoyager
- `web_intrect.py`: Web interaction module
- `mark_page.js`: Page marking script
- `prompt.yaml`: Vendor-specific customized prompts for intelligent crawling

### 2. Firmware Analysis System (FirmAnalyzer)

`firmanalyzer` provides comprehensive firmware security analysis capabilities.

#### Main Features
- Firmware unpacking and filesystem identification
- Static analysis and vulnerability detection
- Binary analysis
- CVE vulnerability matching
- Security risk assessment

#### Core Files
- `run.py`: System entry point
- `explore.py`: Firmware exploration
- `analyze.py`: Firmware file analysis
  - Shell Command Executor: Support for strings, grep, and other Linux tools
  - CVE Query Tool: Support for API interface queries
  - Disassembly Assistant: Integration with radare2 and LLM
  - Sensitive Information Pattern Matching: Code pattern recognition based on regex and semantics
- `requirements.yaml`: Analysis configuration file
  - File Requirements: Defines target file types and components for analysis
  - Directory Requirements: Specifies priority directories and analysis areas
  - Analysis Requirements: Configures security analysis workflow and severity criteria
  - Report Templates: Customizable templates for security reports and summaries

The requirements.yaml allows users to customize:
- Analysis scope and target components
- Directory scanning priorities
- Security analysis strategies
- Risk severity classifications
- Report and summary formats

### 3. Analysis Result Samples

`Examples` contains analysis results using DeepSeek-v3 and DeepSeek-r1 models.

#### Analysis Logs and Reports
- `explore.log`: Complete firmware analysis process example
- `report.txt`: Detailed security analysis report by file
- `summary.txt`: Overall firmware security issues summary and risk level assessment

## Notes

1. Analysis results are for research reference only
2. Please comply with relevant laws and regulations
3. Verification in test environment is recommended
