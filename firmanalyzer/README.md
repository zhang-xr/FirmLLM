# FirmAnalyzer - Intelligent Firmware Analysis System

## System Architecture

```mermaid
sequenceDiagram
    participant User
    participant Runner
    participant Explorer
    participant Analyzer
    participant Tools
    participant LLMAssistant
    
    User->>Runner: Input firmware & custom prompts
    Note over Runner: Load prompts from YAML
    Runner->>Runner: Extract & locate root
    Runner->>Explorer: Start exploration
    
    loop Directory Analysis
        Explorer->>Explorer: Scan directory content
        Explorer->>Analyzer: Assign analysis tasks
        
        par Parallel Analysis
            Analyzer->>Tools: Binary analysis
            Tools-->>Analyzer: Raw findings
            
            Analyzer->>LLMAssistant: Risk assessment
            LLMAssistant-->>Analyzer: Security evaluation
            
            Analyzer->>Tools: Configuration check
            Tools-->>Analyzer: Config issues
        end
        
        Analyzer-->>Explorer: Analysis results
        Explorer->>Explorer: Summarize findings
        Note over Explorer: Make next decision
        Explorer->>Explorer: Select next target
    end
    
    Explorer-->>User: Security report
```

## Core Components

### Main Components
- **main.py** - System entry point and orchestration
- **explore.py** - Firmware filesystem exploration engine
- **analyze.py** - File analysis and security assessment core

### Configuration
- **requirements.yaml**
  - File type definitions and analysis rules
  - Priority directory configurations
  - Security severity criteria
  - Analysis workflow specifications

## Requirements
- Python 3.8+
- radare2 5.9.9 



