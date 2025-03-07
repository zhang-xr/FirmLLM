import os
import magic
import re
import json
import logging
import subprocess
from typing import TypedDict, List, Optional, Tuple
from langchain_core.messages import BaseMessage
from langgraph.graph import END, START, StateGraph
from langchain_core.messages import BaseMessage, AIMessage, SystemMessage,HumanMessage
import magic
from langchain.prompts.chat import (
    ChatPromptTemplate,
    MessagesPlaceholder,
    SystemMessagePromptTemplate,
)
from langchain_core.runnables import RunnableLambda
from langchain_core.prompts import PromptTemplate
from disassembly import R2Analyzer
from R2decetor import R2VersionDetector
from securityscan import SecurityScanner
from CVEsearch import query_nvd_and_mitre
from llm_config import LLMClient
from callback import TokenUsageCallbackHandler
from tools import BinaryAnalyzer
from utils import check_real_permissions, parse_analysis_response
from firmanalyzer.LogManage import LogManager

analysis_logger = LogManager.get_logger('Analyzer')

llm_client = LLMClient()  # Use 'config.ini' by default

class FThought(TypedDict):
    findings: str
    reason: str
    next_step: str
    severity: str

class FResponse(TypedDict):
    thought: FThought
    command: str
    status: str

class FAgentState(TypedDict):
    input: str                          
    file: str                       
    current_dir: str                    
    response: FResponse                 
    scratchpad: List[BaseMessage]       
    observation: str      
    save_path: str


def format_file_description(state):
    """Format the description information of a single file and add it to the history"""
    file_path = state['file']
    try:
        file_stat = os.stat(file_path)
        file_type = magic.from_file(file_path)
        mime_type = magic.from_file(file_path, mime=True)
        real_perms = check_real_permissions(file_path)
        
        # Build basic file information
        file_info = [
            "[Basic Information]",
            f"Name: {os.path.basename(file_path)}",
            f"Size: {file_stat.st_size} bytes",
            f"Type: {file_type}",
            f"MIME: {mime_type}"
        ]
        
        if real_perms and real_perms.strip():
            file_info.append(f"Permissions: {real_perms}")

        # Sensitive information analysis for all file types
        sensitive_results = {}
        try:
            bin_analyzer = BinaryAnalyzer(file_path)
            sensitive_results = bin_analyzer.analyze_sensitive_info()
        except Exception as e:
            file_info.append(f"\n[Sensitive Analysis Error] {str(e)}")

        # Binary file specific analysis
        is_binary = ('ELF' in file_type 
                    or 'executable' in file_type.lower() 
                    or 'binary' in mime_type)
        
        if is_binary:
            try:
                # R2 version detection
                r2_detector = R2VersionDetector()
                version_info = r2_detector.detect_version(file_path)
                if version_info:
                    file_info.append("\n[Potential Version Detection From R2(Need to be verified)]")
                    for v_info in version_info[:5]:  # Show top 5 most reliable results
                        file_info.append(
                            f"- {v_info['version']} "
                            f"(Confidence: {v_info['confidence']:.2f})"
                        )
            except Exception as e:
                file_info.append(f"\n[Version Analysis Error] {str(e)}")

            try:
                # Full binary analysis
                bin_report = bin_analyzer.full_analysis()
                
                # Version information (backwards compatible)
                if bin_report.get('versions'):
                    file_info.append("\n[Potential Embedded Version Strings(Need to be verified)]")
                    for ver in bin_report['versions'][:20]:
                        file_info.append(f"- {ver}")
                
                # ELF section analysis
                if bin_report.get('elf_sections'):
                    file_info.append("\n[ELF Structure Analysis(Need to be verified)]")
                    for section, content in bin_report['elf_sections'].items():
                        file_info.append(f"- {section}: {len(content)} valid strings")
                        
            except Exception as e:
                file_info.append(f"\n[Binary Analysis Error] {str(e)}")

        # Unified sensitive information display (all file types)
        if sensitive_results:
            file_info.append("\n[Potential Sensitive Content Detection(Need to be verified)]")
            for category, items in sensitive_results.items():
                if items:
                    file_info.append(f"\n{category.upper()} ({len(items)} found):")
                    for item in items[:10]:  # Show up to 10 items per category
                        # Data masking
                        sanitized = re.sub(r'(key|token|password)=[\w-]+', r'\1=******', item)
                        truncated = sanitized[:75] + '...' if len(sanitized) > 75 else sanitized
                        file_info.append(f"  - {truncated}")
                    if len(items) > 10:
                        file_info.append(f"  - ...and {len(items)-10} more")

        file_info_str = "\n".join(file_info)
        analysis_logger.info(file_info_str)
            
        return {**state, "file_info": file_info_str}
        
    except Exception as e:
        error_msg = f"File analysis failed {file_path}: {str(e)}"
        analysis_logger.error(f"[File Description Formatting] {error_msg}", exc_info=True)
        return {**state, "file_info": error_msg}

analysis_system_template = """You are a firmware security analysis expert. You need to appropriately explore to determine if there are security issues in the currently specified file. You must strictly follow the specified JSON format for output, without adding any other content.

**Output Format**:
{{
    "thought": {{
        "findings": "string",     
        "severity": "number",     
        "reason": "string",       
        "next_step": "string"     
    }},
    "command": 'string',     
    "status": "string"            
}}

Field definitions:
- thought.findings: Avoid repeating existing findings, point out new specific security issues found, if not found, use "none"
- thought.severity: Severity ratings must be based on the rating criteria, version exposure are level 3,if there is no new findings,use 0
- thought.reason: Avoid vague descriptions, point out specific content clearly，do not omitted(code,config,sensitive data,CVE,etc). 
- thought.next_step: If further analysis is needed, explain the next analysis idea
- command: The specific command to execute next, use "none" if analysis is complete
- status: Analysis status: "continue" to continue analysis, "complete" when analysis is finished

{input}

Currently known file information:
{file_info}
Only analyze this file, do not analyze other files, other files will be analyzed later. Do not make any assumptions about other files. Background Information: The files to be analyzed are extracted from firmware using binwalk.

**Available command list**
1. Basic analysis:
   - strings <file> | grep -i "pattern": Extract and filter strings in files
   - strings <file> | grep -iE "pattern": Use regular expressions to filter

2. Text search:
   - strings <file> | grep -n -A 3 -B 3 "pattern": Search with line numbers and context 
   
3. View file content:
   - cat <file>: View full file content 
   - head -n N <file>: View first N lines of file (N=50-500, default 100 recommended)
   - tail -n N <file>: View last N lines of file (N=50-500, default 100 recommended)
   - sed -n 'N,Mp' <file>: View specified line range (N,M recommended range <=500 lines)

4. Version analysis:
   - strings <file> | grep -iE "version|v[0-9]"
   - readelf -d <file>  # Check dynamic segment info, fairly reliable
   - readelf -h <file>  # Check ELF header info, available in most cases

5. Vulnerability search:
   - vulnsearch <name> <version>: Search for all related CVE vulnerabilities(one component per search)   Example: vulnsearch busybox 1.36.1
    When analyzing results:
    - Only include CVEs where the vulnerable version range INCLUDES the target version
    - Exclude CVEs that affect versions BEFORE the target version
    - List all CVEs that affect the target version do not omit any

6. Function analysis:
   - disassembly <file>: Start disassembly mode to check for function calls (limited to one use,for executable and shared library you should use this tool)
    Example: disassembly busybox

**Notes**
1. Environment: Already in the directory of the file, execute commands directly, no need to change directory
2. Analysis process: Execute one command at a time → Decide the next step based on context
3. Output specification: Concretize findings → Avoid vague descriptions → Point out specific content
4. If the output result is too long, it will automatically switch to user-defined security scan mode
5. Command usage: Avoid using the same command consecutively → Try different approaches for analysis
6. Completion condition: Necessary steps completed + Analysis complete = complete

"""

analysis_prompt = ChatPromptTemplate(
messages=[
    SystemMessagePromptTemplate(
    prompt=[
        PromptTemplate.from_template(analysis_system_template),
    ],
    ),
    MessagesPlaceholder(
    optional=True,
    variable_name="scratchpad",
    ),
],
input_variables=[
    "file_info",
    "input",
],
partial_variables={"scratchpad":[]},
)


def retry(state: FAgentState) -> str:
    """Retry operation, return state with error information"""
    analysis_logger.warning("Retrying operation")
    return "Error: Answer format is incorrect, please strictly follow the JSON format"

def save_message_history(state: FAgentState, message_type: str, content: str):
    """Generic message history recording function"""
    save_path = state.get('save_path', '')
    history_file = os.path.join(save_path, 'analysis_history.json')
    
    try:
        os.makedirs(save_path, exist_ok=True)
        if os.path.exists(history_file):
            with open(history_file, 'r', encoding='utf-8') as f:
                history = json.load(f)
        else:
            history = []
    except Exception as e:
        analysis_logger.error(f"[Save Message History] Failed to read history: {str(e)}")
        history = []
    
    # Add new message
    history.append({
        "type": message_type,
        "content": content
    })
    
    # Save history
    try:
        with open(history_file, 'w', encoding='utf-8') as f:
            json.dump(history, f, ensure_ascii=False, indent=2)
    except Exception as e:
        analysis_logger.error(f"[Save Message History] Failed to save history: {str(e)}")


def vulnsearch(query: str, save_path: str) -> str:
    """Execute vulnerability search and return results"""
    try:
        analysis_logger.info(f"[VulnSearch] Starting vulnerability search for: {query}")
        results = query_nvd_and_mitre(query, save_path=save_path)

        if results and "analyzed_results" in results:
            return results["analyzed_results"]
        else:
            return "No vulnerabilities found or analysis failed"

    except Exception as e:
        analysis_logger.error(f"[VulnSearch] Vulnerability search error: {str(e)}")
        return f"Error performing vulnerability search: {str(e)}"

def execute_shell(state: FAgentState) -> str:
    """Execute shell command, including vulnerability search"""
    command = state["response"]["command"]
    
    try:
        # Define allowed command whitelist
        ALLOWED_COMMANDS = [
            r"^strings.*",
            r"^grep.*", 
            r"^cat.*",
            r"^head.*",
            r"^tail.*",
            r"^sed -n.*",
            r"^readelf.*",  # Allow all readelf commands
            r"^file.*",
            r"^vulnsearch.*", 
            r"^disassembly.*",
            r"^\./[^/]+\s+(?:--version|-v|--help|-h)?$"
        ]
        
        try:
            # Validate command whitelist
            if not any(re.match(pattern, command) for pattern in ALLOWED_COMMANDS):
                raise ValueError("Command not allowed. Please use only permitted commands.")
                
            # Handle vulnsearch command
            if command.startswith("vulnsearch"):
                query = command[10:].strip().strip('"')
                result = vulnsearch(query, state['save_path'])
                save_message_history(state, "vulnsearch", result)
                return f"Vulnerability search results: {result}"
                
            # Execute command directly
            result = subprocess.check_output(
                command,
                shell=True,
                cwd=state['current_dir'],
                stderr=subprocess.STDOUT,
                timeout=30
            ).decode('utf-8', errors='ignore')
            
            # If result exceeds threshold, switch to security scan mode
            if len(result) > 8192:
                original_command = command
                command = "security_scan"
                analysis_logger.info("[Execute Shell] Result too long, switching to security scan mode")
                scanner = SecurityScanner()
                scan_results = scanner.scan_file(state['file'])

                result = f"Security scan results: Original command '{original_command}' output too long, switched to security scan:\n"
                for item in scan_results:
                    if 'error' in item:
                        result += f"Error: {item['error']}\n"
                    else:
                        result += f"- Found {item['type']}: {item['line_content']}"
                        if 'line_number' in item:
                            result += f" at line {item['line_number']}"
                        result += "\n"
            else:
                # Add command identifier for normal commands
                result = f" Command: {command}\nCommand output:\n{result}"
                
            analysis_logger.debug(f"[Execute Shell] Command output:\n{result}")
            
            # Record tool execution result
            save_message_history(state, "shell", result)
            
            return result
                
        except Exception as e:
            analysis_logger.error(f"[Execute Shell] Failed: {str(e)}")
            error_msg = f" Command: {command}\nCommand output:\n{str(e)}"
            analysis_logger.error(error_msg)
            save_message_history(state, "shell", error_msg)
            return error_msg
        
    except Exception as e:
        analysis_logger.error(f"[Execute Shell] Processing failed: {str(e)}")
        return f"Error: {str(e)}"

def disassembly(state: FAgentState) -> str:
    """Start disassembly analysis and return JSON string"""
    analysis_logger.info(f"[Disassembly]{state['file']}")
    try:
        # Get analysis history
        history_file = os.path.join(state['save_path'], 'analysis_history.json')
        analysis_history = []
        if os.path.exists(history_file):
            with open(history_file, 'r', encoding='utf-8') as f:
                analysis_history = json.load(f)
        
        # Define available dangerous functions
        dangerous_functions = {
            "system", "popen",           
            "strcpy", "strcat", "gets", 
            "sprintf", "snprintf", "sscanf",
            "memcpy",                 
            "fprintf",                
            "setuid",                    
            "recv"                       
        }
        
        # Prepare prompt for LLM to analyze history
        analysis_prompt = """Based on the analysis history, identify which of the following dangerous functions need to be analyzed for potential vulnerabilities.

Available dangerous functions:
1. Command Injection: system, popen
2. Buffer Overflow: strcpy, strcat, gets, sprintf, sscanf
3. Memory Corruption: memcpy
4. Format String: fprintf
5. Privilege Escalation: setuid
6. Network Input: recv

Please select ONLY the most critical functions based on the analysis history. Do not select all functions by default.Quality over quantity - it's better to focus deeply on a few high-risk functions than to superficially analyze many.

Analysis history:
{history}

Output format:
'''
{{
    "target_functions": ["function1", "function2",...],
    "reason": "Explanation of why these functions were selected"
}}
'''
Note: Only select functions from the provided list above. Do not include any other functions."""

        # Get LLM analysis
        token_usage_path = os.path.join(state['save_path'], "token_usage.jsonl")
        token_callback = TokenUsageCallbackHandler(token_usage_path)
        llm_client.set_callbacks([token_callback])
        
        llm_response = llm_client.invoke([
            SystemMessage(content=analysis_prompt.format(
                history=json.dumps(analysis_history, indent=2)
            ))
        ])
        
        try:
            # Extract JSON from LLM response
            # Look for JSON pattern between triple backticks if present
            json_match = re.search(r'```(?:json)?\s*({[\s\S]*?})\s*```', llm_response)
            if json_match:
                json_str = json_match.group(1)
            else:
                # If no backticks, try to find JSON directly
                json_match = re.search(r'({[\s\S]*})', llm_response)
                if json_match:
                    json_str = json_match.group(1)
                else:
                    raise ValueError("No JSON found in response")

            # Parse and validate JSON structure
            try:
                target_functions = json.loads(json_str)
                
                # Validate JSON structure
                if not isinstance(target_functions, dict):
                    raise ValueError("Response must be a dictionary")
                if "target_functions" not in target_functions:
                    raise ValueError("Missing 'target_functions' key")
                if "reason" not in target_functions:
                    raise ValueError("Missing 'reason' key")
                if not isinstance(target_functions["target_functions"], list):
                    raise ValueError("'target_functions' must be a list")
                if not isinstance(target_functions["reason"], str):
                    raise ValueError("'reason' must be a string")
                
                # Validate functions against predefined list
                validated_functions = [
                    func for func in target_functions['target_functions'] 
                    if func in dangerous_functions
                ]
                
                if validated_functions:
                    analysis_logger.info(f"[Disassembly] Target functions identified: {validated_functions}")
                    target_functions['target_functions'] = validated_functions
                else:
                    analysis_logger.warning("[Disassembly] No valid dangerous functions identified, will analyze all dangerous functions")
                    target_functions['target_functions'] = list(dangerous_functions)
                    target_functions['reason'] = "No specific dangerous functions identified from history, analyzing all"
                
            except json.JSONDecodeError as e:
                analysis_logger.error(f"[Disassembly] JSON parsing error: {str(e)}")
                raise ValueError(f"Invalid JSON format: {str(e)}")
                
        except Exception as e:
            analysis_logger.warning(f"[Disassembly] Failed to parse LLM response: {str(e)}, will analyze all dangerous functions")
            target_functions = {
                "target_functions": list(dangerous_functions),
                "reason": "Failed to identify specific functions, analyzing all dangerous functions"
            }

        # Use multiprocessing to implement timeout mechanism 
        from multiprocessing import Process, Queue

        def analyze_with_timeout(file_path: str, result_queue: Queue, target_funcs: List[str]):
            try:
                analyzer = R2Analyzer(
                    file_path, 
                    state['save_path'],
                    max_analysis_count=20,
                    timeout_seconds=1800,
                    command_timeout=90,
                    max_iterations=8,
                    target_functions=target_funcs # Pass target functions to analyzer
                )
                result = analyzer.analyze_binary()
                result_queue.put(result)
            except Exception as e:
                result_queue.put(f"Error: {str(e)}")

        result_queue = Queue()
        p = Process(
            target=analyze_with_timeout, 
            args=(state['file'], result_queue, target_functions['target_functions'])
        )
        p.start()
        
        # Wait for 15 minutes
        p.join(timeout=900)
        
        if p.is_alive():
            p.terminate()
            p.join()
            raise TimeoutError("Disassembly analysis timeout")
            
        if not result_queue.empty():
            result = result_queue.get()
            analysis_logger.info("[Disassembly] Success")
            if isinstance(result, str) and result.startswith("Error:"):
                raise Exception(result)
                
            # Ensure result is JSON string
            if not isinstance(result, str):
                result = json.dumps(result, ensure_ascii=False, indent=2)
                
            # Record disassembly result
            result = f"Disassembly Analysis Result:\n{result}"
            save_message_history(state, "disassembly", result)
            
            return result
        else:
            raise Exception("Disassembly analysis did not return result")
            
    except TimeoutError as e:
        error_msg = str(e)
        analysis_logger.error(f"[Disassembly] Timeout: {error_msg}")
        save_message_history(state, "disassembly", f"⏰ {error_msg}")
        return json.dumps({
            "findings": "Analysis timeout",
            "severity": "0",
            "reason": f"Disassembly analysis timeout: {error_msg}",
            "next_step": "Suggest retry or reduce analysis scope"
        }, ensure_ascii=False)
        
    except Exception as e:
        error_msg = f"Disassembly analysis error: {str(e)}"
        analysis_logger.error(f"[Disassembly] Failed: {error_msg}")
        save_message_history(state, "disassembly", f"❌ {error_msg}")
        return json.dumps({
            "findings": "Analysis error",
            "severity": "0",
            "reason": error_msg,
            "next_step": "Need to check error and retry"
        }, ensure_ascii=False)

def update_analysis_scratchpad(state: FAgentState) -> FAgentState:
    """Update analysis history, only process scratchpad"""
    observation = state.get('observation', '')
    analysis_logger.info(f"[Update] Observation: {observation}")
    current_scratchpad = state.get('scratchpad', [])
    
    # Original scratchpad processing logic
    previous_ai_messages = [msg for msg in current_scratchpad if isinstance(msg, AIMessage)]
    new_scratchpad = [
        *previous_ai_messages,
        AIMessage(content=f"{state['response']}")
    ]
    new_scratchpad.append(HumanMessage(content=observation))
    analysis_logger.info("[Update] Scratchpad updated")
    return {
        **state,
        "scratchpad": new_scratchpad
    }

def select_analysis_next_action(state: FAgentState) -> str:
    """Decide next action based on status and command"""
    try:
        status = state["response"]["status"]
        command = state["response"]["command"]
        save_message_history(state, "AI", state["response"])
        analysis_logger.info(f"[Status] {status}, [Command]: {command}")

        # 1. Handle complete status
        if status == "complete":
            analysis_logger.info("[Action] Analysis complete")
            return END
            
        # 2. Handle continue status
        elif status == "continue":
            if command == "retry":
                return "retry"
            elif command.startswith("disassembly"):
                return "disassembly"
            else:
                return "execute_shell"
                
    except Exception as e:
        analysis_logger.error(f"[Action] Error getting status or command: {str(e)}")
        return "retry"

# First define a function to wrap agent behavior
def AnalysisNode(state: FAgentState) -> FAgentState:
    """Node function to wrap agent behavior"""
    logging.info(f"[Analysis Node] Processing file: {state['file']}")
    
    try:
        # 1. Format file description
        state_with_info = format_file_description(state)
        
        # 2. Prepare prompt
        messages = analysis_prompt.format_messages(
            file_info=state_with_info["file_info"],
            input=state["input"],
            scratchpad=state.get("scratchpad", [])
        )
        token_usage_path = os.path.join(state['save_path'], "token_usage.jsonl")
        token_callback = TokenUsageCallbackHandler(token_usage_path)
        llm_client.set_callbacks([token_callback])

        response = llm_client.invoke(messages)
        print(response)
        parsed_response = parse_analysis_response(response)
        # Record AI message
        
        # Fix: Correct dictionary merge syntax
        return {
            **state,  # Base state first
            "input": state["input"],
            "file": state["file"],
            "current_dir": state["current_dir"],
            "response": parsed_response,
            "scratchpad": state.get("scratchpad", []),
            "observation": state.get("observation", ""),
        }
        
    except Exception as e:
        logging.error(f"[Analysis Node] Processing failed: {str(e)}")
        return {
            **state,
            "response": {
                "thought": "Error response format",
                "action": "retry"
            },
            "observation": f"Error: {str(e)}",
        }

# Modify graph building part
def build_analysis_graph():
    """Build workflow graph"""
    analysis_logger.info("[Build] Building analysis workflow graph")
    graph_builder = StateGraph(FAgentState)
    
    # 1. Add all nodes
    graph_builder.add_node("agent", AnalysisNode)
    graph_builder.add_node("update_analysis_scratchpad", update_analysis_scratchpad)
    
    # 2. Add start edge
    graph_builder.add_edge(START, "agent")
    
    # 3. Add conditional edges
    graph_builder.add_conditional_edges(
        "agent",
        select_analysis_next_action,
        {
            "execute_shell": "execute_shell",
            "disassembly": "disassembly",
            "retry": "retry",
            END: END
        }
    )
    tools = {
        "execute_shell": execute_shell,
        "disassembly": disassembly,
        "retry": retry,
    }

    for node_name, tool in tools.items():
        graph_builder.add_node(
            node_name,
            RunnableLambda(tool) | (lambda observation: {"observation": observation}),
        )
        graph_builder.add_edge(node_name, "update_analysis_scratchpad")
    
    # 5. Add edge from update scratchpad back to agent
    graph_builder.add_edge("update_analysis_scratchpad", "agent")
    
    analysis_logger.info("[Build] Success")
    return graph_builder.compile()

# Use new graph building method
analysis_graph = build_analysis_graph()

def analyzer(state: FAgentState, graph, max_steps=30):
    """Main function to run agent"""
    analysis_logger.info(f"[Analyzer] {state['file']}")
    
    try:
        save_path = os.path.normpath(state['save_path'])
        if not os.path.exists(save_path):
            try:
                os.makedirs(save_path)
                analysis_logger.info(f"[Analyzer] Created directory: {save_path}")
            except Exception as e:
                analysis_logger.error(f"[Analyzer] Failed to create directory: {str(e)}")
                return None
                
        analysis_logger.info("[Analyzer] Success")
        analysis_logger.debug(f"[Analyzer] Initial state: {state}")
        
        # Only save last thought
        final_thought = None
        
        event_stream = graph.stream(
            state,
            {"recursion_limit": max_steps},
        )
        
        for event in event_stream:
            try:
                # Update last thought
                if "agent" in event:
                    response = event["agent"].get("response", {})
                    if "thought" in response:
                        final_thought = response["thought"]
                        analysis_logger.info("[Analyzer] Updated final thought")
                
                if END in event:
                    break
                    
            except Exception as e:
                analysis_logger.error(f"[Analyzer] Error processing event: {str(e)}")
                continue
                
    except Exception as e:
        analysis_logger.error(f"[Analyzer] Failed: {str(e)}")
    
    finally:
        # Print final thought content
        if final_thought:
            analysis_logger.info("[Analyzer] Completed with final thought")
            
            try:
                # Prepare result data
                from datetime import datetime
                result_data = {
                    "timestamp": datetime.now().strftime("%d %H:%M"),
                    "file_path": state["file"],
                    "file_name": state["file"].split("/")[-1],
                    "analysis_result": final_thought,
                    "max_steps": max_steps
                }
                
                # Save as JSON file
                result_file = os.path.join(save_path, "analysis_result.json")
                
                try:
                    # Ensure directory exists
                    os.makedirs(os.path.dirname(result_file), exist_ok=True)
                    
                    # Write to file
                    import json
                    with open(result_file, "w", encoding='utf-8') as f:
                        json.dump(result_data, f, ensure_ascii=False, indent=2)
                    analysis_logger.info(f"\n💾 [Result] {result_file}")
                    
                except PermissionError:
                    analysis_logger.error(f"\n❌ [Save] Failed: No write permission: {result_file}")
                except OSError as e:
                    analysis_logger.error(f"\n❌ [Save] Failed: Error creating directory or file: {str(e)}")
                except Exception as e:
                    analysis_logger.error(f"\n❌ [Save] Failed: Unknown error: {str(e)}")
                    
            except Exception as e:
                analysis_logger.error(f"\n❌ [Save] Failed: {str(e)}")
    
    return final_thought





