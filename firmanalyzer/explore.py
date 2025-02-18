import re
import json
import logging
import magic
import os
from langgraph.graph import END, START, StateGraph
from langchain.prompts.chat import (
    ChatPromptTemplate,
    MessagesPlaceholder,
    SystemMessagePromptTemplate,
)
from langchain_core.messages import BaseMessage, AIMessage, SystemMessage, HumanMessage
from langchain_core.runnables import RunnableLambda, RunnablePassthrough
from langchain_core.runnables import chain as chain_decorator
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import PromptTemplate
from typing_extensions import TypedDict, List, Literal, Optional, Union
from analyze import LLMClient, analysis_graph
from tenacity import retry, stop_after_attempt, stop_after_delay, wait_exponential
from callback import TokenUsageCallbackHandler
from utils import check_real_permissions,parse_file_selection,parse_directory_selection,parse_directory_removal

def get_logger(name):
    return logging.getLogger(name)

explorer_logger = get_logger('Explorer')
analyzer_logger = get_logger('Analyzer')

llm_client = LLMClient()

class FileDescription(TypedDict):
    name: str
    path: str
    type: str
    size: int
    permissions: Optional[str]
    is_directory: bool

class Thought(TypedDict):
    file: str
    reason: str

class Response(TypedDict):
    thought: Thought
    action: str

class Requirements(TypedDict):
    file_findings_requirements: str
    security_report_template: str
    summary_template: str
    directory_requirements: str
    file_requirements: str

class DirInfo(TypedDict):
    files: List[FileDescription]
    index: int
    dir_path: str

class AgentState(TypedDict):
    input: Requirements
    current_dir: str
    base_path: str
    dir_data: DirInfo
    dir_stack: List[str]
    response: Response
    scratchpad: List[BaseMessage]
    observation: str
    security_report_summary: str
    save_path: str

@chain_decorator
def list_dir(current_dir):
    sub_dirs = []
    file_descriptions = []
    explorer_logger.info(f"[Scan] Scanning directory: {current_dir}")
    try:
        with os.scandir(current_dir) as entries:
            for entry in entries:
                try:
                    file_stat = entry.stat(follow_symlinks=False)
                    if entry.is_dir(follow_symlinks=False):
                        try:
                            with os.scandir(entry.path) as sub_entries:
                                next(sub_entries, None)
                                sub_dirs.append(entry.path)
                        except (PermissionError, Exception):
                            continue
                        continue
                    
                    try:
                        file_type = magic.from_file(entry.path)
                    except Exception:
                        file_type = "unknown"
                    
                    perms = check_real_permissions(entry.path)
                    
                    file_desc = {
                        "name": entry.name,
                        "path": entry.path,
                        "type": file_type,
                        "size": file_stat.st_size,
                        "is_directory": False,
                        "permissions": perms
                    }
                    
                    file_descriptions.append(file_desc)
                    
                except PermissionError:
                    continue
                except Exception:
                    continue
                    
    except PermissionError:
        explorer_logger.warning(f"[Scan] Scan failed: Permission denied: {current_dir}")
        return {"file_descriptions": [], "sub_dirs": []}
    except Exception as e:
        explorer_logger.error(f"[Scan] Scan failed: {str(e)}")
        return {"file_descriptions": [], "sub_dirs": []}

    explorer_logger.info(f"[Scan] Scan Summary: Files: {len(file_descriptions)}")
    explorer_logger.info(f"[Scan] Scan Summary: Subdirectories: {len(sub_dirs)}")

    return {
        "sub_dirs": sub_dirs,
        "file_descriptions": file_descriptions
    }

def annotate(state: AgentState) -> AgentState:
    explorer_logger.info(f"[Annotate] Scanning directory: {state['current_dir']}")
    
    current_dir = state["current_dir"]
    dir_data = state["dir_data"]
    batch_size = 50
    
    if dir_data["dir_path"] != current_dir or not dir_data["files"]:
        explorer_logger.info(f"[Annotate] Starting new directory scan: {current_dir}")
        dir_desc = list_dir.with_retry().invoke(current_dir)
        sub_dirs = dir_desc["sub_dirs"]
        state["dir_stack"].extend(sub_dirs)
        
        explorer_logger.info(f"[Annotate] Total files found: {len(dir_desc['file_descriptions'])}")
        
        return {
            **state,
            "dir_data": {
                "files": dir_desc["file_descriptions"],
                "index": 0,
                "dir_path": current_dir
            }
        }
    
    if dir_data["index"] == -1:
        explorer_logger.info(f"[Annotate] Directory already processed: {current_dir}")
        return state
    
    explorer_logger.info(f"[Annotate] Continuing with current directory: {current_dir}")
    next_index = dir_data["index"] + batch_size
    
    if next_index >= len(dir_data["files"]):
        next_index = -1
        explorer_logger.info("[Annotate] All batches processed")
    else:
        explorer_logger.info(f"[Annotate] Moving to next batch, index: {next_index}")
    
    return {
        **state,
        "dir_data": {
            **dir_data,
            "index": next_index
        }
    }


def format_descriptions(state: AgentState) -> AgentState:
    batch_size = 50
    dir_data = state["dir_data"]
    current_index = dir_data["index"]
    all_files = dir_data["files"]
    
    current_batch = all_files[current_index : current_index + batch_size]
    
    def calculate_importance(file_desc):
        score = 0
        file_type = file_desc['type']
        file_name = file_desc['name'].lower()
        perms = file_desc.get('permissions', '')
        
        if ('ELF' in file_type or 'shared' in file_type.lower()) and 'executable' in file_type.lower():
            score += 5
        elif any(ext in file_name for ext in ['.cfg', '.ini', '.cgi', '.so', '.sh']):
            score += 3
        elif any(ext in file_name for ext in ['.sh', '.conf']):
            score += 2
            
        if perms:
            if 's' in perms:
                score += 3
            if 'x' in perms:
                score += 1
                
        important_names = {'login':4, 'busybox': 4, 'init': 4, 'http': 4, 'lighttpd': 4, 'nginx': 4, 'dropbear': 4, 'ssh': 4, 'telnetd': 4, 'dnsmasq': 4, 'hostapd': 4, 'uboot': 4, 'mtd': 4, 'passwd': 4, 'shadow': 4, 'sudoers': 4, 'zlib': 3, 'curl': 3, 'hosts': 3, 'ping': 3, 'cert': 3, 'key': 3, 'pem': 3, 'iptables': 3, 'firewall': 3, 'acl': 3, 'resolv': 3, 'interfaces': 3, 'wpa': 3, 'table': 3, 'dhcpd': 3, 'my': 3, 'nvram': 3, 'dns': 3, 'opkg': 3, 'ubnt': 3, 'flash': 3,'util': 3, 'net': 2, 'ip': 2, 'ssl': 2, 'crypto': 2, 'hosts': 2, 'group': 2, 'pam': 2}
        for key, value in important_names.items():
            if key in file_name:
                score += value
                
        size = file_desc.get('size', 0)
        if size > 1000000:
            score += 1
            
        return score

    categorized_files_info = f"\n[Files] Directory contents (Batch {current_index//batch_size + 1}):\n"
    categorized_files_info += "-" * 50 + "\n"
    
    explorer_logger.info(f"[Format Descriptions] Processing batch with {len(current_batch)} files")
    
    valid_files = [f for f in current_batch 
                  if not f['type'].lower().startswith('symbolic link')]
    
    explorer_logger.info(f"[Format Descriptions] Files after symlink filtering: {len(valid_files)}")
    
    sorted_files = sorted(valid_files, 
        key=lambda x: (-calculate_importance(x), x['name'].lower())
    )
    
    explorer_logger.info(f"[Format Descriptions] Files in current batch by importance:")
    for i, f in enumerate(sorted_files):
        explorer_logger.info(f"  {i+1}. {f['name']} - Type: {f['type']}")
    
    for f in sorted_files:
        categorized_files_info += f"File: {f['name']}\n"
        categorized_files_info += f"Type: {f['type']}\n"
        categorized_files_info += f"Size: {f['size']} bytes\n"
        
        perms = f.get('permissions')
        if perms and perms.strip():
            categorized_files_info += f"Permissions: {perms}\n"
        
        categorized_files_info += "-" * 25 + "\n"
    
    total_batches = (len(all_files) + batch_size - 1) // batch_size
    current_batch_num = current_index // batch_size + 1
    
    explorer_logger.info(f"[Format Descriptions] Batch {current_batch_num}/{total_batches} processed")
    explorer_logger.debug(f"[Format Descriptions] File Summary:\n{categorized_files_info}")

    next_index = current_index + batch_size
    
    if next_index >= len(all_files):
        next_index = -1
        explorer_logger.info("[Format Descriptions] All batches processed")
    else:
        explorer_logger.info(f"[Format Descriptions] Moving to next batch, index: {next_index}")
    
    updated_dir_data = {
        **dir_data,
        "files": all_files,
        "index": next_index,
        "dir_path": dir_data.get("dir_path")
    }

    updated_state = {
        **state,
        "file_info": categorized_files_info,
        "file_requirements": state['input']['file_requirements'],
        "dir_data": updated_dir_data
    }
    
    explorer_logger.debug(f"[Format Descriptions] Updated state: dir_data.index = {updated_state['dir_data']['index']}")
    
    return updated_state

def parse_file_selection(response_text: str) -> dict:
    explorer_logger.info("-" * 50)
    explorer_logger.info(f"[Parse] \n{response_text}\n")
    explorer_logger.info("-" * 50)

    MAX_FINDINGS = 50
    findings = []
    
    json_pattern = re.compile(
        r'\{\s*"reason"\s*:\s*"[^"]*"\s*,\s*"file"\s*:\s*"[^"]*"\s*\}',
        re.DOTALL
    )
    matches = json_pattern.finditer(response_text)
    
    for match in matches:
        if len(findings) >= MAX_FINDINGS:
            explorer_logger.warning(f"[Parse] Exceeded maximum findings limit ({MAX_FINDINGS})")
            break
            
        try:
            json_str = match.group().strip()
            if not (json_str.startswith('{') and json_str.endswith('}')):
                continue
                
            result = json.loads(json_str)
            
            if not isinstance(result.get("reason"), str) or not isinstance(result.get("file"), str):
                explorer_logger.warning(f"[Parse] Invalid field types in JSON: {json_str}")
                continue
                
            if len(result["reason"]) > 1000 or len(result["file"]) > 255:
                explorer_logger.warning(f"[Parse] Field length exceeds limit in JSON: {json_str}")
                continue
                
            findings.append(result)
            
        except json.JSONDecodeError as e:
            explorer_logger.error(f"[Parse] JSON parsing error: {e}")
            continue
        except Exception as e:
            explorer_logger.error(f"[Parse] Unexpected error while parsing JSON: {e}")
            continue
    
    if all(finding["file"] == "None" for finding in findings):
        explorer_logger.info("[Parse] No files to analyze in current directory")
        return {
            "thought": findings,
            "action": "next"
        }

    valid_findings = [f for f in findings if f["file"] != "None"]
    explorer_logger.info(f"[Parse] Found {len(valid_findings)} valid findings")
    
    return {
        "thought": valid_findings,
        "action": "analyze"
    }

def build_Explore(save_path: str):
    explorer_logger.info("[Explore Node] Building exploration node")
    system_template = """As a firmware security analyst, you are analyzing the extracted firmware file system. Currently, you only need to provide files that need in-depth analysis in the current directory based on the current firmware security analysis report and user requirements.

**User Requirements About Files**:
{file_requirements}

**Output Format Requirements**
Please output the files that need to be analyzed in order of importance. For each file, specify the specific reason in two aspects:
1. Analysis Reason
2. Issue Connection: Only if there are issues in the current firmware summary that are directly related to this file. Omit this part if no direct connection exists.

Format:
{{
"reason": "[Analysis reason]" or "[Analysis reason] | [Directly related issues]",
"file": "File name"
}}

Note: Only include the " | " separator and related issues if there are clear, direct connections to known issues. If no direct connection exists, only output the analysis reason.

If there are no files in the current directory that require in-depth analysis, output a single JSON object:
{{
    "reason": "There are no files that require in-depth analysis at the moment.",
    "file": "None"
}}

**Important Principles**:    
1. Strict limitation: Only analyze files shown in the file list of the current directory
2. No speculation: Do not perform speculative analysis on files not provided
3. Avoid confusion: Do not analyze files that appear in the firmware security analysis report
4. Evidence-based analysis: Make judgments based only on specific information provided in the file list
5. Example distinction: Do not confuse files with examples in the command, only focus on files actually in the current directory

**Files in Current Directory**:
{file_info}

    """
    prompt = ChatPromptTemplate(
        messages=[
            SystemMessagePromptTemplate(
                prompt=[
                    PromptTemplate.from_template(system_template),
                ],
            ),
            MessagesPlaceholder(
                optional=True,
                variable_name="scratchpad",
            ),
        ],
        input_variables=[
            "file_info",
            "file_requirements",
        ],
        partial_variables={"scratchpad": []},
    )
    
    token_usage_path = os.path.join(save_path, "token_usage.jsonl")
    token_callback = TokenUsageCallbackHandler(token_usage_path)
    llm_client.set_callbacks([token_callback])
    
    llm = llm_client.get_llm()
    
    ExploreNode = annotate | RunnablePassthrough.assign(response=format_descriptions | prompt |  llm | StrOutputParser() | parse_file_selection)
    return ExploreNode


def analyze(state: AgentState) -> str:
    MAX_FILES = 50
    thought_items = state["response"]["thought"]
    analysis_results = []
    summary = None
    
    try:
        analysis_items = thought_items[:MAX_FILES]
        
        explorer_logger.info(f"[Analyzer] Analysis order:")
        for idx, item in enumerate(analysis_items, 1):
            explorer_logger.info(f"{idx}. {item['file']}: {item['reason']}")
        
        if len(thought_items) > MAX_FILES:
            analyzer_logger.warning(f"[Analyzer] Found {len(thought_items)} files, but only analyzing first {MAX_FILES}")
        
        for item in analysis_items:
            try:
                reason_parts = item["reason"].split(" | ")
                file_path = os.path.join(state["current_dir"], item["file"])
                
                if not os.path.exists(file_path):
                    analyzer_logger.error(f"[Analyzer] File not found: {file_path}")
                    continue
                    
                analyzer_logger.info(f"[Analyzer] Analyzing file: {file_path}")
                
                base_save_path = os.path.join(state["save_path"], f"{item['file']}")
                save_path = base_save_path
                counter = 1
                while os.path.exists(save_path):
                    save_path = f"{base_save_path}_{counter}"
                    counter += 1

                focused_requirements = state["input"]["file_findings_requirements"]
                
                if len(reason_parts) > 1:
                    context = reason_parts[1].strip()
                    if context:
                        context_analysis = f"\nConnection to known issues, but do not let this limit your analysis: {context}"
                        focused_requirements = f"{context_analysis}{focused_requirements}"

                initial_state = {
                    "input": focused_requirements,
                    "file": file_path,
                    "current_dir": state["current_dir"],
                    "response": {
                        "thought": "",
                        "command": "",
                        "status": ""
                    },
                    "scratchpad": [],
                    "observation": "",
                    "save_path": save_path
                }
                
                save_path = os.path.normpath(initial_state['save_path'])
                if not os.path.exists(save_path):
                    os.makedirs(save_path, exist_ok=True)
                    analyzer_logger.debug(f"[Analyzer] Created analysis directory: {save_path}")
                
                try:
                    event_stream = analysis_graph.invoke(
                        initial_state,
                        {"recursion_limit": 30}
                    )
                    analyzer_logger.debug(f"[Analyze] Analysis completed for {file_path}")
                except Exception as e:
                    analyzer_logger.error(f"[Analyze] Analysis graph error for {file_path}: {str(e)}")
                
                file_analysis_history = os.path.join(save_path, 'analysis_history.json')
                if os.path.exists(file_analysis_history):
                    try:
                        with open(file_analysis_history, 'r', encoding='utf-8') as f:
                            history = json.load(f)
                        
                        high_severity_findings = []
                        for msg in history:
                            if msg['type'] == 'AI':
                                try:
                                    severity = msg['content'].get('thought', {}).get('severity', '0')
                                    if isinstance(severity, str):
                                        if severity.isdigit():
                                            severity = float(severity)
                                        else:
                                            continue
                                    
                                    if severity > 2:
                                        findings = msg['content'].get('thought', {}).get('findings', '').strip()
                                        reason = msg['content'].get('thought', {}).get('reason', '').strip()
                                        if findings and reason:
                                            combined_finding = f"{findings}: {reason}"
                                            high_severity_findings.append(combined_finding)
                                        elif findings:
                                            high_severity_findings.append(findings)
                                except (ValueError, TypeError):
                                    continue
                        
                        if high_severity_findings:
                            combined_findings = " | ".join(high_severity_findings)
                            analysis_results.append({
                                "file": get_relative_path(file_path, state["base_path"]),
                                "findings": combined_findings + "\n"
                            })
                            analyzer_logger.info(f"[Analyzer] High severity findings for {file_path}:\n{combined_findings}")
                            
                    except Exception as e:
                        analyzer_logger.error(f"[Analyzer] Error reading history file for {file_path}: {str(e)}")
                        continue
                
            except Exception as e:
                analyzer_logger.error(f"[Analyzer] Error processing file {item['file']}: {str(e)}")
                continue
        
        if analysis_results:
            summary = ""
            for result in analysis_results:
                summary += "===FINDING===\n"
                summary += f"File: {result['file']}\n"
                summary += f"Analysis results:\n{result['findings']}\n"
                
    except Exception as e:
        analyzer_logger.error(f"[Analyzer] Error in analyze function: {str(e)}")
        summary = None
    
    return summary


@retry(
    stop=(
        stop_after_attempt(3) |
        stop_after_delay(60)
    ),
    wait=wait_exponential(multiplier=1, min=4, max=10)
)
def update_security_report(security_report_template: str, new_findings: str, save_path: str):
    explorer_logger.info("[Update Report] Updating security report with new findings")
    integration_prompt = f"""As a security analysis assistant, please strictly generate a firmware security analysis report based on the provided file analysis results.

**Analysis Principles**:
    - Accuracy: Accurately record all discovered analysis results with clear evidence
    - Evidence-based: Each finding must be supported by specific evidence, including file paths and specific content
    - Caution: Do not perform speculative analysis, only based on exact evidence
    - Clarity: Mark uncertain information as "Unknown", do not make guesses. Only report findings that have clear supporting evidence.
    - Traceability: Each issue must be traceable to a specific file location
    - Path Normalization: Use path format relative to the firmware root directory

Please output the results in the following format, and finally only return the following report, without including other explanations and content:
'''
{security_report_template}
'''

The analysis results are as follows:
{new_findings}
"""
    
    try:
        token_usage_path = os.path.join(save_path, "token_usage.jsonl")
        token_callback = TokenUsageCallbackHandler(token_usage_path)
        llm_client.set_callbacks([token_callback])
        
        response = llm_client.stream([SystemMessage(content=integration_prompt)])
        
        if not response:
            explorer_logger.warning("[Update Report] Empty response from LLM")
            return response
            
        explorer_logger.info("[Update Report] Successfully updated security report")
        explorer_logger.debug(f"[Update Report] Updated report content:\n{response}")
        return response
        
    except Exception as e:
        explorer_logger.error(f"[Update Report] Error updating security report: {e}")
        if getattr(e, 'last_attempt', False):
            explorer_logger.warning("[Update Report] All retry attempts failed, returning original report")
            return new_findings
        raise

@retry(
    stop=(
        stop_after_attempt(3) |
        stop_after_delay(60)
    ),
    wait=wait_exponential(multiplier=1, min=4, max=10)
)
def update_summary(summary_template: str, summary: str, findings: str, save_path: str) -> str:
    explorer_logger.info("[Summary] Generating security report summary")
    
    summary_prompt = f"""As a firmware security analyst, you are analyzing the extracted firmware file system. Please generate an updated comprehensive firmware security analysis summary based on the original summary and new findings from the firmware analysis process. Please keep it extremely concise, focusing only on the most critical firmware security issues.

Principles:
- Always keep descriptions concise and clear
- Sort all security issues by severity
- Do not perform speculative analysis, only based on exact evidence
- Each finding must be supported by specific evidence
- Ensure all paths use formats relative to the firmware root directory
- Link each security issue with specific file/directory evidence
- Merge the same and similar security issues,do not repeat the same issue

Please strictly output the updated summary according to the following template format:
'''
{summary_template}
'''

Original Firmware Analysis Summary:
{summary}

New Firmware Security Findings:
{findings}
"""
    
    try:
        token_usage_path = os.path.join(save_path, "token_usage.jsonl")
        token_callback = TokenUsageCallbackHandler(token_usage_path)
        llm_client.set_callbacks([token_callback])
        
        explorer_logger.debug("[Summary] Sending prompt to LLM for summary generation")
        response = llm_client.stream([SystemMessage(content=summary_prompt)])
        
        if not response:
            explorer_logger.warning("[Summary] Empty response from LLM")
            return summary
            
        explorer_logger.info("[Summary] Successfully generated security summary")
        explorer_logger.debug(f"[Summary] Summary content:\n{response}")  
            
        return response
        
    except Exception as e:
        explorer_logger.error(f"[Summary] Error generating security summary: {e}")
        if getattr(e, 'last_attempt', False):
            explorer_logger.warning("[Summary] All retry attempts failed")
            return summary
        raise

def get_relative_path(full_path: str, base_path: str) -> str:
    try:
        return os.path.relpath(full_path, base_path)
    except ValueError:
        return full_path

def get_full_path(relative_path: str, base_path: str) -> str:
    return os.path.join(base_path, relative_path)

@retry(
    stop=(
        stop_after_attempt(3) |
        stop_after_delay(60)
    ),
    wait=wait_exponential(multiplier=1, min=4, max=10)
)
def update_directory_group(directory_group: List[str], requirements: str, save_path: str):
    
    analysis_prompt = f"""As a firmware security analyst, you are analyzing the extracted firmware file system. Analyze the directory structure to identify potential security issues and determine which directories should be excluded.

**Directory List**:
{json.dumps(directory_group, indent=2)}

**User Requirements About Directories**:
{requirements}

Remove directories that:
- Are duplicates or redundant
- Do not match requirements
- Non-security-relevant directories
- Are .extracted directories containing binary fragments(Remove after summarizing content)

Output in the following JSON format without any additional explanation:
{{
    "findings": [
        {{
            "issue": "Security issue description",
            "reason": "Directories that provide evidence for this issue, ONLY from the provided directory list"
        }}
    ],
    "exclude": ["ONLY directories that are confirmed to be irrelevant for security analysis and do not match user requirements"]
}}

Important:
1. Evidence-Based Analysis: All security findings must be based on concrete evidence from the directory structure. Speculation and assumptions are strictly prohibited
2. Output directory paths exactly as they appear in the provided list
3. Do not modify or reformat directory paths
4. Do not exclude directories that are required by user requirements and its subdirectories
5. If no directories need to be excluded or you are uncertain, use empty list [] for exclude
6. Focus findings on patterns and relationships between the directories in the list, do not make assumptions
"""

    try:
        token_usage_path = os.path.join(save_path, "token_usage.jsonl")
        token_callback = TokenUsageCallbackHandler(token_usage_path)
        llm_client.set_callbacks([token_callback])
        
        explorer_logger.debug("[Update Directory Group] Analyzing structure")
        response = llm_client.stream([SystemMessage(content=analysis_prompt)])
        
        try:
            result = parse_directory_removal(response)
            dir_findings = []
            
            dirs_to_remove = set(result.get("exclude", []))
            
            cleaned_dirs = [d for d in directory_group if d not in dirs_to_remove]
            
            for finding in result.get("findings", []):
                evidence_dirs = finding['reason']
                if isinstance(evidence_dirs, str):
                    evidence_dirs = [evidence_dirs]
                    
                dir_findings.append(
                    f"Directory Finding: {finding['issue']}\n"
                    f"Evidence Directories: {', '.join(evidence_dirs)}\n"
                )
            
            explorer_logger.info(f"[Update Directory Group] Removed directories: {dirs_to_remove}")
            explorer_logger.debug(f"[Update Directory Group] Remaining directories: {len(cleaned_dirs)}")
            
            return dir_findings, cleaned_dirs
            
        except Exception as e:
            explorer_logger.error(f"[Update Directory Group] Parse failed: {e}")
            return [], directory_group
            
    except Exception as e:
        explorer_logger.error(f"[Update Directory Group] Failed: {e}")
        return [], directory_group

def update(state: AgentState):
    explorer_logger.debug("[Update] Updating state")
    message = state["scratchpad"]
    next_dir = state["current_dir"]
    action = state["response"]["action"]
    base_path = state["base_path"]
    updated_summary = state.get("security_report_summary", "No summary yet")
    history_file = os.path.join(state["save_path"], "message_history.json")
    
    relative_dir_stack = [get_relative_path(d, base_path) for d in state['dir_stack']]

    dir_findings, cleaned_dir_stack = update_directory_group(
        relative_dir_stack,
        state["input"]["directory_requirements"],
        state["save_path"]
    )
    
    state['dir_stack'] = [get_full_path(d, base_path) for d in cleaned_dir_stack]

    try:
        if os.path.exists(history_file):
            with open(history_file, 'r', encoding='utf-8') as f:
                history = json.load(f)
        else:
            history = []
    except Exception as e:
        explorer_logger.error(f"[Update] Failed to read history file: {e}")
        history = []

    new_records = []
    
    if "response" in state and state["response"]:
        new_records.append({
            "type": "FILE_SELECTION",
            "current_dir": state["current_dir"],
            "content": state["response"]
        })

    if "observation" in state and state["observation"]:
        new_records.append({
            "type": "ANALYSIS_RESULT",
            "current_dir": state["current_dir"],
            "content": state["observation"]
        })

    if action == "analyze" and state.get("observation"):
        observation = state["observation"]
        updated_report = update_security_report(state["input"]["security_report_template"], observation, state["save_path"])
        with open(os.path.join(state["save_path"], "report.txt"), 'a', encoding='utf-8') as f:
            f.write(f"{updated_report}\n")
        updated_summary = state.get("security_report_summary", "No summary yet")
        
        if observation:
            file_findings = observation.split("===FINDING===")
            file_findings = [f.strip() for f in file_findings if f.strip()]
            
            # Process findings in batches of 3
            BATCH_SIZE = 3
            for i in range(0, len(file_findings), BATCH_SIZE):
                batch = file_findings[i:i + BATCH_SIZE]
                batch_findings = "===FINDING===\n" + "\n===FINDING===\n".join(batch)
                updated_summary = update_summary(
                    state["input"]["summary_template"], 
                    updated_summary,
                    batch_findings,
                    state["save_path"]
                )
                explorer_logger.debug(f"[Update] Processed findings batch {i//BATCH_SIZE + 1}")
        
        summary_path = os.path.join(state["save_path"], "summary.txt")
        with open(summary_path, 'w', encoding='utf-8') as f:
            f.write(f'{updated_summary}\n')
        explorer_logger.info(f"[Update] Security summary updated and saved to: {summary_path}:\n{updated_summary}")
        
        new_records.append({
            "type": "SECURITY_SUMMARY",
            "current_dir": state["current_dir"],
            "content": updated_summary
        })

    def save_history(history, new_records):
        try:
            history.extend(new_records)
            os.makedirs(os.path.dirname(history_file), exist_ok=True)
            with open(history_file, 'w', encoding='utf-8') as f:
                json.dump(history, f, indent=2, ensure_ascii=False)
        except Exception as e:
            explorer_logger.error(f"[Update History] Failed to save history: {e}")
    
    save_history(history, new_records)

    current_dir = state["current_dir"]
    dir_data = state["dir_data"]
    
    explorer_logger.info(f"[Select Next Dir] Index: {dir_data['index']}")
    
    if dir_data["index"] != -1:
        explorer_logger.info(f"[Select Next Dir] Continuing with current directory: {current_dir}")
        return {
            **state,
            "current_dir": current_dir,
            "dir_data": dir_data,
            "dir_stack": state["dir_stack"],
            "scratchpad": message,
            "security_report_summary": updated_summary
        }
    
    try:
        analysis_prompt = f"""As a firmware security analyst, you are analyzing the extracted firmware file system.Your task is to select a directory from the firmware, considering the current firmware security analysis summary and user requirements, and choose the next directory that needs in-depth analysis.

**User Requirements About Directories**:
{state['input']['directory_requirements']}

**Important Principles**:
1. Continuity: Only switch to the next directory after one directory is fully analyzed, directories of the same type should be analyzed continuously (e.g. complete all bin directories first).
2. Priority: Strictly analyze in the order of directory importance and user requirements.
3. Practicality: Must ensure it is a directory from the selectable directory list, and provide the same path without any changes.
4. Avoid Confusion: Do not analyze directories already analyzed in the firmware security analysis summary.
5. Single Selection: Strictly analyze in the order of the security analysis summary and user requirements, only select the single highest priority directory each time.

**Please strictly output in the following JSON format, do not add any other content**:
{{
    "Directory": "Selected single directory path",
    "Reasoning": "Why this directory is currently the highest priority for analysis"
}}

If you think no further analysis is needed, please output:
{{
    "Directory": "None",
    "Reasoning": "Task complete"
}}

Current Firmware Security Analysis Summary:
{updated_summary}

Selectable Directory List:
{json.dumps(cleaned_dir_stack, indent=2)}
"""
        token_usage_path = os.path.join(state['save_path'], "token_usage.jsonl")
        token_callback = TokenUsageCallbackHandler(token_usage_path)
        llm_client.set_callbacks([token_callback])
        response = llm_client.invoke([SystemMessage(content=analysis_prompt)])
        
        try:
            result = parse_directory_selection(response)
            if not isinstance(result, dict) or 'Directory' not in result or 'Reasoning' not in result:
                raise ValueError("Invalid response format")
        except Exception as e:
            explorer_logger.error(f"[Update] JSON validation failed: {e}")
            result = {
                "Directory": state["dir_stack"][0] if state["dir_stack"] else "None",
                "Reasoning": "Format error, using fallback"
            }
            
        explorer_logger.info(f"[Update] Directory selection result: {result}")
        
        chosen_dir = result['Directory']
        if chosen_dir.lower() != "none":
            chosen_dir_full = get_full_path(chosen_dir, base_path)
            
            if chosen_dir_full in state['dir_stack']:
                next_dir = chosen_dir_full
                state['dir_stack'].remove(chosen_dir_full)
                new_records.append({
                    "type": "SELECT_NEXT_DIR",
                    "current_dir": state["current_dir"],
                    "content": chosen_dir_full
                })
            else:
                next_dir = state["dir_stack"].pop(0)
                explorer_logger.warning(f"[Select Next Dir] Fallback selection: {next_dir}")
        else:
            explorer_logger.info("[Select Next Dir] Analysis complete")
            next_dir = None
            new_records.append({
                "type": "SELECT_NEXT_DIR",
                "current_dir": state["current_dir"],
                "content": "Analysis complete"
            })
    except Exception as e:
        explorer_logger.error(f"[Select Next Dir] Update failed: {e}")
        new_records.append({
            "type": "SELECT_NEXT_DIR",
            "current_dir": state["current_dir"],
            "content": str(e)
        })
        if state["dir_stack"]:
            next_dir = state["dir_stack"].pop(0)
            explorer_logger.warning(f"[Select Next Dir] Error recovery, switching to: {next_dir}")
        else:
            next_dir = None

    save_history(history, new_records)
        
    current_dir = state["current_dir"]
    dir_data = state["dir_data"]
    
    explorer_logger.info(f"[Select Next Dir] Index: {dir_data['index']}")
    if chosen_dir.lower() == "none":
        next_dir = None
    else:
        if chosen_dir_full and chosen_dir_full != current_dir:
            next_dir = chosen_dir_full
            dir_data = {
                "files": [],
                "index": 0,
                "dir_path": next_dir
            }
        else:
            next_dir = None
    
    explorer_logger.info(f"[Update] Next directory: {next_dir}, Index: {dir_data['index']}")
    
    return {
        **state,
        "current_dir": next_dir,
        "dir_data": dir_data,
        "dir_stack": state["dir_stack"],
        "scratchpad": message,
        "security_report_summary": updated_summary
    }

def select_next_action(state: AgentState) -> str:
    action = state["response"]["action"]
    if action == "analyze":
        explorer_logger.info("[Select Next Action] Analyze files")
        return "analyze"
    else:
        explorer_logger.info("[Select Next Action] Switching to next directory")
        return "next"
        
def select_next_dir(state: AgentState):
    if state["current_dir"]:
        return "agent"
    else:
        explorer_logger.info("[Select Next Dir] Analysis complete")
        return END
    
def retry(state: AgentState):
    return "Response format error, please strictly follow the required format"

def next_dir(state: AgentState):
    return "No files to analyze, switching to next directory"

tools = {
    "analyze": analyze,
    "retry": retry,
    "next": next_dir,
}

def build_graph(save_path: str):
    explorer_logger.info("[Build] Building exploration graph")
    ExploreNode = build_Explore(save_path)
    graph_builder = StateGraph(AgentState)
    graph_builder.add_node("update", update)
    graph_builder.add_edge(START, "agent")
    graph_builder.add_node("agent", ExploreNode)
    graph_builder.add_conditional_edges("agent", select_next_action)

    for node_name, tool in tools.items():
        graph_builder.add_node(
            node_name,
            RunnableLambda(tool) | (lambda observation: {"observation": observation}),
        )
        graph_builder.add_edge(node_name, "update")

    graph_builder.add_conditional_edges("update", select_next_dir)
    explorer_logger.debug("[Build] Graph construction complete")
    return graph_builder.compile()

def explorer(state: AgentState, max_steps=200):
    explorer_logger.info(f"[Main] Starting analysis (max steps: {max_steps})")
    
    final_security_report_summary = None
    graph = build_graph(state["save_path"])
    try:
        event_stream = graph.stream(
            state,
            {"recursion_limit": max_steps},
        )
        
        for event in event_stream:
            try:
                if "agent" in event:
                    if "security_report_summary" in event["agent"]:
                        final_security_report_summary = event["agent"]["security_report_summary"]

                if END in event:
                    if "security_report_summary" in event[END]:
                        final_security_report_summary = event[END]["security_report_summary"]
                    explorer_logger.info("[Main] Analysis complete")
                    break
                    
            except Exception as e:
                explorer_logger.error(f"[Main] Event processing error: {str(e)}")
                continue
                
    except Exception as e:
        explorer_logger.error(f"[Main] Runtime error: {str(e)}")
    
    finally:
        explorer_logger.info("[Main] Final security report:")
        explorer_logger.info("-" * 50)
        explorer_logger.info(f"[Main] \n{final_security_report_summary}")
        explorer_logger.info("-" * 50)
