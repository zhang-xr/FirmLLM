import r2pipe
import cmd
import httpx
import json
import re
import os
import threading
import time
from functools import wraps
import logging
from collections import defaultdict
import queue
from concurrent.futures import ThreadPoolExecutor, as_completed
from client import create_openai_client
from typing import List, Optional

class ThreadLogCollector:
    def __init__(self):
        self.logs = defaultdict(list)
        self.lock = threading.Lock()
    
    def add_log(self, thread_id: int, message: str):
        with self.lock:
            self.logs[thread_id].append(message)
    
    def get_logs(self, thread_id: int) -> List[str]:
        with self.lock:
            return self.logs.pop(thread_id, [])

def get_logger(name, save_path=None, log_collector=None):
    logger = logging.getLogger(name)
    logger.handlers = []
    logger.setLevel(logging.INFO)
    
    class CollectorHandler(logging.Handler):
        def emit(self, record):
            if log_collector:
                thread_id = threading.get_ident()
                message = self.format(record)
                log_collector.add_log(thread_id, message)
    
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(name)s: %(message)s',
                                datefmt='%H:%M:%S')
    
    collector_handler = CollectorHandler()
    collector_handler.setFormatter(formatter)
    logger.addHandler(collector_handler)
    
    if os.getenv('DEBUG'):
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
    
    logger.propagate = False
    return logger

class TimeoutError(Exception):
    pass

def timeout_decorator(timeout_seconds):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            result = {'value': None, 'exception': None}
            
            def target():
                try:
                    result['value'] = func(*args, **kwargs)
                except Exception as e:
                    result['exception'] = e
                    
            thread = threading.Thread(target=target)
            thread.daemon = True
            thread.start()
            thread.join(timeout_seconds)
            
            if thread.is_alive():
                raise TimeoutError(f"Function {func.__name__} timed out after {timeout_seconds} seconds")
            
            if result['exception']:
                raise result['exception']
                
            return result['value']
        return wrapper
    return decorator

class R2Analyzer(cmd.Cmd):
    def __init__(self, binary_path: str, save_path: str = "r2", 
                 max_analysis_count: int = 5,
                 timeout_seconds: int = 1800,
                 command_timeout: int = 90,
                 max_iterations: int = 10,
                 find_dangerous_timeout: int = 900,
                 target_functions: List[str] = None):
        super().__init__()
        self.log_collector = ThreadLogCollector()
        self.disassembly_logger = get_logger('R2', save_path, self.log_collector)
        self.disassembly_logger.info(f"[Init] Initializing: {binary_path}")
        self.binary_path = binary_path
        self.r2 = r2pipe.open(binary_path, flags=['-e', 'io.cache=true'])
        self.save_path = save_path
        
        self.MAX_ANALYSIS_COUNT = max_analysis_count
        self.TIMEOUT_SECONDS = timeout_seconds
        self.COMMAND_TIMEOUT = command_timeout
        self.MAX_ITERATIONS = max_iterations
        self.FIND_DANGEROUS_TIMEOUT = find_dangerous_timeout
        
        self.r2.cmd('e anal.hasnext=true')    
        self.r2.cmd('e anal.depth=256')       
        self.r2.cmd('e io.va=true')           
        self.r2.cmd('aaa')                    
        
        info = self.r2.cmdj('ij')
        if not info:
            self.disassembly_logger.error("[Init] Failed to load binary file")
            raise RuntimeError("Failed to load binary file")
            
        self.disassembly_logger.info(f"[Init] Successfully loaded file: {info.get('core', {}).get('file', 'unknown')}")
        
        self.base_addr = info.get('bin', {}).get('baddr', 0)
        self.disassembly_logger.info(f"[Init] Binary base address: 0x{self.base_addr:x}")

        self.r2.cmd('aff')  
        self.r2.cmd('afr')  
        self.r2.cmd('af@@f')
        
        functions = self.r2.cmdj('aflj')
        if not functions:
            self.disassembly_logger.warning("[Init] No functions detected, attempting deeper analysis")
            self.r2.cmd('aaaa')  
            functions = self.r2.cmdj('aflj')
        
        self.disassembly_logger.info(f"[Init] Detected {len(functions) if functions else 0} functions")
        
        self.model, self.client = create_openai_client()
        if self.model == "deepseek-reasoner":
            self.client.base_url = "https://api.deepseek.com/beta"
        
        self.dangerous_functions = {
            "system": {"weight": 30, "category": "command_injection", "description": "Direct command execution, CVE-2016-1555/CVE-2018-1328"},
            "popen": {"weight": 30, "category": "command_injection", "description": "Command execution with pipe, CVE-2017-7859"},
            "strcpy": {"weight": 25, "category": "buffer_overflow", "description": "Unbounded string copy, CVE-2020-10562"},
            "strcat": {"weight": 25, "category": "buffer_overflow", "description": "Unbounded string concatenation, CVE-2019-1573"},
            "gets": {"weight": 25, "category": "buffer_overflow", "description": "Dangerous input function, CVE-2016-2563"},
            "sprintf": {"weight": 25, "category": "buffer_overflow", "description": "Buffer overflow in string formatting, CVE-2020-8597"},
            "sscanf": {"weight": 25, "category": "buffer_overflow", "description": "String parsing overflow, CVE-2012-2393"},
            "memcpy": {"weight": 25, "category": "memory", "description": "Memory copy without bounds check, CVE-2019-8936"},
            "fprintf": {"weight": 25, "category": "format_string", "description": "File output format string, CVE-2019-14685"},
            "printf": {"weight": 25, "category": "format_string", "description": "File output format string, CVE-2019-14685"},
            "setuid": {"weight": 25, "category": "privilege", "description": "Privilege change, CVE-2019-11043"},
            "recv": {"weight": 25, "category": "network", "description": "Network input handling, CVE-2020-8597"}
        }
        
        self.message_history = []
        self._init_conversation()
        
        self.call_chain_cache = {}
        self.cache_lock = threading.Lock()
        self.r2_lock = threading.Lock()

        self.MAX_RESULT_LENGTH = min(
            int(os.getenv('MAX_RESULT_LENGTH', 20000)),
            64000
        )

        self.target_functions = set(target_functions) if target_functions else set()
        if self.target_functions:
            self.disassembly_logger.info(f"[Init] Prioritizing analysis of functions: {self.target_functions}")

    @timeout_decorator(300)
    def find_dangerous_functions(self):
        self.disassembly_logger.info("[Find] Starting dangerous function search")
        try:
            found_refs = {}
            
            imports = self.r2.cmdj('iij') or []
            symbols = self.r2.cmdj('isj') or []
            functions = self.r2.cmdj('aflj') or []
            
            for item in imports + symbols + functions:
                name = item.get('name', '').lower()
                addr = item.get('vaddr', item.get('offset', 0))
                
                if not addr or not name:
                    continue
                    
                clean_name = re.sub(r'^[_@.]', '', name.split('.')[-1])
                base_name = clean_name.split('_')[0]
                
                for func_name in self.dangerous_functions:
                    if (func_name in clean_name or 
                        func_name == base_name or 
                        f"_{func_name}" in clean_name or 
                        f"{func_name}_" in clean_name):
                        
                        if func_name not in found_refs:
                            found_refs[func_name] = {}
                            
                        if addr not in found_refs[func_name]:
                            found_refs[func_name][addr] = {
                                'function': func_name,
                                'address': addr,
                                'xrefs': []
                            }
                            
                            xrefs = self.r2.cmdj(f'axtj @ {addr}') or []
                            for xref in xrefs:
                                ref_addr = xref.get('from', 0)
                                if ref_addr:
                                    caller_func = self.r2.cmdj(f'afij @ {ref_addr}')
                                    if caller_func and caller_func[0]:
                                        found_refs[func_name][addr]['xrefs'].append({
                                            'caller_name': caller_func[0].get('name', 'unknown'),
                                            'caller_addr': caller_func[0].get('offset', 0),
                                            'call_offset': ref_addr
                                        })

            strings = self.r2.cmdj('izj') or []
            for string in strings:
                str_value = string.get('string', '').lower()
                str_addr = string.get('vaddr', 0)
                
                if not str_addr:
                    continue
                    
                for func_name in self.dangerous_functions:
                    if func_name in str_value:
                        xrefs = self.r2.cmdj(f'axtj @ {str_addr}') or []
                        for xref in xrefs:
                            ref_addr = xref.get('from', 0)
                            if ref_addr:
                                caller_func = self.r2.cmdj(f'afij @ {ref_addr}')
                                if caller_func and caller_func[0]:
                                    if func_name not in found_refs:
                                        found_refs[func_name] = {}
                                    
                                    str_key = f"str_{str_addr}"
                                    if str_key not in found_refs[func_name]:
                                        found_refs[func_name][str_key] = {
                                            'function': func_name,
                                            'address': str_addr,
                                            'xrefs': []
                                        }
                                    
                                    found_refs[func_name][str_key]['xrefs'].append({
                                        'caller_name': caller_func[0].get('name', 'unknown'),
                                        'caller_addr': caller_func[0].get('offset', 0),
                                        'call_offset': ref_addr
                                    })

            results = []
            for func_refs in found_refs.values():
                for ref in func_refs.values():
                    for xref in ref['xrefs']:
                        caller_entry = next(
                            (r for r in results if r['address'] == xref['caller_addr']),
                            None
                        )
                        
                        if not caller_entry:
                            caller_entry = {
                                'function': xref['caller_name'],
                                'address': xref['caller_addr'],
                                'dangerous_calls': []
                            }
                            results.append(caller_entry)
                        
                        caller_entry['dangerous_calls'].append({
                            'function': ref['function'],
                            'address': ref['address'],
                            'call_offset': xref['call_offset']
                        })

            return results

        except Exception as e:
            self.disassembly_logger.error(f"[Analysis] Error in dangerous function search: {str(e)}")
            return []

    def _score_call_chain(self, chain: List[dict], dangerous_func: str) -> float:
        try:
            if not chain:
                return 0.0
            
            score = 0.0
            chain_length = len(chain)
            
            dangerous_info = self.dangerous_functions.get(dangerous_func, {})
            base_weight = dangerous_info.get('weight', 15)
            score += base_weight
            
            for i, func in enumerate(chain):
                func_name = func.get('name', '').lower()
                
                position_weight = 1.0 - (i / chain_length) * 0.1
                
                if self.target_functions and func_name in self.target_functions:
                    score += 1.5 * position_weight 
                
                patterns = {
                    'main': 15.0,
                    'init': 12.0,
                    'handle': 10.0,
                    'process': 8.0,
                    'callback': 8.0,
                    'recv': 12.0,
                    'read': 10.0,
                    'parse': 8.0
                }
                
                for pattern, weight in patterns.items():
                    if pattern in func_name:
                        score += weight * position_weight
                        break
            
            length_factor = 1.0 + (0.5 / chain_length)
            score *= length_factor
            
            entry_func = chain[0].get('name', '').lower()
            if 'main' in entry_func or 'init' in entry_func:
                score *= 1.1
            
            if (self.target_functions and 
                chain[-1].get('name', '').lower() in self.target_functions):
                score *= 1.15
            
            return min(100.0, score)
            
        except Exception as e:
            self.disassembly_logger.error(f"[Score] Error scoring call chain: {str(e)}")
            return 0.0

    def _remove_duplicate_chains(self, chains: List[List[dict]]) -> List[List[dict]]:
        """Remove duplicate and subset call chains
        
        Args:
            chains: List of call chains to deduplicate
            
        Returns:
            List[List[dict]]: Deduplicated call chains
        """
        try:
            if not chains:
                return []
            
            # Sort chains by length (longest first)
            sorted_chains = sorted(chains, key=len, reverse=True)
            unique_chains = []
            
            def is_subchain(shorter, longer):
                """Check if one chain is a subset of another"""
                if len(shorter) > len(longer):
                    return False
                
                # Convert chains to address sequences for comparison
                shorter_addrs = [func.get('offset') for func in shorter]
                longer_addrs = [func.get('offset') for func in longer]
                
                # Check if shorter sequence exists in longer sequence
                for i in range(len(longer_addrs) - len(shorter_addrs) + 1):
                    if shorter_addrs == longer_addrs[i:i + len(shorter_addrs)]:
                        return True
                return False
            
            # Add chains that are not subsets of already added chains
            for chain in sorted_chains:
                is_subset = False
                for unique_chain in unique_chains:
                    if is_subchain(chain, unique_chain):
                        is_subset = True
                        break
                if not is_subset:
                    unique_chains.append(chain)
            
            return unique_chains
            
        except Exception as e:
            self.disassembly_logger.error(f"[Dedup] Error removing duplicate chains: {str(e)}")
            return chains

    def find_complete_call_chains(self, dangerous_refs: List[dict]) -> List[dict]:
        try:
            function_results = {}
            
            for ref in dangerous_refs:
                caller_func = ref['function']
                caller_addr = ref['address']
                
                for dangerous_call in ref['dangerous_calls']:
                    result_key = f"{caller_addr}_{dangerous_call['function']}"
                    
                    if result_key not in function_results:
                        function_results[result_key] = {
                            'dangerous_function': dangerous_call['function'],
                            'dangerous_addr': dangerous_call['address'],
                            'caller_function': caller_func,
                            'caller_addr': caller_addr,
                            'call_chains': [],
                            'risk_score': 0.0
                        }
                    
                    result = function_results[result_key]
                    
                    try:
                        chains = []
                        visited = set()
                        
                        def build_chain(current_addr: int, current_chain: List[dict]):
                            if any(func.get('offset') == current_addr for func in current_chain):
                                return
                            
                            func_info = self.r2.cmdj(f'afij @ {current_addr}')
                            if not func_info or not func_info[0]:
                                return
                            
                            new_chain = current_chain + [func_info[0]]
                            
                            refs = self.r2.cmdj(f'axtj @ {current_addr}') or []
                            
                            if not refs:
                                chains.append(new_chain)
                            else:
                                for ref in refs:
                                    ref_addr = ref.get('from')
                                    if ref_addr and ref_addr not in visited:
                                        visited.add(ref_addr)
                                        build_chain(ref_addr, new_chain)
                                        visited.remove(ref_addr)
                        
                        build_chain(caller_addr, [])
                        
                        unique_chains = self._remove_duplicate_chains(chains)
                        
                        for chain in unique_chains:
                            score = self._score_call_chain(chain, result['dangerous_function'])
                            if score > result['risk_score']:
                                result['risk_score'] = score
                                if chain not in result['call_chains']:
                                    result['call_chains'].append(chain)
                    
                    except Exception as e:
                        self.disassembly_logger.error(f"[Chain] Error building call chains for {caller_func}: {str(e)}")
                        continue
            
            results = list(function_results.values())
            results.sort(key=lambda x: x['risk_score'], reverse=True)
            
            for result in results:
                result['call_chains'] = result['call_chains'][:10]
            
            return results
            
        except Exception as e:
            self.disassembly_logger.error(f"[Chain] Error in call chain analysis: {str(e)}")
            return []
    def _init_conversation(self):
        """Initialize conversation history"""
        self.message_history = [{
            "role": "system",
            "content": """**Binary Security Analysis Framework**

1. Analysis Initialization
   ```
   You are a firmware binary security analysis expert. Your task is to analyze binary security using r2 commands.The current analysis is within the radare2 (r2) environment, and only r2 built-in commands are allowed.
   For each reply, return a single JSON object with format:
   {
       "analysis": {
           "risk_level": "Critical|High|Medium|Low|Unknown",
           "reason": {
               "description": "reason description",
               "evidence": "reason evidence"
           },
           "next_step": "Next analysis step explanation"
       },
       "commands": "r2 command <hex_addr>",
       "status": "continue|complete"
   }
   ```
2.**Commands Usage**
Required Parameters:
<hex_addr> - Function address (must start with '0x', e.g. 0x4005a0)

Optional Parameters:
[~limit]   - Number of items to display
[@offset]  - Starting offset for display

a. Function Analysis Commands
-------------------------
Primary Analysis:
- pdd @ <hex_addr>   # Decompile function
- pdf @ <hex_addr>   # Print disassembly 
- afb @ <hex_addr>   # Analyze basic blocks

Variable & Reference Analysis:
- afvd @ <hex_addr>  # Analyze variables 
- afcf @ <hex_addr>  # View call graph 
- axt @ <hex_addr>  # View cross references 
- axtj @ <hex_addr> # Cross references in JSON 

b. Basic Information Commands
-------------------------
Quick Info:
- aflm @ <hex_addr>  # List local variables
- afll @ <hex_addr>  # List loop information
- pds @ <hex_addr>   # View string constants
- af @ <hex_addr>    # Analyze function
- afi @ <hex_addr>   # Get basic function info

c. Command Syntax Examples
-------------------------
Valid Examples:
✓ pdd @ 0x4005a0           # Basic usage with default limit
✓ pdd @ 0x4005a0 ~100     # Custom limit of 100 lines
✓ pdd @ 0x4005a0 ~50 @50  # Show lines 50-100

Invalid Examples:
 pdd @ 4005a0     # Error: missing 0x prefix
 pdd @ 0x        # Error: incomplete address
 pdd             # Error: missing address
 pdd @ sys.upnpdev_main   # Error: invalid hex

d. Important Notes
-------------------------
Address Requirements:
- Must start with '0x' prefix
- Must be a valid hexadecimal address
- Cannot be omitted
- Case sensitive (use lowercase 'x')

3. Evidence In Reason Requirements
-------------------------
a. Call Chain Analysis
b. Vulnerability Details(Only for critical risk)
c. Protection Analysis(If the function is protected)


4. Risk Assessment Criteria
   A. Critical Risk 
      - Direct external accessibility
      - Full parameter control
      - No effective protection
      - System-level impact
      Required evidence:
      - Complete attack chain code
      - Parameter control proof
      - Protection bypass demo
      - Impact verification
      
   B. High Risk 
      - Indirect accessibility
      - Partial parameter control
      - Weak protection
      - Significant impact
      Required evidence:
      - Partial attack chain
      - Control point analysis
      - Protection weakness
      - Impact assessment
      
   C. Medium Risk
      - Limited accessibility
      - Constrained control
      - Basic protection
      - Moderate impact
      Required evidence:
      - Access limitations
      - Control constraints
      - Protection details
      - Impact scope
      
   D. Low Risk 
      - Difficult access
      - Minimal control
      - Strong protection
      - Minor impact
      Required evidence:
      - Access difficulty
      - Control limitations
      - Protection strength
      - Impact analysis

5. Analysis Requirements
   A. Completeness
      - Full call chain analysis
      - Complete parameter tracking
      - All condition verification
      - Protection assessment
      
   B. Evidence
      - Code snippets required
      - Addresses required
      - Parameter documentation
      - Condition verification

6. Command Execution Rules
   - Only one command can be executed at a time. Do not use semicolons to connect multiple commands.
   - Must provide evidence for conclusions,do not make any assumptions
   - Set status="complete",commands="None" only when full analysis done
   - If external tools are required beyond r2's static analysis capabilities (e.g., dynamic debugging, decompilation, hardware interaction), immediately terminate the task with status "complete" and provide an assessment based on available information.

Remember: Execute commands sequentially, analyze each result thoroughly, and provide complete evidence for all conclusions.
"""
        }]

    def get_llm_response(self, message_history, max_retries=3) -> str:
        for attempt in range(max_retries):
            try:
                # Filter out existing prefix messages
                # Only handle message alternation for deepseek-reasoner model
                if self.model == "deepseek-reasoner":
                    # First filter out prefix messages
                    message_history = [msg for msg in message_history if msg.get('type') != 'prefix']
                    
                    # Filter out consecutive assistant messages, keeping only the last one
                    filtered_messages = []
                    for i, msg in enumerate(message_history):
                        if msg['role'] == 'assistant':
                            # Skip if this is a consecutive assistant message (not the last one)
                            if (i + 1 < len(message_history) and 
                                message_history[i + 1]['role'] == 'assistant'):
                                continue
                        filtered_messages.append(msg)
                    message_history = filtered_messages
                    
                    # Check if last message is from assistant and add continuation if needed
                    if message_history and message_history[-1]['role'] == 'assistant':
                        message_history.append({
                            "role": "user",
                            "content": "Continue the analysis.",
                            "type": "continuation"
                        })
                
                    # Now add the prefix message
                    message_history.append({
                        "role": "assistant", 
                        "content": "```json\n",
                        "type": "prefix",
                        "prefix": True
                    })
                    
                # self.disassembly_logger.info(f"[LLM] Sending message: {message_history}")
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=message_history,
                    timeout=60,
                    # stop=["```"],
                    seed=42
                )
                if self.save_path:
                    input_tokens = response.usage.prompt_tokens
                    output_tokens = response.usage.completion_tokens
                    
                    input_cost = round(input_tokens * (2.50 / 1_000_000), 6)
                    output_cost = round(output_tokens * (10.00 / 1_000_000), 6)
                    total_cost = round(input_cost + output_cost, 6)
                    
                    usage_data = {
                        "input_cost": input_cost,
                        "output_cost": output_cost,
                        "total_cost": total_cost
                    }
                    
                    try:
                        token_usage_path = os.path.join(self.save_path, "token_usage.jsonl")
                        with open(token_usage_path, 'a', encoding='utf-8') as f:
                            f.write(json.dumps(usage_data) + '\n')
                    except Exception as e:
                        self.disassembly_logger.error(f"[LLM] Failed to save token usage: {str(e)}")
                
                return response.choices[0].message.content
                
            except httpx.TimeoutException:
                self.disassembly_logger.warning(f"[LLM] Timeout on attempt {attempt + 1}/{max_retries}")
                if attempt < max_retries - 1:
                    continue
                return json.dumps({
                    "analysis": "Analysis timeout, please retry",
                    "commands": "",
                    "status": "complete"
                })
            except Exception as e:
                self.disassembly_logger.error(f"[LLM] API error: {str(e)}")
                return json.dumps({
                    "analysis": f"API error: {str(e)}",
                    "commands": "",
                    "status": "complete"
                })

    def parse_llm_response(self, response: str) -> dict:
        self.disassembly_logger.info(f"[Parser] {response}")
        try:
            json_pattern = r'```(?:json)?\s*(\{.*?\})\s*```'
            matches = re.findall(json_pattern, response, re.DOTALL)
            
            if matches:
                json_str = matches[-1].strip()
            else:
                json_str = response.strip()
            
            result = json.loads(json_str)
            if not isinstance(result, dict):
                self.disassembly_logger.error("[Parser] Response is not a dictionary")
                raise ValueError("Response is not a dictionary")
            return result
                  
        except Exception as e:
            error_msg = f"Parsing error: {str(e)}\nOriginal response: {response}..."
            self.disassembly_logger.error(f"[Parser] {error_msg}")
            
            return {
                "analysis": {
                    "risk_level": "Unknown",
                    "reason": error_msg,
                    "next_step": "Please provide your response in valid JSON format."
                },
                "commands": "None",
                "status": "continue"
            }
        
    def execute_r2_command(self, cmd: str, timeout: int = 90) -> str:
        with self.r2_lock:
            result_queue = queue.Queue()
            
            def run_command(cmd, result_queue):
                try:
                    result = self.r2.cmd(cmd)
                    result_queue.put(result)
                except Exception as e:
                    result_queue.put(f"Error: {str(e)}")

            command_thread = threading.Thread(target=run_command, args=(cmd, result_queue))
            command_thread.daemon = True
            command_thread.start()
            
            try:
                result = result_queue.get(timeout=timeout)
                self.disassembly_logger.info(f"[Command] {cmd}")
                self.disassembly_logger.info(f"[Result]\n{result}")
                return result
            except queue.Empty:
                return "ERROR: Command timeout"
            except Exception as e:
                return f"ERROR: {str(e)}"
            
    def _validate_command(self, cmd_str: str) -> bool:
        valid_commands = {
            'pdd',
            'pdf',
            'afb',
            'afvd',
            'afcf',
            'axt',
            'axtj',
            'aflm',
            'afll',
            'pds',
            'af',
            'afi',
        }
        
        if ';' in cmd_str:
            self.disassembly_logger.error("[!] Error: Only one command can be executed at a time. Do not use semicolons to connect multiple commands.")
            return False
        
        try:
            parts = cmd_str.split()
            self.disassembly_logger.info(f"[Command] {parts}")
            base_cmd = parts[0]
            if base_cmd not in valid_commands:
                self.disassembly_logger.error(f"[Command] {base_cmd} is not a valid command")
                return False
            return True
        except (ValueError, IndexError):
            return False
        
    def write_analysis_logs(self, function_name: str, thread_id: int):
        logs = self.log_collector.get_logs(thread_id)
        if not logs:
            return
            
        log_text = f"\n=== Analysis for {function_name} ===\n"
        log_text += "\n".join(logs)
        log_text += "\n=== End of Analysis ===\n\n"
        
        with self.r2_lock:
            if self.save_path:
                try:
                    log_file = os.path.join(self.save_path, 'disassembly.log')
                    with open(log_file, 'a', encoding='utf-8') as f:
                        f.write(log_text)
                except Exception as e:
                    print(f"Error writing logs: {str(e)}")
    def analyze_function_risk(self, ref: dict):
        """Analyze function risk level based on dangerous function calls and call chains
        
        Args:
            ref: Dictionary containing function and call chain information:
            {
                'function': str,              # Name of immediate caller
                'address': int,               # Address of immediate caller
                'dangerous_function': str,     # Name of dangerous function
                'dangerous_addr': int,         # Address of dangerous function
                'call_chains': List[List[dict]] # Complete call chains to entry points
            }
        """
        thread_id = threading.get_ident()
        
        self.disassembly_logger.info(
            f"[Analysis] Analyzing function: {ref['function']} @ {hex(ref['address'])}"
        )
        
        last_analysis = {
            "function": ref['function'],
            "address": ref['address'],
            "risk_level": "Unknown",
            "reason": "Analysis incomplete"
        }

        try:
            local_message_history = self.message_history[:1]
            
            analysis_str = f"""Analyze this function call and its complete call chains:

Function Information:
- Insecure Function: {ref['dangerous_function']}
- Call Location: {hex(ref['dangerous_addr'])}
- Caller Function: {ref['function']} @ {hex(ref['address'])}

Call Chain Analysis:
"""
            if ref.get('call_chains'):
                for i, chain in enumerate(ref['call_chains'], 1):
                    analysis_str += f"\nCall Chain {i}:\n"
                    for func in chain:
                        name = func.get('name', 'unknown')
                        offset = func.get('offset', 0)
                        analysis_str += f"  -> {name} @ {hex(offset)}\n"
            else:
                analysis_str += "No call chains found - this might be a direct entry point\n"

            initial_prompt = f"""{analysis_str}

Please analyze the security risk considering:
1. Call chain accessibility and attack surface
2. Input validation and sanitization in the chain
3. Authentication and access controls
4. Existing protection mechanisms

For each call chain:
- Identify potential entry points
- Analyze parameter propagation
- Check for security controls
- Evaluate exploitation difficulty

Determine risk level (Critical/High/Medium/Low) based on:
- Number and accessibility of entry points
- Protection measures in the call chain
- Potential for privilege escalation
- Overall system impact

Notice:
- Based on the analysis, provide the risk level and reason for your analysis, do not make any assumptions
"""

            local_message_history.append({
                "role": "user",
                "content": initial_prompt,
                "type": "initial_analysis"
            })
            for idx, msg in enumerate(local_message_history):
                self.disassembly_logger.info(f"\n--- Message {idx + 1} ---")
                self.disassembly_logger.info(msg['content'])
            try:
                for i in range(self.MAX_ITERATIONS):
                    response = self.get_llm_response(local_message_history)
                    if not response:
                        continue

                    local_message_history.append({
                        "role": "assistant",
                        "content": response
                    })

                    parsed_response = self.parse_llm_response(response)
                    
                    if "Parsing error" in parsed_response.get('analysis', {}).get('reason', ''):
                        local_message_history.append({
                            "role": "user",
                            "content": "Please provide your response in valid JSON format.",
                            "type": "error_feedback"
                        })
                        continue
                    
                    if ('analysis' in parsed_response and 
                        isinstance(parsed_response['analysis'], dict) and
                        parsed_response['analysis'].get('risk_level') and 
                        parsed_response['analysis'].get('reason')):
                        
                        analysis = parsed_response['analysis']
                        last_analysis.update({
                            "risk_level": analysis['risk_level'],
                            "reason": analysis['reason']
                        })

                    if parsed_response.get('status') == 'complete':
                        break

                    if parsed_response.get('commands'):
                        cmd_str = parsed_response['commands'].strip()
                        
                        if self._validate_command(cmd_str):
                            result = self.execute_r2_command(cmd_str)

                            self.disassembly_logger.info(f"[Analysis] Executing command: {cmd_str}")
                            result_display = (
                                result[:self.MAX_RESULT_LENGTH] + 
                                f"\n... Result truncated (showing {self.MAX_RESULT_LENGTH} of {len(result)} chars)" 
                                if len(result) > self.MAX_RESULT_LENGTH 
                                else result
                            )
                            self.disassembly_logger.info(f"[Analysis] Execution result: {result_display}")
                            
                            local_message_history = [
                                msg for msg in local_message_history 
                                if (msg['role'] == 'system' or  
                                    (msg['role'] == 'user' and msg.get('type') == 'initial_analysis') or  
                                    msg['role'] == 'assistant')  
                            ]
                            
                            empty_msg = '''[!] Execution result is empty'''

                            command_result = f"""Command {cmd_str} execution result:

                            {result[:self.MAX_RESULT_LENGTH] if result else empty_msg}

                            Please analyze this result, pay special attention to security risks."""

                            local_message_history.append({
                                "role": "user",
                                "content": command_result,
                                "type": "command_result",
                            })
            except Exception as e:
                self.disassembly_logger.error(f"[Analysis] Error during LLM analysis: {str(e)}")
                last_analysis['reason'] = f"Analysis error: {str(e)}"
            finally:
                if 'local_message_history' in locals():
                    local_message_history.clear()

            self.write_analysis_logs(ref['function'], thread_id)
            return last_analysis

        except Exception as e:
            self.write_analysis_logs(ref['function'], thread_id)
            self.disassembly_logger.error(f"[Analysis] Error in risk analysis: {str(e)}")
            last_analysis['reason'] = f"Analysis error: {str(e)}"
            return last_analysis        
        
    def analyze_binary(self):
        @timeout_decorator(self.TIMEOUT_SECONDS)
        def run_analysis():
            if self.save_path:
                os.makedirs(self.save_path, exist_ok=True)
            
            self.disassembly_logger.info("[+] Finding dangerous functions...")
            dangerous_refs = self.find_dangerous_functions()
            
            if not dangerous_refs:
                self.disassembly_logger.warning("[!] No dangerous functions found")
                return "[]"
            
            self.disassembly_logger.info("[+] Building complete call chains...")
            call_chain_results = self.find_complete_call_chains(dangerous_refs)
            
            if not call_chain_results:
                self.disassembly_logger.warning("[!] No call chains found")
                return "[]"
            
            if len(call_chain_results) > self.MAX_ANALYSIS_COUNT:
                self.disassembly_logger.info(f"[Analysis] Found total {len(call_chain_results)} call chains")
                self.disassembly_logger.warning(f"[!] Limiting analysis to the top {self.MAX_ANALYSIS_COUNT} highest risk chains")
                call_chain_results = call_chain_results[:self.MAX_ANALYSIS_COUNT]
            
            all_results = []
            analyzed_chains = 0
            
            for chain_result in call_chain_results:
                if analyzed_chains >= self.MAX_ANALYSIS_COUNT:
                    break
                
                try:
                    result = self.analyze_function_risk({
                        'function': chain_result['caller_function'],
                        'address': chain_result['caller_addr'],
                        'dangerous_function': chain_result['dangerous_function'],
                        'dangerous_addr': chain_result['dangerous_addr'],
                        'call_chains': chain_result['call_chains']
                    })
                    
                    if result:
                        result.update({
                            'function': chain_result['caller_function'],
                            'address': chain_result['caller_addr'],
                        })
                        all_results.append(result)
                        analyzed_chains += 1
                        
                except Exception as e:
                    self.disassembly_logger.error(
                        f"[Run] Error analyzing chain for {chain_result['caller_function']}: {str(e)}"
                    )
                    continue

            if all_results and self.save_path:
                self._save_final_results(all_results)
            
            filtered_results = [
                result for result in all_results
                if result.get('risk_level', '').upper() in ['CRITICAL', 'HIGH']
            ]
            
            return json.dumps(filtered_results, ensure_ascii=False, indent=2)

        try:
            results = run_analysis()
            return results
        except TimeoutError:
            return "[]"
        except Exception as e:
            self.disassembly_logger.error(f"[Run] Error during analysis: {str(e)}")
            return "[]"

    def _save_final_results(self, results):
        if not self.save_path:
            return
        
        try:
            os.makedirs(self.save_path, exist_ok=True)
            result_file = os.path.join(self.save_path, 'disassembly.json')
            
            flattened_results = []
            for result_group in results:
                if isinstance(result_group, list):
                    flattened_results.extend(result_group)
                else:
                    flattened_results.append(result_group)
            
            simplified_results = []
            for result in flattened_results:
                simplified_result = {
                    "function": result.get('function'),
                    "address": result.get('address'),
                    "risk_level": result.get('risk_level'),
                    "reason": result.get('reason'),
                    "call_chain": result.get('call_chains', [])
                }
                simplified_results.append(simplified_result)
            
            with open(result_file, 'w', encoding='utf-8') as f:
                json.dump(simplified_results, f, ensure_ascii=False, indent=2)
            
            self.disassembly_logger.info(f"[Save] Analysis results saved to {result_file}")
            
        except Exception as e:
            self.disassembly_logger.error(f"[Save] Failed to save results: {str(e)}")
            raise

    def analyze_binary_parallel(self):
        @timeout_decorator(self.TIMEOUT_SECONDS)
        def run_parallel_analysis():
            if self.save_path:
                os.makedirs(self.save_path, exist_ok=True)
            
            self.disassembly_logger.info("[+] Finding dangerous functions...")
            dangerous_refs = self.find_dangerous_functions()
            
            if not dangerous_refs:
                self.disassembly_logger.warning("[!] No dangerous functions found")
                return "[]"
            
            self.disassembly_logger.info("[+] Building complete call chains...")
            call_chain_results = self.find_complete_call_chains(dangerous_refs)
            
            if not call_chain_results:
                self.disassembly_logger.warning("[!] No call chains found")
                return "[]"
            
            if len(call_chain_results) > self.MAX_ANALYSIS_COUNT:
                self.disassembly_logger.info(f"[Analysis] Found total {len(call_chain_results)} call chains")
                self.disassembly_logger.warning(f"[!] Limiting analysis to the top {self.MAX_ANALYSIS_COUNT} highest risk chains")
                call_chain_results = call_chain_results[:self.MAX_ANALYSIS_COUNT]
            
            with ThreadPoolExecutor(max_workers=min(os.cpu_count(), 4)) as executor:
                analysis_tasks = []
                for chain_result in call_chain_results:
                    analysis_params = {
                        'function': chain_result['caller_function'],
                        'address': chain_result['caller_addr'],
                        'dangerous_function': chain_result['dangerous_function'],
                        'dangerous_addr': chain_result['dangerous_addr'],
                        'call_chains': chain_result['call_chains']
                    }
                    task = executor.submit(self.analyze_function_risk, analysis_params)
                    analysis_tasks.append(task)
                
                all_results = []
                for future in as_completed(analysis_tasks):
                    try:
                        result = future.result()
                        if result:
                            all_results.append(result)
                    except Exception as e:
                        self.disassembly_logger.error(f"[Run] Error in parallel analysis task: {str(e)}")
                        continue
            
            if all_results and self.save_path:
                with self.r2_lock:
                    self._save_final_results(all_results)
            
            filtered_results = [
                result for result in all_results
                if result.get('risk_level', '').upper() in ['CRITICAL']
            ]
            
            return json.dumps(filtered_results, ensure_ascii=False, indent=2)

        try:
            results = run_parallel_analysis()
            return results
        except TimeoutError:
            return "[]"
        except Exception as e:
            self.disassembly_logger.error(f"[Run] Error during parallel analysis: {str(e)}")
            return "[]"





