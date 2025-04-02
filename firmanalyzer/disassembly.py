import r2pipe
import cmd
import httpx
import queue
import json
import re
import os
import logging
import threading
from typing import List
from functools import wraps
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from firmanalyzer.client import create_openai_client


class ThreadLogCollector:
    """Thread-safe log collector"""
    def __init__(self):
        self.logs = defaultdict(list)
        self.lock = threading.Lock()
    
    def add_log(self, thread_id: int, message: str):
        """Add a log message for a specific thread"""
        with self.lock:
            self.logs[thread_id].append(message)
    
    def get_logs(self, thread_id: int) -> List[str]:
        """Get all logs for a specific thread"""
        with self.lock:
            return self.logs.pop(thread_id, [])

def get_logger(name, save_path=None, log_collector=None):
    """Get a logger with thread-specific log collection
    
    Args:
        name: Logger name
        save_path: Optional path to save log file
        log_collector: ThreadLogCollector instance
    """
    logger = logging.getLogger(name)
    logger.handlers = []
    logger.setLevel(logging.INFO)
    
    class CollectorHandler(logging.Handler):
        def emit(self, record):
            if log_collector:
                thread_id = threading.get_ident()
                message = self.format(record)
                log_collector.add_log(thread_id, message)
    
    formatter = logging.Formatter('%(name)s - %(levelname)s - %(message)s')
    
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
        """Initialize R2 analyzer
        
        Args:
            binary_path: Binary file path
            save_path: Result save path
            max_analysis_count: Max number of call chains to analyze
            timeout_seconds: Overall analysis timeout (seconds)
            command_timeout: Single command timeout (seconds)
            max_iterations: Max LLM interaction iterations
            find_dangerous_timeout: Timeout for finding dangerous functions (seconds)
            target_functions: List of function names to prioritize in analysis
        """
        super().__init__()
        # Create logger instance
        self.log_collector = ThreadLogCollector()
        self.disassembly_logger = get_logger('R2', save_path, self.log_collector)
        self.disassembly_logger.info(f"[Init] Initializing: {binary_path}")
        self.binary_path = binary_path
        self.r2 = r2pipe.open(binary_path, flags=['-e', 'io.cache=true'])
        self.save_path = save_path
        
        # Config parameters
        self.MAX_ANALYSIS_COUNT = max_analysis_count
        self.TIMEOUT_SECONDS = timeout_seconds
        self.COMMAND_TIMEOUT = command_timeout
        self.MAX_ITERATIONS = max_iterations
        self.FIND_DANGEROUS_TIMEOUT = find_dangerous_timeout
        
        # R2 configuration
        self.r2.cmd('e anal.hasnext=true')    
        self.r2.cmd('e anal.depth=256')       
        self.r2.cmd('e io.va=true')           
        self.r2.cmd('aaa')                    
        
        # Get binary info
        info = self.r2.cmdj('ij')
        if not info:
            self.disassembly_logger.error("[Init] Failed to load binary file")
            raise RuntimeError("Failed to load binary file")
            
        self.disassembly_logger.info(f"[Init] Successfully loaded file: {info.get('core', {}).get('file', 'unknown')}")
        
        # Get base address
        self.base_addr = info.get('bin', {}).get('baddr', 0)
        self.disassembly_logger.info(f"[Init] Binary base address: 0x{self.base_addr:x}")

        # Analyze import table
        self.r2.cmd('aff')  
        self.r2.cmd('afr')  
        self.r2.cmd('af@@f')
        
        # Verify function analysis
        functions = self.r2.cmdj('aflj')
        if not functions:
            self.disassembly_logger.warning("[Init] No functions detected, attempting deeper analysis")
            self.r2.cmd('aaaa')  
            functions = self.r2.cmdj('aflj')
        
        self.disassembly_logger.info(f"[Init] Detected {len(functions) if functions else 0} functions")
        
        # Initialize LLM client
        self.model, self.client = create_openai_client()
        if self.model == "deepseek-reasoner":
            self.client.base_url = "https://api.deepseek.com/beta"
        
        # Initialize dangerous functions dictionary
        self.dangerous_functions = {
            # Command Injection (Critical, weight 30)
            "system": {"weight": 30, "category": "command_injection", "description": "Direct command execution, CVE-2016-1555/CVE-2018-1328"},
            "popen": {"weight": 30, "category": "command_injection", "description": "Command execution with pipe, CVE-2017-7859"},
            
            # Buffer Overflow (High, weight 25)
            "strcpy": {"weight": 25, "category": "buffer_overflow", "description": "Unbounded string copy, CVE-2020-10562"},
            "strcat": {"weight": 25, "category": "buffer_overflow", "description": "Unbounded string concatenation, CVE-2019-1573"},
            "gets": {"weight": 25, "category": "buffer_overflow", "description": "Dangerous input function, CVE-2016-2563"},
            "sprintf": {"weight": 25, "category": "buffer_overflow", "description": "Buffer overflow in string formatting, CVE-2020-8597"},
            "sscanf": {"weight": 25, "category": "buffer_overflow", "description": "String parsing overflow, CVE-2012-2393"},
            
            # Memory Corruption (High, weight 25) 
            "memcpy": {"weight": 25, "category": "memory", "description": "Memory copy without bounds check, CVE-2019-8936"},
            
            # Format String (High, weight 25)
            "fprintf": {"weight": 25, "category": "format_string", "description": "File output format string, CVE-2019-14685"},
            "printf": {"weight": 25, "category": "format_string", "description": "File output format string, CVE-2019-14685"},
            
            # Privilege Escalation (High, weight 25)
            "setuid": {"weight": 25, "category": "privilege", "description": "Privilege change, CVE-2019-11043"},
            
            # Network Input (Medium, weight 20)
            "recv": {"weight": 25, "category": "network", "description": "Network input handling, CVE-2020-8597"}
        }
        
        # Initialize conversation history
        self.message_history = []
        self._init_conversation()
        
        # Initialize caches and locks
        self.call_chain_cache = {}
        self.cache_lock = threading.Lock()
        self.r2_lock = threading.Lock()

        # Set result length limit
        self.MAX_RESULT_LENGTH = min(
            int(os.getenv('MAX_RESULT_LENGTH', 20000)),
            64000  # Hard limit 64k
        )

        # Store target functions
        self.target_functions = set(target_functions) if target_functions else set()
        if self.target_functions:
            self.disassembly_logger.info(f"[Init] Prioritizing analysis of functions: {self.target_functions}")

    @timeout_decorator(1800)
    def find_dangerous_functions(self):
        """Find dangerous function calls in the binary and their complete call chains
        
        Returns:
            list: List of dictionaries containing dangerous function references with format:
            [{
                'function': caller_function_name,
                'address': caller_function_address,
                'dangerous_calls': [{
                    'function': dangerous_function_name,
                    'address': dangerous_function_address,
                    'call_offset': call_location_address
                }]
            }]
        """
        self.disassembly_logger.info("[Find] Starting dangerous function search")
        try:
            # 使用嵌套字典存储，第一个键是函数名，第二个键是调用地址
            found_refs = {}
            
            # Get all functions, imports and symbols
            imports = self.r2.cmdj('iij') or []
            symbols = self.r2.cmdj('isj') or []
            functions = self.r2.cmdj('aflj') or []
            
            # Create address mapping for dangerous functions
            for item in imports + symbols + functions:
                name = item.get('name', '').lower()
                addr = item.get('vaddr', item.get('offset', 0))
                
                if not addr or not name:
                    continue
                    
                # Clean and normalize function name
                clean_name = re.sub(r'^[_@.]', '', name.split('.')[-1])
                base_name = clean_name.split('_')[0]
                
                # Check for dangerous function matches
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
                            
                            # Get cross references
                            xrefs = self.r2.cmdj(f'axtj @ {addr}') or []
                            for xref in xrefs:
                                ref_addr = xref.get('from', 0)
                                if ref_addr:
                                    # Get caller function info
                                    caller_func = self.r2.cmdj(f'afij @ {ref_addr}')
                                    if caller_func and caller_func[0]:
                                        found_refs[func_name][addr]['xrefs'].append({
                                            'caller_name': caller_func[0].get('name', 'unknown'),
                                            'caller_addr': caller_func[0].get('offset', 0),
                                            'call_offset': ref_addr
                                        })

            # Search for string references to dangerous functions
            strings = self.r2.cmdj('izj') or []
            for string in strings:
                str_value = string.get('string', '').lower()
                str_addr = string.get('vaddr', 0)
                
                if not str_addr:
                    continue
                    
                for func_name in self.dangerous_functions:
                    if func_name in str_value:
                        # Get cross references to the string
                        xrefs = self.r2.cmdj(f'axtj @ {str_addr}') or []
                        for xref in xrefs:
                            ref_addr = xref.get('from', 0)
                            if ref_addr:
                                # Get caller function info
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

            # Format results
            results = []
            for func_refs in found_refs.values():
                for ref in func_refs.values():
                    for xref in ref['xrefs']:
                        # Find or create caller entry
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
                        
                        # Add dangerous call info
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
                    'parse': 25.0,                 # 数据解析
                    'json': 25.0,                  # JSON处理
                    'xml': 25.0,                   # XML处理
                    'config': 28.0,                # 配置处理
                    
                    # 入口点函数 (中高权重)
                    'main': 35.0,                  # 主函数
                    'init': 25.0,                  # 初始化函数
                    'start': 25.0,                 # 启动函数
                    
                    # 处理器函数 (中等权重)
                    'handler': 22.0,               # 处理器函数
                    'process': 20.0,               # 处理函数
                    'handle': 22.0,                # 处理函数
                    'callback': 18.0,              # 回调函数
                    
                    # 输入处理 (高权重)
                    'input': 30.0,                 # 输入处理
                    'get': 25.0,                   # 获取数据
                    'post': 25.0,                  # 提交数据
                    'request': 25.0,               # 请求处理
                    'response': 20.0,              # 响应处理
                    
                    # 文件操作 (中等权重)
                    'file': 18.0,                  # 文件操作
                    'upload': 28.0,                # 文件上传 (高风险)
                    'download': 25.0,              # 文件下载
                    'read': 18.0,                  # 读取操作
                    'write': 20.0,                 # 写入操作
                    
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
        """Find complete call chains for dangerous function calls
        
        Args:
            dangerous_refs: Results from find_dangerous_functions()
            
        Returns:
            List[dict]: Complete analysis results with format:
            [{
                'dangerous_function': str,          # Name of dangerous function
                'dangerous_addr': int,              # Address of dangerous function
                'caller_function': str,             # Name of immediate caller
                'caller_addr': int,                 # Address of immediate caller
                'call_chains': List[List[dict]],    # Complete call chains to entry points
                'risk_score': float                 # Overall risk score
            }]
        """
        try:
            # 使用字典来合并同一函数的多个危险调用
            function_results = {}
            
            for ref in dangerous_refs:
                caller_func = ref['function']
                caller_addr = ref['address']
                
                for dangerous_call in ref['dangerous_calls']:
                    # 创建结果键
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
                        # 获取调用链
                        chains = []
                        visited = set()
                        
                        def build_chain(current_addr: int, current_chain: List[dict]):
                            """递归构建调用链，避免循环调用
                            
                            Args:
                                current_addr: 当前分析的函数地址
                                current_chain: 当前构建的调用链
                            """
                            # 首先检查是否已经在当前调用链中
                            if any(func.get('offset') == current_addr for func in current_chain):
                                return
                            
                            # 获取函数信息
                            func_info = self.r2.cmdj(f'afij @ {current_addr}')
                            if not func_info or not func_info[0]:
                                return
                            
                            # 添加当前函数到调用链
                            new_chain = current_chain + [func_info[0]]
                            
                            # 获取引用此函数的地址
                            refs = self.r2.cmdj(f'axtj @ {current_addr}') or []
                            
                            if not refs:
                                # 如果没有更多引用，说明到达了可能的入口点
                                chains.append(new_chain)
                            else:
                                # 继续构建调用链
                                for ref in refs:
                                    ref_addr = ref.get('from')
                                    if ref_addr and ref_addr not in visited:
                                        visited.add(ref_addr)
                                        build_chain(ref_addr, new_chain)
                                        visited.remove(ref_addr)
                        
                        # 构建调用链
                        build_chain(caller_addr, [])
                        
                        # 去重和评分
                        unique_chains = self._remove_duplicate_chains(chains)
                        
                        # 计算每条链的分数
                        for chain in unique_chains:
                            score = self._score_call_chain(chain, result['dangerous_function'])
                            # 只保留高分调用链
                            if score > result['risk_score']:
                                result['risk_score'] = score
                                if chain not in result['call_chains']:
                                    result['call_chains'].append(chain)
                    
                    except Exception as e:
                        self.disassembly_logger.error(f"[Chain] Error building call chains for {caller_func}: {str(e)}")
                        continue
            
            # 转换结果为列表并排序
            results = list(function_results.values())
            results.sort(key=lambda x: x['risk_score'], reverse=True)
            
            # 对每个结果限制调用链数量（保留最高分的10条）
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
   For each reply, return  only a single JSON object with format:
   ```
    {
    "analysis": {
        "risk_level": "Critical | High | Medium | Low | Unknown", 
        "reason": {
        "description": "Brief risk description",
        "evidence": "Call chain analysis; Key instructions; Variable tracking; Input sources; Taint trace",
        "confidence": "High | Medium | Low"
        },
        "next_step": "Next analysis step or target address"
    },
    "commands": "r2 command @ address",
    "status": "continue | complete"
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
- pdg @ <hex_addr>   # Decompile function
- pdf @ <hex_addr>   # Print disassembly 
- afb @ <hex_addr>   # Analyze basic blocks

Variable & Reference Analysis:
- afvd @ <hex_addr>  # Analyze variables 
- afcf @ <hex_addr>  # View call graph 
- axt @ <hex_addr>  # View cross references 

b. Basic Information Commands
-------------------------
Quick Info:
- af @ <hex_addr>    # Analyze function
- afi @ <hex_addr>   # Get basic function info

c. Command Syntax Examples
-------------------------
Valid Examples:
✓ pdg @ 0x4005a0           # Basic usage with default limit

Invalid Examples:
 pdg @ 4005a0     # Error: missing 0x prefix
 pdg @ 0x        # Error: incomplete address
 pdg             # Error: missing address
 pdg @ sys.upnpdev_main   # Error: invalid hex

---

## 3. Risk Evaluation Criteria

### A. Critical
- Input is externally controllable
- Input reaches a dangerous function (e.g., system, sprintf)
- Input is not sanitized
- Protection (bounds check, canary, ASLR, etc.) is missing
- The full taint path is confirmed

### B. High
- Indirect input
- Partial control
- Weak or bypassable protection

### C. Other (Medium | Low | Unknown)
- Controlled input with filtering
- Internal use only or difficult to reach
- Strong checks present
- Incomplete analysis or insufficient evidence
- Moderate or low impact

If any item is missing or unclear, **risk_level must be "High" or lower, or "Unknown"**
---

## 4. Evidence Requirements

For all conclusions, include:
- Taint propagation path
- Function chain (who called what)
- Variable flow tracking
- Relevant instruction addresses
- Unsafe function usage confirmation

---

## 5. Status Transition Rules

- `"status": "continue"` when analysis is ongoing (e.g., unresolved function, input unknown)
- `"status": "complete"` only when all:
  - Call chain traced
  - Input → sink confirmed
  - Variable state understood
  - Protections analyzed
- Use `"commands": "None"` only if status is `"complete"`

---

## 6. Disallowed Behaviors
- **Never** infer behavior or risk based on assumption
- Use `"risk_level": "Unknown"` if evidence is missing
- Do not elevate risk based on partial decompilation or guessed control flow
- No speculative reasoning (e.g., "this might be obfuscated")
- No multi-command lines (`;` not allowed)

---

## 7. Binary Extraction and Integrity Awareness (for Binwalk / Firmware Cases)

Binaries extracted from firmware images may have structural issues.
In such cases:
- Set `"risk_level": "Unknown"` if analysis is blocked
- Add `"confidence": "High | Medium | Low"
- **Never** speculate about binary structure issues without clear evidence
- Focus analysis only on visible and confirmed code sections
---

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
        """解析 LLM 响应，使用正则表达式提取JSON"""
        self.disassembly_logger.info(f"[Parser] {response}")
        try:
            # 首先尝试查找代码块
            code_block_pattern = r'```(?:json)?\s*([\s\S]*?)\s*```'
            code_blocks = re.findall(code_block_pattern, response, re.DOTALL)
            
            if code_blocks:
                # 尝试解析每个代码块，直到找到有效的JSON
                for block in code_blocks:
                    try:
                        block = block.strip()
                        result = json.loads(block)
                        if isinstance(result, dict):
                            return result
                    except json.JSONDecodeError:
                        continue
                
                # 如果所有代码块都不是有效JSON，尝试提取可能的JSON部分
                for block in code_blocks:
                    try:
                        # 尝试查找块中的JSON对象
                        json_pattern = r'(\{(?:[^{}]|(?:\{[^{}]*\}))*\})'
                        potential_jsons = re.findall(json_pattern, block, re.DOTALL)
                        for potential_json in potential_jsons:
                            try:
                                result = json.loads(potential_json)
                                if isinstance(result, dict):
                                    return result
                            except json.JSONDecodeError:
                                continue
                    except Exception:
                        continue
            
            # 尝试直接解析整个响应
            try:
                result = json.loads(response.strip())
                if isinstance(result, dict):
                    return result
            except json.JSONDecodeError:
                # 最后尝试提取可能的JSON部分
                json_pattern = r'(\{(?:[^{}]|(?:\{[^{}]*\}))*\})'
                potential_jsons = re.findall(json_pattern, response, re.DOTALL)
                for potential_json in potential_jsons:
                    try:
                        result = json.loads(potential_json)
                        if isinstance(result, dict):
                            return result
                    except json.JSONDecodeError:
                        continue
                
                self.disassembly_logger.error("[Parser] 无法从响应中提取有效的JSON")
                raise ValueError("响应中不包含有效的JSON")

        except Exception as e:
            error_msg = f"Parsing error: {str(e)}\nOriginal response: {response[:200]}..."
            self.disassembly_logger.error(f"[Parser] {error_msg}")
            
            # 返回一个带有命令的错误响应,这样可以触发下一轮对话
            return {
                "analysis": {
                    "risk_level": "Unknown",
                    "reason": error_msg,
                    "next_step": "Please provide your response in valid JSON format."
                },
                "commands": "None",  # 使用None作为命令,这样会被验证通过
                "status": "continue"
            }
            
    def execute_r2_command(self, cmd: str, timeout: int = 90) -> str:
        """Execute r2 command with timeout control and thread safety"""
        with self.r2_lock:  # Lock to ensure concurrency safety
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
                # 直接记录完整的命令执行结果
                self.disassembly_logger.info(f"[Command] {cmd}")
                self.disassembly_logger.info(f"[Result]\n{result}")
                return result
            except queue.Empty:
                return "ERROR: Command timeout"
            except Exception as e:
                return f"ERROR: {str(e)}"
            
    def _validate_command(self, cmd_str: str) -> bool:
        """Validate command format"""
        valid_commands = {
            'pdg',   # Decompile function (50 lines per view)
            'pdf',   # Print disassembly (50 lines per view)
            'afb',   # Analyze basic blocks (80 blocks per view)
            'afvd',  # Analyze variables and parameters (100 items per view)
            'afcf',  # View function call graph (100 calls per view)
            'axt',   # View cross references (100 refs per view)
            'axtj',  # View cross references in JSON format (100 refs per view)
            'aflm',  # List local variables
            'afll',  # List loop information
            'pds',   # View string constants
            'af',    # Analyze function
            'afi',   # Get basic function info
        }
        
        # Check if multiple commands are included
        if ';' in cmd_str:
            self.disassembly_logger.error("[!] Error: Only one command can be executed at a time. Do not use semicolons to connect multiple commands.")
            return False
        
        try:
            # Check basic format
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
        """Write collected logs for a specific analysis"""
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
            self.disassembly_logger.info(initial_prompt)
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

            # 分析完成后写入日志
            self.write_analysis_logs(ref['function'], thread_id)
            return last_analysis

        except Exception as e:
            self.write_analysis_logs(ref['function'], thread_id)
            self.disassembly_logger.error(f"[Analysis] Error in risk analysis: {str(e)}")
            last_analysis['reason'] = f"Analysis error: {str(e)}"
            return last_analysis        
        
    def analyze_binary(self):
        """Main analysis process without parallel processing"""
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
            
            # 限制分析数量
            if len(call_chain_results) > self.MAX_ANALYSIS_COUNT:
                self.disassembly_logger.info(f"[Analysis] Found total {len(call_chain_results)} call chains")
                self.disassembly_logger.warning(f"[!] Limiting analysis to the top {self.MAX_ANALYSIS_COUNT} highest risk chains")
                call_chain_results = call_chain_results[:self.MAX_ANALYSIS_COUNT]
            
            all_results = []
            analyzed_chains = 0
            
            # 分析每个调用链
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

            # 保存完整结果
            if all_results and self.save_path:
                self._save_final_results(all_results)
            
            # 过滤出高风险结果
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
        """Save analysis results to JSON file with simplified structure"""
        if not self.save_path:
            return
        
        try:
            os.makedirs(self.save_path, exist_ok=True)
            result_file = os.path.join(self.save_path, 'disassembly.json')
            
            # 展平嵌套的结果列表
            flattened_results = []
            for result_group in results:
                if isinstance(result_group, list):
                    flattened_results.extend(result_group)
                else:
                    flattened_results.append(result_group)
            
            # 简化结果结构
            simplified_results = []
            for result in flattened_results:
                simplified_result = {
                    "function": result.get('function'),
                    "address": result.get('address'),
                    "risk_level": result.get('risk_level'),
                    "reason": result.get('reason'),
                }
                simplified_results.append(simplified_result)
            
            with open(result_file, 'w', encoding='utf-8') as f:
                json.dump(simplified_results, f, ensure_ascii=False, indent=2)
            
            self.disassembly_logger.info(f"[Save] Analysis results saved to {result_file}")
            
        except Exception as e:
            self.disassembly_logger.error(f"[Save] Failed to save results: {str(e)}")
            raise

    def analyze_binary_parallel(self):
        """Main analysis process with parallel processing"""
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
            
            # 限制分析数量
            if len(call_chain_results) > self.MAX_ANALYSIS_COUNT:
                self.disassembly_logger.info(f"[Analysis] Found total {len(call_chain_results)} call chains")
                self.disassembly_logger.warning(f"[!] Limiting analysis to the top {self.MAX_ANALYSIS_COUNT} highest risk chains")
                call_chain_results = call_chain_results[:self.MAX_ANALYSIS_COUNT]
            
            # 创建线程池
            with ThreadPoolExecutor(max_workers=min(os.cpu_count(), 4)) as executor:
                # 准备任务列表
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
                
                # 收集结果
                all_results = []
                for future in as_completed(analysis_tasks):
                    try:
                        result = future.result()
                        if result:
                            all_results.append(result)
                    except Exception as e:
                        self.disassembly_logger.error(f"[Run] Error in parallel analysis task: {str(e)}")
                        continue
            
            # 保存完整结果
            if all_results and self.save_path:
                with self.r2_lock:
                    self._save_final_results(all_results)
            
            # 过滤出高风险结果
            filtered_results = [
                result for result in all_results
                if result.get('risk_level', '').upper() in ['CRITICAL', 'HIGH']
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

def test_binary_analysis(binary_path: str, save_path: str = "test_results") -> bool:
    """Test binary analysis functionality
    
    Args:
        binary_path: Path to test binary
        save_path: Path to save test results
        
    Returns:
        bool: True if all tests pass
    """
    try:
        # Initialize logger for testing
        test_logger = get_logger('R2Test', save_path)
        test_logger.info("[Test] Starting binary analysis test")
        
        # Test configuration
        test_config = {
            'max_analysis_count': 3,
            'timeout_seconds': 600,
            'command_timeout': 30,
            'max_iterations': 3,
            'find_dangerous_timeout': 300
        }
        
        # Initialize analyzer
        test_logger.info("[Test] Initializing R2Analyzer")
        analyzer = R2Analyzer(
            binary_path=binary_path,
            save_path=save_path,
            **test_config
        )
        
        # Test components
        test_results = {
            'init': False,
            'dangerous_funcs': False,
            'call_chains': False,
            'full_analysis': False
        }
        
        # Test 1: Check initialization
        try:
            test_logger.info("[Test] Testing initialization")
            if analyzer.r2 and analyzer.base_addr is not None:
                test_results['init'] = True
                test_logger.info("[Test] ✓ Initialization successful")
        except Exception as e:
            test_logger.error(f"[Test] ✗ Initialization failed: {str(e)}")
            return False
            
        # Test 2: Find dangerous functions
        try:
            test_logger.info("[Test] Testing dangerous function detection")
            dangerous_refs = analyzer.find_dangerous_functions()
            if isinstance(dangerous_refs, list):
                test_results['dangerous_funcs'] = True
                test_logger.info(f"[Test] ✓ Found {len(dangerous_refs)} dangerous function references")
                
                # Log found functions
                for ref in dangerous_refs[:3]:  # Log first 3 for brevity
                    test_logger.info(
                        f"Found: {ref['function']} @ {hex(ref['address'])} "
                        f"with {len(ref['dangerous_calls'])} dangerous calls"
                    )
        except Exception as e:
            test_logger.error(f"[Test] ✗ Dangerous function detection failed: {str(e)}")
            
        # Test 3: Call chain analysis
        if test_results['dangerous_funcs'] and dangerous_refs:
            try:
                test_logger.info("[Test] Testing call chain analysis")
                call_chains = analyzer.find_complete_call_chains(dangerous_refs)
                if isinstance(call_chains, list):
                    test_results['call_chains'] = True
                    test_logger.info(f"[Test] ✓ Found {len(call_chains)} call chains")
                    
                    # Log sample chains
                    for chain in call_chains[:2]:  # Log first 2 chains
                        test_logger.info(
                            f"Chain for {chain['dangerous_function']}: "
                            f"Risk score: {chain['risk_score']}"
                        )
            except Exception as e:
                test_logger.error(f"[Test] ✗ Call chain analysis failed: {str(e)}")
        
        # Test 4: Full analysis
        try:
            test_logger.info("[Test] Testing full binary analysis")
            results = analyzer.analyze_binary()
            if results and results != "[]":
                test_results['full_analysis'] = True
                test_logger.info("[Test] ✓ Full analysis completed successfully")
                
                # Parse and log results
                parsed_results = json.loads(results)
                test_logger.info(f"[Test] Found {len(parsed_results)} high-risk results")
                
                # Log sample results
                for result in parsed_results[:2]:  # Log first 2 results
                    test_logger.info(
                        f"Risk Level: {result.get('risk_level')} "
                        f"Function: {result.get('function')}"
                    )
        except Exception as e:
            test_logger.error(f"[Test] ✗ Full analysis failed: {str(e)}")
        
        # Calculate test coverage
        passed_tests = sum(test_results.values())
        total_tests = len(test_results)
        coverage = (passed_tests / total_tests) * 100
        
        # Log test summary
        test_logger.info("\n=== Test Summary ===")
        test_logger.info(f"Total Tests: {total_tests}")
        test_logger.info(f"Passed Tests: {passed_tests}")
        test_logger.info(f"Coverage: {coverage:.2f}%")
        for test_name, result in test_results.items():
            test_logger.info(f"{test_name}: {'✓' if result else '✗'}")
        
        # Clean up
        analyzer.r2.quit()
        
        return all(test_results.values())
        
    except Exception as e:
        if 'test_logger' in locals():
            test_logger.error(f"[Test] Critical test failure: {str(e)}")
        return False

def test_parallel_analysis(binary_path: str, save_path: str = "parallel_results") -> bool:
    """Test parallel binary analysis functionality"""
    try:
        # 初始化测试日志
        test_logger = get_logger('R2Test', save_path)
        
        # 添加控制台处理器用于测试输出
        console_handler = logging.StreamHandler()
        formatter = logging.Formatter('%(name)s - %(levelname)s - %(message)s')
        console_handler.setFormatter(formatter)
        test_logger.addHandler(console_handler)
        
        test_logger.info("[Test] Starting parallel analysis test")
        
        # 测试配置
        test_config = {
            'max_analysis_count': 5,  # 增加分析数量以测试并发
            'timeout_seconds': 600,
            'command_timeout': 30,
            'max_iterations': 3,
            'find_dangerous_timeout': 300
        }
        
        # 初始化分析器
        test_logger.info("[Test] Initializing R2Analyzer")
        analyzer = R2Analyzer(
            binary_path=binary_path,
            save_path=save_path,
            **test_config
        )
        
        # 测试组件
        test_results = {
            'init': False,
            'parallel_analysis': False,
            'log_collection': False,
            'thread_safety': False
        }
        
        # 测试1: 检查初始化
        try:
            if analyzer.r2 and analyzer.base_addr is not None:
                test_results['init'] = True
                test_logger.info("[Test] ✓ Initialization successful")
        except Exception as e:
            test_logger.error(f"[Test] ✗ Initialization failed: {str(e)}")
            return False
        
        # 测试2: 并发分析
        try:
            test_logger.info("[Test] Testing parallel analysis")
            results = analyzer.analyze_binary_parallel()
            parsed_results = json.loads(results)
            
            if isinstance(parsed_results, list):
                test_results['parallel_analysis'] = True
                test_logger.info(f"[Test] ✓ Parallel analysis completed with {len(parsed_results)} results")
        except Exception as e:
            test_logger.error(f"[Test] ✗ Parallel analysis failed: {str(e)}")
        
        # 测试3: 日志收集
        try:
            test_logger.info("[Test] Testing log collection")
            log_file = os.path.join(save_path, 'disassembly.log')
            if os.path.exists(log_file):
                with open(log_file, 'r', encoding='utf-8') as f:
                    log_content = f.read()
                
                # 检查日志格式和完整性
                if "=== Analysis for" in log_content and "=== End of Analysis ===" in log_content:
                    test_results['log_collection'] = True
                    test_logger.info("[Test] ✓ Log collection working correctly")
        except Exception as e:
            test_logger.error(f"[Test] ✗ Log collection test failed: {str(e)}")
        
        # 测试4: 线程安全
        try:
            test_logger.info("[Test] Testing thread safety")
            # 检查日志中的分析块是否完整
            with open(log_file, 'r', encoding='utf-8') as f:
                log_content = f.read()
            
            # 统计分析块的开始和结束标记数量
            start_markers = log_content.count("=== Analysis for")
            end_markers = log_content.count("=== End of Analysis ===")
            
            if start_markers == end_markers and start_markers > 0:
                test_results['thread_safety'] = True
                test_logger.info("[Test] ✓ Thread safety verified")
        except Exception as e:
            test_logger.error(f"[Test] ✗ Thread safety test failed: {str(e)}")
        
        # 计算测试覆盖率
        passed_tests = sum(test_results.values())
        total_tests = len(test_results)
        coverage = (passed_tests / total_tests) * 100
        
        # 输出测试总结
        test_logger.info("\n=== Test Summary ===")
        test_logger.info(f"Total Tests: {total_tests}")
        test_logger.info(f"Passed Tests: {passed_tests}")
        test_logger.info(f"Coverage: {coverage:.2f}%")
        for test_name, result in test_results.items():
            test_logger.info(f"{test_name}: {'✓' if result else '✗'}")
        
        # 清理
        analyzer.r2.quit()
        
        return all(test_results.values())
        
    except Exception as e:
        if 'test_logger' in locals():
            test_logger.error(f"[Test] Critical test failure: {str(e)}")
        return False

if __name__ == "__main__":
    # 示例用法
    test_binary = "cgibin,0x405e18"
    success = test_parallel_analysis(test_binary)
    print(f"\n{'='*50}")
    print(f"Parallel analysis test {'passed' if success else 'failed'}")
    print(f"{'='*50}\n")






