import r2pipe
import re
from typing import List, Dict
import signal
from functools import wraps
import json

def timeout_handler(signum, frame):
    raise TimeoutError("r2 analysis timed out")

def with_timeout(seconds=30):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(seconds)
            try:
                result = func(*args, **kwargs)
            finally:
                signal.alarm(0)
            return result
        return wrapper
    return decorator

class R2VersionDetector:
    def __init__(self):
        self.version_patterns = [
            r'((?:v|V|version|Version|ver|Ver|REV|Revision|release|Release)[- _.]?[0-9][0-9a-zA-Z.-]+)',
            r'([0-9][0-9a-zA-Z.-]+(?:-(?:release|alpha|beta|rc|dev|snapshot)))',
            r'([0-9]+\.[0-9]+\.[0-9]+(?:-[0-9]+)?)',
            r'((?:v|V)?[0-9]+\.[0-9]+(?:-(?:dev|alpha|beta|rc|snapshot))?)'
        ]
        
        self.version_related_patterns = {
            'version_info': [
                r'SOFTWARE\s*VERSION',
                r'FIRMWARE\s*VERSION',
                r'BUILD\s*VERSION',
                r'RELEASE\s*VERSION',
                r'VERSION\s*INFO',
                r'VERSION\s*STRING'
            ],
            'version_func': [
                r'get[_]?version',
                r'version[_]?string',
                r'print[_]?version',
                r'show[_]?version'
            ],
            'version_var': [
                r'g_version',
                r'version_str',
                r'version_info',
                r'build_version'
            ]
        }

        self.dynamic_version_patterns = {
            'dynamic_load': [
                r'dlopen',
                r'dlsym',
                r'LoadLibrary',
                r'GetProcAddress',
                r'system',
                r'popen',
                r'exec[vl]?[pe]?'
            ],
            'config_file': [
                r'version\.txt',
                r'\.version',
                r'version\.conf',
                r'version\.json',
                r'version\.xml',
                r'VERSION'
            ],
            'env_vars': [
                r'VERSION=',
                r'APP_VERSION',
                r'PRODUCT_VERSION',
                r'SOFTWARE_VERSION',
                r'getenv'
            ],
            'dynamic_strings': [
                r'sprintf.*version',
                r'snprintf.*version',
                r'strcat.*version',
                r'strcpy.*version',
                r'strncpy.*version'
            ]
        }

    @with_timeout(30)
    def detect_version(self, binary_path: str) -> List[Dict]:
        versions = []
        r2 = None
        
        try:
            r2 = r2pipe.open(binary_path, flags=['-e', 'bin.relocs.apply=true'])
            
            r2.cmd('aaa')
            
            strings = r2.cmdj('izj') or []
            for s in strings:
                str_val = s.get('string', '')
                str_addr = s.get('vaddr', 0)
                if not str_val or not str_addr:
                    continue

                versions.extend(self._process_strings(str_val, 'data_section'))

                for pattern_type, patterns in self.version_related_patterns.items():
                    for pat in patterns:
                        if re.search(pat, str_val, re.IGNORECASE):
                            try:
                                xrefs = r2.cmdj(f"axtj @ {str_addr}") or []
                                if not isinstance(xrefs, list):
                                    xrefs = []
                            except json.JSONDecodeError:
                                xrefs = []

                            for xref in xrefs:
                                ref_addr = xref.get("from", 0)
                                if ref_addr:
                                    nearby_strings = self._analyze_nearby_strings(r2, ref_addr)
                                    for ns in nearby_strings:
                                        versions.extend(self._process_strings(ns, f'nearby_{pattern_type}'))

            strings_all = r2.cmd('izz')
            versions.extend(self._process_strings(strings_all, 'full_binary'))
            
            for s in strings:
                str_val = s.get('string', '')
                str_addr = s.get('vaddr', 0)
                if not str_val or not str_addr:
                    continue

                for dl_type, patterns in self.dynamic_version_patterns.items():
                    for pat in patterns:
                        if re.search(pat, str_val, re.IGNORECASE):
                            try:
                                xrefs = r2.cmdj(f"axtj @ {str_addr}") or []
                                if not isinstance(xrefs, list):
                                    xrefs = []
                            except json.JSONDecodeError:
                                xrefs = []

                            for xref in xrefs:
                                ref_addr = xref.get("from", 0)
                                if ref_addr:
                                    nearby_strings = self._analyze_nearby_strings(r2, ref_addr)
                                    for ns in nearby_strings:
                                        versions.extend(self._process_strings(ns, f'dynamic_{dl_type}'))
                                    
                                    func_strings = self._analyze_function_strings(r2, ref_addr)
                                    for fs in func_strings:
                                        versions.extend(self._process_strings(fs, f'func_{dl_type}'))

            for version in versions[:]:
                try:
                    str_info = r2.cmdj(f'izzj~{version["version"]}')
                    if str_info:
                        for item in str_info:
                            if 'offset' in item:
                                refs_cmd = f'axtj @ {item["offset"]}'
                                refs = r2.cmdj(refs_cmd)
                                if refs and len(refs) > 0:
                                    version['confidence'] += 0.1
                                    version['source'] += ' (referenced)'
                                    break
                except:
                    continue
                    
        except TimeoutError:
            return []
        except Exception as e:
            return []
        finally:
            if r2:
                try:
                    r2.quit()
                except:
                    pass
                    
        return self._deduplicate_versions(versions)
        
    def _process_strings(self, output: str, source: str) -> List[Dict]:
        versions = []
        
        for line in output.splitlines():
            for pattern in self.version_patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    version = match.group(1)
                    if self._is_valid_version(version):
                        versions.append({
                            'version': version,
                            'source': f'r2_{source}',
                            'confidence': self._calculate_confidence(version, source)
                        })
                        
        return versions
        
    def _is_valid_version(self, version: str) -> bool:
        if len(version) < 3 or len(version) > 30:
            return False
            
        if not any(c.isdigit() for c in version):
            return False
            
        if re.match(r'20\d{2}\.\d{2}\.\d{2}', version):
            return False
            
        invalid = ['0000', '1111', 'test', 'debug', 'unknown']
        if any(x in version.lower() for x in invalid):
            return False
            
        valid_patterns = [
            r'^(?:v|V|version|Version|ver|Ver|REV|Revision|release|Release)[- _.]?\d+\.\d+\.\d+(?:-?\w+)?$',
            r'^(?:v|V|version|Version|ver|Ver|REV|Revision|release|Release)[- _.]?\d+\.\d+(?:-?\w+)?$',
            r'^\d+\.\d+\.\d+(?:-?\w+)?$',
            r'^\d+\.\d+(?:-?\w+)?$',
            r'^[a-zA-Z-]+\d+\.\d+(?:\.\d+)?$',
            r'^\d+\.\d+\.\d+[a-zA-Z]\d*$'
        ]
        
        return any(re.match(p, version, re.IGNORECASE) for p in valid_patterns)
        
    def _calculate_confidence(self, version: str, source: str) -> float:
        score = 0.3
        
        if source == 'data_section':
            score += 0.2
        elif source.startswith('nearby_version_info'):
            score += 0.25
        elif source.startswith('nearby_version_func'):
            score += 0.2
        elif source.startswith('nearby_version_var'):
            score += 0.15
            
        if re.match(r'^\d+\.\d+\.\d+$', version):
            score += 0.3
        elif re.match(r'^\d+\.\d+$', version):
            score += 0.2
        elif re.match(r'v\d+\.\d+\.\d+$', version):
            score += 0.3
            
        version_parts = re.findall(r'\d+', version)
        if version_parts:
            if int(version_parts[0]) > 20:
                score -= 0.2
                
        if source.startswith('dynamic_load'):
            score += 0.15
        elif source.startswith('dynamic_config_file'):
            score += 0.2
        elif source.startswith('dynamic_env_vars'):
            score += 0.1
        elif source.startswith('dynamic_strings'):
            score += 0.15
        elif source.startswith('func_'):
            score += 0.2
        
        return min(max(score, 0.1), 1.0)
        
    def _deduplicate_versions(self, versions: List[Dict]) -> List[Dict]:
        unique_versions = {}
        
        for version in versions:
            v = version['version']
            if v not in unique_versions or version['confidence'] > unique_versions[v]['confidence']:
                unique_versions[v] = version
                
        result = list(unique_versions.values())
        result.sort(key=lambda x: x['confidence'], reverse=True)
        
        return result[:3]

    @with_timeout(30)
    def analyze_binary(self, binary_path: str) -> str:
        try:
            versions = self.detect_version(binary_path)
            
            if not versions:
                return "No version information detected"
            
            result = []
            result.append(f"radare2 detected {len(versions)} possible version(s):")
            
            for i, v in enumerate(versions, 1):
                result.append(f"\n{i}. Version: {v['version']}")
                result.append(f"   Confidence: {v['confidence']:.2f}")
                
            return "\n".join(result)
            
        except TimeoutError:
            return "Analysis timeout"
        except Exception as e:
            return f"Analysis error: {str(e)}"

    def _analyze_nearby_strings(self, r2, address: int, range_bytes: int = 32) -> List[str]:
        try:
            cmd = f"ps @@ {address-range_bytes}~{address+range_bytes}"
            strings = r2.cmd(cmd).splitlines()
            return strings
        except:
            return []

    def _analyze_function_strings(self, r2, address: int) -> List[str]:
        try:
            func_info = r2.cmdj(f'afij @ {address}')
            if not func_info or not isinstance(func_info, list):
                return []
            
            func_start = func_info[0].get('offset', 0)
            func_end = func_start + func_info[0].get('size', 0)
            
            strings_cmd = f'ps @@ {func_start}~{func_end}'
            strings = r2.cmd(strings_cmd).splitlines()
            return strings
        except:
            return []
