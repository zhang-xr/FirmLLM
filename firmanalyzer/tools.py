import re
import subprocess
import logging
import os
import shutil
from typing import Dict, List
from collections import defaultdict
from math import log2

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler()]
)

PROCESS_TIMEOUT = 30
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB

VERSION_PATTERNS = [
    r'(?i)\b(?:v|version)?(?:0|[1-9]\d*[a-z]*)(?:\.(?:0|[1-9]\d*[a-z]*)){1,3}'
    r'(?:-(?:0|[1-9]\d*|\d*[a-z-][0-9a-z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-z-][0-9a-z-]*))*)?'
    r'(?:\+[0-9a-z-]+(?:\.[0-9a-z-]+)*)?\b',
    
    r'\b(?:20\d{2}(?:[-_./]?(?:0[1-9]|1[0-2]|jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec))'
    r'{1,2}(?:[-_./]?(?:0[1-9]|[12][0-9]|3[01]))?)\b',
    
    r'(?i)\b(?:build|bld|rev|r|rel|release)[-_]?(?:\d+[a-z]*|\d+\.\d+(?:\.\d+){0,2})\b',
    
    r'\b(?:\d+\.){3}\d+\b',
    
    r'(?i)\b(?:lib|dll|so|module)[-_]?(?:[a-z0-9]+[-_])?v?\d+(?:\.\d+){1,3}[a-z0-9-]*\b',
    
    r'\b(?:0x)?[0-9a-f]{4,8}(?:[-_.][0-9a-f]{4,8}){1,3}\b',
    
    r'\b(?:[a-z]+-?)(?:20\d{2}[a-z]?|\d+[a-z]{2,})\b',
    
    r'(?i)\b[a-z0-9_-]+[/-]v?\d+\.\d+(?:\.\d+)*[a-z0-9.-]*\b',
    
    r'(?i)\bv?\d+\.\d+(?:\.\d+)*[-_]?[a-z]+\d*\b',
    
    r'\b\d+\.\d+\.\d+[a-z]+\b'
]

SENSITIVE_PATTERNS = {
    'password': r'(?i)\b(?:password|passwd|pwd)\s*[:=]\s*["\']?([^\s"\']{8,})["\']?',
    'api_key': r'(?i)\b(?:api[_-]?key|secret[_-]?key)\s*[:=]\s*["\']?([a-f0-9]{16,}|[A-Za-z0-9+/]{32,})["\']?',
    'token': r'(?i)\b(?:access[_-]?token|auth[_-]?token|bearer)\s*[:=]\s*["\']?([a-f0-9]{32,}|eyJ[\w-]*\.[\w-]*\.[\w-]*)["\']?',
    'url': r'(?i)\b(?:https?|ftp)://(?:[^\s:@/]+(?::[^\s@/]*)?@)?(?:[a-z0-9-]+\.)+[a-z]{2,}\b(?:/[^\s"\']*)?',
    'ip': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?::\d{1,5})?\b',
    'email': r'\b[\w.%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b',
    'firmware_creds': r'(?i)\b(?:admin|root|user)\s*[=:]\s*["\']?(?:admin|root|password|12345|zte521)["\']?',
    'private_key': r'-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
    'encrypted_data': r'\b(?:AES|DES|3DES|BLOWFISH)[-_]?(?:KEY|IV)\s*[=:]\s*["\']?[0-9a-fA-F]{16,}["\']?',
    'debug_interface': r'(?i)\b(?:uart|jtag|console)\s*[=:]\s*\d+',
    'hidden_service': r'(?i)\b(?:backdoor|secret)_(?:port|service)\s*[=:]\s*\d+',
    'suspicious_path': r'/(?:etc|tmp|var)/(?:passwd|shadow|secret)[^\s"\']*',
    'base64_data': r'(?:[A-Za-z0-9+/]{4}){20,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
}

class BinaryAnalyzer:
    def __init__(self, file_path: str):
        self.file_path = self._validate_file(file_path)
        self.strings_cache = None
        self._common_false_positives = {
            'example.com', 'localhost', 'test.com', 
            'dummy', 'test', 'example', 'sample',
            'changeme', 'placeholder', 'TODO', 'FIXME'
        }

    @staticmethod
    def _validate_file(path: str) -> str:
        if not os.path.exists(path):
            raise ValueError(f"File does not exist: {path}")
        if os.path.islink(path):
            raise ValueError("Symbolic links are not supported")
        if not os.path.isfile(path):
            raise ValueError("Regular file required")
        if os.path.getsize(path) > MAX_FILE_SIZE:
            raise ValueError("File size exceeds limit")
        return os.path.abspath(path)

    def _get_strings_output(self) -> str:
        if self.strings_cache is not None:
            return self.strings_cache

        try:
            result = subprocess.run(
                ['strings', self.file_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=PROCESS_TIMEOUT
            )
            if result.returncode != 0:
                logging.warning(f"strings command failed: {result.stderr.decode()[:200]}")
                return ""
            
            self.strings_cache = result.stdout.decode('utf-8', errors='ignore')
            return self.strings_cache
        except Exception as e:
            logging.error(f"Failed to execute strings: {str(e)}")
            return ""

    def _safe_grep(self, pattern: str, data: str) -> List[str]:
        try:
            compiled = re.compile(pattern)
            return [m.group() for m in compiled.finditer(data)]
        except re.error as e:
            logging.warning(f"Invalid regex pattern {pattern}: {str(e)}")
            return []

    def _is_false_positive(self, s: str) -> bool:
        s_lower = s.lower()
        return any(fp in s_lower for fp in self._common_false_positives) or len(set(s)) < 4

    def extract_versions(self) -> List[str]:
        versions = []
        strings_data = self._get_strings_output()
        
        for pattern in VERSION_PATTERNS:
            matches = self._safe_grep(pattern, strings_data)
            for ver in matches:
                if len(ver) > 4 and not self._is_false_positive(ver):
                    versions.append(ver)
        
        return sorted(set(versions), key=len, reverse=True)

    def analyze_sensitive_info(self) -> Dict[str, List[str]]:
        results = defaultdict(list)
        strings_data = self._get_strings_output()
        
        for info_type, pattern in SENSITIVE_PATTERNS.items():
            matches = self._safe_grep(pattern, strings_data)
            filtered = [m for m in matches if not self._is_false_positive(m)]
            
            if info_type == 'base64_data':
                filtered = [s for s in filtered if self._validate_base64(s)]
            
            results[info_type].extend(filtered[:50])

        return dict(results)

    def _validate_base64(self, s: str) -> bool:
        import base64
        try:
            if len(s) % 4 != 0:
                return False
            base64.b64decode(s)
            return True
        except:
            return False

    def analyze_elf_info(self) -> Dict[str, List[str]]:
        elf_info = defaultdict(list)
        
        if not shutil.which('objdump'):
            logging.warning("objdump not available, skipping ELF analysis")
            return dict(elf_info)
        
        try:
            section_meta = subprocess.run(
                ['objdump', '-h', self.file_path],
                stdout=subprocess.PIPE,
                timeout=PROCESS_TIMEOUT
            ).stdout.decode(errors='ignore')
            
            section_strategies = {
                '.rodata': {'min_length': 6, 'filters': [self._is_version_like, self._is_credential_like], 'max_items': 50},
                '.data': {'min_length': 8, 'filters': [self._is_config_like], 'max_items': 30},
                '.comment': {'min_length': 4, 'filters': [self._is_compiler_info], 'max_items': 20}
            }
            
            for section, strategy in section_strategies.items():
                if f"{section} " in section_meta:
                    content = subprocess.run(
                        ['objdump', '-s', '-j', section, self.file_path],
                        stdout=subprocess.PIPE,
                        timeout=PROCESS_TIMEOUT
                    ).stdout.decode(errors='ignore')
                    
                    candidates = self._extract_meaningful_strings(content, strategy['min_length'])
                    filtered = [s.strip() for s in candidates if any(f(s.strip()) for f in strategy['filters'])]
                    if filtered:
                        elf_info[section] = list(dict.fromkeys(filtered))[:strategy['max_items']]
                    
            return dict(elf_info)
        except Exception as e:
            logging.error(f"ELF analysis failed: {str(e)}")
            return dict(elf_info)

    def _extract_meaningful_strings(self, content: str, min_length: int = 8) -> List[str]:
        base_strings = re.findall(fr'[\x20-\x7E]{{{min_length},}}', content)
        entropy_filtered = [s for s in base_strings if self._calculate_entropy(s) > 2.5]
        structure_patterns = [
            r'^[A-Za-z0-9][A-Za-z0-9_.+-]*$',
            r'^[A-Za-z]+(?:\s[A-Za-z]+)*$',
            r'^v?\d+\.\d+',
        ]
        return [s for s in entropy_filtered if any(re.match(p, s) for p in structure_patterns)]

    def _calculate_entropy(self, s: str) -> float:
        freq = defaultdict(int)
        for c in s:
            freq[c] += 1
        entropy, total = 0.0, len(s)
        for count in freq.values():
            p = count / total
            entropy -= p * log2(p)
        return entropy

    def _is_version_like(self, s: str) -> bool:
        return any(re.search(p, s) for p in VERSION_PATTERNS)

    def _is_credential_like(self, s: str) -> bool:
        return any(re.search(p, s) for p in SENSITIVE_PATTERNS.values())

    def _is_config_like(self, s: str) -> bool:
        config_patterns = [
            r'^[A-Za-z_][A-Za-z0-9_]*=',
            r'^\w+://',
            r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?$'
        ]
        return any(re.match(p, s) for p in config_patterns)

    def _is_compiler_info(self, s: str) -> bool:
        compiler_keywords = {'GCC', 'clang', 'MSVC', 'build', 'optimize', 'version', 'target', 'configure'}
        return any(kw in s for kw in compiler_keywords)

    def full_analysis(self) -> Dict:
        return {
            'file_info': {
                'path': self.file_path,
                'size': os.path.getsize(self.file_path),
                'sha256': self._calculate_hash(),
            },
            'versions': self.extract_versions(),
            'sensitive_info': self.analyze_sensitive_info(),
            'elf_sections': self.analyze_elf_info()
        }

    def _calculate_hash(self) -> str:
        try:
            result = subprocess.run(
                ['sha256sum', self.file_path],
                stdout=subprocess.PIPE,
                timeout=PROCESS_TIMEOUT
            )
            return result.stdout.decode().split()[0]
        except Exception as e:
            logging.warning(f"Hash calculation failed: {str(e)}")
            return ""
