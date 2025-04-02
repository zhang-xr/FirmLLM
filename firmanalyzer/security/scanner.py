import subprocess
import re
import os
import logging

class SecurityScanner:
    def __init__(self):
        # Configure logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        
        # Define keyword patterns
        self.patterns = {
            'passwords': r'(?<![\w/])(password|passwd|pwd|secret|key)(?![\w/-])',
            'private_keys': r'BEGIN.*PRIVATE.*KEY',
            'tokens': r'(?<![\w/])(token|api[_-]key|access[_-]key)(?![\w/-])',
            'urls': r'https?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
            'ips': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
            'emails': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'debug_flags': r'(?<![\w/])(debug|verbose|test)(?![\w/-])',
            'passwd_entry': r'^([^:]+):([^:]*):(\d+):(\d+):([^:]*):([^:]*):([^:]+)$',
            'root_user': r'^(root|admin|Admin):[^:]+:0:',
            'system_user': r'^[^:]+:x:\d+:\d+:[^:]*:/(?:root|bin|sbin):'
        }
        
        # Configure gitleaks
        self.gitleaks_enabled = self._check_tool_exists('gitleaks')
        
        # Add command whitelist
        self.command_whitelist = {
            'pwd', 'password', 'test', 'debug', 'verbose'  # Common commands for tools like busybox
        }

    def _check_tool_exists(self, tool_name):
        """Check if tool is available"""
        try:
            subprocess.check_output(['which', tool_name], stderr=subprocess.PIPE)
            self.logger.info(f"{tool_name} is available")
            return True
        except subprocess.CalledProcessError:
            self.logger.warning(f"{tool_name} is not available")
            return False

    def _run_gitleaks(self, file_path):
        """Run gitleaks scan"""
        if not self.gitleaks_enabled:
            return []
            
        try:
            cmd = [
                'gitleaks',
                'detect',
                '--source',
                file_path,
                '--no-git',
                '--verbose'
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            # Process output even if return code is non-zero
            if result.stdout:
                return [{
                    'tool': 'gitleaks',
                    'type': 'secret',
                    'finding': finding.strip(),
                    'file': file_path
                } for finding in result.stdout.split('\nFinding:')[1:]]
                
        except Exception as e:
            self.logger.error(f"Gitleaks scan error: {str(e)}")
        return []

    def scan_file(self, file_path):
        """Unified file scanning entry point
        
        Args:
            file_path: Path to file to scan
            
        Returns:
            list: List of scan results
        """
        try:
            # Check if file exists
            if not os.path.exists(file_path):
                self.logger.error(f"File does not exist: {file_path}")
                return []
                
            # Use file command to determine file type
            try:
                file_type = subprocess.check_output(['file', '-b', file_path], text=True).strip()
                self.logger.info(f"File type: {file_type}")
                
                # Determine if binary file
                is_binary = any(type_str in file_type.lower() for type_str in [
                    'executable', 'binary', 'elf', 'data'," share"
                ])
                
                if is_binary:
                    self.logger.info("Using binary scan method")
                    return self.scan_binary_file(file_path)
                else:
                    self.logger.info("Using text scan method")
                    return self.scan_text_file(file_path)
                    
            except subprocess.CalledProcessError:
                # If file command fails, try reading first few bytes to determine
                try:
                    with open(file_path, 'rb') as f:
                        content = f.read(1024)
                        is_binary = b'\0' in content
                        if is_binary:
                            return self.scan_binary_file(file_path)
                        else:
                            return self.scan_text_file(file_path)
                except Exception as e:
                    self.logger.error(f"Failed to read file: {str(e)}")
                    return []
                    
        except Exception as e:
            self.logger.error(f"Failed to scan file: {str(e)}")
            return []

    def scan_binary_file(self, file_path):
        """Scan binary file"""
        results = []
        # Keep existing version patterns
        version_patterns = {
            'semantic': rb'(?:version|ver|v)[\s\-_]?(\d+\.\d+(?:\.\d+)?)',
            'date': rb'(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])',
            'firmware': rb'[Ff][Ww][\s\-_]?\d+\.\d+(?:\.\d+)?[a-zA-Z]?\d*',
            'build': rb'[Bb]uild\s*\d{2,}',
            'release': rb'[Rr]elease\s*\d+[\d.]*'
        }
        
        # Add sensitive information patterns
        sensitive_patterns = {
            'passwords': rb'(?<![\w/])(password|passwd|pwd|secret|key)(?![\w/-])',
            'private_keys': rb'BEGIN.*PRIVATE.*KEY',
            'tokens': rb'(?<![\w/])(token|api[_-]key|access[_-]key)(?![\w/-])',
            'urls': rb'https?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
            'ips': rb'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
            'emails': rb'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        }
        
        try:
            cmd = ['strings', '-n', '4', '-t', 'd', file_path]
            strings_output = subprocess.check_output(cmd, text=True)
            
            for line_num, line in enumerate(strings_output.splitlines(), 1):
                if not line.strip():
                    continue
                    
                parts = line.split(None, 1)
                if len(parts) != 2:
                    continue
                    
                offset, string = parts
                offset = int(offset)
                
                # Scan version information
                for version_type, pattern in version_patterns.items():
                    pattern_str = pattern.decode('ascii')
                    matches = re.finditer(pattern_str, string, re.IGNORECASE)
                    for match in matches:
                        results.append({
                            'type': version_type,
                            'line_number': line_num,
                            'line_content': string.strip(),
                            'offset': offset,
                            'file': file_path
                        })
                
                # Scan sensitive information
                for sensitive_type, pattern in sensitive_patterns.items():
                    pattern_str = pattern.decode('ascii')
                    matches = re.finditer(pattern_str, string, re.IGNORECASE)
                    for match in matches:
                        match_str = match.group()
                        # Filter false positives
                        if match_str.lower() in self.command_whitelist:
                            continue
                        if self._is_false_positive(match_str, string):
                            continue
                            
                        results.append({
                            'type': sensitive_type,
                            'line_number': line_num,
                            'line_content': string.strip(),
                            'offset': offset,
                            'file': file_path
                        })
                        
        except Exception as e:
            self.logger.error(f"Error scanning binary file: {str(e)}")
            
        return self._deduplicate_results(results)

    def scan_text_file(self, file_path):
        results = []
        try:
            with open(file_path, 'r', errors='ignore') as f:
                lines = f.readlines()
                for i, line in enumerate(lines, 1):
                    line = line.strip()
                    
                    # Special handling for passwd file format
                    if '/passwd' in file_path or '/shadow' in file_path:
                        # Check if passwd file format
                        if re.match(self.patterns['passwd_entry'], line):
                            parts = line.split(':')
                            username, passwd, uid, gid = parts[:4]
                            
                            # Check privileged users
                            if uid == '0' or username.lower() in ['root', 'admin']:
                                results.append({
                                    'type': 'privileged_user',
                                    'line_number': i,
                                    'line_content': line,
                                    'details': f'Privileged user {username} (UID: {uid})',
                                    'file': file_path
                                })
                                
                            # Check system users
                            if int(uid) < 1000 and '/bin/' in parts[-1]:
                                results.append({
                                    'type': 'system_user',
                                    'line_number': i,
                                    'line_content': line,
                                    'details': f'System user {username} (UID: {uid})',
                                    'file': file_path
                                })
                                
                    # Regular pattern matching
                    for category, pattern in self.patterns.items():
                        if category in ['passwd_entry', 'root_user', 'system_user']:
                            continue  # These patterns were handled above
                            
                        matches = re.finditer(pattern, line, re.IGNORECASE)
                        for match in matches:
                            match_str = match.group()
                            if match_str.lower() in self.command_whitelist:
                                continue
                                
                            if self._is_false_positive(match_str, line):
                                continue
                                
                            results.append({
                                'type': category,
                                'line_number': i,
                                'line_content': line,
                                'file': file_path
                            })
                            
        except Exception as e:
            self.logger.error(f"Error scanning text file: {str(e)}")
            
        return self._deduplicate_results(results)

    def _is_false_positive(self, match_str, context):
        """Determine if false positive based on context"""
        # If match appears in command help or usage text
        if 'usage:' in context.lower() or '--help' in context:
            return True
        # If match is a command name
        if re.search(r'(?:^|\s)' + re.escape(match_str) + r'\s+[a-z-]+', context, re.I):
            return True
        return False

    def _deduplicate_results(self, results):
        """Deduplicate and sort results"""
        unique_results = []
        seen_matches = set()
        
        for result in results:
            # Use match content as unique key
            match_content = result['line_content'].strip()
            if match_content not in seen_matches:
                seen_matches.add(match_content)
                unique_results.append(result)
                
        # Sort by line number and offset
        return sorted(unique_results, key=lambda x: (x['line_number'], x.get('offset', 0)))


