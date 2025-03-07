import os
import re
import json
import logging
import subprocess
from firmanalyzer.LogManage import LogManager

explorer_logger = LogManager.get_logger('Explorer')
analyzer_logger = LogManager.get_logger('Analyzer')


def check_real_permissions(file_path: str):
    try:
        firmware_root = None
        current_path = file_path
        while current_path != '/':
            if 'squashfs-root' in os.path.basename(current_path):
                firmware_root = current_path
                break
            current_path = os.path.dirname(current_path)
            
        if firmware_root:
            rel_path = os.path.relpath(file_path, firmware_root)
            squashfs_file = None
            for parent in [os.path.dirname(firmware_root), os.path.dirname(os.path.dirname(firmware_root))]:
                for f in os.listdir(parent):
                    if f.endswith('.squashfs'):
                        squashfs_file = os.path.join(parent, f)
                        break
                if squashfs_file:
                    break
                    
            if squashfs_file:
                cmd = ['unsquashfs', '-ll', squashfs_file]
                output = subprocess.check_output(cmd, text=True)
                for line in output.splitlines():
                    if rel_path in line:
                        squashfs_perms = line.split()[0]
                        return squashfs_perms if squashfs_perms.strip() else None
            
        return None
                
    except Exception as e:
        logging.error(f"Error analyzing permissions: {e}")
        return None

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
                
            if len(result["reason"]) > 2000 or len(result["file"]) > 255:
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
    
def parse_directory_selection(response_text: str) -> dict:
    explorer_logger.debug(f"[Parser] Raw response: {response_text}")
    
    response_text = re.sub(r'```(?:json)?\s*|\s*```', '', response_text)
    
    json_pattern = re.compile(
        r'\{[^{]*"Directory"\s*:\s*"[^"]*"[^{]*"Reasoning"\s*:\s*"[^"]*"[^{]*\}',
        re.DOTALL
    )
    matches = json_pattern.finditer(response_text)
    
    valid_jsons = []
    for match in matches:
        try:
            json_str = match.group().strip()
            
            json_str = re.sub(r'\s+', ' ', json_str).strip()
            
            explorer_logger.debug(f"[Parser] Processed JSON string: {json_str}")
            
            data = json.loads(json_str)
            
            if not isinstance(data.get("Directory"), str) or not isinstance(data.get("Reasoning"), str):
                explorer_logger.warning(f"[Parser] Invalid field types in JSON: {json_str}")
                continue
                
            valid_jsons.append(data)
            
        except json.JSONDecodeError as e:
            explorer_logger.error(f"[Parser] JSON parsing error: {e}")
            continue
        except Exception as e:
            explorer_logger.error(f"[Parser] Unexpected error while parsing JSON: {e}")
            continue
    
    if not valid_jsons:
        explorer_logger.error("[Parser] No valid JSON objects found")
        raise ValueError("No valid JSON objects found in response")
        
    result = valid_jsons[0]
    explorer_logger.debug(f"[Parser] Successfully extracted JSON: {result}")
    return result

def parse_analysis_response(response_text: str) -> dict:
    analyzer_logger.info("-" * 50)
    analyzer_logger.info("Parsing response:")
    analyzer_logger.debug(f"Raw input: {response_text[:200]}..." if len(response_text) > 200 else response_text)
    
    try:
        if isinstance(response_text, dict):
            data = response_text
        else:
            cleaned_text = re.sub(r'```(?:json)?\s*|\s*```', '', response_text)
            
            data = None
            parse_methods = [
                ('direct_json', lambda x: json.loads(x)),
                ('preprocessed_json', lambda x: _preprocess_and_parse_json(x)),
                ('python_dict', lambda x: _parse_python_dict(x))
            ]
            
            for method_name, parse_func in parse_methods:
                try:
                    data = parse_func(cleaned_text)
                    if data and _validate_data_structure(data):
                        break
                except Exception:
                    continue
            
            if not data:
                raise ValueError("Failed to parse response using all methods")

        data = _normalize_data(data)
        
        _validate_data_fields(data)
        
        return data
        
    except Exception as e:
        analyzer_logger.warning(f"Failed to parse response: {str(e)}")
        raise ValueError(f"Failed to parse response: {str(e)}")

def _preprocess_and_parse_json(text: str) -> dict:
    try:
        text = re.sub(r'```(?:json)?\s*|\s*```', '', text)
        
        from collections import OrderedDict
        return json.loads(text, object_pairs_hook=OrderedDict)
            
    except Exception as e:
        analyzer_logger.warning(f"Preprocessing failed: {str(e)}")
        analyzer_logger.warning(f"Original text:\n{text}")
        raise

def _parse_python_dict(text: str) -> dict:
    import ast
    text = text.strip()
    if not (text.startswith('{') and text.endswith('}')):
        raise ValueError("Not a valid Python dictionary string")
    
    text = text.replace('True', 'True')\
               .replace('False', 'False')\
               .replace('None', 'None')
    
    return ast.literal_eval(text)

def _normalize_data(data: dict) -> dict:
    def normalize_value(value):
        if value is None:
            return ""
        if isinstance(value, bool):
            return str(value).lower()
        if isinstance(value, (int, float)):
            return value
        return str(value)
    
    def normalize_dict(d):
        if not isinstance(d, dict):
            return normalize_value(d)
        return {
            key: normalize_dict(value) if isinstance(value, dict) else normalize_value(value)
            for key, value in d.items()
        }
    
    return normalize_dict(data)

def _validate_data_structure(data: dict) -> bool:
    return isinstance(data, dict) and all(
        key in data for key in ['thought', 'command', 'status']
    )

def _validate_data_fields(data: dict) -> None:
    required_fields = {
        'thought': dict,
        'command': str,
        'status': lambda x: x in ['continue', 'complete']
    }
    
    for field, validation in required_fields.items():
        if field not in data:
            raise ValueError(f"Missing required field: {field}")
        
        if callable(validation):
            if not validation(data[field]):
                raise ValueError(f"Invalid value for field: {field}")
        elif not isinstance(data[field], validation):
            raise ValueError(f"Invalid type for field: {field}")
    
    thought_fields = {
        'findings': str,
        'severity': (int, float, str),
        'reason': str,
        'next_step': str
    }
    
    for field, field_type in thought_fields.items():
        if field not in data['thought']:
            raise ValueError(f"Missing required thought field: {field}")
        
        if not isinstance(data['thought'][field], field_type if isinstance(field_type, type) else field_type[0:][0]):
            if field == 'severity' and isinstance(data['thought'][field], str):
                try:
                    float_val = float(data['thought'][field])
                    data['thought'][field] = float_val
                    continue
                except ValueError:
                    pass
            raise ValueError(f"Invalid type for thought field: {field}")

def parse_directory_removal(response_text: str) -> dict:
    explorer_logger.debug(f"[Parser] Raw response: {response_text}")
    
    try:
        json_str = response_text.strip()
        json_str = re.sub(r'\r\n|\r|\n', '\n', json_str)
        
        json_str = re.sub(r'^```\s*(?:json)?\s*\n?|```\s*$', '', json_str, flags=re.MULTILINE)
        
        json_str = '\n'.join(line.strip() for line in json_str.split('\n'))
        
        json_pattern = re.compile(r'\{.*\}', re.DOTALL)
        match = json_pattern.search(json_str)
        if not match:
            raise ValueError("No JSON object found")
            
        json_str = match.group()
        
        json_str = re.sub(r'([{,]\s*)(\w+)(\s*:)', r'\1"\2"\3', json_str)
        
        json_str = re.sub(r"'([^']*)'", r'"\1"', json_str)
        
        json_str = re.sub(r',(\s*[}\]])', r'\1', json_str)
        
        explorer_logger.debug(f"[Parser] Preprocessed JSON: {json_str}")
        
        data = json.loads(json_str)
        
        findings = []
        if "findings" in data and isinstance(data["findings"], list):
            for finding in data["findings"]:
                if isinstance(finding, dict) and "issue" in finding and "reason" in finding:
                    findings.append({
                        "issue": str(finding["issue"]),
                        "reason": finding["reason"] if isinstance(finding["reason"], list) 
                                else str(finding["reason"])
                    })
        
        exclude = []
        if "exclude" in data and isinstance(data["exclude"], list):
            exclude = [str(d) for d in data["exclude"] if isinstance(d, (str, int))]
        
        result = {
            "findings": findings,
            "exclude": exclude
        }
        
        explorer_logger.debug(f"[Parser] Successfully parsed: {result}")
        return result
        
    except json.JSONDecodeError as e:
        explorer_logger.error(f"[Parser] JSON decode error: {e}")
        return {"findings": [], "exclude": []}
    except ValueError as e:
        explorer_logger.error(f"[Parser] Value error: {e}")
        return {"findings": [], "exclude": []}
    except Exception as e:
        explorer_logger.error(f"[Parser] Unexpected error: {e}")
        return {"findings": [], "exclude": []}
