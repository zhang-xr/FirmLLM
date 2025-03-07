import os 
import re
import requests
import json
import time
from bs4 import BeautifulSoup  # Add BeautifulSoup for parsing HTML
from typing import List, Dict, Any
from client import create_openai_client

def parse_openai_response(response_text: str) -> List[Dict[str, str]]:
    """
    从LLM响应中提取并验证JSON数据
    返回结构示例：[{"cve_id": "CVE-XXXX-XXXX", "description": "..."}]
    """
    # 匹配JSON数组模式（支持多行）
    json_pattern = r'\[\s*\{.*?\}\s*\]'
    matches = re.finditer(json_pattern, response_text, re.DOTALL)
    
    valid_entries = []
    
    for match in matches:
        try:
            # 尝试解析JSON
            json_str = match.group()
            parsed = json.loads(json_str)
            
            # 验证数据结构
            if isinstance(parsed, list):
                for entry in parsed:
                    if all(key in entry for key in ('cve_id', 'description')):
                        # 基础字段验证
                        valid_entry = {
                            'cve_id': str(entry['cve_id']).strip(),
                            'description': str(entry['description']).strip()
                        }
                        # 可选添加额外验证（如CVE ID格式）
                        if valid_entry['cve_id'].startswith('CVE-'):
                            valid_entries.append(valid_entry)
                        else:
                            print(f"Invalid CVE ID format: {valid_entry['cve_id']}")
            else:
                print(f"Expected JSON array, got {type(parsed)}")
                
        except json.JSONDecodeError as e:
            print(f"JSON解析失败: {str(e)}")
            print(f"Problematic JSON: {json_str}")
            
    return valid_entries
def parse_component_and_version(component: str) -> tuple:
    """使用正则表达式匹配版本号"""
    version_pattern = r"\b(v?\d+\.\d+[\w.]*)\b"
    match = re.search(version_pattern, component)
    if match:
        version = match.group(1)
        name = component.replace(version, "").strip()
        return name, version
    return component, ""

def parse_mitre_html(html_content, component_name, version):
    """Parse MITRE HTML response to extract CVE information"""
    soup = BeautifulSoup(html_content, 'html.parser')
    cve_items = []
    
    # Find tables (not dependent on specific ID)
    tables = soup.find_all('table')
    
    for table in tables:
        rows = table.find_all('tr')
        for row in rows:
            cells = row.find_all('td')
            if len(cells) >= 2:  # Ensure at least two columns
                cve_cell = cells[0]
                desc_cell = cells[1]
                
                # Find CVE ID
                cve_link = cve_cell.find('a')
                if cve_link and 'CVE-' in cve_link.text:
                    cve_id = cve_link.text.strip()
                    desc_text = desc_cell.text.strip()
                    
                    # Check if description contains component name (case insensitive)
                    if component_name.lower() in desc_text.lower():
                        cve_item = {
                            'cve_id': cve_id,
                            'description': desc_text,
                            'source': 'MITRE'
                        }
                        cve_items.append(cve_item)
    
    print(f"Found {len(cve_items)} related CVEs from MITRE")
    return cve_items

def analyze_cve_with_openai(component_name: str, version: str, search_results: Dict[str, Any]) -> List[str]:
    """Analyze CVE results using OpenAI, supporting batch processing"""
    # Extract all CVE entries from search results
    all_cves = []
    if search_results.get("mitre"):
        all_cves.extend(search_results["mitre"])
    
    # Batch size
    BATCH_SIZE = 15
    analyzed_results = []
    
    # Process CVEs in batches
    for i in range(0, len(all_cves), BATCH_SIZE):
        batch = all_cves[i:i + BATCH_SIZE]
        batch_num = i//BATCH_SIZE + 1
        
        # Prepare prompt
        prompt = f"""
Target Component: {component_name}{version}

Please analyze the following {len(batch)} CVEs to determine if they affect this version. Do not make extra inferences.
{json.dumps(batch, indent=2)}

**Version Analysis Rules**:
When analyzing CVEs:
   - Only include CVEs where the vulnerable version range INCLUDES the component version
   For example, if the component version is 1.01, and the CVE description mentions version through v1.02, it should be included.

Please return all matching CVEs in JSON format, otherwise return an empty list. Do not include any other content. Format as follows:
'''
[
    {{
        "cve_id": "CVE-ID",
        "description": "Vulnerability description",
    }}
]
'''

"""
        print(prompt)
        try:
            # Call OpenAI API
            model,client = create_openai_client()
            response = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": "You are a security expert specializing in analyzing CVE vulnerability information to confirm which CVEs affect the target component."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0
            )
            # Get response text
            if response.choices and response.choices[0].message:
                result_text = response.choices[0].message.content
                print(f"\n=== Batch {batch_num} Analysis Results ===")
                parsed_data = parse_openai_response(result_text)
                analyzed_results.extend(parsed_data)
                print(parsed_data)
                print(f"Analyzed {len(analyzed_results) * BATCH_SIZE}/{len(all_cves)} CVEs")
            
            # Add delay to avoid rate limits
            time.sleep(1)
            
        except Exception as e:
            print(f"Error processing batch {batch_num}: {e}")
            continue
    
    print("\n=== Merging Analysis Results ===")
    print(json.dumps(analyzed_results, indent=2, ensure_ascii=False))  # 修改这里
    
    return analyzed_results

def query_nvd_and_mitre(component: str, save_path: str = None):
    """
    Query CVE information for a component
    :param component: Component name, e.g. "BusyBox 1.01" or "BusyBox v1.01" 
    :param save_path: Optional path to save results to JSON file
    """
    # Parse component name and version
    component_name, version = parse_component_and_version(component)
    
    try:
        print(f"\nQuerying MITRE: {component}")
        mitre_url = f"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={component}"
        mitre_response = requests.get(mitre_url)
        
        if mitre_response.status_code == 200:
            mitre_results = parse_mitre_html(mitre_response.text, component_name, version)
        else:
            print(f"MITRE returned error status code: {mitre_response.status_code}")
            mitre_results = None
            
    except Exception as e:
        print(f"MITRE query error: {e}")
        mitre_results = None

    # Integrate results
    results = {
        "mitre": mitre_results,
        "component": component_name,
        "version": version
    }

    # Sort and limit results before analysis
    if results["mitre"]:
        # Sort CVEs by ID in descending order (newest first)
        sorted_cves = sorted(results["mitre"], 
                           key=lambda x: x['cve_id'], 
                           reverse=True)

        results["mitre"] = sorted_cves[:100]
        print(f"Limited to newest 100 CVEs from {len(sorted_cves)} total CVEs")

    # Analyze results using OpenAI
    analyzed_results = analyze_cve_with_openai(component_name, version, results)
    
    # Save results if save_path provided
    if save_path:
        try:
            os.makedirs(save_path, exist_ok=True)
            output_file = os.path.join(save_path, "cve_search.txt")
            with open(output_file, 'a', encoding="utf-8") as f:
                save_data = {
                    "analyzed_results": analyzed_results
                }
                json.dump(save_data, f, indent=2)
            print(f"Results saved to {output_file}")
        except Exception as e:
            print(f"Error saving results to file: {e}")
        print(f"\n=== Final Results ===")
    print(f"Total vulnerabilities found: {len(analyzed_results)}")
    for idx, cve in enumerate(analyzed_results, 1):
        print(f"{idx}. [{cve['cve_id']}] {cve['description'][:60]}...")
    
    return {
        "raw_results": results,
        "analyzed_results": analyzed_results
    }


if __name__ == "__main__":
    components = [
        "BusyBox 1.01",
        "hostapd 2.0-devel",
        "wpa_supplicant 2.0-devel"
    ]
    
    print("Starting component vulnerability query...")
    all_results = {}
    for component in components:
        print(f"\n=== Querying component: {component} ===")
        results = query_nvd_and_mitre(component,"./cve_results")
        all_results[component] = results
        time.sleep(1)  # Add brief delay
    
    print("\nQuery complete")
