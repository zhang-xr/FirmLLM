import os
import yaml
import time
import glob
import logging
import subprocess
from pathlib import Path
from explore import explorer
import argparse
from LogManage import LogManager


def find_firmware_root(start_path, required_dirs=None, file_patterns=None, min_score=12):

    dir_weights = {
        'bin': 3, 'sbin': 2, 'lib': 3, 'etc': 2, 
        'usr': 1, 'var': 1, 'www': 2, 'system': 2
    }
    file_weights = {
        'bin/sh': 5, 'etc/*.conf': 2, '*.ko': 3,
        'init': 4, 'bin/busybox': 5, 'usr/lib/*.so': 2
    }
    
    # 合并自定义配置
    required_dirs = dir_weights if required_dirs is None else dict(required_dirs)
    file_patterns = file_weights if file_patterns is None else dict(file_patterns)
    
    best_candidate = {'path': None, 'score': 0, 'depth': 0}
    
    # 新增传统结构快速检测
    def is_standard_fs(root):
        must_have = ['bin', 'lib']
        optional = ['etc', 'usr', 'www', 'var']
        return (
            all(os.path.isdir(os.path.join(root, d)) for d in must_have) and
            any(os.path.isdir(os.path.join(root, d)) for d in optional)
        )

    # 新增根目录特征检测
    def is_root_like(root):
        return any(os.path.isdir(os.path.join(root, d)) for d in ['bin', 'sbin', 'etc'])

    for root, dirs, _ in os.walk(os.path.normpath(start_path), topdown=False):
        # 新增根目录优先判断
        if is_root_like(root) and is_standard_fs(root):
            return os.path.normpath(root)
        
        # 调整评分规则
        dir_score = sum(
            weight * (1 if os.path.isdir(os.path.join(root, d)) else 0)
            for d, weight in required_dirs.items()
        )
        
        # 文件特征评分
        file_score = 0
        for pattern, weight in file_patterns.items():
            full_pattern = os.path.join(root, pattern)
            file_score += weight * len(glob.glob(full_pattern))
        
        # 路径深度加分（每层+1）
        depth = len(os.path.relpath(root, start_path).split(os.sep))
        
        # 新增路径深度惩罚（越深得分越低）
        depth_penalty = depth * 0.2  # 原为加分项，现改为惩罚项
        total_score = dir_score + file_score - depth_penalty
        
        # 增强排除条件
        exclude_subdirs = {'modules', 'kernel', 'drivers'}
        if any(sd in root.split(os.sep) for sd in exclude_subdirs):
            continue  # 直接跳过内核模块等子目录
        
        # 排除干扰目录
        exclude_terms = {'extracted', 'unpacked', 'temp'}
        if any(term in root.lower() for term in exclude_terms):
            total_score *= 0.3  # 降低可疑路径的权重
        
        # 优选条件：分数更高 或 同分时路径更深
        if total_score >= min_score:
            if (total_score > best_candidate['score'] or 
               (total_score == best_candidate['score'] and depth > best_candidate['depth'])):
                best_candidate.update({
                    'path': root,
                    'score': total_score,
                    'depth': depth
                })
    
    # 如果没有检测到传统结构，执行原有评分逻辑
    return best_candidate['path'] if best_candidate['score'] >= min_score else None

def extract_firmware_with_binwalk(firmware_path: str, extract_path: str) -> str:
    """
    Extract firmware using binwalk and return the extraction report
    
    Args:
        firmware_path: Path to firmware file
        extract_path: Path to extract firmware to
        
    Returns:
        str: Binwalk extraction report
    """
    try:
        # Create extraction directory with firmware name
        firmware_name = os.path.splitext(os.path.basename(firmware_path))[0]
        firmware_extract_path = os.path.join(extract_path, firmware_name)
        
        # 清理已存在的提取目录，避免符号链接冲突
        if os.path.exists(firmware_extract_path):
            import shutil
            shutil.rmtree(firmware_extract_path)
            
        os.makedirs(firmware_extract_path, exist_ok=True)
        
        # Use the specified binwalk path
        binwalk_path = "/usr/local/rust-binwalk/binwalk-rust"
        
        # Run binwalk extraction
        cmd = f"'{binwalk_path}' -Me '{firmware_path}' --directory '{firmware_extract_path}'"
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        
        # Get binwalk report
        binwalk_report = stdout.decode('utf-8', errors='ignore')
        
        if process.returncode != 0:
            raise Exception(f"Binwalk extraction failed: {stderr.decode()}")
            
        return binwalk_report
        
    except Exception as e:
        logging.error(f"Firmware extraction failed: {str(e)}")
        raise

def process_firmware(input_path: str, output_path: str, extraction_path: str = None):
    """
    Process and analyze firmware (can be a file or extracted firmware directory)
    """
    # Setup logging first
    log_path = os.path.join(output_path, 'logs')
    LogManager.setup(log_path)
    logger = LogManager.get_logger('FirmwareProcessor')
    
    firmware_name = os.path.splitext(os.path.basename(input_path))[0]
    base_analysis_dir = os.path.join(output_path, firmware_name)
    
    # Create base analysis directory
    os.makedirs(base_analysis_dir, exist_ok=True)
    
    # Create analysis and extraction directories
    analysis_dir = os.path.join(base_analysis_dir, "analysis")  # 新的save_path位置
    extraction_path = os.path.join(base_analysis_dir, "extracted_firmware")
    
    os.makedirs(analysis_dir, exist_ok=True)
    os.makedirs(extraction_path, exist_ok=True)

    binwalk_report = ""
    filesystem_root = None

    # Check if input is file or directory
    if os.path.isdir(input_path):
        # If directory, skip extraction and find root filesystem
        logger.info(f"Input is an extracted firmware directory, analyzing directly: {input_path}")
        filesystem_root = find_firmware_root(input_path)
    else:
        # For files, proceed with extraction
        if not os.path.isfile(input_path):
            raise ValueError(f"Invalid firmware file: {input_path}")
        
        # Extract firmware and get binwalk report
        logger.info(f"Extracting firmware file: {input_path}")
        logger.info(f"Extracting to: {extraction_path}")
        binwalk_report = extract_firmware_with_binwalk(input_path, extraction_path)
        
        # Find firmware root directory in extracted files
        logger.info("Locating filesystem root in extracted firmware...")
        filesystem_root = find_firmware_root(extraction_path)

    if not filesystem_root:
        raise ValueError("Could not locate valid filesystem root directory")
    
    logger.info(f"Found filesystem root at: {filesystem_root}")
    
    # Pass the analysis directory as save_path
    return analyze_firmware_content(
        firmware_dir=filesystem_root, 
        save_path=analysis_dir,  # 使用analysis子目录
        binwalk_report=binwalk_report
    )

def analyze_firmware_content(firmware_dir: str, save_path: str, binwalk_report: str = ""):
    """
    Analyze firmware directory content and generate security analysis reports
    
    Args:
        firmware_dir: Path to firmware directory
        save_path: Path to save analysis results
        binwalk_report: Binwalk extraction report (empty string if firmware was pre-extracted)
    """
    # Start timing
    start_time = time.time()
    
    # Validate inputs
    if not os.path.isdir(firmware_dir):
        raise ValueError(f"Invalid firmware directory: {firmware_dir}")
    
    # Create save directory if not exists
    os.makedirs(save_path, exist_ok=True)
    
    # Configure logging early
    try:
        # Get the root logger
        root_logger = logging.getLogger()
        
        # Remove any existing handlers
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
            
        # Set the level
        root_logger.setLevel(logging.INFO)
        
        # Create and add handlers
        file_handler = logging.FileHandler(os.path.join(save_path, "explore.log"))
        console_handler = logging.StreamHandler()
        
        # Set format for both handlers
        formatter = logging.Formatter('%(name)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        # Add handlers to root logger
        root_logger.addHandler(file_handler)
        root_logger.addHandler(console_handler)
        
        # Test logging
        root_logger.info("Logging initialized successfully")
        root_logger.info(f"Analyzing firmware in: {firmware_dir}")
        root_logger.info(f"Saving results to: {save_path}")
        
    except Exception as e:
        print(f"Failed to initialize logging: {str(e)}")
        raise

    # Load prompts
    requirements_path = os.path.join(os.path.dirname(__file__), 'requirements.yaml')
    with open(requirements_path, encoding='utf-8') as f:
        prompts = yaml.safe_load(f)

    # Initialize analysis state
    initial_state = {
        "input": {
            "file_requirements": prompts['file_requirements']['user'],
            "file_findings_requirements": prompts['file_findings_requirements']['user'],
            "directory_requirements": prompts['directory_requirements']['user'],
            "security_report_template": prompts['security_report_template']['user'],
            "summary_template": prompts['summary_template']['user'],
        },
        "current_dir": firmware_dir,
        "base_path": str(Path(firmware_dir)),
        "dir_data": {
            "files": [],        # 初始为空列表，等待第一次目录扫描
            "index": 0,         # 初始索引为0
            "dir_path": ""      # 初始为空字符串，将在第一次扫描时设置
        },
        "dir_stack": [],        # 待处理的目录列表
        "response": {
            "thought": {
                "file": "",
                "reason": ""
            },
            "action": "next"
        },
        "scratchpad": [],
        "observation": "",
        "security_report_summary": binwalk_report[:10000],
        "save_path": save_path
    }

    # Run analysis
    security_report = explorer(initial_state, max_steps=360)
    
    # Calculate and log total time
    total_time = time.time() - start_time
    logging.info(f"Total analysis time: {total_time:.2f} seconds")
    
    return security_report

def main(firmware_path, save_path):
    """
    直接使用传入的参数分析固件
    
    Args:
        firmware_path: 固件文件或已提取固件目录的路径
        save_path: 保存分析结果的路径
        
    Returns:
        security_report: 分析报告
    """
    try:
        # Process firmware and get security report
        security_report = process_firmware(firmware_path, save_path)
        
        print(f"\nAnalysis complete. Results saved to: {save_path}")
        
        return security_report
        
    except Exception as e:
        print(f"Error during firmware analysis: {str(e)}")
        raise

if __name__ == "__main__":
    # Create argument parser
    parser = argparse.ArgumentParser(description='Firmware Analysis Tool')
    parser.add_argument('firmware_path', help='Path to firmware file or extracted firmware directory')
    parser.add_argument('save_path', help='Path to save analysis results')
    
    args = parser.parse_args()
    
    main(args.firmware_path, args.save_path)