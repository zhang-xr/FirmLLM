import os
import yaml
import time
import glob
import logging
import subprocess
import argparse
import configparser
from pathlib import Path
from firmanalyzer.explore import explorer
from firmanalyzer.LogManage import LogManager


def load_binwalk_path():
    config = configparser.ConfigParser()
    config_path = os.path.join(os.path.dirname(__file__), 'config.ini')
    try:
        config.read(config_path)
        return config.get('Settings', 'binwalk_path', fallback='/usr/local/bin/binwalk')
    except Exception as e:
        logging.warning(f"Failed to load config file, using default binwalk path: {str(e)}")
        return '/usr/local/bin/binwalk'


def extract_firmware_with_binwalk(firmware_path: str, extract_root: str) -> str:
    firmware_name = os.path.splitext(os.path.basename(firmware_path))[0]
    firmware_extract_path = os.path.join(extract_root, firmware_name)

    if os.path.exists(firmware_extract_path):
        import shutil
        shutil.rmtree(firmware_extract_path)

    os.makedirs(firmware_extract_path, exist_ok=True)
    binwalk_path = load_binwalk_path()

    cmd = f"'{binwalk_path}' -Me '{firmware_path}' --directory '{firmware_extract_path}'"
    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()

    if process.returncode != 0:
        raise Exception(f"Binwalk extraction failed: {stderr.decode()}")

    return stdout.decode('utf-8', errors='ignore')


def find_firmware_root(start_path, required_dirs=None, file_patterns=None, min_score=12):
    dir_weights = {
        'bin': 3, 'sbin': 2, 'lib': 3, 'etc': 2, 'usr': 1,
        'var': 1, 'www': 2, 'system': 2
    }
    file_weights = {
        'bin/sh': 5, 'etc/*.conf': 2, '*.ko': 3,
        'init': 4, 'bin/busybox': 5, 'usr/lib/*.so': 2
    }
    required_dirs = required_dirs or dir_weights
    file_patterns = file_patterns or file_weights
    best = {'path': None, 'score': 0, 'depth': 0}

    def is_standard_fs(root):
        must_have = ['bin', 'lib']
        optional = ['etc', 'usr', 'www', 'var']
        return all(os.path.isdir(os.path.join(root, d)) for d in must_have) and \
               any(os.path.isdir(os.path.join(root, d)) for d in optional)

    def is_root_like(root):
        return any(os.path.isdir(os.path.join(root, d)) for d in ['bin', 'sbin', 'etc'])

    for root, dirs, _ in os.walk(os.path.normpath(start_path), topdown=False):
        if is_root_like(root) and is_standard_fs(root):
            return os.path.normpath(root)

        dir_score = sum(weight for d, weight in required_dirs.items() if os.path.isdir(os.path.join(root, d)))
        file_score = sum(weight * len(glob.glob(os.path.join(root, pattern)))
                         for pattern, weight in file_patterns.items())
        depth = len(os.path.relpath(root, start_path).split(os.sep))
        depth_penalty = depth * 0.2
        total_score = dir_score + file_score - depth_penalty

        if any(x in root.split(os.sep) for x in {'modules', 'kernel', 'drivers'}):
            continue
        if any(term in root.lower() for term in {'extracted', 'unpacked', 'temp'}):
            total_score *= 0.3

        if total_score >= min_score and (total_score > best['score'] or 
           (total_score == best['score'] and depth > best['depth'])):
            best.update({'path': root, 'score': total_score, 'depth': depth})

    return best['path'] if best['score'] >= min_score else None


def analyze_firmware_content(firmware_dir: str, save_path: str, binwalk_report: str = ""):
    start_time = time.time()

    if not os.path.isdir(firmware_dir):
        raise ValueError(f"Invalid firmware directory: {firmware_dir}")
    os.makedirs(save_path, exist_ok=True)

    logger = LogManager.get_logger('FirmwareContentAnalyzer', os.path.join(save_path, "explore.log"))
    logger.info(f"Analyzing firmware in: {firmware_dir}")
    logger.info(f"Saving results to: {save_path}")

    with open(os.path.join(os.path.dirname(__file__), 'requirements.yaml'), encoding='utf-8') as f:
        prompts = yaml.safe_load(f)

    state = {
        "input": {
            "file_requirements": prompts['file_requirements']['user'],
            "file_findings_requirements": prompts['file_findings_requirements']['user'],
            "directory_requirements": prompts['directory_requirements']['user'],
            "security_report_template": prompts['security_report_template']['user'],
            "summary_template": prompts['summary_template']['user'],
        },
        "current_dir": firmware_dir,
        "base_path": str(Path(firmware_dir)),
        "dir_data": {"files": [], "index": 0, "dir_path": ""},
        "dir_stack": [],
        "response": {"thought": {"file": "", "reason": ""}, "action": "next"},
        "scratchpad": [],
        "observation": "",
        "security_report_summary": binwalk_report[:10000],
        "save_path": save_path
    }

    report = explorer(state, max_steps=360)
    logging.info(f"Total analysis time: {time.time() - start_time:.2f} seconds")
    return report


def process_firmware(input_path: str, output_path: str):
    logger = LogManager.get_logger('FirmwareProcessor')
    firmware_name = os.path.splitext(os.path.basename(input_path))[0]
    base_dir = os.path.join(output_path, firmware_name)
    analysis_dir = os.path.join(base_dir, "log")
    extraction_dir = os.path.join(base_dir, "extracted")

    os.makedirs(analysis_dir, exist_ok=True)
    os.makedirs(extraction_dir, exist_ok=True)
    LogManager.setup(analysis_dir)

    binwalk_report = ""
    if os.path.isdir(input_path):
        logger.info(f"Analyzing extracted firmware directory: {input_path}")
        root = find_firmware_root(input_path)
    else:
        if not os.path.isfile(input_path):
            raise ValueError(f"Invalid firmware file: {input_path}")
        logger.info(f"Extracting firmware: {input_path} -> {extraction_dir}")
        binwalk_report = extract_firmware_with_binwalk(input_path, extraction_dir)
        root = find_firmware_root(extraction_dir)

    if not root:
        raise ValueError("Could not locate valid filesystem root directory")

    logger.info(f"Found filesystem root at: {root}")
    return analyze_firmware_content(root, analysis_dir, binwalk_report)


def main(firmware_path, save_path):
    try:
        report = process_firmware(firmware_path, save_path)
        print(f"\nAnalysis complete. Results saved to: {save_path}")
        return report
    except Exception as e:
        print(f"Error during firmware analysis: {str(e)}")
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Firmware Analysis Tool')
    parser.add_argument('firmware_path', help='Path to firmware file or extracted firmware directory')
    parser.add_argument('save_path', help='Path to save analysis results')
    args = parser.parse_args()
    main(args.firmware_path, args.save_path)
    