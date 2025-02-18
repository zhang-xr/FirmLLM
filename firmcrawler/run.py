import os
import yaml
import json
import time
import logging
import asyncio
from asyncio import Semaphore
from firmcrawler.crawler import browse

# Example of actual running effect:
# Assume visiting: https://example.com/products
# Output logs may look like:
# Start crawling: https://example.com/products
# Processing: https://example.com/products (depth: 0)
# Found category page: https://example.com/products
# Found 3 new links:
#  - /products/router1
#  - /products/router2
#  - /products/network-devices
# Processing: https://example.com/products/network-devices (depth: 1)
# Found category page: https://example.com/products/network-devices
# Found 2 new links:
#  - /products/network-devices/switch1
#  - /products/network-devices/switch2
# Processing: https://example.com/products/network-devices/switch2 (depth: 2)
# Found product page: https://example.com/products/network-devices/switch2
# Successfully extracted firmware info: Enterprise Switch v2
# {
#     "name": "Enterprise Switch v2",
#     "version": "2.1.3",
#     "release_date": "2024-01-15",
#     "download_url": "https://example.com/firmware/switch2-v2.1.3.bin",
#     "description": "Bug fixes and security updates",
#     "compatibility": ["Model A", "Model B"]
# }
# Processing: https://example.com/products/network-devices/switch1 (depth: 2)
# ...

prompt_dir = os.path.dirname(os.path.abspath(__file__))
def load_prompts(vendor: str):
    logger = logging.getLogger('Crawler')
    system_prompt_path = os.path.join(prompt_dir, "prompts", "prompts.yaml")
    user_prompt_path = os.path.join(prompt_dir, "prompts", f"{vendor}.yaml")
    logger.info(f"Loading prompts from: {system_prompt_path} and {user_prompt_path}")
    
    try:
        with open(system_prompt_path) as f:
            system_prompts = yaml.safe_load(f)
            logger.debug(f"Loaded system prompts")
        with open(user_prompt_path) as f:
            user_prompts = yaml.safe_load(f)
            logger.debug(f"Loaded vendor prompts")
        return system_prompts, user_prompts
    except FileNotFoundError as e:
        logger.error(f"Prompts file not found: {e.filename}")
        raise
    except yaml.YAMLError as e:
        logger.error(f"Error parsing prompts file: {e}")
        raise
SAVE_PATH = "firmcrawler/output/dlink"
MAX_DEPTH = 2
PRODUCT_TYPES = ["EXPLORER", "SCRAPER", "ALL"]
CRAWL_DELAY = 1
MAX_CONCURRENT = 3
AGENT_BASE_CONFIG = {
    "save_path": SAVE_PATH,
    "max_steps": 10,
    "retain_human_messages": 0,
    "max_messages": 10
}
system_prompts, user_prompts = load_prompts("dlink")
INSPECTOR_CONFIG = {
    **AGENT_BASE_CONFIG,
    "system_prompt": system_prompts['inspector']['system'],
    "user_input": user_prompts['inspector']['user'],
    "max_steps": 10,
    "retain_human_messages": 0,
    "max_messages": 6
}
EXPLORER_CONFIG = {
    **AGENT_BASE_CONFIG, 
    "system_prompt": system_prompts['explorer']['system'],
    "user_input": user_prompts['explorer']['user'],
    "max_steps": 60,
    "retain_human_messages": 0,
    "max_messages": 12
}
SCRAPER_CONFIG = {
    **AGENT_BASE_CONFIG,
    "system_prompt": system_prompts['scraper']['system'], 
    "user_input": user_prompts['scraper']['user'],
    "max_steps": 20,
    "retain_human_messages": 0,
    "max_messages": 10
}
class BaseAgent:
    def __init__(self, 
                 system_prompt: str = None,
                 user_input: str = None,
                 save_path: str = SAVE_PATH,
                 max_steps: int = 10,
                 retain_human_messages: int = 0,
                 max_messages: int = 10):
        self.system_prompt = system_prompt
        self.user_input = user_input
        self.base_save_path = save_path
        self.max_steps = max_steps
        self.retain_human_messages = retain_human_messages
        self.max_messages = max_messages

    def _get_safe_filename(self, url: str) -> str:
        url = url.split('://')[-1]
        safe_name = "".join(c if c.isalnum() else '_' for c in url)
        return safe_name[:100] if len(safe_name) > 100 else safe_name

    async def run(self, url: str):
        safe_name = self._get_safe_filename(url)
        self.save_path = os.path.join(
            self.base_save_path,
            f"{self.__class__.__name__}_result",
            safe_name
        )
        os.makedirs(self.save_path, exist_ok=True)
        
        return await browse(
            url=url,
            system_prompt=self.system_prompt,
            user_input=self.user_input,
            save_path=self.save_path,
            max_steps=self.max_steps,
            retain_human_messages=self.retain_human_messages,
            max_messages=self.max_messages,
            headless=True
        )

class Inspector(BaseAgent):
    def __init__(self, **kwargs):
        kwargs.setdefault('system_prompt', INSPECTOR_CONFIG['system_prompt'])
        kwargs.setdefault('user_input', INSPECTOR_CONFIG['user_input'])
        kwargs.setdefault('max_steps', INSPECTOR_CONFIG['max_steps'])
        kwargs.setdefault('retain_human_messages', INSPECTOR_CONFIG['retain_human_messages'])
        kwargs.setdefault('max_messages', INSPECTOR_CONFIG['max_messages'])
        BaseAgent.__init__(self, **kwargs)

    async def analyze(self, url: str) -> str:
        result = await self.run(url)
        print(f"Raw Inspector result: {result}")
        
        if not result:
            print("Inspector: No result returned, defaulting to UNKNOWN")
            return "UNKNOWN"
            
        try:
            if isinstance(result, list) and len(result) > 0:
                page_type = result[0].strip().upper()
            elif isinstance(result, str):
                page_type = result.strip().upper()
            else:
                print(f"Inspector: Unexpected result format: {type(result)}, defaulting to UNKNOWN")
                return "UNKNOWN"
            
            valid_types = {"EXPLORER", "SCRAPER", "ALL", "UNKNOWN"}
            if page_type not in valid_types:
                print(f"Inspector: Invalid page type '{page_type}', defaulting to UNKNOWN")
                return "UNKNOWN"
                
            print(f"Inspector: Successfully identified page type as {page_type}")
            return page_type
            
        except Exception as e:
            print(f"Inspector: Error parsing result: {e}")
            return "UNKNOWN"

class Explorer(BaseAgent):
    def __init__(self, **kwargs):
        kwargs.setdefault('system_prompt', EXPLORER_CONFIG['system_prompt'])
        kwargs.setdefault('user_input', EXPLORER_CONFIG['user_input'])
        kwargs.setdefault('max_steps', EXPLORER_CONFIG['max_steps'])
        kwargs.setdefault('retain_human_messages', EXPLORER_CONFIG['retain_human_messages'])
        kwargs.setdefault('max_messages', EXPLORER_CONFIG['max_messages'])
        BaseAgent.__init__(self, **kwargs)

    async def extract_links(self, url: str) -> list:
        result = await self.run(url)
        print(f"Explorer result: {result}")
        links = []
        links_file = os.path.join(self.save_path, "navigation_links.jsonl")
        if os.path.exists(links_file):
            with open(links_file, "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        link_data = json.loads(line.strip())
                        links.extend(link_data.get("links", []))
                    except json.JSONDecodeError:
                        print(f"Error parsing links file: {line}")
                        continue
        return links

class Scraper(BaseAgent):
    def __init__(self, **kwargs):
        kwargs.setdefault('system_prompt', SCRAPER_CONFIG['system_prompt'])
        kwargs.setdefault('user_input', SCRAPER_CONFIG['user_input'])
        kwargs.setdefault('max_steps', SCRAPER_CONFIG['max_steps'])
        kwargs.setdefault('retain_human_messages', SCRAPER_CONFIG['retain_human_messages'])
        kwargs.setdefault('max_messages', SCRAPER_CONFIG['max_messages'])
        BaseAgent.__init__(self, **kwargs)
        
    async def extract_firmware(self, url: str) -> dict:
        result = await self.run(url)
        print(f"Scraper result: {result}")
        return result
class WebCrawler:
    def __init__(
        self, 
        save_path: str = SAVE_PATH,
        type_list: list[str] = PRODUCT_TYPES,
        max_depth: int = MAX_DEPTH,
        inspector_kwargs: dict = INSPECTOR_CONFIG,
        explorer_kwargs: dict = EXPLORER_CONFIG,
        scraper_kwargs: dict = SCRAPER_CONFIG
    ):
        self.logger = logging.getLogger('Crawler')
        self.logger.info("Initializing WebCrawler")
        
        if not save_path:
            self.logger.error("save_path cannot be empty")
            raise ValueError("save_path cannot be empty")
            
        self.logger.info(f"Crawler configuration:"
                        f"\n - Save path: {save_path}"
                        f"\n - Max depth: {max_depth}"
                        f"\n - Product types: {type_list}"
                        f"\n - Max concurrent: {MAX_CONCURRENT}"
                        f"\n - Crawl delay: {CRAWL_DELAY}s")
            
        self.save_path = save_path
        self.type_list = type_list or PRODUCT_TYPES
        self.max_depth = max_depth
        
        try:
            os.makedirs(save_path, exist_ok=True)
            self.logger.debug(f"Created save directory: {save_path}")
        except Exception as e:
            self.logger.error(f"Failed to create save directory: {e}")
            raise
        
        self.visited_urls = set()
        self.url_stack = []
        self.collected_data = []
        self.semaphore = Semaphore(MAX_CONCURRENT)
        self.last_request_time = 0
        
        try:
            self.inspector = Inspector(**inspector_kwargs)
            self.explorer = Explorer(**explorer_kwargs)
            self.scraper = Scraper(**scraper_kwargs)
            self.logger.debug("Successfully initialized all agents")
        except Exception as e:
            self.logger.error(f"Failed to initialize agents: {e}")
            raise
        
    async def _delay_request(self):
        now = time.time()
        if now - self.last_request_time < CRAWL_DELAY:
            await asyncio.sleep(CRAWL_DELAY - (now - self.last_request_time))
        self.last_request_time = time.time()
        
    async def _process_explorer(self, url: str, depth: int):
        try:
            links = await self.explorer.extract_links(url)
            if not links:
                self.logger.warning(f"No links found in {url}")
                return
            
            new_links = [link for link in links if link not in self.visited_urls]
            self.logger.info(f"Found {len(new_links)} new links in category page")
            
            for link in new_links:
                self.url_stack.append((link, depth + 1))
        except Exception as e:
            self.logger.error(f"Error in explorer processing {url}: {str(e)}")

    async def _process_scraper(self, url: str):
        self.logger.info(f"Extracting firmware info from: {url}")
        firmware_info = await self.scraper.extract_firmware(url)
        if firmware_info:
            self.collected_data.append({
                "url": url,
                "info": firmware_info
            })
            self.logger.info(f"Successfully extracted firmware info from: {url}")

    async def crawl(self, start_url):
        self.logger.info(f"Starting crawl from: {start_url}")
        self.url_stack.append((start_url, 0))
        
        try:
            while self.url_stack:
                current_url, depth = self.url_stack.pop()
                
                self.logger.info(f"Processing URL: {current_url} (depth: {depth})")
                self.logger.debug(f"Queue status: {len(self.url_stack)} URLs remaining")
                
                if current_url in self.visited_urls:
                    self.logger.debug(f"Skipping already visited URL: {current_url}")
                    continue
                    
                if depth > self.max_depth:
                    self.logger.debug(f"Reached max depth ({self.max_depth}) for URL: {current_url}")
                    continue
                
                async with self.semaphore:
                    await self._delay_request()
                    self.visited_urls.add(current_url)
                    
                    try:
                        page_type = await self.inspector.analyze(current_url)
                        self.logger.info(f"Page type determined: {page_type}")
                        
                        if page_type in ["EXPLORER", "ALL"]:
                            await self._process_explorer(current_url, depth)
                            
                        if page_type in ["SCRAPER", "ALL"]:
                            await self._process_scraper(current_url)
                            
                    except Exception as e:
                        self.logger.error(f"Error processing URL {current_url}: {str(e)}")
                        continue
                        
        except Exception as e:
            self.logger.error(f"Crawl failed: {str(e)}")
            raise
        finally:
            self.logger.info(f"Crawl completed. Processed {len(self.visited_urls)} URLs, "
                           f"collected data from {len(self.collected_data)} products")

if __name__ == "__main__":
    crawler = WebCrawler(
        save_path=SAVE_PATH,
        type_list=PRODUCT_TYPES,
        max_depth=MAX_DEPTH,
        inspector_kwargs=INSPECTOR_CONFIG,
        explorer_kwargs=EXPLORER_CONFIG, 
        scraper_kwargs=SCRAPER_CONFIG
    )
    
    asyncio.run(crawler.crawl("https://support.dlink.com/AllPro.aspx"))
