import asyncio
import base64
import configparser
import os
import re
import time
import json
import openai
from playwright.async_api import async_playwright
from langchain.prompts.chat import (
    ChatPromptTemplate,
    HumanMessagePromptTemplate,
    MessagesPlaceholder,
    SystemMessagePromptTemplate,
)
from langchain_core.messages import AIMessage, HumanMessage,ToolMessage,SystemMessage
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import PromptTemplate
from langchain_core.runnables import RunnableLambda, RunnablePassthrough
from langchain_core.prompts.image import ImagePromptTemplate
from langchain_core.runnables import chain as chain_decorator
from langchain_openai import ChatOpenAI
from langgraph.graph import END, START, StateGraph
from web_intrect import AgentState, click, scroll, wait, go_back, get_navigation_links, get_download_links, retry
from functools import partial
from callback import TokenUsageCallbackHandler
import asyncio
import logging

def get_api_key():
    config = configparser.ConfigParser()
    config.read('./firmcrawler/config.ini')
    try:
        return config['Settings']['Model'], config['Settings']['ModelApiKey'], config['Settings']['OrgId'], config['Settings']['ProjectId'], config['Settings']['BaseURL']
    except KeyError:
        raise KeyError("Cannot find 'ModelApiKey' in 'Settings' section of config.ini")

model, api_key, org_id, project_id, base_url = get_api_key()

script_dir = os.path.dirname(os.path.abspath(__file__))
mark_page_path = os.path.join(script_dir, 'mark_page.js')
with open(mark_page_path, encoding='utf-8') as f:
    mark_page_script = f.read()

def setup_logger(save_path: str):
    os.makedirs(save_path, exist_ok=True)
    
    logger = logging.getLogger('Crawler')
    
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    formatter = logging.Formatter('%(name)s - %(levelname)s - %(message)s')
    
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    log_file = os.path.join(save_path, 'crawler.log')
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    logger.setLevel(logging.INFO)
    
    return logger

@chain_decorator
async def mark_page(page):
    logger = logging.getLogger('Crawler')
    logger.info(f"Marking page: {page.url}")
    await page.evaluate(mark_page_script)
    bboxes = None
    
    for attempt in range(10):
        try:
            logger.debug(f"Attempt {attempt + 1}/10 to mark page")
            bboxes = await page.evaluate("markPage()")
            break
        except Exception as e:
            logger.warning(f"Attempt {attempt + 1} failed: {e}")
            await asyncio.sleep(3)
            
    if bboxes is None:
        logger.error("Failed to mark page after 10 attempts")
        raise Exception("Failed to mark page after 10 attempts")
        
    try:
        logger.debug("Taking page screenshot")
        screenshot = await page.screenshot(timeout=60000)
    except Exception as e:
        logger.error(f"Failed to take screenshot: {e}")
        screenshot = None
        
    try:
        logger.debug("Unmarking page")
        await page.evaluate("unmarkPage()")
    except Exception as e:
        logger.warning(f"Failed to unmark page: {e}")
    
    try:
        b64_img = base64.b64encode(screenshot).decode("utf-8") if screenshot else ""
        logger.debug(f"Found {len(bboxes) if bboxes else 0} interactive elements")
    except Exception as e:
        logger.error(f"Failed to encode screenshot: {e}")
        b64_img = ""
        
    return {
        "img": b64_img,
        "bboxes": bboxes or [],
    }


async def annotate(state):
    marked_page = await mark_page.with_retry().ainvoke(state["page"])
    return {**state, **marked_page}

def format_descriptions(state):
    if not state.get("bboxes"):
        return {**state, "bbox_descriptions": "\nNo interactive elements found on page"}
    labels = []
    for i, bbox in enumerate(state["bboxes"]):
        text = bbox.get("ariaLabel") or bbox.get("text", "").strip()
        el_type = bbox.get("type", "unknown")
        clickable = bbox.get("clickable", False)

        element_info = f'[{i}] (<{el_type}/>{" clickable" if clickable else ""}): "{text}"'
        labels.append(element_info)
    bbox_descriptions = "\nInteractive Elements on Page:\n" + "\n".join(labels)
    if "page" in state:
        bbox_descriptions = f"Current URL: {state['page'].url}\n" + bbox_descriptions
    
    return {**state, "bbox_descriptions": bbox_descriptions}

def parse(text: str) -> dict:
    logger = logging.getLogger('Crawler')
    logger.debug(f"Parsing LLM response:\n{text}")
    print("parse:", text)
    
    json_pattern = re.compile(r"```json\s*([\s\S]*?)```", re.IGNORECASE)
    match = json_pattern.search(text)
    
    if match:
        json_str = match.group(1).strip()
        logger.debug("Found JSON content in code block")
    else:
        logger.warning("No JSON code block found, attempting to find JSON-like content")
        json_braces_pattern = re.compile(r"({.*})", re.DOTALL)
        match = json_braces_pattern.search(text)
        if match:
            json_str = match.group(1).strip()
        else:
            logger.error("No JSON content found in text")
            return {
                "text": text,
                "action": "RETRY",
                "args": "No JSON content found in the text"
            }
    
    try:
        response = json.loads(json_str)
        logger.debug(f"Successfully parsed JSON: {response}")
        
        required_fields = {"thought", "action", "status", "next_step"}
        if not all(field in response for field in required_fields):
            logger.error("Missing required fields in JSON response")
            return {
                "text": text,
                "action": "RETRY",
                "args": "Missing required fields in JSON"
            }
            
        action = response["action"].strip().upper()
        if " " in action:
            action_part, action_input = response["action"].strip().split(" ", 1)
            action = action_part.upper()
        else:
            action_input = None
            
        valid_actions = {
            "CLICK", "SCROLL", "WAIT", "GOBACK", 
            "GET_NAVIGATION_LINKS", "GET_DOWNLOAD_LINKS", "ANSWER"
        }
        
        if action not in valid_actions:
            logger.error(f"Invalid action: {action}")
            return {
                "text": text,
                "action": "RETRY",
                "args": "Invalid action"
            }
            
        result = {
            "text": text,
            "action": action,
            "args": None
        }
            
        if action == "ANSWER":
            result["args"] = [action_input.strip() if action_input else ""]
            return result
            
        if action == "GOBACK":
            return result
            
        if action == "WAIT":
            if not action_input:
                return result
            try:
                wait_time = int(action_input.strip())
                result["args"] = [str(wait_time)]
                return result
            except ValueError:
                return {
                    "text": text,
                    "action": "RETRY",
                    "args": "Invalid wait time format"
                }
            
        if action == "SCROLL":
            if not action_input:
                return {
                    "text": text,
                    "action": "RETRY",
                    "args": "No scroll direction provided"
                }
            try:
                parts = action_input.split(";")
                if len(parts) != 2 or parts[0].strip().upper() != "WINDOW":
                    return {
                        "text": text,
                        "action": "RETRY",
                        "args": "Invalid scroll format. Expected: SCROLL WINDOW; up/down"
                    }
                direction = parts[1].strip().lower()
                if direction not in ["up", "down"]:
                    return {
                        "text": text,
                        "action": "RETRY",
                        "args": "Invalid scroll direction. Use 'up' or 'down'"
                    }
                result["args"] = [parts[0].strip(), direction]
                return result
            except Exception as e:
                return {
                    "text": text,
                    "action": "RETRY",
                    "args": f"Error parsing scroll parameters: {e}"
                }

        if action == "CLICK":
            if not action_input:
                return {
                    "text": text,
                    "action": "RETRY",
                    "args": "No element number provided for click"
                }
            try:
                element_number = int(action_input.strip())
                result["args"] = [str(element_number)]
                return result
            except ValueError:
                return {
                    "text": text,
                    "action": "RETRY",
                    "args": "Invalid element number for click action"
                }
            
        if not action_input:
            return {
                "text": text,
                "action": "RETRY",
                "args": "No action input provided"
            }
            
        try:
            action_args = [arg.strip().strip("[]") for arg in action_input.split(";")]
            result["args"] = action_args
            return result
        except Exception as e:
            return {
                "text": text,
                "action": "RETRY",
                "args": f"Error: Invalid action input: {e}"
            }
                
    except json.JSONDecodeError as e:
        logger.error(f"JSON parsing error: {e}")
        return {
            "text": text,
            "action": "RETRY",
            "args": "Invalid JSON format"
        }


def build_prompt(system_prompt):
    prompt = ChatPromptTemplate(
    messages=[
        SystemMessagePromptTemplate(
        prompt=[
            PromptTemplate.from_template(system_prompt),
        ],
        ),
        MessagesPlaceholder(
        optional=True,
        variable_name="scratchpad",
        ),
        HumanMessagePromptTemplate(
        prompt=[
            ImagePromptTemplate(
            template={"url":"data:image/png;base64,{img}"},
            input_variables=[
                "img",
            ],
            ),
            PromptTemplate.from_template("{bbox_descriptions}"),
            PromptTemplate.from_template("{input}"),
        ],
        ),
    ],
    input_variables=[
        "bbox_descriptions",
        "img",
        "input",
    ],
    partial_variables={"scratchpad":[]},
    )
    return prompt


def create_agent(system_prompt, save_path):
    prompt = build_prompt(system_prompt)
    from openai import AsyncOpenAI
    client = AsyncOpenAI(
        api_key=api_key, 
        timeout=60.0,  
        max_retries=3,  
        default_headers={"OpenAI-Beta": "assistants=v1"},
        organization=org_id,
    )

    global token_callback
    token_callback = TokenUsageCallbackHandler(
        os.path.join(save_path, "token_usage.json")
    )

    llm = ChatOpenAI(
        model="gpt-4o-2024-11-20",  
        temperature=0, 
        client=client,
        api_key=api_key,
        callbacks=[token_callback]
    )

    agent = annotate | RunnablePassthrough.assign(
        response = format_descriptions | prompt | llm | StrOutputParser() | parse
    )
    
    return agent

def update_scratchpad(state: dict, retain_human_messages: int = 0, max_messages: int = 6):
    txt = f"{state['observation']}"
    message = state.get("scratchpad", [])
    
    human_message_content = (
        f"Current Page URL: {state['page'].url}\n"
        f"![Screenshot](data:image/png;base64,{state['img']})"
    )
    human_message = HumanMessage(content=human_message_content)
    message.append(human_message)

    ai_message_content = state["response"]["text"]
    message.append(AIMessage(content=ai_message_content))

    observation_content = (
        f"Observation Result:\n"
        f"Status: {'Success' if 'Error:' not in txt else 'Failed'}\n"
        f"Details: {txt}"
    )
    observation_message = SystemMessage(content=observation_content)
    message.append(observation_message)

    if retain_human_messages > 0:
        human_messages = [msg for msg in message if isinstance(msg, HumanMessage)]
        other_messages = [msg for msg in message if not isinstance(msg, HumanMessage)]
        message = human_messages[-retain_human_messages:] + other_messages
    else:
        message = [msg for msg in message if not isinstance(msg, HumanMessage)]

    message = message[-max_messages:]

    human_msg_indices = [
        idx for idx, msg in enumerate(message)
        if isinstance(msg, HumanMessage) and "![Screenshot]" in msg.content
    ]

    for idx in human_msg_indices[:-1]:
        url_match = re.search(r"URL: (.*?)(?:\n|$)", message[idx].content)
        message[idx].content = f"URL: {url_match.group(1) if url_match else 'Unknown'}"

    from rich.console import Console
    from rich.table import Table

    console = Console()
    table = Table(
        title="Interaction History",
        caption="Product Link Collection Progress",
        show_lines=True
    )

    table.add_column("Step", style="cyan", no_wrap=True)
    table.add_column("Type", style="yellow", no_wrap=True)
    table.add_column("Content", style="magenta")
    table.add_column("Status", style="green")

    for i, msg in enumerate(message, 1):
        status = "✅" if "Error:" not in msg.content else "❌"
        if isinstance(msg, HumanMessage):
            msg_type = "🧑 Human"
            display_content = (
                "Omitted..."
                if "![Screenshot]" in msg.content
                else msg.content
            )
        elif isinstance(msg, AIMessage):
            msg_type = "🤖 AI"
            display_content = msg.content
        elif isinstance(msg, SystemMessage):
            msg_type = " System"
            display_content = msg.content
        else:
            msg_type = "❓ Unknown"
            display_content = msg.content

        table.add_row(
            f"Step {i}",
            msg_type,
            display_content,
            status
        )

    console.print(table)
    console.print(f"\nCurrent URL: {state['page'].url}", style="bold blue")

    return {**state, "scratchpad": message}

def build_graph(system_prompt, retain_human_messages=0, max_messages=10, save_path= None):
    agent = create_agent(system_prompt, save_path)
    graph_builder = StateGraph(AgentState)
    graph_builder.add_node("agent", agent)
    graph_builder.add_edge(START, "agent")

    update_scratchpad_with_params = partial(
        update_scratchpad,
        retain_human_messages=retain_human_messages,
        max_messages=max_messages
    )
    
    graph_builder.add_node("update_scratchpad", update_scratchpad_with_params)
    graph_builder.add_edge("update_scratchpad", "agent")

    tools = {
        "WAIT": wait,
        "RETRY": retry,
        "CLICK": click,
        "SCROLL": scroll,
        "GOBACK": go_back,
        "GET_DOWNLOAD_LINKS": get_download_links,
        "GET_NAVIGATION_LINKS": get_navigation_links,

    }

    for node_name, tool in tools.items():
        graph_builder.add_node(
            node_name,
            RunnableLambda(tool) | (lambda observation: {"observation": observation}),
        )
        graph_builder.add_edge(node_name, "update_scratchpad")

    def select_tool(state: AgentState):
        logger = logging.getLogger('Crawler')
        action = state["response"]["action"]
        action_input = state["response"]["args"]

        if action == "ANSWER":
            print("Over")
            return END         
        if action == "RETRY":
            return "RETRY"      
        if action == "CONTINUE":
            return "agent"
            
        return action

    graph_builder.add_conditional_edges("agent", select_tool)
    return graph_builder.compile()


class OpenAIRateLimiter:
    def __init__(self):
        self.requests_per_minute = 100
        self.interval = 60.0 / self.requests_per_minute
        self.semaphore = asyncio.Semaphore(1)
        self.last_request_time = 0
        self.lock = asyncio.Lock()
        print("初始化 Rate Limiter: 每分钟最多100个请求，请求间隔0.6秒")

    async def acquire(self):
        async with self.lock:
            current_time = time.time()
            if self.last_request_time > 0:
                elapsed = current_time - self.last_request_time
                if elapsed < self.interval:
                    wait_time = self.interval - elapsed
                    print(f"等待 {wait_time:.2f} 秒后发下一个请求...")
                    await asyncio.sleep(wait_time)
            self.last_request_time = time.time()
        await self.semaphore.acquire()

    async def release(self):
        self.semaphore.release()

    async def __aenter__(self):
        await self.acquire()
        return self
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.release()


async def call_agent(state, system_prompt, max_steps: int = 40, retain_human_messages: int = 0, max_messages: int = 10):
    logger = logging.getLogger('Crawler')
    logger.info("Initializing agent call")
    save_path = state.get("collected",None)
    rate_limiter = OpenAIRateLimiter()
    graph = build_graph(system_prompt, retain_human_messages=retain_human_messages, max_messages=max_messages,save_path=save_path)
    event_stream = graph.astream(
        state,
        {
            "recursion_limit": max_steps,
        },
    )
    final_answer = None
    steps = []
    
    async for event in event_stream:
        async with rate_limiter:
            try:
                if "agent" not in event:
                    continue
                    
                pred = event["agent"].get("response") or {}
                action = pred.get("action")
                action_input = pred.get("args")
                
                logger.info(f"Processing action: {action} with input: {action_input}")
                steps.append(f"{len(steps) + 1}.{action}: {action_input}")
                
                if "img" in event["agent"]:
                    img_data = base64.b64decode(event["agent"]["img"])
                    img_path = event["agent"]["collected"] + f"/screenshot_{len(steps)}.png"
                    try:
                        with open(img_path, "wb") as img_file:
                            img_file.write(img_data)
                        logger.debug(f"Screenshot saved to {img_path}")
                    except Exception as e:
                        logger.error(f"Error saving screenshot: {e}")
                        
                if "ANSWER" in action:
                    logger.info("Final answer received")
                    final_answer = action_input[0]
                    break
                    
            except openai.APIConnectionError as e:
                logger.error(f"API connection error: {e}")
                await asyncio.sleep(5)
                continue
            except Exception as e:
                logger.error(f"Error processing event: {e}")
                continue
                
    return final_answer


async def browse(url, system_prompt, user_input, save_path=None, max_steps=20, retain_human_messages=0, max_messages=10, headless=False):
    if save_path is None:
        save_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output")
    os.makedirs(save_path, exist_ok=True)
    
    logger = setup_logger(save_path)
    logger.info(f"Starting browser session for URL: {url}")
    
    downloads_path = os.path.join(save_path, "downloads")
    os.makedirs(downloads_path, exist_ok=True)
    
    logger.debug(f"Save path: {save_path}")
    logger.debug(f"Downloads path: {downloads_path}")
    
    for filename in os.listdir(downloads_path):
        file_path = os.path.join(downloads_path, filename)
        if os.path.isfile(file_path):
            os.remove(file_path)
            
    client = openai.OpenAI(api_key=api_key)
    result = None

    async with async_playwright() as p:
        logger.info("Launching browser")
        browser = await p.chromium.launch(
            headless=headless,
            args=[
                "--window-size=1920,1080",
                "--force-device-scale-factor=1.0",
                "--disable-dev-shm-usage",
                "--no-sandbox"
            ],
            downloads_path=downloads_path
        )
        context = await browser.new_context(
            viewport={'width': 1920, 'height': 1080},
            device_scale_factor=1.0
        )
        page = await context.new_page()
        
        await page.set_viewport_size({"width": 1920, "height": 1080})
        await page.evaluate("document.body.style.zoom = '100%'")
        
        max_retries = 3
        for attempt in range(max_retries):
            try:
                logger.info(f"Attempting to load page (attempt {attempt + 1}/{max_retries})")
                await page.goto(url, timeout=120000, wait_until="domcontentloaded")
                
                try:
                    await page.wait_for_load_state("domcontentloaded", timeout=30000)
                    logger.info("DOM content loaded")
                    
                    await page.wait_for_load_state("load", timeout=30000) 
                    logger.info("Page load complete")
                    
                    await page.wait_for_load_state("networkidle", timeout=60000)
                    logger.info("Network became idle")
                    
                except Exception as e:
                    logger.warning(f"Some load states did not complete: {e}")
                    
                logger.info("Page loaded successfully")
                break
                
            except Exception as e:
                logger.warning(f"Page load attempt {attempt + 1} failed: {e}")
                if attempt == max_retries - 1:
                    logger.error(f"Failed to load page after {max_retries} attempts")
                    raise
                logger.info(f"Retrying in 5 seconds...")
                await asyncio.sleep(5)
                
        state = {
            "page": page,
            "input": user_input,
            "scratchpad": [],
            "downloads": downloads_path,
            "client": client,
            "collected": save_path
        }
        
        logger.info("Starting agent execution")
        result = await call_agent(
            state, 
            system_prompt, 
            max_steps=max_steps,
            retain_human_messages=retain_human_messages,
            max_messages=max_messages
        )
        
        logger.info("Closing browser session")
        await context.close()
        await browser.close()
        
    return result

