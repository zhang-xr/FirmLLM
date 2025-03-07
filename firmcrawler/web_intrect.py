import os
import re
import time
import json
import openai
import asyncio
import platform
import unidecode
import validators
from playwright.async_api import Page
from typing_extensions import TypedDict
from typing import Any, Dict, List, Optional
from langchain_core.messages import BaseMessage
from urllib.parse import urlparse

class BBox(TypedDict):
    x: float
    y: float
    text: str
    type: str
    ariaLabel: str

class Response(TypedDict):
    text: str
    action: str
    args: Optional[List[str]]

class AgentState(TypedDict):
    page: Page
    input: str
    img: str
    bboxes: List[BBox]
    response: Response
    scratchpad: List[BaseMessage]
    observation: str
    downloads: str
    client: openai.OpenAI
    collected: str

def get_pdf_retrieval_ans_from_assistant(client, pdf_path, task):
    print("You download a PDF file that will be retrieved using the Assistant API.")
    file = client.files.create(
        file=open(pdf_path, "rb"),
        purpose='assistants'
    )
    print("Create assistant...")
    assistant = client.beta.assistants.create(
        instructions="You are a helpful assistant that can analyze the content of a PDF file and give an answer that matches the given task, or retrieve relevant content that matches the task.",
        model="gpt-4o-2024-11-20",
        tools=[{"type": "retrieval"}],
        file_ids=[file.id]
    )
    thread = client.beta.threads.create()
    message = client.beta.threads.messages.create(
        thread_id=thread.id,
        role="user",
        content=task,
        file_ids=[file.id]
    )
    print(f"PDF Assistant: {message}")    
    run = client.beta.threads.runs.create(
        thread_id=thread.id,
        assistant_id=assistant.id
    )
    while True:
        run_status = client.beta.threads.runs.retrieve(thread_id=thread.id, run_id=run.id)
        if run_status.status == 'completed':
            break
        time.sleep(2)
    messages = client.beta.threads.messages.list(thread_id=thread.id)
    messages_text = messages.data[0].content[0].text.value
    print(f"PDF Assistant: {messages_text}")
    file_deletion_status = client.beta.assistants.files.delete(
        assistant_id=assistant.id,
        file_id=file.id
    )
    print(f"PDF Assistant: {file_deletion_status}")

    assistant_deletion_status = client.beta.assistants.delete(assistant.id)
    print(f"PDF Assistant: {assistant_deletion_status}")


async def click(state: AgentState) -> str:
    page: Page = state["page"]
    click_args = state["response"].get("args")
    client = state["client"]
    downloads_path = state["downloads"]
    
    if not click_args or len(click_args) != 1:
        return "Error: Invalid click action. Required format: Click [Numerical_Label]"
    
    try:
        bbox_id = int(click_args[0])
    except (ValueError, TypeError):
        return f"Error: Invalid element ID '{click_args[0]}'. Must be a numerical label."
    
    try:
        bbox = state["bboxes"][bbox_id]
    except (IndexError, KeyError, TypeError):
        return f"Error: Element with numerical label {bbox_id} not found on current page."
    
    x, y = bbox.get("x"), bbox.get("y")
    element_description = (
        f"type '{bbox.get('type', 'unknown')}' "
        f"text '{bbox.get('text', '')}'"
    )
    
    try:
        before_files = set(os.listdir(downloads_path))
        
        await page.mouse.click(x, y)
        
        await asyncio.sleep(5)
        
        after_files = set(os.listdir(downloads_path))
        new_files = after_files - before_files
        
        if new_files:
            latest_file = max([os.path.join(downloads_path, f) for f in new_files], 
                            key=os.path.getctime)
            
            if latest_file.lower().endswith('.pdf'):
                print(f"PDF file downloaded: {latest_file}")
                
                try:
                    pdf_analysis = get_pdf_retrieval_ans_from_assistant(
                        client=client,
                        pdf_path=latest_file,
                        task="Please analyze this firmware-related document and extract all relevant information about versions, features, and requirements."
                    )
                    
                    return (f"Successfully clicked element [{bbox_id}] ({element_description})\n"
                           f"PDF Analysis Results:\n{pdf_analysis}")
                
                except Exception as e:
                    return (f"Successfully clicked element [{bbox_id}] and downloaded PDF, "
                           f"but failed to analyze it: {str(e)}")
            
            return (f"Successfully clicked element [{bbox_id}] ({element_description})\n"
                   f"Downloaded file: {', '.join(new_files)}")
        
        return f"Successfully clicked element [{bbox_id}] ({element_description})"
    
    except Exception as e:
        return f"Error: Failed to click element [{bbox_id}]. Please try a different element or action."


async def retry(state: AgentState):
    return f"Error: Invalid response format"

async def scroll(state: AgentState):
    page = state["page"]
    scroll_args = state["response"]["args"]
    
    if scroll_args is None or len(scroll_args) != 2:
        return "Error: Invalid scroll action. Required format: Scroll [Numerical_Label or WINDOW]; [up or down]"
    
    target, direction = scroll_args
    if direction.lower() not in ["up", "down"]:
        return "Error: Scroll direction must be either 'up' or 'down'"

    try:
        if target.upper() == "WINDOW":
            if direction.lower() == "up":
                await page.evaluate("window.scrollTo(0, 0)")
            else:
                viewport_height = await page.evaluate("""() => {
                    return document.documentElement.clientHeight;
                }""")
                scroll_amount = viewport_height - 100
                await page.evaluate(f"window.scrollBy(0, {scroll_amount})")
            
            scroll_status = await page.evaluate("""() => {
                const scrollTop = window.pageYOffset || document.documentElement.scrollTop;
                const scrollHeight = document.documentElement.scrollHeight;
                const clientHeight = document.documentElement.clientHeight;
                const progress = Math.round((scrollTop / (scrollHeight - clientHeight)) * 100);
                
                const isAtBottom = Math.abs(scrollTop + clientHeight - scrollHeight) < 1;
                const isAtTop = scrollTop < 1;
                
                return {progress, isAtBottom, isAtTop};
            }""")
            
            boundary_msg = ""
            if direction.lower() == "down" and scroll_status["isAtBottom"]:
                boundary_msg = " (Reached bottom - Note: there might be 'Load More' or 'Show More' elements to expand the page)"
            elif direction.lower() == "up" and scroll_status["isAtTop"]:
                boundary_msg = " (Reached top)"
            
            return (f"Successfully scrolled {direction} on the main window "
                   f"(Scroll progress: {scroll_status['progress']}%){boundary_msg}")
        else:
            if direction.lower() == "up":
                target_id = int(target)
                try:
                    bbox = state["bboxes"][target_id]
                except (IndexError, KeyError):
                    return f"Error: Element with numerical label {target_id} not found on current page."
                    
                x, y = bbox["x"], bbox["y"]
                await page.evaluate(f"""() => {{
                    const element = document.elementFromPoint({x}, {y});
                    if (element) element.scrollTop = 0;
                }}""")
            else:
                scroll_amount = 200
                target_id = int(target)
                try:
                    bbox = state["bboxes"][target_id]
                except (IndexError, KeyError):
                    return f"Error: Element with numerical label {target_id} not found on current page."
                    
                x, y = bbox["x"], bbox["y"]
                await page.mouse.move(x, y)
                await page.mouse.wheel(0, scroll_amount)
            
            scroll_status = await page.evaluate(f"""() => {{
                const element = document.elementFromPoint({x}, {y});
                if (!element) return {{progress: 0, isAtBottom: false, isAtTop: false}};
                
                const scrollTop = element.scrollTop;
                const scrollHeight = element.scrollHeight;
                const clientHeight = element.clientHeight;
                const progress = Math.round((scrollTop / (scrollHeight - clientHeight)) * 100);
                
                const isAtBottom = Math.abs(scrollTop + clientHeight - scrollHeight) < 1;
                const isAtTop = scrollTop < 1;
                
                return {{progress, isAtBottom, isAtTop}};
            }}""")
            
            boundary_msg = ""
            if direction.lower() == "down" and scroll_status["isAtBottom"]:
                boundary_msg = " (Reached bottom - Note: there might be 'Load More' or 'Show More' elements to expand the content)"
            elif direction.lower() == "up" and scroll_status["isAtTop"]:
                boundary_msg = " (Reached top)"
            
            return (f"Successfully scrolled {direction} in element [{target_id}] "
                   f"(Scroll progress: {scroll_status['progress']}%){boundary_msg}")
    except Exception as e:
        return f"Error: Failed to perform scroll action. Please try a different element or direction."

async def wait(state: AgentState):
    wait_args = state["response"]["args"]
    
    sleep_time = 5
    
    if wait_args and len(wait_args) == 1:
        try:
            sleep_time = int(wait_args[0])
            sleep_time = min(sleep_time, 30)
        except ValueError:
            return "Error: Wait time must be a number in seconds"
            
    await asyncio.sleep(sleep_time)
    return f"Waited for {sleep_time} seconds to allow page loading."


async def go_back(state: AgentState):
    page = state["page"]
    try:
        await page.go_back()
        return "Successfully navigated back to previous page."
    except Exception as e:
        return "Error: Failed to go back. Please try a different action."


async def copy_link_address(state: AgentState):
    page = state["page"]
    copy_args = state["response"]["args"]
    if copy_args is None or len(copy_args) != 1:
        return "Failed to copy link address due to incorrect arguments."
    bbox_id = copy_args[0]
    bbox_id = int(bbox_id)
    try:
        bbox = state["bboxes"][bbox_id]
    except Exception:
        return f"Error: no bbox for : {bbox_id}"
    x, y = bbox["x"], bbox["y"]
    element_handle = await page.evaluate_handle(
        f"""() => document.elementFromPoint({x}, {y})"""
    )
    if element_handle:
        href = await element_handle.get_property('href')
        if href:
            href_value = await href.json_value()
            return f"Copied link address: {href_value} on the page {page.url}."
        else:
            return f"Error: Element ['{bbox_id}'] does not have a link address on the {page.url}."
    else:
        return f"Error: No element found at the given coordinates on the {page.url}."


async def extract_url_from_copy_response(response: str) -> Optional[str]:
    if "Copied link address: " in response:
        url = response.split("Copied link address: ")[1].split(" on the page")[0]
        return url
    return None

def is_valid_url(url: str) -> bool:
    if not url:
        return False
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False

async def process_link(page, x, y, text, bbox_id, bboxes, original_href=None):
    try:
        browser = page.context.browser
        context = await browser.new_context()
        temp_page = await context.new_page()
        
        try:
            await temp_page.goto(page.url, timeout=30000)
            await temp_page.wait_for_load_state("networkidle")
            
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    await temp_page.mouse.move(x, y)
                    await temp_page.mouse.click(x, y)
                    await asyncio.sleep(2)
                    
                    await temp_page.wait_for_load_state("networkidle", timeout=15000)
                    break
                except Exception as e:
                    print(f"Click attempt {attempt + 1} failed: {e}")
                    if attempt == max_retries - 1:
                        raise
                    await asyncio.sleep(1)
            
            new_url = temp_page.url
            if new_url and new_url != page.url and new_url != "about:blank":
                if is_valid_url(new_url):
                    return new_url
            
            temp_state = {
                "page": page,
                "response": {"args": [str(bbox_id)]},
                "bboxes": bboxes
            }
            copy_response = await copy_link_address(temp_state)
            copied_url = await extract_url_from_copy_response(copy_response)
            if copied_url and is_valid_url(copied_url):
                return copied_url
                
            return original_href
            
        finally:
            await context.close()
            
    except Exception as e:
        print(f"Error in process_link: {e}")
        try:
            temp_state = {
                "page": page,
                "response": {"args": [str(bbox_id)]},
                "bboxes": bboxes
            }
            copy_response = await copy_link_address(temp_state)
            copied_url = await extract_url_from_copy_response(copy_response)
            if copied_url and is_valid_url(copied_url):
                return copied_url
        except Exception:
            pass
            
    return original_href

def get_existing_urls(filepath: str) -> set:
    urls = set()
    if os.path.exists(filepath):
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        data = json.loads(line)
                        if "url" in data:
                            urls.add(data["url"])
                    except json.JSONDecodeError:
                        continue
        except Exception:
            pass
    return urls

async def get_navigation_links(state: AgentState) -> str:
    page = state["page"]
    bboxes = state["bboxes"]
    args = state["response"]["args"]
    
    if not args:
        return "Error: Need element IDs"
    
    try:
        bbox_ids = [int(id.strip()) for id in args[0].split(',')]
        print(f"\nProcessing bbox_ids: {bbox_ids}")
    except Exception as e:
        return f"Error parsing element IDs: {e}"

    visible_links = []
    for bbox_id in bbox_ids:
        try:
            bbox = bboxes[bbox_id]
            if bbox["type"] != "a":
                print(f"Element {bbox_id} is not a link")
                continue
                
            x, y = bbox["x"], bbox["y"]
            text = bbox.get("text", "").strip()
            
            print(f"\nProcessing element {bbox_id}:")
            print(f"- Position: x={x}, y={y}")
            print(f"- Text: {text}")
            
            element = await page.evaluate_handle(
                f"""() => document.elementFromPoint({x}, {y})"""
            )
            
            if not element:
                print(f"- No element found at position")
                continue

            href = None
            href_prop = await element.get_property('href')
            if href_prop:
                href = await href_prop.json_value()
            print(f"- Original href: {href}")

            needs_special_handling = (
                not href or
                href == '#' or 
                href.startswith('javascript:') or 
                await element.get_attribute('onclick') or
                not is_valid_url(href)
            )
            
            if needs_special_handling:
                print("- Needs special handling")
                actual_url = await process_link(page, x, y, text, bbox_id, bboxes, href)
            else:
                actual_url = href

            print(f"- Final URL: {actual_url}")
            
            if actual_url and is_valid_url(actual_url):
                link_info = {
                    "text": text,
                    "url": actual_url,
                    "source_page": page.url,
                    "original_href": href
                }
                visible_links.append(link_info)
                print("- Successfully added to visible links")

        except Exception as e:
            print(f"Error processing element {bbox_id}: {e}")
            continue
    
    if visible_links:
        save_path = os.path.join(state["collected"], f"navigation_links.jsonl")
        try:
            existing_urls = get_existing_urls(save_path)
            
            new_links = [link for link in visible_links if link["url"] not in existing_urls]
            
            if new_links:
                with open(save_path, "a", encoding="utf-8") as f:
                    for link in new_links:
                        json.dump(link, f, ensure_ascii=False)
                        f.write("\n")
                visible_links = new_links
        except Exception as e:
            print(f"Error saving links: {e}")
    
    def format_links(links):
        if len(links) <= 4:
            return "\n".join(f"{link['text']} -> {link['url']}" for link in links)
        
        first_two = [f"{link['text']} -> {link['url']}" for link in links[:2]]
        last_two = [f"{link['text']} -> {link['url']}" for link in links[-2:]]
        return "\n".join(first_two + ["..."] + last_two)
    
    return f"Collected {len(visible_links)} links:\n{format_links(visible_links)}"


async def get_download_links(state: AgentState) -> str:
    page = state["page"]
    bboxes = state["bboxes"]
    args = state["response"]["args"]
    
    if not args:
        return "Error: Need element IDs"
    
    try:
        bbox_ids = [int(id.strip()) for id in args[0].split(',')]
        print(f"\nProcessing bbox_ids: {bbox_ids}")
    except Exception as e:
        return f"Error parsing element IDs: {e}"
    
    download_extensions = [
        '.bin', '.fw', '.hex', '.rom', '.img', '.elf', '.fwu',
        '.firmware', '.update', '.upgrade', '.zip', '.rar', '.7z',
        '.tar', '.gz', '.bz2', '.xz', '.exe', '.pdf'
    ]
    
    visible_links = []
    for bbox_id in bbox_ids:
        try:
            bbox = bboxes[bbox_id]
            if bbox["type"] == "a":
                x, y = bbox["x"], bbox["y"]
                text = bbox.get("text", "").strip()
                
                print(f"\nProcessing element {bbox_id}:")
                print(f"- Position: x={x}, y={y}")
                print(f"- Text: {text}")
                
                element = await page.evaluate_handle(
                    f"""() => document.elementFromPoint({x}, {y})"""
                )
                if not element:
                    print(f"- No element found at position")
                    continue

                href = await element.get_property('href')
                href_value = await href.json_value() if href else None
                print(f"- Original href: {href_value}")
                
                if not href_value:
                    print("- No href value found")
                    continue
                
                actual_url = await process_link(page, x, y, text, bbox_id, bboxes, href_value)
                print(f"- Final URL: {actual_url}")
                
                if actual_url and is_valid_url(actual_url):
                    if any(actual_url.lower().endswith(ext) for ext in download_extensions):
                        link_info = {
                            "text": text,
                            "url": actual_url,
                            "source_page": page.url,
                            "original_href": href_value
                        }
                        visible_links.append(link_info)
                        print("- Successfully added to visible links")

        except Exception as e:
            print(f"Error processing element {bbox_id}: {e}")
            continue
    
    if visible_links:
        save_path = os.path.join(state["collected"], f"download_links.jsonl")
        try:
            existing_urls = get_existing_urls(save_path)
            
            new_links = [link for link in visible_links if link["url"] not in existing_urls]
            
            if new_links:
                with open(save_path, "a", encoding="utf-8") as f:
                    for link in new_links:
                        json.dump(link, f, ensure_ascii=False)
                        f.write("\n")
                visible_links = new_links
        except Exception as e:
            print(f"Error saving links: {e}")
    
    def format_links(links):
        if len(links) <= 4:
            return "\n".join(f"{link['text']} -> {link['url']}" for link in links)
        
        first_two = [f"{link['text']} -> {link['url']}" for link in links[:2]]
        last_two = [f"{link['text']} -> {link['url']}" for link in links[-2:]]
        return "\n".join(first_two + ["..."] + last_two)
    
    return f"Collected {len(visible_links)} links:\n{format_links(visible_links)}"

