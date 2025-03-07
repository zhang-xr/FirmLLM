import json
import logging
from typing import Dict, Any, List
from langchain_core.callbacks import BaseCallbackHandler

class TokenUsageCallbackHandler(BaseCallbackHandler):
    def __init__(self, save_path):
        super().__init__()
        self.total_prompt_tokens = 0
        self.total_completion_tokens = 0
        self.total_cost = 0
        self.save_path = save_path
        
    def on_llm_start(self, serialized: Dict[str, Any], prompts: List[str], **kwargs: Any) -> None:
        """Called when LLM invocation starts"""
        logging.info("[Prompt]")
        for i, prompt in enumerate(prompts, 1):
            logging.info(f"\n{'-' * 50}\n{prompt}\n{'-' * 50}")
        
    def on_llm_end(self, response: Any, **kwargs: Any) -> None:
        """Called when LLM invocation ends"""
        try:
            # Log the raw LLM response
            if hasattr(response, 'generations'):
                for gen in response.generations:
                    if gen:
                        logging.info(f"\n{'-' * 50}\n{gen[0].text}\n{'-' * 50}")

            if hasattr(response, 'llm_output') and response.llm_output:
                token_usage = response.llm_output.get('token_usage', {})
                
                prompt_tokens = token_usage.get('prompt_tokens', 0)
                completion_tokens = token_usage.get('completion_tokens', 0)
                
                input_cost = prompt_tokens * (2.50 / 1_000_000)
                output_cost = completion_tokens * (10.00 / 1_000_000)
                
                self.total_prompt_tokens += prompt_tokens
                self.total_completion_tokens += completion_tokens
                self.total_cost += input_cost + output_cost
                
                print(f"\n📊 [Token Usage for this call]")
                print(f"Input tokens: {prompt_tokens:,} (${input_cost:.4f})")
                print(f"Output tokens: {completion_tokens:,} (${output_cost:.4f})")
                print(f"Total tokens: {prompt_tokens + completion_tokens:,}")
                print(f"Running total cost: ${self.total_cost:.4f}")

                # Save token usage
                usage_data = {
                    "input_cost": input_cost,
                    "output_cost": output_cost,
                    "total_cost": self.total_cost
                }
                
                with open(self.save_path, 'a', encoding='utf-8') as f:
                    json.dump(usage_data, f, ensure_ascii=False)
                    f.write("\n")
                    
        except Exception as e:
            logging.error(f"Error in token usage calculation: {str(e)}")
            if hasattr(response, 'llm_output'):
                logging.debug("LLM output: %s", response.llm_output)