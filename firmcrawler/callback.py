from langchain_core.callbacks import BaseCallbackHandler
from typing import Dict, Any
import json
class TokenUsageCallbackHandler(BaseCallbackHandler):
    def __init__(self, save_path):
        super().__init__()
        self.total_prompt_tokens = 0
        self.total_completion_tokens = 0
        self.total_cost = 0
        self.save_path = save_path
        
    def on_llm_end(self, response: Any, **kwargs: Any) -> None:
        try:
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
                with open(self.save_path, 'w') as f:
                    json.dump({
                        "total_prompt_tokens": self.total_prompt_tokens,
                        "total_completion_tokens": self.total_completion_tokens,
                        "total_cost": self.total_cost
                    }, f)
        except Exception as e:
            print(f"Error in token usage calculation: {str(e)}")
            print("Response structure:", dir(response))
            if hasattr(response, 'llm_output'):
                print("LLM output:", response.llm_output)