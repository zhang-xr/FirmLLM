import logging
import configparser
from langchain_openai import ChatOpenAI
from typing import Optional, Tuple, List
from langchain_core.runnables import RunnableLambda

class LLMClient:
    _instance = None
    _llm = None
    _callbacks = None
    
    def __new__(cls, config_path: str = 'config.ini'):
        if cls._instance is None:
            cls._instance = super(LLMClient, cls).__new__(cls)
        return cls._instance

    def __init__(self, config_path: str = 'config.ini'):
        if not hasattr(self, 'initialized'):
            self.config_path = config_path
            self.model = None
            self.api_key = None 
            self.org_id = None
            self.project_id = None
            self.base_url = None
            self._callbacks = []
            self.initialized = True
    
    def add_callback(self, callback) -> None:
        if callback not in self._callbacks:
            self._callbacks.append(callback)
            if self._llm:
                self._llm.callbacks = self._callbacks

    def set_callbacks(self, callbacks: List) -> None:
        self._callbacks = callbacks
        if self._llm:
            self._llm.callbacks = self._callbacks

    def get_config(self) -> Tuple[str, str, str, str, str]:
        if all([self.model, self.api_key, self.org_id, self.project_id, self.base_url]):
            return self.model, self.api_key, self.org_id, self.project_id, self.base_url
            
        config = configparser.ConfigParser()
        config.read(self.config_path)
        
        try:
            self.model = config['Settings']['Model']
            self.api_key = config['Settings']['ModelApiKey']
            self.org_id = config['Settings']['OrgId']
            self.project_id = config['Settings']['ProjectId'] 
            self.base_url = config['Settings']['BaseURL']
            
            return self.model, self.api_key, self.org_id, self.project_id, self.base_url
            
        except KeyError as e:
            logging.error(f"Missing required config: {str(e)}")
            raise KeyError(f"Missing required config in 'Settings' section of {self.config_path}: {str(e)}")
        except Exception as e:
            logging.error(f"Error reading config: {str(e)}")
            raise

    def get_llm(self, temperature: float = 0) -> ChatOpenAI:
        if not self._llm:
            model, api_key, org_id, project_id, base_url = self.get_config()
            if model == "deepseek-reasoner":
                base_url = "https://api.deepseek.com/beta"
            self._llm = ChatOpenAI(
                model=model,
                api_key=api_key, 
                # temperature=temperature,
                # organization=org_id,
                base_url=base_url,
                callbacks=self._callbacks,
                timeout=120
            )
            
        return self._llm 

    def stream(self, messages: List[dict], temperature: Optional[float] = 0) -> str:
        try:
            llm = self.get_llm(temperature=temperature)
            result = []
            for chunk in llm.stream(messages):
                result.append(chunk.content)
            return "".join(result)
        except Exception as e:
            logging.error(f"Stream call failed: {str(e)}")
            raise

    def invoke(self, messages: List[dict], temperature: Optional[float] = 0) -> str:
        try:
            llm = self.get_llm(temperature=temperature)
            return llm.invoke(messages).content
        except Exception as e:
            logging.error(f"Invoke call failed: {str(e)}")
            raise 
            
    def as_runnable(self, temperature: Optional[float] = 0) -> RunnableLambda:
        def _invoke(content: str) -> str:
            messages = [{"role": "user", "content": content}]
            return self.stream(messages, temperature=temperature)
        
        return RunnableLambda(_invoke)

    def as_runnable_sync(self, temperature: Optional[float] = 0) -> RunnableLambda:
        def _invoke(content: str) -> str:
            messages = [{"role": "user", "content": content}]
            return self.invoke(messages, temperature=temperature).content
        
        return RunnableLambda(_invoke)