
"""
Groq API configuration -- model params, retry settings.
"""
from pydantic_settings import BaseSettings


class GroqConfig(BaseSettings):
    api_key: str = ""
    model: str = "llama-3-8b-8192"
    temperature: float = 0.2
    max_tokens: int = 512
    top_p: float = 0.95
    max_retries: int = 3
    timeout: int = 30

    class Config:
        env_prefix = "GROQ_"
        env_file = ".env"
        extra = "ignore"

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key and self.api_key != "your_groq_api_key_here")


groq_config = GroqConfig()
