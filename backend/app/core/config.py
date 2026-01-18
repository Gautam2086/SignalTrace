from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"
    )
    
    # OpenRouter / LLM Configuration
    openai_api_key: Optional[str] = None
    openai_base_url: str = "https://openrouter.ai/api/v1"
    openai_model: str = "openai/gpt-4o-mini"
    
    # Database
    db_path: str = "./data/signaltrace.db"
    
    # CORS
    cors_origins: str = "http://localhost:5173"
    
    # Logging
    log_level: str = "INFO"
    
    @property
    def cors_origins_list(self) -> list[str]:
        """Parse CORS origins from comma-separated string."""
        return [origin.strip() for origin in self.cors_origins.split(",")]
    
    @property
    def has_llm_key(self) -> bool:
        """Check if LLM API key is configured."""
        return self.openai_api_key is not None and len(self.openai_api_key.strip()) > 0


settings = Settings()

