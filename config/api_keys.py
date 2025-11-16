"""
API Keys Management Module
Handles secure storage and retrieval of API keys
"""

import os
from typing import Optional
from pathlib import Path


class APIKeyManager:
    """Centralized API key management"""

    # OpenAI API Key - Set via environment variable OPENAI_API_KEY
    # Or update this value with your own key
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")

    @classmethod
    def get_openai_key(cls) -> str:
        """
        Get OpenAI API key

        Returns:
            str: OpenAI API key
        """
        # First try environment variable
        env_key = os.getenv("OPENAI_API_KEY")
        if env_key:
            return env_key

        # Fall back to hardcoded key
        return cls.OPENAI_API_KEY

    @classmethod
    def set_openai_key(cls, key: str) -> None:
        """
        Set OpenAI API key

        Args:
            key: OpenAI API key
        """
        cls.OPENAI_API_KEY = key
        os.environ["OPENAI_API_KEY"] = key

    @classmethod
    def validate_key(cls, key: str) -> bool:
        """
        Validate API key format

        Args:
            key: API key to validate

        Returns:
            bool: True if valid format
        """
        if not key:
            return False

        # OpenAI keys start with 'sk-'
        if key.startswith("sk-"):
            return len(key) > 20

        return False

    @classmethod
    def is_configured(cls) -> bool:
        """
        Check if API keys are configured

        Returns:
            bool: True if configured
        """
        key = cls.get_openai_key()
        return cls.validate_key(key)


# Initialize environment variable
os.environ["OPENAI_API_KEY"] = APIKeyManager.get_openai_key()


# Export for easy import
__all__ = ["APIKeyManager"]
