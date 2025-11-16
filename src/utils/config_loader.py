"""
Configuration Loader Module
Handles loading and accessing application configuration
"""

import yaml
from pathlib import Path
from typing import Any, Dict, Optional
from dataclasses import dataclass


@dataclass
class OpenAIConfig:
    """OpenAI configuration"""

    model: str = "gpt-4"
    temperature: float = 0.7
    max_tokens: int = 4000
    top_p: float = 1.0
    frequency_penalty: float = 0.0
    presence_penalty: float = 0.0
    timeout: int = 60
    max_retries: int = 3


@dataclass
class AgentConfig:
    """Agent configuration"""

    enabled: bool = True
    modules: list = None


@dataclass
class AppConfig:
    """Application configuration"""

    name: str = "SecureAI Platform"
    version: str = "1.0.0"
    environment: str = "development"
    debug: bool = True
    log_level: str = "INFO"


class ConfigLoader:
    """Configuration loader and manager"""

    _instance: Optional["ConfigLoader"] = None
    _config: Dict[str, Any] = {}

    def __new__(cls):
        """Singleton pattern"""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        """Initialize configuration loader"""
        if not self._config:
            self.load_config()

    def load_config(self, config_path: Optional[str] = None) -> None:
        """
        Load configuration from YAML file

        Args:
            config_path: Path to config file (default: config/config.yaml)
        """
        if config_path is None:
            # Default path
            config_path = Path(__file__).parent.parent.parent / "config" / "config.yaml"
        else:
            config_path = Path(config_path)

        if not config_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")

        with open(config_path, "r") as f:
            self._config = yaml.safe_load(f)

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value by key (supports nested keys with dot notation)

        Args:
            key: Configuration key (e.g., 'app.name' or 'openai.model')
            default: Default value if key not found

        Returns:
            Any: Configuration value
        """
        keys = key.split(".")
        value = self._config

        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default

        return value

    def get_app_config(self) -> AppConfig:
        """Get application configuration"""
        app_data = self.get("app", {})
        return AppConfig(
            name=app_data.get("name", "SecureAI Platform"),
            version=app_data.get("version", "1.0.0"),
            environment=app_data.get("environment", "development"),
            debug=app_data.get("debug", True),
            log_level=app_data.get("log_level", "INFO"),
        )

    def get_openai_config(self) -> OpenAIConfig:
        """Get OpenAI configuration"""
        openai_data = self.get("openai", {})
        return OpenAIConfig(
            model=openai_data.get("model", "gpt-4"),
            temperature=openai_data.get("temperature", 0.7),
            max_tokens=openai_data.get("max_tokens", 4000),
            top_p=openai_data.get("top_p", 1.0),
            frequency_penalty=openai_data.get("frequency_penalty", 0.0),
            presence_penalty=openai_data.get("presence_penalty", 0.0),
            timeout=openai_data.get("timeout", 60),
            max_retries=openai_data.get("max_retries", 3),
        )

    def get_agent_config(self, agent_name: str) -> AgentConfig:
        """
        Get agent configuration

        Args:
            agent_name: Name of the agent

        Returns:
            AgentConfig: Agent configuration
        """
        agent_data = self.get(f"agents.{agent_name}", {})
        return AgentConfig(
            enabled=agent_data.get("enabled", True),
            modules=agent_data.get("modules", []),
        )

    def is_agent_enabled(self, agent_name: str) -> bool:
        """
        Check if agent is enabled

        Args:
            agent_name: Name of the agent

        Returns:
            bool: True if enabled
        """
        return self.get(f"agents.{agent_name}.enabled", True)

    def is_module_enabled(self, agent_name: str, module_name: str) -> bool:
        """
        Check if agent module is enabled

        Args:
            agent_name: Name of the agent
            module_name: Name of the module

        Returns:
            bool: True if enabled
        """
        modules = self.get(f"agents.{agent_name}.modules", [])
        return module_name in modules

    def reload(self) -> None:
        """Reload configuration from file"""
        self._config = {}
        self.load_config()

    @property
    def config(self) -> Dict[str, Any]:
        """Get full configuration dictionary"""
        return self._config


# Global config instance
_config_instance: Optional[ConfigLoader] = None


def get_config() -> ConfigLoader:
    """
    Get global configuration instance

    Returns:
        ConfigLoader: Configuration loader instance
    """
    global _config_instance
    if _config_instance is None:
        _config_instance = ConfigLoader()
    return _config_instance


# Example usage
if __name__ == "__main__":
    config = get_config()

    print("App Config:", config.get_app_config())
    print("OpenAI Config:", config.get_openai_config())
    print("Network Security Agent Enabled:", config.is_agent_enabled("network_security"))
    print(
        "Web Fuzzing Module Enabled:",
        config.is_module_enabled("network_security", "web_fuzzing"),
    )
