from .amazon import AmazonConnector
from .anthropic import AnthropicConnector
from .google import GoogleConnector
from .meta import MetaConnector
from .microsoft import MicrosoftConnector
from .openai import OpenAICompatibleConnector
from .perplexity import PerplexityConnector
from .xai import XAIConnector


CONNECTOR_REGISTRY = {
    "openai": OpenAICompatibleConnector,
    "anthropic": AnthropicConnector,
    "google": GoogleConnector,
    "amazon": AmazonConnector,
    "microsoft": MicrosoftConnector,
    "xai": XAIConnector,
    "meta": MetaConnector,
    "perplexity": PerplexityConnector,
}
