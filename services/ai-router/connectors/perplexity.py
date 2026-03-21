from .openai import OpenAICompatibleConnector


class PerplexityConnector(OpenAICompatibleConnector):
    provider_id = "perplexity"
