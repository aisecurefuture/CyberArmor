from .openai import OpenAICompatibleConnector


class XAIConnector(OpenAICompatibleConnector):
    provider_id = "xai"
