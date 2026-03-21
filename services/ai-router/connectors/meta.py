from .openai import OpenAICompatibleConnector


class MetaConnector(OpenAICompatibleConnector):
    provider_id = "meta"
