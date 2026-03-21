from .openai import OpenAICompatibleConnector


class MicrosoftConnector(OpenAICompatibleConnector):
    provider_id = "microsoft"
