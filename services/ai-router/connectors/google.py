from .openai import OpenAICompatibleConnector


class GoogleConnector(OpenAICompatibleConnector):
    provider_id = "google"
