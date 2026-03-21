from .openai import OpenAICompatibleConnector


class AmazonConnector(OpenAICompatibleConnector):
    provider_id = "amazon"
