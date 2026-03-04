from fastapi import FastAPI, Request

app = FastAPI(title="LLM Mock", version="1.0.0")

@app.get("/health")
async def health():
    return {"status": "ok", "service": "llm-mock"}

@app.post("/v1/chat/completions")
async def chat_completions(req: Request):
    body = await req.json()
    # Minimal OpenAI-like shape so SDK demos can be swapped in later.
    return {
        "id": "cmpl-mock",
        "object": "chat.completion",
        "model": body.get("model", "mock"),
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "(mock) request received",
                },
                "finish_reason": "stop",
            }
        ],
    }
