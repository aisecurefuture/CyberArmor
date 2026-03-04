-- AIShields Envoy Lua Filter - AI Traffic Inspection
-- Inspects HTTP requests/responses for AI API patterns

local AI_DOMAINS = {
  ["api.openai.com"] = true, ["chat.openai.com"] = true,
  ["api.anthropic.com"] = true, ["claude.ai"] = true,
  ["generativelanguage.googleapis.com"] = true, ["gemini.google.com"] = true,
  ["api.mistral.ai"] = true, ["api.cohere.ai"] = true,
  ["api-inference.huggingface.co"] = true, ["huggingface.co"] = true,
  ["api.together.xyz"] = true, ["api.groq.com"] = true,
  ["api.deepseek.com"] = true, ["api.x.ai"] = true,
  ["copilot.github.com"] = true, ["api.perplexity.ai"] = true,
}

local AI_PATH_PATTERNS = {
  "/v1/chat/completions", "/v1/completions", "/v1/embeddings",
  "/v1/messages", "/v1/models",
  "/api/generate", "/api/chat",
}

local INJECTION_KEYWORDS = {
  "ignore previous instructions", "disregard system prompt",
  "jailbreak", "developer mode", "disable safety",
  "DAN mode", "bypass filter", "exfiltrate",
}

function envoy_on_request(handle)
  local host = handle:headers():get(":authority") or ""
  local path = handle:headers():get(":path") or ""
  local method = handle:headers():get(":method") or ""
  local content_type = handle:headers():get("content-type") or ""
  local domain = host:match("^([^:]+)") or host

  -- Check if this is AI service traffic
  local is_ai = AI_DOMAINS[domain] or false
  if not is_ai then
    for _, pattern in ipairs(AI_PATH_PATTERNS) do
      if path:find(pattern, 1, true) then
        is_ai = true
        break
      end
    end
  end

  if is_ai then
    handle:headers():add("x-cyberarmor-ai-detected", "true")
    handle:headers():add("x-cyberarmor-ai-domain", domain)
    handle:logInfo("[AIShields] AI request: " .. method .. " " .. domain .. path)

    -- For POST requests with JSON, attempt to inspect body for injection
    if method == "POST" and content_type:find("application/json") then
      local body = handle:body()
      if body then
        local body_str = body:getBytes(0, body:length())
        if body_str then
          for _, keyword in ipairs(INJECTION_KEYWORDS) do
            if body_str:lower():find(keyword, 1, true) then
              handle:headers():add("x-cyberarmor-injection-detected", "true")
              handle:logWarn("[AIShields] Prompt injection detected: " .. keyword)
              break
            end
          end
        end
      end
    end
  end
end

function envoy_on_response(handle)
  local ai_detected = handle:headers():get("x-cyberarmor-ai-detected")
  if ai_detected == "true" then
    handle:headers():add("x-cyberarmor-inspected", "true")
    local status = handle:headers():get(":status") or "0"
    handle:logInfo("[AIShields] AI response: status=" .. status)
  end
end
