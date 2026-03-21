import unittest

from main import AgentCreate, TokenResponse


class AgentIdentityCompatibilityTests(unittest.TestCase):
    def test_legacy_agent_payload_normalizes(self):
        payload = AgentCreate(
            name="finance-bot",
            trust_level="privileged",
            capabilities=["ai:inference", "ai:audit"],
            tenant_id="tenant-a",
        )
        self.assertEqual(payload.display_name, "finance-bot")
        self.assertEqual(payload.owner_team, "unassigned")
        self.assertEqual(payload.application, "finance-bot")
        self.assertEqual(payload.allowed_tools, ["ai:inference", "ai:audit"])

    def test_token_response_contains_access_token_alias(self):
        r = TokenResponse(
            token="abc",
            access_token="abc",
            token_id="tok_123",
            expires_at="2026-01-01T00:00:00Z",
            agent_id="agt_123",
            ttl_seconds=3600,
            expires_in=3600,
        )
        self.assertEqual(r.token, r.access_token)


if __name__ == "__main__":
    unittest.main()
