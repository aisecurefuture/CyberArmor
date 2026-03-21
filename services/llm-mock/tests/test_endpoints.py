import unittest

from fastapi.testclient import TestClient

from main import app


class LlmMockEndpointTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_health_ready_metrics_exist(self):
        h = self.client.get("/health")
        self.assertEqual(h.status_code, 200)
        self.assertEqual(h.json().get("status"), "ok")

        r = self.client.get("/ready")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json().get("status"), "ready")

        m = self.client.get("/metrics")
        self.assertEqual(m.status_code, 200)
        self.assertIn("cyberarmor_llm_mock_requests_total", m.text)


if __name__ == "__main__":
    unittest.main()
