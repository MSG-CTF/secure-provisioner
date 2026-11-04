import unittest

from koth_pixel_gateway import BEGIN, GATE, pixel_gateway, private_gate


class PixelGatewayTests(unittest.TestCase):
    def setUp(self):
        self.upstream = "10.245.36.204:8080"
        self.original = """pixel.example {
 @internal path /internal/*
 respond @internal 403
 @released expression `approved-window`
 handle @released {
  reverse_proxy 10.245.36.204:8080 {
   header_up Cookie protected
   transport http {
    response_header_timeout 160s
   }
  }
 }
 handle {
  forward_auth https://msgctf.kr {
   uri /api/v1/koth/preview_sessions/game_authorize
  }
  reverse_proxy 10.245.36.204:8080 {
   header_up -X-KOTH-Preview-Session
  }
 }
}
"""

    def test_all_existing_entry_routes_keep_auth_release_headers_and_body(self):
        actual = pixel_gateway(self.original, self.upstream)
        before_gate = actual[:actual.index(BEGIN)].rstrip() + "\n"
        self.assertEqual(before_gate.replace("reverse_proxy " + GATE, "reverse_proxy " + self.upstream), self.original)
        self.assertEqual(actual.count("bind 127.0.0.1"), 1)
        self.assertEqual(actual.count("max_conns_per_host 2"), 1)
        self.assertEqual(actual.count("max_conns_per_host 4"), 1)
        self.assertIn("method POST\n  path /api/v1/submissions", actual)

    def test_repeat_does_not_add_more_pools_or_restart_a_game(self):
        actual = pixel_gateway(self.original, self.upstream)
        self.assertEqual(pixel_gateway(actual, self.upstream), actual)

    def test_tampered_pool_or_bypass_needs_review(self):
        actual = pixel_gateway(self.original, self.upstream)
        for changed in (actual.replace("bind 127.0.0.1", "bind 0.0.0.0"),
                        actual.replace("max_conns_per_host 2", "max_conns_per_host 20"),
                        self.original + actual[actual.index(BEGIN):],
                        actual[:actual.index(BEGIN)] + "reverse_proxy 10.245.36.204:8080\n" + actual[actual.index(BEGIN):],
                        actual + private_gate(self.upstream)):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                pixel_gateway(changed, self.upstream)

    def test_wrong_destination_or_used_listener_is_rejected(self):
        for upstream in ("127.0.0.1:8080", "8.8.8.8:8080", "10.245.36.204:80", "example.com:8080"):
            with self.subTest(upstream=upstream), self.assertRaises(ValueError):
                pixel_gateway(self.original, upstream)
        with self.assertRaises(ValueError):
            pixel_gateway(self.original + "http://:18081 {\n}\n", self.upstream)
        with self.assertRaises(ValueError):
            pixel_gateway(self.original, "10.245.0.2:8080")


if __name__ == "__main__":
    unittest.main()
