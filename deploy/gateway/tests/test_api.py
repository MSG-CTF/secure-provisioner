import os
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient
from gateway import controller as c
from gateway import main as api
import test_controller as fixtures


class APITests(unittest.TestCase):
    setUp = fixtures.ControllerTests.setUp
    write_config = fixtures.ControllerTests.write_config
    enable_pool = fixtures.ControllerTests.enable_pool

    def client(self):
        p = patch.dict(os.environ, {'RUNTIME_API_TOKEN': 'synthetic-runtime-token-for-local-tests-only'})
        p.start()
        self.addCleanup(p.stop)
        def controller(request):
            try:
                return c.dispatch(request)
            except c.ControllerError as error:
                raise api.GatewayError(error.status, error.code, str(error)) from error
        p = patch.object(api, 'controller', controller)
        p.start()
        self.addCleanup(p.stop)
        client = TestClient(api.create_app(), raise_server_exceptions=False)
        self.addCleanup(client.close)
        return client

    def test_plaintext_allocation_returned_by_real_http_api(self):
        self.enable_pool(42817, 42817)
        client = self.client()
        headers = {'Authorization': 'Bearer synthetic-runtime-token-for-local-tests-only'}
        request = {'target_ip': '8.8.8.8', 'target_port': 31042, 'protocol': 'tcp'}
        response = client.put('/v1/routes/sample', headers=headers, json=request)
        self.assertEqual(response.status_code, 201, response.text)
        self.assertEqual(response.json()['port'], 42817)
        self.assertIs(response.json()['tls'], False)
        self.assertIsNone(response.json()['url'])
        self.assertEqual(client.put('/v1/routes/sample', headers=headers, json=request).json(), response.json())
        self.assertEqual(client.get('/v1/routes/sample', headers=headers).json(), response.json())
        self.assertEqual(client.delete('/v1/routes/sample', headers=headers).status_code, 204)

    def test_management_authentication_is_still_required(self):
        client = self.client()
        for headers in ({}, {'Authorization': 'Bearer wrong'}):
            response = client.put('/v1/routes/sample', headers=headers, json={'target_ip': '8.8.8.8', 'target_port': 31042, 'protocol': 'tcp'})
            self.assertEqual(response.status_code, 401)
            self.assertFalse(c.REGISTRY.exists())

    def test_origin_api_requires_authentication_and_does_not_publish_a_route(self):
        client = self.client()
        for headers in ({}, {'Authorization': 'Bearer wrong'}):
            self.assertEqual(client.get('/v1/routes/future/origin', headers=headers).status_code, 401)
        headers = {'Authorization': 'Bearer synthetic-runtime-token-for-local-tests-only'}
        origin = client.get('/v1/routes/future/origin', headers=headers)
        self.assertEqual(origin.status_code, 200)
        self.assertFalse(c.REGISTRY.exists())
        self.assertEqual(client.get('/v1/routes/future', headers=headers).status_code, 404)
        route = client.put('/v1/routes/future', headers=headers, json={'target_ip':'8.8.8.8','target_port':31042,'protocol':'http'})
        self.assertEqual(route.json()['url'], origin.json()['url'])

    def test_http_response_model_rejects_plaintext_or_non_443_metadata(self):
        from pydantic import ValidationError
        base = {'instance_id': 'sample', 'hostname': 'a.gate.msgctf.kr', 'port': 443, 'tls': True, 'protocol': 'http', 'url': 'https://a.gate.msgctf.kr', 'created_at': '2026-10-27T00:00:00Z'}
        api.RouteResponse.model_validate(base)
        for changes in ({'tls': False}, {'port': 42817}, {'url': 'https://other.gate.msgctf.kr'}):
            with self.subTest(changes=changes):
                with self.assertRaises(ValidationError):
                    api.RouteResponse.model_validate({**base, **changes})
