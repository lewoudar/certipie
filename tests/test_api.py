import pytest

from .helpers import assert_zipfile


class TestPrivateKey:
    """Tests POST /certs/private-key"""

    def test_should_return_error_when_key_size_is_not_convertible_to_int(self, client):
        r = client.post('/certs/private-key', json={'key_size': 'foo'})

        assert r.status_code == 422
        assert r.json() == {
            'detail': [
                {
                    'loc': ['body', 'key_size'],
                    'msg': 'value is not a valid integer',
                    'type': 'type_error.integer'
                }
            ]
        }

    def test_should_return_error_when_key_size_is_less_than_512(self, client):
        r = client.post('/certs/private-key', json={'key_size': 40})

        assert r.status_code == 422
        assert r.json() == {
            'detail': [
                {
                    'loc': ['body', 'key_size'],
                    'msg': 'ensure this value is greater than or equal to 512',
                    'type': 'value_error.number.not_ge',
                    'ctx': {'limit_value': 512}
                }
            ]
        }

    def test_should_create_pair_of_keys_without_payload(self, client, tmp_path):
        r = client.post('/certs/private-key')

        assert r.status_code == 200
        assert r.headers['content-type'] == 'application/zip'

        assert_zipfile(r.content, tmp_path)

    @pytest.mark.parametrize(('payload', 'prefix'), [
        ({'filename_prefix': 'foo'}, 'foo'),
        ({'key_size': 1024}, 'id_rsa'),
        ({'passphrase': 'secret', 'filename_prefix': 'top_secret'}, 'top_secret')
    ])
    def test_should_create_pair_of_keys_with_payload(self, client, tmp_path, payload, prefix):
        r = client.post('/certs/private-key', json=payload)

        assert r.status_code == 200
        assert r.headers['content-type'] == 'application/zip'

        assert_zipfile(r.content, tmp_path, prefix)
