#!/usr/bin/env python3
import os


class _FixtureResponse:
    content = b"fixture"


class _FixtureRequests:
    @staticmethod
    def get(_url, *, verify):
        del verify
        return _FixtureResponse()


class _FixturePickle:
    @staticmethod
    def loads(value):
        return value.decode()


requests = _FixtureRequests()
pickle = _FixturePickle()

api_token = os.environ["RTP_FIXTURE_EXTERNAL_FACT_PYTHON_SECRET_DO_NOT_LEAK"]
response = requests.get("https://python-facts.example.invalid/v1", verify=False)
print("cloud=" + str(pickle.loads(response.content)))
