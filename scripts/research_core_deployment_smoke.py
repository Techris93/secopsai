"""Read-only production smoke: no jobs, drafts or approvals are created."""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request


def main():
    token = os.environ.get('SECOPSAI_CORE_BRIDGE_TOKEN', '')
    if not token:
        raise ValueError('Core bridge credential is not configured')
    opener = urllib.request.build_opener(NoRedirect())
    endpoint = 'https://core.secopsai.dev/api/v1/research/assistant/results'
    body = b'{"job_ids":[]}'
    for authorized in (False, True):
        headers = {'Content-Type': 'application/json', 'User-Agent': 'SecOpsAI-Core-Deployment-Smoke/1'}
        if authorized:
            headers['Authorization'] = 'Bearer ' + token
        request = urllib.request.Request(endpoint, data=body, headers=headers)
        try:
            with opener.open(request, timeout=20) as response:
                raw = response.read(4097)
                if not authorized or response.status != 200 or len(raw) > 4096 or json.loads(raw).get('results') != []:
                    raise ValueError('Core assistant read contract did not pass')
        except urllib.error.HTTPError as error:
            if authorized or error.code != 401:
                raise ValueError('Core assistant access control did not pass') from None
    print(json.dumps({'status': 'passed', 'authenticated_empty_read': True, 'unauthorized_read_rejected': True, 'jobs_created': 0}))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('Core smoke endpoint redirects are not allowed')


if __name__ == '__main__':
    main()
