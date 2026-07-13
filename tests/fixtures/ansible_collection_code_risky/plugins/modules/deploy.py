import os
import subprocess

import requests
import yaml
from ansible.module_utils.basic import AnsibleModule

module = AnsibleModule(
    argument_spec=dict(api_token=dict(type="str", no_log=False)),
    supports_check_mode=True,
)
api_token = os.environ.get("RTP_FIXTURE_ANSIBLE_SECRET_DO_NOT_LEAK")
subprocess.run(module.params["command"], shell=True)
requests.get(module.params["url"], verify=False)
os.remove(module.params["path"])
yaml.load(module.params["document"])
module.exit_json(changed=True)
