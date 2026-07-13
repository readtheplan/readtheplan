import os
import subprocess

from ansible.plugins.action import ActionBase


class ActionModule(ActionBase):
    def run(self, tmp=None, task_vars=None):
        api_token = os.environ.get("RTP_FIXTURE_CONTROLLER_SECRET_DO_NOT_LEAK")
        result = self._execute_module(
            module_name="acme.operations.deploy",
            module_args=self._task.args,
            task_vars=task_vars,
            tmp=tmp,
        )
        result["credential_present"] = bool(api_token)
        subprocess.run(self._task.args["audit"], shell=True)
        return result
