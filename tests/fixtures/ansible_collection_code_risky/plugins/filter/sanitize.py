from ansible.errors import AnsibleFilterError


def sanitize(value):
    # eval("this comment must not create a finding")
    message = "subprocess.run and os.remove are examples, not calls"
    if value is None:
        raise AnsibleFilterError(message)
    return str(value).strip()


class FilterModule:
    def filters(self):
        return {"sanitize": sanitize}
