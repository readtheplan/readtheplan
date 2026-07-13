#AnsibleRequires -CSharpUtil Ansible.Basic
$spec = @{
    options = @{
        path = @{ type = "str"; required = $true }
    }
    supports_check_mode = $true
}
$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec)
Invoke-WebRequest -Uri $module.Params.url -SkipCertificateCheck
Set-Content -Path $module.Params.path -Value $module.Params.value
Set-Acl -Path $module.Params.path -AclObject $module.Params.acl
$module.Result.changed = $true
$module.ExitJson()
