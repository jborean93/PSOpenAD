# PSOpenAD Integration Environment

This contains a Vagrantfile and Ansible playbook that can be used to setup an AD environment to test PSOpenAD with.
The plan is to expand this environment setup to test out edge case scenarios that cannot be done through CI.

To set up the environment run the following:

```bash
vagrant up

ansible-playbook main.yml -vv
```
