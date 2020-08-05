firstboot [![circleci](https://circleci.com/gh/GSA/ansible-firstboot.svg?style=svg)](https://circleci.com/gh/GSA/ansible-firstboot)
=========

This ansible role runs on first boot.

Requirements
------------

Role Variables
--------------

| Variable | Default | Purpose |
| ------ | ------ | ------ |
| redhat_cylance_agent_filename | "" | redhat installer msi |

Dependencies
------------

None

Example Playbook
----------------

```yaml
- hosts: servers
  roles:
     - firstboot
```

Public domain
-------------

This project is in the worldwide [public domain](LICENSE.md). As stated in [CONTRIBUTING](CONTRIBUTING.md):

> This project is in the public domain within the United States, and copyright and related rights in the work worldwide are waived through the [CC0 1.0 Universal public domain dedication](https://creativecommons.org/publicdomain/zero/1.0/).
>
> All contributions to this project will be released under the CC0 dedication. By submitting a pull request, you are agreeing to comply with this waiver of copyright interest.
