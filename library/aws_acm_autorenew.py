#!/usr/bin/env python3
DOCUMENTATION = '''
---
module: aws_acm_autorenew
short_description: Adds support for automatically updating certificates on an EC2 from the ACM Private CA
'''
EXAMPLES = '''
- name: My ACM Certificate
  aws_acm_autorenew:
    hostname: "mycoolhostname"
    passphrase: "superSecretPassphrase1!"
    cert_path: "/etc/pki/tls/certs/mycoolhostname.pem"
    trust_path: "/etc/pki/tls/certs/acm-ca.pem"
    key_path: "/etc/pki/tls/private/mycoolhostname.pem"
'''
import ssl
import boto3
import pytz
import datetime
from ansible.module_utils.basic import *
utc=pytz.UTC
def find_cert(hostname):
    # Create ACM client
    acm = boto3.client('acm', region_name='us-east-1')
    # List certificates with the pagination interface
    paginator = acm.get_paginator('list_certificates')
    for response in paginator.paginate():
        for certificate in response['CertificateSummaryList']:
            parts = certificate['DomainName'].split('.', 1)
            if parts[0] == hostname:
                return certificate
def remote_cert_not_before(arn):
    acm = boto3.client('acm', region_name='us-east-1')
    response = acm.describe_certificate(CertificateArn=arn)
    return response['Certificate']['NotBefore']
def local_cert_not_before(path):
    cert_dict = None
    try:
        cert_dict = ssl._ssl._test_decode_cert(path)
    except:
        pass
    d = 'Jan 1 00:00:00 1901 GMT'
    if cert_dict is not None and 'notBefore' in cert_dict:
        d = cert_dict['notBefore']
    return datetime.datetime.strptime(d, '%b %d %H:%M:%S %Y %Z')
def export_certificate(arn, data):
    acm = boto3.client('acm', region_name='us-east-1')
    response = acm.export_certificate(
        CertificateArn=arn,
        Passphrase=str.encode(data['passphrase'])
    )
    # Write to /etc/pki/tls/certs/$name.pem
    f = open(data['cert_path'], "w")
    f.write(response['Certificate']+response['CertificateChain'])
    f.close()
    # Write to /etc/pki/tls/certs/$name-trust.pem
    f = open(data['trust_path'], "w")
    f.write(response['CertificateChain'])
    f.close()
    # Write to /etc/pki/tls/private/$name.pem
    f = open(data['key_path'], "w")
    f.write(response['PrivateKey'])
    f.close()
def run(data):
    has_changed = False
    cert_arn = find_cert(data['hostname'])['CertificateArn']
    ldate = utc.localize(local_cert_not_before(data['cert_path']))
    if ldate != None:
        rdate = remote_cert_not_before(cert_arn)
        if ldate < rdate:
            print("upgrading certificate ldate: " + datetime.datetime.strftime(ldate, '%b %d %H:%M:%S %Y %Z')  + " rdate: " + datetime.datetime.strftime(rdate, '%b %d %H:%M:%S %Y %Z'))
            export_certificate(cert_arn, data)
            has_changed = True
    else:
        print("deploying certificate")
        export_certificate(cert_arn, data)
        has_changed = True
    return has_changed
def main():
    fields = {
		"hostname": {"required": True, "type": "str"},
		"passphrase": {"required": True, "type": "str" },
        "cert_path": {"required": True, "type": "str"},
        "trust_path": {"required": True, "type": "str" },
        "key_path": {"required": True, "type": "str" },
	}
    module = AnsibleModule(argument_spec=fields)
    has_changed = run(module.params)
    module.exit_json(changed=has_changed, meta=module.params)
if __name__ == "__main__":
    main()
