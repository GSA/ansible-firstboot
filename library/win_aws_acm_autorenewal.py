#!/usr/bin/python

DOCUMENTATION = r'''
---
module: win_aws_acm_autorenewal
version_added: "0.0.1"
short_description: Imports a host certificate from ACM PCA and renews it on-change.
description:
     - Searches AWS ACM for a certificate issued to the provided hostname, then
	   exports the certificate, creates a PFX file locally, and imports the PFX
	   into the Windows Certificate Store.
     - The certificate, certificate chain, and private key are loading into the
	   appopriate certificate stores to ensure the certificate is trusted natively.
requirements: [ "openssl", "AWSPowershell" ]
author: "GRACE Team (GSA)"
options:
  hostname:
    description:
      - 'The hostname for the matching certificate (without the domain/subdomain)'
    required: true
  passphrase:
    description:
      - The password used when exporting the certificate from AWS ACM and when creating
	    the PFX file that will be stored locally.
    required: true
  basepath:
    description:
      - The destination directory for the PFX file. This directory will also be used
	    as a scratch directory while performing the OpenSSL transformation operations.
    required: false
	default: 'C:\ProgramData\certificates'
  region:
    description:
      - The AWS region to use when making calls to ACM.
    required: false
	default: 'us-east-1'
  openssl:
    description:
      - The full path to openssl.exe for use with ACM
    required: false
    default: 'C:\Program Files\OpenSSL-Win64\bin\openssl.exe'
'''

EXAMPLES = r'''
- name: Machine Certificate
  win_aws_acm_autorenewal:
    hostname: server1
	passphrase: 'MySuperSecr3tP@s$w0rd!'
	basepath: 'C:\certs'
	region: 'us-west-1'
    openssl: 'C:\Program Files\OpenSSL-Win64\bin\openssl.exe'
'''
