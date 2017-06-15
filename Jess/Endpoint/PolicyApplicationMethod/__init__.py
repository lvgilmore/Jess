#! /usr/bin/python

from Jess.Endpoint.PolicyApplicationMethod.printer_policy_application import PrinterPolicyApplication
from Jess.Endpoint.PolicyApplicationMethod.ssh_policy_application import SSHPolicyAplication

COMMIT_METHOD = {'default': PrinterPolicyApplication,
                 'ssh': SSHPolicyAplication}
