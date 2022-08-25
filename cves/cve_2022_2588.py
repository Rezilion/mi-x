"""
Support for graphviz, version from packaging and other modules which written for avoiding repetitive code.
"""
import graphviz
from modules import commons, constants, os_release

VULNERABILITY = 'CVE-2022-2588'
DESCRIPTION = '''Dirty Cred

CVSS Score: 7.5
NVD Link: https://nvd.nist.gov/vuln/detail/cve-2014-0160

Dirty Cred are (now) two `use-after-free` privilege escalation vulnerabilities (CVE-2021-4154 and CVE-2022-2588) in the 
Linux kernel which can also be utilized for container escape.
The CVE-2021-4154 exploitation was first presented at the latest Black Hat USA 2022 conference. The researchers 
demonstrated how the exploit can be used to escalate privileges from unprivileged user to privileged one (root) on 
Centos 8 and Ubuntu 20.04 machines. 

* The vulnerability module is still in progress and changes may have occurred according to new updates.

Related Links:
https://i.blackhat.com/USA-22/Thursday/US-22-Lin-Cautious-A-New-Exploitation-Method.pdf
'''
FIXED = {'Debian 11': '5.10.136-1', 'Debian unstable': '5.18.16-1', 'Ubuntu 16.04': '4.4.0-231.265',
         'Ubuntu 18.04': '4.15.0-191.202', 'Ubuntu 20.02': '5.4.0-124.140', 'Ubuntu 22.04': '5.15.0-46.49'}


def validate(debug, container_name):
    """This function validates if the host is vulnerable to Heartbleed vulnerabilities."""
    if not container_name:
        if commons.check_linux_and_affected_distribution(VULNERABILITY, debug, container_name):
            affected_kernel = os_release.check_release(FIXED, debug, container_name)
            if affected_kernel == constants.UNSUPPORTED:
                print(constants.FULL_NOT_DETERMINED_MESSAGE.format(VULNERABILITY))
            elif affected_kernel:
                print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(VULNERABILITY))
            else:
                print(constants.FULL_VULNERABLE_MESSAGE.format(VULNERABILITY))
    else:
        print(constants.FULL_EXPLANATION_MESSAGE.format('Containers are not affected by kernel vulnerabilities'))
        print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(VULNERABILITY))


def validation_flow_chart():
    """This function creates graph that shows the vulnerability validation process of Heartbleed."""
    vol_graph = graphviz.Digraph('G', filename=VULNERABILITY, format='png')
    commons.graph_start(VULNERABILITY, vol_graph)
    vol_graph.edge('Is it Linux?', 'Is kernel version affected?', label='Yes')
    vol_graph.edge('Is it Linux?', 'Not Vulnerable', label='No')
    vol_graph.edge('Is kernel version affected?', 'Vulnerable', label='Yes')
    vol_graph.edge('Is kernel version affected?', 'Not Vulnerable', label='No')
    commons.graph_end(vol_graph)


def main(description, graph, debug, container_name):
    """This is the main function."""
    if description:
        print(f'\n{DESCRIPTION}')
    validate(debug, container_name)
    if graph:
        validation_flow_chart()
