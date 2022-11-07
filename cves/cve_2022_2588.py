"""
Support for graphviz, version from packaging and other modules which written for avoiding repetitive code.
"""
import graphviz
from modules import constants, graph_functions, status, os_release, kernel_version

VULNERABILITY = 'CVE-2022-2588'
DESCRIPTION = '''Dirty Cred

CVSS Score: 8.8
NVD Link: https://nvd.nist.gov/vuln/detail/CVE-2021-4154

Dirty Cred are (now) two `use-after-free` privilege escalation vulnerabilities (CVE-2021-4154 and CVE-2022-2588) in the 
Linux kernel which can also be utilized for container escape.
The CVE-2021-4154 exploitation was first presented at the latest Black Hat USA 2022 conference. The researchers 
demonstrated how the exploit can be used to escalate privileges from unprivileged user to privileged one (root) on 
Centos 8 and Ubuntu 20.04 machines. 

* The vulnerability detection module will be updated as new information regarding the vulnerability becomes available.

Related Links:
https://www.rezilion.com/blog/dirty-cred-what-you-need-to-know/
https://i.blackhat.com/USA-22/Thursday/US-22-Lin-Cautious-A-New-Exploitation-Method.pdf
'''
MIN_KERNEL_VERSION = '0'
FIXED_KERNEL_VERSIONS = {'Debian unstable': '6.0.7-1', 'Debian 12': '6.0.5-1', 'Debian 11': '5.10.140-1',
                         'Debian 10': '4.19.260-1', 'Ubuntu 14.04': '3.13.0-191.242', 'Ubuntu 16.04': '4.4.0-231.265',
                         'Ubuntu 18.04': '4.15.0-191.202', 'Ubuntu 20.04': '5.4.0-124.140',
                         'Ubuntu 22.04': '5.15.0-46.49', 'Ubuntu 22.10': '5.19.0-16.16'}
FIXED_AWS_KERNEL_VERSIONS = {'Ubuntu 14.04': '4.4.0-1111.117', 'Ubuntu 16.04': '4.4.0-1147.162',
                             'Ubuntu 18.04': '4.15.0-1139.150', 'Ubuntu 20.04': '5.4.0-1083.90',
                             'Ubuntu 22.04': '5.15.0-1017.21', 'Ubuntu 22.10': '5.19.0-1006.6'}
REMEDIATION = f'Upgrade kernel versions to:\n{FIXED}'
MITIGATION = ''


def validate(debug, container_name):
    """This function validates if the host is vulnerable to Heartbleed vulnerabilities."""
    state = {}
    if not container_name:
        kernel_version_output = kernel_version.check_kernel_version(FIXED_KERNEL_VERSIONS, FIXED_AWS_KERNEL_VERSIONS, debug, container_name)
        if kernel_version_output == constants.UNSUPPORTED:
            state[VULNERABILITY] = status.not_determind(VULNERABILITY)
        elif kernel_version_output:
            state[VULNERABILITY] = status.vulnerable(VULNERABILITY)
            status.remediation_mitigation(REMEDIATION, MITIGATION)
        else:
            state[VULNERABILITY] = status.not_vulnerable(VULNERABILITY)
    else:
        print(constants.FULL_EXPLANATION_MESSAGE.format('Containers are not affected by kernel vulnerabilities'))
        state[VULNERABILITY] = status.not_vulnerable(VULNERABILITY)
    return state


def validation_flow_chart():
    """This function creates graph that shows the vulnerability validation process of Heartbleed."""
    vulnerability_graph = graphviz.Digraph('G', filename=VULNERABILITY, format='png')
    graph_functions.graph_start(VULNERABILITY, vulnerability_graph)
    vulnerability_graph.edge('Is it Linux?', 'Is kernel version affected?', label='Yes')
    vulnerability_graph.edge('Is it Linux?', 'Not Vulnerable', label='No')
    vulnerability_graph.edge('Is kernel version affected?', 'Vulnerable', label='Yes')
    vulnerability_graph.edge('Is kernel version affected?', 'Not Vulnerable', label='No')
    graph_functions.graph_end(vulnerability_graph)


def main(description, graph, debug, container_name):
    """This is the main function."""
    if description:
        print(f'\n{DESCRIPTION}')
    state = validate(debug, container_name)
    if graph:
        validation_flow_chart()
    return state
