"""
Support for semver, graphviz and other modules which written for avoiding repetitive code.
"""
import graphviz
from packaging import version
from modules import constants, graph_functions, status, version_functions, kernel_version

VULNERABILITY = 'CVE-2022-0847'
DESCRIPTION = f'''{VULNERABILITY} - Dirty Pipe

CVSS Score: 7.8
NVD Link: https://nvd.nist.gov/vuln/detail/CVE-2022-0847

Linux Kernel bug in the PIPE mechanism due to missing initialization of the `flags` member in the 
`pipe_buffer` struct. The bug allows an attacker to create an unprivileged process that will inject code into a root 
process, and through doing so, escalate privileges by getting write permissions to read-only files. This can also be 
used in order to modify files in container images on the host, effectively poisoning any new containers based on the 
modified image.

Related Links:
https://www.rezilion.com/blog/dirty-pipe-what-you-need-to-know/
https://dirtypipe.cm4all.com/
https://blog.malwarebytes.com/exploits-and-vulnerabilities/2022/03/linux-dirty-pipe-vulnerability-gives-unprivileged-users-root-access/
'''
FIRST_AFFECTED_VERSION = '5.8.0'
PATCHED_VERSIONS = ['5.10.102', '5.15.25', '5.16.11']
FIXED_VERSION = '5.17.0-rc6'
REMEDIATION = 'Upgrade kernel versions to 5.10.102, 5.15.25, 5.16.11, 5.17.0-rc6 or higher.'
MITIGATION = ''


def check_kernel_version(debug):
    """This function checks if the kernel version is affected by CVE-2022-0847."""
    affected = False
    valid_kernel_version = kernel_version.get_valid_kernel_version(debug)
    if not valid_kernel_version:
        print(constants.FULL_QUESTION_MESSAGE.format('Is kernel version affected?'))
        print(constants.FULL_EXPLANATION_MESSAGE.format('Unsupported kernel version value'))
        return constants.UNSUPPORTED
    if version.parse(valid_kernel_version) >= version.parse(FIXED_VERSION) or \
            version.parse(valid_kernel_version) < version.parse(FIRST_AFFECTED_VERSION):
        print(constants.FULL_QUESTION_MESSAGE.format('Is kernel version affected?'))
        print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'Your kernel version which is: {valid_kernel_version}, is not'
                                                        f'in the affected kernel versions range which is: '
                                                        f'{FIRST_AFFECTED_VERSION} to {FIXED_VERSION}'))
    else:
        return version_functions.check_patched_version('Kernel', valid_kernel_version, PATCHED_VERSIONS)
    return affected


def validate(debug, container_name):
    """This function validates if the host is vulnerable to CVE-2022-0847."""
    state = {}
    if not container_name:
        affected = check_kernel_version(debug)
        if affected == constants.UNSUPPORTED:
            state[VULNERABILITY] = status.not_determined(VULNERABILITY)
        elif affected:
            state[VULNERABILITY] = status.vulnerable(VULNERABILITY)
            status.remediation_mitigation(REMEDIATION, MITIGATION)
        else:
            state[VULNERABILITY] = status.not_vulnerable(VULNERABILITY)
    else:
        print(constants.FULL_EXPLANATION_MESSAGE.format('Containers are not affected by kernel vulnerabilities'))
        state[VULNERABILITY] = status.not_vulnerable(VULNERABILITY)
    return state


def validation_flow_chart():
    """This function creates a graph that shows the vulnerability validation process of CVE-2022-0847."""
    vulnerability_graph = graphviz.Digraph('G', filename=VULNERABILITY, format='png')
    graph_functions.graph_start(VULNERABILITY, vulnerability_graph)
    vulnerability_graph.edge('Is it Linux?', 'Is the kernel version affected?', label='Yes')
    vulnerability_graph.edge('Is it Linux?', 'Not Vulnerable', label='No')
    vulnerability_graph.edge('Is the kernel version affected?', 'Vulnerable', label='Yes')
    vulnerability_graph.edge('Is the kernel version affected?', 'Not Vulnerable', label='No')
    graph_functions.graph_end(vulnerability_graph)


def main(description, graph, debug, container_name):
    """This is the main function."""
    if description:
        print(f'\n{DESCRIPTION}')
    state = validate(debug, container_name)
    if graph:
        validation_flow_chart()
    return state
