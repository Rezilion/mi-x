"""
Support for semver, graphviz and other modules which written for avoiding repetitive code.
"""
import graphviz
from packaging import version
from modules import kernel_version, commons, constants

CVE_ID = 'CVE-2022-0847'
DESCRIPTION = f'''{CVE_ID} - Dirty Pipe

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


def check_kernel_version(debug):
    """This function checks if the kernel version is affected by CVE-2022-0847."""
    affected = False
    host_kernel_version = kernel_version.get_kernel_version(debug)
    if not host_kernel_version:
        print(constants.FULL_QUESTION_MESSAGE.format('Is kernel version affected?'))
        print(constants.FULL_EXPLANATION_MESSAGE.format('Unsupported kernel version value'))
        return constants.UNSUPPORTED
    valid_kernel_version = commons.valid_kernel_version(host_kernel_version)
    if version.parse(valid_kernel_version) >= version.parse(FIXED_VERSION) or \
            version.parse(valid_kernel_version) < version.parse(FIRST_AFFECTED_VERSION):
        print(constants.FULL_QUESTION_MESSAGE.format('Is kernel version affected?'))
        print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'Your kernel version which is: {valid_kernel_version}, is not'
                                                        f'in the affected kernel versions range which is: '
                                                        f'{FIRST_AFFECTED_VERSION} to {FIXED_VERSION}'))
    else:
        return commons.check_patched_version('Kernel', valid_kernel_version, PATCHED_VERSIONS)
    return affected


def validate(debug, container_name):
    """This function validates if the host is vulnerable to CVE-2022-0847."""
    if not container_name:
        if commons.check_linux_and_affected_distribution(CVE_ID, debug, container_name):
            affected = check_kernel_version(debug)
            if affected == constants.UNSUPPORTED:
                print(constants.FULL_NOT_DETERMINED_MESSAGE.format(CVE_ID))
            elif affected:
                print(constants.FULL_VULNERABLE_MESSAGE.format(CVE_ID))
            else:
                print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(CVE_ID))
    else:
        print(constants.FULL_EXPLANATION_MESSAGE.format('Containers are not affected by kernel vulnerabilities'))
        print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(CVE_ID))


def validation_flow_chart():
    """This function creates a graph that shows the vulnerability validation process of CVE-2022-0847."""
    vol_graph = graphviz.Digraph('G', filename=CVE_ID, format='png')
    commons.graph_start(CVE_ID, vol_graph)
    vol_graph.edge('Is it Linux?', 'Is the kernel version affected?', label='Yes')
    vol_graph.edge('Is it Linux?', 'Not Vulnerable', label='No')
    vol_graph.edge('Is the kernel version affected?', 'Vulnerable', label='Yes')
    vol_graph.edge('Is the kernel version affected?', 'Not Vulnerable', label='No')
    commons.graph_end(vol_graph)


def main(describe, graph, debug, container_name):
    """This is the main function."""
    if describe:
        print(f'\n{DESCRIPTION}')
    validate(debug, container_name)
    if graph:
        validation_flow_chart()
