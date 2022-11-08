"""
Support for modules written to avoid repetitive code.
"""
from modules import constants, graph_functions, status, version_functions, kernel_functions

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
FIXED_KERNEL_VERSIONS = {'Debian unstable': '6.0.7-1', 'Debian 12': '6.0.5-1', 'Debian 11': '5.10.140-1',
                         'Debian 10': '4.19.249-2', 'Ubuntu 21.10': '5.13.0-35.40'}
FIXED_AWS_KERNEL_VERSIONS = {'Ubuntu 21.10': '5.13.0-1017.19'}
REMEDIATION = f'Upgrade kernel versions to:{FIXED_KERNEL_VERSIONS} or if running on an EC2 instance update kernel ' \
              f'version to: {FIXED_AWS_KERNEL_VERSIONS} or higher'
MITIGATION = ''


def validate(debug, container_name):
    """This function validates if the host is vulnerable to CVE-2022-0847."""
    state = {}
    if not container_name:
        affected = kernel_functions.check_kernel_version(FIXED_KERNEL_VERSIONS, FIXED_AWS_KERNEL_VERSIONS, debug, container_name)
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
    vulnerability_graph = graph_functions.generate_graph(VULNERABILITY)
    vulnerability_graph.edge('Is it Linux?', 'Is the kernel version affected?', label='Yes')
    vulnerability_graph.edge('Is it Linux?', 'Not Vulnerable', label='No')
    vulnerability_graph.edge('Is the kernel version affected?', 'Vulnerable', label='Yes')
    vulnerability_graph.edge('Is the kernel version affected?', 'Not Vulnerable', label='No')
    vulnerability_graph.view()


def main(description, graph, debug, container_name):
    """This is the main function."""
    if description:
        print(f'\n{DESCRIPTION}')
    state = validate(debug, container_name)
    if graph:
        validation_flow_chart()
    return state
