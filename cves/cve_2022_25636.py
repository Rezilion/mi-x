"""
Support for modules written to avoid repetitive code.
"""
from modules import constants, graph_functions, status, run_command, file_functions, kernel_functions

VULNERABILITY = 'CVE-2022-25636'
DESCRIPTION = f'''{VULNERABILITY}

CVSS Score: 7.8
NVD Link: https://nvd.nist.gov/vuln/detail/CVE-2022-25636
 
A heap overflow Linux kernel bug due to an incorrect flow offload action array size in the `nf_tables_offload`
function of the file `net/netfilter/nf_dup_netdev.c` of the Netfilter component.
It impacts Linux kernel versions 5.4 through 5.6.10 and can be leveraged by a local adversary to gain elevated 
privileges on affected systems to execute arbitrary code, escape containers, or induce a kernel panic.

Related Links:
https://nickgregory.me/linux/security/2022/03/12/cve-2022-25636/
https://support.f5.com/csp/article/K13559191
'''
FIXED_KERNEL_VERSIONS = {'Debian unstable': '6.0.7-1', 'Debian 12': '6.0.5-1', 'Debian 11': '5.10.140-1',
                         'Debian 10': '4.19.249-2', 'Ubuntu 21.10': '5.13.0-35.40', 'Ubuntu 20.04': '5.4.0-104.118'}
FIXED_AWS_KERNEL_VERSIONS = {'Ubuntu 21.10': '5.4.0-1068.72', 'Ubuntu 20.04': '5.13.0-1017.19'}
AFFECTED_VARIABLE = 'offload_flags'
FIXED_VARIABLE = 'offload_action'
REMEDIATION = 'Upgrade kernel version to 5.6.11 or higher'
MITIGATION = 'Disable the use of user namespaces using the following command:\necho 0 > /proc/sys/user/max_user_namespaces\nIf you ' \
             'want to apply this change permanently, insert this line into a file in this directory /etc/sysctl.d/ ' \
             '(notice you are not modifying an existing file):\nuser.max_user_namespaces = 0\nThen, reload the changes' \
             ' using this command:\nsudo sysctl --system'


def nf_tables_affected(nf_tables_path, debug, container_name):
    """This function checks if the affected variable - offload_flags or fixed variable - offload_action are in use."""
    strings_command = f'strings {nf_tables_path}'
    pipe_strings_command = run_command.command_output(strings_command, debug, container_name)
    strings_output = pipe_strings_command.stdout
    print(constants.FULL_QUESTION_MESSAGE.format('Is `nf_tables.ko` file fixed?'))
    if not strings_output:
        print(constants.FULL_EXPLANATION_MESSAGE.format('Can not determine vulnerability status, unsupported '
                                                        'nf_tables.ko strings value'))
        return constants.UNSUPPORTED
    for string in strings_output.split('\n'):
        if string == AFFECTED_VARIABLE:
            print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('Yes'))
            print(constants.FULL_EXPLANATION_MESSAGE.format(f'The `nf_tables.ko` file is affected because it uses the '
                                                            f'affected variable which is - {AFFECTED_VARIABLE}'))
            return True
        if string == FIXED_VARIABLE:
            print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
            print(constants.FULL_EXPLANATION_MESSAGE.format(f'The `nf_tables.ko` file is not affected because it uses '
                                                            f'the fixed variable which is - {FIXED_VARIABLE}'))
            return False
    print(constants.FULL_EXPLANATION_MESSAGE.format(f'The affected - {AFFECTED_VARIABLE} and fixed - {FIXED_VARIABLE} '
                                                    f'variables were not found in the `nf_tables.ko` file.. unsupported'
                                                    f' case'))
    return constants.UNSUPPORTED


def validate(debug, container_name):
    """This function validates if the host is vulnerable to CVE-2022-25636."""
    state = {}
    if not container_name:
        affected_kernel_version = kernel_functions.check_kernel_version(FIXED_KERNEL_VERSIONS, FIXED_AWS_KERNEL_VERSIONS, debug, container_name)
        if affected_kernel_version == constants.UNSUPPORTED:
            state[VULNERABILITY] = status.not_determind(VULNERABILITY)
        elif affected_kernel_version:
            nf_tables_path = f'/usr/lib/modules/{affected_kernel_version}/kernel/net/netfilter/nf_tables.ko'
            nf_tables_file = file_functions.check_file_existence(nf_tables_path, debug, container_name)
            if nf_tables_file:
                affected = nf_tables_affected(nf_tables_path, debug, container_name)
                if affected == constants.UNSUPPORTED:
                    state[VULNERABILITY] = status.not_determind(VULNERABILITY)
                elif affected:
                    state[VULNERABILITY] = status.vulnerable(VULNERABILITY)
                    status.remediation_mitigation(REMEDIATION, MITIGATION)
                else:
                    state[VULNERABILITY] = status.not_vulnerable(VULNERABILITY)
            else:
                state[VULNERABILITY] = status.not_vulnerable(VULNERABILITY)
        else:
            state[VULNERABILITY] = status.not_vulnerable(VULNERABILITY)
    else:
        print(constants.FULL_EXPLANATION_MESSAGE.format('Containers are not affected by kernel vulnerabilities'))
        state[VULNERABILITY] = status.not_vulnerable(VULNERABILITY)
    return state


def validation_flow_chart():
    """This function creates a graph that shows the vulnerability validation process of CVE-2022-25636."""
    vulnerability_graph = graph_functions.graph_start(VULNERABILITY)
    vulnerability_graph.edge('Is it Linux?', 'Is the kernel version affected?', label='Yes')
    vulnerability_graph.edge('Is it Linux?', 'Not Vulnerable', label='No')
    vulnerability_graph.edge('Is the kernel version affected?', 'Does the `nf_tables.ko` file exists?', label='Yes')
    vulnerability_graph.edge('Is the kernel version affected?', 'Not Vulnerable', label='No')
    vulnerability_graph.edge('Does the `nf_tables.ko` file exists?', 'Is `nf_tables.ko` file affected?', label='Yes')
    vulnerability_graph.edge('Does the `nf_tables.ko` file exists?', 'Not Vulnerable', label='No')
    vulnerability_graph.edge('Is `nf_tables.ko` file affected?', 'Vulnerable', label='Yes')
    vulnerability_graph.edge('Is `nf_tables.ko` file affected?', 'Not Vulnerable', label='No')
    vulnerability_graph.view()


def main(description, graph, debug, container_name):
    """This is the main function."""
    if description:
        print(f'\n{DESCRIPTION}')
    state = validate(debug, container_name)
    if graph:
        validation_flow_chart()
    return state
