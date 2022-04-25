import Modules.constants as constants
import Modules.run_command as run_command
import Modules.os_type as os_type
import Modules.kernel_version as kernel_version
import Modules.commons as commons
import semver
import graphviz

CVE_ID = 'CVE-2022-25636'
DESCRIPTION = f'''{CVE_ID}

CVSS Score: 7.8
NVD Link: https://nvd.nist.gov/vuln/detail/CVE-2022-25636
 
A heap overflow Linux kernel bug due to an incorrect flow offload action array size in the `nf_tables_offload`
function of the file `net/netfilter/nf_dup_netdev.c` of the Netfilter component.
It impacts Linux kernel versions 5.4 through 5.6.10 and can be leveraged by a local adversary to gain elevated 
privileges on vulnerable systems to execute arbitrary code, escape containers, or induce a kernel panic.
'''
MIN_VULNERABLE_VERSION = '5.4.0'
MAX_VULNERABLE_VERSION = '5.6.10'
VULNERABLE_VARIABLE = 'offload_flags'
INVULNERABLE_VARIABLE = 'offload_action'


# This function checks if the vulnerable variable - offload_flags or invulnerable variable - offload_action are in use.
def nf_tables_affected(nf_tables_path, debug, container_name):
    strings_command = f'strings {nf_tables_path}'
    pipe_strings_command = run_command.command_output(strings_command, debug, container_name)
    strings_output = pipe_strings_command.stdout
    print(constants.FULL_QUESTION_MESSAGE.format(f'Is `nf_tables.ko` file fixed?'))
    if strings_output:
        for string in strings_output.split('\n'):
            if string == VULNERABLE_VARIABLE:
                print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
                print(constants.FULL_EXPLANATION_MESSAGE.format(f'The `nf_tables.ko` file is affected because it uses '
                                                                f'the vulnerable variable which is - '
                                                                f'{VULNERABLE_VARIABLE}'))
                return True
            elif string == INVULNERABLE_VARIABLE:
                print(constants.FULL_POSITIVE_RESULT_MESSAGE)
                print(constants.FULL_EXPLANATION_MESSAGE.format(f'The `nf_tables.ko` file is fixed because it uses the'
                                                                f'invulnerable variable which is - '
                                                                f'{INVULNERABLE_VARIABLE}'))
                return False
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'The vulnerable - {VULNERABLE_VARIABLE} and invulnerable - '
                                                        f'{INVULNERABLE_VARIABLE} variables were not found in the '
                                                        f'`nf_tables.ko` file.. unsupported case'))
        return constants.UNSUPPORTED
    else:
        print(constants.FULL_EXPLANATION_MESSAGE.format('Can not determine vulnerability status, unsupported '
                                                        'nf_tables.ko strings value'))
        return constants.UNSUPPORTED


# This function checks if the kernel version is vulnerable.
def check_kernel(debug, container_name):
    affected = ''
    print(constants.FULL_QUESTION_MESSAGE.format('Is kernel version vulnerable?'))
    host_kernel_version = kernel_version.get_kernel_version(container_name, debug)
    if host_kernel_version:
        if semver.compare(host_kernel_version, MAX_VULNERABLE_VERSION) == 1 and \
                semver.compare(host_kernel_version, MIN_VULNERABLE_VERSION) == -1:
            print(constants.FULL_POSITIVE_RESULT_MESSAGE)
            print(constants.FULL_EXPLANATION_MESSAGE.format(f'According to your os release, vulnerable kernel versions '
                                                            f'range is: {MIN_VULNERABLE_VERSION} to '
                                                            f'{MAX_VULNERABLE_VERSION}\nYour kernel version: '
                                                            f'{host_kernel_version[:constants.END]}'))
        else:
            print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
            print(constants.FULL_EXPLANATION_MESSAGE.format(f'According to your os release, vulnerable kernel versions '
                                                            f'range is: {MIN_VULNERABLE_VERSION} to '
                                                            f'{MAX_VULNERABLE_VERSION}\nYour kernel version: '
                                                            f'{host_kernel_version[:constants.END]}'))
            return host_kernel_version

    else:
        print(constants.FULL_EXPLANATION_MESSAGE.format('Kernel version unsupported value'))
        return constants.UNSUPPORTED
    return affected


# This function validates if the host is vulnerable to CVE-2022-25636.
def validate(debug, container_name):
    if os_type.linux(debug, container_name):
        vulnerable_kernel_version = check_kernel(debug, container_name)
        if vulnerable_kernel_version == constants.UNSUPPORTED:
            print(constants.FULL_UNSUPPORTED_MESSAGE)
        elif vulnerable_kernel_version:
            nf_tables_path = f'/usr/lib/modules/{vulnerable_kernel_version}/kernel/net/netfilter/nf_tables.ko'
            nf_tables_file = commons.file_content(nf_tables_path, debug, container_name)
            if nf_tables_file:
                affected = nf_tables_affected(nf_tables_path, debug, container_name)
                if affected == constants.UNSUPPORTED:
                    print(constants.FULL_UNSUPPORTED_MESSAGE)
                elif affected:
                    print(constants.FULL_VULNERABLE_MESSAGE.format(CVE_ID))
                else:
                    print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(CVE_ID))
            else:
                print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(CVE_ID))
        else:
            print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(CVE_ID))
    else:
        print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(CVE_ID))


# This function creates a graph that shows the vulnerability validation process of CVE-2022-25636.
def validation_flow_chart():
    vol_graph = graphviz.Digraph('G', filename=CVE_ID)
    commons.graph_start(CVE_ID, vol_graph)
    vol_graph.edge('Is it Linux?', 'Is the kernel version affected?', label='Yes')
    vol_graph.edge('Is it Linux?', 'Not Vulnerable', label='No')
    vol_graph.edge('Is the kernel version affected?', 'Does the `nf_tables.ko` file exists?', label='Yes')
    vol_graph.edge('Is the kernel version affected?', 'Not Vulnerable', label='No')
    vol_graph.edge('Does the `nf_tables.ko` file exists?', 'Is `nf_tables.ko` file affected?', label='Yes')
    vol_graph.edge('Does the `nf_tables.ko` file exists?', 'Not Vulnerable', label='No')
    vol_graph.edge('Is `nf_tables.ko` file affected?', 'Vulnerable', label='Yes')
    vol_graph.edge('Is `nf_tables.ko` file affected?', 'Not Vulnerable', label='No')
    commons.graph_end(vol_graph)


def main(describe, graph, debug, container_name):
    if describe:
        print(f'\n{DESCRIPTION}')
    validate(debug, container_name)
    validation_flow_chart()
    if graph:
        validation_flow_chart()


if __name__ == '__main__':
    main()