"""
Support for importlib and other modules written to avoid repetitive code.
"""
import importlib
from modules import constants, graph_functions, status_functions, run_command, kernel_functions, os_release_functions

VULNERABILITY = 'CVE-2016-5195'
NEXT_VULNERABILITY = 'cve_2017_1000405'
DESCRIPTION = f'''The initial fix for this vulnerability contained an additional vulnerability, your system will be
scanned for both {VULNERABILITY} and {NEXT_VULNERABILITY}

{VULNERABILITY} - Dirty COW

CVSS Score: 7.8
NVD Link: https://nvd.nist.gov/vuln/detail/CVE-2016-5195

Is a privilege escalation vulnerability found by the researcher Phil Oester in 2016.
A race condition is caused by using the Copy-On-Write (COW) mechanism in memory pages.
When a parent process creates a child process, both of these processes will initially share the same pages in memory.
To prevent access of two processes to the same place in memory at the same time, the shared pages will be marked as COW.
It means that if any of these processes tries to modify the shared pages, only a copy of these pages will be created.
Then, modifications will be done on the copy of the pages by that process, thus not affecting the other process.
The problem with the COW mechanism is that it also gives write permissions to copied pages, not only modified ones.
Attackers can use the COW mechanism to copy read-only memory pages, get write permissions and modify them.

Related Links:
https://chao-tic.github.io/blog/2017/05/24/dirty-cow
https://www.ncsc.gov.uk/news/dirty-cow-linux-privilege-escalation-vulnerability-being-actively-exploited
'''
NAME_FIELD = 'NAME='
VERSION_FIELD = 'VERSION_ID='
PRETTY_NAME_FIELD = 'PRETTY_NAME='
KPATCH_MODULE_NAMES = [
   'kpatch_3_10_0_327_36_1_1_1',
   'kpatch_3_10_0_327_36_2_1_1',
   'kpatch_3_10_0_229_4_2_1_1',
   'kpatch_3_10_0_327_28_3_1_1',
   'kpatch_3_10_0_327_28_2_1_1',
   'kpatch_3_10_0_327_13_1_1_1',
   'kpatch_3_10_0_327_10_1_1_2',
   'kpatch_3_10_0_327_4_5_1_1',
   'kpatch_3_10_0_229_14_1_1_1',
   'kpatch_3_10_0_229_42_1_1_1',
   'kpatch_3_10_0_327_22_2_1_2',
   'kpatch_3_10_0_327_10_1_1_1',
]
FIXED = {'Ubuntu 12.04': '3.2.0-113.155', 'Ubuntu 14.04': '3.13.0-100.147', 'Ubuntu 16.04': '4.4.0-45.66',
         'Ubuntu 16.10': '4.8.0-26.28', 'Debian 7': '3.2.82-1', 'Debian unstable': '4.7.8-1',
         'Debian 8': '3.16.36-1+deb8u2', 'Red 5': '2.6.18-416', 'Red 6': '2.6.32-642.6.2',
         'Red 7': '3.10.0-327.36.3', 'SLES 11-SP4': '3.0.101-84.1', 'SLES 12': '3.12.60-52.57.1',
         'SLES 12-SP1': '3.12.62-60.64.8.2', 'Alpine 3.4.5': '4.4.27'}
MIN_KERNEL_VERSION = '0.0.0'
REMEDIATION_1 = f'Upgrade kernel version to one of these:\n{FIXED}'
REMEDIATION_2 = f'Install one of the following kpatch:\n{KPATCH_MODULE_NAMES}'
MITIGATION = ''


def check_kpatch(debug, container_name):
    """This function checks if there is kpatch on the target system (relevant ony for Red Hat systems)."""
    patched = False
    lsmod_command = 'lsmod'
    print(constants.FULL_QUESTION_MESSAGE.format('Are there any loaded modules?'))
    pipe_modules = run_command.command_output(lsmod_command, debug, container_name)
    modules = pipe_modules.stdout
    if not modules:
        print(constants.FULL_EXPLANATION_MESSAGE.format('Can not determine loaded modules status, unsupported value'))
        return constants.UNSUPPORTED
    print(constants.FULL_NEUTRAL_RESULT_MESSAGE.format('Yes'))
    print(constants.FULL_QUESTION_MESSAGE.format('Is it patched with kpatch?'))
    for kpatch in KPATCH_MODULE_NAMES:
        if kpatch in modules:
            print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('Yes'))
            print(constants.FULL_EXPLANATION_MESSAGE.format(f'Red Hat relevant kpatch: {KPATCH_MODULE_NAMES}\nYour '
                                                            f'kpatch: {kpatch}'))
            return True
    if not patched:
        print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('No'))
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'Red Hat relevant kpatch: {KPATCH_MODULE_NAMES}\nNo matches '
                                                        f'kpatch was found'))
    return patched


def validate_red_hat(fixed_release, debug, container_name):
    """This function validates the Red Hat case."""
    state = {}
    print(constants.FULL_QUESTION_MESSAGE.format('Is it Red Hat?'))
    if 'Red' in fixed_release:
        print(constants.FULL_NEUTRAL_RESULT_MESSAGE.format('Yes'))
        kpatch = check_kpatch(debug, container_name)
        if kpatch == constants.UNSUPPORTED:
            state[VULNERABILITY] = status_functions.not_determined(VULNERABILITY)
            status_functions.remediation_mitigation(REMEDIATION_1, MITIGATION)
        elif kpatch:
            print(constants.FULL_EXPLANATION_MESSAGE.format('Your kernel release has kpatch'))
            state[VULNERABILITY] = status_functions.not_vulnerable(VULNERABILITY)
        else:
            print(constants.FULL_EXPLANATION_MESSAGE.format('You do not have relevant kpatch'))
            state[VULNERABILITY] = status_functions.vulnerable(VULNERABILITY)
            status_functions.remediation_mitigation(REMEDIATION_2, MITIGATION)
    else:
        print(constants.FULL_NEUTRAL_RESULT_MESSAGE.format('No'))
        state[VULNERABILITY] = status_functions.vulnerable(VULNERABILITY)
    return state


def validate(debug, container_name):
    """This function validates if the host is vulnerable to CVE-2016-5195."""
    state = {}
    if not container_name:
        fixed_release = os_release_functions.check_release(FIXED, debug, container_name)
        if fixed_release == constants.UNSUPPORTED:
            state[VULNERABILITY] = status_functions.not_determined(VULNERABILITY)
        elif fixed_release:
            max_kernel_version = FIXED[fixed_release]
            check_kernel_version = kernel_functions.check_kernel(MIN_KERNEL_VERSION, max_kernel_version, debug)
            if check_kernel_version == constants.UNSUPPORTED:
                state[VULNERABILITY] = status_functions.not_determined(VULNERABILITY)
            elif check_kernel_version:
                print(constants.FULL_EXPLANATION_MESSAGE.format('The os release you are running on is potentially '
                                                                'affected'))
                state = validate_red_hat(fixed_release, debug, container_name)
            else:
                print(constants.FULL_EXPLANATION_MESSAGE.format('Your kernel version is already patched'))
                state[VULNERABILITY] = status_functions.not_vulnerable(VULNERABILITY)
        else:
            state[VULNERABILITY] = status_functions.not_vulnerable(VULNERABILITY)
    else:
        print(constants.FULL_EXPLANATION_MESSAGE.format('Containers are not affected by kernel vulnerabilities'))
        state[VULNERABILITY] = status_functions.not_vulnerable(VULNERABILITY)
    return state


def validation_flow_chart():
    """This function creates graph that shows the vulnerability validation process of CVE-2016-5195."""
    vulnerability_graph = graph_functions.generate_graph(VULNERABILITY)
    vulnerability_graph.edge('Is it Linux?', 'Not Vulnerable', label='No')
    vulnerability_graph.edge('Is it Linux?', 'Is os release effected?', label='Yes')
    vulnerability_graph.edge('Is os release effected?', 'Is the kernel release effected?', label='Yes')
    vulnerability_graph.edge('Is os release effected?', 'Not Vulnerable', label='No')
    vulnerability_graph.edge('Is the kernel release effected?', 'Is it Red Hat?', label='Yes')
    vulnerability_graph.edge('Is the kernel release effected?', 'Not Vulnerable', label='No')
    vulnerability_graph.edge('Is it Red Hat?', 'Are There loaded modules?', label='Yes')
    vulnerability_graph.edge('Is it Red Hat?', 'Vulnerable', label='No')
    vulnerability_graph.edge('Are There loaded modules?', 'Is it Patched with kpatch?', label='Yes')
    vulnerability_graph.edge('Are There loaded modules?', 'Vulnerable', label='No')
    vulnerability_graph.edge('Is it Patched with kpatch?', 'Not Vulnerable', label='Yes')
    vulnerability_graph.edge('Is it Patched with kpatch?', 'Vulnerable', label='No')
    vulnerability_graph.view()


def main(description, graph, debug, container_name):
    """This is the main function."""
    if description:
        print(f'\n{DESCRIPTION}')
    state = validate(debug, container_name)
    if graph:
        validation_flow_chart()
    next_cve_path = 'cves.' + NEXT_VULNERABILITY
    cve_validation = importlib.import_module(next_cve_path)
    cve_validation.main(description, graph, debug, container_name)
    return state
