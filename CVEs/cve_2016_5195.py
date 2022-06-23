"""
Support for importlib, graphviz and other modules which written for avoiding repetitive code.
"""
import importlib
import graphviz
from Modules import run_command, kernel_version, commons, os_release, constants

CVE_ID = 'CVE-2016-5195'
NEXT_VULNERABILITY = 'cve_2017_1000405'
DESCRIPTION = f'''The initial fix for this vulnerability contained an additional vulnerability, your system will be
scanned for both {CVE_ID} and {NEXT_VULNERABILITY}

{CVE_ID} - Dirty COW

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


def check_kpatch(debug, container_name):
    """This function checks if there is kpatch on the target system (relevant ony for Red Hat systems)."""
    patched = False
    lsmod_command = 'lsmod'
    print(constants.FULL_QUESTION_MESSAGE.format('Are there any loaded modules?'))
    pipe_modules = run_command.command_output(lsmod_command, debug, container_name)
    modules = pipe_modules.stdout
    if not modules:
        print(constants.FULL_POSITIVE_RESULT_MESSAGE)
        print(constants.FULL_EXPLANATION_MESSAGE.format('Can not determine loaded modules status, unsupported value'))
        return constants.UNSUPPORTED
    print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
    print(constants.FULL_QUESTION_MESSAGE.format('Is it patched with kpatch?'))
    for kpatch in KPATCH_MODULE_NAMES:
        if kpatch in modules:
            print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
            print(constants.FULL_EXPLANATION_MESSAGE.format(f'Red Hat relevant kpatch: {KPATCH_MODULE_NAMES}\nYour '
                                                            f'kpatch: {kpatch}'))
            patched = True
            break
    if not patched:
        print(constants.FULL_POSITIVE_RESULT_MESSAGE)
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'Red Hat relevant kpatch: {KPATCH_MODULE_NAMES}'))
    return patched


def validate_red_hat(fixed_release, debug, container_name):
    """This function validates the Red Hat case."""
    print(constants.FULL_QUESTION_MESSAGE.format('Is it Red Hat?'))
    if 'Red' in fixed_release:
        print(constants.FULL_NEUTRAL_RESULT_MESSAGE.format('Yes'))
        kpatch = check_kpatch(debug, container_name)
        if kpatch == constants.UNSUPPORTED:
            print(constants.FULL_NOT_DETERMINED_MESSAGE.format(CVE_ID))
        elif kpatch:
            print(constants.FULL_EXPLANATION_MESSAGE.format('Your kernel release has kpatch'))
            print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(CVE_ID))
        else:
            print(constants.FULL_EXPLANATION_MESSAGE.format('You do not have relevant kpatch'))
            print(constants.FULL_VULNERABLE_MESSAGE.format(CVE_ID))
    else:
        print(constants.FULL_NEUTRAL_RESULT_MESSAGE.format('No'))
        print(constants.FULL_VULNERABLE_MESSAGE.format(CVE_ID))


def check_release(debug, container_name):
    """This function checks if the host release is vulnerable according to the fixed os distributions and versions."""
    information_fields = ['Distribution', 'Version']
    host_information = os_release.get_field(information_fields, debug, container_name)
    if host_information.startswith('Debian'):
        information_fields = ['Distribution', 'Sid']
        host_information_debian = os_release.get_field(information_fields, debug, container_name)
        if host_information_debian.endswith('unstable'):
            host_information = host_information_debian
    if host_information == constants.UNSUPPORTED:
        return constants.UNSUPPORTED
    if host_information:
        print(constants.FULL_QUESTION_MESSAGE.format('Is os release affected?'))
        host_distribution = host_information.split(' ')[constants.START]
        if host_distribution not in constants.APT_DISTRIBUTIONS and \
                host_distribution not in constants.APT_DISTRIBUTIONS:
            print(constants.FULL_NEUTRAL_RESULT_MESSAGE.format('Can not determine'))
            print(constants.FULL_EXPLANATION_MESSAGE.format(f'Vulnerable os releases: {list(FIXED.keys())}\nYour os '
                                                            f'release: {host_distribution}\nThe os release you are '
                                                            f'running on is not supported'))
            return constants.UNSUPPORTED
        for fixed_release in FIXED:
            if fixed_release == host_information:
                print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
                print(constants.FULL_EXPLANATION_MESSAGE.format(f'Vulnerable os releases: {list(FIXED.keys())}\nYour os'
                                                                f' release: {host_information}\nThe os release you are '
                                                                f'running on is potentially affected'))
                return fixed_release
        print(constants.FULL_POSITIVE_RESULT_MESSAGE)
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'Vulnerable os releases: {list(FIXED.keys())}\nYour os '
                                                        f'release: {host_information}\nThe os release you are running '
                                                        f'on is not affected'))
    else:
        print(constants.FULL_EXPLANATION_MESSAGE.format('Can not determine vulnerability status, no distribution and '
                                                        'version values'))
    return ''


def validate(debug, container_name):
    """This function validates if the host is vulnerable to CVE-2016-5195."""
    if commons.check_linux_and_affected_distribution(CVE_ID, debug, container_name):
        fixed_release = check_release(debug, container_name)
        if fixed_release == constants.UNSUPPORTED:
            print(constants.FULL_NOT_DETERMINED_MESSAGE.format(CVE_ID))
        elif fixed_release:
            max_kernel_version = FIXED[fixed_release]
            check_kernel_version = kernel_version.check_kernel(MIN_KERNEL_VERSION, max_kernel_version, debug)
            if check_kernel_version == constants.UNSUPPORTED:
                print(constants.FULL_NOT_DETERMINED_MESSAGE.format(CVE_ID))
            elif check_kernel_version:
                print(constants.FULL_EXPLANATION_MESSAGE.format('The os release you are running on is potentially '
                                                                'affected'))
                validate_red_hat(fixed_release, debug, container_name)
            else:
                print(constants.FULL_EXPLANATION_MESSAGE.format('Your kernel version is already patched'))
                print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(CVE_ID))
        else:
            print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(CVE_ID))


def validation_flow_chart():
    """This function creates graph that shows the vulnerability validation process of CVE-2016-5195."""
    vol_graph = graphviz.Digraph('G', filename=CVE_ID)
    commons.graph_start(CVE_ID, vol_graph)
    vol_graph.edge('Is it Linux?', 'Not Vulnerable', label='No')
    vol_graph.edge('Is it Linux?', 'Is os release effected?', label='Yes')
    vol_graph.edge('Is os release effected?', 'Is the kernel release effected?', label='Yes')
    vol_graph.edge('Is os release effected?', 'Not Vulnerable', label='No')
    vol_graph.edge('Is the kernel release effected?', 'Is it Red Hat?', label='Yes')
    vol_graph.edge('Is the kernel release effected?', 'Not Vulnerable', label='No')
    vol_graph.edge('Is it Red Hat?', 'Are There loaded modules?', label='Yes')
    vol_graph.edge('Is it Red Hat?', 'Vulnerable', label='No')
    vol_graph.edge('Are There loaded modules?', 'Is it Patched with kpatch?', label='Yes')
    vol_graph.edge('Are There loaded modules?', 'Vulnerable', label='No')
    vol_graph.edge('Is it Patched with kpatch?', 'Not Vulnerable', label='Yes')
    vol_graph.edge('Is it Patched with kpatch?', 'Vulnerable', label='No')
    commons.graph_end(vol_graph)


def main(describe, graph, debug, container_name):
    """This is the main function."""
    if describe:
        print(f'\n{DESCRIPTION}')
    validate(debug, container_name)
    if graph:
        validation_flow_chart()
    next_cve_path = 'CVEs.' + NEXT_VULNERABILITY
    cve_validation = importlib.import_module(next_cve_path)
    cve_validation.main(describe, graph, debug, container_name)
