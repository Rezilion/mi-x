"""
Support for graphviz and other modules which written for avoiding repetitive code.
"""
import graphviz
from modules import constants, graph_functions, status, file_functions, kernel_version

VULNERABILITY = 'CVE-2017-1000405'
DESCRIPTION = f'''{VULNERABILITY} - Huge Dirty COW

CVSS Score: 7.0
NVD Link: https://nvd.nist.gov/vuln/detail/CVE-2017-1000405

Is a continued vulnerability to CVE-2016-5195 known as Dirty COW.
After the CVE-2016-5195 patch, another race condition was identified in the Transparent Huge Pages mechanism
 and Zero Huge Pages.
Transparent Huge Pages (THP) is a Linux memory management system, that reduces the overhead of
Translation Lookaside Buffer (TLB) lookups on machines with large amounts of memory, by using larger memory pages.
Zero Huge Page is a Huge Page filled with zeros.
The problem with the THP mechanism is that read-only huge pages can be rewritten as objects.
Attackers can use the THP mechanism to write to read-only Huge Pages and Zero Pages.
This can influence how user space applications behave or cause denial-of-service attacks.

Related Links:
https://medium.com/bindecy/huge-dirty-cow-cve-2017-1000405-110eca132de0
https://threatpost.com/flaw-found-in-dirty-cow-patch/129064/
'''
MIN_KERNEL_VERSION = '0'
FIXED_KERNEL_VERSIONS = {'Debian unstable': '6.0.7-1', 'Debian 12': '6.0.5-1', 'Debian 11': '5.10.140-1',
                         'Debian 10': '4.19.249-2', 'Debian 9': '4.9.65-1', 'Debian 8': '3.16.51-1',
                         'Ubuntu 17.10': '4.13.0-19.22', 'Ubuntu 17.04': '4.10.0-42.46',
                         'Ubuntu 16.04': '4.4.0-103.126', 'Ubuntu 14.04': '3.13.0-137.186'}
FIXED_AWS_KERNEL_VERSIONS = {'Ubuntu 16.04': '4.4.0-1043.52', 'Ubuntu 14.04': '4.4.0-1005.5'}
REMEDIATION = f'Upgrade kernel version to {FIXED_KERNEL_VERSIONS} or if running on an EC2 instance update kernel ' \
              f'version to: {FIXED_AWS_KERNEL_VERSIONS} or higher.'
MITIGATION_1 = 'Disable zero page.\nUse the following command to prevent the flaw from being exercised in this method:\n' \
               'echo 0 > /sys/kernel/mm/transparent_hugepage/use_zero_page'
MITIGATION_2 = 'Disable huge pages\nUse the following command to prevent the flaw from being exercised in this method:\n' \
               '[always] madvise never > /sys/kernel/mm/transparent_hugepage/enabled'


def huge_page(debug, container_name):
    """This function performs the check for zero pages."""
    affected = False
    huge_page_path = '/sys/kernel/mm/transparent_hugepage/enabled'
    huge_page_content = file_functions.file_content(huge_page_path, debug, container_name)
    if not huge_page_content:
        return huge_page_content
    print(constants.FULL_QUESTION_MESSAGE.format('Does your system use huge pages mechanism?'))
    if '[never]' in huge_page_content[constants.START]:
        print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
        print(constants.FULL_EXPLANATION_MESSAGE.format('Your system is not using Huge Pages'))
    elif '[madvise]' in huge_page_content[constants.START]:
        affected = True
        print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('Yes'))
        print(constants.FULL_EXPLANATION_MESSAGE.format('Your system is using Huge Pages in "madvise" mode (means that '
                                                        'only applications which need Huge Pages will use it)'))
    elif '[always]' in huge_page_content[constants.START]:
        affected = True
        print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('Yes'))
        print(constants.FULL_EXPLANATION_MESSAGE.format('Your system is using Huge Pages in "always" mode'))
    else:
        print(constants.FULL_EXPLANATION_MESSAGE.format('Can not determine vulnerability status, unsupported '
                                                        '`huge pages` value'))
        return constants.UNSUPPORTED
    return affected


def zero_page(debug, container_name):
    """This function perform the check for zero pages."""
    affected = False
    zero_page_path = '/sys/kernel/mm/transparent_hugepage/use_zero_page'
    zero_page_content = file_functions.file_content(zero_page_path, debug, container_name)
    if not zero_page_content:
        return affected
    print(constants.FULL_QUESTION_MESSAGE.format('Does your system use zero pages mechanism?'))
    if '0' in zero_page_content[constants.START]:
        print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
        print(constants.FULL_EXPLANATION_MESSAGE.format('Your system is not using Huge Zero Pages'))
    elif '1' in zero_page_content[constants.START]:
        affected = True
        print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('Yes'))
        print(constants.FULL_EXPLANATION_MESSAGE.format('Your system is using Huge Zero Pages'))
    else:
        print(constants.FULL_EXPLANATION_MESSAGE.format('Can not determine vulnerability status, unsupported `huge zero'
                                                        ' pages` value'))
        return constants.UNSUPPORTED
    return affected


def check_kernel_version(debug, container_name):
    """This function returns if the kernel version is affected."""
    fixed_kernel_versions = FIXED_KERNEL_VERSIONS
    if kernel_version.is_aws(debug):
        fixed_kernel_versions = FIXED_AWS_KERNEL_VERSIONS
    host_os_release = os_release.check_release(fixed_kernel_versions, debug, container_name)
    if host_os_release == constants.UNSUPPORTED or not host_os_release:
        return host_os_release
    if host_os_release in fixed_kernel_versions:
        fixed_kernel_version = fixed_kernel_versions[host_os_release]
        return kernel_version.check_kernel(MIN_KERNEL_VERSION, fixed_kernel_version, debug)
    return ''


def validate(debug, container_name):
    """This function validates if the host is vulnerable to CVE-2017-1000405."""
    state = {}
    if not container_name:
        kernel_version_output = check_kernel_version(debug, container_name)
        if kernel_version_output == constants.UNSUPPORTED:
            state[VULNERABILITY] = status.not_determined(VULNERABILITY)
        elif kernel_version_output:
            affected = zero_page(debug, container_name)
            if affected == constants.UNSUPPORTED:
                state[VULNERABILITY] = status.not_determined(VULNERABILITY)
            elif affected:
                state[f'{VULNERABILITY} - zero pages'] = status.vulnerable(f'{VULNERABILITY} zero pages manipulation')
                status.remediation_mitigation(REMEDIATION, MITIGATION_1)
            else:
                state[f'{VULNERABILITY} - zero pages'] = status.not_vulnerable(f'zero pages manipulation in {VULNERABILITY}')
            affected = huge_page(debug, container_name)
            if affected == constants.UNSUPPORTED:
                state[VULNERABILITY] = status.not_determined(VULNERABILITY)
            elif affected:
                state[f'{VULNERABILITY} - huge pages'] = status.vulnerable(f'{VULNERABILITY} huge pages manipulation')
                status.remediation_mitigation(REMEDIATION, MITIGATION_2)
            else:
                state[f'{VULNERABILITY} - huge pages'] = status.not_vulnerable(f'huge pages manipulation in {VULNERABILITY}')
        else:
            state[VULNERABILITY] = status.not_vulnerable(VULNERABILITY)
    else:
        print(constants.FULL_EXPLANATION_MESSAGE.format('Containers are not affected by kernel vulnerabilities'))
        state[VULNERABILITY] = status.not_vulnerable(VULNERABILITY)
    return state


def validation_flow_chart():
    """This function creates graph that shows the vulnerability validation process of CVE-2017-1000405."""
    vulnerability_graph = graphviz.Digraph('G', filename=VULNERABILITY, format='png')
    graph_functions.graph_start(VULNERABILITY, vulnerability_graph)
    vulnerability_graph.edge('Is it Linux?', 'Does your system has a Huge Zero Pages mechanism?', label='Yes')
    vulnerability_graph.edge('Is it Linux?', 'Not Vulnerable', label='No')
    vulnerability_graph.edge('Does your system has a Huge Zero Pages mechanism?', 'Is Huge Zero Pages enabled?', label='Yes')
    vulnerability_graph.edge('Does your system has a Huge Zero Pages mechanism?', 'Not Vulnerable', label='No')
    vulnerability_graph.edge('Is Huge Zero Pages enabled?', 'Does your system has a Huge Pages mechanism?', label='Yes')
    vulnerability_graph.edge('Is Huge Zero Pages enabled?', 'Not Vulnerable', label='No')
    vulnerability_graph.edge('Does your system has a Huge Pages mechanism?', 'Is Huge Pages enabled?', label='Yes')
    vulnerability_graph.edge('Does your system has a Huge Pages mechanism?', 'Not Vulnerable', label='No')
    vulnerability_graph.edge('Is Huge Pages enabled?', 'Vulnerable', label='Yes')
    vulnerability_graph.edge('Is Huge Pages enabled?', 'Not Vulnerable', label='No')
    graph_functions.graph_end(vulnerability_graph)


def main(description, graph, debug, container_name):
    """This is the main function."""
    if description:
        print(f'\n{DESCRIPTION}')
    state = validate(debug, container_name)
    if graph:
        validation_flow_chart()
    return state
