"""
Support for graphviz and other modules which written for avoiding repetitive code.
"""
import graphviz
from modules import kernel_version, commons, constants

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
MAX_KERNEL_VERSION = '4.15.0'
MIN_KERNEL_VERSION = '2.6.37'


def huge_page(debug, container_name):
    """This function performs the check for zero pages."""
    affected = False
    huge_page_path = '/sys/kernel/mm/transparent_hugepage/enabled'
    huge_page_content = commons.file_content(huge_page_path, debug, container_name)
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
    zero_page_content = commons.file_content(zero_page_path, debug, container_name)
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


def validate(debug, container_name):
    """This function validates if the host is vulnerable to CVE-2017-1000405."""
    if not container_name:
        if commons.check_linux_and_affected_distribution(VULNERABILITY, debug, container_name):
            kernel_version_output = kernel_version.check_kernel(MIN_KERNEL_VERSION, MAX_KERNEL_VERSION, debug)
            if kernel_version_output == constants.UNSUPPORTED:
                print(constants.FULL_NOT_DETERMINED_MESSAGE.format(VULNERABILITY))
            elif kernel_version_output:
                affected = zero_page(debug, container_name)
                if affected == constants.UNSUPPORTED:
                    print(constants.FULL_NOT_DETERMINED_MESSAGE.format(VULNERABILITY))
                elif affected:
                    print(constants.FULL_VULNERABLE_MESSAGE.format(f'{VULNERABILITY} zero pages manipulation'))
                else:
                    print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(f'zero pages manipulation in {VULNERABILITY}'))
                affected = huge_page(debug, container_name)
                if affected == constants.UNSUPPORTED:
                    print(constants.FULL_NOT_DETERMINED_MESSAGE.format(VULNERABILITY))
                elif affected:
                    print(constants.FULL_VULNERABLE_MESSAGE.format(f'{VULNERABILITY} huge pages manipulation'))
                else:
                    print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(f'huge pages manipulation in {VULNERABILITY}'))
            else:
                print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(VULNERABILITY))
    else:
        print(constants.FULL_EXPLANATION_MESSAGE.format('Containers are not affected by kernel vulnerabilities'))
        print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(VULNERABILITY))


def validation_flow_chart():
    """This function creates graph that shows the vulnerability validation process of CVE-2017-1000405."""
    vol_graph = graphviz.Digraph('G', filename=VULNERABILITY, format='png')
    commons.graph_start(VULNERABILITY, vol_graph)
    vol_graph.edge('Is it Linux?', 'Does your system has a Huge Zero Pages mechanism?', label='Yes')
    vol_graph.edge('Is it Linux?', 'Not Vulnerable', label='No')
    vol_graph.edge('Does your system has a Huge Zero Pages mechanism?', 'Is Huge Zero Pages enabled?', label='Yes')
    vol_graph.edge('Does your system has a Huge Zero Pages mechanism?', 'Not Vulnerable', label='No')
    vol_graph.edge('Is Huge Zero Pages enabled?', 'Does your system has a Huge Pages mechanism?', label='Yes')
    vol_graph.edge('Is Huge Zero Pages enabled?', 'Not Vulnerable', label='No')
    vol_graph.edge('Does your system has a Huge Pages mechanism?', 'Is Huge Pages enabled?', label='Yes')
    vol_graph.edge('Does your system has a Huge Pages mechanism?', 'Not Vulnerable', label='No')
    vol_graph.edge('Is Huge Pages enabled?', 'Vulnerable', label='Yes')
    vol_graph.edge('Is Huge Pages enabled?', 'Not Vulnerable', label='No')
    commons.graph_end(vol_graph)


def main(description, graph, debug, container_name):
    """This is the main function."""
    if description:
        print(f'\n{DESCRIPTION}')
    validate(debug, container_name)
    if graph:
        validation_flow_chart()
