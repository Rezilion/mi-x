from Modules import os_type, kernel_version, commons, constants
import graphviz

CVE_ID = 'CVE-2017-1000405'
DESCRIPTION = f'''{CVE_ID} - Huge Dirty COW

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
'''
MAX_KERNEL_VERSION = '4.15.0'
MIN_KERNEL_VERSION = '2.6.37'


# This function performs the check for zero pages.
def huge_page(debug, container_name):
    affected = False
    huge_page_path = '/sys/kernel/mm/transparent_hugepage/enabled'
    huge_page_content = commons.file_content(huge_page_path, debug, container_name)
    if not huge_page_content:
        return huge_page_content
    print(constants.FULL_QUESTION_MESSAGE.format('Does your system use huge pages mechanism?'))
    if huge_page_content[constants.START].__contains__('[never]'):
        print(constants.FULL_POSITIVE_RESULT_MESSAGE)
        print(constants.FULL_EXPLANATION_MESSAGE.format('Your system is not using Huge Pages'))
    elif huge_page_content[constants.START].__contains__('[madvise]'):
        affected = True
        print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
        print(constants.FULL_EXPLANATION_MESSAGE.format('Your system is using Huge Pages in "madvise" mode (means that '
                                                        'only applications which need Huge Pages will use it)'))
    elif huge_page_content[constants.START].__contains__('[always]'):
        affected = True
        print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
        print(constants.FULL_EXPLANATION_MESSAGE.format('Your system is using Huge Pages in "always" mode'))
    else:
        print(constants.FULL_EXPLANATION_MESSAGE.format('Can not determine vulnerability status, unsupported '
                                                        '`huge pages` value'))
        return constants.UNSUPPORTED
    return affected


# This function perform the check for zero pages.
def zero_page(debug, container_name):
    affected = False
    zero_page_path = '/sys/kernel/mm/transparent_hugepage/use_zero_page'
    zero_page_content = commons.file_content(zero_page_path, debug, container_name)
    if not zero_page_content:
        return affected
    print(constants.FULL_QUESTION_MESSAGE.format('Does your system use zero pages mechanism?'))
    if zero_page_content[constants.START].__contains__('0'):
        print(constants.FULL_POSITIVE_RESULT_MESSAGE)
        print(constants.FULL_EXPLANATION_MESSAGE.format('Your system is not using Huge Zero Pages'))
    elif zero_page_content[constants.START].__contains__('1'):
        affected = True
        print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
        print(constants.FULL_EXPLANATION_MESSAGE.format('Your system is using Huge Zero Pages'))
    else:
        print(constants.FULL_EXPLANATION_MESSAGE.format('Can not determine vulnerability status, unsupported `huge zero'
                                                        ' pages` value'))
        return constants.UNSUPPORTED
    return affected


# This function validates if the host is vulnerable to CVE-2017-1000405.
def validate(debug, container_name):
    if os_type.linux(debug, container_name):
        kernel_version_output = kernel_version.check_kernel(MIN_KERNEL_VERSION, MAX_KERNEL_VERSION, debug)
        if kernel_version_output == constants.UNSUPPORTED:
            print(constants.FULL_NOT_DETERMINED_MESSAGE.format(CVE_ID))
        elif kernel_version_output:
            affected = zero_page(debug, container_name)
            if affected == constants.UNSUPPORTED:
                print(constants.FULL_NOT_DETERMINED_MESSAGE.format(CVE_ID))
            elif affected:
                print(constants.FULL_VULNERABLE_MESSAGE.format(f'{CVE_ID} zero pages manipulation'))
            else:
                print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(f'zero pages manipulation in {CVE_ID}'))
            affected = huge_page(debug, container_name)
            if affected == constants.UNSUPPORTED:
                print(constants.FULL_NOT_DETERMINED_MESSAGE.format(CVE_ID))
            elif affected:
                print(constants.FULL_VULNERABLE_MESSAGE.format(f'{CVE_ID} huge pages manipulation'))
            else:
                print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(f'huge pages manipulation in {CVE_ID}'))
        else:
            print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(CVE_ID))
    else:
        print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(CVE_ID))


# This function creates graph that shows the vulnerability validation process of CVE-2017-1000405.
def validation_flow_chart():
    vol_graph = graphviz.Digraph('G', filename=CVE_ID)
    commons.graph_start(CVE_ID, vol_graph)
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


def main(describe, graph, debug, container_name):
    if describe:
        print(f'\n{DESCRIPTION}')
    validate(debug, container_name)
    if graph:
        validation_flow_chart()


if __name__ == '__main__':
    main()
