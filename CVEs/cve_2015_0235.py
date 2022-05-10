from Modules import os_type, run_command, commons, constants
from packaging import version
import graphviz

CVE_ID = 'CVE-2015-0235'
DESCRIPTION = f'''Ghost

CVSS Score: 6.8
NVD Link: https://nvd.nist.gov/vuln/detail/CVE-2015-0235

{CVE_ID} is a Heap-based buffer overflow vulnerability in the __nss_hostname_digits_dots function .
This vulnerability allows a remote attacker that is able to make an application call to gethostbyname*() functions to
execute arbitrary code with the permissions of the user running the application.
The vulnerable glibc versions are between 2.2 to 2.17 (the fix was introduced in version 2.18).
'''
MIN_AFFECTED_VERSION = '2.2'
MAX_AFFECTED_VERSION = '2.17'


# This function checks if the GLIBC version is affected.
def glibc_version(glibc_value):
    print(constants.FULL_QUESTION_MESSAGE.format('Is GLIBC version affected?'))
    if (version.parse(glibc_value) >= version.parse(MIN_AFFECTED_VERSION)) \
            and (version.parse(glibc_value) <= version.parse(MAX_AFFECTED_VERSION)):
        print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'Vulnerable GLIBC versions are between {MIN_AFFECTED_VERSION} '
                                                        f'to {MAX_AFFECTED_VERSION}'))
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'Your GLIBC version which is: {glibc_value} is affected'))
        return True
    else:
        print(constants.FULL_POSITIVE_RESULT_MESSAGE)
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'Vulnerable GLIBC versions are between {MIN_AFFECTED_VERSION} '
                                                        f'to {MAX_AFFECTED_VERSION}'))
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'Your GLIBC version which is: {glibc_value} is not affected'))
        return False


# This function checks if GLIBC exists.
def glibc_exist(debug, container_name):
    glibc_command = 'ldd --version'
    pipe_glibc = run_command.command_output(glibc_command, debug, container_name)
    glibc_output = pipe_glibc.stdout
    print(constants.FULL_QUESTION_MESSAGE.format('There is GLIBC?'))
    if glibc_output:
        if glibc_output.__contains__('GLIBC') or glibc_output.__contains__('GNU libc'):
            print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
            print(constants.FULL_EXPLANATION_MESSAGE.format('GLIBC does exist'))
            return glibc_output.split('\n')[constants.START].split(' ')[-1]
        else:
            print(constants.FULL_POSITIVE_RESULT_MESSAGE)
            print(constants.FULL_EXPLANATION_MESSAGE.format('GLIBC does not exist'))
            return ''
    else:
        print(constants.FULL_EXPLANATION_MESSAGE.format('Unsupported GLIBC value'))
        return constants.UNSUPPORTED


# This function validates if the host is vulnerable to Ghost vulnerabilities.
def validate(debug, container_name):
    if os_type.linux(debug, container_name):
        glibc_value = glibc_exist(debug, container_name)
        if glibc_value == constants.UNSUPPORTED:
            print(constants.FULL_NOT_DETERMINED_MESSAGE.format(CVE_ID))
        elif glibc_value:
            if glibc_version(glibc_value):
                print(constants.FULL_VULNERABLE_MESSAGE.format(CVE_ID))
            else:
                print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(CVE_ID))
        else:
            print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(CVE_ID))
    else:
        print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(CVE_ID))


# This function creates graph that shows the vulnerability validation process of Ghost.
def validation_flow_chart():
    vol_graph = graphviz.Digraph('G', filename=CVE_ID)
    commons.graph_start(CVE_ID, vol_graph)
    vol_graph.edge('Is it Linux?', 'Is there GLIBC?', label='Yes')
    vol_graph.edge('Is it Linux?', 'Not Vulnerable', label='No')
    vol_graph.edge('Is there GLIBC?', 'Is the GLIBC version affected?', label='Yes')
    vol_graph.edge('Is there GLIBC?', 'Not Vulnerable', label='No')
    vol_graph.edge('Is the GLIBC version affected?', 'Vulnerable', label='Yes')
    vol_graph.edge('Is the GLIBC version affected?', 'Not Vulnerable', label='No')
    commons.graph_end(vol_graph)


def main(describe, graph, debug, container_name):
    if describe:
        print(f'\n{DESCRIPTION}')
    validate(debug, container_name)
    if graph:
        validation_flow_chart()


if __name__ == '__main__':
    main()
