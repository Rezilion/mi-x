"""
Support for graphviz, version from packaging and other modules which written for avoiding repetitive code.
"""
import graphviz
from modules import commons, constants, os_release, kernel_version, run_command

VULNERABILITY = 'CVE-2021-4154'
DESCRIPTION = '''Dirty Cred

CVSS Score: 7.5
NVD Link: https://nvd.nist.gov/vuln/detail/cve-2014-0160

Dirty Cred are (now) two `use-after-free` privilege escalation vulnerabilities (CVE-2021-4154 and CVE-2022-2588) in the 
Linux kernel which can also be utilized for container escape.
The CVE-2021-4154 exploitation was first presented at the latest Black Hat USA 2022 conference. The researchers 
demonstrated how the exploit can be used to escalate privileges from unprivileged user to privileged one (root) on 
Centos 8 and Ubuntu 20.04 machines. 

* The vulnerability detection module is based on the information currently known. The module will be updated whenever new information regarding the vulnerability becomes available.
* The validation flow relies on the Linux kernel configuration file. This file is not signed and can be 
modified by admin users. Means that the configuration file can be modified, hence, the data shown is not 100% accurate.

Related Links:
https://www.rezilion.com/blog/dirty-cred-what-you-need-to-know/
https://i.blackhat.com/USA-22/Thursday/US-22-Lin-Cautious-A-New-Exploitation-Method.pdf
'''
PATCH_VARIABLE = 'CONFIG_CRED_ISOLATION=y'
FIXED = {'Debian 10': '4.19.235-1', 'Debian 11': '5.10.127-1', 'Debian unstable': '5.18.16-1',
         'Ubuntu 20.02': '5.4.0-88.99'}
RED_HAT_FIXES = ['RHBA-2022:0238', 'RHSA-2022:0186', 'RHSA-2022:0187', 'RHSA-2022:0231', 'RHSA-2022:0819',
                 'RHSA-2022:0825', 'RHSA-2022:0841', 'RHSA-2022:0849']


def find_patch(debug, container_name):
    """This function checks if there is a patch installed."""
    print(constants.FULL_QUESTION_MESSAGE.format('Is there patch installed?'))
    full_kernel_version = kernel_version.get_kernel_version(debug)
    if not full_kernel_version:
        print(constants.FULL_EXPLANATION_MESSAGE.format('Error finding kernel version'))
        return constants.UNSUPPORTED
    config_path = f'/boot/config-{full_kernel_version}'
    config_content = commons.file_content(config_path, debug, container_name)
    if not config_content:
        return constants.UNSUPPORTED
    for line in config_content:
        if PATCH_VARIABLE in line:
            print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('Yes'))
            print(constants.FULL_EXPLANATION_MESSAGE.format(f'The {PATCH_VARIABLE} patch string exists'))
            return 'True'
    print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('No'))
    print(constants.FULL_EXPLANATION_MESSAGE.format('The patch does not exist'))
    return ''


def check_red_hat_patch(debug, container_name):
    """This function checks security updates in Red Hat distribution."""
    print(constants.FULL_QUESTION_MESSAGE.format('There is a security update installed?'))
    list_security_fixes_command = 'yum updateinfo list security all'
    pipe_list_security_fixes = run_command.command_output(list_security_fixes_command, debug, container_name)
    list_security_fixes_output = pipe_list_security_fixes.stdout
    if not list_security_fixes_output:
        print(constants.FULL_EXPLANATION_MESSAGE.format('Unsupported output for updateinfo list command'))
        return constants.UNSUPPORTED
    for line in list_security_fixes_output.split('\n'):
        for fix in RED_HAT_FIXES:
            if fix in line:
                print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('Yes'))
                print(constants.FULL_EXPLANATION_MESSAGE.format(f'Your system has the {fix} security update installed'))
                return fix
    print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('No'))
    print(constants.FULL_EXPLANATION_MESSAGE.format('Your system does not have any security updates installed'))
    return ''


def check_distribution_functional(debug, container_name):
    """This function maps vulnerability check according to the host's os release."""
    information_fields = ['Distribution', 'Version']
    host_information = os_release.get_field(information_fields, debug, container_name)
    return_value = ''
    if 'Red' in host_information:
        return_value = check_red_hat_patch(debug, container_name)
    elif 'Ubuntu' in host_information or 'Debian' in host_information:
        return_value = os_release.check_release(FIXED, debug, container_name)
    return return_value


def validate(debug, container_name):
    """This function validates if the host is vulnerable to Dirty Cred vulnerability."""
    if not container_name:
        if commons.check_linux_and_affected_distribution(VULNERABILITY, debug, container_name):
            fixed_distribution = check_distribution_functional(debug, container_name)
            if fixed_distribution == constants.UNSUPPORTED:
                print(constants.FULL_NOT_DETERMINED_MESSAGE.format(VULNERABILITY))
            elif fixed_distribution:
                print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(VULNERABILITY))
            else:
                patch = find_patch(debug, container_name)
                if patch == constants.UNSUPPORTED:
                    print(constants.FULL_NOT_DETERMINED_MESSAGE.format(VULNERABILITY))
                elif patch:
                    print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(VULNERABILITY))
                else:
                    print(constants.FULL_VULNERABLE_MESSAGE.format(VULNERABILITY))
    else:
        print(constants.FULL_EXPLANATION_MESSAGE.format('Containers are not affected by kernel vulnerabilities'))
        print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(VULNERABILITY))


def validation_flow_chart():
    """This function creates graph that shows the vulnerability validation process of Dirty Cred."""
    vol_graph = graphviz.Digraph('G', filename=VULNERABILITY, format='png')
    commons.graph_start(VULNERABILITY, vol_graph)
    vol_graph.edge('Is it Linux?', 'Is kernel version affected?', label='Yes')
    vol_graph.edge('Is it Linux?', 'Not Vulnerable', label='No')
    vol_graph.edge('Is kernel version affected?', 'There is a patch installed?', label='Yes')
    vol_graph.edge('Is kernel version affected?', 'Not Vulnerable', label='No')
    vol_graph.edge('There is a patch installed?', 'Not Vulnerable', label='Yes')
    vol_graph.edge('There is a patch installed?', 'Vulnerable', label='No')
    commons.graph_end(vol_graph)


def main(description, graph, debug, container_name):
    """This is the main function."""
    if description:
        print(f'\n{DESCRIPTION}')
    validate(debug, container_name)
    if graph:
        validation_flow_chart()
