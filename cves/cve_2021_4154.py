"""
Support for modules written to avoid repetitive code.
"""
from modules import constants, graph_functions, status_functions, run_command, file_functions, os_release_functions, kernel_functions

VULNERABILITY = 'CVE-2021-4154'
DESCRIPTION = '''Dirty Cred

CVSS Score: 8.8
NVD Link: https://nvd.nist.gov/vuln/detail/CVE-2021-4154

Dirty Cred are (now) two `use-after-free` privilege escalation vulnerabilities (CVE-2021-4154 and CVE-2022-2588) in the 
Linux kernel which can also be utilized for container escape.
The CVE-2021-4154 exploitation was first presented at the Black Hat USA 2022 conference. The researchers 
demonstrated how the exploit can be used to escalate privileges from unprivileged user to privileged one (root) on 
Centos 8 and Ubuntu 20.04 machines. 

* The vulnerability detection module is based on the information currently known. The module will be updated whenever new information regarding the vulnerability becomes available.
* The validation flow relies on the Linux kernel configuration file. This file is not signed and can be 
modified by admin users. Note that since the file can be modified, validation of the patch may not be accurate.

Related Links:
https://www.rezilion.com/blog/dirty-cred-what-you-need-to-know/
https://i.blackhat.com/USA-22/Thursday/US-22-Lin-Cautious-A-New-Exploitation-Method.pdf
'''
MIN_KERNEL_VERSION = '0'
PATCH_VARIABLE = 'CONFIG_CRED_ISOLATION=y'
FIXED_KERNEL_VERSIONS = {'Debian unstable': '6.0.7-1', 'Debian 12': '6.0.5-1', 'Debian 11': '5.10.140-1',
                         'Debian 10': '4.19.249-2', 'Ubuntu 20.04': '5.4.0-88.99'}
FIXED_AWS_KERNEL_VERSIONS = {'Ubuntu 20.04': '5.4.0-1057.60'}
RED_HAT_FIXES = ['RHBA-2022:0238', 'RHSA-2022:0186', 'RHSA-2022:0187', 'RHSA-2022:0231', 'RHSA-2022:0819',
                 'RHSA-2022:0825', 'RHSA-2022:0841', 'RHSA-2022:0849']
REMEDIATION = f'Choose one of these:\n- Upgrade kernel versions to:{FIXED_KERNEL_VERSIONS} or if running on an EC2 ' \
              f'instance update kernel version to: {FIXED_AWS_KERNEL_VERSIONS} or higher\n- If running on RedHat, ' \
              f'update to one of the following patches:\n{RED_HAT_FIXES}\n- Patch the kernel using the following ' \
              f'script: https://github.com/Markakd/DirtyCred/tree/master/defense'
MITIGATION = ''


def find_patch(debug, container_name):
    """This function checks if there is a patch installed."""
    full_kernel_version = kernel_functions.get_kernel_version(debug)
    if not full_kernel_version:
        print(constants.FULL_EXPLANATION_MESSAGE.format('Error finding kernel version'))
        return constants.UNSUPPORTED
    config_path = f'/boot/config-{full_kernel_version}'
    config_content = file_functions.get_file_content(config_path, debug, container_name)
    print(constants.FULL_QUESTION_MESSAGE.format('Is there a patch installed?'))
    if not config_content:
        return constants.UNSUPPORTED
    patch = False
    for line in config_content:
        if PATCH_VARIABLE in line:
            print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('Yes'))
            print(constants.FULL_EXPLANATION_MESSAGE.format(f'The {PATCH_VARIABLE} patch string exists'))
            patch = True
    print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('No'))
    print(constants.FULL_EXPLANATION_MESSAGE.format('The patch does not exist'))
    return patch


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
    """This function performs the vulnerability checks according to the host's os release."""
    information_fields = ['Distribution', 'Version']
    host_information = os_release_functions.get_field(information_fields, debug, container_name)
    return_value = ''
    print(constants.FULL_QUESTION_MESSAGE.format('Is distribution supported?'))
    if 'Red' in host_information:
        print(constants.FULL_NEUTRAL_RESULT_MESSAGE.format('Yes'))
        return_value = check_red_hat_patch(debug, container_name)
    elif 'Ubuntu' in host_information or 'Debian' in host_information:
        print(constants.FULL_NEUTRAL_RESULT_MESSAGE.format('Yes'))
        return_value = kernel_functions.check_kernel_version(MIN_KERNEL_VERSION, FIXED_KERNEL_VERSIONS, FIXED_AWS_KERNEL_VERSIONS, debug, container_name)
    else:
        print(constants.FULL_NEUTRAL_RESULT_MESSAGE.format('No'))
    return return_value


def validate(debug, container_name):
    """This function validates if the host is vulnerable to Dirty Cred vulnerability."""
    state = {}
    if not container_name:
        fixed_distribution = check_distribution_functional(debug, container_name)
        if fixed_distribution == constants.UNSUPPORTED:
            state[VULNERABILITY] = status_functions.not_determined(VULNERABILITY)
        elif not fixed_distribution:
            state[VULNERABILITY] = status_functions.not_vulnerable(VULNERABILITY)
        else:
            patch = find_patch(debug, container_name)
            if patch == constants.UNSUPPORTED:
                state[VULNERABILITY] = status_functions.not_determined(VULNERABILITY)
                status_functions.remediation_mitigation(REMEDIATION, MITIGATION)
            elif patch:
                state[VULNERABILITY] = status_functions.not_vulnerable(VULNERABILITY)
            else:
                state[VULNERABILITY] = status_functions.vulnerable(VULNERABILITY)
                status_functions.remediation_mitigation(REMEDIATION, MITIGATION)
    else:
        print(constants.FULL_EXPLANATION_MESSAGE.format('Containers are not affected by kernel vulnerabilities'))
        state[VULNERABILITY] = status_functions.not_vulnerable(VULNERABILITY)
    return state


def validation_flow_chart():
    """This function creates graph that shows the vulnerability validation process of Dirty Cred."""
    vulnerability_graph = graph_functions.generate_graph(VULNERABILITY)
    vulnerability_graph.edge('Is it Linux?', 'Is kernel version affected?', label='Yes')
    vulnerability_graph.edge('Is it Linux?', 'Not Vulnerable', label='No')
    vulnerability_graph.edge('Is kernel version affected?', 'There is a patch installed?', label='Yes')
    vulnerability_graph.edge('Is kernel version affected?', 'Not Vulnerable', label='No')
    vulnerability_graph.edge('Is there a patch installed?', 'Not Vulnerable', label='Yes')
    vulnerability_graph.edge('Is there a patch installed?', 'Vulnerable', label='No')
    vulnerability_graph.view()


def main(description, graph, debug, container_name):
    """This is the main function."""
    if description:
        print(f'\n{DESCRIPTION}')
    state = validate(debug, container_name)
    if graph:
        validation_flow_chart()
    return state
