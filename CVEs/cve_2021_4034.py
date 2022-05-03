import Modules.constants as constants
import Modules.receive_package as receive_package
import Modules.run_command as run_command
import Modules.os_type as os_type
import Modules.os_release as os_release
import Modules.commons as commons
from packaging import version
import graphviz

CVE_ID = 'CVE-2021-4034'
DESCRIPTION = f'''{CVE_ID} - PwnKit 

CVSS Score: 9.0
NVD Link: https://nvd.nist.gov/vuln/detail/CVE-2021-45046

The vulnerability is in the pkexec file in Policykit Linux package.
PolicyKit is an application-level toolkit for defining and handling the policy that allows unprivileged processes to 
speak to privileged processes, in order to grant users the right to perform some tasks in certain situations.
The pkexec file can run another process with higher privileges, the same as sudo.
Due to a missing input check of argv and the fact that there is a Linux mechanism that allows argv to be only
NULL, an overflow can occur allowing reading and writing from unexpected memory regions.
This overflow allows exploits to modify variables so that unprivileged users gain root privileges.
'''
FIXED_VERSION = '0.120'
ROOT_OWNER = '# owner: root'
SUID_FLAG = '# flags: s'
FIXED_APT = {'Ubuntu 21.10': '0.105-31ubuntu0.1', 'Ubuntu 20.04': '0.105-26ubuntu1.2',
             'Ubuntu 18.04': '0.105-20ubuntu0.18.04.6', 'Ubuntu 16.04': '0.105-14.1ubuntu0.5+esm1',
             'Ubuntu 14.04': '0.105-4ubuntu3.14.04.6+esm1', 'Debian 9': '0.105-18+deb9u2',
             'Debian 10': '0.105-25+deb10u1', 'Debian 11': '0.105-31+deb11u1', 'Debian unstable': '0.105-31.1'}
FIXED_RPM = {'Fedora 34': ['0.117', '3.fc34'], 'Fedora 35': ['0.120', '1.fc35'],
             'CentOS 7': ['0.112', '26.el7'], 'CentOS 8': ['0.115', '13.el8'],
             'Red 6': ['0.96', '11.el6'], 'Red 7.3': ['0.112', '12.el7'], 'Red 7.4': ['0.112', '12.el7'],
             'Red 7.6': ['0.112', '18.el7'], 'Red 7': ['0.112', '26.el7'], 'Red 7.7': ['0.112', '22.el7'],
             'Red 8': ['0.115', '13.el8'], 'Red 8.1': ['0.115', '9.el8'], 'Red 8.2': ['0.115', '11.el8'],
             'Red 8.4': ['0.115', '11.el8'], 'Amazon 2': ['0.112', '26.amzn2.1']}
MIN_KERNEL_VERSION = '0'


# This function checks the file requirements in order to be vulnerable.
def check_requirements(execute, suid, root):
    affected = ''
    print(constants.FULL_QUESTION_MESSAGE.format('Does pkexec have execute permissions?'))
    if execute:
        print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
        print(constants.FULL_EXPLANATION_MESSAGE.format('Your pkexec file has execute permissions'))
        print(constants.FULL_QUESTION_MESSAGE.format('Does pkexec have suid bit?'))
        if suid:
            print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
            print(constants.FULL_EXPLANATION_MESSAGE.format('Your pkexec file has suid bit'))
            print(constants.FULL_QUESTION_MESSAGE.format('Is the pkexec binary owner root?'))
            if root:
                affected = 'Yes'
                print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
                print(constants.FULL_EXPLANATION_MESSAGE.format('Your pkexec file is running with root '
                                                                'privileges'))
            else:
                print(constants.FULL_POSITIVE_RESULT_MESSAGE)
                print(constants.FULL_EXPLANATION_MESSAGE.format('Your pkexec file is not running with root '
                                                                'privileges'))
        else:
            print(constants.FULL_POSITIVE_RESULT_MESSAGE)
            print(constants.FULL_EXPLANATION_MESSAGE.format('Your pkexec file does not have suid bit'))
    else:
        print(constants.FULL_POSITIVE_RESULT_MESSAGE)
        print(constants.FULL_EXPLANATION_MESSAGE.format('Your pkexec file does not have execute permissions'))
    return affected


# This function checks file information using ls command.
def check_pkexec_using_ls(pkexec_path, debug, container_name):
    ls_command = f'ls -l {pkexec_path}'
    pipe_ls = run_command.command_output(ls_command, debug, container_name)
    ls = pipe_ls.stdout
    if ls:
        ls_split = ls.split(' ')
        file_permissions = ls_split[0]
        file_owner = ls_split[2]
        root = False
        suid = False
        execute = False
        if file_owner == 'root':
            root = True
        if file_permissions.__contains__('s'):
            suid = True
        if file_permissions.__contains__('x'):
            execute = True
        return check_requirements(execute, suid, root)
    else:
        print(constants.FULL_EXPLANATION_MESSAGE.format('Unsupported ls value'))
        return constants.UNSUPPORTED


# This function checks file information using getfacl command.
def check_pkexec_using_getfacl(pkexec_path, debug, container_name):
    getfacl_command = f'getfacl {pkexec_path}'
    pipe_getfacl = run_command.command_output(getfacl_command, debug, container_name)
    getfacl = pipe_getfacl.stdout
    if getfacl:
        pkexec_info = getfacl.split('\n')
        root = False
        suid = False
        execute = False
        for field in pkexec_info:
            if field == ROOT_OWNER:
                root = True
            elif field.__contains__(SUID_FLAG):
                suid = True
            elif not field.startswith('#') and field.__contains__('::') and field.endswith('x'):
                execute = True
                break
        return check_requirements(execute, suid, root)
    else:
        print(constants.FULL_EXPLANATION_MESSAGE.format('The "getfacl" Linux command is not installed in your system, '
                                                        'the system is about to be validated using the ls command, '
                                                        '(ls command is not 100 percents coverage of pkexec file)'))
        return check_pkexec_using_ls(pkexec_path, debug, container_name)


# This function checks for pkexec existence, suid bit and user permissions.
def get_pkexec_path(debug, container_name):
    which_pkexec_command = 'which pkexec'
    pipe_which_pkexec = run_command.command_output(which_pkexec_command, debug, container_name)
    which_pkexec = pipe_which_pkexec.stdout
    if which_pkexec:
        pkexec_path = which_pkexec.split('\n')[constants.START]
        affected = check_pkexec_using_getfacl(pkexec_path, debug, container_name)
    else:
        print(constants.FULL_EXPLANATION_MESSAGE.format('The "which" Linux command is not working for pkexec, '
                                                        'unsupported value'))
        return constants.UNSUPPORTED
    return affected


# This function checks if the Policy Kit package is affected.
def policykit_affected_rpm(host_information, package_name, debug, container_name):
    distribution = host_information.split(' ')[constants.START]
    host_info = receive_package.package_version_rpm(distribution, package_name, debug, container_name)
    host_version = host_info[constants.START]
    host_release = host_info[constants.FIRST]
    polkit_fixed_version = FIXED_RPM[host_information]
    fixed_version = polkit_fixed_version[constants.START]
    if host_version.endswith('\n'):
        host_version = host_version[:constants.END]
    if version.parse(host_version) > version.parse(fixed_version):
        print(constants.FULL_POSITIVE_RESULT_MESSAGE)
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'Your {package_name} versions which is: '
                                                        f'{host_version}, is bigger than the patched '
                                                        f'version which is: {fixed_version}'))
        return False
    elif version.parse(host_version) == version.parse(fixed_version):
        patched_version = polkit_fixed_version[constants.FIRST]
        return commons.compare_versions(patched_version, host_release, package_name)
    else:
        print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'Your {package_name} versions which is: '
                                                        f'{host_version}, is lower than the patched version'
                                                        f' which is: {fixed_version}'))
        return True


# This function checks if the Policy Kit package is affected.
def policykit_affected_apt(host_information, package_name, debug, container_name):
    distribution = host_information.split(' ')[constants.START]
    host_version = receive_package.package_version_apt(distribution, package_name, debug, container_name)
    polkit_fixed_version = FIXED_APT[host_information]
    return commons.compare_versions(polkit_fixed_version, host_version, package_name)


# This function run policy check according to the package manager.
def check_policykit(host_information, debug, container_name):
    if host_information.split(' ')[constants.START] in constants.APT_DISTRIBUTIONS:
        package_name = 'policykit-1'
        return policykit_affected_apt(host_information, package_name, debug, container_name)
    elif host_information.split(' ')[constants.START] in constants.RPM_DISTRIBUTIONS:
        package_name = 'polkit'
        return policykit_affected_rpm(host_information, package_name, debug, container_name)
    else:
        print(constants.FULL_EXPLANATION_MESSAGE.format(
            f'The distribution value is not one of these distributions: {constants.RPM_DISTRIBUTIONS} or these '
            f'distributions: {constants.APT_DISTRIBUTIONS}'))
        return constants.UNSUPPORTED


# This function checks if the host distribution and version are affected.
def distribution_version_affected(debug, container_name):
    information_fields = ['Distribution', 'Version']
    host_information = os_release.get_field(information_fields, debug, container_name)
    print(constants.FULL_QUESTION_MESSAGE.format('Is os release affected?'))
    if host_information == constants.UNSUPPORTED:
        return constants.UNSUPPORTED
    elif host_information:
        if host_information in FIXED_APT.keys():
            print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
            print(constants.FULL_EXPLANATION_MESSAGE.format(f'Vulnerable os releases: {list(FIXED_APT.keys())} '
                                                            f'{list(FIXED_RPM.keys())}\nYour os release: '
                                                            f'{host_information}\nThe os release you are running on is '
                                                            f'potentially affected'))
            return host_information
        elif host_information in FIXED_RPM.keys():
            print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
            print(constants.FULL_EXPLANATION_MESSAGE.format(f'Vulnerable os releases: {list(FIXED_APT.keys())} '
                                                            f'{list(FIXED_RPM.keys())}\nYour os release: '
                                                            f'{host_information}\nThe os release you are running on is '
                                                            f'potentially affected'))
            return host_information
        elif host_information not in constants.APT_DISTRIBUTIONS and host_information not in constants.RPM_DISTRIBUTIONS:
            print(constants.FULL_NEUTRAL_RESULT_MESSAGE.format('Can not determine'))
            print(constants.FULL_EXPLANATION_MESSAGE.format(f'Vulnerable os releases: {list(FIXED_APT.keys())} '
                                                            f'{list(FIXED_RPM.keys())}\nYour os release: '
                                                            f'{host_information}\nThe os release you are running on is '
                                                            f'not supported'))
            return constants.UNSUPPORTED
        else:
            print(constants.FULL_POSITIVE_RESULT_MESSAGE)
            print(constants.FULL_EXPLANATION_MESSAGE.format(f'Vulnerable os releases: {list(FIXED_APT.keys())} '
                                                            f'{list(FIXED_RPM.keys())}\nYour os release: '
                                                            f'{host_information}\nThe os release you are running on is '
                                                            f'not affected'))
            return ''
    else:
        print(constants.FULL_EXPLANATION_MESSAGE.format('Can not determine os release, unsupported value'))
        return constants.UNSUPPORTED


# This function validates if the host is vulnerable to PwnKit.
def validate(debug, container_name):
    if os_type.linux(debug, container_name):
        host_information = distribution_version_affected(debug, container_name)
        if host_information == constants.UNSUPPORTED:
            print(constants.FULL_NOT_DETERMINED_MESSAGE.format(CVE_ID))
        elif host_information:
            policykit_installed = check_policykit(host_information, debug, container_name)
            if policykit_installed == constants.UNSUPPORTED:
                print(constants.FULL_NOT_DETERMINED_MESSAGE.format(CVE_ID))
            elif policykit_installed:
                pkexec_info = get_pkexec_path(debug, container_name)
                if pkexec_info == constants.UNSUPPORTED:
                    print(constants.FULL_NOT_DETERMINED_MESSAGE.format(CVE_ID))
                elif pkexec_info:
                    print(constants.FULL_VULNERABLE_MESSAGE.format(CVE_ID))
                else:
                    print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(CVE_ID))
            else:
                print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(CVE_ID))
        else:
            print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(CVE_ID))
    else:
        print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(CVE_ID))


# This function creates graph that shows the vulnerability validation process of PwnKit.
def validation_flow_chart():
    vol_graph = graphviz.Digraph('G', filename=CVE_ID)
    commons.graph_start(CVE_ID, vol_graph)
    vol_graph.edge('Is it Linux?', 'Is there an affected PolicyKit package installed?', label='Yes')
    vol_graph.edge('Is it Linux?', 'Not Vulnerable', label='No')
    vol_graph.edge('Is there an affected PolicyKit package installed?', 'Does pkexec have execute permissions?',
                   label='Yes')
    vol_graph.edge('Is there an affected PolicyKit package installed?', 'Not Vulnerable', label='No')
    vol_graph.edge('Does pkexec have execute permissions?', 'Does pkexec have suid bit?', label='Yes')
    vol_graph.edge('Does pkexec have execute permissions?', 'Not Vulnerable', label='No')
    vol_graph.edge('Does pkexec have suid bit?', 'Is pkexec binary owner root?', label='Yes')
    vol_graph.edge('Does pkexec have suid bit?', 'Not Vulnerable', label='No')
    vol_graph.edge('Is pkexec binary owner root?', 'Vulnerable', label='Yes')
    vol_graph.edge('Is pkexec binary owner root?', 'Not Vulnerable', label='No')
    commons.graph_end(vol_graph)


def main(describe, graph, debug, container_name):
    if describe:
        print(f'\n{DESCRIPTION}')
    validate(debug, container_name)
    if graph:
        validation_flow_chart()


if __name__ == '__main__':
    main()
