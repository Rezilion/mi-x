"""
Support for os, importlib, argparse and other modules which written for avoiding repetitive code.
"""
import os
import importlib
import argparse
from Modules import constants, run_command

MENU_MESSAGE = '''The 'Am I Really Vulnerable?' CVEs database:
Remote Code Execution (RCE):
Ghost - CVE-2015-0235
CVE-2021-3711
CVE-2021-41773
CVE-2021-42013
Spring4Shell - CVE-2022-22965
Log4Shell - CVE-2021-44228, CVE-2021-45046, CVE-2021-4104, CVE-2021-45105, CVE-2021-44832, CVE-2021-42013
ShellShock - CVE-2014-6271, CVE-2014-6277, CVE-2014-6278, CVE-2014-7169, CVE-2014-7186, CVE-2014-7187

Privilege Escalation (PLE):
Dirty_COW - CVE-2016-5195
Huge_Dirty_COW - CVE-2017-1000405
PWNKIT - CVE-20214034
Dirty_Pipe - CVE-2022-0847
CVE-2022-25636
NimbusPWN - CVE-2022-29799, CVE-2022-29800
Meltdown - CVE-2017-5754

Run options:
all - runs checks for all the CVEs in the database
CVE-YYYY-XXXX - run specific vulnerability check by inserting its CVE id 
name - run specific vulnerability check by inserting its name (for example - Log4Shell)
'''
ALL = 'all'


def run_cve_check(cve_id, describe, graph, debug, container_name):
    """This function run the cve file that matches the entered vulnerability name."""
    cve_path = f'CVEs.{cve_id}'
    cve_validation = importlib.import_module(cve_path)
    cve_validation.main(describe, graph, debug, container_name)


def run(cve_id, describe, graph, debug, container_name):
    """This function checks if the cve_id that received has a file with its name."""
    cve_dir_path = f"{os.getcwd()}/CVEs"
    cve_validation_files = os.listdir(cve_dir_path)
    cves_files = [f.split('.')[constants.START] for f in cve_validation_files]
    if cve_id in cves_files:
        run_cve_check(cve_id, describe, graph, debug, container_name)
    else:
        print(constants.FULL_EXPLANATION_MESSAGE.format('Vulnerability name does not match the CVEs files'))


def fix_cve_format(cve_id):
    """This function fixes the cve format so all cases will be included."""
    cve_id = cve_id.lower()
    if cve_id.startswith('cve') and '-' in cve_id:
        cve_id = cve_id.replace('-', '_')
    return cve_id


def checks_cve_id_parameter(cve_id, describe, debug, graph, container_name):
    """This function run the next function according to the cve_id parameter."""
    fixed_cve = fix_cve_format(cve_id)
    if fixed_cve == ALL:
        for vulnerability in constants.ALL_VULNERABILITIES:
            run(vulnerability, describe, graph, debug, container_name)
    elif fixed_cve in constants.ALL_VULNERABILITIES:
        run(fixed_cve, describe, graph, debug, container_name)
    elif fixed_cve in constants.DUPLICATE_VULNERABILITIES_NAMES:
        run(constants.DUPLICATE_VULNERABILITIES_NAMES[fixed_cve], describe, graph, debug, container_name)
    elif fixed_cve == 'spectre':
        for spectre_cve in constants.SPECTRE:
            run(spectre_cve, describe, graph, debug, container_name)
    elif not cve_id:
        print(constants.FULL_EXPLANATION_MESSAGE.format(MENU_MESSAGE))
        print(constants.FULL_EXPLANATION_MESSAGE.format('Enter one of the running options in order to be scanned'))
    else:
        print(constants.FULL_EXPLANATION_MESSAGE.format('The vulnerability name does not exists in the database'))


def check_dependencies(graph):
    """This function checks if the dependencies can run successfully."""
    if graph:
        try:
            import graphviz
        except NameError:
            print(constants.FULL_EXPLANATION_MESSAGE.format(constants.NOT_INSTALLED_MESSAGE.format('Graphviz',
                                                                                                   'Graphviz')))
    try:
        import semver
    except ModuleNotFoundError:
        print(constants.FULL_EXPLANATION_MESSAGE.format(constants.NOT_INSTALLED_MESSAGE.format('Semver', 'Semver')))
    try:
        from packaging import version
    except ModuleNotFoundError:
        print(constants.FULL_EXPLANATION_MESSAGE.format(constants.NOT_INSTALLED_MESSAGE.format('Packaging',
                                                                                               'Packaging')))


def arguments():
    """This function sets the arguments."""
    parser = argparse.ArgumentParser(description="'AM I Really Vulnerable?' is a service that let's you validate "
                                                 "whether or not your system is susceptible to a given CVE")
    parser.add_argument('--cve_id', type=str, default='', help='Enter CVE name according to the following format:'
                                                               'cve_<YEAR>_<NUMBER> '
                                                               'Otherwise, all CVEs will be checked')
    parser.add_argument('--describe', type=bool, default=True, help='A description of the vulnerability '
                                                                    '(True by default)')
    parser.add_argument('--graph', type=bool, default=False, help='Graph which presents the security checks of the '
                                                                  'vulnerability')
    parser.add_argument('--debug', type=bool, default=False, help='An option to debug the program and see errors')
    parser.add_argument('--container', type=bool, default=False, help='Specify if you run in container or not')
    return parser.parse_args()


def main():
    """This is the main function."""
    args = arguments()
    check_dependencies(args.graph)
    if args.container:
        container_names = []
        docker_ps_command = 'sudo docker ps -f status=running'
        pipe_docker_ps = run_command.command_output(docker_ps_command, args.debug, container_name=False)
        docker_ps = pipe_docker_ps.stdout
        if docker_ps:
            for field in docker_ps.split('\n')[constants.FIRST:constants.END]:
                container_names.append(field.split(' ')[constants.END])
            for container_name in container_names:
                print(f'\nScanning vulnerabilities on {container_name} container')
                checks_cve_id_parameter(args.cve_id, args.describe, args.debug, args.graph, container_name)
        else:
            print(constants.FULL_EXPLANATION_MESSAGE.format('Docker containers where not found, unsupported value'))
    else:
        checks_cve_id_parameter(args.cve_id, args.describe, args.debug, args.graph, container_name='')


if __name__ == '__main__':
    print("Welcome to Rezilion's 'Am I Really Vulnerable?' Service")
    main()
