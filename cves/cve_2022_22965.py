"""
Support for graphviz and other modules which written for avoiding repetitive code.
"""
import graphviz
from modules import run_command, get_pids, commons, constants

CVE_ID = 'CVE-2022-22965'
DESCRIPTION = f'''{CVE_ID} - Spring4Shell

CVSS Score: 9.8
NVD Link: https://nvd.nist.gov/vuln/detail/CVE-2022-22965
 
A zero-day Remote Code Execution (RCE) vulnerability caused by an error in the mechanism which uses 
client-provided data to update the properties of an object in the Spring MVC or Spring WebFlux application. 
The vulnerability can be exploited remotely only if a Spring application is deployed as a WAR on the Apache Tomcat 
server and run on JDK 9 and higher.
'''
MIN_AFFECTED_VERSION = 9
CLASSES = {'org.springframework.web.servlet.mvc.method.annotation.ServletModelAttributeMethodProcessor': 'webmvc',
           'org.springframework.web.reactive.result.method.annotation.ModelAttributeMethodArgumentResolver': 'webflux'}
VM_VERSION = '"VM.version"'
PATCHED_VERSIONS = ['8.5.78', '9.0.62', '10.0.20']


def check_tomcat(debug, container_name):
    """This function checks if the system runs affected tomcat version."""
    print(constants.FULL_QUESTION_MESSAGE.format('Is it Tomcat?'))
    tomcat_version_command = 'version.sh'
    pipe_tomcat_version = run_command.command_output(tomcat_version_command, debug, container_name)
    tomcat_version_output = pipe_tomcat_version.stdout
    if tomcat_version_output.endswith(' not found\n'):
        print(constants.FULL_NEUTRAL_RESULT_MESSAGE.format('No'))
        return False
    print(constants.FULL_NEUTRAL_RESULT_MESSAGE.format('Yes'))
    tomcat_version = ''
    for field in tomcat_version_output.split('\n'):
        if field.startswith('Server version: '):
            tomcat_version = field.split('/')[constants.END]
    if not tomcat_version:
        return constants.UNSUPPORTED
    return commons.check_patched_version('Tomcat', tomcat_version, PATCHED_VERSIONS)


def check_java_version(pid, jcmd_command, debug):
    """This function checks the process`s java version."""
    pipe_jcmd = run_command.command_output(jcmd_command, debug, container_name=False)
    jcmd = pipe_jcmd.stdout
    print(constants.FULL_QUESTION_MESSAGE.format(f'Is the following process: {pid} java version affected?'))
    if not jcmd:
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'Unsupported {VM_VERSION} value'))
        return constants.UNSUPPORTED
    version = jcmd.split('\n')[2].split(' ')[constants.END]
    start_of_version = int(version.split('.')[constants.START])
    if start_of_version < MIN_AFFECTED_VERSION:
        print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'The minimum affected java version is: '
                                                        f'{MIN_AFFECTED_VERSION}, the process`s java version which is: '
                                                        f'{version}, is not affected'))
        return False
    print(constants.FULL_POSITIVE_RESULT_MESSAGE)
    print(constants.FULL_EXPLANATION_MESSAGE.format(f'The minimum affected java version is: {MIN_AFFECTED_VERSION}, the'
                                                    f'process`s java version which is: {version}, is affected'))
    return True


def validate_processes(pids, debug, container_name):
    """This function loops over all java processes and checks if they are vulnerable."""
    for pid in pids:
        if container_name:
            jcmd_path = commons.get_jcmd(pid, debug, container_name)
        else:
            jcmd_path = 'jcmd'
        if jcmd_path == constants.UNSUPPORTED:
            print(constants.FULL_PROCESS_NOT_DETERMINED_MESSAGE.format(CVE_ID, pid))
        jcmd_command = f'sudo {jcmd_path} {pid} {VM_VERSION}'
        version_affected = check_java_version(pid, jcmd_command, debug)
        if not version_affected == constants.UNSUPPORTED:
            if not version_affected:
                print(constants.FULL_PROCESS_NOT_VULNERABLE_MESSAGE.format(pid, CVE_ID))
            jcmd_command = f'sudo {jcmd_path} {pid} '
            utility = commons.available_jcmd_utilities(jcmd_command, debug, container_name)
            if utility:
                full_jcmd_command = jcmd_command + utility
                webmvc_webflux = commons.check_loaded_classes(pid, full_jcmd_command, CLASSES, debug)
                if webmvc_webflux == constants.UNSUPPORTED:
                    print(constants.FULL_PROCESS_NOT_DETERMINED_MESSAGE.format(CVE_ID, pid))
                elif webmvc_webflux:
                    print(constants.FULL_EXPLANATION_MESSAGE.format(f'The {pid} process use the {webmvc_webflux} '
                                                                    f'dependency'))
                    print(constants.FULL_PROCESS_VULNERABLE_MESSAGE.format(pid, CVE_ID))
                else:
                    print(constants.FULL_PROCESS_NOT_VULNERABLE_MESSAGE.format(pid, CVE_ID))
            else:
                print(constants.FULL_PROCESS_NOT_DETERMINED_MESSAGE.format(CVE_ID, pid))
        else:
            print(constants.FULL_PROCESS_NOT_DETERMINED_MESSAGE.format(CVE_ID, pid))


def validate(debug, container_name):
    """This function validates if the instance is vulnerable to Spring4Shell."""
    if commons.check_linux_and_affected_distribution(CVE_ID, debug, container_name):
        pids = get_pids.pids_consolidation('java', debug, container_name)
        if pids:
            validate_processes(pids, debug, container_name)
        else:
            print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(CVE_ID))


def validation_flow_chart():
    """This function creates a graph that shows the vulnerability validation process of Spring4Shell."""
    vol_graph = graphviz.Digraph('G', filename=CVE_ID)
    commons.graph_start(CVE_ID, vol_graph)
    vol_graph.edge('Is it Linux?', 'Are there running Java processes?', label='Yes')
    vol_graph.edge('Is it Linux?', 'Not Vulnerable', label='No')
    vol_graph.edge('Are there running Java processes?', 'Is java version affected?', label='Yes')
    vol_graph.edge('Are there running Java processes?', 'Not Vulnerable', label='No')
    vol_graph.edge('Is java version affected?', 'Does the process use webmvc or webflux dependencies?', label='Yes')
    vol_graph.edge('Is java version affected?', 'Not Vulnerable', label='No')
    vol_graph.edge('Does the process use webmvc or webflux dependencies?', 'Vulnerable', label='Yes')
    vol_graph.edge('Does the process use webmvc or webflux dependencies?', 'Not Vulnerable', label='No')
    commons.graph_end(vol_graph)


def main(describe, graph, debug, container_name):
    """This is the main function."""
    if describe:
        print(f'\n{DESCRIPTION}')
    validate(debug, container_name)
    if graph:
        validation_flow_chart()
