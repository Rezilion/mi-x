"""
Support for graphviz and other modules which written for avoiding repetitive code.
"""
import graphviz
from packaging import version
from modules import constants, graph_functions, status, run_command, process_functions, java_functions

VULNERABILITY = 'CVE-2022-22965'
DESCRIPTION = f'''{VULNERABILITY} - Spring4Shell

CVSS Score: 9.8
NVD Link: https://nvd.nist.gov/vuln/detail/CVE-2022-22965
 
A zero-day Remote Code Execution (RCE) vulnerability caused by an error in the mechanism which uses 
client-provided data to update the properties of an object in the Spring MVC or Spring WebFlux application. 
The vulnerability can be exploited remotely only if a Spring application is deployed as a WAR on the Apache Tomcat 
server and run on JDK 9 and higher.

Related Links:
https://www.rezilion.com/blog/spring4shell-what-you-need-to-know/
https://securitylabs.datadoghq.com/articles/spring4shell-vulnerability-overview-and-remediation/
https://www.upguard.com/blog/what-is-spring4shell
'''
MIN_AFFECTED_JAVA_VERSION = '9'
CLASSES = {'org.springframework.web.servlet.mvc.method.annotation.ServletModelAttributeMethodProcessor': 'webmvc',
           'org.springframework.web.reactive.result.method.annotation.ModelAttributeMethodArgumentResolver': 'webflux'}
VM_VERSION = '"VM.version"'
REMEDIATION = 'Upgrade to the following patch releases:\n- Spring 5.3.x users upgrade to 5.3.18 or higher\n- Spring ' \
              '5.2.x users upgrade to 5.2.20 or higher\n- Spring Boot 2.6.x users upgrade to 2.6.6 or higher\n- Spring' \
              ' Boot 2.5.x users upgrade to 2.5.12 or higher\n- Tomcat 10.0.x users upgrade to 10.0.20 or higher\n- ' \
              'Tomcat 9.0.x users upgrade to 9.0.62 or higher\n- Tomcat 8.5.x users upgrade to 8.5.78 or higher'
MITIGATION = ''


def check_java_version(pid, jcmd_command, debug):
    """This function checks the process`s java version."""
    pipe_jcmd = run_command.command_output(jcmd_command, debug, container_name='')
    jcmd = pipe_jcmd.stdout
    print(constants.FULL_QUESTION_MESSAGE.format(f'Is the java version of the following {pid} process affected?'))
    if not jcmd:
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'Unsupported {VM_VERSION} value'))
        return constants.UNSUPPORTED
    java_version = jcmd.split('\n')[2].split(' ')[constants.END]
    start_of_version = str(java_version.split('.')[constants.START])
    if version.parse(start_of_version) < version.parse(MIN_AFFECTED_JAVA_VERSION):
        print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'The minimum affected java version is: '
                                                        f'{MIN_AFFECTED_JAVA_VERSION}, the process`s java version which'
                                                        f' is: {java_version}, is not affected'))
        return False
    print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('Yes'))
    print(constants.FULL_EXPLANATION_MESSAGE.format(f'The minimum affected java version is: {MIN_AFFECTED_JAVA_VERSION}'
                                                    f', the process`s java version which is: {version}, is affected'))
    return True


def validate_processes(pids, debug, container_name):
    """This function loops over all java processes and checks if they are vulnerable."""
    state = {}
    for pid in pids:
        jcmd_path = 'jcmd'
        if container_name:
            jcmd_path = java_functions.build_jcmd_path(pid, debug, container_name)
            if jcmd_path == constants.UNSUPPORTED:
                state[pid] = status.process_not_determined(pid, VULNERABILITY)
                break
        jcmd_command = f'sudo {jcmd_path} {pid} {VM_VERSION}'
        version_affected = check_java_version(pid, jcmd_command, debug)
        if version_affected == constants.UNSUPPORTED:
            state[pid] = status.process_not_determined(pid, VULNERABILITY)
            break
        if not version_affected:
            state[pid] = status.process_not_vulnerable(pid, VULNERABILITY)
            break
        jcmd_command = f'sudo {jcmd_path} {pid} '
        utility = java_functions.available_jcmd_utilities(jcmd_command, debug)
        if utility:
            full_jcmd_command = jcmd_command + utility
            webmvc_webflux = java_functions.check_loaded_classes(pid, full_jcmd_command, CLASSES, debug)
            if webmvc_webflux == constants.UNSUPPORTED:
                state[pid] = status.process_not_determined(pid, VULNERABILITY)
            elif webmvc_webflux:
                print(constants.FULL_EXPLANATION_MESSAGE.format(f'The {pid} process use the {webmvc_webflux} '
                                                                f'dependency'))
                state[pid] = status.process_vulnerable(pid, VULNERABILITY)
                status.remediation_mitigation(REMEDIATION, MITIGATION)
            else:
                state[pid] = status.process_not_vulnerable(pid, VULNERABILITY)
        else:
            state[pid] = status.process_not_determined(pid, VULNERABILITY)
    return state


def validate(debug, container_name):
    """This function validates if an instance is vulnerable to Log4Shell."""
    state = {}
    pids = process_functions.pids_consolidation('java', debug, container_name)
    if pids:
        state[VULNERABILITY] = validate_processes(pids, debug, container_name)
    else:
        state[VULNERABILITY] = status.not_vulnerable(VULNERABILITY)
    return state


def validation_flow_chart():
    """This function creates a graph that shows the vulnerability validation process of Spring4Shell."""
    vol_graph = graphviz.Digraph('G', filename=VULNERABILITY, format='png')
    graph_functions.graph_start(VULNERABILITY, vol_graph)
    vol_graph.edge('Is it Linux?', 'Are there running Java processes?', label='Yes')
    vol_graph.edge('Is it Linux?', 'Not Vulnerable', label='No')
    vol_graph.edge('Are there running Java processes?', 'Is java version affected?', label='Yes')
    vol_graph.edge('Are there running Java processes?', 'Not Vulnerable', label='No')
    vol_graph.edge('Is java version affected?', 'Does the process use webmvc or webflux dependencies?', label='Yes')
    vol_graph.edge('Is java version affected?', 'Not Vulnerable', label='No')
    vol_graph.edge('Does the process use webmvc or webflux dependencies?', 'Vulnerable', label='Yes')
    vol_graph.edge('Does the process use webmvc or webflux dependencies?', 'Not Vulnerable', label='No')
    graph_functions.graph_end(vol_graph)


def main(description, graph, debug, container_name):
    """This is the main function."""
    if description:
        print(f'\n{DESCRIPTION}')
    state = validate(debug, container_name)
    if graph:
        validation_flow_chart()
    return state
