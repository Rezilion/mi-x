"""
Support for modules written to avoid repetitive code.
"""
from modules import constants, graph_functions, status_functions, process_functions, java_functions

VULNERABILITY = 'Log4Shell'
DESCRIPTION = f'''your system will be scanned for all Log4Shell related CVEs.

{VULNERABILITY}
Remote code execution (RCE) vulnerability affecting Apache’s Log4j library, versions 2.0-beta9 to 2.17.0.
This vulnerability is consists of the following CVEs:

CVE-2021-44228

CVSS Score: 10.0
NVD Link: https://nvd.nist.gov/vuln/detail/CVE-2021-44228

AKA Log4Shell. In Apache Log4j2 versions up to and including 2.14.1, an attacker who can control log
messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution
is enabled.

CVE-2021-45046

CVSS Score: 9.0
NVD Link: https://nvd.nist.gov/vuln/detail/CVE-2021-45046

It was found that the fix addressing CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain
non-default configurations, resulting in an information leak, remote code execution and local code execution.

CVE-2021-4104

CVSS Score: 7.5
NVD Link: https://nvd.nist.gov/vuln/detail/CVE-2021-4104

JMSAppender in Log4j 1.2 is vulnerable to deserialization of untrusted data when the attacker has write
access to the Log4j configuration.

CVE-2021-45105

CVSS Score: 5.9
NVD Link: https://nvd.nist.gov/vuln/detail/CVE-2021-45105

Apache Log4j2 versions 2.0-alpha1 through 2.16.0 (excluding 2.12.3 and 2.3.1) did not protect from
uncontrolled recursion from self-referential lookups. When the logging configuration uses a non-default Pattern Layout
with a Context Lookup, an attacker with control over Thread Context Map data can cause a denial of service.

CVE-2021-44832

CVSS Score: 6.6
NVD Link: https://nvd.nist.gov/vuln/detail/CVE-2021-44832

Apache Log4j2 versions 2.0-beta7 through 2.17.0 (excluding security fix releases 2.3.2 and 2.12.4), are
vulnerable to a remote code execution (RCE) attack where an attacker with permission to modify the logging configuration
file can construct a malicious configuration using a JDBC Appender with a data source referencing a JNDI URI which can
execute remote code.

Related Links:
https://www.rezilion.com/blog/log4shell-vulnerability-cve-2021-44228-should-you-worry/
https://logging.apache.org/log4j/2.x/security.html
https://www.rezilion.com/blog/months-later-are-you-still-vulnerable-to-log4shell/
https://nakedsecurity.sophos.com/2021/12/13/log4shell-explained-how-it-works-why-you-need-to-know-and-how-to-fix-it/
'''
CLASS_CVE = {'org.apache.logging.log4j.core.lookup.JndiLookup': 'CVE-2021-44228 and CVE-2021-45046',
             'org.apache.log4j.net.JMSAppender': 'CVE-2021-4104',
             'org.apache.logging.log4j.core.lookup.ContextMapLookup': 'CVE-2021-45105',
             'org.apache.logging.log4j.core.appender.db.jdbc.JdbcAppender': 'CVE-2021-44832'}
JDK_MINIMUM_VERSION = '10.0.0'
REMEDIATION = 'Upgrade Apache log4j to 2.17.0'
MITIGATION = 'Remove the affected classes: JndiLookup, JMSAppender, ContextMapLookup, JdbcAppender'


def validate_processes(pids, debug, container_name):
    """This function loops over all java processes and checks if they are vulnerable."""
    state = {}
    for pid in pids:
        jcmd_path = 'jcmd'
        if container_name:
            jcmd_path = java_functions.build_jcmd_path(pid, debug, container_name)
            if jcmd_path == constants.UNSUPPORTED:
                state[pid] = status_functions.process_not_determined(pid, VULNERABILITY)
                break
        jcmd_command = f'sudo {jcmd_path} {pid} '
        utility = java_functions.available_jcmd_utilities(jcmd_command, debug)
        if utility:
            full_jcmd_command = jcmd_command + utility
            cves = java_functions.check_loaded_classes(pid, full_jcmd_command, CLASS_CVE, debug)
            if cves == constants.UNSUPPORTED:
                state[pid] = status_functions.process_not_determined(pid, VULNERABILITY)
            elif cves:
                state[pid] = status_functions.process_vulnerable(pid, f'{VULNERABILITY} - {cves}')
                status_functions.remediation_mitigation(REMEDIATION, MITIGATION)
            else:
                state[pid] = status_functions.process_not_vulnerable(pid, VULNERABILITY)
        else:
            state[pid] = status_functions.process_not_determined(pid, VULNERABILITY)
    return state


def validate(debug, container_name):
    """This function validates if an instance is vulnerable to Log4Shell."""
    state = {}
    pids = process_functions.pids_consolidation('java', debug, container_name)
    if pids:
        state[VULNERABILITY] = validate_processes(pids, debug, container_name)
    else:
        state[VULNERABILITY] = status_functions.not_vulnerable(VULNERABILITY)
    return state


def validation_flow_chart():
    """This function creates graph that shows the vulnerability validation process of Log4Shell."""
    vulnerability_graph = graph_functions.generate_graph(VULNERABILITY)
    vulnerability_graph.edge('Is it Linux?', 'Are there running Java processes?', label='Yes')
    vulnerability_graph.edge('Is it Linux?', 'Not Vulnerable', label='No')
    vulnerability_graph.edge('Are there running Java processes?', 'Are the vulnerable classes loaded?', label='Yes')
    vulnerability_graph.edge('Are there running Java processes?', 'Not Vulnerable', label='No')
    vulnerability_graph.edge('Are the vulnerable classes loaded?', 'Vulnerable', label='Yes')
    vulnerability_graph.edge('Are the vulnerable classes loaded?', 'Not Vulnerable', label='No')
    vulnerability_graph.view()


def main(description, graph, debug, container_name):
    """This is the main function."""
    if description:
        print(f'\n{DESCRIPTION}')
    state = validate(debug, container_name)
    if graph:
        validation_flow_chart()
    return state
