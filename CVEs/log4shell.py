from Modules import os_type, get_pids, commons, constants
import graphviz

CVE_ID = 'Log4Shell'
DESCRIPTION = f'''your system will be scanned for all Log4Shell related CVEs. 

{CVE_ID}
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
'''
CLASS_CVE = {'org.apache.logging.log4j.core.lookup.JndiLookup': 'CVE-2021-44228 and CVE-2021-45046',
             'org.apache.log4j.net.JMSAppender': 'CVE-2021-4104',
             'org.apache.logging.log4j.core.lookup.ContextMapLookup': 'CVE-2021-45105',
             'org.apache.logging.log4j.core.appender.db.jdbc.JdbcAppender': 'CVE-2021-44832'}
VM_CLASS_HIERARCHY = 'VM.class_hierarchy'


# This function loops over all java processes and checks if they are vulnerable.
def validate_processes(pids, debug, container_name):
    for pid in pids:
        if container_name:
            jcmd_path = commons.get_jcmd(pid, debug, container_name)
        else:
            jcmd_path = 'jcmd'
        if not jcmd_path == constants.UNSUPPORTED:
            jcmd_command = f'sudo {jcmd_path} {pid} "{VM_CLASS_HIERARCHY}"'
            cves = commons.check_loaded_classes(pid, jcmd_command, CLASS_CVE, debug)
            if cves == constants.UNSUPPORTED:
                print('hello')
            elif cves:
                print(constants.FULL_PROCESS_VULNERABLE_MESSAGE.format(pid, cves))
            else:
                print(constants.FULL_PROCESS_NOT_VULNERABLE_MESSAGE.format(pid, CVE_ID))
        else:
            print(constants.FULL_PROCESS_NOT_DETERMINED_MESSAGE.format(CVE_ID, pid))


# This function validates if an instance is vulnerable to Log4Shell.
def validate(debug, container_name):
    if os_type.linux(debug, container_name):
        pids = get_pids.pids_consolidation('java', debug, container_name)
        if pids:
            validate_processes(pids, debug, container_name)
        else:
            print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(CVE_ID))
    else:
        print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(CVE_ID))


# This function creates graph that shows the vulnerability validation process of Log4Shell.
def validation_flow_chart():
    vol_graph = graphviz.Digraph('G', filename=CVE_ID)
    commons.graph_start(CVE_ID, vol_graph)
    vol_graph.edge('Is it Linux?', 'Are there running Java processes?', label='Yes')
    vol_graph.edge('Is it Linux?', 'Not Vulnerable', label='No')
    vol_graph.edge('Are there running Java processes?', 'Are the vulnerable classes loaded?', label='Yes')
    vol_graph.edge('Are there running Java processes?', 'Not Vulnerable', label='No')
    vol_graph.edge('Are the vulnerable classes loaded?', 'Vulnerable', label='Yes')
    vol_graph.edge('Are the vulnerable classes loaded?', 'Not Vulnerable', label='No')
    commons.graph_end(vol_graph)


def main(describe, graph, debug, container_name):
    if describe:
        print(f'\n{DESCRIPTION}')
    validate(debug, container_name)
    if graph:
        validation_flow_chart()


if __name__ == '__main__':
    main()
