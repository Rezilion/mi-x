"""
Support for graphviz and other modules written to avoid repetitive code.
"""
import graphviz
from modules import constants


def generate_graph(vulnerability):
    """Graphviz start function."""
    vulnerability_graph = graphviz.Digraph('G', filename=vulnerability, format='png')
    vulnerability_graph.attr(label=f'{vulnerability}\n\n', labelloc='t')
    vulnerability_graph.attr('node', shape='box', style='filled', color='red')
    vulnerability_graph.node(constants.GRAPH_VULNERABLE)
    vulnerability_graph.attr('node', shape='box', style='filled', color='green')
    vulnerability_graph.node(constants.GRAPH_NOT_VULNERABLE)
    vulnerability_graph.attr('node', shape='box', color='lightgrey')
    return vulnerability_graph
