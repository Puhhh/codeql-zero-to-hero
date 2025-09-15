/**
 * @name Gradio unsafe deserialization
 * @description This query tracks data flow from inputs passed to a Gradio's Button component to any sink.
 * @kind path-problem
 * @problem.severity warning
 * @id 5/1
 */
import python
import semmle.python.ApiGraphs
import semmle.python.Concepts
import semmle.python.dataflow.new.RemoteFlowSources
import semmle.python.dataflow.new.TaintTracking

import MyFlow::PathGraph

class GradioButton extends RemoteFlowSource::Range {
    GradioButton() {
        exists(API::CallNode n |
        n = API::moduleImport("gradio").getMember("Button").getReturn()
        .getMember("click").getACall() |
        this = n.getParameter(0, "fn").getParameter(_).asSource())
    }

    override string getSourceType() { result = "Gradio untrusted input" }
}

private module MyConfig implements DataFlow::ConfigSig {
    predicate isSource(DataFlow::Node source) { source instanceof GradioButton }

    predicate isSink(DataFlow::Node sink) { exists(Decoding d | sink = d) }
}
module MyFlow = TaintTracking::Global<MyConfig>;

from MyFlow::PathNode source, MyFlow::PathNode sink
where MyFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Data Flow from a Gradio source to decoding"
