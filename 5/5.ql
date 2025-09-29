/**
 * @name Gradio File Input Flow
 * @description This query tracks data flow from Gradio's Button component to a Decoding sink.
 * @kind path-problem
 * @problem.severity warning
 * @id 5/5
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
predicate nameAttrRead(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    // Connects an attribute read of an object's `name` attribute to the object itself
    exists(DataFlow::AttrRead attr |
      attr.accesses(nodeFrom, "name")
      and nodeTo = attr
    )
}

predicate osOpenStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    // Connects the argument to `open()` to the result of `open()`
    // And argument to `os.open()` to the result of `os.open()`
    exists(API::CallNode call |
        call = API::moduleImport("os").getMember("open").getACall() and
        nodeFrom = call.getArg(0) and
        nodeTo = call)
    or
    exists(API::CallNode call |
        call = API::builtin("open").getACall() and
        nodeFrom = call.getArg(0) and
        nodeTo = call)
}

private module MyConfig implements DataFlow::ConfigSig {
    predicate isSource(DataFlow::Node source) { source instanceof GradioButton }

    predicate isSink(DataFlow::Node sink) {
        exists(Decoding d | d.mayExecuteInput() | sink = d.getAnInput()) }

    predicate isAdditionalFlowStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
        nameAttrRead(nodeFrom, nodeTo)
        or
        osOpenStep(nodeFrom, nodeTo)
        }
}
module MyFlow = TaintTracking::Global<MyConfig>;

from MyFlow::PathNode source, MyFlow::PathNode sink
where MyFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Data Flow from a Gradio source to decoding"
