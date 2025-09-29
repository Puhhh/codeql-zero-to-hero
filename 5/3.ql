/**
 * @name Gradio Button partial path graph
 * @description This query tracks data flow from inputs passed to a Gradio's Button component to any sink.
 * @kind path-problem
 * @problem.severity warning
 * @id 5/3
 */

import python
import semmle.python.ApiGraphs
import semmle.python.Concepts
import semmle.python.dataflow.new.RemoteFlowSources
import semmle.python.dataflow.new.TaintTracking

// import MyFlow::PathGraph
import PartialFlow::PartialPathGraph

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

    predicate isSink(DataFlow::Node sink) { exists(Decoding d | d.mayExecuteInput() | sink = d.getAnInput()) }

}


module MyFlow = TaintTracking::Global<MyConfig>;
int explorationLimit() { result = 10 }
module PartialFlow = MyFlow::FlowExplorationFwd<explorationLimit/0>;

from PartialFlow::PartialPathNode source, PartialFlow::PartialPathNode sink
where PartialFlow::partialFlow(source, sink, _)
select sink.getNode(), source, sink, "Partial Graph $@.", source.getNode(), "user-provided value."
