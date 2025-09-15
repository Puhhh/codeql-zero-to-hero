/**
 * @name getAQlClass on Gradio Button input source
 * @description This query reports on a code element's types.
 * @id 5/2
 * @severity error
 * @kind problem
 */
import python
import semmle.python.ApiGraphs
import semmle.python.Concepts
import semmle.python.dataflow.new.RemoteFlowSources



from DataFlow::Node node
where node = API::moduleImport("gradio").getMember("Button").getReturn()
        .getMember("click").getACall().getParameter(0, "fn").getParameter(_).asSource()
select node, node.getAQlClass()
