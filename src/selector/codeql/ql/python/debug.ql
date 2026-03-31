import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.Concepts

module TestConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof DataFlow::ParameterNode }
  predicate isSink(DataFlow::Node n) {
    n = any(SqlExecution e).getSql()
    or n = any(SystemCommandExecution e).getCommand()
    or n = any(FileSystemAccess e).getAPathArgument()
    or n = any(CodeExecution e).getCode()
  }
}
module TestFlow = TaintTracking::Global<TestConfig>;

from DataFlow::Node source, DataFlow::Node sink
where TestFlow::flow(source, sink)
select source, source.getLocation().getFile().getAbsolutePath(), source.getLocation().getStartLine(),
       sink, sink.getLocation().getFile().getAbsolutePath(), sink.getLocation().getStartLine()
