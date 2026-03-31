/**
 * @name Vuljector: taint paths to dangerous sinks (Python)
 * @description Finds external input sources that reach dangerous operation sinks.
 *              Used by Vuljector to identify checkpoint × operation injection candidates.
 * @id vuljector/python/pairs
 * @tags security vuljector
 */

// NOTE: DataFlow must be imported explicitly — TaintTracking alone does not bring
// DataFlow into scope. See vuljector_lib.qll for sink/checkpoint predicates.
import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.dataflow.new.RemoteFlowSources
import vuljector_lib

// ── Taint configuration ───────────────────────────────────────────────────────

module VuljectorConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // HTTP/remote sources (application code)
    source instanceof RemoteFlowSource
    or
    // Library API boundary: any function parameter may receive untrusted data
    source instanceof DataFlow::ParameterNode
  }
  predicate isSink(DataFlow::Node sink) {
    vuljectorSink(sink, _)
  }
}

module VuljectorFlow = TaintTracking::Global<VuljectorConfig>;

// ── Main query ────────────────────────────────────────────────────────────────

from DataFlow::Node source, DataFlow::Node sink, string sinkKind
where
  VuljectorFlow::flow(source, sink) and
  vuljectorSink(sink, sinkKind)
select
  sink.getLocation(),                                          // 1  sink_url
  sink.getLocation().getFile().getAbsolutePath(),              // 2  sink_file
  sink.getLocation().getStartLine(),                           // 3  sink_line
  sink.getEnclosingCallable().toString(),                      // 4  sink_function
  sink.toString(),                                             // 5  sink_text
  sinkKind,                                                    // 6  sink_kind
  source.getLocation(),                                        // 7  source_url
  source.getLocation().getFile().getAbsolutePath(),            // 8  source_file
  source.getLocation().getStartLine(),                         // 9  source_line
  sink.getLocation().getFile().getAbsolutePath(),              // 10 cp_url
  sink.getLocation().getFile().getAbsolutePath(),              // 11 cp_file
  0,                                                           // 12 cp_line
  cpText(sink),                                                // 13 cp_text
  cpKind(sink),                                                // 14 cp_kind
  1,                                                           // 15 path_length
  "vuljector/python/pairs"                                     // 16 query_id
