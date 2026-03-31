/**
 * @name Vuljector: taint paths to dangerous sinks (C/C++)
 * @description Finds external input sources that reach dangerous memory/system sinks.
 *              Used by Vuljector to identify checkpoint × operation injection candidates.
 * @id vuljector/cpp/pairs
 * @tags security vuljector
 */

import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.dataflow.new.TaintTracking
import semmle.code.cpp.security.FlowSources
import vuljector_lib

// ── Taint configuration ───────────────────────────────────────────────────────

module VuljectorConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // Network/system sources
    source instanceof FlowSource
    or
    exists(FunctionCall fc |
      fc = source.asExpr() and
      fc.getTarget().getName()
         .regexpMatch("recv|recvfrom|recvmsg|read|fread|fgets|getline|getenv|gets|scanf|fscanf|sscanf")
    )
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
  "vuljector/cpp/pairs"                                        // 16 query_id
