/**
 * @name Vuljector: taint paths to dangerous sinks (JavaScript/TypeScript)
 * @description Finds HTTP/external sources that reach dangerous operation sinks.
 *              Used by Vuljector to identify checkpoint × operation injection candidates.
 * @id vuljector/javascript/pairs
 * @tags security vuljector
 */

// NOTE: JS lib 2.6.x uses the class-based TaintTracking::Configuration API.
import javascript
import vuljector_lib

// ── Taint configuration ───────────────────────────────────────────────────────

class VuljectorConfig extends TaintTracking::Configuration {
  VuljectorConfig() { this = "VuljectorConfig" }

  override predicate isSource(DataFlow::Node source) {
    // HTTP/remote sources (application code)
    source instanceof RemoteFlowSource
    or
    // Library API boundary: any function parameter may receive untrusted data
    source instanceof DataFlow::ParameterNode
  }

  override predicate isSink(DataFlow::Node sink) {
    vuljectorSink(sink, _)
  }
}

// ── Main query ────────────────────────────────────────────────────────────────

from VuljectorConfig cfg, DataFlow::Node source, DataFlow::Node sink, string sinkKind
where
  cfg.hasFlow(source, sink) and
  vuljectorSink(sink, sinkKind)
select
  sink.getLocation(),                                          // 1  sink_url
  sink.getFile().getAbsolutePath(),                            // 2  sink_file
  sink.getLocation().getStartLine(),                           // 3  sink_line
  sink.getContainer().toString(),                              // 4  sink_function
  sink.toString(),                                             // 5  sink_text
  sinkKind,                                                    // 6  sink_kind
  source.getLocation(),                                        // 7  source_url
  source.getFile().getAbsolutePath(),                          // 8  source_file
  source.getLocation().getStartLine(),                         // 9  source_line
  sink.getFile().getAbsolutePath(),                            // 10 cp_url
  sink.getFile().getAbsolutePath(),                            // 11 cp_file
  0,                                                           // 12 cp_line
  cpText(sink),                                                // 13 cp_text
  cpKind(sink),                                                // 14 cp_kind
  1,                                                           // 15 path_length
  "vuljector/javascript/pairs"                                 // 16 query_id
