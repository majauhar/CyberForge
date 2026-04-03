/**
 * @name Vuljector: dangerous sinks with nearby checkpoints (Python, sink-only)
 * @description Finds ALL dangerous operation sinks paired with nearby checkpoint guards.
 *              No taint source required — maximum yield mode.
 * @id vuljector/python/sinks
 * @tags security vuljector
 */

import python
import semmle.python.dataflow.new.DataFlow
import vuljector_lib

// ── Main query (no source/taint required) ─────────────────────────────────────

from DataFlow::Node sink, string sinkKind
where vuljectorSink(sink, sinkKind)
select
  sink.getLocation(),                                          // 1  sink_url
  sink.getLocation().getFile().getAbsolutePath(),              // 2  sink_file
  sink.getLocation().getStartLine(),                           // 3  sink_line
  sink.getEnclosingCallable().toString(),                      // 4  sink_function
  sink.toString(),                                             // 5  sink_text
  sinkKind,                                                    // 6  sink_kind
  sink.getLocation(),                                          // 7  source_url  (=sink, no real source)
  sink.getLocation().getFile().getAbsolutePath(),              // 8  source_file
  sink.getLocation().getStartLine(),                           // 9  source_line
  sink.getLocation().getFile().getAbsolutePath(),              // 10 cp_url
  sink.getLocation().getFile().getAbsolutePath(),              // 11 cp_file
  0,                                                           // 12 cp_line
  cpText(sink),                                                // 13 cp_text
  cpKind(sink),                                                // 14 cp_kind
  0,                                                           // 15 path_length = 0 → sink-only
  "vuljector/python/sinks"                                     // 16 query_id
