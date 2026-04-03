/**
 * @name Vuljector: combinatorial checkpoint × sink pairs (JavaScript/TypeScript)
 * @description For every dangerous sink, finds ALL checkpoints in the same function.
 *              Mirrors the AST BFS pairing strategy but scoped to function level.
 *              Returns one row per (sink, checkpoint) pair — multiple rows per sink.
 * @id vuljector/javascript/combinatorial
 * @tags security vuljector
 */

import javascript
import vuljector_lib

from DataFlow::Node sink, string sinkKind, Function f,
     Location cpLoc, string cpKind, string cpText
where
  vuljectorSink(sink, sinkKind) and
  not sink.getFile().getAbsolutePath().regexpMatch(".*/tools/data/externs/.*|.*/Caskroom/codeql/.*") and
  // Bind f to the function containing the sink
  f = sink.getContainer() and
  // Find every checkpoint in that same function
  checkpointInFunction(f, cpLoc, cpKind, cpText)
select
  sink.getLocation(),                                          // 1  sink_url
  sink.getFile().getAbsolutePath(),                            // 2  sink_file
  sink.getLocation().getStartLine(),                           // 3  sink_line
  f.toString(),                                                // 4  sink_function
  sink.toString(),                                             // 5  sink_text
  sinkKind,                                                    // 6  sink_kind
  sink.getLocation(),                                          // 7  source_url  (no real source)
  sink.getFile().getAbsolutePath(),                            // 8  source_file
  sink.getLocation().getStartLine(),                           // 9  source_line
  cpLoc,                                                       // 10 cp_url
  cpLoc.getFile().getAbsolutePath(),                           // 11 cp_file
  cpLoc.getStartLine(),                                        // 12 cp_line
  cpText,                                                      // 13 cp_text
  cpKind,                                                      // 14 cp_kind
  -1,                                                          // 15 path_length = -1 → combinatorial
  "vuljector/javascript/combinatorial"                         // 16 query_id
