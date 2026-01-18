import { useState } from "react";

const PRIORITY_COLORS = {
  P0: "bg-red-500 text-white",
  P1: "bg-orange-500 text-white",
  P2: "bg-yellow-500 text-black",
  P3: "bg-slate-600 text-slate-200",
};

const SEVERITY_COLORS = {
  ERROR: "text-red-400",
  WARN: "text-yellow-400",
  WARNING: "text-yellow-400",
  INFO: "text-blue-400",
};

export default function IncidentCard({ incident, onViewDetail, detail }) {
  const [expanded, setExpanded] = useState(false);

  const priorityClass = PRIORITY_COLORS[incident.priority] || PRIORITY_COLORS.P3;
  const severityClass = SEVERITY_COLORS[incident.severity] || "text-slate-400";

  return (
    <div className="rounded-xl bg-slate-800 border border-slate-700 p-5 hover:border-slate-600 transition-colors">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span className={`px-2 py-0.5 rounded text-xs font-bold ${priorityClass}`}>
              {incident.priority}
            </span>
            <span className={`text-sm font-medium ${severityClass}`}>
              {incident.severity}
            </span>
            <span className="text-xs text-slate-500">
              Score: {incident.score?.toFixed(2) || "N/A"}
            </span>
          </div>
          <h3 className="font-semibold text-slate-100 truncate" title={incident.title}>
            {incident.title}
          </h3>
        </div>
        <div className="text-right text-sm text-slate-400 shrink-0">
          <div className="font-mono text-emerald-400">{incident.count}x</div>
        </div>
      </div>

      {/* Meta */}
      <div className="mt-2 text-sm text-slate-400 flex flex-wrap gap-x-4 gap-y-1">
        <span>Services: {incident.services?.join(", ") || "unknown"}</span>
        {incident.first_seen && (
          <span>First: {new Date(incident.first_seen).toLocaleTimeString()}</span>
        )}
        {incident.last_seen && (
          <span>Last: {new Date(incident.last_seen).toLocaleTimeString()}</span>
        )}
      </div>

      {/* Actions */}
      <div className="flex gap-3 mt-4">
        <button
          onClick={() => {
            if (!detail) onViewDetail(incident.incident_id);
            setExpanded(!expanded);
          }}
          className="text-sm text-cyan-400 hover:text-cyan-300 transition-colors"
        >
          {expanded ? "Hide details" : "View details"}
        </button>
      </div>

      {/* Expanded Detail */}
      {expanded && detail && (
        <div className="mt-4 space-y-4">
          {/* Evidence */}
          <div className="rounded-lg bg-slate-900 p-4">
            <h4 className="text-sm font-semibold text-slate-300 mb-2">Sample Logs</h4>
            <ul className="space-y-1 font-mono text-xs text-slate-400 max-h-40 overflow-auto">
              {detail.evidence?.sample_lines?.map((line, i) => (
                <li key={i} className="flex gap-2">
                  <span className="text-slate-600 select-none w-8">{line.line_number}</span>
                  <span className="text-slate-500">{line.timestamp?.split("T")[1]?.slice(0, 8)}</span>
                  <span className={SEVERITY_COLORS[line.level] || ""}>{line.level}</span>
                  <span className="text-slate-300 break-all">{line.message}</span>
                </li>
              ))}
            </ul>
          </div>

          {/* Explanation */}
          {detail.explanation && (
            <div className="rounded-lg bg-gradient-to-br from-emerald-900/30 to-cyan-900/30 border border-emerald-700/30 p-4">
              <div className="flex items-center justify-between mb-2">
                <h4 className="text-sm font-semibold text-emerald-300">AI Analysis</h4>
                <span className={`text-xs px-2 py-0.5 rounded ${
                  detail.validation?.used_llm 
                    ? "bg-emerald-800 text-emerald-200" 
                    : "bg-slate-700 text-slate-300"
                }`}>
                  {detail.validation?.used_llm ? "LLM" : "Fallback"}
                </span>
              </div>

              <p className="text-sm text-slate-300 mb-3">
                {detail.explanation.what_happened}
              </p>

              {detail.explanation.likely_causes?.length > 0 && (
                <div className="mb-3">
                  <h5 className="text-xs font-semibold text-slate-400 uppercase mb-1">Likely Causes</h5>
                  <ul className="text-sm text-slate-300 space-y-1">
                    {detail.explanation.likely_causes.map((cause, i) => (
                      <li key={i} className="flex gap-2">
                        <span className="text-cyan-400">•</span>
                        <span>{cause.hypothesis}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {detail.explanation.recommended_next_steps?.length > 0 && (
                <div className="mb-3">
                  <h5 className="text-xs font-semibold text-slate-400 uppercase mb-1">Next Steps</h5>
                  <ul className="text-sm text-slate-300 space-y-1">
                    {detail.explanation.recommended_next_steps.map((step, i) => (
                      <li key={i} className="flex gap-2">
                        <span className="text-emerald-400">{i + 1}.</span>
                        <span>{step}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {detail.explanation.caveats?.length > 0 && (
                <div className="text-xs text-slate-500 italic">
                  {detail.explanation.caveats.join(" • ")}
                </div>
              )}
            </div>
          )}

          {/* Validation errors if any */}
          {detail.validation?.errors?.length > 0 && (
            <div className="text-xs text-yellow-500">
              ⚠ {detail.validation.errors.join(", ")}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
