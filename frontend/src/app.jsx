import { useState } from "react";
import LogInput from "./components/LogInput";
import IncidentList from "./components/IncidentList";
import { analyzeLogs, getIncidentDetail } from "./api";

export default function App() {
  const [runId, setRunId] = useState(null);
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [incidentDetails, setIncidentDetails] = useState({});

  async function handleAnalyze(file) {
    setLoading(true);
    setError(null);
    setIncidentDetails({});

    try {
      const data = await analyzeLogs(file);
      setRunId(data.run_id);
      setIncidents(data.incidents || []);
    } catch (err) {
      setError(err.message);
      setIncidents([]);
    } finally {
      setLoading(false);
    }
  }

  async function handleViewDetail(incidentId) {
    if (!runId) return;

    try {
      const detail = await getIncidentDetail(runId, incidentId);
      setIncidentDetails((prev) => ({
        ...prev,
        [incidentId]: detail,
      }));
    } catch (err) {
      setError(err.message);
    }
  }

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100">
      <div className="max-w-5xl mx-auto p-6 space-y-6">
        <header className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-emerald-400 to-cyan-500 flex items-center justify-center">
            <span className="text-xl">⚡</span>
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight">SignalTrace</h1>
            <p className="text-sm text-slate-400">AI-powered log triage</p>
          </div>
        </header>

        <LogInput onAnalyze={handleAnalyze} loading={loading} />

        {error && (
          <div className="rounded-lg bg-red-900/50 border border-red-500/50 p-4 text-red-200">
            {error}
          </div>
        )}

        {runId && incidents.length > 0 && (
          <div className="text-sm text-slate-400">
            Run: <code className="text-emerald-400">{runId}</code> • {incidents.length} incident(s)
          </div>
        )}

        <IncidentList
          incidents={incidents}
          onViewDetail={handleViewDetail}
          incidentDetails={incidentDetails}
        />
      </div>
    </div>
  );
}
