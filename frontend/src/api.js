const BASE_URL = import.meta.env.VITE_API_BASE_URL || "/api";

/**
 * Analyze log file → run with incident summaries
 * Backend: POST /api/analyze (multipart file upload)
 */
export async function analyzeLogs(file) {
  const formData = new FormData();
  formData.append("file", file);

  const res = await fetch(`${BASE_URL}/analyze`, {
    method: "POST",
    body: formData,
  });

  if (!res.ok) {
    const error = await res.json().catch(() => ({}));
    throw new Error(error.detail || "Analyze logs failed");
  }

  return res.json();
}

/**
 * Get incident detail with explanation
 * Backend: GET /api/runs/{run_id}/incidents/{incident_id}
 */
export async function getIncidentDetail(runId, incidentId) {
  const res = await fetch(`${BASE_URL}/runs/${runId}/incidents/${incidentId}`);

  if (!res.ok) {
    const error = await res.json().catch(() => ({}));
    throw new Error(error.detail || "Get incident detail failed");
  }

  return res.json();
}

/**
 * List all runs
 * Backend: GET /api/runs
 */
export async function listRuns() {
  const res = await fetch(`${BASE_URL}/runs`);

  if (!res.ok) {
    throw new Error("List runs failed");
  }

  return res.json();
}
