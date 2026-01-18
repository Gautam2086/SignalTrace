import IncidentCard from "./IncidentCard";

export default function IncidentList({ incidents, onViewDetail, incidentDetails }) {
  if (!incidents.length) {
    return (
      <div className="text-center py-12 text-slate-500">
        <p className="text-lg">No incidents yet</p>
        <p className="text-sm mt-1">Upload a log file to get started</p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <h2 className="text-lg font-semibold text-slate-300">
        Incidents <span className="text-slate-500">({incidents.length})</span>
      </h2>
      {incidents.map((inc) => (
        <IncidentCard
          key={inc.incident_id}
          incident={inc}
          onViewDetail={onViewDetail}
          detail={incidentDetails[inc.incident_id]}
        />
      ))}
    </div>
  );
}
