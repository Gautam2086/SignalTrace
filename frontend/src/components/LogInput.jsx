import { useRef, useState } from "react";

export default function LogInput({ onAnalyze, loading }) {
  const [text, setText] = useState("");
  const [fileName, setFileName] = useState(null);
  const fileRef = useRef(null);

  function handleFile(e) {
    const file = e.target.files?.[0];
    if (!file) return;
    setFileName(file.name);
    const reader = new FileReader();
    reader.onload = () => setText(reader.result || "");
    reader.readAsText(file);
  }

  function handleSubmit() {
    if (!text.trim()) return;

    // Convert text to File object for upload
    const blob = new Blob([text], { type: "text/plain" });
    const file = new File([blob], fileName || "logs.txt", { type: "text/plain" });
    onAnalyze(file);
  }

  function handleClear() {
    setText("");
    setFileName(null);
    if (fileRef.current) fileRef.current.value = "";
  }

  return (
    <div className="rounded-xl bg-slate-800 border border-slate-700 p-5">
      <div className="flex items-center justify-between mb-3">
        <h2 className="text-lg font-semibold text-slate-200">Log Input</h2>
        {fileName && (
          <span className="text-sm text-slate-400">
            📄 {fileName}
          </span>
        )}
      </div>

      <textarea
        className="w-full rounded-lg bg-slate-900 border border-slate-600 p-4 font-mono text-sm text-slate-300 placeholder-slate-500 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 outline-none transition-colors"
        rows={10}
        placeholder="Paste logs here or upload a file..."
        value={text}
        onChange={(e) => {
          setText(e.target.value);
          setFileName(null);
        }}
      />

      <div className="flex items-center justify-between mt-4">
        <div className="flex items-center gap-3">
          <label className="cursor-pointer text-sm text-slate-400 hover:text-slate-300 transition-colors">
            <input
              ref={fileRef}
              type="file"
              accept=".log,.txt,.json"
              onChange={handleFile}
              className="hidden"
            />
            <span className="flex items-center gap-1">
              📁 Upload file
            </span>
          </label>
          {text && (
            <button
              onClick={handleClear}
              className="text-sm text-slate-500 hover:text-slate-400 transition-colors"
            >
              Clear
            </button>
          )}
        </div>

        <button
          onClick={handleSubmit}
          disabled={!text.trim() || loading}
          className="rounded-lg bg-gradient-to-r from-emerald-500 to-cyan-500 px-6 py-2.5 font-medium text-white disabled:opacity-50 disabled:cursor-not-allowed hover:from-emerald-400 hover:to-cyan-400 transition-all"
        >
          {loading ? (
            <span className="flex items-center gap-2">
              <span className="animate-spin">⏳</span> Analyzing...
            </span>
          ) : (
            "Analyze"
          )}
        </button>
      </div>

      <div className="mt-3 text-xs text-slate-500">
        Supports .log, .txt, .json files • Paste or drag & drop
      </div>
    </div>
  );
}
