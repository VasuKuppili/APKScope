const API_BASE = import.meta.env.VITE_API_URL
  ? `${import.meta.env.VITE_API_URL.replace(/\/$/, '')}/api`
  : '/api';

export async function checkHealth() {
  const res = await fetch(`${API_BASE}/health`);
  return res.json();
}

export async function uploadApk(file) {
  const formData = new FormData();
  formData.append('file', file);

  const res = await fetch(`${API_BASE}/upload`, {
    method: 'POST',
    body: formData,
  });

  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || 'Upload failed');
  }

  return res.json();
}

export async function startPassiveAnalysis(jobId) {
  const res = await fetch(`${API_BASE}/passive/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ job_id: jobId }),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || 'Failed to start passive analysis');
  }

  return res.json();
}

export async function startActiveAnalysis(jobId) {
  const res = await fetch(`${API_BASE}/active/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ job_id: jobId }),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || 'Failed to start active analysis');
  }

  return res.json();
}

export async function getJobStatus(jobId) {
  const res = await fetch(`${API_BASE}/jobs/${jobId}`);
  if (!res.ok) {
    throw new Error('Failed to retrieve job status');
  }
  return res.json();
}

export async function cancelJob(jobId) {
  const res = await fetch(`${API_BASE}/jobs/${jobId}/cancel`, {
    method: 'POST',
  });
  return res.json();
}

export async function getResults(jobId) {
  const res = await fetch(`${API_BASE}/results/${jobId}`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || 'Failed to fetch analysis results');
  }
  return res.json();
}

export async function getShapExplanation(jobId) {
  const res = await fetch(`${API_BASE}/results/${jobId}/explanation`);
  if (!res.ok) {
    throw new Error('Failed to fetch SHAP explanation');
  }
  return res.json();
}

export async function getThreatIntelligence(jobId) {
  const res = await fetch(`${API_BASE}/results/${jobId}/threat-intelligence`);
  if (!res.ok) {
    throw new Error('Failed to fetch threat intelligence');
  }
  return res.json();
}

export async function generateGeminiExplanation(jobId) {
  const res = await fetch(`${API_BASE}/results/${jobId}/gemini-explanation`, {
    method: 'POST',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || 'Gemini explanation generation failed');
  }
  return res.json();
}

export async function testGeminiApi(apiKey, modelName) {
  const res = await fetch(`${API_BASE}/settings/gemini/test`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ api_key: apiKey, model_name: modelName }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || 'Gemini API test failed');
  }
  return res.json();
}

export async function getHistory(query = '', mode = '', classification = '') {
  const params = new URLSearchParams();
  if (query) params.append('q', query);
  if (mode) params.append('mode', mode);
  if (classification) params.append('classification', classification);

  const res = await fetch(`${API_BASE}/history?${params.toString()}`);
  return res.json();
}

export async function deleteHistoryRecord(jobId) {
  const res = await fetch(`${API_BASE}/history/${jobId}`, {
    method: 'DELETE',
  });
  return res.json();
}

export async function clearHistory() {
  const res = await fetch(`${API_BASE}/history/clear`, {
    method: 'POST',
  });
  return res.json();
}

export async function getDashboardStats() {
  const res = await fetch(`${API_BASE}/dashboard/stats`);
  return res.json();
}

export async function getStixBundle(jobId) {
  const res = await fetch(`${API_BASE}/results/${jobId}/stix`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || 'Failed to export STIX bundle');
  }
  return res.json();
}

export async function getTaxiiConfig() {
  const res = await fetch(`${API_BASE}/taxii/config`);
  return res.json();
}

export async function saveTaxiiConfig(config) {
  const res = await fetch(`${API_BASE}/taxii/config`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(config),
  });
  return res.json();
}

export async function testTaxiiConnection() {
  const res = await fetch(`${API_BASE}/taxii/test`, {
    method: 'POST',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || 'TAXII connection test failed');
  }
  return res.json();
}

export async function shareTaxiiIntelligence(jobId) {
  const res = await fetch(`${API_BASE}/taxii/share`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ job_id: jobId }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || 'TAXII intelligence sharing failed');
  }
  return res.json();
}

export function getReportDownloadUrl(jobId, format = 'pdf') {
  return `${API_BASE}/reports/${jobId}?format=${format}`;
}
