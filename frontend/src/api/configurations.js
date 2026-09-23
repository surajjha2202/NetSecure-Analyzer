import api from "./client";

export async function getConfigurations() {
  const response = await api.get("/api/configurations");
  return response.data;
}

export async function uploadConfiguration(file) {
  const formData = new FormData();
  formData.append("file", file);

  const response = await api.post(
    "/api/configurations/upload",
    formData
  );

  return response.data;
}

export async function analyzeConfiguration(configurationId) {
  const frameworks = [
    "CIS",
    "NIST",
    "DISA_STIG",
    "ISO_27001",
  ];

  const params = new URLSearchParams();

  frameworks.forEach((framework) => {
    params.append("frameworks", framework);
  });

  const response = await api.post(
    `/api/configurations/${configurationId}/analyze?${params.toString()}`
  );

  return response.data;
}

export async function deleteConfiguration(configurationId) {
  const response = await api.delete(
    `/api/configurations/${configurationId}`
  );

  return response.data;
}
export async function deleteConfigurationHistory() {
  const response = await api.delete(
    "/api/configurations/history"
  );

  return response.data;
}
export async function analyzeBulkConfigurations(configurationIds) {
  const frameworks = [
    "CIS",
    "NIST",
    "DISA_STIG",
    "ISO_27001",
  ];

  const params = new URLSearchParams();

  frameworks.forEach((framework) => {
    params.append("frameworks", framework);
  });

  const response = await api.post(
    `/api/bulk/analyze?${params.toString()}`,
    configurationIds
  );

  return response.data;
}