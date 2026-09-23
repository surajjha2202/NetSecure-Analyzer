import api from "./client";

export async function getRemediationRequests(params = {}) {
  const response = await api.get(
    "/api/remediation/requests",
    { params }
  );

  return response.data;
}

export async function createRemediationRequest(payload) {
  const response = await api.post(
    "/api/remediation/requests",
    payload
  );

  return response.data;
}

export async function approveRemediationRequest(requestId) {
  const response = await api.post(
    `/api/remediation/requests/${requestId}/approve`
  );

  return response.data;
}

export async function rejectRemediationRequest(requestId) {
  const response = await api.post(
    `/api/remediation/requests/${requestId}/reject`
  );

  return response.data;
}

export async function executeRemediationRequest(
  requestId,
  payload
) {
  const response = await api.post(
    `/api/remediation/requests/${requestId}/execute`,
    payload
  );

  return response.data;
}