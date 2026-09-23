import api from "./client";

export async function getAuditLogs(params = {}) {
  const response = await api.get(
    "/api/audit/logs",
    { params }
  );

  return response.data;
}
