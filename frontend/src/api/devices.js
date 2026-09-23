import api from "./client";

export async function getDevices() {
  const response = await api.get("/api/devices");
  return response.data;
}

export async function getDevice(deviceId) {
  const response = await api.get(`/api/devices/${deviceId}`);
  return response.data;
}

export async function scanDevice(deviceId, payload) {
  const response = await api.post(
    `/api/devices/${deviceId}/scan`,
    payload
  );

  return response.data;
}
export async function createDevice(payload) {
  const response = await api.post(
    "/api/devices",
    payload
  );

  return response.data;
}