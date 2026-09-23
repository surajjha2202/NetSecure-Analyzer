import api from "./client";

export async function getTrainingCandidates() {
  const response = await api.get(
    "/api/training/candidates",
    {
      params: {
        candidate_status: "PENDING",
      },
    }
  );

  return response.data;
}

export async function getTrainingMappings() {
  const response = await api.get(
    "/api/training/mappings"
  );

  return response.data;
}
