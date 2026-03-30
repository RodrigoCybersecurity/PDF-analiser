export async function uploadForScan(file) {
  const formData = new FormData();
  formData.append("file", file);

  const response = await fetch("/scan", {
    method: "POST",
    body: formData,
  });

  if (response.ok) {
    const blob = await response.blob();
    const filename = response.headers.get("content-disposition")
      ?.match(/filename="?([^";]+)"?/)?.[1] || file.name;

    return {
      status: "accepted",
      filename,
      blob,
    };
  }

  const data = await response.json();
  return data;
}
