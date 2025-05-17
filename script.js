document.getElementById("scanBtn").addEventListener("click", startRealScan);

function startRealScan() {
  const deviceList = document.getElementById("deviceList");
  const logTable = document.getElementById("logTable");
  const loadingText = document.getElementById("loadingText");

  // Clear UI
  deviceList.innerHTML = "";
  logTable.innerHTML = "";
  loadingText.style.display = "block";

  fetch("https://defensyfi.onrender.com/devices")
    .then(response => {
      if (!response.ok) {
        throw new Error("Failed to fetch");
      }
      return response.json();
    })
    .then(devices => {
      loadingText.style.display = "none";

      if (!Array.isArray(devices) || devices.length === 0) {
        alert("No active devices found.");
        return;
      }

      devices.forEach(device => addDeviceToUI(device));
      updateCharts(devices);
    })
    .catch(error => {
      loadingText.style.display = "none";
      alert("❌ Failed to fetch devices. Is your Python backend running?");
      console.error("Error:", error);
    });
}

function addDeviceToUI(device) {
  const deviceList = document.getElementById("deviceList");
  const logTable = document.getElementById("logTable");

  // Card for each device
  const card = document.createElement("div");
  card.className = "device-card";
  card.innerHTML = `
    <h3>${device.ip}</h3>
  <p><strong>Status:</strong> ${device.status}</p>
  <p><strong>MAC Address:</strong> ${device.mac}</p>
  <p><strong>Open Ports:</strong> ${device.ports.join(", ")}</p>
  <p><strong>Risk Level:</strong> ${device.risk}</p>
  `;
  deviceList.appendChild(card);

  if (device.risk === "High") {
  const advice = document.createElement("div");
  advice.className = "quarantine-card";
  advice.innerHTML = `
    <h4>⚠️ Quarantine Advice</h4>
    <p>High-risk ports are open on this device. Consider disabling unused services or enabling your firewall.</p>
  `;
  deviceList.appendChild(advice);
}

  // Row for the scan log
  const row = document.createElement("tr");
  row.innerHTML = `
   <td>${device.ip}</td>
  <td>${device.status}</td>
  <td>${device.mac}</td>
  <td>${device.ports.join(", ")}</td>
  <td>${device.risk}</td>
  `;
  logTable.appendChild(row);
}

function updateCharts(devices) {
  const deviceCount = devices.length;
  const highRisk = devices.filter(d => d.risk === "High").length;
  const lowRisk = devices.filter(d => d.risk === "Low").length;
  const unknownRisk = devices.filter(d => d.risk === "Unknown").length;

  // Destroy existing charts to avoid overlapping
  if (window.deviceChart && typeof window.deviceChart.destroy === "function") {
    window.deviceChart.destroy();
  }
  if (window.riskChart && typeof window.riskChart.destroy === "function") {
    window.riskChart.destroy();
  }

  // Device Count Chart
  window.deviceChart = new Chart(document.getElementById("deviceChart"), {
    type: "doughnut",
    data: {
      labels: ["Active Devices", "Free Slots"],
      datasets: [{
        data: [deviceCount, Math.max(0, 10 - deviceCount)],
        backgroundColor: ["#00f0ff", "#334"]
      }]
    },
    options: {
      plugins: {
        legend: {
          labels: {
            color: "#fff"
          }
        }
      }
    }
  });

  // Risk Distribution Chart
  window.riskChart = new Chart(document.getElementById("riskChart"), {
    type: "pie",
    data: {
      labels: ["High Risk", "Low Risk", "Unknown"],
      datasets: [{
        data: [highRisk, lowRisk, unknownRisk],
        backgroundColor: ["#ff4d4d", "#00ff88", "#888"]
      }]
    },
    options: {
      plugins: {
        legend: {
          labels: {
            color: "#fff"
          }
        }
      }
    }
  });
}

function fetchNetworkInfo() {
  fetch("https://defensyfi.onrender.com/devices")
    .then(res => res.json())
    .then(info => {
      document.getElementById("ipAddress").textContent = info.ip_address;
      document.getElementById("subnet").textContent = info.subnet;
      document.getElementById("hostname").textContent = info.hostname;
    });
}

window.onload = function() {
  fetchNetworkInfo();  // call on page load
}





