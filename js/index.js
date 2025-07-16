// static/index.js

const ws = new WebSocket('ws://' + window.location.host + '/ws');

const logContainer = document.getElementById('log-container');
const attackCountElem = document.getElementById('attack-count');
const packetCountElem = document.getElementById('packet-count');

let attackCount = 0;
let packetCount = 0;

ws.onopen = () => {
  console.log('WebSocket connected');
};

ws.onmessage = event => {
  const data = JSON.parse(event.data);

  // Met à jour les compteurs
  packetCount++;
  if (data.prediction && data.prediction.toLowerCase() === 'attaque') {
    attackCount++;
  }

  attackCountElem.textContent = attackCount;
  packetCountElem.textContent = packetCount;

  // Ajoute le log dans la zone texte
  const logLine = `[${new Date().toLocaleTimeString()}] Paquet ${data.proto.toUpperCase()} vers ${data.service} [${data.flag}] → 🧠 Prédiction : ${data.prediction}\n`;
  logContainer.textContent = logLine + logContainer.textContent;

  // Limite la taille des logs pour éviter un DOM trop gros
  if (logContainer.textContent.length > 10000) {
    logContainer.textContent = logContainer.textContent.substring(0, 10000);
  }
};

ws.onclose = () => {
  console.log('WebSocket closed');
};
