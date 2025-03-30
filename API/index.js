const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const QRCode = require('qrcode');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');
const useragent = require('express-useragent');
const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));

const app = express();
const server = http.createServer(app);
const io = require("socket.io")(server, {
    cors: {
        origin: "https://lambda.kerso.dev",
        credentials: true
    }
})

// Konfiguracja Cloudflare Turnstile
const TURNSTILE_SECRET_KEY = "0x4AAAAAABDCTHoGUGguWmqHKiYKQi5t5ho"; // Zastąp swoim kluczem
const TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

app.use(cors());
app.use(express.json());
app.use(useragent.express());
app.use(express.static('public'));

// Przechowuje aktywne sesje QR
const activeSessions = new Map();

// Weryfikacja tokenu Turnstile
async function verifyTurnstileToken(token, remoteip) {
  try {
    const formData = new URLSearchParams();
    formData.append('secret', TURNSTILE_SECRET_KEY);
    formData.append('response', token);
    
    if (remoteip) {
      formData.append('remoteip', remoteip);
    }
    
    const response = await fetch(TURNSTILE_VERIFY_URL, {
      method: 'POST',
      body: formData,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    });
    
    const data = await response.json();
    return {
      success: data.success,
      errorCodes: data.error_codes,
      challengeTimestamp: data.challenge_ts,
      hostname: data.hostname
    };
  } catch (error) {
    console.error('Błąd weryfikacji Turnstile:', error);
    return { success: false, error: 'Błąd weryfikacji' };
  }
}

// Endpoint do generowania sesji QR z weryfikacją Turnstile
app.post('/api/generate-session', async (req, res) => {
  try {
    const { token } = req.body;
    
    if (!token) {
      return res.status(400).json({
        success: false,
        error: 'Brak tokenu Turnstile'
      });
    }
    
    // Zweryfikuj token Turnstile
    const verificationResult = await verifyTurnstileToken(token, req.ip);
    
    if (!verificationResult.success) {
      return res.status(400).json({
        success: false,
        error: 'Weryfikacja Turnstile nieudana',
        details: verificationResult.errorCodes
      });
    }
    
    // Generuj unikalny ID sesji
    const sessionId = uuidv4();
    
    // URL, który telefon będzie odwiedzał po zeskanowaniu QR kodu
    const qrUrl = `${req.protocol}://api.kerso.dev/api/scan/${sessionId}`;
    
    // Generuj kod QR jako Base64
    const qrCodeBase64 = await QRCode.toDataURL(qrUrl);
    
    // Zapisz sesję z czasem wygaśnięcia (np. 5 minut)
    activeSessions.set(sessionId, {
      created: Date.now(),
      expires: Date.now() + (5 * 60 * 1000), // 5 minut
      connected: false,
      deviceInfo: null,
      turnstileVerified: true,
      turnstileTimestamp: verificationResult.challengeTimestamp
    });
    
    // Zaplanuj usunięcie sesji po wygaśnięciu
    setTimeout(() => {
      if (activeSessions.has(sessionId)) {
        activeSessions.delete(sessionId);
        io.to(sessionId).emit('session_expired');
      }
    }, 5 * 60 * 1000);
    
    // Zwróć ID sesji oraz kod QR w formacie Base64
    res.json({
      success: true,
      sessionId,
      qrCode: qrCodeBase64
    });
  } catch (error) {
    console.error('Błąd generowania sesji QR:', error);
    res.status(500).json({
      success: false,
      error: 'Nie udało się wygenerować sesji QR'
    });
  }
});

// Endpoint dla telefonów skanujących QR kod
app.get('/api/scan/:sessionId', (req, res) => {
  const { sessionId } = req.params;
  const session = activeSessions.get(sessionId);
  
  // Sprawdź, czy sesja istnieje i nie wygasła
  if (!session) {
    return res.status(404).send(`
      <html>
        <body style="font-family: Arial, sans-serif; text-align: center; padding: 20px;">
          <h1>Sesja wygasła lub nie istnieje</h1>
          <p>Kod QR jest nieważny lub wygasł. Poproś o wygenerowanie nowego kodu.</p>
        </body>
      </html>
    `);
  }
  
  if (Date.now() > session.expires) {
    activeSessions.delete(sessionId);
    return res.status(410).send(`
      <html>
        <body style="font-family: Arial, sans-serif; text-align: center; padding: 20px;">
          <h1>Sesja wygasła</h1>
          <p>Kod QR wygasł. Poproś o wygenerowanie nowego kodu.</p>
        </body>
      </html>
    `);
  }
  
  // Sprawdź, czy sesja została zweryfikowana przez Turnstile
  if (!session.turnstileVerified) {
    return res.status(403).send(`
      <html>
        <body style="font-family: Arial, sans-serif; text-align: center; padding: 20px;">
          <h1>Brak weryfikacji</h1>
          <p>Ta sesja nie została poprawnie zweryfikowana. Poproś o wygenerowanie nowego kodu QR.</p>
        </body>
      </html>
    `);
  }
  
  // Pobierz informacje o urządzeniu
  const deviceInfo = {
    userAgent: req.useragent.source,
    browser: req.useragent.browser,
    version: req.useragent.version,
    os: req.useragent.os,
    platform: req.useragent.platform,
    isMobile: req.useragent.isMobile,
    isTablet: req.useragent.isTablet,
    isDesktop: req.useragent.isDesktop,
    ip: req.ip,
    timestamp: new Date().toISOString()
  };
  
  // Aktualizuj sesję z informacjami o urządzeniu
  session.connected = true;
  session.deviceInfo = deviceInfo;
  activeSessions.set(sessionId, session);
  
  // Powiadom frontend przez Socket.IO
  io.to(sessionId).emit('device_connected', deviceInfo);
  
  // Wyświetl stronę potwierdzenia na telefonie
  res.send(`
    <html>
      <head>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
          body { font-family: Arial, sans-serif; text-align: center; padding: 20px; }
          .success { color: green; font-size: 60px; margin: 20px 0; }
          .box { border: 1px solid #ddd; border-radius: 10px; padding: 20px; margin: 20px 0; background-color: #f9f9f9; }
        </style>
      </head>
      <body>
        <div class="success">✓</div>
        <h1>Połączenie udane!</h1>
        <div class="box">
          <p>Twoje urządzenie zostało pomyślnie połączone z aplikacją.</p>
          <p>Możesz teraz zamknąć tę stronę i wrócić do aplikacji.</p>
        </div>
      </body>
    </html>
  `);
});

// Sprawdzanie statusu sesji
app.get('/api/session-status/:sessionId', (req, res) => {
  const { sessionId } = req.params;
  const session = activeSessions.get(sessionId);
  
  if (!session) {
    return res.status(404).json({ 
      success: false, 
      error: 'Sesja nie istnieje' 
    });
  }
  
  if (Date.now() > session.expires) {
    activeSessions.delete(sessionId);
    return res.status(410).json({ 
      success: false, 
      error: 'Sesja wygasła' 
    });
  }
  
  res.json({
    success: true,
    connected: session.connected,
    deviceInfo: session.deviceInfo,
    expiresIn: Math.floor((session.expires - Date.now()) / 1000) // sekundy do wygaśnięcia
  });
});

// Obsługa Socket.IO
io.on('connection', (socket) => {
  console.log('Nowe połączenie WebSocket');
  
  // Przypisz socket do pokoju na podstawie sessionId
  socket.on('join_session', (sessionId) => {
    if (activeSessions.has(sessionId)) {
      socket.join(sessionId);
      console.log(`Socket dołączył do sesji: ${sessionId}`);
      
      // Jeśli urządzenie już jest połączone, wyślij od razu informacje
      const session = activeSessions.get(sessionId);
      if (session.connected) {
        socket.emit('device_connected', session.deviceInfo);
      }
    }
  });
  
  socket.on('disconnect', () => {
    console.log('Połączenie WebSocket zakończone');
  });
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`Serwer działa na porcie ${PORT}`);
});