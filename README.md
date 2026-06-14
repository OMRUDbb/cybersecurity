# Cybersecurity API

A comprehensive RESTful API for cybersecurity threat analysis, password strength checking, phishing detection, and security best practices.

## 🚀 Features

- **Password Strength Checker** - Analyze password security with detailed feedback
- **Phishing Detection** - Detect suspicious URLs and phishing indicators
- **Vulnerability Scanner** - Scan for common security vulnerabilities (SQL injection, XSS, etc.)
- **Security Tips** - Get comprehensive security recommendations
- **Threat Analysis** - Detailed analysis of different cyber threats
- **Best Practices** - Industry-standard security practices
- **Encryption Methods** - Information about encryption algorithms and protocols
- **Threat Database** - Learn about various cyber threats

## 📋 Requirements

- Node.js 16+
- npm or yarn

## 🛠️ Installation

1. Clone the repository
```bash
git clone <repository-url>
cd antiscam-api
```

2. Install dependencies
```bash
npm install
```

3. Create environment file
```bash
cp .env.example .env
```

4. Start development server
```bash
npm run dev
```

## 📚 API Endpoints

### Health Check
```
GET /
```
Returns API status and available endpoints.

### Password Strength Checker
```
POST /api/password-strength
```
**Request Body:**
```json
{
  "password": "YourPassword123!"
}
```

**Response:**
```json
{
  "score": 85,
  "strength": "Strong",
  "issues": [],
  "suggestions": []
}
```

### Phishing URL Detection
```
POST /api/phishing-check
```
**Request Body:**
```json
{
  "url": "https://suspicious-example.com/login"
}
```

**Response:**
```json
{
  "isLikely": true,
  "indicators": [
    "Contains common phishing keywords",
    "Login-related path detected"
  ],
  "riskLevel": "High"
}
```

### Vulnerability Scanner
```
POST /api/vulnerability-scan
```
**Request Body:**
```json
{
  "input": "'; DROP TABLE users; --"
}
```

**Response:**
```json
{
  "hasVulnerabilities": true,
  "vulnerabilities": [
    "Potential SQL injection"
  ],
  "riskLevel": "Critical"
}
```

### Security Tips
```
GET /api/security-tips
```
Returns a list of 8 essential cybersecurity tips.

### Threat Types
```
GET /api/threat-types
```
Returns information about 10 different types of cyber threats.

### Threat Analysis
```
POST /api/threat-analysis
```
**Request Body:**
```json
{
  "threatType": "malware"
}
```

**Response:**
```json
{
  "threatType": "Malware",
  "description": "Malicious software designed to exploit...",
  "riskLevel": "Critical",
  "mitigation": [
    "Use antivirus software",
    "Keep system updated",
    ...
  ]
}
```

### Best Practices
```
GET /api/best-practices
```
Returns security best practices organized by category.

### Encryption Methods
```
GET /api/encryption-methods
```
Returns information about various encryption algorithms and protocols.

## 🏃 Running

### Development
```bash
npm run dev
```

### Build
```bash
npm run build
```

### Production
```bash
npm run build
npm start
```

### Type Check
```bash
npm run type-check
```

## 📦 Dependencies

- **express** - Web framework
- **cors** - CORS middleware
- **typescript** - Type safety
- **nodemon** - Development auto-reload
- **ts-node** - TypeScript execution

## 🔒 Security Considerations

- All passwords are analyzed client-side (never stored)
- No data is persisted on the server
- CORS is enabled for cross-origin requests
- Input validation on all endpoints
- Error handling for malformed requests

## 🚀 Deployment

### Deploy to Heroku
```bash
heroku create your-app-name
git push heroku main
```

### Deploy to RapidAPI

1. Sign up on [RapidAPI](https://rapidapi.com)
2. Create a new API
3. Deploy this application to your server
4. Configure endpoints in RapidAPI dashboard
5. Publish your API

### Deploy to Other Platforms
- AWS Lambda
- Google Cloud Run
- Azure Functions
- DigitalOcean
- Vercel

## 📝 Example Usage

### JavaScript/Node.js
```javascript
const axios = require('axios');

async function checkPassword(password) {
  const response = await axios.post('http://localhost:5000/api/password-strength', {
    password: password
  });
  console.log(response.data);
}

checkPassword('SecurePassword123!');
```

### Python
```python
import requests

response = requests.post('http://localhost:5000/api/password-strength', json={
    'password': 'SecurePassword123!'
})
print(response.json())
```

### cURL
```bash
curl -X POST http://localhost:5000/api/password-strength \
  -H "Content-Type: application/json" \
  -d '{"password":"SecurePassword123!"}'
```

## 🐛 Troubleshooting

### Port already in use
```bash
# Change PORT in .env
PORT=3001
```

### Dependencies not installing
```bash
npm install --legacy-peer-deps
```

### TypeScript errors
```bash
npm run type-check
```

## 📄 License

ISC

## 👨‍💻 Contributing

Contributions are welcome! Please feel free to submit pull requests.

## 📧 Support

For issues and questions, please create an issue on the repository.

---

**Made with ❤️ for cybersecurity awareness**
