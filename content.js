// Phishing detection patterns
const PHISHING_PATTERNS = {
  urgency: [
    /urgent/i,
    /immediate action required/i,
    /account .* suspended/i,
    /security alert/i
  ],
  credentials: [
    /verify .* account/i,
    /confirm .* identity/i,
    /login .* details/i,
    /password .* expired/i
  ],
  financial: [
    /bank .* transfer/i,
    /payment .* pending/i,
    /transaction .* suspicious/i
  ],
  suspicious_links: [
    /bit\.ly/i,
    /tinyurl/i,
    /goo\.gl/i,
    /click here/i,
    /login/i,
    /verify/i,
    /account/i,
    /update/i,
    /password/i,
    /secure/i,
    /click/i
  ]
};

// Risk scoring weights
const RISK_WEIGHTS = {
  urgency: 0.3,
  credentials: 0.4,
  financial: 0.3,
  suspicious_links: 0.6,
  sender_reputation: 0.5
};

class PhishingDetector {
  constructor() {
    this.setupObserver();
    this.processedEmails = new Set();
    this.LEETCODE_DOMAIN = 'leetcode.com'; // Define LeetCode domain
  }

  setupObserver() {
    const observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        if (mutation.addedNodes.length) {
          this.checkForNewEmails(mutation.addedNodes);
        }
      });
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true
    });
  }

  checkForNewEmails(nodes) {
    nodes.forEach((node) => {
      if (node.querySelector && node.querySelector('.a3s')) {
        const emailId = this.getEmailId(node);
        if (emailId && !this.processedEmails.has(emailId)) {
          this.processedEmails.add(emailId);
          this.analyzeEmail(node);
        }
      }
    });
  }

  getEmailId(emailNode) {
    const idElement = emailNode.querySelector('[data-message-id]');
    return idElement ? idElement.getAttribute('data-message-id') : null;
  }

  async analyzeEmail(emailNode) {
    const emailContent = this.extractEmailContent(emailNode);
    if (!emailContent) return;

    const { riskScore, linkCount, isLeetCodeSafe } = this.calculateRiskScore(emailContent);
    const aiAnalysis = await this.performGeminiAnalysis(emailContent);

    this.displayWarning(emailNode, riskScore, linkCount, isLeetCodeSafe, aiAnalysis);
    this.updateStats(riskScore > 0.7 || aiAnalysis.riskLevel === 'fraud');
  }

  extractEmailContent(emailNode) {
    const contentNode = emailNode.querySelector('.a3s');
    if (!contentNode) return null;

    const sender = emailNode.querySelector('.gD')?.getAttribute('email') || '';
    const subject = emailNode.querySelector('.hP')?.textContent || '';
    const body = contentNode.textContent || '';
    const links = Array.from(contentNode.querySelectorAll('a')).map(a => a.href);
    const headers = this.extractHeaders(emailNode);

    return { sender, subject, body, links, headers };
  }

  extractHeaders(emailNode) {
    const headers = {};
    const headerElements = emailNode.querySelectorAll('.adn.ads [class="gF"]');
    headerElements.forEach(header => {
      const key = header.getAttribute('data-hid');
      const value = header.textContent;
      if (key && value) {
        headers[key] = value;
      }
    });
    return headers;
  }

  async performGeminiAnalysis(emailContent) {
    try {
      // **Security Note**: Avoid exposing API keys in client-side code.
      // Consider moving this request to a secure server or using environment variables.

      const prompt = {
        contents: [{
          parts: [{
            text: `Analyze this email for phishing or fraud indicators. If the links are from valid domains, make it safe; else suspect or fraud. Classify it as 'safe', 'suspicious', or 'fraud'. Consider these factors:

1. Sender domain: ${emailContent.sender}
2. Subject: ${emailContent.subject}
3. Body: ${emailContent.body}
4. Links (${emailContent.links.length}): ${emailContent.links.join(', ')}
5. Headers: ${JSON.stringify(emailContent.headers)}

Analyze for:
- Unprofessional or urgent language
- Suspicious links or too many links
- Mismatched sender domains
- Requests for sensitive information
- Pressure tactics or threats

Respond with a JSON object containing:
{
  "riskLevel": "safe|suspicious|fraud",
  "confidence": 0-1,
  "explanation": "brief explanation"
}`
          }]
        }]
      };

      const response = await fetch('https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.GEMINI_API_KEY}` // **SECURITY RISK**
        },
        body: JSON.stringify(prompt)
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      const analysisText = data.candidates[0].content.parts[0].text;
      return JSON.parse(analysisText);
    } catch (error) {
      console.error('Gemini analysis failed:', error);
      return {
        riskLevel: 'unknown',
        confidence: 0,
        explanation: null
      };
    }
  }

  calculateRiskScore(emailContent) {
    let score = 0;
    let matches = 0;

    // Check patterns
    for (const [category, patterns] of Object.entries(PHISHING_PATTERNS)) {
      const categoryMatches = patterns.some(pattern => 
        pattern.test(emailContent.subject) || pattern.test(emailContent.body)
      );
      
      if (categoryMatches) {
        score += RISK_WEIGHTS[category];
        matches++;
      }
    }

    // Check sender reputation
    if (!this.checkSenderReputation(emailContent.sender)) {
      score += RISK_WEIGHTS.sender_reputation;
      matches++;
    }

    // Analyze links
    const linkCount = emailContent.links.length;
    const leetCodeLinks = this.countLeetCodeLinks(emailContent.links);
    const isLeetCodeSafe = this.evaluateLeetCodeSafety(linkCount, leetCodeLinks);

    if (!isLeetCodeSafe) {
      const suspiciousLinkCount = this.countSuspiciousLinks(emailContent.links);
      if (linkCount > 0) {
        score += RISK_WEIGHTS.suspicious_links * (suspiciousLinkCount / linkCount);
        matches++;
      }

      // Adjust score based on link count thresholds
      if (linkCount > 10 && linkCount <= 50) {
        score += 0.3; // Adjust value as needed
        matches++;
      } else if (linkCount > 50) {
        score += 0.6; // Adjust value as needed
        matches++;
      }
    }

    return {
      riskScore: matches > 0 ? score / matches : 0,
      linkCount: linkCount,
      isLeetCodeSafe: isLeetCodeSafe
    };
  }

  countSuspiciousLinks(links) {
    let count = 0;
    const suspiciousPatterns = [
      /bit\.ly/i,
      /tinyurl/i,
      /goo\.gl/i,
      /login/i,
      /verify/i,
      /account/i,
      /update/i,
      /password/i,
      /secure/i,
      /click/i
    ];

    links.forEach(link => {
      if (suspiciousPatterns.some(pattern => pattern.test(link))) {
        count++;
      }
    });

    return count;
  }

  countLeetCodeLinks(links) {
    return links.filter(link => link.toLowerCase().includes(this.LEETCODE_DOMAIN)).length;
  }

  evaluateLeetCodeSafety(linkCount, leetCodeLinks) {
    const allLeetCode = leetCodeLinks === linkCount;
    // Define thresholds if needed, e.g., safe if all links are LeetCode and linkCount < 10
    if (allLeetCode && linkCount < 10) {
      return true;
    }
    return false;
  }

  checkSenderReputation(sender) {
    const reputableDomains = [
      'gmail.com',
      'outlook.com',
      'hotmail.com',
      'yahoo.com',
      'microsoft.com',
      'apple.com',
      'amazon.com'
    ];

    const domain = sender.split('@')[1];
    return reputableDomains.includes(domain?.toLowerCase());
  }

  displayWarning(emailNode, riskScore, linkCount, isLeetCodeSafe, aiAnalysis) {
    const existingWarning = emailNode.querySelector('.phishing-warning');
    if (existingWarning) {
      existingWarning.remove();
    }

    const warningDiv = document.createElement('div');
    warningDiv.className = 'phishing-warning';

    let riskLevel, message;

    // Determine risk level based on link counts and LeetCode safety
    if (isLeetCodeSafe) {
      riskLevel = 'low';
      message = '🟢 Safe (LeetCode Links)';
    } else {
      if (riskScore > 0.7 || aiAnalysis.riskLevel === 'fraud') {
        riskLevel = 'high';
        message = '🔴 Fraudulent';
      } else if (riskScore > 0.4 || aiAnalysis.riskLevel === 'suspicious') {
        riskLevel = 'medium';
        message = '🟡 Suspicious';
      } else {
        riskLevel = 'low';
        message = '🟢 Safe';
      }

      // Additional message based on link count
      if (linkCount > 50) {
        message += ` (Links: ${linkCount} - Fraud Threshold)`;
      } else if (linkCount > 10) {
        message += ` (Links: ${linkCount} - Suspicious Threshold)`;
      } else {
        message += ` (Links: ${linkCount})`;
      }
    }

    warningDiv.innerHTML = `
      <div class="risk-indicator risk-${riskLevel}">
        <span class="risk-text">
          ${message}
          ${aiAnalysis.explanation ? `<br>${aiAnalysis.explanation}` : ''}
        </span>
      </div>
    `;

    const targetElement = emailNode.querySelector('.a3s');
    if (targetElement) {
      targetElement.insertAdjacentElement('beforebegin', warningDiv);
    }
  }

  async updateStats(isPhishing) {
    chrome.runtime.sendMessage({
      type: 'updateStats',
      data: { isPhishing }
    });
  }
}

// Initialize detector
new PhishingDetector();