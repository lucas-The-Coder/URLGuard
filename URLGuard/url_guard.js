const fs = require("fs");

function parseUrl(urlString) {
  if (typeof urlString !== "string" || urlString.trim() === "") {
    return null;
  }

  try {
    const parsed = new URL(urlString);
    return parsed;
  } catch (err) {
    return null;
  }
}

function checkUrl(urlString) {
  const reasons = [];
  let score = 0;

  const parsed = parseUrl(urlString);

  if (parsed === null) {
    reasons.push("INVALID_URL");
    score = 100;
    return {
      url: urlString || "",
      hostname: null,
      score: score,
      risk: "CRITICAL",
      reasons: reasons,
    };
  }

  const hostname = parsed.hostname.toLowerCase();
  const safeUrl = urlString || "";

  if (parsed.protocol === "http:") {
    score += 20;
    reasons.push("INSECURE_HTTP");
  }

  const ipv4Parts = hostname.split(".");
  const isIpv4 =
    ipv4Parts.length === 4 &&
    ipv4Parts.every((part) => {
      if (!/^\d{1,3}$/.test(part)) {
        return false;
      }
      const num = Number(part);
      return num >= 0 && num <= 255;
    });
  const isIpv6 = hostname.includes(":");
  if (isIpv4 || isIpv6) {
    score += 30;
    reasons.push("IP_IN_URL");
  }

  const dotCount = (hostname.match(/\./g) || []).length;
  if (dotCount > 3 && !isIpv4) {
    score += 15;
    reasons.push("MANY_SUBDOMAINS");
  }

  if (safeUrl.includes("@")) {
    score += 25;
    reasons.push("AT_SYMBOL");
  }

  if (hostname.startsWith("xn--") || hostname.includes(".xn--")) {
    score += 20;
    reasons.push("PUNYCODE");
  }

  if (safeUrl.length > 75) {
    score += 10;
    reasons.push("LONG_URL");
  }

  const suspiciousTlds = [
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".gq",
    ".xyz",
    ".top",
    ".click",
  ];
  if (suspiciousTlds.some((tld) => hostname.endsWith(tld))) {
    score += 20;
    reasons.push("SUSPICIOUS_TLD");
  }

  const suspiciousKeywords = [
    "secure-login",
    "verify",
    "free",
    "login-",
    "account-",
    "update-",
  ];
  const hasKeywordAndHyphen =
    hostname.includes("-") &&
    suspiciousKeywords.some((keyword) => hostname.includes(keyword));

  if (hasKeywordAndHyphen) {
    score += 15;
    reasons.push("SUSPICIOUS_KEYWORD");
  }

  if (score > 100) {
    score = 100;
  }

  const risk = scoreToRisk(score);

  return {
    url: urlString,
    hostname: hostname,
    score: score,
    risk: risk,
    reasons: reasons,
  };
}

function scoreToRisk(score) {
  if (score >= 80) {
    return "CRITICAL";
  }
  if (score >= 50) {
    return "HIGH";
  }
  if (score >= 20) {
    return "MEDIUM";
  }
  return "LOW";
}

function main() {
  if (process.argv.length < 3) {
    console.log("Usage: node url_guard.js <url>");
    return;
  }

  const urlString = process.argv[2];
  const result = checkUrl(urlString);

  console.log(`URL:      ${result.url}`);
  console.log(`Hostname: ${result.hostname || "N/A"}`);
  console.log(`Score:    ${result.score}/100`);
  console.log(`Risk:     ${result.risk}`);
  console.log("Reasons:");

  if (result.reasons.length === 0) {
    console.log("  - None (No phishing indicators detected)");
  } else {
    result.reasons.forEach((reason) => {
      console.log(`  - ${reason}`);
    });
  }

  try {
    fs.writeFileSync(
      "url_report.json",
      JSON.stringify(result, null, 2),
      "utf8",
    );
    console.log("\nReport saved to url_report.json");
  } catch (error) {
    console.error(`Error writing url_report.json: ${error.message}`);
    return;
  }
}

main();
