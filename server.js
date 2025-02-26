import express from "express";
import axios from "axios";
import { Octokit } from "@octokit/rest";
import jwt from "jsonwebtoken";
import "dotenv/config";
import fs from "fs";
import path from "path";
import bodyParser from "body-parser";
import { analyzeReports } from "./util.js";

const app = express();
app.use(express.json());
app.use(bodyParser.json());

const installedRepositories = new Map(); 
const orgRepositories = new Map();


const privateKey = fs.readFileSync(path.join(process.cwd(), "digicert-codetrust.2025-02-24.private-key.pem"), "utf8");

const generateGitHubJWT = () => {
    const payload = {
        iat: Math.floor(Date.now() / 1000) - 60,
        exp: Math.floor(Date.now() / 1000) + 600,
        iss: process.env.GITHUB_APP_ID,
    };
    return jwt.sign(payload, privateKey, { algorithm: "RS256" });
};

const getOctokit = async (installationId) => {
    const jwtToken = generateGitHubJWT();
    const octokit = new Octokit({ auth: jwtToken });

    const { data } = await octokit.request("POST /app/installations/{installation_id}/access_tokens", {
        installation_id: installationId,
    });

    return new Octokit({ auth: data.token });
};

const addRepository = (repoFullName, orgName, installationId) => {
    installedRepositories.set(repoFullName, installationId);
    if (!orgRepositories.has(orgName)) {
        orgRepositories.set(orgName, []);
    }
    orgRepositories.get(orgName).push(repoFullName);
};

app.get("/checkIfAdded", (req, res) => {
    const { repoUrl } = req.query;
    if (installedRepositories.has(repoUrl)) {
        return res.json({ message: `✅ Repository ${repoUrl} has installed the app.` });
    }
    res.status(404).json({ message: `❌ Repository ${repoUrl} has NOT installed the app.` });
});

app.post("/addOrgWithRepos", (req, res) => {
  const { org, repos } = req.body;
  
  if (!org || !Array.isArray(repos) || repos.length === 0) {
      return res.status(400).json({ message: "❌ Invalid request. Provide 'org' and a non-empty array of 'repos'." });
  }

  if (!orgRepositories.has(org)) {
      orgRepositories.set(org, []);
  }

  const notInstalledRepos = repos.filter(repo => !installedRepositories.has(repo));

  if (notInstalledRepos.length > 0) {
      return res.status(400).json({
          message: `❌ The following repositories have not installed the app and cannot be added: ${notInstalledRepos.join(", ")}`
      });
  }

  repos.forEach((repo) => {
      if (!orgRepositories.get(org).includes(repo)) {
          orgRepositories.get(org).push(repo);
      }
  });

  res.json({ 
      message: `Added organization ${org} with repositories: ${repos.join(", ")}` 
  });
});


const fetchSecurityReports = async (octokit, owner, repo) => {
    try {
        const codeqlAlerts = await octokit.request("GET /repos/{owner}/{repo}/code-scanning/alerts", { owner, repo });
        const dependabotAlerts = await octokit.request("GET /repos/{owner}/{repo}/dependabot/alerts", { owner, repo });

        return {
            codeql: codeqlAlerts.data.length > 0 ? codeqlAlerts.data : "✅ No CodeQL alerts",
            dependabot: dependabotAlerts.data.length > 0 ? dependabotAlerts.data : "✅ No Dependabot alerts",
        };
    } catch (error) {
        console.error(`Error fetching security reports for ${owner}/${repo}:`, error);
        return { error: "Failed to fetch security reports" };
    }
};

app.get("/checkIfSafeToUse", async (req, res) => {
    const { org } = req.query;
    if (!orgRepositories.has(org)) {
        return res.status(404).json({ message: `❌ No repositories found for org: ${org}` });
    }

    const repos = orgRepositories.get(org);
    const reports = [];

    for (const repoFullName of repos) {
        const [owner, repo] = repoFullName.split("/");
        const installationId = installedRepositories.get(repoFullName);
        if (!installationId) continue;

        const octokit = await getOctokit(installationId);
        const report = await fetchSecurityReports(octokit, owner, repo);
        reports.push({ repoFullName, ...report });
    }

    res.json(reports);
});


const getOrgForRepo = (repoFullName) => {
  for (const [orgName, repos] of orgRepositories.entries()) {
      if (repos.includes(repoFullName)) {
          return orgName;
      }
  }
  return null;
};

const checkRepoSafetyAndReport = async (repoFullName) => {
  const installationId = installedRepositories.get(repoFullName);

  if (!installationId) {
      console.error(`⚠️ Repository ${repoFullName} not found in installed repositories.`);
      return;
  }

  let org = getOrgForRepo(repoFullName);

  if (!org) {
      console.error(`⚠️ Organization not found for repository: ${repoFullName}`);
      return;
  }

  try {
      const octokit = await getOctokit(installationId);
      const report = await fetchSecurityReports(octokit, ...repoFullName.split("/"));

      const isSafe = analyzeReports([{ repoFullName, ...report }])[0].safeToUse;

      await axios.post("https://localhost.digicert.dev/services/v2/order/certificate/123476/vmc/hosting", { "showSeal": isSafe });

      console.log(`📢 Report sent for org: ${org}, safe: ${isSafe}`);
  } catch (error) {
      console.error("Error checking repo safety and reporting:", error);
  }
};


app.post("/webhook", async (req, res) => {
    const event = req.headers["x-github-event"];
    const payload = req.body;

    console.log(`Received event: ${event}`);

    if (event === "installation") {
        payload.repositories.forEach((repo) => {
            addRepository(repo.full_name, payload.installation.account.login, payload.installation.id);
        });
    }

    if (event === "push" || event === "pull_request" || event === "dependabot_alert" || event === "codeql_alert") {
      const repoFullName = payload.repository.full_name;
      checkRepoSafetyAndReport(repoFullName);
    }

    res.status(200).send("Webhook received");
});

// 🏃 Start Express server
const PORT = 3000;
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
