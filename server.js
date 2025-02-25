import express from "express";
import axios from "axios";
import { Octokit } from "@octokit/rest";
import jwt from "jsonwebtoken";
import "dotenv/config";
import fs from "fs";
import path from "path";
import bodyParser from "body-parser";

const app = express();
app.use(express.json());
app.use(bodyParser.json());

// 🏪 In-memory storage for tracking repositories & orgs
const installedRepositories = new Map(); // repoFullName -> installationId
const orgRepositories = new Map(); // orgName -> [repoFullNames]

// installedRepositories.set("dc-codetrust/backend-service", 134);
// installedRepositories.set("dc-codetrust/frontend-app", 32423);

// 📜 Read private key for authentication
const privateKey = fs.readFileSync(path.join(process.cwd(), "digicert-codetrust.2025-02-24.private-key.pem"), "utf8");

// 🔐 Generate JWT for GitHub App authentication
const generateGitHubJWT = () => {
    const payload = {
        iat: Math.floor(Date.now() / 1000) - 60,
        exp: Math.floor(Date.now() / 1000) + 600,
        iss: process.env.GITHUB_APP_ID,
    };
    return jwt.sign(payload, privateKey, { algorithm: "RS256" });
};

// 🛠️ Initialize Octokit for a given installation
const getOctokit = async (installationId) => {
    const jwtToken = generateGitHubJWT();
    const octokit = new Octokit({ auth: jwtToken });

    const { data } = await octokit.request("POST /app/installations/{installation_id}/access_tokens", {
        installation_id: installationId,
    });

    return new Octokit({ auth: data.token });
};

// 🔄 Store repository installation details
const addRepository = (repoFullName, orgName, installationId) => {
    installedRepositories.set(repoFullName, installationId);
    if (!orgRepositories.has(orgName)) {
        orgRepositories.set(orgName, []);
    }
    orgRepositories.get(orgName).push(repoFullName);
};

// 🎯 API: Check if a repository has installed the GitHub App
app.get("/checkIfAdded", (req, res) => {
    const { repoUrl } = req.query;
    if (installedRepositories.has(repoUrl)) {
        return res.json({ message: `✅ Repository ${repoUrl} has installed the app.` });
    }
    res.status(404).json({ message: `❌ Repository ${repoUrl} has NOT installed the app.` });
});

// 🎯 API: Add an organization and its repositories
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

  // Add only existing installed repositories to the organization
  repos.forEach((repo) => {
      if (!orgRepositories.get(org).includes(repo)) {
          orgRepositories.get(org).push(repo);
      }
  });

  res.json({ 
      message: `✅ Added organization ${org} with repositories: ${repos.join(", ")}` 
  });
});


// 🔍 Fetch security reports for a repository
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

// 🎯 API: Check if an org is safe to use (aggregates alerts for all repos)
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

    res.json({ org, reports });
});

// 📦 Webhook handler for repository installation
app.post("/webhook", async (req, res) => {
    const event = req.headers["x-github-event"];
    const payload = req.body;

    console.log(`📩 Received event: ${event}`);

    if (event === "installation") {
        payload.repositories.forEach((repo) => {
            addRepository(repo.full_name, payload.installation.account.login, payload.installation.id);
        });
    }

    if (event === "push" || event === "pull_request" || event === "dependabot_alert" || event === "codeql_alert") {
        const repo = payload.repository.full_name;
        const installationId = payload.installation.id;

        try {
            const octokit = await getOctokit(installationId);
            await fetchSecurityReports(octokit, ...repo.split("/"));
        } catch (error) {
            console.error("Error fetching reports:", error);
        }
    }

    res.status(200).send("✅ Webhook received");
});

// 🏃 Start Express server
const PORT = 3000;
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
