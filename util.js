export const analyzeReports = (reportList) => {
    if (!Array.isArray(reportList) || reportList.length === 0) {
        throw new Error("❌ Invalid input: reportList must be a non-empty array.");
    }

    return reportList.map(({ repoFullName, codeql, dependabot }) => ({
        repoFullName,
        safeToUse: codeql.includes("✅") && dependabot.includes("✅"),
        message: (!codeql.includes("✅") || !dependabot.includes("✅"))
            ? `❌ ${repoFullName} is NOT safe to use due to security alerts.`
            : `✅ ${repoFullName} is safe to use.`,
    }));
};