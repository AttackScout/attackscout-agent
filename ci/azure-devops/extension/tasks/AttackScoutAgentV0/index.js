// Azure Pipelines task for attackscout-agent. No dependency: the agent
// passes the inputs as INPUT_<NAME> variables and reads the result from
// ##vso logging commands.
"use strict";

const { spawnSync } = require("child_process");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");

const REPO = "https://github.com/AttackScout/attackscout-agent/releases/download";

function input(name, def) {
  const v = process.env["INPUT_" + name.toUpperCase()];
  return v === undefined || v === "" ? def : v;
}

function fail(msg) {
  console.log("##vso[task.logissue type=error]" + msg);
  console.log("##vso[task.complete result=Failed;]" + msg);
  process.exit(1);
}

async function get(url) {
  const res = await fetch(url, { redirect: "follow" });
  if (!res.ok) {
    throw new Error(url + ": HTTP " + res.status);
  }
  return Buffer.from(await res.arrayBuffer());
}

function target() {
  const osName = { linux: "linux", darwin: "darwin", win32: "windows" }[process.platform];
  const arch = { x64: "amd64", arm64: "arm64" }[process.arch];
  if (!osName || !arch) {
    fail("unsupported agent: " + process.platform + "/" + process.arch);
  }
  return { osName, arch, ext: osName === "windows" ? "zip" : "tar.gz" };
}

async function install(version) {
  const t = target();
  const name = `attackscout-agent_${version}_${t.osName}_${t.arch}.${t.ext}`;
  const base = `${REPO}/v${version}`;
  const dir = path.join(process.env.AGENT_TEMPDIRECTORY || os.tmpdir(), "attackscout-agent-" + version);
  fs.mkdirSync(dir, { recursive: true });
  const archive = await get(`${base}/${name}`);
  const sums = (await get(`${base}/checksums.txt`)).toString("utf8");
  const want = sums.split("\n").map((l) => l.trim().split(/\s+/)).find((p) => p[1] === name);
  const got = crypto.createHash("sha256").update(archive).digest("hex");
  if (!want || want[0] !== got) {
    fail("checksum mismatch for " + name);
  }
  const file = path.join(dir, name);
  fs.writeFileSync(file, archive);
  // tar reads .tar.gz everywhere and .zip on Windows (bsdtar)
  const r = spawnSync("tar", ["-xf", file, "-C", dir], { stdio: "inherit" });
  if (r.status !== 0) {
    fail("cannot extract " + name);
  }
  return path.join(dir, t.osName === "windows" ? "attackscout-agent.exe" : "attackscout-agent");
}

function run(bin, args) {
  console.log("> attackscout-agent " + args.join(" "));
  const r = spawnSync(bin, args, { stdio: "inherit" });
  return r.status === null ? 2 : r.status;
}

function split(s) {
  return (s.match(/(?:[^\s"]+|"[^"]*")+/g) || []).map((a) => a.replace(/^"|"$/g, ""));
}

async function main() {
  const version = input("version", "0.2.0").replace(/^v/, "");
  const target = input("path", process.env.BUILD_SOURCESDIRECTORY || ".");
  const failOn = input("failOn", "high");
  const extra = split(input("args", ""));
  const sarifDir = input("sarifDir", path.join(process.env.BUILD_ARTIFACTSTAGINGDIRECTORY || ".", "CodeAnalysisLogs"));
  const bin = await install(version);

  if (input("dbUpdate", "true") === "true") {
    const eco = input("ecosystems", "");
    const code = run(bin, eco ? ["db", "update", "--ecosystems", eco] : ["db", "update"]);
    if (code !== 0) {
      console.log("##vso[task.logissue type=warning]some databases could not be downloaded");
    }
  }

  fs.mkdirSync(sarifDir, { recursive: true });
  const sarif = path.join(sarifDir, "attackscout-agent.sarif");
  const common = ["--root", target, "--project", target, ...extra];
  run(bin, ["scan", ...common, "--format", "sarif", "--output", sarif]);
  console.log(`##vso[artifact.upload containerfolder=CodeAnalysisLogs;artifactname=CodeAnalysisLogs]${sarif}`);
  const code = run(bin, ["scan", ...common, "--fail-on", failOn, "--no-audit-link"]);
  if (code === 1) {
    fail(`attackscout-agent found at least one ${failOn} finding`);
  } else if (code !== 0) {
    fail("attackscout-agent failed with code " + code);
  }
  console.log("##vso[task.complete result=Succeeded;]done");
}

main().catch((e) => fail(e.message));
