# PELens

When you receive a suspicious executable -- from an email attachment, an incident report, a malware feed, or just a binary you don't recognize -- the first question is always: **what does this file actually do?**

Running it is not an option. You need to look inside without executing it.

`PELens` is a static analysis tool that does exactly that. It reads a Windows PE binary (`.exe`, `.dll`, `.sys`) and extracts everything structurally meaningful: cryptographic hashes, compile timestamp, section layout, entropy, security mitigations, and the full list of imported Windows API functions -- all without executing a single instruction of the target file.

The second component, `ai_analyzer.py`, takes that extracted data and sends it to an LLM to produce a written triage report: what the binary is likely capable of, what stands out as suspicious, and what an analyst should look at next.

---

## What gets extracted

**From the file itself:**
- SHA-256 hash and imphash (for cross-referencing with VirusTotal, MalwareBazaar, or internal databases)
- Whether it's a 32-bit or 64-bit binary
- Compile timestamp (UTC)
- File size and whether there's data appended after the last section (an "overlay" -- common in droppers)

**From the section table:**
- Name, virtual size, raw size, and Shannon entropy for each section
- Read/Write/Execute permissions -- an RWX section is a strong indicator of shellcode injection or unpacking
- High-entropy sections that suggest packed or encrypted content

**From the Import Address Table:**
- Every DLL and function the binary imports, categorized by capability:
  - `INJECTION` -- VirtualAlloc, WriteProcessMemory, CreateRemoteThread, etc.
  - `ANTI_DEBUG` -- IsDebuggerPresent, CheckRemoteDebuggerPresent, etc.
  - `DYN_RESOLVE` -- GetProcAddress, LoadLibrary (used by packers to hide their real imports)
  - `PERSISTENCE` -- registry write APIs, service creation
  - `NETWORK` -- WinInet, Winsock
  - `CRYPTO` -- CryptEncrypt, CryptDecrypt, CryptGenKey

**Security mitigations in the PE header:**
- ASLR, DEP/NX, CFG -- their absence on a modern binary is itself a finding

**The entry point:**
- Which section the entry point lands in -- if it's not `.text`, that's unusual and worth investigating

---

## The two-step workflow

```
pelens.exe suspicious.exe         (1) parse the binary
        |
        v
pelens_report.json                structured data, no interpretation yet
        |
        v
python ai_analyzer.py --model ... (2) send to LLM for analysis
        |
        v
PELENS_AI_REPORT.md               written triage report
```

You can stop after step one if you just want the raw data. The JSON output is clean and can feed into other tools, scripts, or SIEM pipelines.

---

## Building the parser

**Requirements:** Windows, GCC (MinGW/MSYS2) or MSVC.

```cmd
# GCC
gcc -W -Wall -O2 -municode -o pelens.exe pelens.c -lbcrypt -lm

# MSVC (from a Developer Command Prompt)
cl.exe /W4 /O2 /Fe:pelens.exe pelens.c
```

---

## Running the parser

```cmd
pelens.exe target.exe
pelens.exe target.exe -o report.json
```

Example output against a clean Windows calculator binary:

```
=======================================================
  pelens -- PE Static Analysis Tool
  Fast. Portable. Forensic-Grade.
=======================================================
[*] Target Binary                   : calc.exe
[+] SHA-256                         : 621ba3934afc45c35a4ee16386f4da30119f39fa243e8dc8fef3491a76f829d8
[+] Architecture                    : AMD64 (PE32+)
[+] Compile Timestamp               : 2100-05-10 00:49:47 UTC
[+] Total Sections                  : 7
[+] File Size                       : 49152 bytes
[+] Entry Point RVA                 : 0x00001740 (.text)
[+] Imphash                         : 600f640ef810608f99522e2e982bb92b
[+] Security Mitigations            : ASLR: YES | DEP: YES | CFG: YES
[+] Overlay Detected                : None (0 bytes)

+---------------------------------------------------------------------------+
| NAME     | VIRT SIZE  | RAW SIZE   | ENTROPY  | PERMS  | FLAGS            |
+---------------------------------------------------------------------------+
| .text    | 3248       | 4096       | 4.9982   | R-X    | OK               |
| .rdata   | 3560       | 4096       | 3.8611   | R--    | OK               |
| .data    | 1728       | 4096       | 0.0614   | RW-    | OK               |
| .rsrc    | 18192      | 20480      | 2.8055   | R--    | OK               |
+---------------------------------------------------------------------------+

--- [ IMPORT ADDRESS TABLE (IAT) SUMMARY ] ---

[+] DLL: KERNEL32.dll (Ordinals: 0)
    |-- GetCurrentProcessId
    |-- TerminateProcess
    \-- ... and 10 more functions.
```

---

## Running the AI analyzer

Install dependencies:
```cmd
pip install requests
```

Set your API key as an environment variable. Use `setx` so it persists across terminals:
```cmd
setx GEMINI_API_KEY your_key_here
```
Then open a new terminal and run:

```cmd
python ai_analyzer.py --model gemini-2.0-flash
```

The script reads `pelens_report.json` from the current directory by default and writes the report to `PELENS_AI_REPORT.md`.

### What the AI report looks like

The output is a structured markdown document with two parts:

**Part 1 -- Deterministic findings.** These come directly from the parsed data with no LLM involved: RWX sections, high-entropy sections, suspicious API categories present, missing mitigations, entry point anomalies. This section is factual and verifiable.

**Part 2 -- AI interpretation.** The LLM explains what the capability profile implies, what combinations of APIs are particularly suspicious together, and what an analyst should focus on in dynamic analysis. Each finding includes a confidence rating (Low / Medium / High). The report ends with an explicit disclaimer that AI output requires verification.

The system prompt instructs the model not to name threat actors, not to invent malware family classifications, and to say "insufficient data" when the data doesn't support a conclusion.

### Choosing a provider

The script auto-detects which provider to use based on which environment variable is set. Detection order: `OPENAI_API_KEY` -> `GEMINI_API_KEY` -> `OPENROUTER_API_KEY` -> `GROQ_API_KEY` -> `ANTHROPIC_API_KEY` -> Ollama (no key needed).

You can also specify explicitly:

```cmd
python ai_analyzer.py --provider openai     --model gpt-4o
python ai_analyzer.py --provider gemini     --model gemini-2.0-flash
python ai_analyzer.py --provider anthropic  --model claude-3-5-sonnet-20241022
python ai_analyzer.py --provider groq       --model llama-3.1-70b-versatile
python ai_analyzer.py --provider ollama     --model llama3
python ai_analyzer.py --provider openrouter --model meta-llama/llama-3.1-8b-instruct
```

For a Turkish report:
```cmd
python ai_analyzer.py --model gemini-2.0-flash --lang tr
```

For a custom self-hosted endpoint (vLLM, LM Studio, etc.):
```cmd
python ai_analyzer.py --base-url http://localhost:8000/v1 --model my-local-model
```

Full options:

```
--provider     Provider name (auto-detected if omitted)
--model        Model identifier, required -- no default
--base-url     Override the provider base URL
--input        Input JSON file (default: pelens_report.json)
--output       Output markdown file (default: PELENS_AI_REPORT.md)
--lang         en or tr (default: en)
--key          API key, last resort -- use environment variable instead
```

### A note on privacy

When using a cloud provider, the target file's basename, section names, and import table are sent to a third-party API. The full file path is stripped before the prompt is built. If the file itself is sensitive or confidential, use Ollama for fully local analysis -- it runs on your machine and nothing leaves your network.

---

## Limitations

**Static analysis only.** This tool reads the PE structure -- it does not run, emulate, or unpack the binary. If the sample is packed (UPX, custom packer), you will see the packer's import table, not the payload's. Use the output as a starting point, not a final answer.

**Windows only.** The parser uses the Windows file mapping API and the Windows CNG library for hashing. A portable version is not currently planned.

**The packing heuristic has false positives.** `.rsrc` sections containing compressed icons or manifests can trigger the high-entropy flag. Treat it as a prompt to look closer, not a verdict.

**AI output is not authoritative.** The report is a triage aid. Do not block, quarantine, or attribute based solely on what the model says.

---

## License

MIT
