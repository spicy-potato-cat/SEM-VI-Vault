# Unit 5: Examining Self-Defending Malware

> **Course**: Reverse Engineering and Malware Analysis (REMA)
> **Unit**: 5 — Examining Self-Defending Malware
> **Syllabus Duration**: 6 Hours
> **Reference Book**: Monnappa K A, *Learning Malware Analysis*, Packt Publishing, 2018

---

## Table of Contents

[[#1. How Malware Detects Debuggers and Protects Embedded Data]]
[[#2. Unpacking Malicious Software that Employs Process Hollowing]]
[[#3. Bypassing Malware Attempts to Detect and Evade the Analysis Toolkit]]
[[#4. Handling Code Misdirection Techniques — SEH and TLS Callbacks]]
[[#5. Unpacking Malicious Executables by Anticipating the Packer's Actions]]

---

## 1. How Malware Detects Debuggers and Protects Embedded Data

### 1.1 Why Malware Defends Itself

> **Definition**: **Self-defending malware** uses **anti-analysis techniques** to detect when it is being analyzed and either terminate, behave differently, or protect its payload from extraction.

Self-defending mechanisms fall into two categories:
- **Anti-debugging**: Detect and respond to debuggers
- **Data protection**: Encrypt or hide embedded payload until safe to deploy

### 1.2 Anti-Debugging Techniques

#### 1.2.1 IsDebuggerPresent

The simplest detection — checks the **PEB (Process Environment Block)** flag:

```asm
call IsDebuggerPresent    ; returns 1 if debugger attached
test eax, eax
jnz  debugger_detected    ; jump if non-zero (being debugged)
```

**Bypass**: Patch `IsDebuggerPresent` to always return 0, or use ScyllaHide plugin in x64dbg.

#### 1.2.2 CheckRemoteDebuggerPresent

```c
BOOL bDebugger = FALSE;
CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDebugger);
if (bDebugger) { ExitProcess(1); }
```

**Bypass**: Hook `CheckRemoteDebuggerPresent` to set the output boolean to FALSE.

#### 1.2.3 NtQueryInformationProcess

A lower-level native API call that queries **ProcessDebugPort**:

```c
NtQueryInformationProcess(hProcess, ProcessDebugPort, &debugPort, sizeof(DWORD), NULL);
// If debugPort != 0, a debugger is attached
```

**Bypass**: Hook `ntdll!NtQueryInformationProcess` to return 0 for ProcessDebugPort.

#### 1.2.4 PEB Manual Check (Direct)

Some malware reads the PEB directly without API calls (harder to hook):

```asm
mov  eax, fs:[0x30]       ; EAX = PEB address (x86)
movzx eax, byte [eax+2]   ; PEB.BeingDebugged byte at offset 2
test eax, eax
jnz  exit_or_decrypt       ; being debugged — bail out
```

In x64: `gs:[0x60]` points to the PEB.

#### 1.2.5 Timing Checks (rdtsc / GetTickCount)

Debuggers slow execution. Malware measures elapsed time between two points:

```asm
rdtsc                     ; Read TSC into EDX:EAX (cycle count)
; ... some code ...
rdtsc                     ; Read again
sub  eax, saved_tsc       ; compute delta
cmp  eax, threshold       ; if delta too large → debugger present
jg   cleanup_and_exit
```

**GetTickCount / QueryPerformanceCounter** used similarly — if time delta exceeds expected value, debugger assumed.

#### 1.2.6 Detecting Hardware Breakpoints

Hardware breakpoints are stored in **DR0–DR7 (Debug Registers)**. Malware reads them:

```c
GetThreadContext(GetCurrentThread(), &ctx);
if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) {
    // Hardware breakpoint detected
    ExitProcess(0);
}
```

**Bypass**: Clear DR0–DR7 before execution, or use virtual (memory) breakpoints.

#### 1.2.7 INT3 / Software Breakpoint Detection

Software breakpoints replace an opcode with `0xCC` (INT 3). Malware can detect this by computing **checksums of its own code sections** — if the checksum changes, an INT 3 was placed.

### 1.3 Data Protection — Embedded Payload Encryption

| Method | Description |
|--------|-------------|
| **XOR encoding** | Simple byte-by-byte XOR with a key or key schedule |
| **RC4** | Stream cipher; key stored in `.data` or derived at runtime |
| **AES** | Stronger encryption; key may be hardcoded or derived |
| **Custom encoding** | ROT-N, base64, or custom substitution tables |

**XOR decryption loop (common pattern):**
```asm
mov  esi, offset encrypted_payload   ; source
mov  edi, offset output_buffer       ; destination
mov  ecx, payload_size               ; byte count
mov  al,  0x55                       ; XOR key

decrypt_loop:
    mov  bl, [esi]
    xor  bl, al
    mov  [edi], bl
    inc  esi
    inc  edi
    dec  ecx
    jnz  decrypt_loop
```

**Analysis approach**: Set a breakpoint just **after** the decryption loop; dump the output buffer to obtain the decrypted payload.

---

## 2. Unpacking Malicious Software that Employs Process Hollowing

### 2.1 What is Process Hollowing?

> **Definition**: **Process hollowing** (also called *Process Replacement* or *RunPE*) is a code injection technique where malware creates a legitimate process in a **suspended state**, hollows out its memory, injects a malicious executable into the vacated space, and resumes it — so malicious code runs under a trusted process identity.

### 2.2 Process Hollowing Steps

```
1. CreateProcess(target, CREATE_SUSPENDED)
   └── Start legitimate process (e.g., svchost.exe) in suspended state

2. NtUnmapViewOfSection
   └── Unmap / remove original executable from the suspended process

3. VirtualAllocEx → WriteProcessMemory
   └── Allocate memory in hollow process; write malicious PE into it

4. SetThreadContext
   └── Modify EIP/RIP to point to malicious entry point

5. ResumeThread
   └── Resume execution — malicious code runs under the trusted process name
```

### 2.3 Key APIs in Process Hollowing

| API | Purpose |
|-----|---------|
| `CreateProcess` with `CREATE_SUSPENDED` | Create hollow container process |
| `NtUnmapViewOfSection` | Remove original executable memory |
| `VirtualAllocEx` | Allocate memory in target process |
| `WriteProcessMemory` | Write malicious PE into target process |
| `GetThreadContext` / `SetThreadContext` | Modify EIP to point to malicious entry |
| `ResumeThread` | Start execution of injected code |

### 2.4 Detecting Process Hollowing

| Indicator | Detection Method |
|-----------|-----------------|
| Suspicious API sequence | `CreateProcess(SUSPENDED)` → `NtUnmapViewOfSection` → `VirtualAllocEx` |
| Process image mismatch | Memory contents don't match on-disk executable |
| Hollow process | Process shows no mapped PE image |

**Tools**: Process Hacker (memory map view); Volatility `malfind` plugin.

### 2.5 Unpacking from Process Hollowing

1. Set breakpoint on `ResumeThread` in x64dbg
2. When triggered — before resuming — dump the target process memory
3. The dump contains the injected PE
4. Fix PE headers using **Scylla** / **ImportREC**
5. Load fixed PE in IDA/Ghidra for static analysis

---

## 3. Bypassing Malware Attempts to Detect and Evade the Analysis Toolkit

### 3.1 Environment / Sandbox Detection

| Check | How Malware Does It |
|-------|---------------------|
| **VM registry artifacts** | Checks for `HKLM\SOFTWARE\VMware, Inc.`, `HKLM\SOFTWARE\Oracle\VirtualBox` |
| **VM process/files** | Looks for `vmtoolsd.exe`, `vboxservice.exe` |
| **VM device names** | `CreateFile("\\.\VMHGFS")` or `"\\.\VBoxGuest"` |
| **CPUID hypervisor bit** | `CPUID EAX=1`; ECX bit 31 set in VMs |
| **Short uptime** | `GetTickCount` < 10 min suggests sandbox |
| **No mouse movement** | Sandboxes don't simulate user interaction |
| **Known sandbox usernames** | Checks for `SANDBOX`, `MALTEST`, `VIRUS`, `CUCKOO` |
| **Low process count** | Sandbox has fewer processes than a real machine |

### 3.2 Analysis Tool Detection

Malware enumerates running processes to detect analyst tools:

```c
HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
Process32First(snap, &pe);
do {
    if (strcmp(pe.szExeFile, "procmon.exe") == 0 ||
        strcmp(pe.szExeFile, "wireshark.exe") == 0 ||
        strcmp(pe.szExeFile, "x64dbg.exe") == 0) {
        ExitProcess(0);
    }
} while (Process32Next(snap, &pe));
```

### 3.3 Bypass Techniques

| Technique | Description |
|-----------|-------------|
| **Rename tools** | Rename `procmon.exe` → `svchost32.exe` |
| **ScyllaHide plugin** | x64dbg plugin; hides debugger presence from many checks |
| **Patch detection code** | NOP out the detection comparison and jump in the malware |
| **Remove VM artifacts** | Remove VMware Tools; delete/rename VM registry keys |
| **VM hardening scripts** | Scripts like VBoxHardenedLoader or VMware hardening tools |

---

## 4. Handling Code Misdirection Techniques — SEH and TLS Callbacks

### 4.1 Structured Exception Handling (SEH)

> **Definition**: **Structured Exception Handling (SEH)** is a Windows mechanism for handling hardware and software exceptions via a per-thread chain of exception handler records stored on the stack.

**SEH chain structure (x86):**
- `FS:[0]` → pointer to `EXCEPTION_REGISTRATION` record
- Each record: `{ next_ptr, handler_function_ptr }`

### 4.2 SEH as Code Misdirection

Malware uses SEH to redirect execution in ways that confuse both disassemblers and debuggers:

```asm
push offset real_code_handler    ; register custom exception handler
push fs:[0]
mov  fs:[0], esp                 ; install as top of SEH chain

; Intentionally trigger exception
xor  eax, eax
div  eax                         ; divide by zero → triggers exception
; Disassembler thinks code continues here (dead code)
; Actual execution → OS invokes real_code_handler

real_code_handler:
; true next instruction (hidden from linear disassembly)
```

**Why it fools disassemblers**: Linear disassemblers don't model exception dispatch — they show the dead bytes after `DIV EAX` as instructions.

**Bypass in debugger:**
- x64dbg: `Options → Preferences → Exceptions` → pass exception to malware; trace to handler
- Manually follow `FS:[0]` handler chain to find real execution target

### 4.3 TLS (Thread Local Storage) Callbacks

> **Definition**: **TLS Callbacks** are functions registered in the PE's **TLS Directory** that execute **before the entry point** (WinMain/DllMain). Malware uses them to run anti-analysis checks before the analyst can set a breakpoint at main.

**TLS callback location in PE:**
```
PE Optional Header → Data Directory[9] → TLS Directory → AddressOfCallBacks array
```

**Analysis approach:**
1. **IDA Pro**: `View → Open Subviews → Segments` → look for `.tls` section; callbacks listed
2. **x64dbg**: `Options → Preferences → Events` → enable *Break on TLS callbacks*
3. Alternatively: `Debug → Break at TLS Callbacks` to intercept before entry point

---

## 5. Unpacking Malicious Executables by Anticipating the Packer's Actions

### 5.1 Packer Execution Flow

```
PACKED PE on disk:
  ├── Packer stub (visible, executable section)
  └── Encrypted/compressed original PE (data blob)

At runtime:
  STEP 1: Stub allocates memory (VirtualAlloc)
  STEP 2: Stub decrypts/decompresses original PE into allocated memory
  STEP 3: Stub reconstructs import table (LoadLibrary + GetProcAddress)
  STEP 4: Stub jumps to OEP (Original Entry Point)
  
  Result: Unpacked PE lives only in memory
```

### 5.2 Generic Unpacking Steps

| Step | Action |
|------|--------|
| 1. Load packed sample | Load in x64dbg; pause at packer stub entry |
| 2. Break on VirtualAlloc | Stub allocates space for unpacked code |
| 3. Note allocated region | Address where unpacked PE lands |
| 4. Set execute memory breakpoint | Fires when OEP is reached |
| 5. Run to OEP | Execution breaks at first instruction of original code |
| 6. Dump and fix | Use Scylla → Get Imports → Fix Dump → save unpacked PE |

### 5.3 Recognizing OEP Signatures

| Compiler | OEP Signature Pattern |
|---------|----------------------|
| **MSVC** | `push ebp; mov ebp, esp; sub esp, xx` |
| **MinGW/GCC** | `push -1; push offset data; push offset handler` |
| **Delphi** | `push ebp; mov ebp, esp; add esp, -xxxxxxxx` |
| **Generic packed** | `POPAD` instruction followed by a long JMP (PUSHAD/POPAD trick) |

> **POPAD trick**: Simple packers save registers with `PUSHAD` at start, unpack, then `POPAD` before jumping to OEP. Break just after `POPAD` to reach OEP quickly.

### 5.4 Dump and Fix Imports

```
1. After reaching OEP: process has unpacked PE in memory
2. Use Scylla (x64dbg plugin):
   a. Enter OEP address
   b. Get Imports (auto-scan IAT)
   c. Fix Dump → produces valid PE file on disk
3. Load fixed PE in IDA/Ghidra for static analysis
```

### 5.5 Dealing with Difficult Packers

| Challenge | Approach |
|-----------|---------|
| **Multi-stage unpacking** | Multiple decrypt loops; dump at final stage only |
| **Anti-dump** (PE header erasure) | Use `pe_sieve` or manually reconstruct DOS/PE headers |
| **TLS-based first stage** | Intercept at TLS callback (before entry point) |
| **Import obfuscation** | IAT uses hash-based resolution; manually resolve via API hash lookup |
| **VM protectors** (VMProtect, Themida) | Custom bytecode VM; requires emulation or symbolic execution |

### 5.6 YARA Rules After Unpacking

Write detection rules from strings/patterns found in the unpacked payload:

```yara
rule Unpacked_Keylogger {
    meta:
        description = "Detects keylogger after unpacking"
    strings:
        $hook_api = "SetWindowsHookExA" ascii
        $log_path = "C:\\Windows\\Temp\\keylog.txt" ascii
        $xor_key  = { 55 AA 55 AA }
    condition:
        all of them
}
```
