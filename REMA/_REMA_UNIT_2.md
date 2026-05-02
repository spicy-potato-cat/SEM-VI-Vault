# Unit 2: Reversing Malicious Code

> **Course**: Reverse Engineering and Malware Analysis (REMA)
> **Unit**: 2 — Reversing Malicious Code
> **Syllabus Duration**: 6 Hours
> **Reference Book**: Monnappa K A, *Learning Malware Analysis*, Packt Publishing, 2018

---

## Table of Contents

[[#1. Core x86 Assembly Concepts]]
[[#2. Key Assembly Logic Structures with a Disassembler]]
[[#3. Program Control Flow and Decision Points]]
[[#4. Common Malware Characteristics at the Windows API Level]]
[[#5. x64 Assembly — Extending the Analysis]]

---

## 1. Core x86 Assembly Concepts

> **Definition**: **Assembly language** is a low-level programming language that corresponds closely to the machine code instructions of a specific processor architecture. Understanding x86 assembly is essential for reverse engineering malware on Windows.

### 1.1 CPU Architecture Fundamentals

```
┌────────────────────────────────────────────────────────────┐
│                   x86 CPU INTERNALS                        │
├────────────────────────────────────────────────────────────┤
│                                                            │
│  REGISTERS                        MEMORY                   │
│  ├── General Purpose    │         ├── Stack               │
│  │   EAX, EBX, ECX, EDX│         ├── Heap                │
│  ├── Index/Pointer      │         ├── Code segment        │
│  │   ESI, EDI           │         └── Data segment        │
│  ├── Stack Registers    │                                  │
│  │   ESP, EBP           │         FLAGS REGISTER          │
│  └── Instruction Ptr    │         ├── ZF (Zero Flag)      │
│      EIP                │         ├── SF (Sign Flag)      │
│                         │         ├── CF (Carry Flag)      │
│                         │         └── OF (Overflow Flag)  │
└────────────────────────────────────────────────────────────┘
```

### 1.2 General Purpose Registers

| Register | Full Name | Primary Conventional Use |
|----------|-----------|--------------------------|
| **EAX** | Accumulator | Arithmetic operations; function return value |
| **EBX** | Base | Pointer to data in memory (base addressing) |
| **ECX** | Counter | Loop counter; string/memory operation count |
| **EDX** | Data | I/O port operations; extends EAX in multiply/divide |
| **ESI** | Source Index | Source pointer for string/memory operations |
| **EDI** | Destination Index | Destination pointer for string/memory operations |
| **ESP** | Stack Pointer | Points to the top of the stack (current stack frame) |
| **EBP** | Base Pointer | Points to the base of the current stack frame |
| **EIP** | Instruction Pointer | Points to the next instruction to execute |

> **Important for RE**: `EAX` always holds the **return value** of a function. When analyzing what a function does, check what's in EAX just before the `RET` instruction.

### 1.3 Register Sub-divisions (16-bit and 8-bit)

| 32-bit | 16-bit | 8-bit High | 8-bit Low |
|--------|--------|-----------|----------|
| EAX | AX | AH | AL |
| EBX | BX | BH | BL |
| ECX | CX | CH | CL |
| EDX | DX | DH | DL |

### 1.4 The Stack

> **Definition**: The **stack** is a Last-In-First-Out (LIFO) memory region used for function calls, local variables, and parameter passing.

```
HIGH ADDRESS ──────────────────────
              │  Calling function  │
              │  saved EBP         │
              │  return address    │ ◄── pushed by CALL instruction
              │  local variables   │ ◄── ESP - n
              │  ...               │
LOW ADDRESS  ─────── ESP ───────────  (top of stack grows downward)
```

**Key stack instructions:**

| Instruction | Effect |
|-------------|--------|
| `PUSH val` | Decrement ESP by 4; write `val` to [ESP] |
| `POP reg` | Read [ESP] into `reg`; increment ESP by 4 |
| `CALL addr` | PUSH EIP (return address); JMP to `addr` |
| `RET` | POP saved EIP; JMP to it (return to caller) |

### 1.5 Common x86 Instructions

**Data movement:**

| Instruction | Description |
|-------------|-------------|
| `MOV dst, src` | Copy value from src to dst |
| `LEA dst, [mem]` | Load effective address (pointer arithmetic) |
| `XCHG a, b` | Swap values of a and b |
| `MOVZX dst, src` | Move with zero extension |

**Arithmetic and logic:**

| Instruction | Description |
|-------------|-------------|
| `ADD dst, src` | dst = dst + src |
| `SUB dst, src` | dst = dst - src |
| `MUL src` | Unsigned multiply (EAX × src) |
| `INC reg` | Increment by 1 |
| `DEC reg` | Decrement by 1 |
| `AND dst, src` | Bitwise AND |
| `OR dst, src` | Bitwise OR |
| `XOR dst, src` | Bitwise XOR (XOR reg, reg → zero register) |
| `NOT reg` | Bitwise NOT (one's complement) |
| `SHL/SHR reg, n` | Shift left / right by n bits |

**Comparison and flags:**

| Instruction | Description |
|-------------|-------------|
| `CMP a, b` | Compute a - b; set flags; discard result |
| `TEST a, b` | Compute a AND b; set flags; discard result |

> **Malware trick**: `XOR EAX, EAX` is the fastest way to zero out EAX. `TEST EAX, EAX` followed by `JZ` checks if EAX is zero (function returned NULL/0 = failure).

### 1.6 Calling Conventions

> **Definition**: A **calling convention** defines how function arguments are passed (stack vs. registers), who cleans the stack (caller vs. callee), and where the return value is stored.

| Convention | How Arguments Passed | Stack Cleanup | Used By |
|-----------|---------------------|--------------|---------|
| **cdecl** | Right-to-left on stack | Caller | C standard library |
| **stdcall** | Right-to-left on stack | Callee | Win32 API |
| **fastcall** | First 2 in ECX/EDX; rest on stack | Callee | Optimized internal functions |

**Stack frame setup (function prologue):**
```asm
PUSH EBP          ; Save caller's base pointer
MOV  EBP, ESP     ; Set up new base pointer
SUB  ESP, 0x10    ; Allocate space for local variables
```

**Stack frame teardown (function epilogue):**
```asm
MOV  ESP, EBP     ; Restore stack pointer
POP  EBP          ; Restore caller's base pointer
RET               ; Return to caller
```

---

## 2. Key Assembly Logic Structures with a Disassembler

### 2.1 Using a Disassembler

> **Definition**: A **disassembler** converts binary machine code back into assembly language instructions that a human analyst can read. Key tools include **IDA Pro**, **Ghidra**, and **Binary Ninja**.

**Key disassembler views:**
- **Listing view**: Linear sequence of instructions with addresses
- **Graph view**: Control flow graph (CFG) showing branches visually
- **Decompiler view** (Ghidra/IDA Hex-Rays): Pseudo-C code reconstructed from assembly

### 2.2 Recognizing If-Else Structures

**C code:**
```c
if (condition) { /* true block */ } else { /* false block */ }
```
**Assembly pattern:**
```asm
CMP  EAX, 0          ; compare EAX with 0
JZ   else_block      ; jump to else if equal (ZF=1)
; --- true block ---
JMP  end_if
else_block:
; --- false block ---
end_if:
```

> In the CFG, this looks like a **diamond shape**: one node splits into two branches that reconverge.

### 2.3 Recognizing Loops

**C code:**
```c
for (int i = 0; i < 10; i++) { /* body */ }
```
**Assembly pattern:**
```asm
MOV  ECX, 0          ; i = 0
loop_start:
CMP  ECX, 10         ; compare i with 10
JGE  loop_end        ; exit if i >= 10
; --- loop body ---
INC  ECX             ; i++
JMP  loop_start
loop_end:
```

> **LOOP instruction**: x86 has a dedicated `LOOP label` instruction that decrements ECX and jumps if ECX ≠ 0. Malware often uses this for counting iterations (e.g., XOR decryption loops).

### 2.4 Recognizing Switch Statements

A switch statement often compiles to a **jump table** — an array of code pointers indexed by the switch variable:
```asm
CMP  EAX, 4           ; check if above range
JA   default_case
JMP  [jump_table + EAX*4]  ; indirect jump via table
```
In IDA/Ghidra, this appears as a single node with **multiple outgoing edges** to many case blocks.

### 2.5 Recognizing Function Calls

```asm
PUSH 0x0             ; 3rd argument
PUSH offset "key"    ; 2nd argument
PUSH EAX             ; 1st argument (ECX in fastcall)
CALL CryptEncrypt     ; call function
ADD  ESP, 0xC         ; caller cleans stack (cdecl) -- or not (stdcall)
```

> **Analysis tip**: The **number of PUSH instructions before a CALL** tells you how many arguments the function takes. The `ADD ESP, N` after `CALL` (cdecl) where N = 4 × number of args confirms this.

---

## 3. Program Control Flow and Decision Points

### 3.1 Conditional Jump Instructions

| Instruction | Condition | Flag Check |
|-------------|-----------|-----------|
| `JZ / JE` | Jump if zero / equal | ZF = 1 |
| `JNZ / JNE` | Jump if not zero / not equal | ZF = 0 |
| `JG / JNLE` | Jump if greater (signed) | ZF=0 and SF=OF |
| `JL / JNGE` | Jump if less (signed) | SF ≠ OF |
| `JA / JNBE` | Jump if above (unsigned) | CF=0 and ZF=0 |
| `JB / JNAE` | Jump if below (unsigned) | CF = 1 |
| `JS` | Jump if negative | SF = 1 |
| `JNS` | Jump if not negative | SF = 0 |

### 3.2 Following Control Flow During Analysis

**Approach: Forward Analysis**
1. Start at entry point (WinMain, DllMain, or exports)
2. Follow the execution path — trace each conditional jump
3. When a jump condition depends on a Windows API call result, look up what that API returns
4. Document code blocks by what they do (rename functions in IDA/Ghidra)

**Approach: Backward Analysis**
1. Identify a suspicious API call (e.g., `CreateRemoteThread`)
2. Work backward to understand how arguments are prepared
3. Trace where data originates — is it from a hardcoded string or computed?

### 3.3 Anti-Disassembly Tricks

Malware authors deliberately confuse disassemblers:

| Technique | How It Works |
|-----------|-------------|
| **Jump into instruction** | JMP to middle of a multi-byte instruction; disassembler misaligns |
| **Constant condition jump** | `XOR EAX, EAX; JZ next` — always jumps but disassembler may not simplify |
| **Fake CALL** | `CALL` followed by `ADD ESP, 4` — not a real function call; tricks disassembler into creating wrong function boundary |
| **Overlapping instructions** | Two valid instruction sequences start at overlapping offsets |

---

## 4. Common Malware Characteristics at the Windows API Level

### 4.1 Windows API Overview for Malware Analysis

> Malware interacts with the operating system through the **Windows API (Win32 API)**. Recognizing which API functions are imported and called is one of the most efficient ways to understand what malware does.

**DLLs commonly abused by malware:**

| DLL | Purpose |
|----|---------|
| `kernel32.dll` | File, process, memory, thread management |
| `advapi32.dll` | Registry, services, cryptography, tokens |
| `ntdll.dll` | Native NT API; direct syscall wrappers |
| `user32.dll` | Windows messaging, keyboard/mouse input |
| `ws2_32.dll` / `wininet.dll` | Network socket / HTTP communications |
| `shell32.dll` | Shell operations, file execution |

### 4.2 Registry Manipulation

> Malware uses the Windows Registry for **persistence** (surviving reboots), **configuration storage**, and **disabling security controls**.

**Common persistence registry keys:**

| Key Path | When Executed |
|----------|--------------|
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | On user login |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | On system boot (all users) |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit` | At login (Winlogon) |

**Registry API calls used by malware:**

| Function | Purpose |
|----------|---------|
| `RegOpenKeyEx` | Open an existing registry key |
| `RegCreateKeyEx` | Create or open a registry key |
| `RegSetValueEx` | Write a value to a registry key |
| `RegQueryValueEx` | Read a registry value |
| `RegDeleteKey` / `RegDeleteValue` | Remove persistence or configuration |

**Example: Adding persistence**
```asm
; Add malware to Run key for persistence
PUSH offset "C:\\Windows\\Temp\\malware.exe"  ; value data
PUSH REG_SZ
PUSH offset "WindowsUpdate"                   ; value name
PUSH hKey                                     ; opened HKCU\...\Run key
CALL RegSetValueEx
```

### 4.3 Keylogging

> **Definition**: **Keylogging** is the covert recording of keyboard input, used to steal passwords, credentials, and sensitive information typed by the user.

**Keylogging techniques:**

| Technique | Windows API | Description |
|-----------|------------|-------------|
| **SetWindowsHookEx** | `SetWindowsHookEx(WH_KEYBOARD_LL, ...)` | Install system-wide keyboard hook |
| **GetAsyncKeyState** | `GetAsyncKeyState(vKey)` | Poll each key's state in a loop |
| **DirectX Input** | DirectInput API | Game-level input interception |
| **Kernel-level driver** | Custom driver via I/O dispatch | Most stealthy; filters IRP_MJ_READ on keyboard device |

**Keylogger flow using `SetWindowsHookEx`:**
```
1. LoadLibrary to get user32.dll handle
2. Call SetWindowsHookEx(WH_KEYBOARD_LL, hook_procedure, ...)
3. Hook procedure called by OS for every key press
4. Record VK (virtual key code) + timestamp
5. Periodically write buffer to file or exfiltrate
```

### 4.4 HTTP Communications (C2)

> **Definition**: **Command and Control (C2)** communication allows the attacker to remotely control an infected machine, issue commands, and exfiltrate data — typically over HTTP/HTTPS to blend in with normal web traffic.

**WinINet API (high-level HTTP):**

| Function | Purpose |
|----------|---------|
| `InternetOpen` | Initialize WinINet; set user-agent string |
| `InternetConnect` | Connect to a server by hostname/IP |
| `HttpOpenRequest` | Create an HTTP request (GET, POST) |
| `HttpSendRequest` | Send the request |
| `InternetReadFile` | Read server response |
| `InternetCloseHandle` | Clean up handles |

**Typical C2 beacon pattern:**
```
1. Sleep(interval) — periodic check-in
2. InternetOpen + InternetConnect to C2 host
3. HttpOpenRequest("GET", "/tasks", ...)
4. HttpSendRequest — check-in / beacon
5. InternetReadFile — receive command
6. Execute command; send results via POST
```

**Detection indicators:**
- Periodic outbound HTTP/HTTPS to uncommon domains
- Unusual User-Agent strings (hardcoded in `InternetOpen`)
- HTTP POST with encrypted/encoded body

### 4.5 Droppers and Downloaders

> **Definition**: A **dropper** is malware that installs (drops) another malware payload from embedded resources. A **downloader** fetches the payload from a remote server at runtime.

| Type | Payload Location | Requires Internet? |
|------|-----------------|-------------------|
| **Dropper** | Embedded in PE (`.rsrc` section) | No |
| **Downloader** | Downloads from URL | Yes |

**Dropper technique:**
```
1. Extract payload bytes from resource section (FindResource, LoadResource, LockResource)
2. Write payload to disk (CreateFile, WriteFile) — typically in Temp or System32
3. Execute payload (CreateProcess, ShellExecute, or service installation)
4. Optionally delete dropper itself
```

**Key dropper APIs:**

| Function | Purpose |
|----------|---------|
| `FindResource` | Locate embedded resource by name/type |
| `LoadResource` | Load resource into memory |
| `LockResource` | Get pointer to resource data |
| `SizeofResource` | Get resource size |
| `CreateFile` + `WriteFile` | Write payload to disk |
| `CreateProcess` | Execute payload |

---

## 5. x64 Assembly — Extending the Analysis

### 5.1 Why x64 Matters

Most modern Windows malware targets **64-bit systems**. The x64 architecture (also called AMD64 or x86-64) extends x86 with:
- Wider registers (64-bit)
- More general-purpose registers
- A different calling convention
- Larger virtual address space (128 TB)

### 5.2 x64 Register Set

| x64 Register | x86 Equivalent | Notes |
|-------------|----------------|-------|
| **RAX** | EAX | 64-bit accumulator; function return value |
| **RBX** | EBX | Preserved across calls (callee-saved) |
| **RCX** | ECX | 1st argument (Windows x64 calling convention) |
| **RDX** | EDX | 2nd argument |
| **RSI** | ESI | 5th argument (after R8, R9) |
| **RDI** | EDI | 6th argument |
| **RSP** | ESP | Stack pointer |
| **RBP** | EBP | Base pointer (optional in x64) |
| **RIP** | EIP | Instruction pointer |
| **R8–R15** | (new) | Additional general-purpose registers |

**Sub-register naming in x64:**

| 64-bit | 32-bit | 16-bit | 8-bit |
|--------|--------|--------|-------|
| RAX | EAX | AX | AL |
| R8 | R8D | R8W | R8B |

### 5.3 x64 Windows Calling Convention (Microsoft ABI)

> The x64 Windows calling convention passes the **first 4 arguments** in registers, then the rest on the stack. The caller always allocates a **32-byte shadow space** on the stack before the call.

| Argument Number | Register |
|----------------|----------|
| 1st | RCX |
| 2nd | RDX |
| 3rd | R8 |
| 4th | R9 |
| 5th and beyond | Stack (right-to-left) |

**Function call in x64:**
```asm
sub  rsp, 0x28        ; allocate shadow space (32 bytes) + alignment
mov  rcx, arg1        ; 1st argument
mov  rdx, arg2        ; 2nd argument
mov  r8,  arg3        ; 3rd argument
mov  r9,  arg4        ; 4th argument
call SomeFunction
add  rsp, 0x28        ; clean up shadow space
```

### 5.4 Key Differences: x86 vs x64 Malware Analysis

| Aspect | x86 | x64 |
|--------|-----|-----|
| Argument passing | All on stack | First 4 in registers |
| Stack shadow space | No | Yes (32 bytes before CALL) |
| Pointer size | 4 bytes | 8 bytes |
| RIP-relative addressing | No | Yes (`[RIP + offset]`) |
| New registers | None | R8–R15 |
| Tool support | Universal | Modern tools required |

### 5.5 Analyzing x64 Malware Practically

**In IDA Pro / Ghidra**: 
- Load 64-bit PE normally; disassembler handles x64 instructions
- Function arguments shown as RCX, RDX, R8, R9 (then stack)

**In x64dbg**:
- Set breakpoints on API calls
- The registers panel shows RAX–R15 and RIP
- Step through to see argument values in registers

**Common x64 malware pattern:**
```asm
; CreateFileA call in x64
lea  rcx, [rip + filename_str]  ; 1st arg: lpFileName (RIP-relative)
mov  edx, GENERIC_WRITE         ; 2nd arg: dwDesiredAccess
xor  r8d, r8d                   ; 3rd arg: dwShareMode = 0
xor  r9d, r9d                   ; 4th arg: lpSecurityAttributes = NULL
sub  rsp, 0x28
call CreateFileA
add  rsp, 0x28
```
