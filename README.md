# Minimal-Debugger-MDB
This project implements a minimal debugger (mdb) that runs and debugs ELF programs on Linux-based operating systems. The mdb is capable of loading an ELF executable, setting multiple software breakpoints, and inspecting the running code.

Features:

    ELF Binary Loading: Load and prepare an ELF binary for execution.
    
    Software Breakpoints: Add, list, and delete software breakpoints using symbols or hexadecimal addresses.
    
    Program Execution: Run the program until a breakpoint is reached or the program exits.
    
    Disassembly Display: Display the disassembly of the current instruction and 10 more instructions or until the end of a function is reached.
    
    Continue Execution: Continue program execution after a breakpoint is reached.

Implementation Details:

    Written in C/C++ using libelf or libbfd for ELF binary handling.
    
    Supports commands to add, list, and delete breakpoints.
    
    Executes the program and manages breakpoints efficiently.
    
    Displays disassembly of instructions when a breakpoint is hit.

Bonus Features:

    Single Instruction Execution (si): Progress the program by executing a single command.
    
    Disassembly Command (disas): Output the disassembly of the current instruction and 10 more instructions or until the end of a function is reached.

Files Included:

    Source Code: Contains the implementation code.
    
    Makefile: For building the project.
