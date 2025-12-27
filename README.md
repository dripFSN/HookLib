# HookLib v3 Documentation

## Table of Contents
- [Overview](#overview)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Core Concepts](#core-concepts)
- [API Reference](#api-reference)
- [Advanced Usage](#advanced-usage)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)
- [Limitations](#limitations)

## Overview

HookLib v3 is a comprehensive Lua library designed for game modification and memory manipulation in controlled environments. It provides a robust set of tools for hooking functions, patching memory, and interacting with game interfaces through Virtual Method Table (VMT) hooking and detour techniques.

**Key Features:**
- VMT (Virtual Method Table) hooking for C++ interfaces
- Detour hooking for function redirection
- Memory patching and manipulation
- Pattern scanning for dynamic address resolution
- Automatic cleanup and resource management
- Convenience wrappers for common game hooks
- Cross-platform memory allocation via kernel32

## Installation

### Requirements
- LuaJIT with FFI support
- Access to kernel32.dll functions
- Proper execution environment with memory permissions

### Setup
1. Place `hooklib v3.lua` in your script directory
2. Import the library in your Lua script:

```lua
local HookLib = require("hooklib v3")
```

3. Initialize the library before use:

```lua
HookLib.initialize()
```

## Quick Start

### Basic Initialization

```lua
local HookLib = require("hooklib v3")

-- Initialize the library
HookLib.initialize()

-- Enable debug logging (optional)
HookLib.config.debug = true

-- Your hooking code here
```

### Simple VMT Hook Example

```lua
-- Hook a function in a game interface
local panel_interface = HookLib.get_interface("vgui2.dll", "VGUI_Panel")
local vmt_hook = HookLib.create_vmt_hook(panel_interface)

-- Hook PaintTraverse (index 41)
vmt_hook:hook_function(41, function(thisptr, edx, vgui_panel, force_repaint, allow_force)
    -- Call original function first
    vmt_hook:call_original(41, thisptr, edx, vgui_panel, force_repaint, allow_force)
    
    -- Your custom logic here
    print("PaintTraverse called for panel: " .. vgui_panel)
end, "void(__fastcall*)(void*, void*, unsigned int, bool, bool)")
```

### Simple Detour Hook Example

```lua
-- Hook a function using pattern scanning
local detour = HookLib.create_detour(
    "void(__cdecl*)(float, bool)",  -- Function signature
    function(accumulated_extra_samples, bFinalTick)
        -- Your custom logic
        print("CL_Move hooked!")
        
        -- Call original function
        detour:call_original(accumulated_extra_samples, bFinalTick)
    end,
    "\x55\x8B\xEC\x81\xEC\xCC\xCC\xCC\xCC\x53\x56\x8A\xF9",  -- Pattern
    "engine.dll",  -- Module
    5,  -- Patch size
    true  -- Use trampoline
)

-- Enable the hook
detour:enable()
```

## Core Concepts

### VMT Hooking
VMT hooking intercepts calls to virtual functions in C++ classes by modifying the virtual function table. This allows you to replace or wrap original functions with your own implementations.

### Detour Hooking
Detour hooking replaces the beginning of a function with a jump to your custom code. It can optionally use a trampoline to preserve the ability to call the original function.

### Memory Patching
Direct modification of executable code in memory. Useful for enabling/disabling features or changing game behavior.

### Pattern Scanning
Finding function addresses in memory by searching for unique byte patterns, making your hooks resilient to game updates.

## API Reference

### Configuration

#### `HookLib.config`
Configuration table for library behavior:
- `debug`: Enable/disable debug logging (default: true)
- `auto_cleanup`: Automatically clean up hooks on shutdown (default: true)

#### `HookLib.initialize()`
Initializes the library. Must be called before any hooking operations. Performs memory allocation tests and sets up cleanup handlers.

#### `HookLib.log(message)`
Logs a message with HookLib prefix. Respects the `debug` configuration option.

### Interface Management

#### `HookLib.get_interface(module_name, interface_name)`
Retrieves an interface pointer from a loaded module.

**Parameters:**
- `module_name`: Name of the DLL (e.g., "client.dll")
- `interface_name`: Name of the interface (e.g., "VClient018")

**Returns:** Interface pointer or nil

**Example:**
```lua
local client = HookLib.get_interface("client.dll", "VClient018")
```

### Pattern Scanning

#### `HookLib.find_pattern(module, pattern, offset)`
Finds a memory address using a byte pattern.

**Parameters:**
- `module`: DLL name
- `pattern`: Byte pattern string (wildcards not supported)
- `offset`: Additional offset from found address (default: 0)

**Returns:** Address or nil

**Example:**
```lua
local address = HookLib.find_pattern("client.dll", "\x55\x8B\xEC\x83\xEC", 0)
```

#### `HookLib.find_pattern_masked(module, pattern, mask)`
Finds a memory address using a pattern with mask.

**Parameters:**
- `module`: DLL name
- `pattern`: Byte pattern string
- `mask`: Mask string ('x' for exact match, '?' for wildcard)

**Returns:** Address or nil

**Example:**
```lua
local address = HookLib.find_pattern_masked(
    "client.dll", 
    "\x8B\x35\x00\x00\x00\x00\x57\x85\xF6", 
    "xx????xxx"
)
```

### Memory Operations

#### `HookLib.read_memory(address, type)`
Reads a value from memory.

**Parameters:**
- `address`: Memory address
- `type`: FFI type (e.g., "int", "float", "uintptr_t")

**Returns:** Value

**Example:**
```lua
local value = HookLib.read_memory(0x12345678, "int")
```

#### `HookLib.write_memory(address, value, type)`
Writes a value to memory.

**Parameters:**
- `address`: Memory address
- `value`: Value to write
- `type`: FFI type

**Example:**
```lua
HookLib.write_memory(0x12345678, 42, "int")
```

#### `HookLib.read_string(address, max_length)`
Reads a null-terminated string from memory.

**Parameters:**
- `address`: Memory address
- `max_length`: Maximum length to read (default: 256)

**Returns:** String

#### `HookLib.write_string(address, str)`
Writes a null-terminated string to memory.

**Parameters:**
- `address`: Memory address
- `str`: String to write

#### `HookLib.allocate(size, executable)`
Allocates memory.

**Parameters:**
- `size`: Size in bytes
- `executable`: Whether memory should be executable (default: false)

**Returns:** Pointer to allocated memory

#### `HookLib.free_all_allocated()`
Frees all memory allocated by HookLib.

### Memory Patching

#### `HookLib.create_memory_patch(pattern_or_address, module, bytes)`
Creates a memory patch object.

**Parameters:**
- `pattern_or_address`: Pattern string or direct address
- `module`: DLL name (required for pattern)
- `bytes`: Byte array to patch

**Returns:** MemoryPatch object

**Example:**
```lua
local patch = HookLib.create_memory_patch(
    "\x74\x15",  -- Pattern: jz +0x15
    "client.dll",
    "\x90\x90"   -- Replace with: nop nop
)
patch:apply()    -- Enable patch
patch:restore()  -- Disable patch
```

#### MemoryPatch Methods
- `apply()`: Applies the patch
- `restore()`: Restores original bytes

### VMT Hooking

#### `HookLib.create_vmt_hook(interface_ptr_or_name, module, interface_name)`
Creates a VMT hook object.

**Parameters:**
- `interface_ptr_or_name`: Interface pointer or interface name string
- `module`: DLL name (if using interface name)
- `interface_name`: Interface name (if using interface name)

**Returns:** VMTHook object

**Example:**
```lua
-- Using interface pointer
local client = HookLib.get_interface("client.dll", "VClient018")
local vmt_hook = HookLib.create_vmt_hook(client)

-- Using interface name
local vmt_hook = HookLib.create_vmt_hook("VGUI_Panel", "vgui2.dll", "VGUI_Panel")
```

#### VMTHook Methods

##### `hooked_functions = VMTHook:hook_function(index, callback, typedef)`
Hooks a function at the specified VTable index.

**Parameters:**
- `index`: VTable index (0-based)
- `callback`: Lua function to call
- `typedef`: FFI function signature

**Returns:** Original function pointer

**Example:**
```lua
local original = vmt_hook:hook_function(37, function(thisptr, edx, stage)
    -- Pre-call logic
    print("FrameStageNotify called: " .. stage)
    
    -- Call original
    vmt_hook:call_original(37, thisptr, edx, stage)
    
    -- Post-call logic
end, "void(__fastcall*)(void*, void*, int)")
```

##### `success = VMTHook:unhook_function(index)`
Unhooks a function at the specified index.

**Returns:** true if successful

##### `original_func = VMTHook:get_original(index)`
Gets the original function pointer for an index.

**Returns:** Original function pointer or nil

##### `result = VMTHook:call_original(index, ...)`
Calls the original function with arguments.

**Returns:** Result from original function

##### `VMTHook:cleanup()`
Cleans up all hooks on this VMT and releases resources.

### Detour Hooking

#### `HookLib.create_detour(typedef, callback, pattern_or_address, module, size, trampoline)`
Creates a detour hook object.

**Parameters:**
- `typedef`: FFI function signature
- `callback`: Lua function to call
- `pattern_or_address`: Pattern string or direct address
- `module`: DLL name (required for pattern)
- `size`: Number of bytes to overwrite (default: 5)
- `trampoline`: Whether to use trampoline (default: false)

**Returns:** DetourHook object

**Example:**
```lua
local detour = HookLib.create_detour(
    "void(__fastcall*)(void*, void*)",
    function(thisptr, edx)
        print("PhysicsSimulate hooked!")
        return detour:call_original(thisptr, edx)
    end,
    "\x56\x8B\xF1\x8B\x8E\xCC\xCC\xCC\xCC",
    "client.dll",
    5,
    true
)
```

#### DetourHook Methods

##### `DetourHook:enable()`
Enables the detour hook.

##### `DetourHook:disable()`
Disables the detour hook.

##### `result = DetourHook:call_original(...)`
Calls the original function.

**Returns:** Result from original function

##### `DetourHook:cleanup()`
Cleans up the hook and releases allocated memory.

### Convenience Hooks

HookLib provides convenience functions for common game hooks:

#### `HookLib.hook_cl_move(callback)`
Hooks CL_Move function.

#### `HookLib.hook_frame_stage_notify(callback)`
Hooks FrameStageNotify function.

#### `HookLib.hook_physics_simulate(callback)`
Hooks PhysicsSimulate function.

#### `HookLib.hook_create_move(callback)`
Hooks CreateMove function.

#### `HookLib.hook_paint_traverse(callback)`
Hooks PaintTraverse function.

#### `HookLib.hook_draw_model_execute(callback)`
Hooks DrawModelExecute function.

#### `HookLib.hook_lock_cursor(callback)`
Hooks LockCursor function.

#### `HookLib.hook_clamp_bones_in_bbox(callback)`
Hooks ClampBonesInBBox function.

**Example:**
```lua
HookLib.hook_create_move(function(sequence_number, input_sample_frametime, active, send_packet)
    -- Your movement logic here
    send_packet[0] = true  -- Modify send_packet
end)
```

### Utility Functions

#### `HookLib.ptr_to_number(ptr)`
Converts a pointer to a number.

#### `HookLib.number_to_ptr(num, type)`
Converts a number to a pointer.

#### `buffer = HookLib.read_buffer(address, size)`
Reads raw bytes from memory.

#### `HookLib.write_buffer(address, buffer, size)`
Writes raw bytes to memory.

### Management Functions

#### `HookLib.disable_all_hooks()`
Disables all active hooks.

#### `HookLib.cleanup_all()`
Cleans up all hooks and releases all resources.

#### `has_hooks = HookLib.has_active_hooks()`
Checks if any hooks are active.

#### `count = HookLib.get_hook_count()`
Gets the total number of active hooks.

## Advanced Usage

### Multiple Hooks on Same Function

```lua
-- Create multiple hooks on the same VTable index
local vmt = HookLib.create_vmt_hook(panel_interface)

-- First hook
vmt:hook_function(41, function(...)
    print("Hook 1: Before original")
    local result = vmt:call_original(41, ...)
    print("Hook 1: After original")
    return result
end, "void(__fastcall*)(void*, void*, unsigned int, bool, bool)")

-- Second hook (will be called after first)
vmt:hook_function(41, function(...)
    print("Hook 2: Before original")
    local result = vmt:call_original(41, ...)
    print("Hook 2: After original")
    return result
end, "void(__fastcall*)(void*, void*, unsigned int, bool, bool)")
```

### Chaining Hooks with Callbacks

```lua
local hooks = {}

-- Store original for chaining
local original_func = nil

hooks.frame_stage = HookLib.hook_frame_stage_notify(function(stage)
    -- Your logic here
    
    -- Call next hook in chain
    if original_func then
        -- You need to pass the correct thisptr and edx
        -- This is simplified - actual implementation depends on context
    end
end)

-- Store the original function from the hook
original_func = hooks.frame_stage:get_original(37)
```

### Dynamic Hook Management

```lua
local hook_manager = {
    hooks = {},
    enabled = true
}

function hook_manager:toggle_hooks()
    self.enabled = not self.enabled
    
    if self.enabled then
        for _, hook in pairs(self.hooks) do
            if hook.enable then
                hook:enable()
            end
        end
    else
        HookLib.disable_all_hooks()
    end
end

-- Add hooks to manager
hook_manager.hooks.cl_move = HookLib.hook_cl_move(function(...)
    if not hook_manager.enabled then
        return hook_manager.hooks.cl_move:call_original(...)
    end
    -- Your logic
end)
```

## Best Practices

### 1. Always Initialize
```lua
-- At the start of your script
HookLib.initialize()
```

### 2. Use Error Handling
```lua
local success, err = pcall(function()
    HookLib.hook_frame_stage_notify(function(stage)
        -- Your code
    end)
end)

if not success then
    print("Hook failed: " .. tostring(err))
end
```

### 3. Clean Up Properly
```lua
-- Manual cleanup when done
client.set_event_callback("shutdown", function()
    HookLib.cleanup_all()
end)

-- Or use auto cleanup
HookLib.config.auto_cleanup = true
```

### 4. Cache Interface Pointers
```lua
-- Store interfaces for reuse
local cached_interfaces = {}

function get_cached_interface(module, name)
    if not cached_interfaces[module] then
        cached_interfaces[module] = {}
    end
    
    if not cached_interfaces[module][name] then
        cached_interfaces[module][name] = HookLib.get_interface(module, name)
    end
    
    return cached_interfaces[module][name]
end
```

### 5. Use Pattern Caching
HookLib automatically caches pattern scan results. Reuse patterns when possible.

### 6. Validate Function Indices
```lua
-- Always check VTable bounds
local MAX_VTABLE_SIZE = 256  -- Adjust based on interface

function safe_hook_index(vmt_hook, index, callback, typedef)
    if index < 0 or index >= MAX_VTABLE_SIZE then
        error("Invalid VTable index: " .. index)
    end
    
    return vmt_hook:hook_function(index, callback, typedef)
end
```

## Troubleshooting

### Common Issues

#### "Failed to find proxy signature"
The library cannot find the required signature in client.dll. Ensure:
- The game/client is properly loaded
- You're using the correct version of the library for your game version

#### "Cannot read from interface pointer"
The interface pointer is invalid. Check:
- Interface name and module are correct
- The DLL is loaded
- You have proper permissions

#### "VTable has 0 entries"
The interface pointer doesn't point to a valid VTable. This usually means:
- Wrong interface pointer
- Memory corruption
- Timing issue (interface not initialized yet)

#### Hook causes crash
- Verify function signatures match exactly
- Check stack alignment in callbacks
- Ensure proper cleanup of hooks
- Use trampoline for detours when modifying long functions

#### Memory leaks
- Ensure all allocated memory is freed
- Use `HookLib.free_all_allocated()` if needed
- Check that `cleanup_all()` is called on shutdown

### Debugging Tips

1. Enable debug logging:
```lua
HookLib.config.debug = true
```

2. Check hook counts:
```lua
print("Active hooks: " .. HookLib.get_hook_count())
```

3. Verify addresses:
```lua
local addr = HookLib.find_pattern("client.dll", "\x55\x8B\xEC")
if addr then
    print("Pattern found at: 0x" .. string.format("%X", HookLib.ptr_to_number(addr)))
end
```

4. Test memory operations:
```lua
-- Test allocation
local test_mem = HookLib.allocate(1024, false)
if test_mem then
    print("Allocation successful")
    HookLib.free_all_allocated()
end
```

## Limitations

### Platform Dependencies
- Requires Windows (kernel32.dll)
- Depends on specific game/client architecture
- Pattern signatures may change with game updates

### Memory Safety
- Direct memory manipulation can cause crashes if done incorrectly
- No bounds checking on memory reads/writes
- Hooks can interfere with other modifications

### Performance Considerations
- Pattern scanning is relatively slow
- Multiple hooks on the same function add overhead
- Trampoline detours allocate executable memory

### Stability
- Not all game functions can be safely hooked
- Resource cleanup must be managed carefully
