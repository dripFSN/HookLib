local ffi = require("ffi")
local bit = require("bit")

ffi.cdef[[
    typedef unsigned long DWORD;
    typedef void* LPVOID;
    typedef unsigned long long SIZE_T;
    typedef int BOOL;
    
    LPVOID VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
    BOOL VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
    BOOL VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, DWORD* lpflOldProtect);
    
    typedef struct {
        void** vtable;
    } VTableHolder;
]]

local PAGE_EXECUTE_READWRITE = 0x40
local PAGE_EXECUTE_READ = 0x20
local PAGE_READWRITE = 0x04
local MEM_COMMIT = 0x1000
local MEM_RESERVE = 0x2000
local MEM_RELEASE = 0x8000

local function get_kernel32_functions()
    local proxy_addr = client.find_signature("client.dll", "\x51\xC3")
    if not proxy_addr then
        error("[HookLib] Failed to find proxy signature")
    end

    local get_mod_add_pattern = client.find_signature("client.dll", 
        "\xC6\x06\x00\xFF\x15\xCC\xCC\xCC\xCC\x50")
    if not get_mod_add_pattern then
        error("[HookLib] Failed to find get module pattern")
    end
    
    local get_mod_add_addr = ffi.cast("void***", ffi.cast("char*", get_mod_add_pattern) + 5)[0][0]
    local get_mod_add_proxy = ffi.cast("uintptr_t (__thiscall*)(void*, const char*)", proxy_addr)

    local get_proc_add_pattern = client.find_signature("client.dll", 
        "\x50\xFF\x15\xCC\xCC\xCC\xCC\x85\xC0\x0F\x84\xCC\xCC\xCC\xCC\x6A\x00")
    if not get_proc_add_pattern then
        error("[HookLib] Failed to find get proc pattern")
    end
    
    local get_proc_add_addr = ffi.cast("void***", ffi.cast("char*", get_proc_add_pattern) + 3)[0][0]
    local get_proc_add_proxy = ffi.cast("uintptr_t (__thiscall*)(void*, uintptr_t, const char*)", proxy_addr)

    local kernel32_addr = get_mod_add_proxy(get_mod_add_addr, "kernel32.dll")
    if not kernel32_addr or kernel32_addr == 0 then
        error("[HookLib] Failed to get kernel32.dll handle")
    end
    
    local VirtualAlloc_addr = get_proc_add_proxy(get_proc_add_addr, kernel32_addr, "VirtualAlloc")
    local VirtualAlloc_proxy = ffi.cast("void* (__thiscall*)(uintptr_t, void*, uintptr_t, uintptr_t, uintptr_t)", proxy_addr)

    local VirtualProtect_addr = get_proc_add_proxy(get_proc_add_addr, kernel32_addr, "VirtualProtect")
    local VirtualProtect_proxy = ffi.cast("uintptr_t (__thiscall*)(uintptr_t, void*, uintptr_t, uintptr_t, uintptr_t*)", proxy_addr)
    
    local VirtualFree_addr = get_proc_add_proxy(get_proc_add_addr, kernel32_addr, "VirtualFree")
    local VirtualFree_proxy = ffi.cast("uintptr_t (__thiscall*)(uintptr_t, void*, uintptr_t, uintptr_t)", proxy_addr)

    return {
        VirtualAlloc = function(size, executable)
            local protect = executable and PAGE_EXECUTE_READWRITE or PAGE_READWRITE
            return VirtualAlloc_proxy(VirtualAlloc_addr, nil, size, MEM_COMMIT + MEM_RESERVE, protect)
        end,
    
        VirtualProtect = function(address, size, protect)
            local oldprotect = ffi.new("uintptr_t[1]")
            local result = VirtualProtect_proxy(VirtualProtect_addr, ffi.cast("void*", address), size, protect, oldprotect)
            return tonumber(result) ~= 0, tonumber(oldprotect[0])
        end,
    
        VirtualFree = function(address)
            return VirtualFree_proxy(VirtualFree_addr, ffi.cast("void*", address), 0, MEM_RELEASE)
        end
    }
end

local kernel32 = get_kernel32_functions()

local function color_log(...)
    local args = { ... }
    local len = #args
    
    for i = 1, len do
        local arg = args[i]
        local r, g, b = unpack(arg)
        
        local msg = {}
        
        if #arg == 3 then
            table.insert(msg, " ")
        else
            for j = 4, #arg do
                table.insert(msg, arg[j])
            end
        end
        msg = table.concat(msg)
        
        if len > i then
            msg = msg .. "\0"
        end
        
        client.color_log(r, g, b, msg)
    end
end

local HookLib = {
    debug = true,
    vmt_hooks = {},
    detour_hooks = {},
    callbacks = {},
    active_hooks = {},
    pattern_cache = {},
    allocated_memory = {},
    
    convenience = {
        CL_Move = nil,
        FrameStageNotify = nil,
        PhysicsSimulate = nil,
        CreateMove = nil,
        PaintTraverse = nil,
        DrawModelExecute = nil,
        LockCursor = nil
    },
    
    config = {
        debug = true,
        auto_cleanup = true
    },
    
    initialized = false,
    interfaces = {}
}

function HookLib.log(message)
    if HookLib.config.debug then
        color_log(
            {50, 200, 150, "[HookLib] "},
            {255, 255, 255, message}
        )
    end
end

function HookLib.get_interface(module_name, interface_name)
    local interface_ptr = client.create_interface(module_name, interface_name)
    if interface_ptr then
        HookLib.log("Interface found: " .. interface_name .. " in " .. module_name)
        return interface_ptr
    end
    
    if string.find(interface_name, "%d%d%d$") then
        local base_name = string.sub(interface_name, 1, -4)
        interface_ptr = client.create_interface(module_name, base_name)
        if interface_ptr then
            HookLib.log("Interface found (no version): " .. base_name .. " in " .. module_name)
            return interface_ptr
        end
    end
    
    HookLib.log("Interface not found: " .. interface_name .. " in " .. module_name)
    return nil
end

function HookLib.find_pattern(module, pattern, offset)
    offset = offset or 0
    local cache_key = module .. pattern .. tostring(offset)
    
    if HookLib.pattern_cache[cache_key] then
        return HookLib.pattern_cache[cache_key]
    end
    
    local signature = client.find_signature(module, pattern)
    if signature then
        local result = ffi.cast("uintptr_t", signature) + offset
        HookLib.pattern_cache[cache_key] = result
        
        local result_num = tonumber(ffi.cast("uintptr_t", result))
        HookLib.log("Pattern found: " .. pattern .. " -> 0x" .. string.format("%X", result_num))
        
        return result
    end
    
    HookLib.log("Pattern not found: " .. pattern .. " in " .. module)
    return nil
end

function HookLib.ptr_to_number(ptr)
    return tonumber(ffi.cast("uintptr_t", ptr))
end

function HookLib.read_memory(address, type)
    return ffi.cast(type .. "*", address)[0]
end

function HookLib.write_memory(address, value, type)
    local success, old_protect = kernel32.VirtualProtect(address, ffi.sizeof(type), PAGE_EXECUTE_READWRITE)
    if success then
        ffi.cast(type .. "*", address)[0] = value
        kernel32.VirtualProtect(address, ffi.sizeof(type), old_protect)
    end
end

function HookLib.read_string(address, max_length)
    max_length = max_length or 256
    local buffer = ffi.new("char[?]", max_length)
    ffi.copy(buffer, ffi.cast("void*", address), max_length - 1)
    return ffi.string(buffer)
end

function HookLib.number_to_ptr(num, type)
    type = type or "void*"
    return ffi.cast(type, ffi.cast("uintptr_t", num))
end

function HookLib.allocate(size, executable)
    local mem = kernel32.VirtualAlloc(size, executable)
    if mem then
        HookLib.allocated_memory[#HookLib.allocated_memory + 1] = mem
        HookLib.log("Allocated " .. size .. " bytes at 0x" .. string.format("%X", tonumber(ffi.cast("uintptr_t", mem))))
    end
    return mem
end

function HookLib.free_all_allocated()
    for i, mem in ipairs(HookLib.allocated_memory) do
        kernel32.VirtualFree(mem)
        HookLib.allocated_memory[i] = nil
    end
    HookLib.log("Freed all allocated memory")
end

function HookLib.find_pattern_masked(module, pattern, mask)
    local module_start = ffi.cast("uintptr_t", client.module_start(module))
    local module_end = module_start + client.module_size(module)
    
    for addr = module_start, module_end - #mask do
        local found = true
        for i = 1, #mask do
            local byte = ffi.cast("uint8_t*", addr)[i-1]
            local mask_char = mask:sub(i, i)
            local pattern_byte = pattern:sub(i, i)
            
            if mask_char == 'x' and string.byte(pattern_byte) ~= byte then
                found = false
                break
            elseif mask_char == '?' then
            end
        end
        if found then
            return ffi.cast("uintptr_t", addr)
        end
    end
    return nil
end

function HookLib.write_string(address, str)
    for i = 1, #str do
        ffi.cast("uint8_t*", address)[i-1] = string.byte(str, i)
    end
    ffi.cast("uint8_t*", address)[#str] = 0
end

function HookLib.read_buffer(address, size)
    local buffer = ffi.new("uint8_t[?]", size)
    ffi.copy(buffer, ffi.cast("void*", address), size)
    return buffer
end

function HookLib.write_buffer(address, buffer, size)
    local success, old_protect = kernel32.VirtualProtect(address, size, PAGE_EXECUTE_READWRITE)
    if success then
        ffi.copy(ffi.cast("void*", address), buffer, size)
        kernel32.VirtualProtect(address, size, old_protect)
    end
end

local MemoryPatch = {}
MemoryPatch.__index = MemoryPatch

function MemoryPatch.new(address, bytes, size)
    local original = HookLib.read_buffer(address, size)
    local self = setmetatable({
        address = address,
        size = size,
        original = original,
        patched = bytes,
        active = false
    }, MemoryPatch)
    return self
end

function MemoryPatch:apply()
    if self.active then return end
    HookLib.write_buffer(self.address, self.patched, self.size)
    self.active = true
    HookLib.log("Patch applied at 0x" .. string.format("%X", tonumber(self.address)))
end

function MemoryPatch:restore()
    if not self.active then return end
    HookLib.write_buffer(self.address, self.original, self.size)
    self.active = false
    HookLib.log("Patch restored at 0x" .. string.format("%X", tonumber(self.address)))
end

function HookLib.create_memory_patch(pattern_or_address, module, bytes)
    local address
    if type(pattern_or_address) == "string" then
        address = HookLib.find_pattern(module, pattern_or_address)
    else
        address = pattern_or_address
    end
    if not address then return nil end
    return MemoryPatch.new(address, bytes, #bytes)
end

local VMTHook = {}
VMTHook.__index = VMTHook

function VMTHook.new(interface_ptr)
    if not interface_ptr then
        error("VMTHook.new: interface_ptr is nil")
    end
    
    local ptr_num = tonumber(ffi.cast("uintptr_t", interface_ptr))
    HookLib.log("Creating VMT hook for interface: 0x" .. string.format("%X", ptr_num))
    
    local success, test_read = pcall(function()
        return ffi.cast("void**", interface_ptr)[0]
    end)
    
    if not success then
        error("Cannot read from interface pointer (invalid memory)")
    end
   
    local vtable_holder = ffi.cast("VTableHolder*", interface_ptr)
    local vtable = vtable_holder.vtable
    if not vtable then
        error("Failed to get VTable from interface pointer")
    end
    
    local vtable_num = tonumber(ffi.cast("uintptr_t", vtable))
    HookLib.log("VTable pointer: 0x" .. string.format("%X", vtable_num))
    
    local function count_vtable_entries()
        local count = 0
        while count < 256 do
            local success, entry = pcall(function()
                return vtable[count]
            end)
            if not success or entry == nil or tonumber(ffi.cast("uintptr_t", entry)) == 0 then
                break
            end
            count = count + 1
        end
        return count
    end
    
    local vtable_size = count_vtable_entries()
    
    if vtable_size == 0 then
        error("VTable has 0 entries (invalid interface)")
    end
    
    HookLib.log("VTable size: " .. vtable_size .. " entries")
    
    local original_vtable = {}
    for i = 0, vtable_size - 1 do
        original_vtable[i] = vtable[i]
    end
    
    local self = setmetatable({
        interface = interface_ptr,
        vtable = vtable,
        vtable_size = vtable_size,
        original_vtable = original_vtable,
        hooked_functions = {},
        hook_count = 0
    }, VMTHook)
    
    HookLib.vmt_hooks[self] = true
    
    return self
end

function VMTHook:hook_function(index, callback, typedef)
    HookLib.log("Attempting to hook VTable index " .. index)
    
    if index < 0 or index >= self.vtable_size then
        error(string.format("VTable index %d out of bounds (0-%d)", index, self.vtable_size - 1))
    end
    
    local original_func = self.vtable[index]
    if original_func == nil then
        error(string.format("VTable entry %d is NULL", index))
    end
    
    HookLib.log("Original function at index " .. index .. ": 0x" .. 
        string.format("%X", tonumber(ffi.cast("uintptr_t", original_func))))
    
    self.hooked_functions[index] = {
        original = original_func,
        callback = callback,
        typedef = typedef
    }
    
    local hook_func = ffi.cast(typedef, callback)
    if not hook_func then
        error("Failed to cast callback to function pointer")
    end
    
    HookLib.log("Hook function created: 0x" .. 
        string.format("%X", tonumber(ffi.cast("uintptr_t", ffi.cast("void*", hook_func)))))
    
    local vtable_entry = ffi.cast("void**", self.vtable) + index
    
    HookLib.log("Changing memory protection...")
    local success, old_protect = kernel32.VirtualProtect(vtable_entry, ffi.sizeof("void*"), PAGE_EXECUTE_READWRITE)
    if not success then
        error("Failed to change memory protection")
    end
    
    HookLib.log("Old protection: 0x" .. string.format("%X", old_protect))
    
    HookLib.log("Replacing function pointer...")
    self.vtable[index] = ffi.cast("void*", hook_func)
    
    kernel32.VirtualProtect(vtable_entry, ffi.sizeof("void*"), old_protect)
    
    HookLib.log("VTable entry updated successfully")
    
    HookLib.callbacks[#HookLib.callbacks + 1] = callback
    HookLib.callbacks[#HookLib.callbacks + 1] = hook_func
    
    self.hook_count = self.hook_count + 1
    HookLib.active_hooks[self] = true
    
    HookLib.log(string.format("VMT hook installed at index %d", index))
    
    return original_func
end

function VMTHook:unhook_function(index)
    HookLib.log("Attempting to unhook VTable index " .. index)
    
    if not self.hooked_functions[index] then
        HookLib.log("No hook at index " .. index)
        return false
    end
    
    if not self.interface or not self.vtable then
        HookLib.log("Interface or vtable is nil, skipping unhook")
        self.hooked_functions[index] = nil
        return false
    end
    
    local hook_data = self.hooked_functions[index]
    
    local success, err = pcall(function()
        local vtable_entry = ffi.cast("void**", self.vtable) + index
        
        HookLib.log("Restoring original function at index " .. index)
        
        local success, old_protect = kernel32.VirtualProtect(vtable_entry, ffi.sizeof("void*"), PAGE_EXECUTE_READWRITE)
        if success then
            self.vtable[index] = hook_data.original
            kernel32.VirtualProtect(vtable_entry, ffi.sizeof("void*"), old_protect)
            HookLib.log("Original function restored")
        else
            HookLib.log("Warning: Failed to change memory protection for unhook")
        end
    end)
    
    if not success then
        HookLib.log("Error during unhook: " .. tostring(err))
    end
    
    self.hooked_functions[index] = nil
    self.hook_count = self.hook_count - 1
    
    if self.hook_count == 0 then
        HookLib.active_hooks[self] = nil
    end
    
    HookLib.log("Unhooked index " .. index)
    return true
end

function VMTHook:get_original(index)
    if index < 0 or index >= self.vtable_size then
        return nil
    end
    
    if self.hooked_functions[index] then
        return ffi.cast(self.hooked_functions[index].typedef, self.hooked_functions[index].original)
    end
    
    return ffi.cast("void*", self.original_vtable[index])
end

function VMTHook:call_original(index, ...)
    local original_func = self:get_original(index)
    if not original_func then
        return nil
    end
    return original_func(self.interface, ...)
end

function VMTHook:cleanup()
    HookLib.log("Cleaning up VMT hook for interface: 0x" .. 
        string.format("%X", tonumber(ffi.cast("uintptr_t", self.interface))))
    
    local indices = {}
    for index, _ in pairs(self.hooked_functions) do
        table.insert(indices, index)
    end
    
    table.sort(indices, function(a, b) return a > b end)
    
    for _, index in ipairs(indices) do
        self:unhook_function(index)
    end
    
    self.interface = nil
    self.vtable = nil
    self.original_vtable = nil
    self.hooked_functions = {}
    
    HookLib.log("VMT hook cleanup complete")
end

local DetourHook = {}
DetourHook.__index = DetourHook

function DetourHook.new(typedef, callback, target_address, size, trampoline)
    size = size or 5
    trampoline = trampoline or false
    
    local hook = setmetatable({
        target = target_address,
        callback = callback,
        typedef = typedef,
        size = size,
        trampoline = trampoline,
        active = false,
        original_bytes = ffi.new("uint8_t[?]", size),
        trampoline_address = nil,
        old_protect = nil,
        original_func = nil
    }, DetourHook)
    
    ffi.copy(hook.original_bytes, ffi.cast("void*", target_address), size)
    
    local hook_bytes = ffi.new("uint8_t[?]", size, 0x90)
    hook_bytes[0] = 0xE9
    
    local callback_address = ffi.cast("uintptr_t", ffi.cast(typedef, callback))
    local jmp_offset = callback_address - tonumber(ffi.cast("uintptr_t", target_address)) - 5
    ffi.cast("int32_t*", hook_bytes + 1)[0] = jmp_offset
    
    hook._hook_bytes = hook_bytes
    
    if trampoline then
        local tramp_size = size + 5
        hook.trampoline_address = kernel32.VirtualAlloc(tramp_size, true)
        
        if not hook.trampoline_address then
            error("Failed to allocate memory for trampoline")
        end
        
        local tramp_bytes = ffi.new("uint8_t[?]", tramp_size, 0x90)
        ffi.copy(tramp_bytes, hook.original_bytes, size)
        
        tramp_bytes[size] = 0xE9
        local return_jmp = tonumber(ffi.cast("uintptr_t", target_address)) + size - 
                          tonumber(ffi.cast("uintptr_t", hook.trampoline_address)) - 5
        ffi.cast("int32_t*", tramp_bytes + size + 1)[0] = return_jmp
        
        kernel32.VirtualProtect(hook.trampoline_address, tramp_size, PAGE_EXECUTE_READWRITE)
        ffi.copy(hook.trampoline_address, tramp_bytes, tramp_size)
        
        hook.original_func = ffi.cast(typedef, hook.trampoline_address)
    else
        hook.original_func = ffi.cast(typedef, target_address)
    end
    
    HookLib.detour_hooks[hook] = true
    
    return hook
end

function DetourHook:enable()
    if self.active then return end
    
    local success, old_protect = kernel32.VirtualProtect(ffi.cast("void*", self.target), self.size, PAGE_EXECUTE_READWRITE)
    if success then
        ffi.copy(ffi.cast("void*", self.target), self._hook_bytes, self.size)
        kernel32.VirtualProtect(ffi.cast("void*", self.target), self.size, old_protect)
        
        self.active = true
        HookLib.active_hooks[self] = true
        HookLib.log("Detour enabled at 0x" .. string.format("%X", tonumber(ffi.cast("uintptr_t", self.target))))
    end
end

function DetourHook:disable()
    if not self.active then return end
    
    kernel32.VirtualProtect(ffi.cast("void*", self.target), self.size, PAGE_EXECUTE_READWRITE)
    ffi.copy(ffi.cast("void*", self.target), self.original_bytes, self.size)
    
    self.active = false
    HookLib.active_hooks[self] = nil
    HookLib.log("Detour disabled at 0x" .. string.format("%X", tonumber(ffi.cast("uintptr_t", self.target))))
end

function DetourHook:call_original(...)
    if not self.active then
        return self.original_func(...)
    end
    
    self:disable()
    local result = self.original_func(...)
    self:enable()
    
    return result
end

function DetourHook:cleanup()
    self:disable()
    
    if self.trampoline_address then
        kernel32.VirtualFree(self.trampoline_address)
        self.trampoline_address = nil
    end
    
    HookLib.detour_hooks[self] = nil
end

function HookLib.create_vmt_hook(interface_ptr_or_name, module, interface_name)
    local interface_ptr
    
    if type(interface_ptr_or_name) == "string" then
        interface_ptr = HookLib.get_interface(module, interface_ptr_or_name)
    else
        interface_ptr = interface_ptr_or_name
    end
    
    if not interface_ptr then
        error("Failed to get interface pointer")
    end
    
    return VMTHook.new(interface_ptr)
end

function HookLib.create_detour(typedef, callback, pattern_or_address, module, size, trampoline)
    local address
    
    if type(pattern_or_address) == "string" then
        if not module then
            error("Module name required when using pattern")
        end
        address = HookLib.find_pattern(module, pattern_or_address)
    else
        address = pattern_or_address
    end
    
    if not address then
        error("Failed to find target address")
    end
    
    return DetourHook.new(typedef, callback, address, size, trampoline)
end

function HookLib.hook_cl_move(callback)
    local pattern = "\x55\x8B\xEC\x81\xEC\xCC\xCC\xCC\xCC\x53\x56\x8A\xF9\xF3\x0F\x11\x45\xCC\x8b\x4D\x04"
    HookLib.convenience.CL_Move = HookLib.create_detour(
        "void(__cdecl*)(float, bool)",
        callback,
        pattern,
        "engine.dll",
        5,
        true
    )
    HookLib.convenience.CL_Move:enable()
    return HookLib.convenience.CL_Move
end

function HookLib.hook_frame_stage_notify(callback)
    HookLib.log("Attempting to hook FrameStageNotify...")
    
    local client_iface = HookLib.get_interface("client.dll", "VClient018")
    if not client_iface then
        error("Failed to get VClient018 interface")
    end
    
    local ptr_num = tonumber(ffi.cast("uintptr_t", client_iface))
    HookLib.log("Client interface found at: 0x" .. string.format("%X", ptr_num))
    
    local vmt = HookLib.create_vmt_hook(client_iface)
    HookLib.callbacks[#HookLib.callbacks + 1] = vmt
    
    local original_fsn = nil
    
    local hook_callback = function(thisptr, edx, stage)
        if original_fsn then
            original_fsn(thisptr, edx, stage)
        end
        
        if callback then
            local success, err = pcall(callback, stage)
            if not success then
            end
        end
    end
    
    vmt._frame_stage_callback = hook_callback
    vmt:hook_function(37, hook_callback, "void(__fastcall*)(void*, void*, int)")
    
    local hook_data = vmt.hooked_functions[37]
    if hook_data and hook_data.original then
        original_fsn = ffi.cast("void(__fastcall*)(void*, void*, int)", hook_data.original)
    else
        error("Failed to get original FrameStageNotify function")
    end
    
    HookLib.log("FrameStageNotify hook installed successfully")
    HookLib.convenience.FrameStageNotify = vmt
    return vmt
end

function HookLib.hook_physics_simulate(callback)
    local pattern = "\x56\x8B\xF1\x8B\x8E\xCC\xCC\xCC\xCC\x83\xF9\xFF\x74\x23\x0F\xB7\xC1\xC1\xE0\x04\x05\xCC\xCC\xCC\xCC"
    HookLib.convenience.PhysicsSimulate = HookLib.create_detour(
        "void(__fastcall*)(void*, void*)",
        callback,
        pattern,
        "client.dll",
        5,
        true
    )
    HookLib.convenience.PhysicsSimulate:enable()
    return HookLib.convenience.PhysicsSimulate
end

function HookLib.hook_create_move(callback)
    local client_interface = HookLib.get_interface("client.dll", "VClient018")
    if not client_interface then
        error("Failed to get Client interface")
    end
    
    local vmt_hook = HookLib.convenience.CreateMove
    if not vmt_hook then
        vmt_hook = HookLib.create_vmt_hook(client_interface)
        HookLib.convenience.CreateMove = vmt_hook
    end
    
    vmt_hook:hook_function(22, function(thisptr, edx, sequence_number, input_sample_frametime, active)
        local send_packet = ffi.new("bool[1]", false)
        
        callback(sequence_number, input_sample_frametime, active, send_packet)
        
        local original_func = vmt_hook:get_original(22)
        if original_func then
            return ffi.cast("void(__fastcall*)(void*, void*, int, float, bool)", original_func)(
                thisptr, edx, sequence_number, input_sample_frametime, active
            )
        end
    end, "void(__fastcall*)(void*, void*, int, float, bool)")
    
    return vmt_hook
end

function HookLib.hook_paint_traverse(callback)
    local panel = HookLib.get_interface("vgui2.dll", "VGUI_Panel")
    if not panel then
        error("Failed to get Panel interface")
    end
    
    local vmt = HookLib.create_vmt_hook(panel)
    vmt:hook_function(41, callback, "void(__fastcall*)(void*, void*, unsigned int, bool, bool)")
    
    HookLib.convenience.PaintTraverse = vmt
    return vmt
end

function HookLib.hook_draw_model_execute(callback)
    local model_render = HookLib.get_interface("engine.dll", "VEngineModel")
    if not model_render then
        error("Failed to get ModelRender interface")
    end
    
    local vmt_hook = HookLib.convenience.DrawModelExecute or HookLib.create_vmt_hook(model_render)
    HookLib.convenience.DrawModelExecute = vmt_hook
    
    vmt_hook:hook_function(21, callback, "void(__thiscall*)(void*, void*, const void*, const void*, void*)")
    return vmt_hook
end

function HookLib.hook_lock_cursor(callback)
    local surface = HookLib.get_interface("vguimatsurface.dll", "VGUI_Surface")
    if not surface then
        error("Failed to get Surface interface")
    end
    
    local vmt = HookLib.create_vmt_hook(surface)
    vmt:hook_function(67, callback, "void(__fastcall*)(void*, void*)")
    
    HookLib.convenience.LockCursor = vmt
    return vmt
end

function HookLib.disable_all_hooks()
    HookLib.log("Disabling all hooks...")
    
    for vmt_hook, _ in pairs(HookLib.vmt_hooks) do
        local success, err = pcall(function()
            vmt_hook:cleanup()
        end)
        
        if not success then
            HookLib.log("Error cleaning up VMT hook: " .. tostring(err))
        end
    end
    
    for hook, _ in pairs(HookLib.detour_hooks) do
        if hook.active then
            local success, err = pcall(function()
                hook:disable()
            end)
            
            if not success then
                HookLib.log("Error disabling detour hook: " .. tostring(err))
            end
        end
    end
    
    HookLib.log("All hooks disabled")
end

function HookLib.cleanup_all()
    HookLib.log("Cleaning up all hooks...")
    
    HookLib.disable_all_hooks()

    for k, _ in pairs(HookLib.convenience) do
        HookLib.convenience[k] = nil
    end
    
    for hook in pairs(HookLib.detour_hooks) do
        hook:cleanup()
    end
    
    for vmt in pairs(HookLib.vmt_hooks) do
        vmt:cleanup()
    end
    
    HookLib.detour_hooks = {}
    HookLib.vmt_hooks = {}
    HookLib.active_hooks = {}
    HookLib.pattern_cache = {}
    
    for k, _ in pairs(HookLib.convenience) do
        HookLib.convenience[k] = nil
    end
    
    HookLib.log("All hooks cleaned up")
end

function HookLib.has_active_hooks()
    return next(HookLib.active_hooks) ~= nil
end

function HookLib.get_hook_count()
    local count = 0
    
    for hook in pairs(HookLib.detour_hooks) do
        if hook.active then
            count = count + 1
        end
    end
    
    for vmt in pairs(HookLib.vmt_hooks) do
        count = count + vmt.hook_count
    end
    
    return count
end

function HookLib.initialize()
    if HookLib.initialized then
        return true
    end
    
    HookLib.log("Initializing HookLib...")
    
    local test_alloc = kernel32.VirtualAlloc(1024, false)
    if not test_alloc then
        error("Failed to allocate test memory")
    end
    
    HookLib.log("Memory allocation test passed")
    
    local success, old_protect = kernel32.VirtualProtect(test_alloc, 1024, PAGE_EXECUTE_READWRITE)
    if not success then
        HookLib.log("Warning: VirtualProtect test failed")
    else
        HookLib.log("Memory protection test passed")
        kernel32.VirtualProtect(test_alloc, 1024, old_protect)
    end
    
    kernel32.VirtualFree(test_alloc)
    HookLib.log("Memory free test passed")
    
    if HookLib.config.auto_cleanup then
        client.set_event_callback("shutdown", HookLib.cleanup_all)
    end
    
    HookLib.initialized = true
    HookLib.log("HookLib initialized successfully")
    
    return true
end

client.set_event_callback("shutdown", function()
    HookLib.log("Cleaning up all hooks...")
    for vmt in pairs(HookLib.vmt_hooks) do
        pcall(function()
            vmt:cleanup()
        end)
    end
    for hook in pairs(HookLib.detour_hooks) do
        pcall(function()
            hook:cleanup()
        end)
    end
end)

HookLib.log("HookLib loaded successfully")

return HookLib
